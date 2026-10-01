using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using ProtocolForge.Models;

namespace ProtocolForge.Services;

public sealed record TsharkDetection(bool Ok, string Version, string? Path, string Message)
{
    /// <summary>Localization key for the user-visible message (null = <see cref="Message"/> is final).</summary>
    public string? MessageKey { get; init; }

    /// <summary>Format arguments for <see cref="MessageKey"/>.</summary>
    public object?[]? MessageArgs { get; init; }

    /// <summary>
    /// Current-language resolution of the detection outcome for UI display.
    /// Console hosts (pf-verify) keep using <see cref="Message"/> untouched.
    /// </summary>
    public string LocalizedMessage => MessageKey is null
        ? Message
        : LocalizationService.Resolve(MessageKey, MessageArgs);
}

public sealed record PdmlData(
    Dictionary<(string Name, int Pos), string> ProtoShowNames,
    Dictionary<(string Name, int Pos), string> FieldLookup,
    Dictionary<(string Name, int Pos), string> TypeLookup,
    Dictionary<string, List<int>> ProtoPositions,
    Dictionary<string, List<int>> ProtoBiases,
    HashSet<string> HiddenFields,
    Dictionary<string, HashSet<int>> HiddenPositions,
    // Anonymous <field name="" show="…"> spans keyed by their show text, so
    // jsonraw plain-scalar leaves (e.g. the "\r\n" blank line of an SSDP request
    // at pos 215, size 2) can attach real byte spans for hex highlighting.
    Dictionary<string, (int Pos, int Size)>? AnonymousSpans = null,
    (int Base, int Length)? ReassemblyRegion = null,
    // PDML 'value' attribute (contiguous lowercase hex of field bytes) keyed
    // by (fieldName, byteOffset). Used by EditTransactionService to verify
    // that a tree-edit actually landed at the expected byte position.
    Dictionary<(string Name, int Pos), string>? ValueLookup = null,
    // Every PDML position per field name. A zero-span container (tshark's _ws.expert
    // wrapper) has no _raw twin to carry its offset, so the only way to find its
    // showname — and with it the "Expert Info (Note/Sequence)" label Wireshark shows —
    // is to look the name up here.
    Dictionary<string, HashSet<int>>? NamePositions = null);

/// <summary>
/// Invokes Tshark asynchronously to parse PCAP files into structured <see cref="PacketDocument"/>.
/// Uses tshark -T jsonraw to get both the protocol tree (with byte offsets) and the raw hex values
/// needed for hex ↔ field synchronization.
///
/// Tshark binary discovery: checks well-known install paths on Windows, Linux, and macOS.
/// </summary>
public sealed class TsharkService
{
    private readonly PcapIngestService _pcapIngest;
    private readonly PcapExportService _pcapExport;
    private string? _tsharkPath;
    private string? _tlsKeylogPath;
    private string[]? _tlsKeylogArgs;

    public TsharkService(PcapIngestService pcapIngest, PcapExportService pcapExport, string? tsharkPath = null)
    {
        _pcapIngest = pcapIngest;
        _pcapExport = pcapExport;
        _tsharkPath = tsharkPath ?? FindTshark();
    }

    /// <summary>
    /// Loads a PCAP file into the given <paramref name="document"/>.
    ///
    /// Phase 1 reads the raw bytes natively via <see cref="PcapIngestService"/>
    /// (timestamps, link-layer type, packet data). Phase 2 streams a single
    /// tshark "-T fields" pass that fills every packet-list column
    /// (Source/Destination/Protocol/Info) in frame order. No full-file
    /// jsonraw/json/pdml productions happen here — the protocol tree of a packet
    /// is built on demand per selection via <see cref="BuildPacketTreeAsync"/>.
    /// Packets are appended incrementally so the grid fills progressively.
    /// </summary>
    public async Task<PacketDocument> LoadPcapAsync(
        PacketDocument document,
        string filePath,
        IProgress<double>? progress = null,
        CancellationToken ct = default)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("PCAP file not found", filePath);

        EnsureTsharkAvailable();

        // Phase 1: Read raw bytes (fast native parser, seconds even for large
        // captures; no tshark involvement).
        progress?.Report(0.05);
        var rawResult = await _pcapIngest.ReadPacketsAsync(filePath, ct);
        document.PacketCount = rawResult.Packets.Count;
        document.LinkLayerType = rawResult.LinkLayerType;
        document.Snaplen = rawResult.Snaplen;

        // Phase 2: single streamed "-T fields" pass producing the Wireshark
        // column texts per packet. Source/Destination come from _ws.col.* which
        // uses Wireshark's own column logic (MAC analysis names for non-IP
        // frames, tunnel handling, etc.) — closer to the Wireshark UI than the
        // old layer-scan extraction. Info is the last column and may itself
        // contain tabs (multi-value Info), so split at most 5 fields.
        int total = rawResult.Packets.Count;

        // Context providers (SDP signaling, IP fragment groups, TCP stream
        // reassembly) are attached to the document but do NOT scan here: each
        // provider runs its whole-capture tshark scan lazily on the first
        // per-packet tree build that needs it, so captures that never touch
        // such packets pay zero extra tshark processes.
        async Task<IReadOnlyList<string>> RowReader(string filter, IReadOnlyList<string> fields, CancellationToken c)
            => await RunTsharkFilterRowsAsync(filePath, filter, fields, c);
        document.ContextProviders =
        [
            new SdpContextProvider(RowReader),
            new FragmentContextProvider(RowReader),
            new TcpStreamContextProvider(RowReader),
        ];

        var psi = new ProcessStartInfo
        {
            FileName = _tsharkPath!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("-r");
        psi.ArgumentList.Add(filePath);
        psi.ArgumentList.Add("-T");
        psi.ArgumentList.Add("fields");
        psi.ArgumentList.Add("-E");
        psi.ArgumentList.Add("header=n");
        psi.ArgumentList.Add("-E");
        psi.ArgumentList.Add("separator=/t");
        foreach (string field in new[] { "frame.number", "_ws.col.Source", "_ws.col.Destination", "_ws.col.Protocol", "_ws.col.Info" })
        {
            psi.ArgumentList.Add("-e");
            psi.ArgumentList.Add(field);
        }
        AddTlsKeylogArgs(psi);

        using (var process = new Process { StartInfo = psi })
        {
            process.Start();
            var errorTask = process.StandardError.ReadToEndAsync(ct);

            // Stream the parsed rows in batches. Each AddRange raises one
            // CollectionChanged event; per-packet Add would fire 180k UI-thread
            // grid updates and turn a ~16 s load into a minute-long one.
            const int batchSize = 500;
            var batch = new List<Packet>(batchSize);

            string? line;
            while ((line = await process.StandardOutput.ReadLineAsync(ct)) != null)
            {
                ct.ThrowIfCancellationRequested();
                var cols = line.Split('\t', 5);
                if (cols.Length < 4 || !int.TryParse(cols[0], out int frameNumber))
                    continue;
                int idx = frameNumber - 1;
                if (idx < 0 || idx >= total)
                    continue;

                var (timestamp, rawData) = rawResult.Packets[idx];
                batch.Add(new Packet
                {
                    Index = idx,
                    Timestamp = timestamp,
                    RawData = rawData,
                    SourceAddress = string.IsNullOrEmpty(cols[1]) ? "N/A" : cols[1],
                    DestinationAddress = string.IsNullOrEmpty(cols[2]) ? "N/A" : cols[2],
                    ProtocolName = cols[3].ToUpperInvariant(),
                    InfoText = cols.Length >= 5 ? cols[4].Replace("\t", " | ") : string.Empty,
                });

                if (batch.Count >= batchSize)
                {
                    document.Packets.AddRange(batch);
                    batch.Clear();
                    progress?.Report(0.05 + 0.9 * document.Packets.Count / total);
                }
            }

            if (batch.Count > 0)
                document.Packets.AddRange(batch);

            await process.WaitForExitAsync(ct);
            var error = await errorTask;
            if (process.ExitCode != 0)
                throw new InvalidOperationException(
                    $"Tshark exited with code {process.ExitCode}: {error}");
        }

        progress?.Report(1.0);
        if (document.Packets.Count > 0)
            document.SelectedPacket = document.Packets[0];
        return document;
    }

    /// <summary>
    /// Builds the protocol layer tree of a single packet on demand. Writes the
    /// packet's effective bytes to a temp PCAP, runs jsonraw (byte spans),
    /// json (display values) and pdml (Wireshark shownames) in parallel on that
    /// one packet (~0.4s), and fills <see cref="Packet.Layers"/>. Returns false
    /// when tshark produced no usable tree. Optional context frames (SDP
    /// signaling and/or IP fragment siblings) are prepended so tshark can
    /// resolve dynamic RTP payload types and reassemble fragmented datagrams.
    /// </summary>
    public async Task<bool> BuildPacketTreeAsync(
        Packet packet,
        int linkLayerType,
        IReadOnlyList<(long Timestamp, byte[] Data)>? contextFrames = null,
        CancellationToken ct = default)
    {
        EnsureTsharkAvailable();

        string tempPath = Path.Combine(Path.GetTempPath(), $"pf_tree_{Guid.NewGuid():N}.pcap");
        try
        {
            if (contextFrames is { Count: > 0 })
            {
                await _pcapExport.SavePacketWithContextAsync(packet, contextFrames, tempPath, linkLayerType, ct);
            }
            else
            {
                await _pcapExport.SavePacketAsync(packet, tempPath, linkLayerType, ct);
            }

            return await ParsePacketFromPcapFileAsync(packet, tempPath, ct);
        }
        finally
        {
            try { File.Delete(tempPath); }
            catch (Exception) { /* best-effort temp clean-up */ }
        }
    }

    /// <summary>
    /// Runs the three tshark passes (jsonraw/json/pdml) over an existing PCAP file and
    /// fills the given packet's layer tree from the LAST frame of that file. The file is
    /// left untouched — callers own its lifecycle. Shared by tree builds and the
    /// protocol-tree verification harness so both exercise the identical parse path.
    /// </summary>
    public async Task<bool> ParsePacketFromPcapFileAsync(
        Packet packet,
        string filePath,
        CancellationToken ct = default)
    {
        EnsureTsharkAvailable();

        var jsonRawTask = RunTsharkJsonRawAsync(filePath, ct);
        var jsonTask = RunTsharkJsonAsync(filePath, ct);
        var pdmlTask = RunTsharkPdmlAsync(filePath, ct);

        string jsonOutput = await jsonRawTask;
        string jsonDisplayOutput = await jsonTask;
        string pdmlOutput = await pdmlTask;

        var pdmlData = ParsePdmlToLookup(pdmlOutput);
        // The target packet is always the last frame in the temp PCAP, so
        // its parse result is the final element of every tshark output array.
        var pdmlSingle = pdmlData.Count > 0 ? pdmlData[^1] : null;

        using var doc = JsonDocument.Parse(jsonOutput);
        var rootArray = doc.RootElement;
        if (rootArray.ValueKind != JsonValueKind.Array || rootArray.GetArrayLength() == 0)
            return false;
        var packetElement = rootArray[rootArray.GetArrayLength() - 1];

        using var displayDoc = JsonDocument.Parse(jsonDisplayOutput);
        var displayRoot = displayDoc.RootElement;
        var displayArray = displayRoot.ValueKind == JsonValueKind.Array ? displayRoot : default;

        JsonElement layersElement = default;
        var hasLayers =
            packetElement.TryGetProperty("_source", out var sourceElement) &&
            sourceElement.TryGetProperty("layers", out layersElement);
        if (!hasLayers)
            return false;

        JsonElement displayLayers = default;
        var hasDisplay = displayArray.ValueKind == JsonValueKind.Array &&
                         displayArray.GetArrayLength() > 0 &&
                         displayArray[displayArray.GetArrayLength() - 1].TryGetProperty("_source", out var dSource) &&
                         dSource.TryGetProperty("layers", out displayLayers);

        ParseLayers(layersElement, hasDisplay ? displayLayers : default, pdmlSingle, packet);
        return packet.Layers.Count > 0;
    }

    private static TsharkDetection? _detectionCache;
    private static readonly object _detectionLock = new();

    /// <summary>
    /// Detects whether tshark is available and meets the minimum version requirement.
    /// Result is cached for the process lifetime.
    /// </summary>
    public static TsharkDetection DetectTshark()
    {
        lock (_detectionLock)
        {
            _detectionCache ??= DetectTsharkCore();
            return _detectionCache;
        }
    }

    /// <summary>
    /// Re-runs detection unconditionally (used after the user picks a new tshark
    /// path at runtime) and returns the fresh result.
    /// </summary>
    public static TsharkDetection RedetectTshark()
    {
        lock (_detectionLock)
        {
            _detectionCache = DetectTsharkCore();
            return _detectionCache;
        }
    }

    private static TsharkDetection DetectTsharkCore()
    {
        var path = FindTshark();
        if (path == null || !File.Exists(path))
            return new TsharkDetection(false, string.Empty, null,
                "tshark not found. Install Wireshark (which includes tshark) or set the TSHARK_PATH environment variable.\n" +
                "Download: https://www.wireshark.org/download.html")
            { MessageKey = "Tsh.NotFound" };

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = path,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("-v");

            using var process = Process.Start(psi);
            if (process == null)
                return new TsharkDetection(false, string.Empty, path,
                    "Cannot start tshark process.")
                { MessageKey = "Tsh.CannotStart" };

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(5000);

            // First line: "TShark (Wireshark) 4.2.6 (Git v4.2.6 ...)" or similar
            var firstLine = output.Split('\n').FirstOrDefault()?.Trim() ?? "";
            string version = ParseVersion(firstLine);

            if (string.IsNullOrEmpty(version))
                return new TsharkDetection(false, string.Empty, path,
                    $"Cannot parse version from tshark output:\n{firstLine}")
                { MessageKey = "Tsh.VersionParse", MessageArgs = new object?[] { firstLine } };

            // Format floor: every output shape the parser consumes (-T jsonraw with
            // duplicate keys, -T json --no-duplicate-keys, -T pdml pos/size/value,
            // -Y filters, -T fields) has been stable since Wireshark 2.6.0. Older
            // tshark simply lacks those output modes, so the gate drops to read-only.
            if (VersionCompare(version, "2.6.0") < 0)
                return new TsharkDetection(false, version, path,
                    $"tshark {version} found, minimum supported is 2.6.")
                { MessageKey = "Tsh.TooOld", MessageArgs = new object?[] { version } };

            return new TsharkDetection(true, version, path, string.Empty);
        }
        catch (Exception ex)
        {
            return new TsharkDetection(false, string.Empty, path,
                $"Error detecting tshark: {ex.Message}")
            { MessageKey = "Tsh.Err", MessageArgs = new object?[] { ex.Message } };
        }
    }

    private static string ParseVersion(string firstLine)
    {
        var match = System.Text.RegularExpressions.Regex.Match(firstLine, @"(\d+\.\d+\.\d+)");
        return match.Success ? match.Groups[1].Value : string.Empty;
    }

    private static int VersionCompare(string a, string b)
    {
        var pa = a.Split('.').Select(int.Parse).ToArray();
        var pb = b.Split('.').Select(int.Parse).ToArray();
        for (int i = 0; i < Math.Max(pa.Length, pb.Length); i++)
        {
            int va = i < pa.Length ? pa[i] : 0;
            int vb = i < pb.Length ? pb[i] : 0;
            if (va != vb) return va.CompareTo(vb);
        }
        return 0;
    }

    /// <summary>
    /// Loads a PCAP file in read-only mode: reads raw packets via PcapIngestService
    /// without invoking tshark. The packet list shows frame numbers, timestamps,
    /// and lengths, but Source/Destination/Protocol/Info columns are not populated.
    /// </summary>
    public async Task<PacketDocument> LoadPcapReadOnlyAsync(
        PacketDocument document,
        string filePath,
        CancellationToken ct = default)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("PCAP file not found", filePath);

        var rawResult = await _pcapIngest.ReadPacketsAsync(filePath, ct);
        document.PacketCount = rawResult.Packets.Count;
        document.LinkLayerType = rawResult.LinkLayerType;
        document.Snaplen = rawResult.Snaplen;

        int idx = 0;
        foreach (var (timestamp, rawData) in rawResult.Packets)
        {
            ct.ThrowIfCancellationRequested();
            document.Packets.Add(new Packet
            {
                Index = idx++,
                Timestamp = timestamp,
                RawData = rawData,
                SourceAddress = "N/A",
                DestinationAddress = "N/A",
                ProtocolName = "",
                InfoText = $"(raw {rawData.Length} bytes)",
            });
        }

        if (document.Packets.Count > 0)
            document.SelectedPacket = document.Packets[0];
        return document;
    }

    /// <summary>
    /// Updates the tshark path used by this instance (for runtime re-detection
    /// after the user picks a new path). Does NOT update the detection cache.
    /// </summary>
    internal void UpdateTsharkPath(string newPath)
    {
        _tsharkPath = newPath;
    }

    /// <summary>
    /// Finds the tshark executable in the system.
    /// </summary>
    public static string? FindTshark()
    {
        // Check TSHARK environment variable override
        var envPath = Environment.GetEnvironmentVariable("TSHARK_PATH");
        if (!string.IsNullOrWhiteSpace(envPath) && File.Exists(envPath))
            return envPath;

        // Check PATH
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
        {
            try
            {
                var full = Path.Combine(dir, OperatingSystem.IsWindows() ? "tshark.exe" : "tshark");
                if (File.Exists(full))
                    return full;
            }
            catch { /* skip invalid PATH entries */ }
        }

        // Windows: common Wireshark install paths
        if (OperatingSystem.IsWindows())
        {
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var candidates = new[]
            {
                Path.Combine(programFiles, "Wireshark", "tshark.exe"),
                @"C:\Program Files\Wireshark\tshark.exe",
                @"C:\Program Files (x86)\Wireshark\tshark.exe",
            };
            foreach (var c in candidates)
            {
                if (File.Exists(c))
                    return c;
            }
        }

        // Linux/macOS: check common locations
        var unixCandidates = new[]
        {
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/opt/homebrew/bin/tshark",
            "/snap/bin/tshark"
        };
        foreach (var c in unixCandidates)
        {
            if (File.Exists(c))
                return c;
        }

        return null;
    }

    private void EnsureTsharkAvailable()
    {
        if (_tsharkPath == null || !File.Exists(_tsharkPath))
            throw new InvalidOperationException(
                "Tshark not found. Install Wireshark (which includes tshark) " +
                "or set the TSHARK_PATH environment variable to the tshark executable location.\n" +
                "Download: https://www.wireshark.org/download.html");
    }

    /// <summary>
    /// Sets the TLS key-log file used to decrypt TLS traffic in every subsequent
    /// tshark invocation. An empty/null path falls back to the SSLKEYLOGFILE
    /// environment variable; when neither resolves to an existing file no TLS
    /// option is passed at all. The option name follows the tshark version
    /// (ssl.keylog_file before 3.0, tls.keylog_file from 3.0 on).
    /// Deliberately has no UI entry point: the key-log selection menu was removed
    /// because it reported success for any existing file, while tshark silently
    /// skipped unparseable lines — users saw "it did not decrypt" with no clue.
    /// Entry points are the SSLKEYLOGFILE environment variable and the
    /// TlsKeylogPath value persisted in settings.json (restored by App).
    /// </summary>
    public void SetTlsKeylogPath(string? path)
    {
        _tlsKeylogPath = path;
        _tlsKeylogArgs = null;
    }

    internal void ResetTlsKeylogArgs()
    {
        _tlsKeylogArgs = null;
    }

    private string[] GetTlsKeylogArgs()
    {
        if (_tlsKeylogArgs is not null)
            return _tlsKeylogArgs;

        var path = _tlsKeylogPath ?? Environment.GetEnvironmentVariable("SSLKEYLOGFILE");
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            _tlsKeylogArgs = [];
            return _tlsKeylogArgs;
        }

        string optionName = VersionCompare(DetectTshark().Version, "3.0.0") >= 0
            ? "tls.keylog_file"
            : "ssl.keylog_file";
        _tlsKeylogArgs = ["-o", $"{optionName}:{path}"];
        return _tlsKeylogArgs;
    }

    private void AddTlsKeylogArgs(ProcessStartInfo startInfo)
    {
        foreach (string argument in GetTlsKeylogArgs())
            startInfo.ArgumentList.Add(argument);
    }

    // ────────────────────────────────────────────────────────
    // Tshark process invocation
    // ────────────────────────────────────────────────────────

    private async Task<string> RunTsharkJsonRawAsync(string filePath, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _tsharkPath!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("-r");
        psi.ArgumentList.Add(filePath);
        psi.ArgumentList.Add("-T");
        psi.ArgumentList.Add("jsonraw");
        AddTlsKeylogArgs(psi);

        using var process = new Process { StartInfo = psi };
        process.Start();

        // Read both streams concurrently to avoid deadlocks
        var outputTask = process.StandardOutput.ReadToEndAsync(ct);
        var errorTask = process.StandardError.ReadToEndAsync(ct);

        await process.WaitForExitAsync(ct);

        var output = await outputTask;
        var error = await errorTask;

        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"Tshark exited with code {process.ExitCode}: {error}");

        return output;
    }

    private async Task<string> RunTsharkJsonAsync(string filePath, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _tsharkPath!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("-r");
        psi.ArgumentList.Add(filePath);
        psi.ArgumentList.Add("-T");
        psi.ArgumentList.Add("json");
        psi.ArgumentList.Add("--no-duplicate-keys");
        AddTlsKeylogArgs(psi);

        using var process = new Process { StartInfo = psi };
        process.Start();

        // Read both streams concurrently to avoid deadlocks
        var outputTask = process.StandardOutput.ReadToEndAsync(ct);
        var errorTask = process.StandardError.ReadToEndAsync(ct);

        await process.WaitForExitAsync(ct);

        var output = await outputTask;
        var error = await errorTask;

        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"Tshark exited with code {process.ExitCode}: {error}");

        return output;
    }

    private async Task<string> RunTsharkPdmlAsync(string filePath, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _tsharkPath!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("-r");
        psi.ArgumentList.Add(filePath);
        psi.ArgumentList.Add("-T");
        psi.ArgumentList.Add("pdml");
        AddTlsKeylogArgs(psi);

        using var process = new Process { StartInfo = psi };
        process.Start();

        var outputTask = process.StandardOutput.ReadToEndAsync(ct);
        var errorTask = process.StandardError.ReadToEndAsync(ct);

        await process.WaitForExitAsync(ct);

        var output = await outputTask;
        var error = await errorTask;

        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"Tshark exited with code {process.ExitCode}: {error}");

        return output;
    }

    private async Task<IReadOnlyList<string>> RunTsharkFilterRowsAsync(
        string filePath, string displayFilter, IReadOnlyList<string> fields, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _tsharkPath!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("-r");
        psi.ArgumentList.Add(filePath);
        psi.ArgumentList.Add("-Y");
        psi.ArgumentList.Add(displayFilter);
        psi.ArgumentList.Add("-T");
        psi.ArgumentList.Add("fields");
        psi.ArgumentList.Add("-E");
        psi.ArgumentList.Add("header=n");
        psi.ArgumentList.Add("-E");
        psi.ArgumentList.Add("separator=/t");
        foreach (string field in fields)
        {
            psi.ArgumentList.Add("-e");
            psi.ArgumentList.Add(field);
        }
        AddTlsKeylogArgs(psi);

        var rows = new List<string>();
        using var process = new Process { StartInfo = psi };
        process.Start();
        var errorTask = process.StandardError.ReadToEndAsync(ct);

        string? line;
        while ((line = await process.StandardOutput.ReadLineAsync(ct)) != null)
            rows.Add(line);

        await process.WaitForExitAsync(ct);
        var error = await errorTask;
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"Tshark filter scan exited with code {process.ExitCode}: {error}");

        return rows;
    }

    /// <summary>
    /// Re-parses a single-packet PCAP file with tshark -T pdml and returns the
    /// field/showname lookup for that packet. Used after a field edit to refresh
    /// container and layer display texts without rebuilding the protocol tree.
    /// </summary>
    public async Task<PdmlData?> ReparseSinglePacketAsync(string filePath, CancellationToken ct = default)
    {
        EnsureTsharkAvailable();
        string pdmlOutput = await RunTsharkPdmlAsync(filePath, ct);
        var parsed = ParsePdmlToLookup(pdmlOutput);
        return parsed.Count > 0 ? parsed[^1] : null;
    }

    // ────────────────────────────────────────────────────────
    // JSON parser: walks tshark jsonraw output recursively
    // ────────────────────────────────────────────────────────

    private static void ParseLayers(
        JsonElement layersElement,
        JsonElement displayLayersElement,
        PdmlData? pdmlData,
        Packet packet)
    {
        // A rebuild REPLACES the layer tree. The reset path re-parses a packet
        // whose tree is already populated; appending would double every layer on
        // each rebuild. No caller depends on accumulation (selection and prefetch
        // both skip packets that already have layers), so clear first.
        packet.Layers.Clear();

        var pdmlLookup = pdmlData?.FieldLookup;
        var pdmlTypeLookup = pdmlData?.TypeLookup;
        var pdmlHiddenNames = pdmlData?.HiddenFields;
        var pdmlHiddenPositions = pdmlData?.HiddenPositions;
        var pdmlNamePositions = pdmlData?.NamePositions;
        var protoShowNames = pdmlData?.ProtoShowNames;
        var protoPositions = pdmlData?.ProtoPositions;
        var protoBiases = pdmlData?.ProtoBiases;
        var pdmlAnonSpans = pdmlData?.AnonymousSpans;
        var reassemblyRegion = pdmlData?.ReassemblyRegion;

        string? malformedNote = null;

        // Duplicate layer keys (e.g. the four http2.stream dissections of one frame)
        // arrive as repeated top-level objects in the same layer object. Number them
        // by protocol name so PDML positions, biases and the display tree line up.
        var instanceSeqByProto = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var layerProp in layersElement.EnumerateObject())
        {
            string protocolName = layerProp.Name;
            JsonElement layerValue = layerProp.Value;

            if (protocolName == "geninfo" || protocolName == "raw"
                || protocolName.EndsWith("_raw", StringComparison.Ordinal))
                continue;

            if (protocolName.StartsWith("_ws.", StringComparison.Ordinal))
            {
                if (protocolName == "_ws.malformed" && protoShowNames != null)
                {
                    foreach (var kvp in protoShowNames)
                    {
                        if (kvp.Key.Name == "_ws.malformed" && kvp.Value.Contains("Malformed Packet", StringComparison.Ordinal))
                        {
                            malformedNote = kvp.Value;
                            break;
                        }
                    }
                }
                continue;
            }

            int layerSeq = instanceSeqByProto.TryGetValue(protocolName, out var seen) ? seen : 0;
            bool wasArray = layerValue.ValueKind == JsonValueKind.Array;

            if (layerValue.ValueKind == JsonValueKind.Object)
            {
                instanceSeqByProto[protocolName] = layerSeq + 1;
                ParseSingleLayer(
                    protocolName, layerValue, displayLayersElement,
                    pdmlLookup, pdmlTypeLookup, protoShowNames, protoPositions, packet,
                    layerSeq, protoBiases, pdmlHiddenNames, pdmlHiddenPositions,
                    pdmlAnonSpans, reassemblyRegion, pdmlNamePositions);
            }
            else if (wasArray)
            {
                // Repeated dissections of the same protocol (e.g. outer + inner IP
                // of a GTP/GRE-in-UDP tunnel) still fit the array shape when the
                // identical key group repeats contiguously in older tshark output.
                int elementIndex = layerSeq;
                foreach (var element in layerValue.EnumerateArray())
                {
                    if (element.ValueKind != JsonValueKind.Object)
                        continue;
                    instanceSeqByProto[protocolName] = elementIndex + 1;
                    ParseSingleLayer(
                        protocolName, element, displayLayersElement,
                        pdmlLookup, pdmlTypeLookup, protoShowNames, protoPositions, packet,
                        elementIndex, protoBiases, pdmlHiddenNames, pdmlHiddenPositions,
                        pdmlAnonSpans, reassemblyRegion, pdmlNamePositions);
                    elementIndex++;
                }
            }
        }

        // tshark --no-duplicate-keys merges repeated dissections of the same
        // protocol into a single array key at the first instance's JSON position,
        // so restore true wire order by sorting on the layer byte offset.
        packet.Layers = new ObservableCollection<ProtocolLayer>(
            packet.Layers.OrderBy(l => l.Offset));

        if (malformedNote != null && packet.Layers.Count > 0)
        {
            // Wireshark attaches "[Malformed Packet: X]" to the innermost
            // protocol that failed to dissect, not as a top-level layer.
            var innermost = packet.Layers[^1];
            innermost.DisplayText = $"{innermost.DisplayText}  ({malformedNote})";
        }

        ExtractAddressInfo(packet);
    }

    private static void ParseSingleLayer(
        string protocolName,
        JsonElement layerValue,
        JsonElement displayLayersElement,
        Dictionary<(string Name, int Pos), string>? pdmlLookup,
        Dictionary<(string Name, int Pos), string>? pdmlTypeLookup,
        Dictionary<(string Name, int Pos), string>? protoShowNames,
        Dictionary<string, List<int>>? protoPositions,
        Packet packet,
        int instanceIndex = 0,
        Dictionary<string, List<int>>? protoBiases = null,
        HashSet<string>? pdmlHiddenNames = null,
        Dictionary<string, HashSet<int>>? pdmlHiddenPositions = null,
        Dictionary<string, (int Pos, int Size)>? pdmlAnonSpans = null,
        (int Base, int Length)? reassemblyRegion = null,
        Dictionary<string, HashSet<int>>? pdmlNamePositions = null)
    {
        int layerOffset = GetLayerOffset(layerValue);
        int offsetBias = 0;
        if (protoPositions != null &&
            protoPositions.TryGetValue(protocolName, out var positions) &&
            instanceIndex < positions.Count)
        {
            layerOffset = positions[instanceIndex];
            if (protoBiases != null &&
                protoBiases.TryGetValue(protocolName, out var biases) &&
                instanceIndex < biases.Count)
            {
                offsetBias = biases[instanceIndex];
            }
        }
        else if (reassemblyRegion is { } region &&
                 layerOffset >= 0 && layerOffset < region.Length)
        {
            // jsonraw-only layers (e.g. the data payload of a reassembled IP whose
            // PDML proto is a position-less fake-field-wrapper) carry reassembly
            // relative offsets; align them to the reassembly base so layers sort in
            // wire order (after the inner ip, not before it).
            layerOffset += region.Base;
            offsetBias = region.Base;
        }

        var layer = new ProtocolLayer
        {
            ProtocolName = protocolName,
            ParentPacket = packet,
            Offset = layerOffset,
        };

        JsonElement displayLayer = default;
        bool hasDisplay = false;
        if (displayLayersElement.ValueKind == JsonValueKind.Object &&
            displayLayersElement.TryGetProperty(protocolName, out var rawDisplay))
        {
            if (rawDisplay.ValueKind == JsonValueKind.Object)
            {
                displayLayer = rawDisplay;
                hasDisplay = true;
            }
            else if (rawDisplay.ValueKind == JsonValueKind.Array &&
                     instanceIndex < rawDisplay.GetArrayLength() &&
                     rawDisplay[instanceIndex].ValueKind == JsonValueKind.Object)
            {
                displayLayer = rawDisplay[instanceIndex];
                hasDisplay = true;
            }
        }

        ParseJsonrawObject(layerValue, hasDisplay ? displayLayer : default, pdmlLookup, pdmlTypeLookup, pdmlHiddenNames, pdmlHiddenPositions, layer.Fields, protocolName, layer, offsetBias: offsetBias, pdmlAnonSpans: pdmlAnonSpans, pdmlNamePositions: pdmlNamePositions);

        if (protoShowNames != null &&
            protoShowNames.TryGetValue((protocolName, layerOffset), out var showname))
        {
            layer.DisplayText = showname;
        }
        else
        {
            layer.DisplayText = protocolName.ToUpperInvariant();
        }

        packet.Layers.Add(layer);
    }

    private static int GetLayerOffset(JsonElement layerValue)
    {
        // The layer's byte offset equals the offset of its first field (e.g.
        // ip.version_raw at pos 14 for the outer IP, pos 58 for the inner IP of a
        // GTP tunnel). Fall back to the smallest *_raw offset seen in the object.
        // PDML positions (protoPositions) are preferred and normally take over.
        int min = int.MaxValue;
        foreach (var prop in layerValue.EnumerateObject())
        {
            if (!prop.Name.EndsWith("_raw", StringComparison.Ordinal))
                continue;
            // Pseudo/meta fields (tcp.completeness_raw, *_stream_raw, _ws.*) carry
            // offset 0 and would drag the whole layer to the frame start.
            if (prop.Name.Contains(".completeness_raw", StringComparison.Ordinal) ||
                prop.Name.Contains(".stream_raw", StringComparison.Ordinal) ||
                prop.Name.Contains("_ws.", StringComparison.Ordinal))
                continue;
            if (prop.Value.ValueKind != JsonValueKind.Array || prop.Value.GetArrayLength() < 2)
                continue;
            var second = prop.Value[1];
            if (second.ValueKind == JsonValueKind.Number)
                min = Math.Min(min, second.GetInt32());
        }
        return min == int.MaxValue ? 0 : min;
    }

    /// <summary>
    /// Extracts source/destination addresses and ports from parsed layers
    /// by scanning for well-known ip.src, ip.dst, udp.srcport, tcp.srcport fields.
    /// </summary>
    private static void ExtractAddressInfo(Packet packet)
    {
        foreach (var layer in packet.Layers)
        {
            var proto = layer.ProtocolName.ToLowerInvariant();
            switch (proto)
            {
                case "ip":
                case "ipv4":
                    ScanAddressFields(layer.Fields, packet, isV6: false);
                    break;
                case "ipv6":
                    ScanAddressFields(layer.Fields, packet, isV6: true);
                    break;
                case "udp":
                case "tcp":
                    ScanPortFields(layer.Fields, packet, proto);
                    break;
            }
        }
    }

    private static void ScanAddressFields(
        ObservableCollection<ProtocolField> fields, Packet packet, bool isV6)
    {
        foreach (var f in fields)
        {
            if (f.Name is "src" or "ip_src" or "addr" or "Source Address")
            {
                string ip = TryConvertHexToIp(f.DisplayValue, isV6);
                if (isV6)
                    packet.SourceAddress = ip;
                else if (packet.SourceAddress == "N/A")
                    packet.SourceAddress = ip;
            }
            else if (f.Name is "dst" or "ip_dst" or "Destination Address")
            {
                string ip = TryConvertHexToIp(f.DisplayValue, isV6);
                if (isV6)
                    packet.DestinationAddress = ip;
                else if (packet.DestinationAddress == "N/A")
                    packet.DestinationAddress = ip;
            }

            if (f.HasChildren)
                ScanAddressFields(f.Children, packet, isV6);
        }
    }

    private static void ScanPortFields(
        ObservableCollection<ProtocolField> fields, Packet packet, string proto)
    {
        foreach (var f in fields)
        {
            if (f.Name is "srcport" or "port" or "Source Port")
            {
                int.TryParse(TryConvertHexToDecimal(f.DisplayValue), out var sp);
                if (sp > 0) packet.SourcePort = sp;
            }
            else if (f.Name is "dstport" or "Destination Port")
            {
                int.TryParse(TryConvertHexToDecimal(f.DisplayValue), out var dp);
                if (dp > 0) packet.DestinationPort = dp;
            }

            if (f.HasChildren)
                ScanPortFields(f.Children, packet, proto);
        }
    }

    private static string TryConvertHexToIp(string hex, bool isV6)
    {
        if (string.IsNullOrEmpty(hex)) return "N/A";

        // Already a human-readable IP (from the merged display value).
        if (hex.Contains('.'))
            return hex;

        if (!isV6 && hex.Length == 8) // 4 bytes = 8 hex chars
        {
            try
            {
                var bytes = Convert.FromHexString(hex);
                if (bytes.Length == 4)
                    return string.Join(".", bytes);
            }
            catch { }
        }
        return hex;
    }

    private static string TryConvertHexToDecimal(string hex)
    {
        if (string.IsNullOrEmpty(hex)) return hex;

        // Already a decimal value (from the merged display value).
        if (int.TryParse(hex, System.Globalization.NumberStyles.Integer, null, out var dec))
            return dec.ToString();

        if (hex.Length <= 4 && int.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var val))
            return val.ToString();
        return hex;
    }

    // ────────────────────────────────────────────────────────
    // jsonraw _raw-array-format parser
    // tshark -T jsonraw outputs fields as arrays:
    //   "field.name_raw": [ "hex_value", offset, length, 0, field_id ]
    //   "field.name_tree": { sub-fields }
    // ────────────────────────────────────────────────────────

    // tshark marks unknown/truncated IEs with raw keys like
    // "pfcp.ie_data_not_decoded_raw" / "pfcp.ie_not_decoded_null_raw" (always [0,0,0,0]).
    private static bool IsUndecodedMarkerKey(string key)
        => key.Contains("not_decoded", StringComparison.Ordinal);

    private static void ParseJsonrawObject(
        JsonElement obj,
        JsonElement displayObj,
        Dictionary<(string Name, int Pos), string>? pdmlLookup,
        Dictionary<(string Name, int Pos), string>? pdmlTypeLookup,
        HashSet<string>? pdmlHiddenNames,
        Dictionary<string, HashSet<int>>? pdmlHiddenPositions,
        ObservableCollection<ProtocolField> targetCollection,
        string protocolPrefix,
        ProtocolLayer parentLayer,
        ProtocolField? parentField = null,
        int offsetBias = 0,
        Dictionary<string, (int Pos, int Size)>? pdmlAnonSpans = null,
        Dictionary<string, HashSet<int>>? pdmlNamePositions = null)
    {
        // tshark's jsonraw writer emits repeated fields as duplicate JSON keys rather
        // than arrays (e.g. DHCP option containers: "dhcp.option.type_raw" x7 and
        // "dhcp.option.type_tree" x7). JsonElement preserves them in document order,
        // so raws are collected as an ordered list per base name and each container
        // instance consumes its own i-th twin — a last-wins dictionary would hand
        // every instance the final option's span (all at 341:1).
        var rawFields = new Dictionary<string, List<(string HexValue, int Offset, int Length, long Mask)>>(StringComparer.Ordinal);
        var rawPosition = new Dictionary<string, int>(StringComparer.Ordinal);

        // Pass 1: index scalar *_raw arrays in document order. Multivalue keys (arrays
        // of arrays, e.g. repeated ip.addr or http2.header) and meta keys whose first
        // element is not a hex string (tcp.completeness) fail ParseRawArray and stay
        // out of the index; their instances are emitted inline by the array branches.
        foreach (var prop in obj.EnumerateObject())
        {
            string name = prop.Name;
            if (name.StartsWith("_", StringComparison.Ordinal))
                continue;

            if (name.EndsWith("_raw", StringComparison.Ordinal) && prop.Value.ValueKind == JsonValueKind.Array)
            {
                var data = ParseRawArray(prop.Value);
                if (data != null)
                {
                    string baseName = name[..^4];
                    if (!rawFields.TryGetValue(baseName, out var list))
                        rawFields[baseName] = list = new List<(string HexValue, int Offset, int Length, long Mask)>();
                    list.Add(data.Value);
                }
            }
        }

        // Pre-scan container bases: tshark's jsonraw writer keys a field with children
        // as "X_tree" when it carries a value and as the plain key "X" otherwise
        // (FT_NONE containers like tcp.analysis or http2.stream); repeated containers
        // collapse into an array of objects. Every such base absorbs its "X_raw" twin,
        // so the bases must be known before the emission pass reaches either key.
        // treeCount additionally records how many container instances each base has, so
        // the surplus-twin pass below can tell raws that no container will ever claim
        // from raws a later container is still going to consume.
        var containerBases = new HashSet<string>(StringComparer.Ordinal);
        var treeCount = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var prop in obj.EnumerateObject())
        {
            var v = prop.Value;
            if (v.ValueKind == JsonValueKind.Object ||
                (v.ValueKind == JsonValueKind.Array && v.GetArrayLength() > 0 &&
                 v[0].ValueKind == JsonValueKind.Object))
            {
                string name = prop.Name;
                string baseName = name.EndsWith("_tree", StringComparison.Ordinal) ? name[..^5] : name;
                containerBases.Add(baseName);
                treeCount[baseName] = treeCount.GetValueOrDefault(baseName) + 1;
            }
        }

        // Single emission pass in JSON key order — that order is the Wireshark GUI
        // row order (jsonraw, json, and pdml serialize the dissection tree in order).
        var seenProps = new HashSet<string>(StringComparer.Ordinal);

        foreach (var prop in obj.EnumerateObject())
        {
            string name = prop.Name;
            var val = prop.Value;

            string baseName = name.EndsWith("_raw", StringComparison.Ordinal) ? name[..^4]
                            : name.EndsWith("_tree", StringComparison.Ordinal) ? name[..^5]
                            : name;

            // Containers: a single object, or an array of objects (repeated instances).
            if (val.ValueKind == JsonValueKind.Object ||
                (val.ValueKind == JsonValueKind.Array && val.GetArrayLength() > 0 &&
                 val[0].ValueKind == JsonValueKind.Object))
            {
                seenProps.Add(name);

                // Rows Wireshark hides in the GUI (hide="yes") are dropped so the tree
                // matches what the Packet Details pane renders.
                if (pdmlHiddenNames != null && pdmlHiddenNames.Contains(baseName))
                    continue;

                bool isObjectArray = val.ValueKind == JsonValueKind.Array;
                int instanceCount = isObjectArray ? val.GetArrayLength() : 1;

                for (int i = 0; i < instanceCount; i++)
                {
                    JsonElement containerObj = isObjectArray ? val[i] : val;
                    if (containerObj.ValueKind != JsonValueKind.Object)
                        continue;

                    bool isTreeContainer = name.EndsWith("_tree", StringComparison.Ordinal);

                    var container = new ProtocolField
                    {
                        Name = isTreeContainer ? StripFieldName(baseName) : baseName,
                        DisplayValue = isTreeContainer ? name : string.Empty,
                        OriginalPdmlName = baseName,
                        ParentLayer = parentLayer,
                        ParentField = parentField,
                        IsUndecodedMarker = IsUndecodedMarkerKey(name) || name.Contains("not decoded", StringComparison.Ordinal),
                    };

                    // Anonymous containers (PFCP IEs like "F-SEID : SEID: 0x…, IPv4 …")
                    // arrive with their full rendered text as the JSON key; split it into
                    // Name/DisplayValue so the tree shows "F-SEID: SEID: 0x…, IPv4 …"
                    // instead of a dangling ":" appended to the whole string. Their PDML
                    // twin is <field name="" show="…">, so the reparse lookup keys them
                    // by ("", pos) and the tree node must carry an empty OriginalPdmlName
                    // to match (the rendered text itself changes with child byte edits).
                    bool isAnonymousContainer = false;
                    // Anonymous containers: tshark keys them with the full rendered
                    // showname ("Node ID : IPv4 address: 10.0.0.1") instead of an
                    // abbreviation. A '.' is NOT a discriminator — those shownames embed
                    // IPv4/time renders with dots — but spaces/colons/capitals are.
                    if (!isTreeContainer &&
                        (baseName.Contains(' ') || baseName.Contains(':') ||
                         baseName.Count(char.IsUpper) > 1))
                    {
                        if (TrySplitShowname(baseName) is var (anonName, anonValue))
                        {
                            container.Name = anonName;
                            container.DisplayValue = anonValue;
                        }
                        isAnonymousContainer = true;
                    }
                    if (isAnonymousContainer)
                        container.OriginalPdmlName = string.Empty;

                    // The container's own byte span: its i-th raw twin (duplicate JSON
                    // keys pair by position), or — for array-collapsed containers — the
                    // i-th element of the sibling raw array.
                    (string HexValue, int Offset, int Length, long Mask)? rawInfo = null;
                    if (rawFields.TryGetValue(baseName, out var rawList) && rawList.Count > 0)
                    {
                        int idx = isObjectArray ? i : rawPosition.GetValueOrDefault(baseName);
                        if (idx < rawList.Count)
                        {
                            rawInfo = rawList[idx];
                            if (!isObjectArray)
                                rawPosition[baseName] = idx + 1;
                        }
                    }
                    else if (isObjectArray && obj.TryGetProperty(baseName + "_raw", out var rawTwin) &&
                             rawTwin.ValueKind == JsonValueKind.Array && i < rawTwin.GetArrayLength() &&
                             ParseRawArray(rawTwin[i]) is var twinRaw && twinRaw != null)
                    {
                        rawInfo = twinRaw;
                    }

                    if (rawInfo != null)
                    {
                        container.Offset = rawInfo.Value.Offset + offsetBias;
                        container.Length = rawInfo.Value.Length;
                        container.LengthBits = MaskToLengthBits(rawInfo.Value.Mask, rawInfo.Value.Length);
                        container.RawBytes = ProtocolEditorService.ParseTsharkHexValue(rawInfo.Value.HexValue);
                        if (isTreeContainer)
                            container.DisplayValue = GetDisplayValue(displayObj, baseName) ?? rawInfo.Value.HexValue;

                        // Kind keys off the clean display value (BCD digits / colon MAC)
                        // set above — before the showname split below replaces it with a
                        // possibly vendor-prefixed text like "Xensource_6c:21:54 (…)".
                        container.Kind = ResolveFieldKind(pdmlTypeLookup, baseName,
                            rawInfo.Value.Offset, rawInfo.Value.Length,
                            container.DisplayValue ?? rawInfo.Value.HexValue);
                    }
                    else if (isAnonymousContainer && pdmlAnonSpans != null &&
                             pdmlAnonSpans.TryGetValue(baseName, out var anonSpan))
                    {
                        container.Offset = anonSpan.Pos + offsetBias;
                        container.Length = anonSpan.Size;
                        var bytes = parentLayer.ParentPacket?.EffectiveData;
                        if (bytes != null && container.Offset >= 0 &&
                            container.Offset <= bytes.Length - container.Length)
                        {
                            container.RawBytes = bytes.AsSpan(container.Offset, container.Length).ToArray();
                        }
                    }
                    else if (!isTreeContainer && rawInfo == null && pdmlNamePositions != null &&
                             pdmlNamePositions.TryGetValue(baseName, out var namePositions))
                    {
                        // Zero-span container (tshark's _ws.expert wrapper): no _raw twin
                        // carries an offset, so the label can only be found by looking the
                        // name up in PDML — Wireshark shows "Expert Info (Note/Sequence)",
                        // not the bare "_ws.expert" abbreviation.
                        foreach (int candidate in namePositions)
                        {
                            if (pdmlLookup != null &&
                                pdmlLookup.TryGetValue((baseName, candidate), out var zeroSpanShowname) &&
                                TrySplitShowname(zeroSpanShowname) is var (zsName, zsValue))
                            {
                                container.Name = zsName;
                                container.DisplayValue = zsValue;
                                break;
                            }
                        }
                    }

                    // Wireshark's friendly name replaces the stripped abbr when the PDML
                    // showname splits into "Name: value" (e.g. "Message Type: PFCP…").
                    if (rawInfo != null && container.Offset > 0 && pdmlLookup != null &&
                        pdmlLookup.TryGetValue((baseName, rawInfo.Value.Offset), out var showname) &&
                        TrySplitShowname(showname) is var (pdmName, pdmValue))
                    {
                        container.Name = pdmName;
                        container.DisplayValue = pdmValue;
                        container.HexPreferred = pdmValue.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
                    }

                    JsonElement displayChild = default;
                    if (displayObj.ValueKind == JsonValueKind.Object &&
                        displayObj.TryGetProperty(name, out var dc))
                    {
                        if (dc.ValueKind == JsonValueKind.Object && i == 0)
                            displayChild = dc;
                        else if (dc.ValueKind == JsonValueKind.Array && i < dc.GetArrayLength() &&
                                 dc[i].ValueKind == JsonValueKind.Object)
                            displayChild = dc[i];
                    }

                    ParseJsonrawObject(containerObj, displayChild, pdmlLookup, pdmlTypeLookup,
                        pdmlHiddenNames, pdmlHiddenPositions, container.Children, protocolPrefix, parentLayer, container, offsetBias, pdmlAnonSpans, pdmlNamePositions);
                    targetCollection.Add(container);
                }

                // Reassembly fields key duplicate "X_raw" twins next to a single "X_tree"
                // container (e.g. three ip.fragment_raw + one ip.fragment_tree). The container
                // above consumed only the first raw, so the surplus raws — real Wireshark
                // rows — would be lost to the leftovers filter; emit them as siblings.
                // Repeated containers instead arrive paired (two avp_raw + two avp_tree), and
                // there every raw already has an owner: rawPosition counts the containers
                // processed so far, so after the first of two it reads 1 of 2 and would
                // re-emit the second raw as a phantom childless sibling. Only raws past the
                // total container count are genuinely unclaimed.
                int rawConsumed = isObjectArray ? instanceCount : rawPosition.GetValueOrDefault(baseName);
                int surplusStart = Math.Max(rawConsumed, treeCount.GetValueOrDefault(baseName));
                if (rawFields.TryGetValue(baseName, out var twinRaws) && surplusStart < twinRaws.Count)
                {
                    for (int t = surplusStart; t < twinRaws.Count; t++)
                    {
                        var twin = twinRaws[t];
                        if (pdmlHiddenPositions != null &&
                            pdmlHiddenPositions.TryGetValue(baseName, out var twinHidden) &&
                            twinHidden.Contains(twin.Offset))
                            continue;

                        string twinDisplay = GetDisplayValue(displayObj, baseName) ?? twin.HexValue;
                        string twinName = StripFieldName(baseName);
                        if (pdmlLookup != null &&
                            pdmlLookup.TryGetValue((baseName, twin.Offset), out var twinShowname) &&
                            TrySplitShowname(twinShowname) is var (twName, twValue))
                        {
                            twinName = twName;
                            twinDisplay = twValue;
                        }

                        targetCollection.Add(new ProtocolField
                        {
                            Name = twinName,
                            DisplayValue = twinDisplay,
                            OriginalPdmlName = baseName,
                            HexPreferred = twinDisplay.StartsWith("0x", StringComparison.OrdinalIgnoreCase),
                            Offset = twin.Offset + offsetBias,
                            Length = twin.Length,
                            LengthBits = MaskToLengthBits(twin.Mask, twin.Length),
                            RawBytes = ProtocolEditorService.ParseTsharkHexValue(twin.HexValue),
                            Kind = ResolveFieldKind(pdmlTypeLookup, baseName, twin.Offset, twin.Length, twinDisplay),
                            ParentLayer = parentLayer,
                            ParentField = parentField,
                            IsUndecodedMarker = IsUndecodedMarkerKey(name) || twinName.Contains("not decoded", StringComparison.Ordinal),
                        });
                    }
                }
                continue;
            }

            // Raw twins: the field's own scalar/leaf rows.
            if (name.EndsWith("_raw", StringComparison.Ordinal) && val.ValueKind == JsonValueKind.Array)
            {
                seenProps.Add(name);

                // Consumed by the container twin at its JSON position: the merged
                // scalar+children row must appear exactly once in the tree.
                if (containerBases.Contains(baseName))
                    continue;

                bool isMulti = val.GetArrayLength() > 0 && val[0].ValueKind == JsonValueKind.Array;
                if (isMulti)
                {
                    // Fully-hidden names are dropped up-front; mixed names (some hidden
                    // instances, e.g. a hidden sccp.parameter_length twin next to visible
                    // ones) skip only the per-position hidden rows inside the loop.
                    if (pdmlHiddenNames != null && pdmlHiddenNames.Contains(baseName))
                        continue;

                    var multiHiddenPos = pdmlHiddenPositions != null && pdmlHiddenPositions.TryGetValue(baseName, out var mhp) ? mhp : null;

                    // Skip aggregate pseudo-fields (ip.addr, ip.host, udp.port, tcp.port)
                    // that bundle src+dst under one generic label — only in multivalue
                    // form: a scalar aggregate like eth.addr is a real GUI row.
                    string aggregatePart = baseName.Contains('.')
                        ? baseName[(baseName.LastIndexOf('.') + 1)..]
                        : baseName;
                    if (aggregatePart is "addr" or "host" or "port")
                        continue;

                    var displayArr = GetDisplayArray(displayObj, name);
                    string pdmlFieldName = baseName;
                    int elemIdx = 0;
                    foreach (var subArr in val.EnumerateArray())
                    {
                        var data = ParseRawArray(subArr);
                        if (data != null)
                        {
                            if (multiHiddenPos != null && multiHiddenPos.Contains(data.Value.Offset))
                            {
                                elemIdx++;
                                continue;
                            }
                            string displayName = StripFieldName(name);
                            if (displayName.EndsWith("_raw", StringComparison.Ordinal))
                                displayName = displayName[..^4];

                            string displayVal = GetDisplayArrayItem(displayArr, elemIdx) ?? data.Value.HexValue;

                            if (pdmlLookup != null &&
                                pdmlLookup.TryGetValue((pdmlFieldName, data.Value.Offset), out var mvShowname) &&
                                TrySplitShowname(mvShowname) is var (mvName, mvValue))
                            {
                                displayName = mvName;
                                displayVal = mvValue;
                            }

                            targetCollection.Add(new ProtocolField
                            {
                                Name = displayName,
                                DisplayValue = displayVal,
                                OriginalPdmlName = pdmlFieldName,
                                HexPreferred = displayVal.StartsWith("0x", StringComparison.OrdinalIgnoreCase),
                                Offset = data.Value.Offset + offsetBias,
                                Length = data.Value.Length,
                                LengthBits = MaskToLengthBits(data.Value.Mask, data.Value.Length),
                                RawBytes = ProtocolEditorService.ParseTsharkHexValue(data.Value.HexValue),
                                Kind = ResolveFieldKind(pdmlTypeLookup, pdmlFieldName, data.Value.Offset, data.Value.Length, displayVal),
                                ParentLayer = parentLayer,
                                ParentField = parentField,
                                IsUndecodedMarker = IsUndecodedMarkerKey(name) || displayName.Contains("not decoded", StringComparison.Ordinal),
                            });
                        }
                        elemIdx++;
                    }
                    continue;
                }

                // Scalar raw — the common leaf (ip.src, udp.srcport, per.extension_bit, …).
                var raw = ParseRawArray(val);
                if (raw == null)
                {
                    // First element is a number, not hex, so there is no byte range — but
                    // Wireshark still renders such fields (tcp.completeness, and every
                    // expert-info row: ip.ttl.too_small, _ws.expert.severity/group). They
                    // carry no bytes, so fall back to a text leaf; PDML is the only place
                    // their label and value exist. Rows Wireshark hides stay hidden, and a
                    // field PDML never saw (no showname) is still dropped as before.
                    bool expertHidden = pdmlHiddenNames != null && pdmlHiddenNames.Contains(baseName);
                    bool expertKnown = pdmlLookup != null && pdmlLookup.ContainsKey((baseName, 0));
                    if (expertKnown && !expertHidden)
                        EmitTextLeaf(baseName, string.Empty);
                    continue;
                }

                if (pdmlHiddenNames != null && pdmlHiddenNames.Contains(baseName))
                    continue; // fully-hidden name — drop every instance

                var scalarHiddenPos = pdmlHiddenPositions != null && pdmlHiddenPositions.TryGetValue(baseName, out var shp) ? shp : null;
                if (scalarHiddenPos != null && scalarHiddenPos.Contains(raw.Value.Offset))
                    continue; // per-instance hidden twin, e.g. http.request.line HOST/USER-AGENT

                var displayVal2 = GetDisplayValue(displayObj, baseName) ?? raw.Value.HexValue;
                string fieldName = StripFieldName(baseName);

                if (pdmlLookup != null &&
                    pdmlLookup.TryGetValue((baseName, raw.Value.Offset), out var leafShowname) &&
                    TrySplitShowname(leafShowname) is var (leafName, leafValue))
                {
                    fieldName = leafName;
                    displayVal2 = leafValue;
                }

                // Wireshark renders this row as "UDP payload (N bytes)".
                bool showHex = true;
                var kind2 = ResolveFieldKind(pdmlTypeLookup, baseName, raw.Value.Offset, raw.Value.Length, displayVal2);
                if (fieldName == "payload" && protocolPrefix is "udp" or "tcp")
                {
                    fieldName = $"{protocolPrefix.ToUpperInvariant()} payload";
                    displayVal2 = $"({raw.Value.Length} {(raw.Value.Length == 1 ? "byte" : "bytes")})";
                    showHex = false;
                    // Whole payload blobs are not edited as a single numeric value.
                    kind2 = FieldKind.Unknown;
                }

                targetCollection.Add(new ProtocolField
                {
                    Name = fieldName,
                    DisplayValue = displayVal2,
                    OriginalPdmlName = baseName,
                    HexPreferred = displayVal2.StartsWith("0x", StringComparison.OrdinalIgnoreCase),
                    Offset = raw.Value.Length > 0 ? raw.Value.Offset + offsetBias : -1,
                    Length = raw.Value.Length,
                    LengthBits = MaskToLengthBits(raw.Value.Mask, raw.Value.Length),
                    RawBytes = ProtocolEditorService.ParseTsharkHexValue(raw.Value.HexValue),
                    Kind = kind2,
                    ParentLayer = parentLayer,
                    ParentField = parentField,
                    ShowHex = showHex,
                    IsUndecodedMarker = IsUndecodedMarkerKey(baseName) || fieldName.Contains("not decoded", StringComparison.Ordinal),
                });
                continue;
            }

            // Remaining array shapes and plain scalars carry no byte rows.
            seenProps.Add(name);
            if (val.ValueKind != JsonValueKind.Array)
            {
                // hf_text_only pseudo-text fields serialize as plain scalar keys and
                // render as position-less text leaves (uncolored, like in Wireshark).
                if (pdmlHiddenNames != null && pdmlHiddenNames.Contains(baseName))
                    continue;

                EmitTextLeaf(baseName, val.ValueKind == JsonValueKind.String ? val.GetString() ?? string.Empty : val.GetRawText());
            }
        }

        // A field Wireshark renders as a position-less text row: its label comes from the
        // PDML showname, and any real bytes come from pdmlAnonSpans (anonymous leaves
        // such as an SSDP request's "\r\n" blank line have no _raw twin). Used both for
        // hf_text_only scalars and for _raw arrays whose first element is not a hex
        // string (tcp.completeness, and the expert-info rows under _ws.expert).
        void EmitTextLeaf(string leafName, string text)
        {
            string textName = StripFieldName(leafName);
            if (pdmlLookup != null &&
                pdmlLookup.TryGetValue((leafName, 0), out var textShowname))
            {
                if (TrySplitShowname(textShowname) is var (txtName, txtValue))
                {
                    textName = txtName;
                    if (text.Length == 0) text = txtValue;
                }
                else if (text.Length == 0)
                {
                    // No "Name: value" split (e.g. the expert row showname
                    // "\"Time To Live\" only 1"), so the whole showname is the text.
                    text = textShowname;
                }
            }

            int leafPos = -1;
            int leafLen = 0;
            byte[]? leafBytes = null;
            if (pdmlAnonSpans != null &&
                pdmlAnonSpans.TryGetValue(leafName, out var leafSpan))
            {
                leafPos = leafSpan.Pos + offsetBias;
                leafLen = leafSpan.Size;
                var packetBytes = parentLayer.ParentPacket?.EffectiveData;
                if (packetBytes != null &&
                    leafPos >= 0 && leafPos <= packetBytes.Length - leafLen)
                {
                    leafBytes = packetBytes.AsSpan(leafPos, leafLen).ToArray();
                }
            }

            targetCollection.Add(new ProtocolField
            {
                Name = textName,
                DisplayValue = text,
                OriginalPdmlName = leafName,
                Offset = leafPos,
                Length = leafLen,
                RawBytes = leafBytes ?? [],
                ParentLayer = parentLayer,
                ParentField = parentField,
                ShowHex = false,
            });
        }

        // Defensive tail: raws no emission branch visited (should be none — every prop
        // above was consumed) are appended in byte order so no field is ever lost.
        // Aggregate aliases are excluded so hidden rows are not resurrected.
        var leftovers = rawFields
            .Where(kvp => !seenProps.Contains(kvp.Key) && !seenProps.Contains(kvp.Key + "_raw")
                          && !containerBases.Contains(kvp.Key) && !IsRedundantAlias(kvp.Key))
            .OrderBy(kvp => kvp.Value[0].Offset);

        foreach (var left in leftovers)
        {
            var rawLeft = left.Value[0];
            var leftDisplayVal = GetDisplayValue(displayObj, left.Key) ?? rawLeft.HexValue;
            string leftName = StripFieldName(left.Key);

            if (pdmlLookup != null &&
                pdmlLookup.TryGetValue((left.Key, rawLeft.Offset), out var leftShowname) &&
                TrySplitShowname(leftShowname) is var (lName, lValue))
            {
                leftName = lName;
                leftDisplayVal = lValue;
            }

            targetCollection.Add(new ProtocolField
            {
                Name = leftName,
                DisplayValue = leftDisplayVal,
                OriginalPdmlName = left.Key,
                HexPreferred = leftDisplayVal.StartsWith("0x", StringComparison.OrdinalIgnoreCase),
                Offset = rawLeft.Offset + offsetBias,
                Length = rawLeft.Length,
                LengthBits = MaskToLengthBits(rawLeft.Mask, rawLeft.Length),
                RawBytes = ProtocolEditorService.ParseTsharkHexValue(rawLeft.HexValue),
                Kind = ResolveFieldKind(pdmlTypeLookup, left.Key, rawLeft.Offset, rawLeft.Length, leftDisplayVal),
                ParentLayer = parentLayer,
                ParentField = parentField,
                IsUndecodedMarker = IsUndecodedMarkerKey(left.Key) || leftName.Contains("not decoded", StringComparison.Ordinal),
            });
        }
    }

    /// <summary>
    /// True for Wireshark aggregate alias fields that duplicate the specific src/dst
    /// variants of the same bytes (e.g. ip.addr, ip.host, ip.src_host, udp.port).
    /// The concrete fields (ip.src, ip.dst, udp.srcport, udp.dstport) are emitted instead.
    /// </summary>
    private static bool IsRedundantAlias(string baseName)
    {
        string part = baseName.Contains('.')
            ? baseName[(baseName.LastIndexOf('.') + 1)..]
            : baseName;
        return part is "addr" or "host" or "port" or "src_host" or "dst_host";
    }

    /// <summary>
    /// Maps a jsonraw property key to its human-readable value in the parallel display object.
    /// jsonraw key "ip.src_raw" ↔ json key "ip.src".
    /// </summary>
    private static string? GetDisplayValue(JsonElement displayObj, string rawKey)
    {
        if (displayObj.ValueKind != JsonValueKind.Object)
            return null;

        string key = rawKey;
        if (key.EndsWith("_raw", StringComparison.Ordinal))
            key = key[..^4];
        else if (key.EndsWith("_tree", StringComparison.Ordinal))
            key = key[..^5];

        if (displayObj.TryGetProperty(key, out var v))
        {
            if (v.ValueKind == JsonValueKind.String)
                return v.GetString();
            if (v.ValueKind == JsonValueKind.Number)
                return v.GetRawText();
        }
        return null;
    }

    /// <summary>
    /// Container keys are identical between the jsonraw and json outputs (both use the
    /// same "_tree" suffix / descriptive title), so the sub-object is looked up by the
    /// exact same key rather than the stripped field name.
    /// </summary>
    private static JsonElement GetDisplayObject(JsonElement displayObj, string rawKey)
    {
        if (displayObj.ValueKind != JsonValueKind.Object)
            return default;

        if (displayObj.TryGetProperty(rawKey, out var v) && v.ValueKind == JsonValueKind.Object)
            return v;
        return default;
    }

    // For a field present multiple times (e.g. ip.addr), jsonraw stores an array of
    // [hex,offset,length,...] arrays while json stores an array of readable strings.
    private static JsonElement GetDisplayArray(JsonElement displayObj, string rawKey)
    {
        if (displayObj.ValueKind != JsonValueKind.Object)
            return default;

        string key = rawKey;
        if (key.EndsWith("_raw", StringComparison.Ordinal))
            key = key[..^4];

        if (displayObj.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Array)
            return v;
        return default;
    }

    private static string? GetDisplayArrayItem(JsonElement displayArr, int index)
    {
        if (displayArr.ValueKind != JsonValueKind.Array || index >= displayArr.GetArrayLength())
            return null;
        var item = displayArr[index];
        if (item.ValueKind == JsonValueKind.String)
            return item.GetString();
        if (item.ValueKind == JsonValueKind.Number)
            return item.GetRawText();
        return null;
    }

    private static (string HexValue, int Offset, int Length, long Mask)? ParseRawArray(JsonElement arr)
    {
        if (arr.GetArrayLength() < 3) return null;

        var elements = arr.EnumerateArray().ToArray();
        if (elements.Length < 3) return null;

        string? hexVal = elements[0].ValueKind == JsonValueKind.String
            ? elements[0].GetString()
            : null;

        int offset = elements[1].ValueKind == JsonValueKind.Number
            ? elements[1].GetInt32() : 0;

        int length = elements[2].ValueKind == JsonValueKind.Number
            ? elements[2].GetInt32() : 0;

        long mask = elements.Length > 3 && elements[3].ValueKind == JsonValueKind.Number
            ? elements[3].GetInt64() : 0;

        if (hexVal == null) return null;

        return (hexVal, offset, length, mask);
    }

    /// <summary>
    /// Maps tshark's jsonraw bitmask to <see cref="ProtocolField.LengthBits"/>:
    /// -1 for byte-aligned fields, the covered bit count for bit-extracted
    /// sub-fields (eth.src.lg, ip.dsfield.dscp, tcp.flags.*, …). A mask that
    /// covers the whole byte span still means a byte-aligned field.
    /// </summary>
    private static int MaskToLengthBits(long mask, int length)
    {
        if (mask <= 0 || length <= 0) return -1;
        int bits = BitOperations.PopCount((ulong)mask);
        return bits >= length * 8 ? -1 : bits;
    }

    private static string StripFieldName(string fieldName)
    {
        if (string.IsNullOrEmpty(fieldName)) return fieldName;
        var dot = fieldName.LastIndexOf('.');
        return dot >= 0 ? fieldName.Substring(dot + 1) : fieldName;
    }

    // ────────────────────────────────────────────────────────
    // PDML showname enrichment
    // Parses tshark -T pdml into per-packet (fieldName, byteOffset) -> showname lookups,
    // then overlays Wireshark's friendly names and value_string expansions onto fields.
    // ────────────────────────────────────────────────────────

    private static List<PdmlData> ParsePdmlToLookup(string pdmlText)
    {
        var result = new List<PdmlData>();
        var doc = XDocument.Parse(pdmlText);

        if (doc.Root == null)
            return result;

        foreach (var packet in doc.Root.Elements("packet"))
        {
            var protoShowNames = new Dictionary<(string, int), string>();
            var fieldLookup = new Dictionary<(string, int), string>();
            var typeLookup = new Dictionary<(string, int), string>();
            var protoPositions = new Dictionary<string, List<int>>();
            var protoBiases = new Dictionary<string, List<int>>();
            var hiddenNames = new HashSet<string>();
            var hiddenPositions = new Dictionary<string, HashSet<int>>(StringComparer.Ordinal);
            var allPositions = new Dictionary<string, HashSet<int>>(StringComparer.Ordinal);
            var anonSpans = new Dictionary<string, (int Pos, int Size)>(StringComparer.Ordinal);
            var valueLookup = new Dictionary<(string, int), string>();

            // Track IP/TCP reassembly: when a proto contains a reassembly-indicator
            // field (ip.fragments, tcp.segments), descendant protos report offsets
            // relative to the reassembly payload buffer. The base is the container's
            // frame offset + its header length, and the region [base, base+payloadLen)
            // covers every reassembly-relative descendant; only positions past the
            // region's end have returned to true frame offsets.
            int reassemblyBase = -1;
            int reassemblyEnd = -1;

            foreach (var proto in packet.Elements("proto"))
            {
                string name = proto.Attribute("name")?.Value ?? "";
                if (string.IsNullOrEmpty(name))
                    continue;

                string? posStr = proto.Attribute("pos")?.Value;
                if (!int.TryParse(posStr, out int pos))
                {
                    // tshark wraps the data pseudo-protocol in a pos-less
                    // <proto name="fake-field-wrapper">, but its child fields
                    // (data.data, data.len) carry real positions — without them
                    // the post-edit refresh lookup can never match those nodes.
                    CollectPdmlFields(proto, fieldLookup, typeLookup, hiddenPositions, allPositions, anonSpans, valueLookup);
                    continue;
                }

                string showname = proto.Attribute("showname")?.Value ?? "";

                int bias = 0;
                if (reassemblyBase >= 0 && pos < reassemblyEnd)
                {
                    bias = reassemblyBase;
                }
                else if (reassemblyBase >= 0 && pos >= reassemblyEnd)
                {
                    reassemblyBase = -1;
                    reassemblyEnd = -1;
                }

                if (!protoPositions.TryGetValue(name, out var list))
                {
                    list = [];
                    protoPositions[name] = list;
                }
                list.Add(pos + bias);

                if (!protoBiases.TryGetValue(name, out var biasList))
                {
                    biasList = [];
                    protoBiases[name] = biasList;
                }
                biasList.Add(bias);

                if (!string.IsNullOrEmpty(showname))
                    protoShowNames[(name, pos + bias)] = showname;

                CollectPdmlFields(proto, fieldLookup, typeLookup, hiddenPositions, allPositions, anonSpans, valueLookup);

                if (reassemblyBase < 0 && HasReassemblyField(proto, name))
                {
                    int hdrLen = GetProtocolHeaderLen(proto, name);
                    if (hdrLen > 0)
                    {
                        reassemblyBase = pos + hdrLen;
                        int payloadLen = GetReassemblyPayloadLen(proto, name);
                        reassemblyEnd = payloadLen > 0 ? reassemblyBase + payloadLen : reassemblyBase;
                    }
                }
            }

            // A field name whose every instance is hidden is dropped entirely; a name
            // with only some hidden twins (e.g. http.request.line where the HOST and
            // USER-AGENT duplicates are hidden but MAN/MX/ST are visible rows) keeps its
            // visible instances, filtered per (name, pos) during jsonraw emission.
            foreach (var (name, hiddenSet) in hiddenPositions)
            {
                if (allPositions.TryGetValue(name, out var allSet) && hiddenSet.Count >= allSet.Count)
                    hiddenNames.Add(name);
            }

            result.Add(new PdmlData(protoShowNames, fieldLookup, typeLookup,
                                    protoPositions, protoBiases, hiddenNames, hiddenPositions,
                                    anonSpans.Count > 0 ? anonSpans : null,
                                    reassemblyBase >= 0 ? (reassemblyBase, reassemblyEnd - reassemblyBase) : null,
                                    valueLookup,
                                    allPositions));
        }

        return result;
    }

    private static void CollectPdmlFields(
        XElement parent,
        Dictionary<(string, int), string> lookup,
        Dictionary<(string, int), string> typeLookup,
        Dictionary<string, HashSet<int>> hiddenPositions,
        Dictionary<string, HashSet<int>> allPositions,
        Dictionary<string, (int Pos, int Size)>? anonSpans = null,
        Dictionary<(string, int), string>? valueLookup = null)
    {
        foreach (var field in parent.Elements("field"))
        {
            string name = field.Attribute("name")?.Value ?? "";
            string showname = field.Attribute("showname")?.Value ?? "";
            string show = field.Attribute("show")?.Value ?? "";
            string type = field.Attribute("type")?.Value ?? "";
            string posStr = field.Attribute("pos")?.Value ?? "0";

            if (int.TryParse(posStr, out int pos))
            {
                if (!string.IsNullOrEmpty(name))
                {
                    if (!allPositions.TryGetValue(name, out var allSet))
                        allPositions[name] = allSet = new HashSet<int>();
                    allSet.Add(pos);
                    if (field.Attribute("hide")?.Value == "yes")
                    {
                        if (!hiddenPositions.TryGetValue(name, out var hidSet))
                            hiddenPositions[name] = hidSet = new HashSet<int>();
                        hidSet.Add(pos);
                    }
                }

                if (string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(show))
                {
                    // Anonymous container (e.g. a PFCP IE header emitted as
                    // <field name="" show="F-SEID : SEID: 0x…, IPv4 …">): its rendered
                    // text changes with its children's bytes, so match it by the
                    // stable (empty-name, pos) key instead — see ParseJsonrawObject.
                    lookup[("", pos)] = show;

                    // Anonymous spans keyed by show text. tshark keys an anonymous
                    // container by its rendered text and gives it no _raw twin, so its
                    // byte span is only knowable from PDML — both leaves (an SSDP "\r\n"
                    // blank line) and containers (a PFCP IE header) need it, otherwise
                    // they render with a zero-length span: no hex highlight, not editable,
                    // unreachable by hex→tree sync.
                    if (anonSpans != null &&
                        int.TryParse(field.Attribute("size")?.Value ?? "0", out int spanSize) && spanSize > 0)
                    {
                        anonSpans[show] = (pos, spanSize);
                    }
                }
                else if (!string.IsNullOrEmpty(showname))
                {
                    lookup[(name, pos)] = showname;
                }
                if (!string.IsNullOrEmpty(type))
                    typeLookup[(name, pos)] = type;

                if (valueLookup != null && !string.IsNullOrEmpty(name))
                {
                    string val = field.Attribute("value")?.Value ?? "";
                    if (!string.IsNullOrEmpty(val))
                        valueLookup[(name, pos)] = val;
                }
            }

            CollectPdmlFields(field, lookup, typeLookup, hiddenPositions, allPositions, anonSpans, valueLookup);
        }

        foreach (var subProto in parent.Elements("proto"))
            CollectPdmlFields(subProto, lookup, typeLookup, hiddenPositions, allPositions, anonSpans, valueLookup);
    }

    /// <summary>
    /// True when a proto element contains a reassembly-indicator field (ip.fragments,
    /// tcp.segments, or {name}.reassembled.*) meaning its descendant protos are
    /// dissected from a reassembly buffer with offsets relative to the payload start.
    /// </summary>
    private static bool HasReassemblyField(XElement proto, string protoName)
    {
        string fragField = $"{protoName}.fragments";
        string segField = $"{protoName}.segments";
        string reassPrefix = $"{protoName}.reassembled";
        foreach (var field in proto.Elements("field"))
        {
            string fn = field.Attribute("name")?.Value ?? "";
            if (fn == fragField || fn == segField ||
                fn.StartsWith(reassPrefix, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Reads the protocol header length from the PDML proto element (e.g. ip.hdr_len
    /// show="20" or tcp.hdr_len). Falls back to well-known defaults for IP/TCP.
    /// </summary>
    private static int GetProtocolHeaderLen(XElement proto, string protoName)
    {
        string hdrField = $"{protoName}.hdr_len";
        foreach (var field in proto.Elements("field"))
        {
            if (field.Attribute("name")?.Value == hdrField)
            {
                string show = field.Attribute("show")?.Value ?? "";
                if (int.TryParse(show, out int len) && len > 0)
                    return len;
            }
        }
        return protoName switch
        {
            "ip" => 20,
            "ipv6" => 40,
            _ => 0
        };
    }

    /// <summary>
    /// Reads the reassembly payload length from the proto's {proto}.fragments /
    /// {proto}.segments field size attribute, falling back to the
    /// {proto}.reassembled.length value. Returns 0 when unknown.
    /// </summary>
    private static int GetReassemblyPayloadLen(XElement proto, string protoName)
    {
        string fragField = $"{protoName}.fragments";
        string segField = $"{protoName}.segments";
        string reassLenField = $"{protoName}.reassembled.length";
        foreach (var field in proto.Elements("field"))
        {
            string fn = field.Attribute("name")?.Value ?? "";
            if (fn == fragField || fn == segField)
            {
                string size = field.Attribute("size")?.Value ?? "";
                if (int.TryParse(size, out int len) && len > 0)
                    return len;
            }
            if (fn == reassLenField)
            {
                string show = field.Attribute("show")?.Value ?? "";
                if (int.TryParse(show, out int len) && len > 0)
                    return len;
            }
        }
        return 0;
    }

    /// <summary>
    /// Splits a PDML showname like "Message Type: PFCP Session Establishment Request (50)"
    /// into ("Message Type", "PFCP Session Establishment Request (50)").
    /// Returns null for bitfield lines containing " = " before the first ": ".
    /// </summary>
    internal static (string Name, string Value)? TrySplitShowname(string showname)
    {
        // Wireshark renders containers both as "Name: value" (fields) and
        // "Name : value" (anonymous IEs, with spaces around the colon); trimming
        // the name keeps matches ("Node ID") stable against either form.
        int colonIdx = showname.IndexOf(": ", StringComparison.Ordinal);
        if (colonIdx < 0)
            return null;

        string name = showname[..colonIdx].TrimEnd();
        string value = showname[(colonIdx + 2)..];

        if (name.Contains(" = ", StringComparison.Ordinal))
        {
            // Bitfields render as "<bit pattern> = <Label>: <value>" (e.g. "0100 .... =
            // Version: 4"). The label Wireshark shows is the text after " = ", not the
            // leading bit pattern, so take it — but only when the head really is a bit
            // pattern, so any other " = " shape keeps falling back to the field
            // abbreviation rather than being split into something misleading.
            int eqIdx = name.LastIndexOf(" = ", StringComparison.Ordinal);
            string head = name[..eqIdx];
            string label = name[(eqIdx + 3)..].Trim();
            if (label.Length == 0 || !head.All(static c => c is '0' or '1' or '#' or '.' or ' '))
                return null;
            return (label, value);
        }

        return (name, value);
    }

    // ────────────────────────────────────────────────────────
    // Field kind resolution (type → editability)
    // ────────────────────────────────────────────────────────

    /// <summary>
    /// Resolves the editable <see cref="FieldKind"/> of a field: prefers the PDML
    /// FT_* type, falling back to a heuristic based on byte length when PDML is absent.
    /// </summary>
    private static FieldKind ResolveFieldKind(
        Dictionary<(string Name, int Pos), string>? pdmlTypeLookup,
        string fieldName,
        int offset,
        int length,
        string? displayValue)
    {
        if (pdmlTypeLookup != null &&
            pdmlTypeLookup.TryGetValue((fieldName, offset), out var pdmlType))
        {
            var mapped = MapPdmlType(pdmlType);
            if (mapped != FieldKind.Unknown)
                return mapped;
        }

        return InferFieldKind(fieldName, length, displayValue);
    }

    private static FieldKind MapPdmlType(string pdmlType) => pdmlType switch
    {
        "FT_UINT8" or "FT_UINT16" or "FT_UINT24" or "FT_UINT32" or
        "FT_UINT40" or "FT_UINT48" or "FT_UINT56" or "FT_UINT64" or
        "FT_UINT_BYTES" or "FT_BOOLEAN" => FieldKind.UInt,
        "FT_INT8" or "FT_INT16" or "FT_INT24" or "FT_INT32" or
        "FT_INT40" or "FT_INT48" or "FT_INT56" or "FT_INT64" => FieldKind.Int,
        "FT_IPv4" => FieldKind.IPv4,
        "FT_IPv6" => FieldKind.IPv6,
        "FT_ETHER" => FieldKind.Mac,
        "FT_BACD" => FieldKind.Bcd,
        "FT_STRING" or "FT_STRINGZ" or "FT_STRINGZPAD" or "FT_UINT_STRING" => FieldKind.String,
        _ => FieldKind.Unknown,
    };

    /// <summary>
    /// Heuristic when PDML provides no type: BCD digit fields first (terminal
    /// field name imsi/imei/imeisv/msisdn, 4-16 bytes, all-digit display);
    /// a dotted string of length 4 is IPv4; 16 bytes with a colon is IPv6;
    /// a colon-hex display of 4/6/8 groups is a MAC; anything else of 1-8
    /// bytes is a plain unsigned integer.
    /// </summary>
    private static FieldKind InferFieldKind(string fieldName, int length, string? displayValue)
    {
        // User ID sub-fields NAI/SUPI/GPSI/PEI are TS 29.571 string types (ASCII with
        // TS 23.003 prefixes), not BCD digits; SUPI/GPSI can be all-digit yet are strings.
        const string pfcpUserIdPrefix = "pfcp.user_id.";
        if (fieldName.StartsWith(pfcpUserIdPrefix, StringComparison.Ordinal) &&
            fieldName[pfcpUserIdPrefix.Length..] is "nai" or "supi" or "gpsi" or "pei")
            return FieldKind.String;

        if (IsBcdShapedField(fieldName, length, displayValue))
            return FieldKind.Bcd;
        if (length == 4 && displayValue != null && displayValue.Split('.').Length == 4)
            return FieldKind.IPv4;
        if (length == 16 && displayValue != null && displayValue.Contains(':'))
            return FieldKind.IPv6;
        if (IsMacShapedField(length, displayValue))
            return FieldKind.Mac;

        return length is >= 1 and <= 8 ? FieldKind.UInt : FieldKind.Unknown;
    }

    /// <summary>
    /// 3GPP BCD digit fields (IMSI/IMEI/IMEISV/MSISDN) expose no PDML type but are
    /// unambiguous by their terminal field name. The all-digit display excludes
    /// fields tshark renders with '?' (nas-5gs unknown-digit IMEISV) and the 4-16
    /// byte span excludes 1-byte length_of_/flag siblings.
    /// </summary>
    private static bool IsBcdShapedField(string fieldName, int length, string? displayValue)
    {
        if (length is < 4 or > 16 || displayValue is null || displayValue.Length == 0)
            return false;

        int dot = fieldName.LastIndexOf('.');
        string last = dot >= 0 ? fieldName[(dot + 1)..] : fieldName;
        if (!last.Equals("imsi", StringComparison.OrdinalIgnoreCase) &&
            !last.Equals("imei", StringComparison.OrdinalIgnoreCase) &&
            !last.Equals("imeisv", StringComparison.OrdinalIgnoreCase) &&
            !last.Equals("msisdn", StringComparison.OrdinalIgnoreCase))
            return false;

        return displayValue.All(char.IsAsciiDigit);
    }

    /// <summary>
    /// Colon-separated 2-hex-digit groups of even byte count in 4-8 bytes: real
    /// 6-byte MACs, 8-byte EUI forms (ipv6.slaac_mac), and 4-byte octet blobs
    /// tshark shows as MACs (NGAP transport address / TEID). Plain numeric
    /// displays never match, so numeric fields stay UInt.
    /// </summary>
    private static bool IsMacShapedField(int length, string? displayValue)
    {
        if (displayValue is null || length is < 4 or > 8)
            return false;

        var parts = displayValue.Split(':');
        return parts.Length is 4 or 6 or 8 &&
               parts.All(p => p.Length == 2 &&
                              Uri.IsHexDigit(p[0]) && Uri.IsHexDigit(p[1]));
    }
}
