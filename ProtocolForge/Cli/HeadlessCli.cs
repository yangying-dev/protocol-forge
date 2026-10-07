using System.Globalization;
using ProtocolForge.Models;
using ProtocolForge.Services;

namespace ProtocolForge.Cli;

/// <summary>
/// Headless entry points over the same services the GUI uses. The edit path routes
/// through <see cref="EditTransactionService"/> rather than touching packet bytes, so
/// a scripted edit gets the identical Verify-Before-Commit guarantee the GUI gives:
/// tshark must reparse the candidate frame and confirm the new value landed, or
/// nothing is written.
///
/// Exit codes: 0 success, 1 the operation failed or a verification aborted,
/// 2 bad usage.
/// </summary>
public static class HeadlessCli
{
    public const int ExitOk = 0;
    public const int ExitFailed = 1;
    public const int ExitUsage = 2;

    public static IReadOnlySet<string> VerbSet { get; } =
        new HashSet<string>(StringComparer.Ordinal) { "validate", "edit", "send", "stats" };

    public static int PrintUsage()
    {
        Console.Error.WriteLine("""
            ProtocolForge headless CLI

            Usage:
              protocolforge validate <capture.pcap> [--filter <display-filter>]
              protocolforge edit <capture.pcap> --offset <n> --length <n> --hex <hex> --out <out.pcap>
              protocolforge send <capture.pcap> --interface <name> [--count <n>] [--interval <ms>] [--all]
              protocolforge stats <capture.pcap> --tap <tap> [--filter <display-filter>]

            Exit codes: 0 ok, 1 failed or verification aborted, 2 bad usage.
            """);
        return ExitUsage;
    }

    public static async Task<int> RunAsync(string[] args, TextWriter output)
    {
        if (args.Length == 0)
            return PrintUsage();

        string command = args[0];
        var rest = args.Skip(1).ToArray();

        return command switch
        {
            "validate" => await ValidateAsync(rest, output),
            "edit" => await EditAsync(rest, output),
            "send" => await SendAsync(rest, output),
            "stats" => await StatsAsync(rest, output),
            _ => PrintUsage(),
        };
    }

    private static bool TryParseHex(string text, out byte[] bytes)
    {
        bytes = [];
        string hex = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? text[2..] : text;
        if (hex.Length == 0 || hex.Length % 2 != 0)
            return false;
        try
        {
            bytes = Convert.FromHexString(hex);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static async Task<int> ValidateAsync(string[] args, TextWriter output)
    {
        if (args.Length < 1)
            return PrintUsage();
        string path = args[0];
        string? filter = ArgValue(args, "--filter");

        var ingest = new PcapIngestService();
        var export = new PcapExportService();
        var tshark = new TsharkService(ingest, export);

        var detection = TsharkService.DetectTshark();
        if (!detection.Ok)
        {
            output.WriteLine($"tshark unavailable: {detection.LocalizedMessage}");
            return ExitFailed;
        }

        var read = await ingest.ReadPacketsAsync(path);
        output.WriteLine($"packets: {read.Packets.Count}");
        output.WriteLine($"linktype: {read.LinkLayerType}");
        output.WriteLine($"snaplen: {read.Snaplen}");
        output.WriteLine($"endianness: {(read.IsLittleEndian ? "little" : "big")}");
        output.WriteLine($"timestamp resolution: {(read.IsNanoSeconds ? "nanoseconds" : "microseconds")}");

        var doc = new PacketDocument { FilePath = path };
        if (!string.IsNullOrWhiteSpace(filter))
        {
            await tshark.LoadPcapAsync(doc, path, null, filter);
            output.WriteLine($"filtered rows: {doc.Packets.Count} (filter: {filter})");
        }

        // Walking one frame end-to-end is the only way to prove the tree, the hex
        // offsets and the reparse all agree without a GUI.
        if (read.Packets.Count > 0)
        {
            var (timestamp, data) = read.Packets[0];
            var packet = new Packet { Index = 0, Timestamp = timestamp, RawData = data };
            bool parsed = await tshark.ParsePacketFromPcapFileAsync(packet, path);
            output.WriteLine($"frame 1 dissected: {parsed}, layers: {packet.Layers.Count}");
            foreach (var layer in packet.Layers)
                output.WriteLine($"  {layer.ProtocolName}");
        }

        return ExitOk;
    }

    private static async Task<int> EditAsync(string[] args, TextWriter output)
    {
        if (args.Length < 1)
            return PrintUsage();
        string path = args[0];
        string? outPath = ArgValue(args, "--out");
        string? hexArg = ArgValue(args, "--hex");

        if (outPath is null || hexArg is null ||
            !int.TryParse(ArgValue(args, "--offset"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int offset) ||
            !int.TryParse(ArgValue(args, "--length"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int length))
        {
            output.WriteLine("edit requires --offset, --length, --hex and --out");
            return ExitUsage;
        }

        if (!TryParseHex(hexArg, out byte[] newValue))
        {
            output.WriteLine($"--hex is not an even-length hex string: {hexArg}");
            return ExitUsage;
        }

        if (newValue.Length != length)
        {
            output.WriteLine($"--length {length} does not match the {newValue.Length} bytes supplied by --hex");
            return ExitUsage;
        }

        var ingest = new PcapIngestService();
        var export = new PcapExportService();
        var tshark = new TsharkService(ingest, export);
        var tx = new EditTransactionService(export, tshark);

        var read = await ingest.ReadPacketsAsync(path);
        if (read.Packets.Count == 0)
        {
            output.WriteLine("capture has no packets");
            return ExitFailed;
        }

        // Which packet to edit: default to the only frame, else require --packet.
        int index = 0;
        if (read.Packets.Count > 1)
        {
            string? p = ArgValue(args, "--packet");
            if (p is null)
            {
                output.WriteLine("capture has multiple frames; pass --packet <n> (1-based)");
                return ExitUsage;
            }
            if (!int.TryParse(p, NumberStyles.Integer, CultureInfo.InvariantCulture, out index) || index < 1)
            {
                output.WriteLine($"--packet is not a 1-based frame number: {p}");
                return ExitUsage;
            }
            index--;
        }

        var (timestamp, data) = read.Packets[index];
        var packet = new Packet { Index = index, Timestamp = timestamp, RawData = data };
        if (!await tshark.ParsePacketFromPcapFileAsync(packet, path))
        {
            output.WriteLine($"tshark could not dissect frame {index + 1}");
            return ExitFailed;
        }

        var field = FirstFieldCovering(packet, offset, length);
        if (field is null)
        {
            output.WriteLine($"no protocol field covers offset {offset} length {length} in frame {index + 1}");
            return ExitFailed;
        }

        output.WriteLine($"target: {field.Name} ({field.OriginalPdmlName}) at offset {field.Offset} length {field.Length}");

        var result = await tx.CommitFieldEditAsync(packet, field, newValue, null, read.LinkLayerType);
        if (!result.Success)
        {
            output.WriteLine($"edit aborted: {result.Reason}");
            output.WriteLine("packet left byte-identical");
            return ExitFailed;
        }

        // Write the whole capture back with only the edited frame substituted.
        // Saving just the edited packet would silently drop every other frame in the
        // file, which is the kind of data loss a scripted edit must never cause.
        var editedData = packet.EffectiveData;
        var all = new List<Packet>(read.Packets.Count);
        for (int i = 0; i < read.Packets.Count; i++)
        {
            var (ts, raw) = read.Packets[i];
            all.Add(new Packet
            {
                Index = i,
                Timestamp = ts,
                RawData = i == index ? editedData : raw,
            });
        }

        await export.ExportAsync(all, new PacketExportOptions
        {
            OutputPath = outPath,
            ExportOnlyModified = false,
            IncludeUnmodified = true,
            LinkLayerType = read.LinkLayerType,
            Snaplen = read.Snaplen,
        });

        output.WriteLine($"committed and written: {outPath}");
        output.WriteLine($"frames written: {all.Count} (frame {index + 1} edited)");
        output.WriteLine($"verified: {result.Reason}");
        return ExitOk;
    }

    private static async Task<int> SendAsync(string[] args, TextWriter output)
    {
        if (args.Length < 1)
            return PrintUsage();
        string path = args[0];
        string? ifaceName = ArgValue(args, "--interface");

        var ingest = new PcapIngestService();
        var doc = new PacketDocument { FilePath = path };
        var tshark = new TsharkService(ingest, new PcapExportService());
        await tshark.LoadPcapAsync(doc, path, null, ArgValue(args, "--filter"));

        var interfaces = new NetworkInterfaceService().GetInterfaces();
        var target = ifaceName is null
            ? interfaces.FirstOrDefault(i => !i.IsLoopback)
            : interfaces.FirstOrDefault(i => i.Name.Equals(ifaceName, StringComparison.OrdinalIgnoreCase));

        if (target is null)
        {
            output.WriteLine("no such interface; available:");
            foreach (var i in interfaces)
                output.WriteLine($"  {i.Name}{(i.IsLoopback ? " (loopback)" : "")}");
            return ExitUsage;
        }

        if (target.IsLoopback)
        {
            output.WriteLine($"{target.Name} is loopback; the send ladder refuses it");
            return ExitFailed;
        }

        _ = int.TryParse(ArgValue(args, "--count"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int count);
        _ = int.TryParse(ArgValue(args, "--interval"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int interval);
        var all = args.Contains("--all");
        var toSend = all ? doc.Packets.ToList() : doc.Packets.Take(1).ToList();

        var send = new PacketSendService();
        var results = new List<PacketSendResult>();
        send.PacketSent += r => results.Add(r);
        await send.StartSendAsync(toSend, target, count <= 0 ? 1 : count, interval, autoFixFrames: false);

        int ok = results.Count(r => r.Success);
        foreach (var r in results)
            output.WriteLine($"[{r.PacketIndex}] {(r.Success ? "sent" : "FAILED")} {r.Message}");

        output.WriteLine($"sent {ok}/{results.Count} over {target.Name}");
        return ok == results.Count && results.Count > 0 ? ExitOk : ExitFailed;
    }

    private static async Task<int> StatsAsync(string[] args, TextWriter output)
    {
        if (args.Length < 1)
            return PrintUsage();
        string? tap = ArgValue(args, "--tap");
        if (tap is null)
        {
            output.WriteLine("stats requires --tap <name>");
            return ExitUsage;
        }

        var tshark = new TsharkService(new PcapIngestService(), new PcapExportService());
        var lines = await tshark.RunStatisticsTapAsync(args[0], tap, ArgValue(args, "--filter"));
        foreach (var line in lines)
            output.WriteLine(line);

        if (lines.Count == 0)
        {
            output.WriteLine($"tap {tap} produced no output");
            return ExitFailed;
        }
        return ExitOk;
    }

    private static ProtocolField? FirstFieldCovering(Packet packet, int offset, int length)
    {
        ProtocolField? best = null;
        foreach (var layer in packet.Layers)
        {
            foreach (var candidate in AllFields(layer.Fields))
            {
                if (candidate.RawBytes.Length == 0 || candidate.Length <= 0)
                    continue;
                if (offset >= candidate.Offset && offset + length <= candidate.Offset + candidate.Length)
                {
                    if (best is null || candidate.Length < best.Length)
                        best = candidate;
                }
            }
        }
        return best;
    }

    private static IEnumerable<ProtocolField> AllFields(IEnumerable<ProtocolField> fields)
    {
        foreach (var f in fields)
        {
            yield return f;
            foreach (var c in AllFields(f.Children))
                yield return c;
        }
    }

    private static string? ArgValue(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        return null;
    }
}