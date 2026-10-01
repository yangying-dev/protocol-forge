using ProtocolForge.Models;

namespace ProtocolForge.Services;

/// <summary>
/// Writes a PCAP file from packet data without requiring Tshark.
/// This is the inverse of PcapIngestService — produces a standard libpcap file
/// readable by Wireshark, Tshark, and any PCAP-capable tool.
/// </summary>
public sealed class PcapExportService
{
    /// <summary>
    /// Writes a single packet to a PCAP file (used both for overwrite-save and for
    /// the temporary single-packet capture the display-refresh reparse reads back).
    /// </summary>
    public async Task SavePacketAsync(Packet packet, string? outputPath = null, int linkLayerType = 1, CancellationToken ct = default)
    {
        var path = outputPath ?? packet.SaveFilePath;
        if (string.IsNullOrWhiteSpace(path))
            throw new InvalidOperationException("No save path specified for packet.");

        var exportOptions = new PacketExportOptions
        {
            OutputPath = path,
            ExportOnlyModified = false,
            IncludeUnmodified = true,
            LinkLayerType = linkLayerType,
        };

        await WriteAtomicallyAsync(path, writer =>
        {
            WriteGlobalHeader(writer, exportOptions);
            WritePacketRecord(writer, packet, ct);
        }, ct);
    }

    /// <summary>
    /// Writes the given context frames (raw bytes with timestamps) followed by
    /// the target packet to a PCAP file. Used by tree builds so tshark can
    /// dissect RTP payloads whose codec mapping arrives in earlier SDP frames.
    /// </summary>
    public async Task SavePacketWithContextAsync(
        Packet packet,
        IReadOnlyList<(long Timestamp, byte[] Data)> contextFrames,
        string? outputPath = null,
        int linkLayerType = 1,
        CancellationToken ct = default)
    {
        var path = outputPath ?? packet.SaveFilePath;
        if (string.IsNullOrWhiteSpace(path))
            throw new InvalidOperationException("No save path specified for packet.");

        var exportOptions = new PacketExportOptions
        {
            OutputPath = path,
            ExportOnlyModified = false,
            IncludeUnmodified = true,
            LinkLayerType = linkLayerType,
        };

        await WriteAtomicallyAsync(path, writer =>
        {
            WriteGlobalHeader(writer, exportOptions);
            foreach (var (timestamp, data) in contextFrames)
                WriteFrameRecord(writer, timestamp, data);
            WriteFrameRecord(writer, packet.Timestamp, packet.EffectiveData);
        }, ct);
    }

    /// <summary>
    /// Writes a PCAP file containing the specified packets.
    /// </summary>
    public async Task ExportAsync(
        IEnumerable<Packet> packets,
        PacketExportOptions options,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(options.OutputPath))
            throw new ArgumentException("Output path is required.", nameof(options));

        await WriteAtomicallyAsync(options.OutputPath, writer =>
        {
            WriteGlobalHeader(writer, options);

            foreach (var packet in packets)
            {
                ct.ThrowIfCancellationRequested();
                if (options.ExportOnlyModified && !packet.IsModified)
                    continue;
                WritePacketRecord(writer, packet, ct);
            }
        }, ct);
    }

    private static async Task WriteAtomicallyAsync(string path, Action<BinaryWriter> writeContent, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new ArgumentException("Output directory could not be resolved.", nameof(path));
        Directory.CreateDirectory(directory);

        var tempPath = Path.Combine(
            directory,
            $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");

        try
        {
            var streamOptions = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.Asynchronous | FileOptions.WriteThrough,
            };
            if (!OperatingSystem.IsWindows())
            {
                streamOptions.UnixCreateMode =
                    UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            await using (var stream = new FileStream(tempPath, streamOptions))
            using (var writer = new BinaryWriter(stream))
            {
                writeContent(writer);
                await stream.FlushAsync(ct);
                stream.Flush(flushToDisk: true);
            }

            ct.ThrowIfCancellationRequested();
            File.Move(tempPath, fullPath, overwrite: true);
        }
        catch (Exception writeError)
        {
            try
            {
                File.Delete(tempPath);
            }
            catch (Exception cleanupError)
            {
                TraceLog.Write($"Atomic PCAP cleanup failed for {tempPath}: {cleanupError.Message}");
            }

            TraceLog.Write($"Atomic PCAP write failed for {fullPath}: {writeError.Message}");
            throw;
        }
    }

    private static void WriteGlobalHeader(BinaryWriter writer, PacketExportOptions options)
    {
        writer.Write(0xa1b2c3d4u);   // Magic number (little-endian, microsecond)
        writer.Write((ushort)2);      // Version major
        writer.Write((ushort)4);      // Version minor
        writer.Write(0);              // Timezone (GMT)
        writer.Write(0u);             // Sigfigs (accuracy)
        writer.Write((uint)options.Snaplen);
        writer.Write((uint)options.LinkLayerType);
    }

    private static void WritePacketRecord(BinaryWriter writer, Packet packet, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        WriteFrameRecord(writer, packet.Timestamp, packet.EffectiveData);
    }

    private static void WriteFrameRecord(BinaryWriter writer, long timestamp, byte[] data)
    {
        uint tsSec = (uint)(timestamp / 1_000_000);
        uint tsUsec = (uint)(timestamp % 1_000_000);

        writer.Write(tsSec);
        writer.Write(tsUsec);
        writer.Write((uint)data.Length);  // incl_len
        writer.Write((uint)data.Length);  // orig_len
        writer.Write(data);
    }
}
