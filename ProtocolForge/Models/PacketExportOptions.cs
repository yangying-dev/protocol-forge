namespace ProtocolForge.Models;

/// <summary>
/// Options for exporting a modified PCAP file.
/// </summary>
public class PacketExportOptions
{
    /// <summary>Output file path.</summary>
    public string OutputPath { get; set; } = string.Empty;

    /// <summary>Whether to include only modified packets.</summary>
    public bool ExportOnlyModified { get; set; }

    /// <summary>Whether to include original (unmodified) packets as-is.</summary>
    public bool IncludeUnmodified { get; set; } = true;

    /// <summary>DLT (Data Link Type) for the PCAP global header. Default: Ethernet.</summary>
    public int LinkLayerType { get; set; } = 1;

    /// <summary>Snapshot length from PCAP global header. Default: 65535.</summary>
    public int Snaplen { get; set; } = 65535;
}
