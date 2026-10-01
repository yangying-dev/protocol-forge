using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using ProtocolForge.Services;

namespace ProtocolForge.Models;

/// <summary>
/// Represents a fully loaded PCAP document with packets,
/// file metadata, and modification state.
/// </summary>
public partial class PacketDocument : ObservableObject
{
    /// <summary>Path to the source PCAP file.</summary>
    [ObservableProperty]
    private string _filePath = string.Empty;

    /// <summary>All packets loaded from the PCAP.</summary>
    public PacketCollection Packets { get; set; } = new();

    /// <summary>Total number of packets.</summary>
    [ObservableProperty]
    private int _packetCount;

    /// <summary>Whether the document has unsaved changes.</summary>
    [ObservableProperty]
    private bool _hasUnsavedChanges;

    /// <summary>The selected packet for detailed inspection.</summary>
    [ObservableProperty]
    private Packet? _selectedPacket;

    /// <summary>Link layer type (e.g., Ethernet = 1).</summary>
    public int LinkLayerType { get; set; } = 1; // Default: Ethernet

    /// <summary>Snapshot length from PCAP global header.</summary>
    public int Snaplen { get; set; } = 65535;

    /// <summary>
    /// Context providers that locate frames which must precede a target frame in a
    /// per-packet temp PCAP so tshark dissects it with cross-frame state (SDP codec
    /// mapping, IP fragment siblings). Each provider scans the capture lazily on the
    /// first per-packet tree build that calls it, so a capture never paying that
    /// context costs no tshark processes. Empty when the capture was loaded in
    /// read-only mode or holds no such context.
    /// </summary>
    public IReadOnlyList<IPacketContextProvider> ContextProviders { get; set; } = [];

    /// <summary>Whether a PCAP is currently loaded.</summary>
    public bool IsLoaded => Packets.Count > 0;

    /// <summary>
    /// Gets all modified packets for export.
    /// </summary>
    public IEnumerable<Packet> GetModifiedPackets() =>
        Packets.Where(p => p.IsModified);

    /// <summary>
    /// Fully resets all packet modifications.
    /// </summary>
    public void ResetAllModifications()
    {
        foreach (var packet in Packets)
            packet.ResetModifications();
        HasUnsavedChanges = false;
    }
}
