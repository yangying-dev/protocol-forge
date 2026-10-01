using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;

namespace ProtocolForge.Models;

/// <summary>
/// Represents a single captured packet with raw bytes, protocol layers,
/// and modification tracking.
/// </summary>
public partial class Packet : ObservableObject
{
    /// <summary>Zero-based index in the loaded PCAP.</summary>
    [ObservableProperty]
    private int _index;

    /// <summary>Original PCAP file path for save-back.</summary>
    public string SaveFilePath { get; set; } = string.Empty;

    /// <summary>Packet timestamp in microseconds since epoch.</summary>
    [ObservableProperty]
    private long _timestamp;

    /// <summary>Raw packet bytes (original, unmodified).</summary>
    [ObservableProperty]
    private byte[] _rawData = [];

    /// <summary>Modified packet bytes (null if unmodified).</summary>
    [ObservableProperty]
    private byte[]? _modifiedData;

    /// <summary>Parsed protocol layers from Tshark.</summary>
    public ObservableCollection<ProtocolLayer> Layers { get; set; } = [];

    // ─── Display columns (populated during parsing) ───

    /// <summary>Source IP address (or "N/A").</summary>
    [ObservableProperty]
    private string _sourceAddress = "N/A";

    /// <summary>Destination IP address (or "N/A").</summary>
    [ObservableProperty]
    private string _destinationAddress = "N/A";

    /// <summary>Source port number (-1 = unknown).</summary>
    [ObservableProperty]
    private int _sourcePort = -1;

    /// <summary>Destination port number (-1 = unknown).</summary>
    [ObservableProperty]
    private int _destinationPort = -1;

    /// <summary>Short protocol name for the Protocol column (e.g., "PFCP").</summary>
    [ObservableProperty]
    private string _protocolName = "";

    /// <summary>Whether this packet participates in packet sending.</summary>
    [ObservableProperty]
    private bool _sendSelected = false;

    /// <summary>
    /// Wireshark Info column text for this packet (e.g., "PFCP Establishment Request").
    /// Populated from tshark's _ws.col.Info field when available.
    /// </summary>
    public string InfoText { get; set; } = string.Empty;

    /// <summary>Whether this packet has been modified by the user.</summary>
    public bool IsModified => ModifiedData is not null;

    /// <summary>
    /// The effective bytes to use (modified if available, else original).
    /// </summary>
    public byte[] EffectiveData => ModifiedData ?? RawData;

    /// <summary>Packet number displayed in UI (1-based).</summary>
    public int PacketNumber => Index + 1;

    /// <summary>Short summary of the highest protocol layer (Info column).</summary>
    public string Summary
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(InfoText))
                return InfoText;
            if (Layers.Count > 0)
                return Layers[^1].DisplayText;
            return $"Packet #{PacketNumber}";
        }
    }

    /// <summary>Protocol stack as a comma-separated string.</summary>
    public string ProtocolStack => string.Join(" > ", Layers.Select(l => l.ProtocolName.ToUpperInvariant()));

    /// <summary>Packet length in bytes.</summary>
    public int Length => EffectiveData.Length;

    /// <summary>Timestamp in seconds (with microsecond precision).</summary>
    public double TimestampSeconds => Timestamp / 1_000_000.0;

    /// <summary>
    /// Timestamp formatted as a local DateTime string with microsecond precision,
    /// e.g. "2025-05-15 16:39:47.324567".
    /// </summary>
    public string TimestampDisplay
    {
        get
        {
            long seconds = Timestamp / 1_000_000;
            long micros = Timestamp % 1_000_000;
            // AddTicks: one tick = 100 ns = 0.1 µs, so micros * 10 = ticks.
            var local = DateTimeOffset.FromUnixTimeSeconds(seconds).ToLocalTime().DateTime;
            return local.AddTicks(micros * 10).ToString("yyyy-MM-dd HH:mm:ss.ffffff");
        }
    }

    /// <summary>Resets modifications, reverting to original bytes.</summary>
    public void ResetModifications()
    {
        ModifiedData = null;
        OnPropertyChanged(nameof(IsModified));
        OnPropertyChanged(nameof(EffectiveData));
        OnPropertyChanged(nameof(Length));
    }

    /// <summary>
    /// Applies byte modifications at a given offset, marking the packet as dirty.
    /// </summary>
    public void ApplyModification(int offset, byte[] newBytes)
    {
        ModifiedData ??= (byte[])RawData.Clone();
        Array.Copy(newBytes, 0, ModifiedData, offset, newBytes.Length);
        OnPropertyChanged(nameof(IsModified));
        OnPropertyChanged(nameof(EffectiveData));
        OnPropertyChanged(nameof(Length));
    }
}
