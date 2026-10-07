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
    /// Replaces the current bytes wholesale, used by undo/redo. The tree offsets are
    /// NOT adjusted: a history entry always restores a frame that was parsed from those
    /// exact bytes, and the caller rebuilds the tree from the file afterwards.
    /// </summary>
    public void RestoreBytes(byte[] bytes)
    {
        ModifiedData = bytes.Length == RawData.Length && bytes.AsSpan().SequenceEqual(RawData)
            ? null
            : (byte[])bytes.Clone();
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

    /// <summary>
    /// Replaces <paramref name="removeLength"/> bytes at <paramref name="offset"/>
    /// with <paramref name="insert"/>, which may be a different length.
    ///
    /// This is the only primitive that changes packet length. Callers must have
    /// verified the result by reparse first: once the bytes are gone, the original
    /// span cannot be recovered from this packet.
    /// </summary>
    public void SpliceBytes(int offset, int removeLength, byte[] insert)
    {
        if (offset < 0 || removeLength < 0 || offset + removeLength > EffectiveData.Length)
            throw new ArgumentOutOfRangeException(nameof(offset), "Splice range is outside the frame.");

        byte[] current = EffectiveData;
        int tailLength = current.Length - offset - removeLength;
        int resultLength = offset + insert.Length + tailLength;

        var result = new byte[resultLength];
        Array.Copy(current, 0, result, 0, offset);
        Array.Copy(insert, 0, result, offset, insert.Length);
        if (tailLength > 0)
            Array.Copy(current, offset + removeLength, result, offset + insert.Length, tailLength);

        ModifiedData = result;
        OnPropertyChanged(nameof(IsModified));
        OnPropertyChanged(nameof(EffectiveData));
        OnPropertyChanged(nameof(Length));
    }

    /// <summary>
    /// Moves every field at or after <paramref name="pivot"/> by <paramref name="delta"/>,
    /// then prunes the fields the splice pushed outside the frame. Without the prune
    /// a truncated field would linger in the tree with an offset past the last byte,
    /// where the hex viewer cannot show it and the edit fence rejects it.
    /// </summary>
    public void ShiftFieldOffsets(int pivot, int delta)
    {
        if (delta == 0)
            return;

        foreach (var layer in Layers)
        {
            layer.Offset = Shift(layer.Offset, pivot, delta);
            ShiftChildren(layer.Fields, pivot, delta);
            PruneChildren(layer.Fields);
        }
    }

    private static void ShiftChildren(IEnumerable<ProtocolField> fields, int pivot, int delta)
    {
        foreach (var field in fields)
        {
            field.Offset = Shift(field.Offset, pivot, delta);
            if (field.Children.Count > 0)
                ShiftChildren(field.Children, pivot, delta);
        }
    }

    private void PruneChildren(ObservableCollection<ProtocolField> fields)
    {
        int frameLength = EffectiveData.Length;
        for (int i = fields.Count - 1; i >= 0; i--)
        {
            var field = fields[i];
            if (field.Children.Count > 0)
                PruneChildren(field.Children);

            bool outside = field.Length > 0 && field.Offset + field.Length > frameLength;
            if (outside || field.Children.Count == 0 && field.Length == 0 && field.Offset >= frameLength)
                fields.RemoveAt(i);
        }
    }

    private static int Shift(int offset, int pivot, int delta) =>
        offset >= pivot ? offset + delta : offset;
}
