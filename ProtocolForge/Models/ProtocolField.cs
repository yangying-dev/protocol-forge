using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;

namespace ProtocolForge.Models;

/// <summary>
/// Data type of a protocol field, used to decide how user input (decimal/IP/string)
/// is converted to raw bytes when editing from the protocol tree.
/// </summary>
public enum FieldKind
{
    /// <summary>Type not resolvable — field is not editable from the tree.</summary>
    Unknown,

    /// <summary>Unsigned integer (1/2/4/8 bytes).</summary>
    UInt,

    /// <summary>Signed integer.</summary>
    Int,

    /// <summary>IPv4 address (4 bytes).</summary>
    IPv4,

    /// <summary>IPv6 address (16 bytes).</summary>
    IPv6,

    /// <summary>MAC address (colon-hex display, 4-8 bytes).</summary>
    Mac,

    /// <summary>BCD-encoded digits (IMSI/IMEI/MSISDN): two digits per byte, low nibble shown first, 0xF filler.</summary>
    Bcd,

    /// <summary>Text string.</summary>
    String,
}

/// <summary>
/// Represents a single protocol Information Element (IE) or field
/// parsed from Tshark JSON output. Maps to byte offsets in the raw packet.
/// </summary>
public partial class ProtocolField : ObservableObject
{
    /// <summary>Display name (e.g., "PFCP SEID", "NGAP AMF-UE-NGAP-ID").</summary>
    [ObservableProperty]
    private string _name = string.Empty;

    /// <summary>Human-readable value as shown by Tshark.</summary>
    [ObservableProperty]
    private string _displayValue = string.Empty;

    /// <summary>Byte offset of this field in the raw packet data.</summary>
    [ObservableProperty]
    private int _offset;

    /// <summary>Length in bytes. For bit-level fields, use <see cref="LengthBits"/>.</summary>
    [ObservableProperty]
    private int _length;

    /// <summary>Length in bits when field is not byte-aligned (-1 = byte-aligned).</summary>
    [ObservableProperty]
    private int _lengthBits = -1;

    /// <summary>
    /// Original PDML field name (e.g., "pfcp.seid") used to match re-parsed
    /// shownames back to this field after an edit (with <see cref="Offset"/>).
    /// </summary>
    public string OriginalPdmlName { get; set; } = string.Empty;

    /// <summary>
    /// True when Wireshark renders this field's value in hexadecimal (e.g. PFCP
    /// SEID/TEID shown as "0x…"). The tree editor then displays and accepts hex.
    /// </summary>
    public bool HexPreferred { get; set; }

    /// <summary>Raw bytes of this field's value.</summary>
    [ObservableProperty]
    private byte[] _rawBytes = [];

    /// <summary>
    /// Any RawBytes change (tree edit, hex-edit backfill) must also refresh
    /// <see cref="HexValue"/>, which the tree's gray hex text binds to.
    /// </summary>
    partial void OnRawBytesChanged(byte[] value) => OnPropertyChanged(nameof(HexValue));

    /// <summary>Resolved data type used for tree-based value editing.</summary>
    [ObservableProperty]
    private FieldKind _kind = FieldKind.Unknown;

    /// <summary>True while this field's value editor is open in the tree.</summary>
    [ObservableProperty]
    private bool _isEditing;

    /// <summary>Text currently shown in the tree's value editor.</summary>
    [ObservableProperty]
    private string _editText = string.Empty;

    /// <summary>
    /// Whether the field can be edited from the protocol tree: a resolvable type,
    /// a concrete byte span, and not a "not decoded" tail marker.
    /// </summary>
    public bool IsTreeEditable =>
        Kind != FieldKind.Unknown && Offset >= 0 && Length > 0 && !IsUndecodedMarker;

    /// <summary>First byte this field or its descendants occupy; -1 when positionless.</summary>
    public int EffectiveStart
    {
        get
        {
            if (Length > 0)
                return Offset;
            int min = int.MaxValue;
            foreach (var child in Children)
                if (child.EffectiveStart >= 0 && child.EffectiveStart < min)
                    min = child.EffectiveStart;
            return min == int.MaxValue ? -1 : min;
        }
    }

    /// <summary>Parent protocol layer this field belongs to.</summary>
    public ProtocolLayer? ParentLayer { get; set; }

    /// <summary>True for Wireshark's zero-size "not decoded" marker leaves, which have no
    /// byte span of their own but represent the undecoded tail of their containing IE.</summary>
    public bool IsUndecodedMarker { get; set; }

    /// <summary>
    /// Parent protocol field this field belongs to (null for layer-level fields).
    /// Lets span resolution walk up to the containing IE/container.
    /// </summary>
    public ProtocolField? ParentField { get; set; }

    /// <summary>Nested sub-fields (Tshark can nest IEs).</summary>
    public ObservableCollection<ProtocolField> Children { get; set; } = [];

    /// <summary>
    /// Whether this field contains sub-fields and acts as a tree branch.
    /// </summary>
    public bool HasChildren => Children.Count > 0;

    /// <summary>Hexadecimal string representation for display.</summary>
    public string HexValue => string.Join(" ", RawBytes.Select(b => b.ToString("X2")));

    /// <summary>False for Wireshark-style payload rows ("UDP payload (29 bytes)") to avoid inlining the hex blob.</summary>
    public bool ShowHex { get; set; } = true;

    public override string ToString() => $"{Name}: {DisplayValue}";
}
