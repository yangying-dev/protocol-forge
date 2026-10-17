using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace ProtocolForge.Models;

/// <summary>
/// Represents a protocol layer in a packet (e.g., "PFCP", "NGAP", "GTP-U", "NAS").
/// Each layer contains a list of Information Elements (fields).
/// </summary>
public partial class ProtocolLayer : ObservableObject
{
    /// <summary>Protocol abbreviation as reported by Tshark (e.g., "pfcp", "ngap").</summary>
    [ObservableProperty]
    private string _protocolName = string.Empty;

    /// <summary>Display text from Tshark (e.g., "PFCP Session Establishment Request").</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShortLabel))]
    private string _displayText = string.Empty;

    /// <summary>Fields / Information Elements in this layer.</summary>
    public ObservableCollection<ProtocolField> Fields { get; set; } = [];

    /// <summary>Parent packet this layer belongs to.</summary>
    public Packet? ParentPacket { get; set; }

    /// <summary>Byte offset of this layer within the packet (used to disambiguate
    /// repeated layers of the same protocol, e.g. outer + inner IP of a tunnel).</summary>
    public int Offset { get; set; }

    /// <summary>Short label for tree display.</summary>
    public string ShortLabel => DisplayText;

    /// <summary>
    /// True when this layer's field tree carries both halves of a transport port
    /// pair, using tshark's own field-name convention (srcport/dstport plus the
    /// showname variants the port scanners accept). Structural signature instead
    /// of a protocol allow-list, so any transport tshark dissects — tcp/udp/sctp
    /// today, dccp/udplite/whatever tomorrow — is recognised without code changes.
    /// Mirrors the name sets ScanPortFields matches, recursively.
    /// </summary>
    public bool HasPortFields => ContainsPortPair(Fields);

    private static bool ContainsPortPair(IEnumerable<ProtocolField> fields)
    {
        bool hasSrc = false, hasDst = false;
        foreach (var f in fields)
        {
            if (f.Name is "srcport" or "port" or "Source Port") hasSrc = true;
            else if (f.Name is "dstport" or "Destination Port") hasDst = true;
            if (hasSrc && hasDst) return true;
            if (f.HasChildren && ContainsPortPair(f.Children)) return true;
        }
        return false;
    }

    public override string ToString() => ShortLabel;
}
