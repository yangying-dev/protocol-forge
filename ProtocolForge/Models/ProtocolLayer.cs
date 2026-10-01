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

    public override string ToString() => ShortLabel;
}
