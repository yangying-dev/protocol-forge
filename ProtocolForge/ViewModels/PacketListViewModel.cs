using System.Collections.ObjectModel;
using System.Collections.Specialized;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProtocolForge.Models;

namespace ProtocolForge.ViewModels;

/// <summary>
/// ViewModel for the packet list panel (left pane).
/// Displays a flat list of all packets with summary info.
/// Allows selection to drive the protocol tree and hex editor.
/// </summary>
public sealed partial class PacketListViewModel : ObservableObject
{
    [ObservableProperty]
    private ObservableCollection<Packet> _packets = [];

    [ObservableProperty]
    private Packet? _selectedPacket;

    [ObservableProperty]
    private int _selectedIndex = -1;

    [ObservableProperty]
    private bool _isEnabled;

    /// <summary>True when every packet is marked for sending, false when none, null when mixed.</summary>
    [ObservableProperty]
    private bool? _allSelectedForSend = false;

    /// <summary>
    /// Raised when the selected packet changes.
    /// The MainWindowViewModel subscribes to update the other panels.
    /// </summary>
    public event Action<Packet?>? PacketSelected;

    /// <summary>Raised when any packet's send selection changes.</summary>
    public event Action? SendSelectionChanged;

    private ObservableCollection<Packet>? _hookedPackets;

    public PacketListViewModel()
    {
        Packets.CollectionChanged += OnPacketsCollectionChanged;
    }

    /// <summary>
    /// Binds to a PacketDocument's packets and selection.
    /// </summary>
    public void LoadFromDocument(PacketDocument document)
    {
        Packets = document.Packets;
        SelectedPacket = document.SelectedPacket;
        IsEnabled = document.IsLoaded;

        if (document.SelectedPacket != null)
            SelectedIndex = document.SelectedPacket.Index;

        RehookPackets();
    }

    /// <summary>
    /// Clears the packet list.
    /// </summary>
    public void Clear()
    {
        Packets.Clear();
        SelectedPacket = null;
        SelectedIndex = -1;
        IsEnabled = false;
        RecomputeAllSelected();
        SendSelectionChanged?.Invoke();
    }

    /// <summary>Marks every packet for sending.</summary>
    public void SelectAllForSend() => AllSelectedForSend = true;

    /// <summary>Unmarks every packet for sending.</summary>
    public void ClearSendSelection() => AllSelectedForSend = false;

    /// <summary>Flips the send mark of every packet.</summary>
    public void InvertSendSelection()
    {
        foreach (var p in Packets)
            p.SendSelected = !p.SendSelected;
    }

    partial void OnSelectedPacketChanged(Packet? value)
    {
        if (value != null)
            SelectedIndex = value.Index;
        PacketSelected?.Invoke(value);
    }

    partial void OnAllSelectedForSendChanged(bool? value)
    {
        if (value is null)
            return;
        foreach (var p in Packets)
            p.SendSelected = value.Value;
    }

    private void RehookPackets()
    {
        Packets.CollectionChanged -= OnPacketsCollectionChanged;
        Packets.CollectionChanged += OnPacketsCollectionChanged;

        if (_hookedPackets != null)
            foreach (var p in _hookedPackets)
                p.PropertyChanged -= OnPacketPropertyChanged;
        _hookedPackets = Packets;
        foreach (var p in Packets)
            p.PropertyChanged += OnPacketPropertyChanged;

        RecomputeAllSelected();
        SendSelectionChanged?.Invoke();
    }

    private void OnPacketsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.NewItems != null)
            foreach (Packet p in e.NewItems)
                p.PropertyChanged += OnPacketPropertyChanged;
        if (e.OldItems != null)
            foreach (Packet p in e.OldItems)
                p.PropertyChanged -= OnPacketPropertyChanged;
    }

    private void OnPacketPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(Packet.SendSelected))
            return;
        RecomputeAllSelected();
        SendSelectionChanged?.Invoke();
    }

    private void RecomputeAllSelected()
    {
        bool allChecked = Packets.Count > 0;
        bool noneChecked = Packets.Count > 0;
        foreach (var p in Packets)
        {
            if (!p.SendSelected) allChecked = false;
            if (p.SendSelected) noneChecked = false;
        }
        bool? next = Packets.Count == 0 ? false : allChecked ? true : noneChecked ? false : null;
        if (next != AllSelectedForSend)
            AllSelectedForSend = next;
    }
}
