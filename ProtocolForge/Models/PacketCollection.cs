using System.Collections.ObjectModel;
using System.Collections.Specialized;

namespace ProtocolForge.Models;

/// <summary>
/// ObservableCollection of packets supporting bulk appends that raise a single
/// CollectionChanged event. The packet list DataGrid subscribes to per-item
/// events; streaming 180k+ packets one Add at a time forces the grid to process
/// 180k incremental insertions on the UI thread, which is what turned a ~16 s
/// console load into a ~1 minute UI load. AddRange collapses that into one
/// notification per batch.
/// </summary>
public sealed class PacketCollection : ObservableCollection<Packet>
{
    public void AddRange(IEnumerable<Packet> items)
    {
        var batch = items as List<Packet> ?? items.ToList();
        if (batch.Count == 0)
            return;

        int start = Count;
        foreach (var item in batch)
            Items.Add(item);

        OnCollectionChanged(new NotifyCollectionChangedEventArgs(
            NotifyCollectionChangedAction.Add, batch, start));
    }
}