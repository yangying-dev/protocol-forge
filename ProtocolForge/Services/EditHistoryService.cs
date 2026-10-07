using System.Collections.ObjectModel;
using ProtocolForge.Models;

namespace ProtocolForge.Services;

/// <summary>
/// Undo/redo over committed packet edits.
///
/// Snapshots whole-frame bytes rather than individual field writes. That costs memory
/// proportional to the edited frames, but it is the only representation that survives a
/// length-changing edit: a splice rewrites every later offset, so replaying field-level
/// deltas would have to re-derive the whole layout. Frames are small and edits are
/// operator-driven, so full snapshots are the cheaper trade.
/// </summary>
public sealed class EditHistoryService
{
    /// <summary>
    /// A committed change to one packet. <see cref="Before"/> is null when the packet was
    /// unmodified beforehand, which is what makes the first edit undoable back to raw.
    /// </summary>
    public sealed record Entry(int PacketIndex, int PacketNumber, byte[]? Before, byte[] After, string Summary);

    private readonly List<Entry> _undo = [];
    private readonly List<Entry> _redo = [];

    /// <summary>Deepest stack kept. Older entries fall off the bottom and become unreachable.</summary>
    public const int Capacity = 200;

    public ReadOnlyCollection<Entry> UndoStack => _undo.AsReadOnly();
    public ReadOnlyCollection<Entry> RedoStack => _redo.AsReadOnly();

    public bool CanUndo => _undo.Count > 0;
    public bool CanRedo => _redo.Count > 0;

    public string? PeekUndoSummary => _undo.Count > 0 ? _undo[^1].Summary : null;
    public string? PeekRedoSummary => _redo.Count > 0 ? _redo[^1].Summary : null;

    /// <summary>
    /// Records a committed edit. A new edit invalidates the redo branch, which is the
    /// behaviour every editor has: you cannot redo past a change made afterwards.
    /// </summary>
    public void Record(int packetIndex, int packetNumber, byte[]? before, byte[] after, string summary)
    {
        _undo.Add(new Entry(
            packetIndex,
            packetNumber,
            before is null ? null : (byte[])before.Clone(),
            (byte[])after.Clone(),
            summary));
        _redo.Clear();

        while (_undo.Count > Capacity)
            _undo.RemoveAt(0);
    }

    /// <summary>
    /// Restores the frame as it was before the newest edit, moving that entry onto the
    /// redo stack. Returns null when there is nothing to undo.
    /// </summary>
    public Entry? Undo(Packet packet)
    {
        if (_undo.Count == 0)
            return null;

        var entry = _undo[^1];
        _undo.RemoveAt(_undo.Count - 1);
        _redo.Add(entry);

        if (entry.Before is null)
            packet.ResetModifications();
        else
            packet.RestoreBytes(entry.Before);

        return entry;
    }

    public Entry? Redo(Packet packet)
    {
        if (_redo.Count == 0)
            return null;

        var entry = _redo[^1];
        _redo.RemoveAt(_redo.Count - 1);
        _undo.Add(entry);

        packet.RestoreBytes(entry.After);
        return entry;
    }

    public void Clear()
    {
        _undo.Clear();
        _redo.Clear();
    }

    /// <summary>
    /// Drops history for a packet that was reloaded from disk, so undo cannot resurrect
    /// bytes that no longer correspond to the file on screen.
    /// </summary>
    public void Forget(int packetIndex)
    {
        _undo.RemoveAll(e => e.PacketIndex == packetIndex);
        _redo.RemoveAll(e => e.PacketIndex == packetIndex);
    }
}
