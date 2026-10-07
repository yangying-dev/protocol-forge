using ProtocolForge.Models;

namespace ProtocolForge.Services;

/// <summary>
/// Verdict returned by <see cref="CommitFieldEditAsync"/>.
/// </summary>
public sealed record EditResult(bool Success, string Reason, PdmlData? Fresh);

/// <summary>
/// Executes a verify-before-commit transaction for tree-field edits.
/// Builds a candidate frame, writes a temp PCAP (with context frames when
/// supplied), re-parses it via tshark, and compares the reparse field at the
/// target position against the expected hex value before committing.
/// </summary>
public sealed class EditTransactionService
{
    private static EditResult Abort(string fieldName, string reason)
    {
        TraceLog.Write($"VBC edit aborted for field '{fieldName}': {reason}");
        return new EditResult(false, reason, null);
    }

    private readonly PcapExportService _pcapExport;
    private readonly TsharkService _tshark;

    public EditTransactionService(PcapExportService pcapExport, TsharkService tshark)
    {
        _pcapExport = pcapExport;
        _tshark = tshark;
    }

    /// <summary>
    /// Verifies a proposed field edit via tshark reparse before committing.
    /// On success the packet bytes are mutated, the field's RawBytes is
    /// updated, and the fresh PdmlData is returned so the caller can feed
    /// RefreshFieldDisplays. On failure the packet is byte-identical and the
    /// reason is surfaced in the returned EditResult.
    /// </summary>
    public async Task<EditResult> CommitFieldEditAsync(
        Packet packet,
        ProtocolField field,
        byte[] newValue,
        IReadOnlyList<(long Timestamp, byte[] Data)>? contextFrames,
        int linkLayerType = 1,
        CancellationToken ct = default)
    {
        string tempPath = Path.Combine(Path.GetTempPath(), $"pf_vbc_{Guid.NewGuid():N}.pcap");
        try
        {
            byte[] candidate = (byte[])packet.EffectiveData.Clone();

            // Bounds must be settled before the copy, not by VerifyFieldInReparse:
            // the copy below is unguarded, so a length-changing edit that runs past
            // the frame throws out of a method whose contract is to return a verdict.
            // Only the frame bound is checked here — the length verdict stays in
            // VerifyFieldInReparse where it runs last, after landing and value, so an
            // over-long edit still reports the more informative reason first.
            if (field.Offset < 0 || newValue.Length == 0 ||
                field.Offset + newValue.Length > candidate.Length)
            {
                return Abort(field.Name, LocalizationService.Resolve(
                    "Vbc.OutOfFrame", field.Offset, newValue.Length, candidate.Length));
            }

            Array.Copy(newValue, 0, candidate, field.Offset, newValue.Length);

            var tempPacket = new Packet
            {
                Timestamp = packet.Timestamp,
                RawData = candidate,
            };

            if (contextFrames is { Count: > 0 })
                await _pcapExport.SavePacketWithContextAsync(tempPacket, contextFrames, tempPath, linkLayerType, ct);
            else
                await _pcapExport.SavePacketAsync(tempPacket, tempPath, linkLayerType, ct);

            var fresh = await _tshark.ReparseSinglePacketAsync(tempPath, ct);
            if (fresh == null)
                return Abort(field.Name, LocalizationService.Resolve("Vbc.NoData"));

            var verdict = VerifyFieldInReparse(field, newValue, fresh);
            if (!verdict.Success)
                return verdict;

            packet.ApplyModification(field.Offset, newValue);
            field.RawBytes = newValue;

            return verdict;
        }
        finally
        {
            try { File.Delete(tempPath); }
            catch (Exception) { }
        }
    }

    /// <summary>
    /// Commits an edit whose new value differs in length from the field's current one.
    ///
    /// The invariant this replaces is "packet length never changes", which is not
    /// weaker: it is "after tshark reparses the spliced frame, the edited field still
    /// sits at the expected position, the protocol stack is unchanged, and nothing in
    /// the frame came back malformed". A splice that leaves an enclosing length field
    /// stale therefore fails the same way a bad value does, and the packet is left
    /// byte-identical.
    ///
    /// Enclosing length fields are NOT recomputed here. Doing so needs a model of
    /// which field is a length of which, which this project deliberately does not
    /// carry; tshark's dissection is the source of truth, and the reparse below is
    /// what decides whether the frame is still coherent.
    /// </summary>
    public async Task<EditResult> CommitLengthChangingEditAsync(
        Packet packet,
        ProtocolField field,
        byte[] newValue,
        IReadOnlyList<(long Timestamp, byte[] Data)>? contextFrames,
        int linkLayerType = 1,
        CancellationToken ct = default)
    {
        int offset = field.Offset;
        int previousLength = field.Length;
        int delta = newValue.Length - previousLength;

        if (offset < 0 || previousLength < 0 || offset + previousLength > packet.EffectiveData.Length)
            return Abort(field.Name, LocalizationService.Resolve("Vbc.OutOfFrame", offset, previousLength, packet.EffectiveData.Length));

        // Snapshot for the rollback path: shifting offsets and splicing bytes are only
        // applied after verification, but the offset shift is not trivially reversible
        // once the tree has been walked.
        var originalOffsets = CaptureOffsets(packet);
        string expectedHex = Convert.ToHexString(newValue).ToLowerInvariant();

        string tempPath = Path.Combine(Path.GetTempPath(), $"pf_vbc_{Guid.NewGuid():N}.pcap");
        try
        {
            var spliced = new byte[packet.EffectiveData.Length + delta];
            Array.Copy(packet.EffectiveData, 0, spliced, 0, offset);
            Array.Copy(newValue, 0, spliced, offset, newValue.Length);
            int tail = packet.EffectiveData.Length - offset - previousLength;
            if (tail > 0)
                Array.Copy(packet.EffectiveData, offset + previousLength, spliced, offset + newValue.Length, tail);

            var candidate = new Packet { Timestamp = packet.Timestamp, RawData = spliced };
            if (contextFrames is { Count: > 0 })
                await _pcapExport.SavePacketWithContextAsync(candidate, contextFrames, tempPath, linkLayerType, ct);
            else
                await _pcapExport.SavePacketAsync(candidate, tempPath, linkLayerType, ct);

            var fresh = await _tshark.ReparseSinglePacketAsync(tempPath, ct);
            if (fresh == null)
                return Abort(field.Name, LocalizationService.Resolve("Vbc.NoData"));

            // The edited field must land at its own (unshifted) offset holding the new
            // bytes. A stale enclosing length shows up here as a miss.
            if (!fresh.FieldLookup.ContainsKey((field.OriginalPdmlName, offset)))
            {
                RestoreOffsets(packet, originalOffsets);
                return Abort(field.Name, LocalizationService.Resolve("Vbc.NotLanding", field.OriginalPdmlName, offset));
            }
            if (fresh.ValueLookup != null &&
                fresh.ValueLookup.TryGetValue((field.OriginalPdmlName, offset), out string? landed) &&
                !string.Equals(landed, expectedHex, StringComparison.OrdinalIgnoreCase))
            {
                RestoreOffsets(packet, originalOffsets);
                return Abort(field.Name, LocalizationService.Resolve("Vbc.ValueMismatch", landed, offset, expectedHex));
            }

            // A splice that desynchronises the framing makes tshark emit a malformed
            // marker. That is the signal that an enclosing length field went stale.
            if (MalformedFields(fresh).Count > 0)
            {
                RestoreOffsets(packet, originalOffsets);
                return Abort(field.Name, LocalizationService.Resolve("Vbc.MalformedAfterSplice", delta));
            }

            packet.SpliceBytes(offset, previousLength, newValue);
            packet.ShiftFieldOffsets(offset + previousLength, delta);
            field.RawBytes = newValue;
            field.Length = newValue.Length;

            return new EditResult(true, "OK", fresh);
        }
        catch (Exception ex)
        {
            RestoreOffsets(packet, originalOffsets);
            TraceLog.Write($"Length-changing edit failed for {field.Name}: {ex.Message}");
            return Abort(field.Name, ex.Message);
        }
        finally
        {
            try { File.Delete(tempPath); }
            catch (Exception) { }
        }
    }

    private static List<string> MalformedFields(PdmlData fresh)
    {
        var result = new List<string>();
        if (fresh.FieldLookup == null)
            return result;
        foreach (var ((name, _), _) in fresh.FieldLookup)
            if (name.Contains("malformed", StringComparison.OrdinalIgnoreCase))
                result.Add(name);
        return result;
    }

    private static List<(object Node, int Offset)> CaptureOffsets(Packet packet)
    {
        var captured = new List<(object, int)>();
        foreach (var layer in packet.Layers)
        {
            captured.Add((layer, layer.Offset));
            CaptureChildren(layer.Fields, captured);
        }
        return captured;
    }

    private static void CaptureChildren(IEnumerable<ProtocolField> fields, List<(object, int)> into)
    {
        foreach (var field in fields)
        {
            into.Add((field, field.Offset));
            if (field.Children.Count > 0)
                CaptureChildren(field.Children, into);
        }
    }

    private static void RestoreOffsets(Packet packet, List<(object Node, int Offset)> captured)
    {
        foreach (var (node, offset) in captured)
        {
            if (node is ProtocolField field)
                field.Offset = offset;
            else if (node is ProtocolLayer layer)
                layer.Offset = offset;
        }
    }

    /// <summary>
    /// Commits several edits to one frame atomically.
    ///
    /// A single-field splice is almost never usable on its own: growing an IE's payload
    /// leaves the IE's own Length field stale, and fixing that Length field is itself an
    /// edit. Doing them one transaction at a time cannot work, because the frame is
    /// malformed in between and each transaction would (correctly) refuse it. So the
    /// edits are applied to one candidate frame and verified once.
    ///
    /// All splices are applied from the highest offset down, so an earlier edit's
    /// offset is still valid when a later one shifts bytes beneath it.
    /// </summary>
    public async Task<EditResult> CommitCompoundEditAsync(
        Packet packet,
        IReadOnlyList<(ProtocolField Field, byte[] NewValue)> edits,
        IReadOnlyList<(long Timestamp, byte[] Data)>? contextFrames,
        int linkLayerType = 1,
        CancellationToken ct = default)
    {
        if (edits.Count == 0)
            return new EditResult(true, "OK", null);

        var originalOffsets = CaptureOffsets(packet);
        byte[] before = (byte[])packet.EffectiveData.Clone();

        string tempPath = Path.Combine(Path.GetTempPath(), $"pf_vbc_{Guid.NewGuid():N}.pcap");
        try
        {
            byte[] candidate = (byte[])packet.EffectiveData.Clone();
            int totalDelta = 0;

            foreach (var (field, _) in edits.OrderByDescending(e => e.Field.Offset))
            {
                byte[] insert = CurrentValue(field, edits);
                candidate = Splice(candidate, field.Offset, field.Length, insert);
                totalDelta += insert.Length - field.Length;
            }

            var candidatePacket = new Packet { Timestamp = packet.Timestamp, RawData = candidate };
            if (contextFrames is { Count: > 0 })
                await _pcapExport.SavePacketWithContextAsync(candidatePacket, contextFrames, tempPath, linkLayerType, ct);
            else
                await _pcapExport.SavePacketAsync(candidatePacket, tempPath, linkLayerType, ct);

            var fresh = await _tshark.ReparseSinglePacketAsync(tempPath, ct);
            if (fresh == null)
            {
                RestoreOffsets(packet, originalOffsets);
                return Abort(edits[0].Field.Name, LocalizationService.Resolve("Vbc.NoData"));
            }

            var malformed = MalformedFields(fresh);
            if (malformed.Count > 0)
            {
                RestoreOffsets(packet, originalOffsets);
                return Abort(edits[0].Field.Name, LocalizationService.Resolve("Vbc.MalformedAfterSplice", totalDelta));
            }

            // Every edited field must be present in the reparse holding the bytes asked
            // for. A spliced payload that shifted its own container will not be.
            foreach (var (field, newValue) in edits)
            {
                string expected = Convert.ToHexString(newValue).ToLowerInvariant();
                if (!fresh.FieldLookup.ContainsKey((field.OriginalPdmlName, field.Offset)))
                {
                    RestoreOffsets(packet, originalOffsets);
                    return Abort(field.Name, LocalizationService.Resolve("Vbc.NotLanding", field.OriginalPdmlName, field.Offset));
                }
                if (fresh.ValueLookup != null &&
                    fresh.ValueLookup.TryGetValue((field.OriginalPdmlName, field.Offset), out string? landed) &&
                    !string.Equals(landed, expected, StringComparison.OrdinalIgnoreCase))
                {
                    RestoreOffsets(packet, originalOffsets);
                    return Abort(field.Name, LocalizationService.Resolve("Vbc.ValueMismatch", landed, field.Offset, expected));
                }
            }

            packet.SpliceBytes(0, before.Length, candidate);
            ApplyEdits(packet, edits);
            return new EditResult(true, "OK", fresh);
        }
        catch (Exception ex)
        {
            RestoreOffsets(packet, originalOffsets);
            TraceLog.Write($"Compound edit failed: {ex.Message}");
            return Abort(edits[0].Field.Name, ex.Message);
        }
        finally
        {
            try { File.Delete(tempPath); }
            catch (Exception) { }
        }
    }

    private static byte[] CurrentValue(ProtocolField field, IReadOnlyList<(ProtocolField Field, byte[] NewValue)> edits)
    {
        foreach (var (f, v) in edits)
            if (ReferenceEquals(f, field))
                return v;
        return field.RawBytes;
    }

    private static void ApplyEdits(Packet packet, IReadOnlyList<(ProtocolField Field, byte[] NewValue)> edits)
    {
        // Offsets above the lowest splice move by that splice's delta; recompute the
        // shift from the lowest edited field so the tree stays aligned with the bytes.
        int pivot = edits.Min(e => e.Field.Offset);
        int delta = edits.Sum(e => e.NewValue.Length - e.Field.Length);
        if (delta != 0)
            packet.ShiftFieldOffsets(pivot, delta);

        foreach (var (field, newValue) in edits)
        {
            field.RawBytes = newValue;
            field.Length = newValue.Length;
        }
    }

    private static byte[] Splice(byte[] source, int offset, int removeLength, byte[] insert)
    {
        int tail = source.Length - offset - removeLength;
        var result = new byte[offset + insert.Length + tail];
        Array.Copy(source, 0, result, 0, offset);
        Array.Copy(insert, 0, result, offset, insert.Length);
        if (tail > 0)
            Array.Copy(source, offset + removeLength, result, offset + insert.Length, tail);
        return result;
    }

    private static EditResult VerifyFieldInReparse(ProtocolField field, byte[] newValue, PdmlData fresh)
    {
        string pdmlName = field.OriginalPdmlName;
        if (pdmlName.Length == 0)
            return Abort(field.Name, LocalizationService.Resolve("Vbc.NoPdmlName"));

        int primaryPos = field.Offset;
        int fallbackPos = field.EffectiveStart;
        string expectedHex = Convert.ToHexString(newValue).ToLowerInvariant();
        string oldHex = Convert.ToHexString(field.RawBytes).ToLowerInvariant();

        int searchPos = primaryPos >= 0 ? primaryPos : fallbackPos;
        if (searchPos < 0)
            return Abort(field.Name, LocalizationService.Resolve("Vbc.NoPosition"));

        if (!fresh.FieldLookup.ContainsKey((pdmlName, searchPos)))
        {
            if (fallbackPos >= 0 && fallbackPos != primaryPos &&
                fresh.FieldLookup.ContainsKey((pdmlName, fallbackPos)))
            {
                searchPos = fallbackPos;
            }
        }

        bool foundAtPosition = fresh.FieldLookup.ContainsKey((pdmlName, searchPos));

        if (!foundAtPosition)
        {
            int wrongPos = -1;
            foreach (var ((name, pos), _) in fresh.FieldLookup)
            {
                if (string.Equals(name, pdmlName, StringComparison.OrdinalIgnoreCase))
                {
                    wrongPos = pos;
                    break;
                }
            }

            string reparseHexAtWrong = fresh.ValueLookup != null &&
                fresh.ValueLookup.TryGetValue((pdmlName, wrongPos), out string? wv) ? wv : string.Empty;

            bool looksLikeDrift = wrongPos >= 0 &&
                (reparseHexAtWrong.Length == 0 || string.Equals(reparseHexAtWrong, oldHex, StringComparison.OrdinalIgnoreCase));

            if (looksLikeDrift)
            {
                return Abort(field.Name,
                    LocalizationService.Resolve("Vbc.OffsetDrift", pdmlName, wrongPos, searchPos));
            }

            return Abort(field.Name,
                LocalizationService.Resolve("Vbc.NotLanding", pdmlName, searchPos));
        }

        if (fresh.ValueLookup != null && fresh.ValueLookup.TryGetValue((pdmlName, searchPos), out string? reparseValue))
        {
            if (!string.Equals(reparseValue, expectedHex, StringComparison.OrdinalIgnoreCase))
            {
                return Abort(field.Name,
                    LocalizationService.Resolve("Vbc.ValueMismatch", reparseValue, searchPos, expectedHex));
            }
        }

        if (field.Length > 0 && field.Length != newValue.Length)
            return Abort(field.Name, LocalizationService.Resolve("Vbc.LengthMismatch", field.Length, newValue.Length));

        return new EditResult(true, "OK", fresh);
    }
}
