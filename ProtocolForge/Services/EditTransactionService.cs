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
