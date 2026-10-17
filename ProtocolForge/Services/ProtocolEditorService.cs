using ProtocolForge.Models;

namespace ProtocolForge.Services;

/// <summary>
/// Handles field-level edits on packet bytes.
/// Maps between structured ProtocolField values and raw byte arrays,
/// and provides bidirectional synchronization for the hex editor.
/// </summary>
public sealed class ProtocolEditorService
{
    /// <summary>Result of a tree-edit fence check.</summary>
    public sealed record EditFence(bool Allowed, string Reason);

    private static EditFence RejectFence(string fieldName, string reason)
    {
        TraceLog.Write($"Edit fence rejected field '{fieldName}': {reason}");
        return new EditFence(false, reason);
    }

    /// <summary>
    /// Checks whether a field can be safely edited from the protocol tree.
    /// Returns Allowed=false when the field's offset/length/raw-bytes are not
    /// provably consistent with the captured frame bytes.
    /// </summary>
    public EditFence CheckTreeEditFence(Packet packet, ProtocolField field)
    {
        if (!field.IsTreeEditable)
            return RejectFence(field.Name, LocalizationService.Resolve(
                field.IsUndecodedMarker ? "Fence.UndecodedSpanUnknown" : "Fence.UnknownField"));

        if (field.Offset < 0 || field.Length <= 0)
            return RejectFence(field.Name, LocalizationService.Resolve("Fence.NoByteSpan"));

        if (field.Offset + field.Length > packet.EffectiveData.Length)
        {
            string hint = packet.Layers.Count > 0 ? LocalizationService.Resolve("Fence.PduHint") : "";
            return RejectFence(field.Name, LocalizationService.Resolve("Fence.OutOfFrame", field.Offset, field.Length, packet.EffectiveData.Length, hint));
        }

        // Bit field: read-modify-write of the whole byte span, so the mask must be
        // one contiguous run of bits (ComputeBitFieldEditBytes assumes it).
        if (field.IsBitField)
        {
            if (field.Length > 8)
                return RejectFence(field.Name, LocalizationService.Resolve("Fence.BitOutOfRange"));

            int k = System.Numerics.BitOperations.PopCount((ulong)field.BitMask);
            long shifted = field.BitMask >> field.BitShift;
            long expected = k >= 64 ? -1 : (1L << k) - 1;
            if (shifted != expected)
                return RejectFence(field.Name, LocalizationService.Resolve("Fence.BitMaskNonContiguous"));

            // No RawBytes evidence check: bit subfields usually carry none, and the
            // RMW reads the live frame bytes at (Offset, Length) instead.
            return new EditFence(true, "OK");
        }

        // Bit-level in the PDML (LengthBits set) but no usable mask: not editable.
        if (field.LengthBits >= 0)
            return RejectFence(field.Name, LocalizationService.Resolve("Fence.BitMaskMissing"));

        if (field.RawBytes.Length != field.Length || field.RawBytes.Length == 0)
            return RejectFence(field.Name, LocalizationService.Resolve("Fence.NoByteEvidence", field.RawBytes.Length, field.Length));

        // Recorded bytes must agree with actual frame bytes at the field's offset.
        if (!field.RawBytes.AsSpan().SequenceEqual(packet.EffectiveData.AsSpan(field.Offset, field.Length)))
            return RejectFence(field.Name, LocalizationService.Resolve("Fence.BytesDisagree"));

        return new EditFence(true, "OK");
    }

    /// <summary>
    /// Applies a new raw byte value to a specific protocol field within a packet.
    /// Creates a modified copy of the packet bytes if not already dirty.
    /// </summary>
    /// <returns>The updated effective data bytes.</returns>
    public byte[] ApplyFieldEdit(Packet packet, ProtocolField field, byte[] newValue)
    {
        if (field.Offset < 0)
            throw new ArgumentException("Field has no valid offset.", nameof(field));

        int fieldLen = field.Length > 0 ? field.Length : newValue.Length;

        if (fieldLen != newValue.Length)
            throw new ArgumentException(
                $"Field length mismatch: field expects {fieldLen} bytes but value is {newValue.Length} bytes.",
                nameof(newValue));

        if (field.Offset + fieldLen > packet.EffectiveData.Length)
            throw new ArgumentOutOfRangeException(nameof(field),
                $"Field at offset {field.Offset} with length {fieldLen} exceeds packet data.");

        // Apply the modification (marks packet as dirty and clones original)
        packet.ApplyModification(field.Offset, newValue);

        // Update the field's display representation
        field.RawBytes = newValue;
        field.DisplayValue = FormatHexValue(newValue);

        return packet.EffectiveData;
    }

    /// <summary>
    /// Converts a decimal/IP/MAC/string typed into the protocol tree into the raw
    /// bytes for a field, validating that the parsed value fits the field's type
    /// and byte length. Throws <see cref="ArgumentException"/> on invalid input.
    /// </summary>
    public static byte[] ConvertRawValue(FieldKind kind, string input, int expectedLength)
    {
        string text = input.Trim();
        if (string.IsNullOrWhiteSpace(text))
            throw new ArgumentException("Value cannot be empty.", nameof(input));

        switch (kind)
        {
            case FieldKind.UInt:
                return ConvertUInt(text, expectedLength);
            case FieldKind.Int:
                return ConvertInt(text, expectedLength);
            case FieldKind.IPv4:
                return ConvertIPv4(text);
            case FieldKind.IPv6:
                return ConvertIPv6(text);
            case FieldKind.Mac:
                return ConvertMac(text);
            case FieldKind.Bcd:
                return ConvertBcd(text, expectedLength);
            case FieldKind.Bytes:
                return ConvertBytes(text, expectedLength);
            case FieldKind.String:
                var strBytes = System.Text.Encoding.UTF8.GetBytes(text);
                if (strBytes.Length > expectedLength)
                    throw new ArgumentException(
                        $"Value too long: {strBytes.Length} bytes, field holds {expectedLength}.", nameof(input));
                if (strBytes.Length < expectedLength)
                    strBytes = [.. strBytes, .. new byte[expectedLength - strBytes.Length]];
                return strBytes;
            default:
                throw new ArgumentException($"Field type {kind} is not editable.", nameof(kind));
        }
    }

    /// <summary>
    /// Parses colon-hex (aa:bb:cc), plain hex (aabbcc) or 0x-prefixed hex into exactly
    /// <paramref name="expectedLength"/> bytes. REPLACE-only editing means any length
    /// mismatch is rejected rather than padded — offsets outside the span must stay valid.
    /// </summary>
    private static byte[] ConvertBytes(string text, int expectedLength)
    {
        string hexText = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? text[2..] : text;
        hexText = hexText.Replace(":", string.Empty).Replace(" ", string.Empty);
        if (hexText.Length == 0 || (hexText.Length & 1) != 0)
            throw new ArgumentException($"'{text}' is not valid hex bytes.", nameof(text));

        byte[] bytes;
        try
        {
            bytes = Convert.FromHexString(hexText);
        }
        catch (FormatException)
        {
            throw new ArgumentException($"'{text}' is not valid hex bytes.", nameof(text));
        }

        if (bytes.Length != expectedLength)
            throw new ArgumentException(
                $"Value is {bytes.Length} bytes, field holds {expectedLength}.", nameof(text));
        return bytes;
    }

    private static byte[] ConvertUInt(string text, int length)
    {
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!ulong.TryParse(text.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out ulong hex))
                throw new ArgumentException($"'{text}' is not a valid hexadecimal value.", nameof(text));
            return LengthCheckedBigEndian(hex, length, unsigned: true, text);
        }

        if (!ulong.TryParse(text, out ulong value))
            throw new ArgumentException($"'{text}' is not a valid unsigned integer.", nameof(text));

        return LengthCheckedBigEndian(value, length, unsigned: true, text);
    }

    private static byte[] ConvertInt(string text, int length)
    {
        int bitWidth = length * 8;
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!ulong.TryParse(text.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out ulong hex))
                throw new ArgumentException($"'{text}' is not a valid hexadecimal value.", nameof(text));

            ulong hexMax = bitWidth >= 64 ? ulong.MaxValue : (1UL << bitWidth) - 1ul;
            if (hex > hexMax)
                throw new ArgumentException($"'{text}' exceeds {length}-byte range ({hexMax}).", nameof(text));
            return LengthCheckedBigEndian(hex, length, unsigned: false, text);
        }

        if (!long.TryParse(text, out long value))
            throw new ArgumentException($"'{text}' is not a valid signed integer.", nameof(text));

        long min = bitWidth >= 64 ? long.MinValue : -(1L << (bitWidth - 1));
        long max = bitWidth >= 64 ? long.MaxValue : (1L << (bitWidth - 1)) - 1L;
        if (value < min || value > max)
            throw new ArgumentException($"'{text}' exceeds {length}-byte signed range ({min}..{max}).", nameof(text));

        return LengthCheckedBigEndian(unchecked((ulong)value), length, unsigned: false, text);
    }

    private static byte[] LengthCheckedBigEndian(ulong value, int length, bool unsigned, string text)
    {
        int bitWidth = length * 8;
        ulong max = bitWidth >= 64 ? ulong.MaxValue : (1UL << bitWidth) - 1ul;

        if (unsigned && value > max)
            throw new ArgumentException($"'{text}' exceeds {length}-byte unsigned range (0..{max}).", nameof(text));

        var bytes = new byte[length];
        for (int i = length - 1; i >= 0; i--)
        {
            bytes[i] = (byte)(value & 0xFF);
            value >>= 8;
        }
        return bytes;
    }

    private static byte[] ConvertIPv4(string text)
    {
        if (!System.Net.IPAddress.TryParse(text, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ArgumentException($"'{text}' is not a valid IPv4 address.", nameof(text));
        return ip.GetAddressBytes();
    }

    private static byte[] ConvertIPv6(string text)
    {
        if (!System.Net.IPAddress.TryParse(text, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
            throw new ArgumentException($"'{text}' is not a valid IPv6 address.", nameof(text));
        return ip.GetAddressBytes();
    }

    private static byte[] ConvertMac(string text)
    {
        var parts = text.Split(':');
        if (parts.Length is not (4 or 6 or 8))
            throw new ArgumentException($"'{text}' is not a valid MAC address (expected aa:bb:...).", nameof(text));

        var bytes = new byte[parts.Length];
        for (int i = 0; i < parts.Length; i++)
        {
            if (!byte.TryParse(parts[i], System.Globalization.NumberStyles.HexNumber, null, out bytes[i]))
                throw new ArgumentException($"'{text}' is not a valid MAC address.", nameof(text));
        }
        return bytes;
    }

    /// <summary>
    /// Converts a digit string (IMSI/IMEI/MSISDN, e.g. "001019444408073") into the
    /// swapped-BCD bytes tshark uses for these fields: each byte holds two digits,
    /// low nibble shown first (0x64 renders "46"); an odd digit count pads the last
    /// byte's high nibble with 0xF. The digit count must fit the field's byte length.
    /// </summary>
    private static byte[] ConvertBcd(string text, int length)
    {
        bool odd = (text.Length & 1) == 1;
        if (length <= 0 || text.Length != length * 2 - (odd ? 1 : 0))
            throw new ArgumentException($"'{text}' is not a valid BCD digit string for a {length}-byte field.", nameof(text));
        if (!text.All(char.IsAsciiDigit))
            throw new ArgumentException($"'{text}' is not a valid BCD digit string.", nameof(text));

        var bytes = new byte[length];
        int i = 0;
        int index = 0;
        while (index < text.Length)
        {
            byte low = (byte)(text[index++] - '0');
            byte high = index < text.Length ? (byte)(text[index++] - '0') : (byte)0xF;
            bytes[i++] = (byte)((high << 4) | low);
        }
        return bytes;
    }

    /// <summary>
    /// Applies a hex string value (e.g., "0A1B2C") to a protocol field.
    /// </summary>
    public byte[] ApplyHexStringEdit(Packet packet, ProtocolField field, string hexString)
    {
        var cleanHex = hexString.Replace(" ", "").Replace("0x", "", StringComparison.OrdinalIgnoreCase);
        if (cleanHex.Length % 2 != 0)
            throw new ArgumentException("Hex string must have an even number of characters.", nameof(hexString));

        var bytes = new byte[cleanHex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(cleanHex.Substring(i * 2, 2), 16);

        return ApplyFieldEdit(packet, field, bytes);
    }

    /// <summary>
    /// Given a byte offset in the packet, finds which protocol field (if any)
    /// occupies that offset. Returns the leaf-most (innermost) field, preferring
    /// the most specific match across ALL layers: a real dissected field always
    /// beats a trailing payload catch-all ("UDP payload") that spans everything
    /// after its header, and among equal-priority fields the smallest span wins.
    /// </summary>
    public ProtocolField? FindFieldAtOffset(Packet packet, int offset)
    {
        ProtocolField? best = null;
        foreach (var layer in packet.Layers)
        {
            var candidate = FindFieldInLayer(layer.Fields, offset);
            if (candidate != null && (best == null || IsMoreSpecific(candidate, best)))
                best = candidate;
        }
        return best;
    }

    /// <summary>
    /// True when Wireshark's trailing payload catch-all ("UDP payload",
    /// "TCP payload") spans a byte; such a field only owns bytes that no
    /// deeper dissected field claims.
    /// </summary>
    private static bool IsPayloadContinuation(ProtocolField field)
        => field.Name.Contains("payload", StringComparison.OrdinalIgnoreCase);

    private static bool IsMoreSpecific(ProtocolField candidate, ProtocolField current)
    {
        bool candidatePayload = IsPayloadContinuation(candidate);
        bool currentPayload = IsPayloadContinuation(current);
        if (candidatePayload != currentPayload)
            return !candidatePayload;

        int candidateSpan = candidate.Length > 0 ? candidate.Length : int.MaxValue;
        int currentSpan = current.Length > 0 ? current.Length : int.MaxValue;
        if (candidateSpan != currentSpan)
            return candidateSpan < currentSpan;

        // Equal spans: prefer the inner layer's field (later in wire order),
        // which belongs to the deeper dissector.
        return true;
    }

    /// <summary>
    /// Re-syncs the RawBytes of every in-frame field overlapping an edited byte
    /// span from the packet's current effective bytes. Hex-editor edits never
    /// touch ProtocolField.RawBytes, so without this the tree's gray hex text
    /// goes stale after a hex commit. Out-of-band (reassembled) spans are skipped.
    /// </summary>
    public static void RefreshEditedFieldBytes(Packet packet, int editOffset, int editLength)
    {
        if (packet == null || editOffset < 0 || editLength <= 0)
            return;

        byte[] data = packet.EffectiveData;
        int editEnd = editOffset + editLength;
        if (editOffset >= data.Length)
            return;

        foreach (var layer in packet.Layers)
            RefreshEditedFieldBytesRecursive(layer.Fields, data, editOffset, editEnd);
    }

    private static void RefreshEditedFieldBytesRecursive(
        IEnumerable<ProtocolField> fields, byte[] data, int editStart, int editEnd)
    {
        foreach (var field in fields)
        {
            // Bit fields included too: the fence RMWs effective bytes, not RawBytes.
            if (field.Offset >= 0 && field.Length > 0 && field.Offset + field.Length <= data.Length)
            {
                int fieldEndExclusive = field.Offset + field.Length;
                if (field.Offset < editEnd && editStart < fieldEndExclusive)
                {
                    var current = new byte[field.Length];
                    Array.Copy(data, field.Offset, current, 0, field.Length);
                    field.RawBytes = current;
                }
            }

            if (field.HasChildren)
                RefreshEditedFieldBytesRecursive(field.Children, data, editStart, editEnd);
        }
    }

    private static ProtocolField? FindFieldInLayer(IEnumerable<ProtocolField> fields, int offset)
    {
        foreach (var field in fields)
        {
            int fieldStart = field.Offset;
            int fieldEnd = field.Offset + Math.Max(field.Length, 1);

            if (fieldStart <= offset && offset < fieldEnd)
            {
                // Check children first for more precise match
                if (field.HasChildren)
                {
                    var childMatch = FindFieldInLayer(field.Children, offset);
                    if (childMatch != null)
                        return childMatch;
                }
                return field;
            }

            // Also check children even if offset is outside parent
            // (some Tshark outputs have offset mismatches in nested fields)
            if (field.HasChildren)
            {
                var childMatch = FindFieldInLayer(field.Children, offset);
                if (childMatch != null)
                    return childMatch;
            }
        }
        return null;
    }

    /// <summary>
    /// Gets the byte range for a field as (startOffset, endOffsetExclusive).
    /// </summary>
    public (int Start, int End) GetFieldByteRange(ProtocolField field)
    {
        int length = field.Length > 0 ? field.Length : field.RawBytes.Length;
        return (field.Offset, field.Offset + length);
    }

    /// <summary>
    /// Parses a Tshark offset string like "24:8" into (offset, length).
    /// Returns null if the string is not a valid offset spec.
    /// </summary>
    public static (int Offset, int Length)? ParseTsharkOffset(string? wsOffset)
    {
        if (string.IsNullOrWhiteSpace(wsOffset))
            return null;

        var parts = wsOffset.Split(':');
        if (parts.Length != 2)
            return null;

        if (int.TryParse(parts[0], out int offset) &&
            int.TryParse(parts[1], out int length))
        {
            return (offset, length);
        }
        return null;
    }

    /// <summary>
    /// Parses a Tshark hex value string like "00:11:aa:ff" or "0011aaff"
    /// into a byte array.
    /// </summary>
    public static byte[] ParseTsharkHexValue(string? wsValue)
    {
        if (string.IsNullOrWhiteSpace(wsValue))
            return [];

        var clean = wsValue.Replace(":", "");
        if (clean.Length % 2 != 0)
            return [];

        var result = new byte[clean.Length / 2];
        for (int i = 0; i < result.Length; i++)
            result[i] = Convert.ToByte(clean.Substring(i * 2, 2), 16);

        return result;
    }


    /// <summary>
    /// Computes the full field bytes for a bit-level RMW edit: keeps every bit in the
    /// field's byte span except those covered by <see cref="ProtocolField.BitMask"/>,
    /// which take <paramref name="newRaw"/>. Pure by design — the caller passes the
    /// result through verify-before-commit, which mutates the packet only on success,
    /// so this method must not touch <paramref name="packet"/>.
    /// </summary>
    public static byte[] ComputeBitFieldEditBytes(Packet packet, ProtocolField field, ulong newRaw)
    {
        if (field.Offset < 0 || field.Length <= 0)
            throw new ArgumentException("Field has no valid byte span.", nameof(field));

        if (field.BitMask == 0)
            throw new ArgumentException("Field has no bit mask.", nameof(field));

        var data = packet.EffectiveData;
        if (field.Offset + field.Length > data.Length)
            throw new ArgumentOutOfRangeException(nameof(field),
                $"Field at offset {field.Offset} with length {field.Length} exceeds packet data.");

        ulong mask = (ulong)field.BitMask;
        int k = System.Numerics.BitOperations.PopCount(mask);
        ulong max = k >= 64 ? ulong.MaxValue : (1UL << k) - 1UL;
        if (newRaw > max)
            throw new ArgumentException(
                $"Bit value {newRaw} exceeds maximum {max} for a {k}-bit field.", nameof(newRaw));

        // Read the whole field span big-endian — the same convention the tree uses.
        ulong current = 0;
        for (int i = 0; i < field.Length; i++)
            current = (current << 8) | data[field.Offset + i];

        ulong updated = (current & ~mask) | ((newRaw << field.BitShift) & mask);

        var result = new byte[field.Length];
        for (int i = field.Length - 1; i >= 0; i--)
        {
            result[i] = (byte)(updated & 0xFF);
            updated >>= 8;
        }
        return result;
    }

    private static string FormatHexValue(byte[] bytes) =>
        string.Join(" ", bytes.Select(b => b.ToString("X2")));
}
