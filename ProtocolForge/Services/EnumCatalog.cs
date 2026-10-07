using System.Collections.Concurrent;
using ProtocolForge.Models;

namespace ProtocolForge.Services;

/// <summary>
/// Session-scoped record of which byte values tshark rendered as which named
/// interpretation, keyed by PDML field name.
///
/// tshark has no enum-dump facility and a PDML <c>show</c> attribute only ever
/// describes the value in that one packet, so the full 3GPP table is unreachable
/// from outside. Harvesting during dissection costs no extra tshark invocation:
/// the tree build already holds the showname and the raw bytes.
/// </summary>
public static class EnumCatalog
{
    private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, string>> Observed = new();

    /// <summary>
    /// Records that tshark rendered <paramref name="rawHex"/> for
    /// <paramref name="pdmlFieldName"/> as <paramref name="label"/>.
    /// </summary>
    public static void Observe(string pdmlFieldName, string label, string rawHex)
    {
        if (string.IsNullOrEmpty(pdmlFieldName) || string.IsNullOrEmpty(rawHex))
            return;
        if (!LooksInterpreted(label))
            return;

        var forField = Observed.GetOrAdd(pdmlFieldName, _ => new ConcurrentDictionary<string, string>());
        forField[rawHex] = label;
    }

    /// <summary>
    /// Every interpretation observed for a field, ordered by numeric value where the
    /// bytes form one so list order matches the wire value rather than hash order.
    /// </summary>
    public static IReadOnlyList<EnumOption> OptionsFor(string pdmlFieldName)
    {
        if (string.IsNullOrEmpty(pdmlFieldName) ||
            !Observed.TryGetValue(pdmlFieldName, out var forField) ||
            forField.IsEmpty)
        {
            return [];
        }

        return forField
            .Select(kv => new EnumOption(kv.Value, kv.Key))
            .OrderBy(o => TryNumericValue(o.RawHex) ?? int.MaxValue)
            .ThenBy(o => o.Label, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>True when a label names a value rather than restating it.</summary>
    private static bool LooksInterpreted(string label)
    {
        if (string.IsNullOrWhiteSpace(label))
            return false;
        if (label.Length > 160)
            return false;

        // A label that is exactly the value adds nothing to a dropdown the user can
        // already type. Hex and bare decimals are the two shapes tshark emits for a
        // field with no value_string, so those are what we filter out.
        if (label.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return false;
        return !ulong.TryParse(label, out _);
    }

    private static long? TryNumericValue(string rawHex)
    {
        if (string.IsNullOrEmpty(rawHex) || rawHex.Length > 8)
            return null;
        return ulong.TryParse(rawHex, System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out var v)
            ? (long)v
            : null;
    }

    /// <summary>Drops all observations. Called when a new document is loaded.</summary>
    public static void Reset() => Observed.Clear();
}
