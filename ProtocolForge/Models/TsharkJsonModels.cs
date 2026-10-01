using System.Text.Json.Serialization;

namespace ProtocolForge.Models;

// ────────────────────────────────────────────────────────────
// JSON deserialization models for `tshark -T json` output
// See: https://www.wireshark.org/docs/man-pages/tshark.html
// ────────────────────────────────────────────────────────────

/// <summary>
/// Root array element produced by tshark -T json.
/// Each element is one packet.
/// </summary>
public class TsharkPacketRoot
{
    [JsonPropertyName("_index")]
    public string Index { get; set; } = string.Empty;

    [JsonPropertyName("_type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("_score")]
    public string? Score { get; set; }

    [JsonPropertyName("_source")]
    public TsharkSource Source { get; set; } = new();
}

/// <summary>
/// The "_source" container holding the layers object.
/// </summary>
public class TsharkSource
{
    [JsonPropertyName("layers")]
    public TsharkLayers Layers { get; set; } = new();
}

/// <summary>
/// The "layers" object containing all protocol layers.
/// Each property is dynamically named by protocol abbreviation.
/// Layer field arrays contain the actual parsed fields.
/// </summary>
public class TsharkLayers
{
    /// <summary>
    /// The raw frame metadata layer.
    /// </summary>
    [JsonPropertyName("frame")]
    public TsharkLayer? Frame { get; set; }

    /// <summary>
    /// Additional protocol layers are stored as a dictionary
    /// keyed by protocol name (e.g., "pfcp", "ngap", "gtp").
    /// We use JsonExtensionData to capture all protocol layers.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, System.Text.Json.JsonElement> ExtensionData { get; set; } = [];
}

/// <summary>
/// A protocol layer containing an array of field values.
/// Tshark serializes fields as arrays; the first element
/// is the layer summary line, subsequent elements are field entries.
/// </summary>
public class TsharkLayer
{
    [JsonPropertyName("frame.protocols")]
    public string? Protocols { get; set; }

    [JsonPropertyName("frame.file_off")]
    public string? FileOffset { get; set; }

    [JsonPropertyName("frame.time_epoch")]
    public string? TimeEpoch { get; set; }

    [JsonExtensionData]
    public Dictionary<string, System.Text.Json.JsonElement> ExtensionData { get; set; } = [];
}

/// <summary>
/// Low-level protocol field entry from Tshark.
/// Generated dynamically for each field with offset information.
/// </summary>
public class TsharkFieldEntry
{
    /// <summary>
    /// Display string from Tshark (e.g., "PFCP SEID: 0x12345678").
    /// </summary>
    [JsonPropertyName("_value")]
    public string? Value { get; set; }

    /// <summary>
    /// Byte offset and length encoded as "Offset:Length" (e.g., "24:8").
    /// Not all fields have this.
    /// </summary>
    [JsonPropertyName("_ws.offset")]
    public string? WsOffset { get; set; }

    /// <summary>
    /// Full field name as defined in the Wireshark display filter.
    /// </summary>
    [JsonPropertyName("_ws.field_name")]
    public string? FieldName { get; set; }

    /// <summary>
    /// Raw hex value of the field as a colon-separated hex string.
    /// </summary>
    [JsonPropertyName("_ws.value")]
    public string? WsValue { get; set; }

    /// <summary>
    /// Protocol abbreviation this field belongs to.
    /// </summary>
    [JsonPropertyName("_ws.proto")]
    public string? Protocol { get; set; }
}
