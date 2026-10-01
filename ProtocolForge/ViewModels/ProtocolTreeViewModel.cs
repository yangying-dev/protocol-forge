using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProtocolForge.Models;
using ProtocolForge.Services;

namespace ProtocolForge.ViewModels;

/// <summary>
/// ViewModel for the protocol tree panel (center pane).
/// Shows parsed protocol layers and fields/Information Elements for the selected packet.
/// Supports clicking a field to highlight it in the hex editor and editing a field's
/// value in place (decimal/IP/MAC/string input converted to raw bytes).
/// </summary>
public sealed partial class ProtocolTreeViewModel : ObservableObject
{
    private readonly ProtocolEditorService _editorService;
    private readonly EditTransactionService _editTransaction;

    [ObservableProperty]
    private ObservableCollection<ProtocolLayer> _layers = [];

    [ObservableProperty]
    private bool _isEnabled;

    [ObservableProperty]
    private string _selectedFieldInfo = string.Empty;

    // Last status shown via ShowStatus, re-resolved on language switch.
    private string? _statusKey = "Field.ClickToInspect";
    private object?[]? _statusArgs;

    /// <summary>
    /// Raised when the user clicks a protocol field.
    /// Payload is the field + the packet so the hex editor can highlight it.
    /// </summary>
    public event Action<(Packet Packet, ProtocolField Field)>? FieldSelected;

    /// <summary>
    /// Raised when the user clicks a protocol layer header.
    /// Payload is the layer + the packet so the hex editor can highlight the layer.
    /// </summary>
    public event Action<(Packet Packet, ProtocolLayer Layer)>? LayerSelected;

    /// <summary>
    /// Raised after a field value has been verified and committed to the packet bytes.
    /// </summary>
    public event Action<(Packet Packet, ProtocolField Field)>? FieldEdited;

    /// <summary>
    /// Raised when a field should be visually selected and revealed in the tree
    /// (hex → tree reverse sync). The View performs the actual container walk;
    /// no load or click events are involved.
    /// </summary>
    public event Action<ProtocolField>? TreeSelectRequested;

    public ProtocolTreeViewModel(ProtocolEditorService editorService, EditTransactionService editTransaction)
    {
        _editorService = editorService;
        _editTransaction = editTransaction;

        // Idle hint shown until a field is clicked (replaces the removed XAML TargetNullValue).
        SelectedFieldInfo = LocalizationService.Resolve("Field.ClickToInspect");

        // Re-resolve the last status on language switch.
        LocalizationService.LanguageChanged += OnLanguageChanged;
    }

    private void ShowStatus(string key, params object?[] args)
    {
        _statusKey = key;
        _statusArgs = args;
        SelectedFieldInfo = LocalizationService.Resolve(key, args);
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        if (_statusKey is not null)
            SelectedFieldInfo = LocalizationService.Resolve(_statusKey, _statusArgs ?? Array.Empty<object?>());
    }

    /// <summary>
    /// Context frames for the currently selected packet's tree build, supplied
    /// by MainWindowViewModel before a commit. The transaction refuses to verify
    /// when the original build had context but this is null.
    /// </summary>
    public IReadOnlyList<(long Timestamp, byte[] Data)>? PendingContextFrames { get; set; }

    /// <summary>
    /// Link layer type for the current document, supplied by MainWindowViewModel.
    /// </summary>
    public int PendingLinkLayerType { get; set; } = 1;

    /// <summary>
    /// True when tshark is unavailable (read-only mode); commits are refused.
    /// Mirrored from MainWindowViewModel.
    /// </summary>
    public bool IsReadOnly { get; set; }

    /// <summary>
    /// Updates the tree for a newly selected packet.
    /// </summary>
    public void LoadPacket(Packet? packet)
    {
        Layers.Clear();
        IsEnabled = packet != null;
        SelectedFieldInfo = string.Empty;

        if (packet == null)
            return;

        foreach (var layer in packet.Layers)
            Layers.Add(layer);
    }

    /// <summary>
    /// Called from the View when a field is clicked in the tree.
    /// Propagates the event so the hex editor can react.
    /// </summary>
    public void OnFieldClicked(Packet packet, ProtocolField field)
    {
        // Neutral hex-position frame (matches the hex display format); not localized.
        _statusKey = null;
        if (field.Offset >= 0 && field.Length > 0)
        {
            SelectedFieldInfo = $"{field.Name} @ [{field.Offset}:{field.Offset + field.Length - 1}]";
        }
        else
        {
            SelectedFieldInfo = field.Name;
        }

        FieldSelected?.Invoke((packet, field));
    }

    /// <summary>
    /// Called from the View when a layer header is clicked in the tree.
    /// Propagates the event so the hex editor can highlight the whole layer.
    /// </summary>
    public void OnLayerClicked(Packet packet, ProtocolLayer layer)
    {
        // layer.DisplayText is tshark's showname (not localized).
        _statusKey = null;
        SelectedFieldInfo = layer.DisplayText;
        LayerSelected?.Invoke((packet, layer));
    }

    /// <summary>
    /// Requests the View to visually select and reveal the given field (hex → tree
    /// reverse sync). Fires <see cref="TreeSelectRequested"/> only; never touches
    /// the tree contents or raises click/load events.
    /// </summary>
    public void SelectFieldOnTree(ProtocolField field)
    {
        // Neutral hex-position frame (matches the hex display format); not localized.
        _statusKey = null;
        if (field.Name.Length > 0)
            SelectedFieldInfo = $"{field.Name} @ [{field.Offset}:{field.Offset + field.Length - 1}]";
        TreeSelectRequested?.Invoke(field);
    }

    /// <summary>
    /// Clears the tree.
    /// </summary>
    public void Clear()
    {
        Layers.Clear();
        IsEnabled = false;
        SelectedFieldInfo = string.Empty;
    }

    // ────────────────────────────────────────────────────────
    // Post-edit display refresh (background reparse backfill)
    // ────────────────────────────────────────────────────────

    /// <summary>
    /// Patches Name/DisplayValue of the tree in place from freshly re-parsed PDML
    /// data (single-packet reparse after a field edit). Matches each field by its
    /// <see cref="ProtocolField.OriginalPdmlName"/> + <see cref="ProtocolField.Offset"/>
    /// against the reparse lookup, and refreshes layer display texts. Tree structure
    /// is never rebuilt here — only display strings change.
    /// </summary>
    public int RefreshFieldDisplays(Packet packet, PdmlData fresh)
    {
        int misses = 0;
        foreach (var layer in Layers)
        {
            if (TryGetProtoShowName(fresh.ProtoShowNames, layer.ProtocolName, layer.Offset, out var showname) &&
                !string.IsNullOrWhiteSpace(showname))
            {
                layer.DisplayText = showname;
            }
            misses += PatchFieldTexts(layer.Fields, fresh.FieldLookup);
        }
        return misses;
    }

    private static bool TryGetProtoShowName(
        Dictionary<(string Name, int Pos), string> lookup,
        string protocolName,
        int layerOffset,
        out string showname)
    {
        if (lookup.TryGetValue((protocolName, layerOffset), out showname!))
            return true;

        // Offset-mismatch safety net: fall back to the first (name, pos) entry
        // for this protocol, regardless of position.
        foreach (var kvp in lookup)
        {
            if (string.Equals(kvp.Key.Name, protocolName, StringComparison.OrdinalIgnoreCase))
            {
                showname = kvp.Value;
                return true;
            }
        }

        showname = string.Empty;
        return false;
    }

    private static int PatchFieldTexts(
        IEnumerable<ProtocolField> fields,
        Dictionary<(string Name, int Pos), string> lookup)
    {
        int misses = 0;
        foreach (var field in fields)
        {
            // Containers (e.g. a PFCP IE like F-SEID) carry Offset==0 while
            // their children hold the real byte position, so fall back to the
            // effective (min-descendant) offset when matching against reparse data.
            int matchOffset = field.Offset > 0 ? field.Offset : field.EffectiveStart;

            // Anonymous containers carry an empty OriginalPdmlName and are matched
            // via the ("", pos) lookup key (their rendered text varies with edits).
            if (matchOffset >= 0 &&
                lookup.TryGetValue((field.OriginalPdmlName, matchOffset), out var showname) &&
                TsharkService.TrySplitShowname(showname) is var (name, value))
            {
                field.Name = name;
                field.DisplayValue = value;
            }
            else if (field.OriginalPdmlName.Length > 0 && matchOffset >= 0)
            {
                misses++;
            }
            misses += PatchFieldTexts(field.Children, lookup);
        }
        return misses;
    }

    // ────────────────────────────────────────────────────────
    // In-place field editing (verify-before-commit)
    // ────────────────────────────────────────────────────────

    private ProtocolField? _editingField;
    private bool _commitInProgress;

    /// <summary>True while a field value editor is open.</summary>
    public bool IsEditingField => _editingField != null;

    /// <summary>
    /// Opens an editor for the given field: converts its current raw bytes into
    /// human-readable text (decimal/IP/MAC/string) and marks it as editing.
    /// </summary>
    public void BeginFieldEdit(Packet packet, ProtocolField field)
    {
        var fence = _editorService.CheckTreeEditFence(packet, field);
        if (!fence.Allowed)
        {
            ShowStatus("Field.NotEditable", fence.Reason);
            return;
        }

        CancelFieldEdit();
        _editingField = field;
        field.EditText = FormatForEdit(field);
        field.IsEditing = true;
        ShowStatus("Field.Editing", field.Name);
    }

    /// <summary>
    /// Commits the pending field edit via verify-before-commit. The packet is
    /// only mutated when tshark reparse confirms the edit landed correctly.
    /// On failure the packet is byte-identical, the editor stays open, and the
    /// reason is surfaced via <see cref="SelectedFieldInfo"/>.
    /// </summary>
    public async Task CommitFieldEditAsync()
    {
        var field = _editingField;
        if (field == null)
            return;

        if (_commitInProgress)
            return;

        if (IsReadOnly)
        {
            ShowStatus("Field.ReadOnly");
            return;
        }

        var packet = field.ParentLayer?.ParentPacket;
        if (packet == null)
        {
            CancelFieldEdit();
            return;
        }

        _commitInProgress = true;
        try
        {
            var bytes = ProtocolEditorService.ConvertRawValue(field.Kind, field.EditText, field.Length);
            if (bytes.AsSpan().SequenceEqual(field.RawBytes))
            {
                field.IsEditing = false;
                _editingField = null;
                ShowStatus("Field.NoChange", field.Name);
                return;
            }

            var result = await _editTransaction.CommitFieldEditAsync(
                packet, field, bytes,
                PendingContextFrames, PendingLinkLayerType);

            if (!result.Success)
            {
                if (_editingField == field)
                    ShowStatus("Field.Blocked", result.Reason);
                return;
            }

            if (result.Fresh is { } fresh)
            {
                int misses = RefreshFieldDisplays(packet, fresh);
                if (misses > 0)
                    TraceLog.Write($"Display refresh: {misses} field(s) unmatched for packet #{packet.PacketNumber}");
            }

            field.DisplayValue = FormatForEdit(field);
            var edited = field;
            if (_editingField == field)
            {
                field.IsEditing = false;
                _editingField = null;
                ShowStatus("Field.SetTo", edited.Name, edited.EditText);
            }
            FieldEdited?.Invoke((packet, edited));
        }
        catch (ArgumentException ex)
        {
            // ex.Message is a raw exception text, not a dictionary key.
            _statusKey = null;
            SelectedFieldInfo = ex.Message;
        }
        finally
        {
            _commitInProgress = false;
        }
    }

    /// <summary>Discards the pending edit and closes the editor.</summary>
    public void CancelFieldEdit()
    {
        if (_editingField == null)
            return;
        _editingField.IsEditing = false;
        _editingField = null;
    }

    /// <summary>
    /// Renders the field's current raw bytes as edit text: big-endian integers as
    /// decimal, IP/MAC as the usual dotted/colon form, BCD fields (IMSI/IMEI/
    /// MSISDN) as the plain digit string, strings as UTF-8 text.
    /// </summary>
    private static string FormatForEdit(ProtocolField field)
    {
        var bytes = field.RawBytes;
        if (bytes.Length == 0)
            return string.Empty;

        return field.Kind switch
        {
            FieldKind.UInt => field.HexPreferred ? "0x" + ToBigEndianUInt64(bytes).ToString("X") : ToBigEndianUInt64(bytes).ToString(),
            FieldKind.Int => field.HexPreferred ? "0x" + ToBigEndianInt64(bytes).ToString("X") : ToBigEndianInt64(bytes).ToString(),
            FieldKind.IPv4 => string.Join(".", bytes),
            FieldKind.IPv6 => new System.Net.IPAddress(bytes).ToString(),
            FieldKind.Mac => string.Join(":", bytes.Select(b => b.ToString("X2"))),
            FieldKind.Bcd => FormatBcdDigits(bytes),
            FieldKind.String => System.Text.Encoding.UTF8.GetString(bytes).TrimEnd('\0'),
            _ => string.Empty,
        };
    }

    private static ulong ToBigEndianUInt64(byte[] bytes)
    {
        ulong value = 0;
        foreach (byte b in bytes)
            value = (value << 8) | b;
        return value;
    }

    private static long ToBigEndianInt64(byte[] bytes)
    {
        ulong value = ToBigEndianUInt64(bytes);
        int shift = (sizeof(ulong) - bytes.Length) * 8;
        return (long)(value << shift) >> shift;
    }

    /// <summary>
    /// Renders swapped-BCD bytes as the digit string tshark displays: two digits
    /// per byte (low nibble first), skipping 0xF filler nibbles.
    /// </summary>
    private static string FormatBcdDigits(byte[] bytes)
    {
        var sb = new System.Text.StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
        {
            byte low = (byte)(b & 0x0F);
            byte high = (byte)(b >> 4);
            if (low != 0xF)
                sb.Append((char)('0' + low));
            if (high != 0xF)
                sb.Append((char)('0' + high));
        }
        return sb.ToString();
    }
}
