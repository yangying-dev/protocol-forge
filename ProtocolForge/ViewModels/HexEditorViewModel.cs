using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using ProtocolForge.Models;
using ProtocolForge.Services;

namespace ProtocolForge.ViewModels;

public sealed partial class HexEditorViewModel : ObservableObject
{
    private readonly ProtocolEditorService _editorService;
    private Packet? _currentPacket;

    private const int BytesPerRow = 16;

    // In-progress (uncommitted) byte-edit run. REPLACE-only: every byte in the run
    // is built from a full pair of typed hex digits, so the run never changes the
    // packet length and all offsets outside the span stay valid.
    private int _pendingAnchor = -1;
    private readonly List<byte> _pendingRunBytes = [];
    private string _pendingNibble = string.Empty;

    [ObservableProperty]
    private ObservableCollection<HexByte> _bytes = [];

    [ObservableProperty]
    private bool _isEnabled;

    [ObservableProperty]
    private int _rowCount;

    [ObservableProperty]
    private int _selectedByteOffset = -1;

    [ObservableProperty]
    private string _statusInfo = LocalizationService.Resolve("Field.ClickToInspect");

    // Last status shown via ShowStatus, re-resolved on language switch.
    private string? _statusKey = "Field.ClickToInspect";
    private object?[]? _statusArgs;

    /// <summary>Raised when the hex view should scroll to a specific byte offset.</summary>
    public event Action<int>? ScrollToOffsetRequested;

    /// <summary>Raised when the hex view should refresh its visual state (backgrounds, text).</summary>
    public event Action? RefreshVisualRequested;

    /// <summary>
    /// Raised after a hex byte edit has been committed to the packet. Payload is
    /// the packet + the replaced span (offset, length) so the tree/list can refresh.
    /// The packet mutation is synchronous; display refresh is fire-and-forget.
    /// </summary>
    public event Action<(Packet Packet, int Offset, int Length)>? HexEdited;

    /// <summary>
    /// Raised when a byte selection resolves to a protocol field, so the tree can
    /// select and reveal the matching node (hex → tree reverse sync).
    /// </summary>
    public event Action<ProtocolField>? FieldFoundAtOffset;

    /// <summary>
    /// True while a byte-edit run has been started but not yet committed/cancelled.
    /// The View uses this to commit before arrows or other navigation.
    /// </summary>
    public bool IsHexEditPending => _pendingAnchor >= 0;

    /// <summary>
    /// True when tshark is unavailable; hex edits are refused. Mirrored from
    /// MainWindowViewModel (same shape as <see cref="ProtocolTreeViewModel.IsReadOnly"/>).
    /// </summary>
    public bool IsReadOnly { get; set; }

    public HexEditorViewModel(ProtocolEditorService editorService)
    {
        _editorService = editorService;

        // Re-resolve the last status on language switch.
        LocalizationService.LanguageChanged += OnLanguageChanged;
    }

    private void ShowStatus(string key, params object?[] args)
    {
        _statusKey = key;
        _statusArgs = args;
        StatusInfo = LocalizationService.Resolve(key, args);
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        if (_statusKey is not null)
            StatusInfo = LocalizationService.Resolve(_statusKey, _statusArgs ?? Array.Empty<object?>());
    }

    public void LoadPacket(Packet? packet)
    {
        TraceLog.Write($"HEX.LoadPacket(packet={packet != null})");
        _currentPacket = packet;
        ClearPendingRun();
        Bytes.Clear();
        SelectedByteOffset = -1;
        StatusInfo = string.Empty;

        if (packet == null)
        {
            IsEnabled = false;
            RowCount = 0;
            return;
        }

        var data = packet.EffectiveData;
        for (int i = 0; i < data.Length; i++)
        {
            Bytes.Add(new HexByte
            {
                Offset = i,
                Value = data[i],
                IsSelected = false,
                IsHighlighted = false,
                HighlightColor = "Transparent",
            });
        }

        RowCount = (data.Length + BytesPerRow - 1) / BytesPerRow;
        IsEnabled = true;
    }

    /// <summary>
    /// Highlights a range of bytes for a protocol field and scrolls to it.
    /// Uses Wireshark-style dark highlight.
    /// </summary>
    public void HighlightField(ProtocolField field)
    {
        TraceLog.Write($"HEX.HighlightField({field.Name}) offset={field.Offset} len={field.Length} parentLayer={field.ParentLayer?.ProtocolName ?? "null"}");
        ClearHighlights();

        if (_currentPacket == null)
            return;

        ComputeFieldSpan(field, _currentPacket.EffectiveData.Length, out int start, out int length);
        if (length <= 0)
            return;
        // Virtual/reassembly fields (e.g. IP fragments) carry synthetic raw spans
        // beyond the packet's real bytes; a single-field highlight must not stretch
        // into data that does not exist in this packet.
        if (start + length > _currentPacket.EffectiveData.Length)
            return;

        HighlightRange(start, length, GetHighlightColor(field));

        // Scroll-follow: the tree → hex highlight path must bring the highlighted
        // span into view (HighlightRange explicitly leaves scrolling to its caller).
        ScrollToOffsetRequested?.Invoke(start);
    }

    public void HighlightLayer(ProtocolLayer layer)
    {
        TraceLog.Write($"HEX.HighlightLayer({layer.ProtocolName})");
        ClearHighlights();

        if (_currentPacket == null)
            return;

        // Match Wireshark: clicking a protocol row highlights only that protocol's
        // own bytes. The trailing "payload" catch-all field (e.g. "UDP payload") is a
        // Wireshark artifact spanning everything after the header, so it must NOT
        // extend the layer's selection into the payload bytes. Virtual reconstruction
        // spans (IP fragments) are out of band and excluded the same way.
        int packetLength = _currentPacket.EffectiveData.Length;
        bool OutOfBand(ProtocolField field, int start, int length)
            => start < 0 || length <= 0 || start + length > packetLength;

        int minStart = int.MaxValue;
        int maxEnd = int.MinValue;
        foreach (var field in layer.Fields)
        {
            if (IsPayloadContinuation(field) || HasPayloadDescendant(field))
                continue;
            ComputeFieldSpan(field, packetLength, out int start, out int length);
            if (OutOfBand(field, start, length))
                continue;
            if (start < minStart) minStart = start;
            if (start + length > maxEnd) maxEnd = start + length;
        }

        // Layer consists solely of payload-style fields (rare) — fall back to the
        // full span so the row still highlights something sensible.
        if (minStart == int.MaxValue)
        {
            foreach (var field in layer.Fields)
            {
                ComputeFieldSpan(field, packetLength, out int start, out int length);
                if (OutOfBand(field, start, length))
                    continue;
                if (start < minStart) minStart = start;
                if (start + length > maxEnd) maxEnd = start + length;
            }
        }

        if (minStart == int.MaxValue)
            return;

        HighlightRange(minStart, maxEnd - minStart, GetProtocolColor(layer.ProtocolName));

        // Scroll-follow for layer clicks (same caller-responsibility as HighlightField).
        ScrollToOffsetRequested?.Invoke(minStart);
    }

    private void HighlightRange(int start, int length, string color)
    {
        int end = Math.Min(start + length, Bytes.Count);

        for (int i = start; i < end; i++)
        {
            if (i < Bytes.Count)
            {
                Bytes[i].IsHighlighted = true;
                Bytes[i].HighlightColor = color;
            }
        }

        // Only set SelectedByteOffset if no byte is currently selected.
        // This prevents overriding the user's actual selection position.
        if (SelectedByteOffset < 0)
            SelectedByteOffset = start;

        // Refresh visual state only - scrolling is handled by the caller.
        RefreshVisualRequested?.Invoke();
    }

    /// <summary>
    /// Resolves the byte span a field covers in the packet. Leaf fields use their
    /// own offset/length; containers without an offset span their descendants.
    /// A zero-size marker leaf ("IE not decoded yet") resolves to the undecoded tail
    /// of its containing IE: from the nearest enclosing field's start to packet end.
    /// </summary>
    private static void ComputeFieldSpan(ProtocolField field, int packetEnd, out int start, out int length)
    {
        // A real leaf field occupies bytes (Length > 0) even at offset 0; positionless
        // containers (Length == 0) defer to their descendants for their extent.
        if (field.Length > 0)
        {
            start = field.Offset;
            length = field.Length;
            return;
        }

        int min = int.MaxValue;
        int maxEnd = int.MinValue;
        foreach (var child in field.Children)
        {
            ComputeFieldSpan(child, packetEnd, out int cs, out int cl);
            if (cs < 0 || cl <= 0)
                continue;
            if (cs < min) min = cs;
            if (cs + cl > maxEnd) maxEnd = cs + cl;
        }

        if (min == int.MaxValue)
        {
            // Only genuine "not decoded" marker leaves resolve to the enclosing IE's
            // undecoded tail. Other positionless fields (Wireshark metadata like
            // stream indices, container headers) must stay spanless or they would
            // extend every ancestor's highlight to the end of the packet.
            if (field.IsUndecodedMarker)
            {
                int markerStart = FindEnclosingStart(field);
                if (markerStart >= 0 && packetEnd > markerStart)
                {
                    start = markerStart;
                    length = packetEnd - markerStart;
                    return;
                }
            }

            start = -1;
            length = 0;
            return;
        }

        start = min;
        length = maxEnd - min;
    }

    private static int FindEnclosingStart(ProtocolField field)
    {
        for (ProtocolField? ancestor = field.ParentField; ancestor != null; ancestor = ancestor.ParentField)
        {
            int s = ancestor.EffectiveStart;
            if (s >= 0)
                return s;
        }

        if (field.ParentLayer != null)
        {
            int min = int.MaxValue;
            foreach (var f in field.ParentLayer.Fields)
            {
                int s = f.EffectiveStart;
                if (s >= 0 && s < min)
                    min = s;
            }
            if (min != int.MaxValue)
                return min;
        }

        return -1;
    }

    /// <summary>
    /// True when the field is Wireshark's trailing payload catch-all ("UDP payload",
    /// "payload"), which spans everything after a protocol's header.
    /// </summary>
    private static bool IsPayloadContinuation(ProtocolField field)
        => field.Name.Contains("payload", StringComparison.OrdinalIgnoreCase);

    private static bool HasPayloadDescendant(ProtocolField field)
        => field.Children.Any(c => IsPayloadContinuation(c) || HasPayloadDescendant(c));

    public ProtocolField? SelectByteAtOffset(int offset)
    {
        if (offset < 0 || offset >= Bytes.Count)
            return null;

        ClearSelection();
        Bytes[offset].IsSelected = true;
        SelectedByteOffset = offset;

        var hexByte = Bytes[offset];
        ShowStatus("Hex.OffsetInfo", offset, hexByte.HexValue, hexByte.AsciiValue);

        if (_currentPacket != null)
        {
            var field = _editorService.FindFieldAtOffset(_currentPacket, offset);
            if (field != null)
            {
                HighlightField(field);
                FieldFoundAtOffset?.Invoke(field);
            }

            // Scroll to the clicked byte to ensure it's visible.
            ScrollToOffsetRequested?.Invoke(offset);
            RefreshVisualRequested?.Invoke();

            return field;
        }

        ScrollToOffsetRequested?.Invoke(offset);
        RefreshVisualRequested?.Invoke();
        return null;
    }

    /// <summary>
    /// Re-extracts address/port fields from the current packet's (possibly modified)
    /// bytes. Called after a protocol-tree edit so the packet-list columns stay in sync.
    /// </summary>
    /// <summary>Packet currently shown in the hex pane; null when no capture is open.</summary>
    public Packet? CurrentPacket => _currentPacket;

    public void RefreshAddressInfo()
    {
        ReExtractAddressInfo();
    }

    /// <summary>
    /// Re-derives the packet-list Source/Destination/port columns from a packet's current
    /// <see cref="Packet.EffectiveData"/>. Per-packet and public so a whole-capture
    /// modification reset can restore columns for every packet it touched, not only the
    /// one on screen.
    /// </summary>
    public static void ReExtractAddressInfo(Packet packet)
    {
        packet.SourceAddress = "N/A";
        packet.DestinationAddress = "N/A";
        packet.SourcePort = -1;
        packet.DestinationPort = -1;

        foreach (var layer in packet.Layers)
        {
            switch (layer.ProtocolName.ToLowerInvariant())
            {
                case "ip":
                case "ipv4":
                    ScanAddressFields(layer.Fields, packet, false);
                    break;
                case "ipv6":
                    ScanAddressFields(layer.Fields, packet, true);
                    break;
                case "udp":
                case "tcp":
                    ScanPortFields(layer.Fields, packet);
                    break;
            }
        }
    }

    /// <summary>Clears the orange "user edited" marks and repaints.</summary>
    public void ClearEditedMarks()
    {
        foreach (var b in Bytes)
            b.IsEdited = false;
        RefreshVisualRequested?.Invoke();
    }

    /// <summary>
    /// Marks the bytes a field occupies as user-edited so the hex view shows the
    /// orange modified background even though editing now happens in the tree.
    /// </summary>
    public void MarkFieldEdited(ProtocolField field)
    {
        if (field.Offset < 0 || field.Length <= 0)
            return;
        int end = Math.Min(field.Offset + field.Length, Bytes.Count);
        for (int i = field.Offset; i < end; i++)
            Bytes[i].IsEdited = true;
        RefreshVisualRequested?.Invoke();
    }

    // ────────────────────────────────────────────────────────
    // Hex-native byte editing (REPLACE-only)
    // ────────────────────────────────────────────────────────

    /// <summary>
    /// Routes one typed hex digit (0-9, a-f, A-F) into the pending edit run.
    /// The odd digit stores a nibble and marks the current byte pending; the even
    /// digit completes the byte into the run and advances cursor + selection to the
    /// next byte. The run is only committed by <see cref="CommitHexEditAsync"/>.
    /// </summary>
    public void HandleHexInput(char c)
    {
        if (IsReadOnly)
        {
            ShowStatus("Field.ReadOnly");
            return;
        }

        if (!IsEnabled || _currentPacket == null || SelectedByteOffset < 0)
            return;

        byte digit = ParseHexDigit(c);
        if (digit > 0xF)
            return;

        if (_pendingAnchor < 0)
        {
            _pendingAnchor = SelectedByteOffset;
            _pendingRunBytes.Clear();
            _pendingNibble = string.Empty;
        }

        // REPLACE-only clamp: never start a byte past the end of the packet.
        int currentOffset = _pendingAnchor + _pendingRunBytes.Count;
        if (currentOffset >= Bytes.Count)
            return;

        _pendingNibble += char.ToLowerInvariant(c).ToString();
        var currentByte = Bytes[currentOffset];

        if (_pendingNibble.Length == 1)
        {
            currentByte.SetPending(_pendingNibble, "?");
            RefreshVisualRequested?.Invoke();
        }
        else
        {
            byte value = (byte)((ParseHexDigit(_pendingNibble[0]) << 4) | ParseHexDigit(_pendingNibble[1]));
            _pendingRunBytes.Add(value);
            _pendingNibble = string.Empty;
            currentByte.SetPending(value.ToString("X2"), ToAsciiChar(value));

            int next = currentOffset + 1;
            if (next < Bytes.Count)
                SelectByteAtOffset(next);
            else
                RefreshVisualRequested?.Invoke();
        }
    }

    /// <summary>
    /// Commits the pending run as a single REPLACE edit: fence-checked, then
    /// <see cref="Packet.ApplyModification"/> (synchronous), edited bytes marked
    /// orange, then <see cref="HexEdited"/> raised so the tree/list refresh runs
    /// the existing single-packet reparse once. No-op when no run is pending.
    /// </summary>
    public Task CommitHexEditAsync()
    {
        Packet? packet = _currentPacket;
        int anchor = _pendingAnchor;
        if (packet == null || anchor < 0)
            return Task.CompletedTask;

        if (IsReadOnly)
        {
            ShowStatus("Field.ReadOnly");
            CancelHexEdit();
            return Task.CompletedTask;
        }

        // Assemble the run bytes. A lone odd digit is an uncompleted high nibble
        // and is padded with a zero low nibble (0x4 → 0x40).
        var runBytes = new List<byte>(_pendingRunBytes);
        if (_pendingNibble.Length == 1)
        {
            int partialOffset = anchor + runBytes.Count;
            if (partialOffset < Bytes.Count)
                runBytes.Add((byte)(ParseHexDigit(_pendingNibble[0]) << 4));
        }

        if (runBytes.Count == 0)
        {
            CancelHexEdit();
            return Task.CompletedTask;
        }

        if (anchor + runBytes.Count > packet.EffectiveData.Length)
        {
            ShowStatus("Hex.OutOfRange", anchor, runBytes.Count);
            CancelHexEdit();
            return Task.CompletedTask;
        }

        byte[] newBytes = runBytes.ToArray();
        packet.ApplyModification(anchor, newBytes);

        int end = Math.Min(anchor + newBytes.Length, Bytes.Count);
        for (int i = anchor; i < end; i++)
        {
            var hexByte = Bytes[i];
            hexByte.Value = newBytes[i - anchor];
            hexByte.IsEdited = true;
            hexByte.ClearPending();
        }

        ClearPendingRun();
        RefreshBytes();
        RefreshAddressInfo();
        ShowStatus("Hex.Edited", newBytes.Length, anchor);
        RefreshVisualRequested?.Invoke();

        HexEdited?.Invoke((packet, anchor, newBytes.Length));

        return Task.CompletedTask;
    }

    /// <summary>
    /// Cancels the pending run and restores the original display of its bytes.
    /// The packet is never touched.
    /// </summary>
    public void CancelHexEdit()
    {
        if (_pendingAnchor < 0)
            return;

        int count = _pendingRunBytes.Count + (_pendingNibble.Length == 1 ? 1 : 0);
        int end = Math.Min(_pendingAnchor + count, Bytes.Count);
        for (int i = _pendingAnchor; i < end; i++)
            Bytes[i].ClearPending();

        ClearPendingRun();
        ShowStatus("Hex.Cancel");
        RefreshVisualRequested?.Invoke();
    }

    private void ClearPendingRun()
    {
        _pendingAnchor = -1;
        _pendingRunBytes.Clear();
        _pendingNibble = string.Empty;
    }

    private static byte ParseHexDigit(char c) => c switch
    {
        >= '0' and <= '9' => (byte)(c - '0'),
        >= 'a' and <= 'f' => (byte)(c - 'a' + 10),
        >= 'A' and <= 'F' => (byte)(c - 'A' + 10),
        _ => 0xFF,
    };

    private static string ToAsciiChar(byte value) =>
        value is >= 32 and <= 126 ? ((char)value).ToString() : ".";

    private void ReExtractAddressInfo()
    {
        if (_currentPacket == null) return;

        ReExtractAddressInfo(_currentPacket);
    }

    private static void ScanAddressFields(
        System.Collections.ObjectModel.ObservableCollection<ProtocolField> fields,
        Packet packet, bool isV6)
    {
        foreach (var f in fields)
        {
            if (ReadFieldBytes(packet, f, isV6 ? 16 : 4) is { } bytes)
            {
                string hex = string.Join("", bytes.Select(b => b.ToString("X2")));
                if (f.Name is "src" or "ip_src" or "addr" or "Source Address")
                {
                    string ip = TryConvertHexToIp(hex, isV6);
                    if (isV6) packet.SourceAddress = ip;
                    else if (packet.SourceAddress == "N/A") packet.SourceAddress = ip;
                }
                else if (f.Name is "dst" or "ip_dst" or "Destination Address")
                {
                    string ip = TryConvertHexToIp(hex, isV6);
                    if (isV6) packet.DestinationAddress = ip;
                    else if (packet.DestinationAddress == "N/A") packet.DestinationAddress = ip;
                }
            }
            if (f.HasChildren) ScanAddressFields(f.Children, packet, isV6);
        }
    }

    private static void ScanPortFields(
        System.Collections.ObjectModel.ObservableCollection<ProtocolField> fields,
        Packet packet)
    {
        foreach (var f in fields)
        {
            if (f.Name is "srcport" or "port" or "Source Port" && ReadFieldBytes(packet, f, 2) is { } srcBytes)
            {
                int port = (srcBytes[0] << 8) | srcBytes[1];
                if (port > 0) packet.SourcePort = port;
            }
            else if (f.Name is "dstport" or "Destination Port" && ReadFieldBytes(packet, f, 2) is { } dstBytes)
            {
                int port = (dstBytes[0] << 8) | dstBytes[1];
                if (port > 0) packet.DestinationPort = port;
            }
            if (f.HasChildren) ScanPortFields(f.Children, packet);
        }
    }

    private static byte[]? ReadFieldBytes(Packet packet, ProtocolField field, int expectedLength)
    {
        if (field.Offset < 0 || field.Length != expectedLength)
            return null;
        var data = packet.EffectiveData;
        if (field.Offset + field.Length > data.Length)
            return null;
        var bytes = new byte[field.Length];
        Array.Copy(data, field.Offset, bytes, 0, field.Length);
        return bytes;
    }

    private static string TryConvertHexToIp(string hex, bool isV6)
    {
        if (string.IsNullOrEmpty(hex)) return "N/A";
        if (!isV6 && hex.Length == 8)
        {
            try
            {
                var bytes = Convert.FromHexString(hex);
                if (bytes.Length == 4) return string.Join(".", bytes);
            }
            catch { }
        }
        else if (isV6 && hex.Length == 32)
        {
            try
            {
                var bytes = Convert.FromHexString(hex);
                if (bytes.Length == 16) return new System.Net.IPAddress(bytes).ToString();
            }
            catch { }
        }
        return hex;
    }

    private void ClearHighlights()
    {
        foreach (var b in Bytes)
        {
            b.IsHighlighted = false;
            b.HighlightColor = "Transparent";
        }
    }

    private void ClearSelection()
    {
        foreach (var b in Bytes)
            b.IsSelected = false;
    }

    /// <summary>
    /// Returns a Wireshark-style highlight color (translucent dark) based on protocol.
    /// Colors are applied as semi-transparent overlays so the hex text remains visible.
    /// </summary>
    private static string GetHighlightColor(ProtocolField field)
        => GetProtocolColor(field.ParentLayer?.ProtocolName ?? "");

    private static string GetProtocolColor(string protocolName)
    {
        var proto = protocolName.ToLowerInvariant();
        return proto switch
        {
            "pfcp" => "#CC81C784",    // Material Green 200 (light green tint)
            "ngap" => "#CC90CAF9",    // Material Blue 200 (light blue tint)
            "gtp" or "gtp-u" => "#CCFFCC80", // Material Orange 200
            "nas" or "nas-eps" => "#CCF48FB1", // Material Pink 200
            "s1ap" => "#CCCE93D8",    // Material Purple 200
            "diameter" => "#CC80DEEA", // Material Cyan 200
            "http" or "http2" => "#CCA1887F", // Material Brown 200
            "sctp" => "#CCB0BEC5",    // Material Blue Grey 200
            "udp" => "#CC9FA8DA",     // Material Indigo 200
            "ip" => "#CCC5E1A5",      // Material Light Green 200
            "eth" => "#CCE0E0E0",     // Light grey
            _ => "#CCB39DDB",         // Material Deep Purple 200 (default)
        };
    }

    /// <summary>
    /// Re-reads every byte from the current packet's <see cref="Packet.EffectiveData"/>
    /// and repaints. The repaint is mandatory: the hex rows live in view code-behind, so
    /// a value change alone leaves stale text until the user clicks another cell.
    /// </summary>
    public void RefreshBytes()
    {
        if (_currentPacket == null) return;

        var data = _currentPacket.EffectiveData;
        for (int i = 0; i < Math.Min(data.Length, Bytes.Count); i++)
        {
            Bytes[i].Value = data[i];
        }
        RefreshVisualRequested?.Invoke();
    }
}
