using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProtocolForge.Services;

namespace ProtocolForge.ViewModels;

public sealed record SendLogEntry(int PacketIndex, int PacketNumber, bool Success, string Message);

/// <summary>
/// ViewModel for the send toolbar with Start/Pause/Stop buttons
/// and a network adapter dropdown.
/// </summary>
public sealed partial class ToolBarViewModel : ObservableObject
{
    // A 9999-round loop over a large capture emits millions of results. Keeping
    // every one would grow the collection without bound for a diagnostic panel, so
    // the oldest are dropped and the truncation is surfaced rather than silent.
    private const int SendHistoryLimit = 5000;
    private readonly NetworkInterfaceService _interfaceService;
    private readonly PacketSendService _sendService;
    private readonly PacketListViewModel _packetList;

    [ObservableProperty]
    private bool _isSending;

    [ObservableProperty]
    private bool _isPaused;

    [ObservableProperty]
    private bool _canSend;

    [ObservableProperty]
    private NetworkInterfaceInfo? _selectedInterface;

    [ObservableProperty]
    private string _statusText = LocalizationService.Resolve("Status.Ready");

    // Last status shown via ShowStatus, re-resolved on language switch. Exposed
    // read-only so MainWindowViewModel's status mirror can re-resolve the same key.
    private string? _statusKey = "Status.Ready";
    private object?[]? _statusArgs;

    public string? StatusKey => _statusKey;
    public object?[]? StatusArgs => _statusArgs;

    [ObservableProperty]
    private int _totalSent;

    [ObservableProperty]
    private int _totalFailed;

    [ObservableProperty]
    private bool _autoFixFrames;

    [ObservableProperty]
    private PacketSendService.VlanMode _vlanMode = PacketSendService.VlanMode.Leave;

    [ObservableProperty]
    private int _vlanId = 100;

    /// <summary>Options for the VLAN combo, resolved for display rather than raw enum names.</summary>
    public IReadOnlyList<PacketSendService.VlanMode> VlanModes { get; } =
        [PacketSendService.VlanMode.Leave, PacketSendService.VlanMode.Insert,
         PacketSendService.VlanMode.Replace, PacketSendService.VlanMode.Remove];

    [ObservableProperty]
    private bool _isVlanIdVisible;

    partial void OnVlanModeChanged(PacketSendService.VlanMode value) =>
        IsVlanIdVisible = value is PacketSendService.VlanMode.Insert or PacketSendService.VlanMode.Replace;

    [ObservableProperty]
    private bool _isReadOnly;

    partial void OnIsReadOnlyChanged(bool value) => UpdateCanSend();

    [ObservableProperty]
    private double _sendIntervalMs = 0;

    [ObservableProperty]
    private int _loopCount = 1;

    public ObservableCollection<NetworkInterfaceInfo> AvailableInterfaces { get; } = [];

    /// <summary>Per-packet send results for the current and previous runs, newest last.</summary>
    public ObservableCollection<SendLogEntry> SendHistory { get; } = [];

    /// <summary>Results dropped once <see cref="SendHistory"/> hit its cap, so truncation is visible.</summary>
    [ObservableProperty]
    private int _sendHistoryDroppedCount;

    public ToolBarViewModel(
        NetworkInterfaceService interfaceService,
        PacketSendService sendService,
        PacketListViewModel packetList)
    {
        _interfaceService = interfaceService;
        _sendService = sendService;
        _packetList = packetList;
        IsVlanIdVisible = false;

        // Wire send service events
        _sendService.PacketSent += OnPacketSent;
        _sendService.SendCompleted += OnSendCompleted;
        _sendService.SendWarning += OnSendWarning;
        _packetList.SendSelectionChanged += UpdateCanSend;

        // Scan interfaces on construction
        RefreshInterfaces();

        // Update CanSend based on selection + packet availability
        _packetList.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(PacketListViewModel.Packets))
                UpdateCanSend();
        };

        // Re-resolve the last status + derived display strings on language switch.
        LocalizationService.LanguageChanged += OnLanguageChanged;
    }

    public string PauseButtonText => LocalizationService.Resolve(IsPaused ? "Btn.Resume" : "Btn.Pause");

    partial void OnIsPausedChanged(bool value) => OnPropertyChanged(nameof(PauseButtonText));

    /// <summary>
    /// Surfaces a send warning in the status line and the send log, without touching the
    /// sent/failed counters: nothing failed, the send just will not do what was asked.
    /// </summary>
    private void OnSendWarning(string message)
    {
        ShowStatus("Status.SendWarning", message);
        SendLogEntry entry = new(-1, 0, false, message);
        if (SendHistory.Count >= SendHistoryLimit)
        {
            SendHistory.RemoveAt(0);
            SendHistoryDroppedCount++;
        }
        SendHistory.Add(entry);
        TraceLog.Write($"Send warning: {message}");
    }

    private void ShowStatus(string key, params object?[] args)
    {
        _statusKey = key;
        _statusArgs = args;
        StatusText = LocalizationService.Resolve(key, args);
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        if (_statusKey is not null)
            StatusText = LocalizationService.Resolve(_statusKey, _statusArgs ?? Array.Empty<object?>());
        OnPropertyChanged(nameof(PauseButtonText));
    }

    partial void OnSelectedInterfaceChanged(NetworkInterfaceInfo? value)
    {
        UpdateCanSend();
    }

    /// <summary>
    /// Fan the send out to every eligible adapter instead of the one picked in the
    /// combo. Avalonia has no multi-select combo box without pulling in a package, so
    /// this targets all usable NICs — <see cref="TargetInterfaces"/> is what will
    /// actually be used and is reported in the status line before sending.
    /// </summary>
    [ObservableProperty]
    private bool _multiNicSend;

    /// <summary>
    /// Adapters a send will actually use: the combo's selection in single-NIC mode,
    /// every non-loopback adapter that is up in multi-NIC mode.
    /// </summary>
    public IReadOnlyList<NetworkInterfaceInfo> TargetInterfaces =>
        MultiNicSend
            ? AvailableInterfaces.Where(i => !i.IsLoopback && i.IsUp).ToList()
            : SelectedInterface is { } single ? [single] : [];

    partial void OnMultiNicSendChanged(bool value)
    {
        OnPropertyChanged(nameof(TargetInterfaces));
        OnPropertyChanged(nameof(TargetInterfaceSummary));
        UpdateCanSend();
    }

    /// <summary>Human-readable target list, so a multi-NIC send is never a surprise.</summary>
    public string TargetInterfaceSummary =>
        MultiNicSend
            ? string.Join(", ", TargetInterfaces.Select(i => i.Name))
            : SelectedInterface?.Name ?? string.Empty;

    /// <summary>
    /// Recomputes the send gate. Public so the window can re-evaluate it after
    /// inputs it owns change (currently: read-only propagation).
    /// </summary>
    public void RefreshGate() => UpdateCanSend();

    private void UpdateCanSend()
    {
        CanSend = !IsReadOnly
                  && TargetInterfaces.Count > 0
                  && TargetInterfaces.Any(i => !i.IsLoopback)
                  && _packetList.Packets.Any(p => p.SendSelected)
                  && !IsSending;
    }

    /// <summary>
    /// Refreshes the list of available network interfaces.
    /// </summary>
    [RelayCommand]
    private void RefreshInterfaces()
    {
        var currentId = SelectedInterface?.Id;
        AvailableInterfaces.Clear();

        var interfaces = _interfaceService.GetInterfaces();
        foreach (var iface in interfaces)
            AvailableInterfaces.Add(iface);

        // Try to restore previous selection
        if (currentId != null)
        {
            SelectedInterface = AvailableInterfaces.FirstOrDefault(i => i.Id == currentId);
        }

        if (SelectedInterface == null && AvailableInterfaces.Count > 0)
        {
            // Select first non-loopback interface by default
            SelectedInterface = AvailableInterfaces.FirstOrDefault(i => !i.IsLoopback)
                                ?? AvailableInterfaces[0];
        }
    }

    /// <summary>
    /// Sends the given packets immediately over the selected interface,
    /// honoring the current loop/interval/auto-fix toolbar settings.
    /// </summary>
    public async Task<bool> SendPacketsAsync(IReadOnlyList<Models.Packet> packets)
    {
        // 发送门禁。工具栏 Start 与右键「发送此报文」都经由本方法,
        // 因此只在这里判定一次 —— UI 层的 IsEnabled 绑定只是额外的 UX 提示。
        // 判定条件与 CanSend 一致,但**不含** SendSelected:右键路径按设计发送
        // 「当前选中行」而忽略复选框(en-US Tip.SendRow),不能被复选框状态拦住。
        if (IsReadOnly)
        {
            ShowStatus("Status.SendBlockedReadOnly");
            return false;
        }
        var targets = TargetInterfaces;
        if (targets.Count == 0)
        {
            ShowStatus("Status.SelectAdapter");
            return false;
        }
        if (targets.All(i => i.IsLoopback))
        {
            ShowStatus("Status.SendBlockedLoopback");
            return false;
        }
        if (IsSending || packets.Count == 0)
            return false;

        IsSending = true;
        IsPaused = false;
        TotalSent = 0;
        TotalFailed = 0;
        _sendBatch = packets;
        SendHistory.Clear();
        SendHistoryDroppedCount = 0;
        // Multi-NIC fans each packet out to every target, so the count the user sees
        // must be the number of transmissions, not the number of checked packets.
        int transmissions = packets.Count * targets.Count;
        string targetLabel = MultiNicSend
            ? $"{targets.Count}×{TargetInterfaceSummary}"
            : TargetInterfaceSummary;
        if (packets.Count == _packetList.Packets.Count)
            ShowStatus("Status.Sending", transmissions, targetLabel);
        else
            ShowStatus("Status.SendingPartial", transmissions, _packetList.Packets.Count, targetLabel);

        try
        {
            await _sendService.StartSendAsync(
                packets,
                TargetInterfaces,
                loopCount: LoopCount,
                intervalMs: (int)SendIntervalMs,
                autoFixFrames: AutoFixFrames,
                vlanMode: VlanMode,
                vlanId: (ushort)Math.Clamp(VlanId, 0, 4095));
        }
        finally
        {
            IsSending = false;
            IsPaused = false;
        }
        return true;
    }

    /// <summary>
    /// Starts sending the checked packets over the selected interface.
    /// </summary>
    [RelayCommand]
    private async Task StartSendAsync()
    {
        var toSend = _packetList.Packets.Where(p => p.SendSelected).ToList();
        if (TargetInterfaces.Count == 0 || toSend.Count == 0)
            return;
        await SendPacketsAsync(toSend);
    }

    /// <summary>
    /// Toggles between pause and resume.
    /// </summary>
    [RelayCommand]
    private void TogglePauseSend()
    {
        if (IsPaused)
        {
            _sendService.ResumeSend();
            IsPaused = false;
            ShowStatus("Status.Resumed");
        }
        else
        {
            _sendService.PauseSend();
            IsPaused = true;
            ShowStatus("Status.Paused", TotalSent, TotalFailed);
        }
    }

    /// <summary>
    /// Stops the ongoing send operation.
    /// </summary>
    [RelayCommand]
    private void StopSend()
    {
        _sendService.StopSend();
        IsSending = false;
        IsPaused = false;
        ShowStatus("Status.Stopped", TotalSent, TotalFailed);
    }

    private void OnPacketSent(PacketSendResult result)
    {
        TotalSent = _sendService.TotalSent;
        TotalFailed = _sendService.TotalFailed;
        // Neutral frame; result.Message is already the localized Send.* text.
        _statusKey = null;
        StatusText = $"[{result.PacketIndex}] {result.Message}";

        // PacketIndex is the position in the batch handed to the send service, which
        // is the document index only when the whole capture was sent. Map it back
        // through the batch so the history points at the row the user ticked.
        var packetNumber = result.PacketIndex >= 0 && result.PacketIndex < _sendBatch.Count
            ? _sendBatch[result.PacketIndex].PacketNumber
            : result.PacketIndex + 1;

        SendHistory.Add(new SendLogEntry(result.PacketIndex, packetNumber, result.Success, result.Message));
        while (SendHistory.Count > SendHistoryLimit)
        {
            SendHistory.RemoveAt(0);
            SendHistoryDroppedCount++;
        }
    }

    private IReadOnlyList<Models.Packet> _sendBatch = [];

    /// <summary>
    /// Writes the send history as CSV. Message text is quoted and internal quotes
    /// doubled, because the localized failure reasons contain commas.
    /// </summary>
    [RelayCommand]
    public void ExportSendHistory(string path)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("index,packet,success,message");
        foreach (var e in SendHistory)
        {
            sb.Append(e.PacketIndex).Append(',')
              .Append(e.PacketNumber).Append(',')
              .Append(e.Success ? "true" : "false").Append(',')
              .Append('"').Append(e.Message.Replace("\"", "\"\"")).Append('"')
              .AppendLine();
        }

        File.WriteAllText(path, sb.ToString(), new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        ShowStatus("Status.SendHistoryExported", SendHistory.Count, Path.GetFileName(path));
    }

    [RelayCommand]
    public void ClearSendHistory()
    {
        SendHistory.Clear();
        SendHistoryDroppedCount = 0;
    }

    private void OnSendCompleted()
    {
        IsSending = false;
        IsPaused = false;
        ShowStatus("Status.SendComplete", TotalSent, TotalFailed);
        UpdateCanSend();
    }
}
