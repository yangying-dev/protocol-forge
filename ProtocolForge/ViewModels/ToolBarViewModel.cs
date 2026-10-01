using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProtocolForge.Services;

namespace ProtocolForge.ViewModels;

/// <summary>
/// ViewModel for the send toolbar with Start/Pause/Stop buttons
/// and a network adapter dropdown.
/// </summary>
public sealed partial class ToolBarViewModel : ObservableObject
{
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
    private bool _isReadOnly;

    partial void OnIsReadOnlyChanged(bool value) => UpdateCanSend();

    [ObservableProperty]
    private double _sendIntervalMs = 0;

    [ObservableProperty]
    private int _loopCount = 1;

    public ObservableCollection<NetworkInterfaceInfo> AvailableInterfaces { get; } = [];

    public ToolBarViewModel(
        NetworkInterfaceService interfaceService,
        PacketSendService sendService,
        PacketListViewModel packetList)
    {
        _interfaceService = interfaceService;
        _sendService = sendService;
        _packetList = packetList;

        // Wire send service events
        _sendService.PacketSent += OnPacketSent;
        _sendService.SendCompleted += OnSendCompleted;
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
    /// Recomputes the send gate. Public so the window can re-evaluate it after
    /// inputs it owns change (currently: read-only propagation).
    /// </summary>
    public void RefreshGate() => UpdateCanSend();

    private void UpdateCanSend()
    {
        CanSend = !IsReadOnly
                  && SelectedInterface != null
                  && !SelectedInterface.IsLoopback
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
        if (SelectedInterface == null)
        {
            ShowStatus("Status.SelectAdapter");
            return false;
        }
        if (SelectedInterface.IsLoopback)
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
        if (packets.Count == _packetList.Packets.Count)
            ShowStatus("Status.Sending", packets.Count, SelectedInterface.Name);
        else
            ShowStatus("Status.SendingPartial", packets.Count, _packetList.Packets.Count, SelectedInterface.Name);

        try
        {
            await _sendService.StartSendAsync(
                packets,
                SelectedInterface,
                loopCount: LoopCount,
                intervalMs: (int)SendIntervalMs,
                autoFixFrames: AutoFixFrames);
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
        if (SelectedInterface == null || toSend.Count == 0)
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
    }

    private void OnSendCompleted()
    {
        IsSending = false;
        IsPaused = false;
        ShowStatus("Status.SendComplete", TotalSent, TotalFailed);
        UpdateCanSend();
    }
}
