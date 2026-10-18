using System.ComponentModel;
using System.Collections.ObjectModel;
using System.Linq;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Dock.Model.Controls;
using Dock.Model.Core;
using Dock.Model.Core.Events;
using Dock.Serializer.SystemTextJson;
using ProtocolForge.Models;
using ProtocolForge.Services;

namespace ProtocolForge.ViewModels;

public sealed partial class MainWindowViewModel : ViewModelBase
{
    private readonly TsharkService _tshark;
    private readonly PcapExportService _pcapExport;
    private readonly ProtocolEditorService _editorService;
    private readonly LayoutService _layoutService;
    private readonly DockSerializer _dockSerializer = new();

    public DockLayoutFactory Factory { get; }

    [ObservableProperty]
    private IRootDock? _layout;

    public event EventHandler? FindFocusRequested;

    // Per-packet version counter so an older in-flight display refresh never
    // overwrites the tree with stale data after the user edited again.
    private readonly Dictionary<Packet, int> _reparseVersions = [];

    // Context frames used by each packet's tree build, cached so the verify-
    // before-commit transaction can supply them to the reparse.
    private readonly Dictionary<Packet, IReadOnlyList<(long Timestamp, byte[] Data)>?> _packetContextFrames = [];

    // Selection sequence counter: an older in-flight on-demand tree build for
    // a previously selected packet must not overwrite the tree of a newer one.
    private int _treeBuildSeq;
    private readonly HashSet<Packet> _buildingPackets = [];

    // Neighbor prefetch: after a selection's tree build finishes, pre-build the
    // trees of nearby packets in the background so sequential browsing incurs no
    // per-click latency. Bounded by the semaphore (prefetch never starves the
    // selection's own build) and by a generation counter (only the newest
    // selection's window keeps progressing).
    private const int PrefetchWindow = 3;
    private readonly SemaphoreSlim _prefetchGate = new(2);
    private int _prefetchSeq;

    // Sub-ViewModels
    public PacketListViewModel PacketList { get; }
    public ProtocolTreeViewModel ProtocolTree { get; }
    public HexEditorViewModel HexEditor { get; }
    public ToolBarViewModel ToolBar { get; }

    // Document State
    [ObservableProperty]
    private PacketDocument? _document;

    [ObservableProperty]
    private bool _isLoading;

    // Last status shown via ShowStatus, re-resolved on language switch.
    private string? _statusKey = "Status.Ready";
    private object?[]? _statusArgs;

    [ObservableProperty]
    private string _statusText = LocalizationService.Resolve("Status.Ready");

    [ObservableProperty]
    private string _fileName = LocalizationService.Resolve("File.None");

    [ObservableProperty]
    private int _totalPackets;

    [ObservableProperty]
    private int _modifiedPackets;

    [ObservableProperty]
    private double _loadProgress;

    // Panel visibility (toggled by View menu)
    [ObservableProperty]
    private bool _showPacketList = true;

    [ObservableProperty]
    private bool _showProtocolTree = true;

    [ObservableProperty]
    private bool _showHexEditor = true;

    [ObservableProperty]
    private bool _isReadOnly;

    partial void OnIsReadOnlyChanged(bool value)
    {
        ProtocolTree.IsReadOnly = value;
        HexEditor.IsReadOnly = value;
        // 发送门禁依赖此状态,传播放在这里以免将来新增的置位路径漏掉 Toolbar。
        ToolBar.IsReadOnly = value;
        // Command-enablement 也读同一条件,置位后需重算。
        ToolBar.RefreshGate();
    }

    [ObservableProperty]
    private string _tsharkWarning = string.Empty;

    // Layout state for persistence
    public LayoutState LayoutState => _layoutService.Load();

    // Computed display strings (replaced XAML StringFormat bindings); re-raised
    // when their inputs change and on language switch.
    public string PacketsDisplay => LocalizationService.Resolve("Grid.Packets", TotalPackets);
    public string FileDisplay => LocalizationService.Resolve("Status.File", FileName);
    public string ModifiedDisplay => LocalizationService.Resolve("Status.Modified", ModifiedPackets);

    partial void OnTotalPacketsChanged(int value) => OnPropertyChanged(nameof(PacketsDisplay));
    partial void OnFileNameChanged(string value) => OnPropertyChanged(nameof(FileDisplay));
    partial void OnModifiedPacketsChanged(int value) => OnPropertyChanged(nameof(ModifiedDisplay));

    // Document is null until a capture is opened, and a null intermediate fails the
    // whole binding path (FallbackValue does not cover it — verified against Avalonia 11).
    public bool HasUnsavedChanges => Document?.HasUnsavedChanges ?? false;

    partial void OnDocumentChanged(PacketDocument? oldValue, PacketDocument? newValue)
    {
        if (oldValue != null)
            oldValue.PropertyChanged -= OnDocumentPropertyChanged;
        if (newValue != null)
            newValue.PropertyChanged += OnDocumentPropertyChanged;
        OnPropertyChanged(nameof(HasUnsavedChanges));
    }

    private void OnDocumentPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(PacketDocument.HasUnsavedChanges))
            OnPropertyChanged(nameof(HasUnsavedChanges));
    }

    public MainWindowViewModel(
        TsharkService tshark,
        PcapExportService pcapExport,
        ProtocolEditorService editorService,
        PacketListViewModel packetList,
        ProtocolTreeViewModel protocolTree,
        HexEditorViewModel hexEditor,
        ToolBarViewModel? toolBar = null,
        LayoutService? layoutService = null,
        EditHistoryService? history = null,
        SessionStateService? session = null)
    {
        _history = history ?? new EditHistoryService();
        _session = session ?? new SessionStateService();
        _tshark = tshark;
        _pcapExport = pcapExport;
        _editorService = editorService;
        _layoutService = layoutService ?? new LayoutService();

        PacketList = packetList;
        ProtocolTree = protocolTree;
        HexEditor = hexEditor;
        ToolBar = toolBar!;

        // Wire up cross-panel events
        PacketList.PacketSelected += OnPacketSelected;
        ProtocolTree.FieldSelected += OnFieldSelected;
        ProtocolTree.LayerSelected += OnLayerSelected;
        ProtocolTree.FieldEdited += OnFieldEdited;
        ProtocolTree.HistoryChanged += RaiseHistoryState;
        HexEditor.HistoryChanged += RaiseHistoryState;
        HexEditor.HexEdited += OnHexEdited;
        HexEditor.FieldFoundAtOffset += OnHexFieldFound;

        // Mirror send-toolbar status (including per-packet errors) to the
        // visible status bar, which binds this VM's StatusText. The key/args are
        // synced too so a language switch re-resolves the toolbar's status.
        ToolBar.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ToolBarViewModel.StatusText))
            {
                _statusKey = ToolBar.StatusKey;
                _statusArgs = ToolBar.StatusArgs;
                StatusText = ToolBar.StatusText;
            }
        };

        Factory = new DockLayoutFactory();
        IRootDock? restoredLayout = null;
        var dockJson = _layoutService.LoadDockLayout();
        if (dockJson is not null)
        {
            try
            {
                restoredLayout = _dockSerializer.Deserialize<IRootDock>(dockJson);
            }
            catch (Exception ex)
            {
                TraceLog.Write($"VM.DockLayout corrupt, falling back to default: {ex.Message}");
            }
        }

        var layout = restoredLayout ?? Factory.CreateLayout();
        Factory.InitLayout(layout);
        Layout = layout;
        AttachPaneHosts(layout);
        Factory.DockableHidden += OnDockableHidden;
        Factory.DockableRestored += OnDockableRestored;
        Factory.DockablePinned += OnDockablePinned;
        Factory.DockableUnpinned += OnDockableUnpinned;
        Factory.WindowClosing += OnFloatingWindowClosing;

        var saved = _layoutService.Load();
        if (restoredLayout is not null)
        {
            // The dock JSON is authoritative for pane visibility when restored;
            // only the OriginalOwner back-links (lost across restart) need repair.
            RewireHiddenPaneOwners(layout);
        }
        else
        {
            ApplyLegacyVisibility(saved);
        }
        SyncPaneVisibility();
        RetitlePanes();

        // Re-resolve the last status + derived display strings on language switch.
        LocalizationService.LanguageChanged += OnLanguageChanged;
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
        if (_lastDetection is not null)
            TsharkWarning = _lastDetection.Ok ? string.Empty : _lastDetection.LocalizedMessage;
        OnPropertyChanged(nameof(PacketsDisplay));
        OnPropertyChanged(nameof(FileDisplay));
        OnPropertyChanged(nameof(ModifiedDisplay));
        RetitlePanes();
    }

    // Commands

    public async Task LoadFileAsync(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return;

        IsLoading = true;
        ShowStatus("Status.Loading", Path.GetFileName(filePath));

        try
        {
            _lastLoadFailed = false;
            var document = new PacketDocument { FilePath = filePath };
            PacketList.LoadFromDocument(document);
            EnumCatalog.Reset();

            var progress = new Progress<double>(p => LoadProgress = p);

            // Bind the grid to the empty document first so the streamed tshark
            // fields pass fills it progressively instead of in one block at the end.
            if (IsReadOnly)
            {
                await _tshark.LoadPcapReadOnlyAsync(document, filePath, ct: default);
            }
            else
            {
                await _tshark.LoadPcapAsync(document, filePath, progress, _displayFilter);
            }

            Document = document;
            FileName = Path.GetFileName(filePath);
            _loadedFilePath = filePath;
            _history.Clear();
            TcpStreams.Clear();
            // Per-packet caches keyed by Packet reference would otherwise retain the
            // previous document's packets (and their context-frame byte arrays) for
            // the whole session. Reset them whenever a new capture is loaded.
            _packetContextFrames.Clear();
            _reparseVersions.Clear();
            _session.NoteOpened(filePath);
            RaiseHistoryState();
            OnPropertyChanged(nameof(RecentFiles));
            TotalPackets = document.PacketCount;
            ModifiedPackets = 0;

            PacketList.LoadFromDocument(document);

            if (document.SelectedPacket != null)
                OnPacketSelected(document.SelectedPacket);

            await LoadTcpStreamsCommand.ExecuteAsync(null);
            ShowStatus("Status.LoadedPackets", document.PacketCount, FileName);

            if (document.InterfaceCount > 1)
            {
                ShowStatus("Status.MultiInterfaceFile", document.InterfaceCount);
                TraceLog.Write($"Capture declares {document.InterfaceCount} interfaces; "
                    + "the per-packet interface id is not preserved and a save writes one interface.");
            }
        }
        catch (Exception ex)
        {
            _lastLoadFailed = true;
            _lastLoadError = ex.Message;
            ShowStatus("Status.Error", ex.Message);
        }
        finally
        {
            IsLoading = false;
            LoadProgress = 0;
        }
    }

    private readonly EditHistoryService _history;
    private readonly SessionStateService _session;

    [ObservableProperty]
    private bool _canUndo;

    [ObservableProperty]
    private bool _canRedo;

    public ObservableCollection<string> RecentFiles => new(_session.RecentFiles);

    public ObservableCollection<string> RecentFilters => new(_session.RecentFilters);

    public ObservableCollection<string> RecentFinds => new(_session.RecentFinds);

    public bool HasRecentFilters => _session.RecentFilters.Count > 0;

    public bool HasRecentFinds => _session.RecentFinds.Count > 0;

    private string? _loadedFilePath;
    private string _displayFilter = string.Empty;
    private bool _lastLoadFailed;
    private string _lastLoadError = string.Empty;

    [ObservableProperty]
    private string _findText = string.Empty;

    [ObservableProperty]
    private int _findMatchCount;

    /// <summary>
    /// Searches forward through the packet list for <see cref="FindText"/>, then
    /// through the selected packet's protocol tree. The tree hit reuses
    /// TreeSelectRequested, which already expands ancestors and reveals the node,
    /// so find-in-tree costs nothing beyond the walk.
    /// </summary>
    [RelayCommand]
    public void FindNext() => Find(forward: true);

    [RelayCommand]
    public void FindPrevious() => Find(forward: false);

    [RelayCommand]
    private void ApplyRecentFind(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return;
        FindText = value;
        FindNextCommand.Execute(null);
    }

    private void Find(bool forward)
    {
        string needle = FindText?.Trim() ?? string.Empty;
        if (needle.Length == 0)
        {
            FindMatchCount = 0;
            ShowStatus("Status.FindEmpty");
            return;
        }

        // A tree hit only exists for the selected packet, so the list search must
        // have already moved the selection there.
        bool hit = FindInPacketList(needle, forward) || FindInTree(needle);
        if (hit)
        {
            _session.NoteFind(needle);
            OnPropertyChanged(nameof(RecentFinds));
            OnPropertyChanged(nameof(HasRecentFinds));
            return;
        }

        ShowStatus("Status.FindNotFound", needle);
    }

    private bool FindInPacketList(string needle, bool forward)
    {
        var packets = PacketList.Packets;
        if (packets.Count == 0)
            return false;

        int current = PacketList.SelectedPacket?.Index ?? -1;
        int step = forward ? 1 : -1;
        int start = current >= 0 ? current : (forward ? -1 : packets.Count);

        for (int i = start + step; i >= 0 && i < packets.Count; i += step)
        {
            if (!RowMatches(packets[i], needle))
                continue;

            PacketList.SelectedPacket = packets[i];
            PacketList.SelectedIndex = i;
            FindMatchCount++;
            ShowStatus("Status.FindMatch", needle, packets[i].PacketNumber);
            return true;
        }

        return false;
    }

    private static bool RowMatches(Packet p, string needle)
    {
        return Contains(p.SourceAddress, needle)
            || Contains(p.DestinationAddress, needle)
            || Contains(p.ProtocolName, needle)
            || Contains(p.InfoText, needle)
            || Contains(p.Summary, needle);
    }

    private static bool Contains(string? haystack, string needle) =>
        !string.IsNullOrEmpty(haystack) &&
        haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);

    private bool FindInTree(string needle)
    {
        var packet = PacketList.SelectedPacket;
        if (packet == null || ProtocolTree == null)
            return false;

        foreach (var layer in packet.Layers)
        {
            var hit = Flatten(layer.Fields).FirstOrDefault(f =>
                Contains(f.Name, needle) || Contains(f.DisplayValue, needle));
            if (hit is null)
                continue;

            ProtocolTree.SelectFieldOnTree(hit);
            FindMatchCount++;
            ShowStatus("Status.FindMatchField", needle, hit.Name);
            return true;
        }

        return false;
    }

    /// <summary>
    /// tshark display filter applied to the packet list. Applied by tshark at load
    /// time, so the grid only ever holds matching packets.
    /// </summary>
    [ObservableProperty]
    private string _filterText = string.Empty;

    /// <summary>
    /// Reloads the capture with <see cref="FilterText"/> as a tshark display filter.
    /// An unparseable filter makes tshark exit non-zero, so the previous list is
    /// left untouched and the reason is surfaced instead of the grid emptying.
    /// </summary>
    [RelayCommand]
    private async Task ApplyFilterAsync()
    {
        if (_loadedFilePath is null)
        {
            ShowStatus("Status.FilterNoFile");
            return;
        }

        string candidate = FilterText?.Trim() ?? string.Empty;
        string previous = _displayFilter;
        _displayFilter = candidate;
        await LoadFileAsync(_loadedFilePath);

        if (_lastLoadFailed)
        {
            _displayFilter = previous;
            ShowStatus("Status.FilterInvalid", candidate, _lastLoadError);
            await LoadFileAsync(_loadedFilePath);
            return;
        }

        if (_displayFilter.Length > 0)
        {
            _session.NoteFilter(_displayFilter);
            OnPropertyChanged(nameof(RecentFilters));
            OnPropertyChanged(nameof(HasRecentFilters));
            ShowStatus("Status.FilterApplied", _displayFilter, TotalPackets);
        }
    }

    [RelayCommand]
    private void ApplyRecentFilter(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return;
        FilterText = value;
        ApplyFilterCommand.Execute(null);
    }

    [RelayCommand]
    private async Task ClearFilterAsync()
    {
        FilterText = string.Empty;
        await ApplyFilterCommand.ExecuteAsync(null);
    }

    // ─── Display-filter validation + field-name autocomplete ───
    // The box tints green/red via class bindings (Classes.filter-valid / .filter-invalid);
    // no IValueConverter is involved and the ViewModel holds no brush/colour type.
    [ObservableProperty]
    private FilterValidationState _filterValidation = FilterValidationState.None;

    public bool IsFilterValid => FilterValidation == FilterValidationState.Valid;

    public bool IsFilterInvalid => FilterValidation == FilterValidationState.Invalid;

    [ObservableProperty]
    private string _filterValidationMessage = string.Empty;

    // 校验消息为空时必须返回 null 而不是空串 —— Avalonia 对空串仍会弹出空气泡提示,
    // 这正是"过滤器为空时悬停出现空提示"的来源。
    /// <summary>Filter-box tooltip: null (not empty) when there is no message to show.</summary>
    public string? FilterToolTip =>
        string.IsNullOrEmpty(FilterValidationMessage) ? null : FilterValidationMessage;

    partial void OnFilterValidationMessageChanged(string value) =>
        OnPropertyChanged(nameof(FilterToolTip));

    /// <summary>Field names matching the token currently being typed in the filter box.</summary>
    public ObservableCollection<string> FilterSuggestions { get; } = [];

    [ObservableProperty]
    private bool _isFilterSuggestionOpen;

    [ObservableProperty]
    private bool _isFilterHistoryOpen;

    [ObservableProperty]
    private bool _isFindHistoryOpen;

    [ObservableProperty]
    private int _selectedFilterSuggestionIndex = -1;

    private const int MaxFilterSuggestions = 100;

    // Cancelled and replaced on every keystroke so only the newest verdict wins.
    private CancellationTokenSource? _filterValidationCts;

    // Mirrors the validation debounce for the suggestion fetch.
    private CancellationTokenSource? _filterSuggestionCts;

    // [ObservableProperty] exposes the field as FilterValidation, so the two derived
    // bools the class bindings read must be re-notified whenever the state changes.
    partial void OnFilterValidationChanged(FilterValidationState value)
    {
        OnPropertyChanged(nameof(IsFilterValid));
        OnPropertyChanged(nameof(IsFilterInvalid));
    }

    partial void OnFilterTextChanged(string value)
    {
        _filterValidationCts?.Cancel();
        _filterValidationCts?.Dispose();
        var cts = new CancellationTokenSource();
        _filterValidationCts = cts;
        _ = ValidateFilterDebouncedAsync(cts.Token);
    }

    private async Task ValidateFilterDebouncedAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(400, ct);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        if (ct.IsCancellationRequested)
            return;

        string text = FilterText ?? string.Empty;
        if (string.IsNullOrWhiteSpace(text))
        {
            // Empty box = no tint at all (not green).
            FilterValidation = FilterValidationState.None;
            FilterValidationMessage = string.Empty;
            return;
        }

        try
        {
            var verdict = await _tshark.ValidateDisplayFilterAsync(text, ct);
            if (ct.IsCancellationRequested)
                return;

            if (verdict.IsValid)
            {
                FilterValidation = FilterValidationState.Valid;
                FilterValidationMessage = LocalizationService.Resolve("Filter.Valid");
            }
            else
            {
                FilterValidation = FilterValidationState.Invalid;
                FilterValidationMessage = string.IsNullOrEmpty(verdict.Error)
                    ? LocalizationService.Resolve("Filter.Invalid")
                    : LocalizationService.Resolve("Filter.InvalidDetail", verdict.Error);
            }
        }
        catch (OperationCanceledException)
        {
            // Superseded by a newer keystroke; that call owns the final state.
        }
    }

    /// <summary>
    /// Refreshes <see cref="FilterSuggestions"/> for the field-name token the user is
    /// typing (starts-with match, falling back to contains). An empty token closes the popup.
    /// </summary>
    public async Task UpdateFilterSuggestionsAsync(string token, CancellationToken ct)
    {
        _filterSuggestionCts?.Cancel();
        _filterSuggestionCts?.Dispose();
        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _filterSuggestionCts = cts;
        var token2 = cts.Token;

        FilterSuggestions.Clear();
        SelectedFilterSuggestionIndex = -1;

        if (string.IsNullOrEmpty(token))
        {
            IsFilterSuggestionOpen = false;
            return;
        }

        IReadOnlyList<string> all;
        try
        {
            all = await _tshark.GetFieldNamesAsync(token2);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        if (token2.IsCancellationRequested)
            return;

        var matches = new List<string>(MaxFilterSuggestions);
        foreach (var name in all)
        {
            if (name.StartsWith(token, StringComparison.OrdinalIgnoreCase))
            {
                matches.Add(name);
                if (matches.Count >= MaxFilterSuggestions)
                    break;
            }
        }

        // Only fall back to "contains" when nothing starts with the token.
        if (matches.Count == 0)
        {
            foreach (var name in all)
            {
                if (name.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    matches.Add(name);
                    if (matches.Count >= MaxFilterSuggestions)
                        break;
                }
            }
        }

        if (token2.IsCancellationRequested)
            return;

        foreach (var name in matches)
            FilterSuggestions.Add(name);

        SelectedFilterSuggestionIndex = FilterSuggestions.Count > 0 ? 0 : -1;
        IsFilterSuggestionOpen = FilterSuggestions.Count > 0;
    }

    /// <summary>
    /// Replaces the token spanning [<paramref name="tokenStart"/>, +<paramref name="tokenLength"/>)
    /// in <see cref="FilterText"/> with the accepted field name and closes the popup.
    /// </summary>
    public void ApplyFilterSuggestion(string name, int tokenStart, int tokenLength)
    {
        if (string.IsNullOrEmpty(name))
            return;

        string text = FilterText ?? string.Empty;
        if (tokenStart < 0)
            tokenStart = 0;
        if (tokenStart > text.Length)
            tokenStart = text.Length;
        if (tokenLength < 0 || tokenStart + tokenLength > text.Length)
            tokenLength = text.Length - tokenStart;

        FilterText = text[..tokenStart] + name + text[(tokenStart + tokenLength)..];

        IsFilterSuggestionOpen = false;
        SelectedFilterSuggestionIndex = -1;
    }

    /// <summary>Streams (TCP + UDP) discovered in the loaded capture, for the follow-stream list.</summary>
    public ObservableCollection<StreamIndex> TcpStreams { get; } = [];

    [ObservableProperty]
    private StreamIndex? _selectedTcpStream;

    /// <summary>
    /// Picking a stream in the combo filters the list to that conversation. Without this
    /// hook the method below was never reached, so the combo only changed the label.
    /// </summary>
    partial void OnSelectedTcpStreamChanged(StreamIndex? value) =>
        _ = ApplySelectedStreamFilterAsync(value);

    /// <summary>
    /// Populates the stream list from every provider that indexes conversations
    /// (TCP for its reassembly index, UDP for its conversation index). The scans
    /// come from work the providers already do, so this does not launch another
    /// tshark pass unless the capture has no such traffic at all.
    /// </summary>
    [RelayCommand]
    private async Task LoadTcpStreamsAsync()
    {
        TcpStreams.Clear();
        if (Document?.ContextProviders is null)
            return;

        foreach (var provider in Document.ContextProviders)
        {
            IReadOnlyList<StreamIndex> streams;
            if (provider is TcpStreamContextProvider tcp)
                streams = await tcp.GetStreamsAsync();
            else if (provider is UdpStreamContextProvider udp)
                streams = await udp.GetStreamsAsync();
            else
                continue;

            foreach (var stream in streams)
                TcpStreams.Add(stream);
        }
    }

    /// <summary>
    /// Filters the packet list down to the selected stream by reusing the display
    /// filter, so the grid shows exactly that conversation. The stream field follows
    /// the stream's own protocol (tcp.stream / udp.stream).
    /// </summary>
    private async Task ApplySelectedStreamFilterAsync(StreamIndex? value)
    {
        if (value is null)
            return;
        FilterText = $"{value.Protocol}.stream eq {value.StreamId}";
        await ApplyFilterCommand.ExecuteAsync(null);
    }

    /// <summary>
    /// Rebuilds the TCP stream index once the edited bytes are actually on disk.
    ///
    /// Timing matters here. <c>tcp.stream</c> is assigned by tshark across the whole
    /// file, from the four-tuple and dissection order: measured against tshark 4.2.2, a
    /// single-packet file always reports stream 0 no matter which stream the frame really
    /// belongs to, so the value cannot be recovered from the per-packet reparse an edit
    /// already does. And a whole-file rescan reads the saved file, which mid-edit is still
    /// the pre-edit bytes. Therefore an unsaved edit has no well-defined stream index, and
    /// the honest moment to refresh is right after the save.
    ///
    /// Editing a payload length does not invalidate the index at all — stream numbering
    /// ignores IP total length and TCP sequence numbers. What does invalidate it is a
    /// four-tuple edit, which is exactly what a save makes observable.
    /// </summary>
    private async Task RefreshStreamIndexAfterSaveAsync()
    {
        bool found = false;
        foreach (var provider in Document?.ContextProviders ?? [])
        {
            switch (provider)
            {
                case TcpStreamContextProvider tcp:
                    tcp.Invalidate();
                    found = true;
                    break;
                case UdpStreamContextProvider udp:
                    udp.Invalidate();
                    found = true;
                    break;
            }
        }
        if (!found)
            return;

        try
        {
            await LoadTcpStreamsCommand.ExecuteAsync(null);

            // The combo was bound to instances from the previous index; re-point it at the
            // rebuilt one so the selection stays valid.
            var previous = SelectedTcpStream;
            if (previous is not null)
                SelectedTcpStream = TcpStreams.FirstOrDefault(
                    s => s.Protocol == previous.Protocol && s.StreamId == previous.StreamId);
        }
        catch (Exception ex)
        {
            TraceLog.Write($"Stream index refresh after save failed: {ex.Message}");
        }
    }

    /// <summary>Reassembled stream bytes, formatted as hex dump lines for the viewer.</summary>
    public ObservableCollection<string> ReassembledLines { get; } = [];

    [ObservableProperty]
    private bool _showReassembled;

    [ObservableProperty]
    private string _reassembledStatus = string.Empty;

    /// <summary>
    /// Fetches the reassembled payload of the selected stream (TCP or UDP) and shows
    /// it as a
    /// read-only hex dump. Read-only by necessity: reassembled bytes span more than the
    /// selected frame, so they have no offset in the packet to edit against.
    /// </summary>
    [RelayCommand]
    private async Task ShowReassembledBytesAsync()
    {
        ReassembledLines.Clear();
        if (_loadedFilePath is null || SelectedTcpStream is null)
        {
            ReassembledStatus = LocalizationService.Resolve("Rv.NoStream");
            return;
        }

        try
        {
            var bytes = await _tshark.GetReassembledStreamAsync(
                _loadedFilePath, SelectedTcpStream.Protocol, SelectedTcpStream.StreamId, _displayFilter);

            if (bytes is null || bytes.Length == 0)
            {
                ReassembledStatus = LocalizationService.Resolve("Rv.Empty", SelectedTcpStream.StreamId);
                return;
            }

            foreach (string line in FormatHexDump(bytes))
                ReassembledLines.Add(line);

            ShowReassembled = true;
            ReassembledStatus = LocalizationService.Resolve(
                "Rv.Loaded", SelectedTcpStream.StreamId, bytes.Length);
        }
        catch (Exception ex)
        {
            ReassembledStatus = LocalizationService.Resolve("Rv.Failed", ex.Message);
        }
    }

    /// <summary>Wireshark-style 16-byte rows with an ASCII gutter.</summary>
    private static IEnumerable<string> FormatHexDump(byte[] bytes)
    {
        const int perRow = 16;
        for (int offset = 0; offset < bytes.Length; offset += perRow)
        {
            int take = Math.Min(perRow, bytes.Length - offset);
            var hex = new System.Text.StringBuilder();
            var ascii = new System.Text.StringBuilder();
            for (int i = 0; i < take; i++)
            {
                byte b = bytes[offset + i];
                hex.Append(b.ToString("X2")).Append(' ');
                ascii.Append(b >= 32 && b <= 126 ? (char)b : '.');
            }
            yield return $"{offset:X8}  {hex.ToString().PadRight(perRow * 3)} {ascii}";
        }
    }

    [RelayCommand]
    private async Task UndoAsync()
    {
        if (PacketList.SelectedPacket is not { } packet)
        {
            ShowStatus("Status.NothingToUndo");
            return;
        }
        if (_history.Undo(packet) is not { } entry)
        {
            ShowStatus("Status.NothingToUndo");
            return;
        }

        await AfterHistoryMoveAsync(packet, "Status.Undone", entry);
    }

    [RelayCommand]
    private async Task RedoAsync()
    {
        if (PacketList.SelectedPacket is not { } packet)
        {
            ShowStatus("Status.NothingToRedo");
            return;
        }
        if (_history.Redo(packet) is not { } entry)
        {
            ShowStatus("Status.NothingToRedo");
            return;
        }

        await AfterHistoryMoveAsync(packet, "Status.Redone", entry);
    }

    /// <summary>
    /// Refreshes the view after an undo/redo. It must not reload the capture from disk:
    /// doing so would discard every other in-memory edit and wipe the history stacks.
    /// Only the affected packet's tree is rebuilt so it matches the restored bytes.
    /// </summary>
    private async Task AfterHistoryMoveAsync(Packet packet, string statusKey, EditHistoryService.Entry entry)
    {
        ModifiedPackets = Document?.GetModifiedPackets().Count() ?? 0;
        if (Document != null)
            Document.HasUnsavedChanges = ModifiedPackets > 0;

        int seq = ++_treeBuildSeq;
        ProtocolTree.LoadPacket(null);
        await BuildTreeAsync(packet, seq);

        HexEditor.RefreshBytes();
        HexEditor.ClearEditedMarks();
        HexEditorViewModel.ReExtractAddressInfo(packet);

        RaiseHistoryState();
        HexEditor.RefreshAddressInfo();
        ShowStatus(statusKey, entry.PacketNumber);
    }

    private void RaiseHistoryState()
    {
        CanUndo = _history.CanUndo;
        CanRedo = _history.CanRedo;
    }

    /// <summary>
    /// Re-runs tshark detection with a user-picked executable path and updates
    /// the read-only state and status line. Called from the File → Tshark Path menu.
    /// </summary>
    public void RedetectTsharkFromPath(string path)
    {
        _tshark.UpdateTsharkPath(path);
        _tshark.ResetTlsKeylogArgs();
        var detection = TsharkService.RedetectTshark();
        IsReadOnly = !detection.Ok;
        ToolBar.IsReadOnly = IsReadOnly;
        ApplyTsharkStatus(detection);
        TraceLog.Write($"Tshark redetected: ok={detection.Ok} version={detection.Version} path={path}");
    }

    private TsharkDetection? _lastDetection;

    /// <summary>
    /// Applies a tshark detection outcome to the status line and warning banner.
    /// Called by App.axaml.cs at startup and by the VM's own redetect path.
    /// </summary>
    public void ApplyTsharkStatus(TsharkDetection detection)
    {
        _lastDetection = detection;
        if (detection.Ok)
        {
            ShowStatus("Status.ReadyTshark", detection.Version);
            TsharkWarning = string.Empty;
        }
        else
        {
            ShowStatus("Status.ReadOnlyPrefix", detection.LocalizedMessage);
            TsharkWarning = detection.LocalizedMessage;
        }
    }

    [RelayCommand]
    private async Task SavePcapAsync()
    {
        if (IsReadOnly)
        {
            ShowStatus("Status.ReadOnlySave");
            return;
        }
        if (Document == null || TotalPackets == 0)
        {
            ShowStatus("Status.NoPacketsSave");
            return;
        }

        // Finalize any in-progress hex-editor run (REPLACE-only pending bytes)
        // before the dirty check and write, so a hex edit never gets dropped.
        await HexEditor.CommitHexEditAsync();

        if (!Document.HasUnsavedChanges)
        {
            ShowStatus("Status.NoChanges");
            return;
        }
        try
        {
            ShowStatus("Status.Saving");
            var options = new PacketExportOptions
            {
                OutputPath = Document.FilePath,
                ExportOnlyModified = false,
                IncludeUnmodified = true,
                LinkLayerType = Document.LinkLayerType,
                Snaplen = Document.Snaplen,
                Pcapng = Document.IsPcapNg,
                BigEndian = Document.SourceBigEndian,
                NanosecondResolution = Document.SourceNanoseconds,
            };
            await _pcapExport.ExportAsync(Document.Packets, options);
            Document.HasUnsavedChanges = false;
            ModifiedPackets = 0;
            await RefreshStreamIndexAfterSaveAsync();
            ShowStatus("Status.Saved", Document.PacketCount, Path.GetFileName(Document.FilePath));
        }
        catch (Exception ex)
        {
            ShowStatus("Status.SaveFailed", ex.Message);
        }
    }

    public async Task ExportToFileAsync(string outputPath)
    {
        if (Document == null) return;

        // Finalize any in-progress hex-editor run so the exported file includes it.
        await HexEditor.CommitHexEditAsync();

        try
        {
            ShowStatus("Status.Exporting");

            var options = new PacketExportOptions
            {
                OutputPath = outputPath,
                ExportOnlyModified = false,
                IncludeUnmodified = true,
                LinkLayerType = Document.LinkLayerType,
                Snaplen = Document.Snaplen,
                // Export-as follows the extension the user actually chose, so a
                // .pcapng source can be deliberately written out as classic pcap.
                Pcapng = outputPath.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase),
                BigEndian = Document.SourceBigEndian,
                NanosecondResolution = Document.SourceNanoseconds,
            };

            var packets = options.IncludeUnmodified
                ? Document.Packets
                : Document.GetModifiedPackets();

            await _pcapExport.ExportAsync(packets, options);

            ShowStatus("Status.Exported", Document.PacketCount, Path.GetFileName(outputPath));
        }
        catch (Exception ex)
        {
            ShowStatus("Status.ExportFailed", ex.Message);
        }
    }

    [RelayCommand]
    private async Task ResetModificationsAsync()
    {
        if (Document == null) return;

        if (IsReadOnly)
        {
            ShowStatus("Status.ResetReadOnly");
            return;
        }

        var modified = Document.GetModifiedPackets().ToList();
        if (modified.Count == 0)
        {
            ShowStatus("Status.ModificationsReset");
            return;
        }

        // A half-typed hex run belongs to the pre-reset bytes; drop it so a later
        // commit cannot re-apply digits the user just discarded.
        HexEditor.CancelHexEdit();

        Document.ResetAllModifications();
        ModifiedPackets = 0;
        Document.HasUnsavedChanges = false;

        // The packet-list columns were rewritten from the edited bytes at edit time.
        foreach (var packet in modified)
            HexEditorViewModel.ReExtractAddressInfo(packet);

        HexEditor.RefreshBytes();
        HexEditor.ClearEditedMarks();

        // Reset discards every edit at once; the per-packet undo stack now points at
        // bytes that no longer exist, so drop it rather than let a later Ctrl+Z
        // resurrect a discarded edit.
        _history.Clear();
        RaiseHistoryState();

        // The cached tree still holds the edited DisplayValue/RawBytes. That both
        // misreports the edit and fails the fence's byte-agreement check, which locks the
        // field out of editing for the rest of the session — so re-parse the packet the
        // user is looking at, rebuilding its tree from the restored bytes.
        var shown = HexEditor.CurrentPacket;
        if (shown != null)
        {
            int seq = ++_treeBuildSeq;
            ProtocolTree.LoadPacket(null);
            await BuildTreeAsync(shown, seq);

            HexEditor.RefreshBytes();
            HexEditor.ClearEditedMarks();
            HexEditorViewModel.ReExtractAddressInfo(shown);
        }

        ShowStatus("Status.ModificationsReset");
    }

    [RelayCommand]
    private void TogglePacketList() => TogglePane(DockLayoutFactory.PacketListId);

    [RelayCommand]
    private void ToggleProtocolTree() => TogglePane(DockLayoutFactory.ProtocolTreeId);

    [RelayCommand]
    private void ToggleHexEditor() => TogglePane(DockLayoutFactory.HexEditorId);

    [RelayCommand]
    private void ToggleStatistics() => TogglePane(DockLayoutFactory.StatisticsId);

    private void TogglePane(string paneId)
    {
        if (IsPaneHidden(paneId))
            RestorePane(paneId);
        else
            HidePane(paneId);
    }

    private void HidePane(string paneId)
    {
        if (Layout is null || IsPaneHidden(paneId))
            return;
        if (FindPane(paneId) is { } pane)
            Factory.HideDockable(pane);
    }

    private void RestorePane(string paneId)
    {
        if (Layout is not { } root || !IsPaneHidden(paneId))
            return;
        if (FindPane(paneId) is not { } pane)
            return;
        if (IsPanePinned(root, pane))
        {
            UnpinPane(root, pane);
            SyncPaneVisibility();
            Dispatcher.UIThread.Post(SaveLayout);
        }
        else
        {
            Factory.RestoreDockable(pane);
        }
    }

    private PaneDock? FindPane(string paneId)
    {
        if (Layout is not { } root)
            return null;
        if (root.HiddenDockables?.FirstOrDefault(d => d.Id == paneId) is PaneDock hiddenPane)
            return hiddenPane;
        if (EnumeratePinnedDockables(root).OfType<PaneDock>().FirstOrDefault(d => d.Id == paneId) is { } pinnedPane)
            return pinnedPane;
        return Factory.Find(root, d => d.Id == paneId).OfType<PaneDock>().FirstOrDefault();
    }

    private bool IsPaneHidden(string paneId) =>
        Layout is { } root &&
        (root.HiddenDockables?.Any(d => d.Id == paneId) == true ||
         EnumeratePinnedDockables(root).Any(d => d.Id == paneId));

    // 图钉(自动隐藏)把面板挪进 RootDock.*PinnedDockables,关闭(X)才进 HiddenDockables;菜单原先只认后者。
    // 故 pinned 一并按隐藏处理,恢复时重新挂回其固定宿主 ToolDock(而非孤儿悬浮)。
    private static bool IsPanePinned(IRootDock root, PaneDock pane) =>
        EnumeratePinnedDockables(root).Any(d => ReferenceEquals(d, pane));

    private void UnpinPane(IRootDock root, PaneDock pane)
    {
        foreach (var pinned in EnumeratePinnedCollections(root))
            pinned.Remove(pane);

        pane.OriginalOwner = null;
        pane.OriginalOwnerId = null;
        pane.Host ??= this;

        if (HomeDockId(pane.Id) is { } homeId &&
            Factory.Find(root, d => d.Id == homeId).OfType<IDock>().FirstOrDefault() is { } home)
        {
            Factory.AddDockable(home, pane);
            home.ActiveDockable = pane;
        }
    }

    private static IEnumerable<IDockable> EnumeratePinnedDockables(IRootDock root) =>
        EnumeratePinnedCollections(root).SelectMany(c => c);

    private static IEnumerable<IList<IDockable>> EnumeratePinnedCollections(IRootDock root)
    {
        if (root.LeftPinnedDockables is { } left) yield return left;
        if (root.RightPinnedDockables is { } right) yield return right;
        if (root.TopPinnedDockables is { } top) yield return top;
        if (root.BottomPinnedDockables is { } bottom) yield return bottom;
    }

    private static string? HomeDockId(string paneId) => paneId switch
    {
        DockLayoutFactory.PacketListId => DockLayoutFactory.TopDockId,
        DockLayoutFactory.ProtocolTreeId => DockLayoutFactory.TreeDockId,
        DockLayoutFactory.HexEditorId => DockLayoutFactory.HexDockId,
        DockLayoutFactory.StatisticsId => DockLayoutFactory.StatsDockId,
        _ => null,
    };

    private void SyncPaneVisibility()
    {
        ShowPacketList = !IsPaneHidden(DockLayoutFactory.PacketListId);
        ShowProtocolTree = !IsPaneHidden(DockLayoutFactory.ProtocolTreeId);
        ShowHexEditor = !IsPaneHidden(DockLayoutFactory.HexEditorId);
        ShowStatistics = !IsPaneHidden(DockLayoutFactory.StatisticsId);
    }

    private void OnDockableHidden(object? sender, DockableHiddenEventArgs e)
    {
        if (e.Dockable is PaneDock pane)
            pane.OriginalOwnerId = pane.OriginalOwner?.Id;
        SyncPaneVisibility();
        // Deferred: a restore fires mid-restore (OriginalOwner branch not yet run),
        // so serialize only once the whole dock operation has completed.
        Dispatcher.UIThread.Post(SaveLayout);
    }

    private void OnDockableRestored(object? sender, DockableRestoredEventArgs e)
    {
        if (e.Dockable is PaneDock pane)
        {
            pane.OriginalOwnerId = null;
            pane.Host ??= this;
        }
        SyncPaneVisibility();
        Dispatcher.UIThread.Post(SaveLayout);
    }

    private void OnDockablePinned(object? sender, DockablePinnedEventArgs e)
    {
        SyncPaneVisibility();
        Dispatcher.UIThread.Post(SaveLayout);
    }

    private void OnDockableUnpinned(object? sender, DockableUnpinnedEventArgs e)
    {
        if (e.Dockable is PaneDock pane)
        {
            pane.OriginalOwner = null;
            pane.OriginalOwnerId = null;
            pane.Host ??= this;
        }
        SyncPaneVisibility();
        Dispatcher.UIThread.Post(SaveLayout);
    }

    // Dock 关闭浮动窗口时(CloseWindow)会把面板 HideDockable 进「浮动根」的 HiddenDockables,
    // 随后 RemoveWindow 丢弃整棵浮动根,面板即成找不到的孤儿(除非重置布局)。WindowClosing 在
    // 丢弃前触发且面板仍在浮动根可见树中,此时移回 HomeDock 即可保住面板。但浮出面板会清空其
    // HomeDock,Dock 的 RemoveDockable(collapse:true) 随即把该空 ToolDock 从布局移除,故需先按
    // 默认布局重建这个空 HomeDock(空 dock 在 ProportionalStackPanel 中按 IsEmpty 折叠为零尺寸,不会留白)。
    private void OnFloatingWindowClosing(object? sender, WindowClosingEventArgs e)
    {
        if (Layout is not { } root || e.Window?.Layout is not IDock windowRoot)
            return;
        if (ReferenceEquals(windowRoot, root))
            return;
        var panes = EnumeratePanes(windowRoot).ToList();
        if (panes.Count == 0)
            return;
        foreach (var pane in panes)
        {
            if (pane.Owner is not IDock source)
                continue;
            if (EnsureHomeDock(root, pane.Id) is { } home)
            {
                Factory.MoveDockable(source, home, pane, null);
                home.ActiveDockable = pane;
            }
        }
        SyncPaneVisibility();
        Dispatcher.UIThread.Post(SaveLayout);
    }

    private IDock? EnsureHomeDock(IRootDock root, string paneId)
    {
        if (HomeDockId(paneId) is not { } homeId)
            return null;
        if (Factory.Find(root, d => d.Id == homeId).OfType<IDock>().FirstOrDefault() is { } existing)
            return existing;

        var template = Factory.CreateLayout();
        if (Factory.Find(template, d => d.Id == homeId).OfType<IDock>().FirstOrDefault() is not { } freshHome)
            return null;

        // The template is never InitLayout'd, so freshHome.Owner is null; locate its parent by scan.
        IDock? freshParent = null;
        var freshIndex = -1;
        foreach (var candidate in Factory.Find(template, _ => true).OfType<IDock>())
        {
            if (candidate.VisibleDockables is { } list && (freshIndex = list.IndexOf(freshHome)) >= 0)
            {
                freshParent = candidate;
                break;
            }
        }

        var liveParent = (freshParent is not null
                ? Factory.Find(root, d => d.Id == freshParent.Id).OfType<IDock>().FirstOrDefault()
                : null)
            ?? Factory.Find(root, d => d.Id == DockLayoutFactory.MainLayoutId).OfType<IDock>().FirstOrDefault();
        if (liveParent?.VisibleDockables is null)
            return null;

        var insertion = new List<IDockable> { freshHome };
        var index = liveParent.VisibleDockables.Count;
        if (freshParent?.VisibleDockables is { } siblings && freshIndex >= 0)
        {
            index = Math.Min(freshIndex, liveParent.VisibleDockables.Count);
            if (freshIndex + 1 < siblings.Count && siblings[freshIndex + 1] is IProportionalDockSplitter splitterAfter)
                insertion.Add(splitterAfter);
            else if (freshIndex - 1 >= 0 && siblings[freshIndex - 1] is IProportionalDockSplitter splitterBefore)
                insertion.Insert(0, splitterBefore);
        }

        freshHome.VisibleDockables?.Clear();
        foreach (var item in insertion)
        {
            liveParent.VisibleDockables.Insert(index++, item);
            Factory.InitDockable(item, liveParent);
        }
        liveParent.ActiveDockable ??= freshHome;
        return freshHome;
    }

    private void ApplyLegacyVisibility(LayoutState saved)
    {
        if (!saved.ShowPacketList)
            HidePane(DockLayoutFactory.PacketListId);
        if (!saved.ShowProtocolTree)
            HidePane(DockLayoutFactory.ProtocolTreeId);
        if (!saved.ShowHexEditor)
            HidePane(DockLayoutFactory.HexEditorId);
        // Pre-migration the statistics checkbox never showed the panel, so no user
        // of the old layout ever had it visible — start hidden on a fresh layout.
        HidePane(DockLayoutFactory.StatisticsId);
    }

    private void RewireHiddenPaneOwners(IRootDock root)
    {
        foreach (var pane in root.HiddenDockables?.OfType<PaneDock>().ToList() ?? [])
        {
            if (pane.OriginalOwnerId is { } ownerId &&
                Factory.Find(root, d => d.Id == ownerId).OfType<IDock>().FirstOrDefault() is { } owner)
            {
                pane.OriginalOwner = owner;
            }
        }
    }

    private void AttachPaneHosts(IDockable dockable)
    {
        if (dockable is PaneDock pane)
            pane.Host = this;
        if (dockable is IDock dock)
        {
            foreach (var child in dock.VisibleDockables ?? [])
                AttachPaneHosts(child);
        }
        if (dockable is IRootDock root)
        {
            // Panes hidden in a restored docklayout.json live only here. Without
            // this they keep Host == null, and the pane DataTemplate
            // (DataContext="{Binding Host}") renders them blank when re-shown.
            foreach (var child in root.HiddenDockables ?? [])
                AttachPaneHosts(child);
            foreach (var child in EnumeratePinnedDockables(root))
                AttachPaneHosts(child);
        }
    }

    private void RetitlePanes()
    {
        if (Layout is not { } root)
            return;
        foreach (var pane in EnumeratePanes(root)
                     .Concat(root.HiddenDockables?.OfType<PaneDock>() ?? [])
                     .Concat(EnumeratePinnedDockables(root).OfType<PaneDock>()))
        {
            pane.Title = pane.Id switch
            {
                DockLayoutFactory.PacketListId => LocalizationService.Resolve("Panel.PacketList"),
                DockLayoutFactory.ProtocolTreeId => LocalizationService.Resolve("Panel.ProtocolTree"),
                DockLayoutFactory.HexEditorId => LocalizationService.Resolve("Panel.HexEditor"),
                DockLayoutFactory.StatisticsId => LocalizationService.Resolve("Panel.Statistics"),
                _ => pane.Title,
            };
        }
    }

    private static IEnumerable<PaneDock> EnumeratePanes(IDock dock)
    {
        foreach (var dockable in dock.VisibleDockables ?? [])
        {
            if (dockable is PaneDock pane)
            {
                yield return pane;
            }
            else if (dockable is IDock child)
            {
                foreach (var childPane in EnumeratePanes(child))
                    yield return childPane;
            }
        }
    }

    public void RequestFindFocus() => FindFocusRequested?.Invoke(this, EventArgs.Empty);

    public void ResetDockLayout()
    {
        var layout = Factory.CreateLayout();
        Factory.InitLayout(layout);
        Layout = layout;
        AttachPaneHosts(layout);
        HidePane(DockLayoutFactory.StatisticsId);
        SyncPaneVisibility();
        RetitlePanes();
        SaveLayout();
    }

    // Layout persistence
    public void SaveLayout()
    {
        PersistLayoutState();
    }

    public void SaveLayout(double winX, double winY, double winW, double winH, int winState)
    {
        var state = _layoutService.Load();
        state.WindowX = winX;
        state.WindowY = winY;
        state.WindowWidth = winW;
        state.WindowHeight = winH;
        state.WindowState = winState;
        PersistLayoutState(state);
    }

    private void PersistLayoutState(LayoutState? state = null)
    {
        state ??= _layoutService.Load();
        state.ShowPacketList = ShowPacketList;
        state.ShowProtocolTree = ShowProtocolTree;
        state.ShowHexEditor = ShowHexEditor;
        _layoutService.Save(state);

        if (Layout is { } layout)
        {
            try
            {
                _layoutService.SaveDockLayout(_dockSerializer.Serialize(layout));
            }
            catch (Exception ex)
            {
                TraceLog.Write($"VM.SaveDockLayout failed: {ex.Message}");
            }
        }
    }

    // Event Handlers

    private void OnPacketSelected(Packet? packet)
    {
        HexEditor.LoadPacket(packet);

        // Keep the pending verify-before-commit context in sync with the selected
        // packet. When the early-return below fires for a packet whose layers were
        // already prefetched, PendingContextFrames would otherwise still hold the
        // previous packet's context and the edit transaction would build its temp
        // PCAP with mismatched context frames.
        ProtocolTree.PendingContextFrames =
            packet != null && _packetContextFrames.TryGetValue(packet, out var cachedContext)
                ? cachedContext
                : null;
        ProtocolTree.PendingLinkLayerType = Document?.LinkLayerType ?? 1;

        if (packet == null || packet.Layers.Count > 0)
        {
            ProtocolTree.LoadPacket(packet);
            return;
        }

        if (IsReadOnly)
        {
            ProtocolTree.LoadPacket(null);
            return;
        }

        // Protocol tree is built on demand (single-packet tshark re-parse).
        // Opening a capture selects the first packet twice (once while binding,
        // once after the streamed list load finishes); a second concurrent build
        // would append a duplicate copy of every layer into this same packet.
        if (!_buildingPackets.Add(packet))
            return;

        int seq = ++_treeBuildSeq;
        ProtocolTree.LoadPacket(null);
        _ = BuildTreeAsync(packet, seq);
    }

    private async Task BuildTreeAsync(Packet packet, int seq)
    {
        try
        {
            var context = await ResolveContextFramesAsync(packet);

            _packetContextFrames[packet] = context;
            ProtocolTree.PendingContextFrames = context;
            ProtocolTree.PendingLinkLayerType = Document?.LinkLayerType ?? 1;

            bool ok = await _tshark.BuildPacketTreeAsync(packet, Document?.LinkLayerType ?? 1, context, foreground: true);
            if (ok && seq == _treeBuildSeq)
            {
                ProtocolTree.LoadPacket(packet);
                BumpPrefetch(packet);
            }
        }
        catch (Exception ex)
        {
            TraceLog.Write($"Tree build failed for packet #{packet.PacketNumber}: {ex.Message}");
            if (seq == _treeBuildSeq)
                ShowStatus("Status.ParseFailed", packet.PacketNumber, ex.Message);
        }
        finally
        {
            _buildingPackets.Remove(packet);
        }
    }

    private async Task<IReadOnlyList<(long Timestamp, byte[] Data)>?> ResolveContextFramesAsync(Packet packet)
    {
        if (Document is not { } doc)
            return null;
        var frameNumbers = await CollectContextFrameNumbersAsync(packet, doc);
        if (frameNumbers.Count == 0)
            return null;
        return frameNumbers
            .Where(fn => fn >= 1 && fn <= doc.Packets.Count)
            .Select(fn => (doc.Packets[fn - 1].Timestamp, doc.Packets[fn - 1].RawData))
            .ToList();
    }

    /// <summary>
    /// Unions the context frames contributed by every provider for the target
    /// packet. Each provider receives the frames selected so far as seeds, so a
    /// provider can expand its closure over another provider's frames (e.g. the
    /// IP-fragment provider also pulls sibling fragments of an SDP seed frame).
    /// </summary>
    private static async Task<IReadOnlyList<int>> CollectContextFrameNumbersAsync(
        Packet packet, PacketDocument doc)
    {
        var seeds = new HashSet<int>();
        foreach (var provider in doc.ContextProviders)
        {
            foreach (var fn in await provider.CollectFramesAsync(packet.PacketNumber, seeds))
                seeds.Add(fn);
        }
        seeds.Remove(packet.PacketNumber);
        return seeds.OrderBy(x => x).ToList();
    }

    private void BumpPrefetch(Packet anchor)
    {
        if (Document == null)
            return;
        int gen = ++_prefetchSeq;
        _ = PrefetchNeighborsAsync(anchor, gen);
    }

    private async Task PrefetchNeighborsAsync(Packet anchor, int gen)
    {
        foreach (var neighbor in NearbyPackets(anchor))
        {
            if (neighbor.Layers.Count > 0 || _buildingPackets.Contains(neighbor))
                continue;
            await _prefetchGate.WaitAsync();
            try
            {
                if (gen != _prefetchSeq)
                    return;
                if (neighbor.Layers.Count > 0 || !_buildingPackets.Add(neighbor))
                    continue;
                await PrefetchTreeAsync(neighbor);
            }
            catch (Exception ex)
            {
                TraceLog.Write($"Prefetch failed for packet #{neighbor.PacketNumber}: {ex.Message}");
            }
            finally
            {
                _buildingPackets.Remove(neighbor);
                _prefetchGate.Release();
            }
        }
    }

    private IEnumerable<Packet> NearbyPackets(Packet anchor)
    {
        var doc = Document;
        if (doc == null)
            yield break;
        int first = Math.Max(0, anchor.Index - PrefetchWindow);
        int last = Math.Min(doc.Packets.Count - 1, anchor.Index + PrefetchWindow);
        for (int i = first; i <= last; i++)
        {
            var packet = doc.Packets[i];
            if (packet != anchor)
                yield return packet;
        }
    }

    private async Task PrefetchTreeAsync(Packet packet)
    {
        var context = await ResolveContextFramesAsync(packet);
        _packetContextFrames[packet] = context;
        await _tshark.BuildPacketTreeAsync(packet, Document?.LinkLayerType ?? 1, context);
    }

    private void OnFieldSelected((Packet Packet, ProtocolField Field) args)
    {
        TraceLog.Write($"MW.OnFieldSelected({args.Field.Name})");
        HexEditor.HighlightField(args.Field, moveSelection: true);
        ShowStatus("Status.FieldSelected", args.Field.Name, args.Field.Offset, args.Field.Length);
    }

    private void OnLayerSelected((Packet Packet, ProtocolLayer Layer) args)
    {
        TraceLog.Write($"MW.OnLayerSelected({args.Layer.ProtocolName})");
        HexEditor.HighlightLayer(args.Layer, moveSelection: true);
        ShowStatus("Status.LayerSelected", args.Layer.DisplayText);
    }

    private void OnFieldEdited((Packet Packet, ProtocolField Field) args)
    {
        if (IsReadOnly)
        {
            ShowStatus("Field.ReadOnly");
            return;
        }

        ModifiedPackets = Document?.GetModifiedPackets().Count() ?? 0;
        if (Document != null)
            Document.HasUnsavedChanges = ModifiedPackets > 0;

        HexEditor.RefreshBytes();
        HexEditor.RefreshAddressInfo();
        HexEditor.MarkFieldEdited(args.Field);
        HexEditor.HighlightField(args.Field, moveSelection: true);
        RefreshLayerDisplayText(args.Packet);
        ProtocolEditorService.RefreshEditedFieldBytes(args.Packet, args.Field.Offset, args.Field.Length);

        ShowStatus("Status.PacketModified", args.Packet.PacketNumber, ModifiedPackets);

        _ = RefreshDisplayAfterEditAsync(args.Packet);
    }

    /// <summary>
    /// Hex-native commit handler: mirrors the tree-edit path but skips the
    /// read-only re-check and the hex refreshes, because the HexEditorViewModel
    /// commit already performed those synchronously. Reuses the same single-packet
    /// reparse so every edit — tree or hex — triggers exactly one refresh pass.
    /// </summary>
    private void OnHexEdited((Packet Packet, int Offset, int Length) args)
    {
        ModifiedPackets = Document?.GetModifiedPackets().Count() ?? 0;
        if (Document != null)
            Document.HasUnsavedChanges = ModifiedPackets > 0;

        RefreshLayerDisplayText(args.Packet);
        ProtocolEditorService.RefreshEditedFieldBytes(args.Packet, args.Offset, args.Length);

        ShowStatus("Status.PacketModified", args.Packet.PacketNumber, ModifiedPackets);

        _ = RefreshDisplayAfterEditAsync(args.Packet);
    }

    private void OnHexFieldFound(ProtocolField field)
    {
        ProtocolTree.SelectFieldOnTree(field);
    }

    /// <summary>
    /// Re-parses the edited packet with tshark in the background and patches the
    /// visible tree texts in place. The edit itself stays synchronous; this only
    /// refreshes container/layer display strings. A newer edit on the same packet
    /// supersedes an in-flight refresh (version counter). Failures degrade
    /// silently to the already-committed edit.
    /// </summary>
    private async Task RefreshDisplayAfterEditAsync(Packet packet)
    {
        int version = _reparseVersions.TryGetValue(packet, out var current) ? current + 1 : 1;
        _reparseVersions[packet] = version;

        string tempPath = Path.Combine(Path.GetTempPath(), $"pf_refresh_{Guid.NewGuid():N}.pcap");
        try
        {
            if (_packetContextFrames.TryGetValue(packet, out var ctx) && ctx is { Count: > 0 })
                await _pcapExport.SavePacketWithContextAsync(packet, ctx, tempPath, Document?.LinkLayerType ?? 1);
            else
                await _pcapExport.SavePacketAsync(packet, tempPath, Document?.LinkLayerType ?? 1);

            if (_reparseVersions.TryGetValue(packet, out int afterSave) && afterSave != version)
                return;

            var fresh = await _tshark.ReparseSinglePacketAsync(tempPath);
            if (fresh == null)
                return;

            if (_reparseVersions.TryGetValue(packet, out int afterReparse) && afterReparse != version)
                return;

            int misses = ProtocolTree.RefreshFieldDisplays(packet, fresh);
            if (misses > 0)
                TraceLog.Write($"Display refresh: {misses} field(s) unmatched for packet #{packet.PacketNumber}");
        }
        catch (Exception ex)
        {
            TraceLog.Write($"Display refresh failed for packet #{packet.PacketNumber}: {ex.Message}");
        }
        finally
        {
            try { File.Delete(tempPath); } catch (Exception) { /* best-effort temp clean-up */ }
        }
    }

    /// <summary>
    /// Rebuilds the tree header text of network/transport layers whose content
    /// depends on addresses or ports, which the byte edit may have changed.
    /// </summary>
    private static void RefreshLayerDisplayText(Packet packet)
    {
        string srcAddr = packet.SourceAddress;
        string dstAddr = packet.DestinationAddress;
        int srcPort = packet.SourcePort;
        int dstPort = packet.DestinationPort;

        foreach (var layer in packet.Layers)
        {
            layer.DisplayText = layer.ProtocolName.ToLowerInvariant() switch
            {
                "ip" or "ipv4" => LocalizationService.Resolve("Layer.Ipv4", srcAddr, dstAddr),
                "ipv6" => LocalizationService.Resolve("Layer.Ipv6", srcAddr, dstAddr),
                _ when (srcPort > 0 || dstPort > 0) && layer.HasPortFields =>
                    LocalizationService.Resolve("Layer.TcpUdpPorts",
                        layer.ProtocolName.ToLowerInvariant() switch
                        {
                            "tcp" => LocalizationService.Resolve("Layer.Tcp"),
                            "udp" => LocalizationService.Resolve("Layer.Udp"),
                            "sctp" => LocalizationService.Resolve("Layer.Sctp"),
                            _ => layer.ProtocolName.ToUpperInvariant(),
                        },
                        srcPort, dstPort),
                _ => layer.DisplayText,
            };
        }
    }
    [ObservableProperty]
    private bool _showStatistics;

    /// <summary>
    /// The tshark taps offered in the statistics panel. Each answers a question an
    /// operator actually asks of a 3GPP capture, and every one is a single tshark
    /// invocation away — the engine was already a dependency, it was just never asked.
    /// IO graphs are deliberately absent: they need a plotting stack, which this
    /// project does not take a dependency on.
    /// </summary>
    public IReadOnlyList<string> StatisticsTaps { get; } =
        ["conv,ip", "conv,tcp", "conv,udp", "conv,sctp", "endpoints,ip", "io,phs", "io,stat,0", "expert"];

    [ObservableProperty]
    private string? _selectedStatisticsTap;

    /// <summary>
    /// Operator-typed <c>-z</c> invocation that overrides the curated list while
    /// non-empty. Picking a curated tap clears it, so the combo always shows what
    /// will actually run.
    /// </summary>
    [ObservableProperty]
    private string _customStatisticsTap = string.Empty;

    partial void OnSelectedStatisticsTapChanged(string? value) =>
        CustomStatisticsTap = string.Empty;

    [ObservableProperty]
    private string _statisticsStatus = string.Empty;

    /// <summary>
    /// Tap output as aligned text lines. tshark pads its own columns for humans, so
    /// imposing a column model would lose fidelity — and the row width differs per
    /// tap (io,stat emits an interval label plus counters, expert emits severity and
    /// group), which makes a fixed grid awkward anyway.
    /// </summary>
    public ObservableCollection<string> StatisticsLines { get; } = [];

    /// <summary>
    /// Runs the selected tap against the loaded capture. Reuses the display filter so
    /// the statistics describe exactly the rows the user is looking at. A non-empty
    /// custom tap wins over the curated list, so any <c>-z</c> invocation tshark
    /// accepts runs here — the panel is not limited to the built-in taps.
    /// </summary>
    [RelayCommand]
    public async Task LoadStatisticsAsync()
    {
        StatisticsLines.Clear();
        StatisticsStatus = string.Empty;

        string? tap = string.IsNullOrWhiteSpace(CustomStatisticsTap)
            ? SelectedStatisticsTap
            : CustomStatisticsTap.Trim();
        if (_loadedFilePath is null || tap is null)
        {
            StatisticsStatus = LocalizationService.Resolve("Stats.NoFile");
            return;
        }

        try
        {
            var lines = await _tshark.RunStatisticsTapAsync(_loadedFilePath, tap, _displayFilter);

            foreach (var line in lines)
                StatisticsLines.Add(line);

            StatisticsStatus = lines.Count == 0
                ? LocalizationService.Resolve("Stats.Empty", tap)
                : LocalizationService.Resolve("Stats.Rows", lines.Count);
        }
        catch (Exception ex)
        {
            StatisticsStatus = LocalizationService.Resolve("Stats.Failed", ex.Message);
        }
    }

    private static IEnumerable<Models.ProtocolField> Flatten(IEnumerable<Models.ProtocolField> fields)
    {
        foreach (var f in fields)
        {
            yield return f;
            foreach (var c in Flatten(f.Children))
                yield return c;
        }
    }
}

/// <summary>Semantic colour state of the display-filter box (bound via CSS classes).</summary>
public enum FilterValidationState
{
    None,
    Valid,
    Invalid,
}
