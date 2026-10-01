using System.ComponentModel;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProtocolForge.Models;
using ProtocolForge.Services;

namespace ProtocolForge.ViewModels;

public sealed partial class MainWindowViewModel : ViewModelBase
{
    private readonly TsharkService _tshark;
    private readonly PcapExportService _pcapExport;
    private readonly ProtocolEditorService _editorService;
    private readonly LayoutService _layoutService;

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
        LayoutService? layoutService = null)
    {
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

        // Restore panel visibility from saved layout
        var saved = _layoutService.Load();
        ShowPacketList = saved.ShowPacketList;
        ShowProtocolTree = saved.ShowProtocolTree;
        ShowHexEditor = saved.ShowHexEditor;

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
    }

    // Commands

    [RelayCommand]
    private async Task OpenPcapAsync()
    {
        await Task.CompletedTask;
    }

    public async Task LoadFileAsync(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return;

        IsLoading = true;
        ShowStatus("Status.Loading", Path.GetFileName(filePath));

        try
        {
            var document = new PacketDocument { FilePath = filePath };
            PacketList.LoadFromDocument(document);

            var progress = new Progress<double>(p => LoadProgress = p);

            // Bind the grid to the empty document first so the streamed tshark
            // fields pass fills it progressively instead of in one block at the end.
            if (IsReadOnly)
            {
                await _tshark.LoadPcapReadOnlyAsync(document, filePath, ct: default);
            }
            else
            {
                await _tshark.LoadPcapAsync(document, filePath, progress);
            }

            Document = document;
            FileName = Path.GetFileName(filePath);
            TotalPackets = document.PacketCount;
            ModifiedPackets = 0;

            PacketList.LoadFromDocument(document);

            if (document.SelectedPacket != null)
                OnPacketSelected(document.SelectedPacket);

            ShowStatus("Status.LoadedPackets", document.PacketCount, FileName);
        }
        catch (Exception ex)
        {
            ShowStatus("Status.Error", ex.Message);
        }
        finally
        {
            IsLoading = false;
            LoadProgress = 0;
        }
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
            };
            await _pcapExport.ExportAsync(Document.Packets, options);
            Document.HasUnsavedChanges = false;
            ModifiedPackets = 0;
            ShowStatus("Status.Saved", Document.PacketCount, Path.GetFileName(Document.FilePath));
        }
        catch (Exception ex)
        {
            ShowStatus("Status.SaveFailed", ex.Message);
        }
    }

    [RelayCommand]
    private async Task ExportPcapAsync()
    {
        if (IsReadOnly)
        {
            ShowStatus("Status.ReadOnlyExport");
            return;
        }
        if (Document == null || TotalPackets == 0)
        {
            ShowStatus("Status.NoPacketsExport");
            return;
        }
        await Task.CompletedTask;
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
    private void TogglePacketList()
    {
        ShowPacketList = !ShowPacketList;
        SaveLayout();
    }

    [RelayCommand]
    private void ToggleProtocolTree()
    {
        ShowProtocolTree = !ShowProtocolTree;
        SaveLayout();
    }

    [RelayCommand]
    private void ToggleHexEditor()
    {
        ShowHexEditor = !ShowHexEditor;
        SaveLayout();
    }

    // Layout persistence
    public void SaveLayout(double topRatio = 0.35, double bottomRatio = 0.5,
        double winX = -1, double winY = -1, double winW = 1200, double winH = 800, int winState = 0)
    {
        _layoutService.Save(new LayoutState
        {
            TopRowRatio = topRatio,
            BottomLeftRatio = bottomRatio,
            WindowX = winX, WindowY = winY,
            WindowWidth = winW, WindowHeight = winH,
            WindowState = winState,
            ShowPacketList = ShowPacketList,
            ShowProtocolTree = ShowProtocolTree,
            ShowHexEditor = ShowHexEditor,
        });
    }

    // Event Handlers

    private void OnPacketSelected(Packet? packet)
    {
        HexEditor.LoadPacket(packet);

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

            bool ok = await _tshark.BuildPacketTreeAsync(packet, Document?.LinkLayerType ?? 1, context);
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
        HexEditor.HighlightField(args.Field);
        ShowStatus("Status.FieldSelected", args.Field.Name, args.Field.Offset, args.Field.Length);
    }

    private void OnLayerSelected((Packet Packet, ProtocolLayer Layer) args)
    {
        TraceLog.Write($"MW.OnLayerSelected({args.Layer.ProtocolName})");
        HexEditor.HighlightLayer(args.Layer);
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
        HexEditor.HighlightField(args.Field);
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
                "udp" or "tcp" when srcPort > 0 || dstPort > 0 =>
                    LocalizationService.Resolve("Layer.TcpUdpPorts",
                        LocalizationService.Resolve(layer.ProtocolName == "tcp" ? "Layer.Tcp" : "Layer.Udp"),
                        srcPort, dstPort),
                _ => layer.DisplayText,
            };
        }
    }
}
