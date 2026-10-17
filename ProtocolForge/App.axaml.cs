using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Dock.Avalonia.Controls;
using Dock.Settings;
using ProtocolForge.Models;
using ProtocolForge.Services;
using ProtocolForge.ViewModels;
using ProtocolForge.Views;

namespace ProtocolForge;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        // Dock 停靠指示层:SukiUI 7.0.1 的窗口模板删除了 VisualLayerManager(6.1.1 尚有),
        // 而 AdornerLayer 由窗口模板中的 VisualLayerManager 惰性创建——整个窗口树都没有它时
        // AdornerLayer.GetAdornerLayer(visual) 返回 null,AdornerHelper.AddRegularAdorner
        // 随即静默返回,拖动窗格时不会出现任何停靠提示。启用 Dock 库自带的浮动指示窗
        // (DockAdornerWindow,顶层透明覆盖窗承载 DockTarget/GlobalDockTarget)替代,
        // 不依赖窗口树中的 AdornerLayer。必须在首个 DockControl 参与拖拽前生效。
        DockSettings.UseFloatingDockAdorner = true;

        // 面板标题栏展开态修正(样式见 Assets/DockDensity.axaml 的 pf-chrome-interacting):
        // 按下工具栏文本框等子控件时,Avalonia 12 的指针隐式捕获会让整条祖先链瞬时丢失
        // :pointerover,标题栏出现「按住消失、松开又出现」。按住期间给窗格 chrome 打一个
        // 交互类,使标题栏在交互期保持展开;松开/移出即恢复原生悬停语义。
        RegisterChromeInteractingHandlers();

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = ComposeMainWindow(desktop.Args);
        }

        base.OnFrameworkInitializationCompleted();
    }

    /// <summary>
    /// Builds the whole object graph and returns the main window. Extracted from the
    /// lifetime callback so the verification harness can mount the real window with the
    /// real view models under Avalonia.Headless — duplicating the graph in the harness
    /// would let it drift away from what the app actually runs.
    /// </summary>
    public static MainWindow ComposeMainWindow(IReadOnlyList<string>? args)
    {
            // ── Manual Dependency Injection ──
            // Simple DI without external containers.
            // Each service is instantiated once (singleton-scoped per app instance).

            // Restore a user-chosen tshark path (if any) as the effective
            // TSHARK_PATH for this session before the first detection.
            var tsharkSettings = new TsharkSettingsService();
            var savedTsharkPath = tsharkSettings.LoadTsharkPath();
            if (!string.IsNullOrWhiteSpace(savedTsharkPath))
                Environment.SetEnvironmentVariable("TSHARK_PATH", savedTsharkPath);

            // ── UI 语言 ──
            // 恢复上次的语言偏好;未保存过则按系统区域(zh 前缀 → 简体中文)。
            // 必须先于任何 ViewModel/Service 构造执行,否则默认文案会在错误语言下解析。
            var savedLanguage = tsharkSettings.LoadLanguage();
            LocalizationService.SetCurrent(
                Enum.TryParse<AppLanguage>(savedLanguage, ignoreCase: true, out var parsedLanguage)
                    ? parsedLanguage
                    : LocalizationService.DetectSystemLanguage());

            // 语言切换即时持久化:任何 SetCurrent(语言菜单等) 都写回 settings.json。
            // （订阅放在初始 SetCurrent 之后,避免启动时把"系统探测值"误存为用户选择。）
            LocalizationService.LanguageChanged += (_, _) =>
                tsharkSettings.SaveLanguage(LocalizationService.CurrentLanguage.ToString());

            // ── UI 主题 ──
            // 恢复上次的 基色(浅/深/跟随系统) + SukiUI 配色 偏好;未保存过则默认 Default+Blue。
            // Initialize 只应用不触发事件;订阅放在其后,避免启动时把默认值误存为用户选择。
            ThemeService.Initialize(tsharkSettings.LoadThemeVariant());
            ThemeService.ThemeVariantChanged += (_, _) =>
                tsharkSettings.SaveThemeVariant(ThemeService.CurrentSerialized);

            var pcapIngest = new PcapIngestService();
            var pcapExport = new PcapExportService();
            var tshark = new TsharkService(pcapIngest, pcapExport);

            // Restore a user-chosen TLS key-log path (if any) so every tshark
            // invocation this session can decrypt matching TLS traffic.
            var savedKeylogPath = tsharkSettings.LoadTlsKeylogPath();
            if (!string.IsNullOrWhiteSpace(savedKeylogPath))
                tshark.SetTlsKeylogPath(savedKeylogPath);

            var protocolEditor = new ProtocolEditorService();
            var editTransaction = new EditTransactionService(pcapExport, tshark);
            var editHistory = new EditHistoryService();
            var sessionState = new SessionStateService();
            var networkInterfaceService = new NetworkInterfaceService();
            var packetSendService = new PacketSendService();

            var packetList = new PacketListViewModel();
            var protocolTree = new ProtocolTreeViewModel(protocolEditor, editTransaction, editHistory);
            var hexEditor = new HexEditorViewModel(protocolEditor, editHistory);
            var toolBar = new ToolBarViewModel(networkInterfaceService, packetSendService, packetList);

            var mainViewModel = new MainWindowViewModel(
                tshark, pcapExport, protocolEditor,
                packetList, protocolTree, hexEditor, toolBar,
                layoutService: null,
                editHistory, sessionState);

            // ── Tshark availability gate ──
            // Detects tshark once at startup. When missing or < 2.6.0 the app runs
            // in read-only mode (raw packet list only) with an instructional banner.
            var detection = TsharkService.DetectTshark();
            if (!detection.Ok)
                mainViewModel.IsReadOnly = true;
            // 状态横幅/警告文本交给 VM 集中处理(ApplyTsharkStatus),语言切换时由 VM 重新解析。
            mainViewModel.ApplyTsharkStatus(detection);

            var mainWindow = new MainWindow
            {
                DataContext = mainViewModel,
            };

            // Open a PCAP path passed on the command line (documented in README).
            // Done after the window is shown so bindings / layout are ready.
            if (args is { Count: > 0 } && !string.IsNullOrWhiteSpace(args[0]))
            {
                var path = args[0];
                mainWindow.Opened += async (_, _) => await mainViewModel.LoadFileAsync(path);
            }

            return mainWindow;
    }

    /// <summary>
    /// 与 Assets/DockDensity.axaml 的 pf-chrome-interacting 选择器成对出现:改名需两处同步。
    /// </summary>
    internal const string ChromeInteractingClass = "pf-chrome-interacting";

    private static bool _chromeInteractingHandlersRegistered;

    /// <summary>
    /// 让 Dock 窗格标题栏在「按住期间」也保持展开。
    /// 根因:Avalonia 12 的 PointerOverPreProcessor 在指针被隐式捕获时把「有效悬停元素」
    /// 算作 null(命中元素 ≠ 捕获元素),祖先链上的 :pointerover 被清除;而 SukiUI.Dock 的
    /// 窗格标题栏正是靠 :pointerover 才从 AutoHide 展开,于是出现「按住消失、松开又出现」。
    /// 处理:按下(隧道)时加类、松开(隧道)时移除,并用「左键仍未按下」的移动事件自愈
    /// (松开发生在窗口外时收不到 Released)。样式侧见 Assets/DockDensity.axaml。
    /// </summary>
    private static void RegisterChromeInteractingHandlers()
    {
        if (_chromeInteractingHandlersRegistered)
            return;
        _chromeInteractingHandlersRegistered = true;

        InputElement.PointerPressedEvent.AddClassHandler<ToolChromeControl>(
            static (chrome, _) =>
            {
                // 浮动窗格有独立窗口 chrome,不参与标题栏悬停展开,避免按下时误触。
                if (!chrome.IsFloating)
                    chrome.Classes.Add(ChromeInteractingClass);
            },
            RoutingStrategies.Tunnel);

        InputElement.PointerReleasedEvent.AddClassHandler<ToolChromeControl>(
            static (chrome, _) => chrome.Classes.Remove(ChromeInteractingClass),
            RoutingStrategies.Tunnel);

        InputElement.PointerMovedEvent.AddClassHandler<ToolChromeControl>(
            static (chrome, e) =>
            {
                if (chrome.Classes.Contains(ChromeInteractingClass) &&
                    !e.GetCurrentPoint(chrome).Properties.IsLeftButtonPressed)
                    chrome.Classes.Remove(ChromeInteractingClass);
            },
            RoutingStrategies.Tunnel);
    }
}
