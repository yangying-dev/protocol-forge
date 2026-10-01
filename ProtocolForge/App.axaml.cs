using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using Avalonia.Markup.Xaml;
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
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
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
            var networkInterfaceService = new NetworkInterfaceService();
            var packetSendService = new PacketSendService();

            var packetList = new PacketListViewModel();
            var protocolTree = new ProtocolTreeViewModel(protocolEditor, editTransaction);
            var hexEditor = new HexEditorViewModel(protocolEditor);
            var toolBar = new ToolBarViewModel(networkInterfaceService, packetSendService, packetList);

            var mainViewModel = new MainWindowViewModel(
                tshark, pcapExport, protocolEditor,
                packetList, protocolTree, hexEditor, toolBar);

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
            if (desktop.Args is { Length: > 0 } cmdArgs &&
                !string.IsNullOrWhiteSpace(cmdArgs[0]))
            {
                var path = cmdArgs[0];
                mainWindow.Opened += async (_, _) => await mainViewModel.LoadFileAsync(path);
            }

            desktop.MainWindow = mainWindow;
        }

        base.OnFrameworkInitializationCompleted();
    }
}
