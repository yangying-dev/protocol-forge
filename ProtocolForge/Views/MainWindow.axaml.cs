using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform.Storage;
using System.Diagnostics;
using System.Reflection;
using ProtocolForge.Services;
using ProtocolForge.ViewModels;
using SukiUI.Controls;
using SukiUI.MessageBox;

namespace ProtocolForge.Views;

public partial class MainWindow : SukiWindow
{
    private MainWindowViewModel? ViewModel => DataContext as MainWindowViewModel;
    private readonly LayoutService _layoutService = new();

    public MainWindow()
    {
        InitializeComponent();
        UpdateLanguageMenuChecks();
        LocalizationService.LanguageChanged += (_, _) => UpdateLanguageMenuChecks();
        UpdateThemeMenuChecks();
        ThemeService.ThemeVariantChanged += (_, _) => UpdateThemeMenuChecks();
        RestoreLayout();
    }

    private bool _allowClose;
    private bool _closePromptOpen;

    private enum UnsavedCloseAction
    {
        Cancel,
        Save,
        Discard,
    }

    // 固定宽度让长文案按该宽度换行,高度自适应内容(旧实现写死高度会裁掉长文本);
    // 居中于主窗口/不进任务栏/不可缩放由 SukiUI 默认处理,不要在此重复设置。
    private static SukiMessageBoxOptions DialogWindow(double width) => new()
    {
        Width = width,
        SizeToContent = SizeToContent.Height,
    };

    private async Task<UnsavedCloseAction> ShowUnsavedChangesDialogAsync()
    {
        var cancelButton = SukiMessageBoxButtonsFactory.CreateButton(
            LocalizationService.Resolve("Dlg.Cancel"), SukiMessageBoxResult.Cancel);
        cancelButton.IsCancel = true;
        cancelButton.IsDefault = true;
        cancelButton.MinWidth = 110;

        var discardButton = SukiMessageBoxButtonsFactory.CreateButton(
            LocalizationService.Resolve("Dlg.CloseDiscard"), SukiMessageBoxResult.No);
        discardButton.MinWidth = 130;

        var saveButton = SukiMessageBoxButtonsFactory.CreateButton(
            LocalizationService.Resolve("Dlg.CloseSave"), SukiMessageBoxResult.Yes);
        saveButton.MinWidth = 130;
        saveButton.FontWeight = FontWeight.Bold;

        var result = await SukiMessageBox.ShowDialogResult(
            this,
            new SukiMessageBoxHost
            {
                IconPreset = SukiMessageBoxIcons.Warning,
                Content = LocalizationService.Resolve("Dlg.CloseUnsavedText"),
                ActionButtonsSource = [cancelButton, discardButton, saveButton],
            },
            LocalizationService.Resolve("Dlg.CloseUnsavedTitle"),
            DialogWindow(500));

        return result switch
        {
            SukiMessageBoxResult.Yes => UnsavedCloseAction.Save,
            SukiMessageBoxResult.No => UnsavedCloseAction.Discard,
            _ => UnsavedCloseAction.Cancel,
        };
    }

    private async Task ConfirmCloseAsync()
    {
        if (_closePromptOpen)
            return;

        _closePromptOpen = true;
        try
        {
            var action = await ShowUnsavedChangesDialogAsync();
            if (action == UnsavedCloseAction.Cancel)
                return;

            if (action == UnsavedCloseAction.Save)
            {
                if (ViewModel == null)
                    return;

                await ViewModel.SavePcapCommand.ExecuteAsync(null);
                if (ViewModel.Document?.HasUnsavedChanges == true)
                    return;
            }

            _allowClose = true;
            Close();
        }
        finally
        {
            _closePromptOpen = false;
        }
    }

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        SaveLayout();
        if (!_allowClose && ViewModel?.Document?.HasUnsavedChanges == true)
        {
            e.Cancel = true;
            _ = ConfirmCloseAsync();
        }
        base.OnClosing(e);
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        // Avalonia's MenuItem.InputGesture is display-only — it never wires an
        // accelerator. Bind the real shortcuts here. Focused controls get first
        // refusal (a TextBox keeps its own Ctrl+Z/Ctrl+A), so only unhandled keys
        // reach the window.
        if ((e.KeyModifiers & KeyModifiers.Control) != 0)
        {
            switch (e.Key)
            {
                case Key.O:
                    e.Handled = true;
                    OnOpenPcapClicked(null, new RoutedEventArgs());
                    break;
                case Key.S:
                    e.Handled = true;
                    if ((e.KeyModifiers & KeyModifiers.Shift) != 0)
                        OnExportPcapClicked(null, new RoutedEventArgs());
                    else
                        OnSavePcapClicked(null, new RoutedEventArgs());
                    break;
                case Key.Z:
                    e.Handled = true;
                    if (ViewModel?.UndoCommand.CanExecute(null) == true)
                        ViewModel.UndoCommand.Execute(null);
                    break;
                case Key.Y:
                    e.Handled = true;
                    if (ViewModel?.RedoCommand.CanExecute(null) == true)
                        ViewModel.RedoCommand.Execute(null);
                    break;
                case Key.F:
                    e.Handled = true;
                    ViewModel?.RequestFindFocus();
                    break;
            }
        }

        base.OnKeyDown(e);
    }

    // ─── Layout Persistence ───

    private void RestoreLayout()
    { 
        TraceLog.Write("MW.RestoreLayout called");
        try
        {
            var state = _layoutService.Load();

            if (state.WindowX >= 0 && state.WindowY >= 0)
            {
                Position = new PixelPoint((int)state.WindowX, (int)state.WindowY);
            }
            Width = state.WindowWidth;
            Height = state.WindowHeight;
            WindowState = (WindowState)state.WindowState;
        }
        catch { /* use defaults */ }
    }

    private void SaveLayout()
    {
        if (ViewModel == null) return;

        ViewModel.SaveLayout(
            Position.X, Position.Y,
            Width, Height,
            (int)WindowState);
    }

    // ─── Menu Event Handlers ───

    private void OnFocusFindBox(object? sender, RoutedEventArgs e) => ViewModel?.RequestFindFocus();

    private async void OnOpenPcapClicked(object? sender, RoutedEventArgs e)
    {
        await OpenPcapDialogAsync();
    }

    private async void OnSavePcapClicked(object? sender, RoutedEventArgs e)
    {
        if (ViewModel != null)
            await ViewModel.SavePcapCommand.ExecuteAsync(null);
    }

    private async void OnExportPcapClicked(object? sender, RoutedEventArgs e)
    {
        await ExportPcapDialogAsync();
    }

    private async void OnResetClicked(object? sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm || vm.ModifiedPackets == 0)
            return;

        if (!await ConfirmResetModificationsAsync(vm.ModifiedPackets))
            return;

        await vm.ResetModificationsCommand.ExecuteAsync(null);
    }

    /// <summary>
    /// Asks before discarding every packet modification in the capture. The operation is
    /// whole-capture and has no undo stack, so a stray click would silently throw away
    /// work; this is the one place a confirmation is genuinely warranted.
    /// </summary>
    private async Task<bool> ConfirmResetModificationsAsync(int modifiedCount)
    {
        var cancelButton = SukiMessageBoxButtonsFactory.CreateButton(
            LocalizationService.Resolve("Dlg.Cancel"), SukiMessageBoxResult.Cancel);
        cancelButton.IsCancel = true;
        cancelButton.MinWidth = 110;

        var confirmButton = SukiMessageBoxButtonsFactory.CreateButton(
            LocalizationService.Resolve("Dlg.ResetModsConfirm"), SukiMessageBoxResult.Yes);
        confirmButton.IsDefault = true;
        confirmButton.MinWidth = 130;
        confirmButton.FontWeight = FontWeight.Bold;

        var result = await SukiMessageBox.ShowDialogResult(
            this,
            new SukiMessageBoxHost
            {
                IconPreset = SukiMessageBoxIcons.Warning,
                Content = LocalizationService.Resolve("Dlg.ResetModsText", modifiedCount),
                ActionButtonsSource = [cancelButton, confirmButton],
            },
            LocalizationService.Resolve("Dlg.ResetModsTitle"),
            DialogWindow(460));

        return result is SukiMessageBoxResult.Yes;
    }

    private void OnExitClicked(object? sender, RoutedEventArgs e)
    {
        SaveLayout();
        Close();
    }

    private async void OnPickTsharkClicked(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = LocalizationService.Resolve("Dlg.PickTshark"),
            AllowMultiple = false,
            FileTypeFilter =
            [
                new FilePickerFileType("Tshark")
                {
                    Patterns = OperatingSystem.IsWindows()
                        ? ["tshark.exe"]
                        : ["tshark"],
                },
                new FilePickerFileType(LocalizationService.Resolve("Dlg.AllFiles"))
                {
                    Patterns = ["*"],
                },
            ],
        });

        if (files.Count != 1)
            return;

        var path = files[0].TryGetLocalPath();
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return;

        var settings = new TsharkSettingsService();
        settings.SaveTsharkPath(path);
        Environment.SetEnvironmentVariable("TSHARK_PATH", path);

        ViewModel?.RedetectTsharkFromPath(path);
        TraceLog.Write($"Tshark path set to {path}");
    }

    private void OnResetLayoutClicked(object? sender, RoutedEventArgs e)
    {
        ViewModel?.ResetDockLayout();
    }

    private async void OnAboutClicked(object? sender, RoutedEventArgs e)
    {
        string version = Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? "0.0.0";
        var okButton = SukiMessageBoxButtonsFactory.CreateButton(
            LocalizationService.Resolve("Dlg.OK"), SukiMessageBoxResult.OK);
        okButton.IsDefault = true;
        okButton.MinWidth = 100;

        await SukiMessageBox.ShowDialog(
            this,
            new SukiMessageBoxHost
            {
                IconPreset = SukiMessageBoxIcons.Information,
                Content = LocalizationService.Resolve("Dlg.AboutText", version),
                ActionButtonsSource = [okButton],
            },
            LocalizationService.Resolve("Dlg.About"),
            DialogWindow(460));
    }

    private async Task ShowInfoAsync(string title, string message)
    {
        var okButton = SukiMessageBoxButtonsFactory.CreateButton(
            LocalizationService.Resolve("Dlg.OK"), SukiMessageBoxResult.OK);
        okButton.IsDefault = true;
        okButton.MinWidth = 100;

        await SukiMessageBox.ShowDialog(
            this,
            new SukiMessageBoxHost
            {
                IconPreset = SukiMessageBoxIcons.Information,
                Content = message,
                ActionButtonsSource = [okButton],
            },
            title,
            DialogWindow(440));
    }

    private void OnOpenLogDirClicked(object? sender, RoutedEventArgs e)
    {
        try
        {
            string dir = TraceLog.SupportDataDirectory;
            Directory.CreateDirectory(dir);
            Process.Start(new ProcessStartInfo { FileName = dir, UseShellExecute = true });
        }
        catch
        {
            // 打开目录失败时静默忽略,不打断用户
        }
    }

    private void OnUserManualClicked(object? sender, RoutedEventArgs e)
    {
        try
        {
            // 手册以单个自包含 HTML 随包分发(Manual/UserManual.html),
            // 用系统默认浏览器打开,完全离线,无需网络。
            string manualPath = Path.Combine(AppContext.BaseDirectory, "Manual", "UserManual.html");
            if (!File.Exists(manualPath))
                manualPath = Path.Combine(AppContext.BaseDirectory, "UserManual.html");
            if (File.Exists(manualPath))
                Process.Start(new ProcessStartInfo { FileName = manualPath, UseShellExecute = true });
            else
                _ = ShowInfoAsync(
                    LocalizationService.Resolve("Mnu.UserManual"),
                    LocalizationService.Resolve("Dlg.ManualMissing", manualPath));
        }
        catch
        {
            // 打开手册失败时静默忽略,不打断用户
        }
    }

    private void OnMenuLangZhCnClicked(object? sender, RoutedEventArgs e)
    {
        LocalizationService.SetCurrent(AppLanguage.ZhCn);
        // SetCurrent is a no-op when already active (no LanguageChanged), but the
        // ToggleType auto-toggle still flipped the check off — restore explicitly.
        UpdateLanguageMenuChecks();
    }

    private void OnMenuLangEnUsClicked(object? sender, RoutedEventArgs e)
    {
        LocalizationService.SetCurrent(AppLanguage.EnUs);
        UpdateLanguageMenuChecks();
    }

    private void UpdateLanguageMenuChecks()
    {
        var cur = LocalizationService.CurrentLanguage;
        MenuLangZhCn.IsChecked = cur == AppLanguage.ZhCn;
        MenuLangEnUs.IsChecked = cur == AppLanguage.EnUs;
    }

    private void OnMenuThemeBaseClicked(object? sender, RoutedEventArgs e)
    {
        if (sender is MenuItem { Tag: string key })
            ThemeService.SetBase(key);
        // SetBase is a no-op when already active (no ThemeVariantChanged), but the
        // ToggleType auto-toggle still flipped the check off — restore explicitly.
        UpdateThemeMenuChecks();
    }

    private void UpdateThemeMenuChecks()
    {
        foreach (var item in MenuTheme.Items.OfType<MenuItem>())
        {
            if (item.Tag is not string tag)
                continue;

            item.IsChecked = ThemeService.BaseKeys.Contains(tag, StringComparer.OrdinalIgnoreCase)
                && string.Equals(tag, ThemeService.CurrentBase, StringComparison.OrdinalIgnoreCase);
        }
    }

    // ─── File Dialogs ───

    public async Task OpenPcapDialogAsync()
    {
        if (ViewModel == null) return;

        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = LocalizationService.Resolve("Dlg.OpenPcap"),
            AllowMultiple = false,
            FileTypeFilter =
            [
                new FilePickerFileType(LocalizationService.Resolve("Dlg.PcapFiles"))
                {
                    Patterns = ["*.pcap", "*.pcapng", "*.cap"],
                },
                new FilePickerFileType(LocalizationService.Resolve("Dlg.AllFiles"))
                {
                    Patterns = ["*"],
                },
            ],
        });

        if (files.Count == 1)
        {
            var path = files[0].TryGetLocalPath();
            if (!string.IsNullOrWhiteSpace(path))
                await ViewModel.LoadFileAsync(path);
        }
    }

    public async Task ExportPcapDialogAsync()
    {
        if (ViewModel == null) return;

        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = LocalizationService.Resolve("Dlg.ExportPcap"),
            // PCAPNG is offered because export-as follows the chosen extension; without
            // it the writer this build ships would be unreachable from the UI.
            DefaultExtension = "pcapng",
            FileTypeChoices =
            [
                new FilePickerFileType(LocalizationService.Resolve("Dlg.PcapNgFile"))
                {
                    Patterns = ["*.pcapng"],
                },
                new FilePickerFileType(LocalizationService.Resolve("Dlg.PcapFile"))
                {
                    Patterns = ["*.pcap"],
                },
            ],
        });

        if (file != null)
        {
            var path = file.TryGetLocalPath();
            if (!string.IsNullOrWhiteSpace(path))
                await ViewModel.ExportToFileAsync(path);
        }
    }
}
