using Avalonia;
using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Platform.Storage;
using System.Diagnostics;
using System.Reflection;
using ProtocolForge.Services;
using ProtocolForge.ViewModels;

namespace ProtocolForge.Views;

public partial class MainWindow : Window
{
    private MainWindowViewModel? ViewModel => DataContext as MainWindowViewModel;
    private readonly LayoutService _layoutService = new();

    public MainWindow()
    {
        InitializeComponent();
        UpdateLanguageMenuChecks();
        LocalizationService.LanguageChanged += (_, _) => UpdateLanguageMenuChecks();
        RestoreLayout();
        DataContextChanged += OnDataContextChanged;
    }

    private bool _selectionSyncWired;
    private bool _allowClose;
    private bool _closePromptOpen;

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (ViewModel == null)
            return;

        if (_selectionSyncWired)
            return;

        _selectionSyncWired = true;
        ViewModel.PacketList.SendSelectionChanged += SyncHeaderSelectAllCheckBox;
        SyncHeaderSelectAllCheckBox();
    }

    private void SyncHeaderSelectAllCheckBox()
    {
        if (ViewModel != null)
            SelectAllSendCheckBox.IsChecked = ViewModel.PacketList.AllSelectedForSend;
    }

    private void OnSelectAllSendToggle(object? sender, RoutedEventArgs e)
    {
        if (ViewModel == null || SelectAllSendCheckBox.IsChecked is null)
            return;
        ViewModel.PacketList.AllSelectedForSend = SelectAllSendCheckBox.IsChecked.Value;
    }

    // ─── Packet List Context Menu ───

    private void OnSelectAllSendClick(object? sender, RoutedEventArgs e)
    {
        ViewModel?.PacketList.SelectAllForSend();
    }

    private void OnClearSendSelectionClick(object? sender, RoutedEventArgs e)
    {
        ViewModel?.PacketList.ClearSendSelection();
    }

    private void OnInvertSendSelectionClick(object? sender, RoutedEventArgs e)
    {
        ViewModel?.PacketList.InvertSendSelection();
    }

    private async void OnSendThisPacketClick(object? sender, RoutedEventArgs e)
    {
        var vm = ViewModel;
        if (vm?.PacketList.SelectedPacket is not { } packet)
            return;
        await vm.ToolBar.SendPacketsAsync(new[] { packet });
    }

    private enum UnsavedCloseAction
    {
        Cancel,
        Save,
        Discard,
    }

    private async Task<UnsavedCloseAction> ShowUnsavedChangesDialogAsync()
    {
        var completion = new TaskCompletionSource<UnsavedCloseAction>(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelButton = new Button
        {
            Content = LocalizationService.Resolve("Dlg.Cancel"),
            IsCancel = true,
            IsDefault = true,
            MinWidth = 110,
        };
        var discardButton = new Button
        {
            Content = LocalizationService.Resolve("Dlg.CloseDiscard"),
            MinWidth = 130,
        };
        var saveButton = new Button
        {
            Content = LocalizationService.Resolve("Dlg.CloseSave"),
            MinWidth = 130,
            FontWeight = FontWeight.Bold,
        };

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 8,
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right,
        };
        buttons.Children.Add(cancelButton);
        buttons.Children.Add(discardButton);
        buttons.Children.Add(saveButton);

        var content = new StackPanel
        {
            Margin = new Thickness(20),
            Spacing = 18,
        };
        content.Children.Add(new TextBlock
        {
            Text = LocalizationService.Resolve("Dlg.CloseUnsavedText"),
            TextWrapping = TextWrapping.Wrap,
            FontSize = 13,
        });
        content.Children.Add(buttons);

        var dialog = new Window
        {
            Title = LocalizationService.Resolve("Dlg.CloseUnsavedTitle"),
            Width = 500,
            Height = 220,
            CanResize = false,
            ShowInTaskbar = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Icon = new WindowIcon(AssetLoader.Open(new Uri("avares://ProtocolForge/Assets/protocol-forge.ico"))),
            Content = content,
        };

        cancelButton.Click += (_, _) => completion.TrySetResult(UnsavedCloseAction.Cancel);
        discardButton.Click += (_, _) => completion.TrySetResult(UnsavedCloseAction.Discard);
        saveButton.Click += (_, _) => completion.TrySetResult(UnsavedCloseAction.Save);
        dialog.Closed += (_, _) => completion.TrySetResult(UnsavedCloseAction.Cancel);
        _ = dialog.ShowDialog(this);
        return await completion.Task;
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

    // ─── Layout Persistence ───

    private void RestoreLayout()
    { 
        TraceLog.Write("MW.RestoreLayout called");
        try
        {
            var state = _layoutService.Load();

            // Restore window geometry
            if (state.WindowX >= 0 && state.WindowY >= 0)
            {
                Position = new PixelPoint((int)state.WindowX, (int)state.WindowY);
            }
            Width = state.WindowWidth;
            Height = state.WindowHeight;
            WindowState = (WindowState)state.WindowState;

            // Restore splitter positions via row/column definitions
            // Top row ratio: e.g., "2*,5*,3*" → top=2/(2+3)=0.4
            double topRatio = Math.Clamp(state.TopRowRatio, 0.15, 0.75);
            double bottomRatio = Math.Clamp(state.BottomLeftRatio, 0.15, 0.85);

            double topStar = topRatio;
            double bottomStar = 1.0 - topRatio;
            ContentGrid.RowDefinitions[0].Height = new GridLength(topStar, GridUnitType.Star);
            ContentGrid.RowDefinitions[2].Height = new GridLength(bottomStar, GridUnitType.Star);

            double leftStar = bottomRatio;
            double rightStar = 1.0 - bottomRatio;
            BottomGrid.ColumnDefinitions[0].Width = new GridLength(leftStar, GridUnitType.Star);
            BottomGrid.ColumnDefinitions[2].Width = new GridLength(rightStar, GridUnitType.Star);
        }
        catch { /* use defaults */ }
    }

    private void SaveLayout()
    {
        if (ViewModel == null) return;

        double totalTopStar = ContentGrid.RowDefinitions[0].Height.Value
                            + ContentGrid.RowDefinitions[2].Height.Value;
        double topRatio = totalTopStar > 0
            ? ContentGrid.RowDefinitions[0].Height.Value / totalTopStar
            : 0.35;

        double totalBottomStar = BottomGrid.ColumnDefinitions[0].Width.Value
                               + BottomGrid.ColumnDefinitions[2].Width.Value;
        double bottomRatio = totalBottomStar > 0
            ? BottomGrid.ColumnDefinitions[0].Width.Value / totalBottomStar
            : 0.5;

        TraceLog.Write($"MW.SaveLayout topRatio={topRatio} bottomRatio={bottomRatio}");

        ViewModel.SaveLayout(
            topRatio, bottomRatio,
            Position.X, Position.Y,
            Width, Height,
            (int)WindowState);
    }

    // ─── Menu Event Handlers ───

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
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelButton = new Button
        {
            Content = LocalizationService.Resolve("Dlg.Cancel"),
            IsCancel = true,
            MinWidth = 110,
        };
        var confirmButton = new Button
        {
            Content = LocalizationService.Resolve("Dlg.ResetModsConfirm"),
            IsDefault = true,
            MinWidth = 130,
            FontWeight = FontWeight.Bold,
        };
        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 8,
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right,
        };
        buttons.Children.Add(cancelButton);
        buttons.Children.Add(confirmButton);

        var content = new StackPanel
        {
            Margin = new Thickness(20),
            Spacing = 18,
        };
        content.Children.Add(new TextBlock
        {
            Text = LocalizationService.Resolve("Dlg.ResetModsText", modifiedCount),
            TextWrapping = TextWrapping.Wrap,
            FontSize = 13,
        });
        content.Children.Add(buttons);

        var dialog = new Window
        {
            Title = LocalizationService.Resolve("Dlg.ResetModsTitle"),
            Width = 460,
            Height = 220,
            CanResize = false,
            ShowInTaskbar = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Icon = new WindowIcon(AssetLoader.Open(new Uri("avares://ProtocolForge/Assets/protocol-forge.ico"))),
            Content = content,
        };

        cancelButton.Click += (_, _) => completion.TrySetResult(false);
        confirmButton.Click += (_, _) => completion.TrySetResult(true);
        dialog.Closed += (_, _) => completion.TrySetResult(false);
        _ = dialog.ShowDialog(this);
        return await completion.Task;
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
        // Reset to default ratios
        ContentGrid.RowDefinitions[0].Height = new GridLength(2, GridUnitType.Star);
        ContentGrid.RowDefinitions[2].Height = new GridLength(3, GridUnitType.Star);
        BottomGrid.ColumnDefinitions[0].Width = new GridLength(1, GridUnitType.Star);
        BottomGrid.ColumnDefinitions[2].Width = new GridLength(1, GridUnitType.Star);
        SaveLayout();
    }

    private void OnAboutClicked(object? sender, RoutedEventArgs e)
    {
        string version = Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? "0.0.0";
        var dialog = new Window
        {
            Title = LocalizationService.Resolve("Dlg.About"),
            Width = 460,
            Height = 280,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Icon = new WindowIcon(AssetLoader.Open(new Uri("avares://ProtocolForge/Assets/protocol-forge.ico"))),
            Content = new TextBlock
            {
                Text = LocalizationService.Resolve("Dlg.AboutText", version),
                Margin = new Thickness(20),
                TextWrapping = TextWrapping.Wrap,
            },
        };
        dialog.ShowDialog(this);
    }



    private async Task ShowInfoAsync(string title, string message)
    {
        var closeButton = new Button
        {
            Content = LocalizationService.Resolve("Lic.OK"),
            IsDefault = true,
            MinWidth = 100,
        };
        var content = new StackPanel
        {
            Margin = new Thickness(20),
            Spacing = 18,
        };
        content.Children.Add(new TextBlock
        {
            Text = message,
            TextWrapping = TextWrapping.Wrap,
            FontSize = 13,
        });
        content.Children.Add(closeButton);

        var dialog = new Window
        {
            Title = title,
            Width = 440,
            Height = 220,
            CanResize = false,
            ShowInTaskbar = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Icon = new WindowIcon(AssetLoader.Open(new Uri("avares://ProtocolForge/Assets/protocol-forge.ico"))),
            Content = content,
        };
        closeButton.Click += (_, _) => dialog.Close();
        await dialog.ShowDialog(this);
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
            DefaultExtension = "pcap",
            FileTypeChoices =
            [
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
