using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.VisualTree;
using ProtocolForge.ViewModels;

namespace ProtocolForge.Views.Controls;

public partial class PacketListPaneView : UserControl
{
    private MainWindowViewModel? ViewModel => DataContext as MainWindowViewModel;

    // Dock 标签页切换会反复装/卸面板内容,VM 事件必须在 DetachedFromVisualTree 时解开,
    // 否则每次切换都累积一份订阅(SendSelectionChanged 会对着旧实例持续回调)。
    private MainWindowViewModel? _wiredVm;
    private bool _attached;

    public PacketListPaneView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (_attached)
            {
                Unwire();
                Wire();
            }
        };
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _attached = true;
        Wire();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        _attached = false;
        Unwire();
        base.OnDetachedFromVisualTree(e);
    }

    private void Wire()
    {
        if (DataContext is not MainWindowViewModel vm)
            return;
        _wiredVm = vm;
        vm.PacketList.SendSelectionChanged += SyncHeaderSelectAllCheckBox;
        vm.FindFocusRequested += OnFindFocusRequested;
        SyncHeaderSelectAllCheckBox();
    }

    private void Unwire()
    {
        if (_wiredVm is null)
            return;
        _wiredVm.PacketList.SendSelectionChanged -= SyncHeaderSelectAllCheckBox;
        _wiredVm.FindFocusRequested -= OnFindFocusRequested;
        _wiredVm = null;
    }

    private void OnFindFocusRequested(object? sender, EventArgs e)
    {
        if (_attached)
            FindBox.Focus();
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

    private async void OnExportSendHistoryClick(object? sender, RoutedEventArgs e)
    {
        var vm = ViewModel;
        if (vm is null || vm.ToolBar.SendHistory.Count == 0)
            return;

        var storage = TopLevel.GetTopLevel(this)?.StorageProvider;
        if (storage is null)
            return;

        var file = await storage.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            SuggestedFileName = "send-history.csv",
            DefaultExtension = "csv",
            FileTypeChoices = [new FilePickerFileType("CSV") { Patterns = ["*.csv"] }],
        });
        if (file is null)
            return;

        vm.ToolBar.ExportSendHistory(file.Path.LocalPath);
    }

    private void OnClearSendHistoryClick(object? sender, RoutedEventArgs e)
    {
        ViewModel?.ToolBar.ClearSendHistory();
    }

    private void OnFindKeyDown(object? sender, KeyEventArgs e)
    {
        if (ViewModel is null)
            return;
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            ViewModel.FindNext();
        }
        else if (e.Key == Key.Escape)
        {
            e.Handled = true;
            ViewModel.FindText = string.Empty;
        }
    }

    private async void OnFilterKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter)
            return;
        e.Handled = true;
        if (ViewModel is not null)
            await ViewModel.ApplyFilterCommand.ExecuteAsync(null);
    }
}
