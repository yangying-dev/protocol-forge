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

    // Filter-box autocomplete: debounce the ~200k-name fetch, and suppress the
    // TextChanged that fires when a suggestion is accepted programmatically.
    private CancellationTokenSource? _filterSuggestCts;
    private bool _suppressFilterTextChanged;

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
        var vm = ViewModel;
        if (vm is null)
            return;

        if (e.Key is Key.Down or Key.Up)
        {
            if (!vm.IsFilterSuggestionOpen)
                return;
            MoveFilterHighlight(vm, e.Key == Key.Down ? 1 : -1);
            e.Handled = true;
            return;
        }

        bool hasHighlight = vm.IsFilterSuggestionOpen
            && vm.SelectedFilterSuggestionIndex >= 0
            && vm.SelectedFilterSuggestionIndex < vm.FilterSuggestions.Count;

        if ((e.Key == Key.Enter || e.Key == Key.Tab) && hasHighlight)
        {
            e.Handled = true;
            AcceptFilterSuggestion(vm.FilterSuggestions[vm.SelectedFilterSuggestionIndex]);
            return;
        }

        if (e.Key == Key.Escape)
        {
            if (vm.IsFilterSuggestionOpen)
            {
                vm.IsFilterSuggestionOpen = false;
                e.Handled = true;
            }
            return;
        }

        // Existing behaviour: Enter with the popup closed applies the filter.
        if (e.Key != Key.Enter)
            return;
        e.Handled = true;
        await vm.ApplyFilterCommand.ExecuteAsync(null);
    }

    private void OnFilterTextChanged(object? sender, TextChangedEventArgs e)
    {
        if (ViewModel is not { } vm || _suppressFilterTextChanged)
            return;

        _filterSuggestCts?.Cancel();
        _filterSuggestCts?.Dispose();
        var cts = new CancellationTokenSource();
        _filterSuggestCts = cts;
        _ = RefreshFilterSuggestionsDebouncedAsync(vm, cts.Token);
    }

    private async Task RefreshFilterSuggestionsDebouncedAsync(
        MainWindowViewModel vm, CancellationToken ct)
    {
        try
        {
            await Task.Delay(200, ct);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        if (ct.IsCancellationRequested)
            return;

        var (token, _, _) = GetFilterToken();
        if (!LooksLikeFieldNameToken(token))
        {
            vm.IsFilterSuggestionOpen = false;
            vm.FilterSuggestions.Clear();
            return;
        }

        try
        {
            await vm.UpdateFilterSuggestionsAsync(token, ct);
        }
        catch (OperationCanceledException)
        {
            // Superseded by a newer keystroke.
        }
        catch (Exception)
        {
            // Field-name lookup is best-effort: a tshark failure just leaves the popup closed.
        }
    }

    private void OnFilterSuggestionTapped(object? sender, TappedEventArgs e)
    {
        if (sender is ListBox { SelectedItem: string name })
        {
            AcceptFilterSuggestion(name);
            e.Handled = true;
        }
    }

    private void AcceptFilterSuggestion(string name)
    {
        if (ViewModel is not { } vm)
            return;

        var (_, tokenStart, tokenLength) = GetFilterToken();
        _suppressFilterTextChanged = true;
        try
        {
            vm.ApplyFilterSuggestion(name, tokenStart, tokenLength);
        }
        finally
        {
            _suppressFilterTextChanged = false;
        }

        FilterBox.CaretIndex = tokenStart + name.Length;
        FilterBox.Focus();
    }

    private (string Token, int Start, int Length) GetFilterToken()
    {
        string text = FilterBox.Text ?? string.Empty;
        int caret = Math.Clamp(FilterBox.CaretIndex, 0, text.Length);
        int start = caret;
        while (start > 0 && !IsFilterTokenBoundary(text[start - 1]))
            start--;
        return (text[start..caret], start, caret - start);
    }

    private static bool IsFilterTokenBoundary(char c) =>
        c is ' ' or '(' or ')' or '!' or '=' or '<' or '>' or '&' or '|' or ',';

    // Field names always start with a letter or underscore (pfcp.msg_type, _ws.col.Source).
    // A token like the "2" in "pfcp.msg_type == 2" is a numeric operand, not a field name,
    // so it must not keep the field-name autocomplete open.
    private static bool LooksLikeFieldNameToken(string token) =>
        token.Length > 0 && (char.IsLetter(token[0]) || token[0] == '_');

    private static void MoveFilterHighlight(MainWindowViewModel vm, int delta)
    {
        int count = vm.FilterSuggestions.Count;
        if (count == 0)
            return;

        int index = vm.SelectedFilterSuggestionIndex;
        index = index < 0 ? (delta > 0 ? 0 : count - 1) : index + delta;
        if (index < 0)
            index = count - 1;
        else if (index >= count)
            index = 0;

        vm.SelectedFilterSuggestionIndex = index;
    }
}
