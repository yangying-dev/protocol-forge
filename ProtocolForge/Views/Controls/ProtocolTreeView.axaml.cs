using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Avalonia.VisualTree;
using ProtocolForge.Models;
using ProtocolForge.Services;
using ProtocolForge.ViewModels;

namespace ProtocolForge.Views.Controls;

public partial class ProtocolTreeView : UserControl
{
    private const int MaxSelectAttempts = 4;

    private ProtocolTreeViewModel? _viewModel;
    private TopLevel? _hostRoot;
    private ProtocolField? _pendingSelect;
    private int _selectAttempt;

    public ProtocolTreeView()
    {
        InitializeComponent();

        ProtocolTree.AddHandler(PointerPressedEvent, OnTreePointerPressed, RoutingStrategies.Tunnel);
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);

        if (_viewModel != null)
            _viewModel.TreeSelectRequested -= OnTreeSelectRequested;

        _viewModel = DataContext as ProtocolTreeViewModel;

        if (_viewModel != null)
            _viewModel.TreeSelectRequested += OnTreeSelectRequested;
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        if (TopLevel.GetTopLevel(this) is TopLevel root)
        {
            _hostRoot = root;
            root.AddHandler(PointerPressedEvent, OnHostPointerPressed, RoutingStrategies.Tunnel);
        }
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        if (_hostRoot != null)
        {
            _hostRoot.RemoveHandler(PointerPressedEvent, OnHostPointerPressed);
            _hostRoot = null;
        }
    }

    private void OnHostPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (_viewModel?.IsEditingField == true && !IsInsideEditingTextBox(e.Source))
            _ = _viewModel.CommitFieldEditAsync();
    }

    private static bool IsInsideEditingTextBox(object? source)
    {
        var current = source as Control;
        while (current != null)
        {
            if (current is TextBox { DataContext: ProtocolField { IsEditing: true } })
                return true;
            current = current.GetVisualParent<Control>();
        }
        return false;
    }

    private void OnTreePointerPressed(object? sender, PointerPressedEventArgs e)
    {
        TraceLog.Write($"Tree.PointerPressed at ({e.GetPosition(this).X},{e.GetPosition(this).Y}) source={e.Source}");
        var source = e.Source as Control;
        if (source == null) return;

        // Walk up the visual tree to find the TreeViewItem that was clicked
        TreeViewItem? item = null;
        var current = source;
        while (current != null && item == null)
        {
            if (current is TreeViewItem tvi)
                item = tvi;
            current = current.GetVisualParent<Control>();
        }

        if (item?.DataContext is ProtocolLayer layer)
        {
            TraceLog.Write($"Tree.click -> LAYER {layer.ProtocolName}");
            if (layer.ParentPacket != null)
                _viewModel?.OnLayerClicked(layer.ParentPacket, layer);
        }
        else if (item?.DataContext is ProtocolField field)
        {
            TraceLog.Write($"Tree.click -> FIELD {field.Name} parentLayer={field.ParentLayer?.ProtocolName ?? "null"}");
            var packet = FindPacketForField(field);
            if (packet != null)
            {
                _viewModel?.OnFieldClicked(packet, field);

                // Double-click on an editable field opens its value editor.
                if (e.ClickCount >= 2)
                    _viewModel?.BeginFieldEdit(packet, field);
            }
            else
            {
                TraceLog.Write($"Tree.click -> FIELD {field.Name} SKIPPED (no ParentLayer)");
            }
        }
    }

    private void OnEditValueClicked(object? sender, RoutedEventArgs e)
    {
        if (sender is MenuItem { DataContext: ProtocolField field })
        {
            var packet = FindPacketForField(field);
            if (packet != null)
                _viewModel?.BeginFieldEdit(packet, field);
        }
    }

    private void OnEditKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            _ = _viewModel?.CommitFieldEditAsync();
            e.Handled = true;
        }
        else if (e.Key == Key.Escape)
        {
            _viewModel?.CancelFieldEdit();
            e.Handled = true;
        }
    }

    private void OnEditLostFocus(object? sender, RoutedEventArgs e)
    {
        _ = _viewModel?.CommitFieldEditAsync();
    }

    private static Packet? FindPacketForField(ProtocolField field)
    {
        return field.ParentLayer?.ParentPacket;
    }

    // ─── Hex → Tree reverse-sync (visual select, never rebuilds) ───

    private void OnTreeSelectRequested(ProtocolField field)
    {
        TraceLog.Write($"Tree.SelectFieldOnTree({field.Name})");
        _pendingSelect = field;
        _selectAttempt = 0;
        Dispatcher.UIThread.Post(() => TrySelectField(field), DispatcherPriority.Background);
    }

    /// <summary>
    /// Walks realized tree containers from the layer down to the target field,
    /// expanding ancestors as needed. Child containers materialize a layout pass
    /// after their parent expands, so a null container is retried a few times
    /// before giving up silently (selection is best-effort).
    /// </summary>
    private void TrySelectField(ProtocolField field)
    {
        if (_pendingSelect != field)
            return;

        var chain = BuildAncestorChain(field);
        if (chain.Count == 0)
        {
            _pendingSelect = null;
            return;
        }

        var layerContainer = ProtocolTree.TreeContainerFromItem(chain[0]);
        if (layerContainer is not TreeViewItem currentNode)
        {
            RetrySelect(field);
            return;
        }

        for (int i = 1; i < chain.Count; i++)
        {
            if (!currentNode.IsExpanded)
                currentNode.IsExpanded = true;

            var childContainer = currentNode.ContainerFromItem(chain[i]);
            if (childContainer is not TreeViewItem childNode)
            {
                RetrySelect(field);
                return;
            }
            currentNode = childNode;
        }

        currentNode.IsSelected = true;
        currentNode.BringIntoView();
        _pendingSelect = null;
        TraceLog.Write($"Tree.SelectFieldOnTree -> field selected at depth {chain.Count - 1}");
    }

    private void RetrySelect(ProtocolField field)
    {
        if (_pendingSelect != field)
            return;
        if (++_selectAttempt > MaxSelectAttempts)
        {
            _pendingSelect = null;
            TraceLog.Write($"Tree.SelectFieldOnTree({field.Name}) GAVE UP after {MaxSelectAttempts} attempts");
            return;
        }
        Dispatcher.UIThread.Post(() => TrySelectField(field), DispatcherPriority.Background);
    }

    /// <summary>
    /// Builds the chain of tree items (layer root first, field last) by walking
    /// the field's parent links. Returns an empty list when the field is not
    /// reachable from any layer.
    /// </summary>
    private static List<object> BuildAncestorChain(ProtocolField field)
    {
        var chain = new List<object>();
        ProtocolField? current = field;
        while (current != null)
        {
            chain.Add(current);
            current = current.ParentField;
        }

        var layer = field.ParentLayer;
        if (field.ParentField == null && layer == null)
            return [];

        chain.Add(layer ?? field.ParentField?.ParentLayer!);
        chain.Reverse();
        return chain;
    }
}
