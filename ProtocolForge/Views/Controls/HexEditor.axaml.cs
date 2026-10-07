using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Threading;
using ProtocolForge.Models;
using ProtocolForge.Services;
using ProtocolForge.ViewModels;
using System.Collections.Specialized;

namespace ProtocolForge.Views.Controls;

/// <summary>
/// Custom hex editor control. Renders packet bytes in rows of 16 with
/// Wireshark-style visual grouping: offset | hex (grouped 8+8) | ASCII.
/// Supports dark field highlighting and auto-scroll to offset.
/// </summary>
public partial class HexEditor : UserControl
{
    private const int BytesPerRow = 16;
    private const double CellWidth = 30;
    private const double CellHeight = 24;
    private const double CellMargin = 1;
    private const double AsciiCellWidth = 11;
    private const double RowLabelWidth = 60;
    private const double ByteGroupGap = 14;

    private static readonly FontFamily MonospaceFont = new("Cascadia Code, JetBrains Mono, Consolas, 'Courier New', monospace");

    private HexEditorViewModel? _viewModel;
    private readonly List<HexRow> _rows = [];
    private ScrollViewer? _scrollViewer;
    private bool _rebuildQueued;

    private struct HexRow
    {
        public Border Container;
        public TextBlock Label;
        public Border[] HexCells;
        public TextBlock[] HexTexts;
        public Border[] AsciiCells;
        public TextBlock[] AsciiTexts;
        public int BaseOffset;
    }

    public HexEditor()
    {
        InitializeComponent();
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);

        if (_viewModel != null)
        {
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
            _viewModel.ScrollToOffsetRequested -= OnScrollToOffsetRequested;
            _viewModel.RefreshVisualRequested -= OnRefreshVisualRequested;
            if (_viewModel.Bytes is INotifyCollectionChanged oldCollection)
                oldCollection.CollectionChanged -= OnBytesCollectionChanged;
            LocalizationService.LanguageChanged -= OnLanguageChanged;
        }

        _viewModel = DataContext as HexEditorViewModel;

        if (_viewModel != null)
        {
            _viewModel.PropertyChanged += OnViewModelPropertyChanged;
            _viewModel.ScrollToOffsetRequested += OnScrollToOffsetRequested;
            _viewModel.RefreshVisualRequested += OnRefreshVisualRequested;
            if (_viewModel.Bytes is INotifyCollectionChanged newCollection)
                newCollection.CollectionChanged += OnBytesCollectionChanged;
            LocalizationService.LanguageChanged += OnLanguageChanged;

            RebuildRows();
        }
    }

    private void OnViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(HexEditorViewModel.Bytes)
            or nameof(HexEditorViewModel.RowCount)
            or nameof(HexEditorViewModel.IsEnabled))
        {
            TraceLog.Write($"VM prop changed: {e.PropertyName} -> schedule RebuildRows");
            ScheduleRebuild();
        }
    }

    private void OnBytesCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.Action != NotifyCollectionChangedAction.Add)
            TraceLog.Write($"Bytes collection changed: {e.Action} -> schedule RebuildRows");
        ScheduleRebuild();
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        // Only the empty-state label is built here; re-render it for the new language.
        if (_viewModel?.Bytes.Count == 0)
            ScheduleRebuild();
    }

    // Coalesce rebuild requests: a packet load fires dozens of collection
    // events (Clear + one Add per byte), and rebuilding the whole control for
    // each one saturates the UI thread. Keep at most one rebuild queued.
    private void ScheduleRebuild()
    {
        if (_rebuildQueued) return;
        _rebuildQueued = true;
        Dispatcher.UIThread.Post(() =>
        {
            _rebuildQueued = false;
            RebuildRows();
        }, DispatcherPriority.Background);
    }

    private void OnScrollToOffsetRequested(int offset)
    {
        TraceLog.Write($"ScrollToOffsetRequested({offset}) queued at Normal");
        Dispatcher.UIThread.Post(() => ScrollToOffset(offset));
    }

    private void OnRefreshVisualRequested()
    {
        Dispatcher.UIThread.Post(RefreshVisualState);
    }

    /// <summary>
    /// Scrolls the hex view so the row containing the given byte offset is visible.
    /// Places the target row near the top of the viewport for context.
    /// </summary>
    private void ScrollToOffset(int offset)
    {
        if (_scrollViewer == null)
        {
            TraceLog.Write($"ScrollToOffset({offset}) SKIP: _scrollViewer null");
            return;
        }

        int rowIndex = offset / BytesPerRow;
        double rowHeight = CellHeight + CellMargin * 2;
        double targetOffset = rowIndex * rowHeight - _scrollViewer.Viewport.Height * 0.25;
        if (targetOffset < 0) targetOffset = 0;
        _scrollViewer.Offset = new Vector(_scrollViewer.Offset.X, targetOffset);
        TraceLog.Write($"ScrollToOffset({offset}): row={rowIndex} vpHeight={_scrollViewer.Viewport.Height} target={targetOffset} finalY={_scrollViewer.Offset.Y}");
    }

    private void RebuildRows()
    {
        TraceLog.Write($"RebuildRows ENTER (bytes={_viewModel?.Bytes.Count} scrollWasNull={_scrollViewer == null})");
        var grid = HexContentGrid;
        grid.Children.Clear();
        _rows.Clear();
        var oldScrollHeight = _scrollViewer != null ? _scrollViewer.Offset.Y : -1;
        _scrollViewer = null;

        if (_viewModel?.Bytes.Count == 0)
        {
            grid.Children.Add(new TextBlock
            {
                Text = LocalizationService.Resolve("Hex.NoPacketSelected"),
                FontSize = 14,
                Foreground = Brushes.Gray,
                Margin = new Thickness(16, 12),
            });
            return;
        }

        var bytes = _viewModel!.Bytes;
        int totalBytes = bytes.Count;
        int totalRows = (totalBytes + BytesPerRow - 1) / BytesPerRow;

        var outerScroll = new ScrollViewer
        {
            Background = Brushes.White,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        };
        _scrollViewer = outerScroll;

        var outerStack = new StackPanel();

        for (int row = 0; row < totalRows; row++)
        {
            int baseOffset = row * BytesPerRow;
            int countInRow = Math.Min(BytesPerRow, totalBytes - baseOffset);

            var rowContainer = new Border
            {
                BorderThickness = new Thickness(0),
                BorderBrush = Brushes.Transparent,
                Padding = new Thickness(4, 0),
            };

            var rowPanel = new StackPanel
            {
                Orientation = Avalonia.Layout.Orientation.Horizontal,
                VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center,
            };

            // Offset label
            var label = new TextBlock
            {
                Text = $"{baseOffset:X8}",
                FontFamily = MonospaceFont,
                FontSize = 12,
                Width = RowLabelWidth,
                Foreground = new SolidColorBrush(Color.FromArgb(255, 100, 100, 100)),
                VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
            };
            rowPanel.Children.Add(label);

            // Hex cells: always lay out all 16 slots, even on the final partial row,
            // so the hex area width (and ASCII column start) never shifts between
            // rows. Slots past the row's real bytes are empty placeholder cells.
            var hexCells = new Border[countInRow];
            var hexTexts = new TextBlock[countInRow];

            for (int i = 0; i < BytesPerRow; i++)
            {
                if (i == 8)
                    rowPanel.Children.Add(new Border { Width = ByteGroupGap });

                if (i >= countInRow)
                {
                    rowPanel.Children.Add(new Border
                    {
                        Width = CellWidth,
                        Height = CellHeight,
                        Margin = new Thickness(CellMargin),
                    });
                    continue;
                }

                int byteIdx = baseOffset + i;
                var hexByte = bytes[byteIdx];
                int capturedIdx = byteIdx;

                var textBlock = new TextBlock
                {
                    Text = GetHexCellText(hexByte),
                    FontFamily = MonospaceFont,
                    FontSize = 13,
                    HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center,
                    VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center,
                };

                var cell = new Border
                {
                    Child = textBlock,
                    Width = CellWidth,
                    Height = CellHeight,
                    Margin = new Thickness(CellMargin),
                    CornerRadius = new CornerRadius(3),
                    Background = GetByteBackground(hexByte),
                    Cursor = new Cursor(StandardCursorType.Hand),
                    Focusable = true,
                };

                cell.PointerPressed += (_, _) =>
                {
                    if (_viewModel is { IsHexEditPending: true })
                        _ = _viewModel.CommitHexEditAsync();
                    _viewModel?.SelectByteAtOffset(capturedIdx);
                    cell.Focus();
                };

                cell.LostFocus += (_, _) =>
                {
                    if (_viewModel is { IsHexEditPending: true })
                        _ = _viewModel.CommitHexEditAsync();
                };

                cell.KeyDown += (_, args) => OnCellKeyDown(capturedIdx, args);

                hexCells[i] = cell;
                hexTexts[i] = textBlock;
                rowPanel.Children.Add(cell);
            }

            // Gap between hex and ASCII
            rowPanel.Children.Add(new Border { Width = 16 });

            // ASCII cells
            var asciiCells = new Border[countInRow];
            var asciiTexts = new TextBlock[countInRow];

            for (int i = 0; i < countInRow; i++)
            {
                int byteIdx = baseOffset + i;
                var hexByte = bytes[byteIdx];
                int capturedIdx = byteIdx;

                var textBlock = new TextBlock
                {
                    Text = GetAsciiCellText(hexByte),
                    FontFamily = MonospaceFont,
                    FontSize = 13,
                    HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center,
                    VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center,
                };

                var cell = new Border
                {
                    Child = textBlock,
                    Width = AsciiCellWidth,
                    Height = CellHeight,
                    Margin = new Thickness(CellMargin),
                    CornerRadius = new CornerRadius(2),
                    Background = Brushes.Transparent,
                    Cursor = new Cursor(StandardCursorType.Hand),
                    Focusable = true,
                };

                cell.PointerPressed += (_, _) =>
                {
                    if (_viewModel is { IsHexEditPending: true })
                        _ = _viewModel.CommitHexEditAsync();
                    _viewModel?.SelectByteAtOffset(capturedIdx);
                    cell.Focus();
                };

                cell.LostFocus += (_, _) =>
                {
                    if (_viewModel is { IsHexEditPending: true })
                        _ = _viewModel.CommitHexEditAsync();
                };

                cell.KeyDown += (_, args) => OnCellKeyDown(capturedIdx, args);

                asciiCells[i] = cell;
                asciiTexts[i] = textBlock;
                rowPanel.Children.Add(cell);
            }

            // Highlight alternating row backgrounds for readability
            if (row % 2 == 1)
                rowContainer.Background = new SolidColorBrush(Color.FromArgb(10, 0, 0, 0));

            rowContainer.Child = rowPanel;
            outerStack.Children.Add(rowContainer);

            _rows.Add(new HexRow
            {
                Container = rowContainer,
                Label = label,
                HexCells = hexCells,
                HexTexts = hexTexts,
                AsciiCells = asciiCells,
                AsciiTexts = asciiTexts,
                BaseOffset = baseOffset,
            });
        }

        outerScroll.Content = outerStack;
        grid.Children.Add(outerScroll);

        // Restore keyboard focus to the selected byte's cell ONLY when focus
        // was already inside the hex editor. Restoring unconditionally steals
        // focus from other controls; notably a GridSplitter cancels its drag
        // when it loses focus (Avalonia GridSplitter.OnLostFocus), which makes
        // the splitters seem dead after the hex view rebuilds.
        bool hadFocusInHex = IsKeyboardFocusWithin;
        if (hadFocusInHex && _viewModel?.SelectedByteOffset >= 0)
        {
            int rowIdx = _viewModel.SelectedByteOffset / BytesPerRow;
            int colIdx = _viewModel.SelectedByteOffset % BytesPerRow;
            if (rowIdx < _rows.Count && colIdx < _rows[rowIdx].HexCells.Length)
                Dispatcher.UIThread.Post(() => _rows[rowIdx].HexCells[colIdx].Focus());
        }
        TraceLog.Write($"RebuildRows EXIT (rows={_rows.Count} prevScrollY={oldScrollHeight} selectedOffset={_viewModel?.SelectedByteOffset ?? -1}) -> scroll reset to 0");
    }

    // ─── Per-Cell Keyboard Navigation + Hex Editing ───

    private void OnCellKeyDown(int offset, KeyEventArgs e)
    {
        if (_viewModel == null) return;

        bool isPending = _viewModel.IsHexEditPending;

        if (isPending)
        {
            switch (e.Key)
            {
                case Key.Enter:
                    _ = _viewModel.CommitHexEditAsync();
                    e.Handled = true;
                    return;
                case Key.Escape:
                    _viewModel.CancelHexEdit();
                    e.Handled = true;
                    return;
                case Key.Tab:
                    e.Handled = true;
                    return;
            }
        }
        else if (e.Key is Key.Escape or Key.Tab)
        {
            e.Handled = true;
            return;
        }

        if (e.Key is Key.Left or Key.Right or Key.Up or Key.Down)
        {
            if (isPending)
                _ = _viewModel.CommitHexEditAsync();
            MoveSelection(e.Key);
            e.Handled = true;
            return;
        }

        // Route hex digits (guarding against Ctrl/Alt shortcuts) into the
        // view model's pending edit run.
        if (TryGetHexKeyChar(e.Key, out char hexChar)
            && (e.KeyModifiers & (KeyModifiers.Control | KeyModifiers.Alt)) == 0)
        {
            _viewModel.HandleHexInput(hexChar);
            e.Handled = true;
        }
    }

    private void MoveSelection(Key key)
    {
        if (_viewModel == null) return;
        int current = _viewModel.SelectedByteOffset;
        if (current < 0) current = 0;

        int targetOffset = -1;
        switch (key)
        {
            case Key.Left:
                if (current > 0) targetOffset = current - 1;
                break;
            case Key.Right:
                if (current < _viewModel.Bytes.Count - 1) targetOffset = current + 1;
                break;
            case Key.Up:
                if (current >= BytesPerRow) targetOffset = current - BytesPerRow;
                break;
            case Key.Down:
                if (current < _viewModel.Bytes.Count - BytesPerRow) targetOffset = current + BytesPerRow;
                break;
        }

        if (targetOffset >= 0)
        {
            _viewModel.SelectByteAtOffset(targetOffset);
            FocusCellAtOffset(targetOffset);
        }
    }

    private static bool TryGetHexKeyChar(Key key, out char hexChar)
    {
        if (key is >= Key.D0 and <= Key.D9)
        {
            hexChar = (char)('0' + (key - Key.D0));
            return true;
        }
        if (key is >= Key.NumPad0 and <= Key.NumPad9)
        {
            hexChar = (char)('0' + (key - Key.NumPad0));
            return true;
        }
        if (key is >= Key.A and <= Key.F)
        {
            hexChar = (char)('a' + (key - Key.A));
            return true;
        }
        hexChar = '\0';
        return false;
    }

    private static string GetHexCellText(HexByte hexByte) =>
        hexByte.IsEditPending && hexByte.PendingHexText.Length > 0
            ? hexByte.PendingHexText
            : hexByte.HexValue;

    private static string GetAsciiCellText(HexByte hexByte) =>
        hexByte.IsEditPending ? hexByte.PendingAsciiText : hexByte.AsciiValue;

    /// <summary>
    /// Moves keyboard focus to the cell at the given byte offset.
    /// </summary>
    private void FocusCellAtOffset(int offset)
    {
        int rowIdx = offset / BytesPerRow;
        int colIdx = offset % BytesPerRow;
        
        if (rowIdx < _rows.Count && colIdx < _rows[rowIdx].HexCells.Length)
        {
            _rows[rowIdx].HexCells[colIdx].Focus();
        }
    }

    /// <summary>
    /// Refreshes all cell backgrounds to match current HexByte state.
    /// </summary>
    public void RefreshVisualState()
    {
        if (_viewModel == null) return;

        var bytes = _viewModel.Bytes;
        foreach (var row in _rows)
        {
            for (int i = 0; i < row.HexCells.Length; i++)
            {
                int byteIdx = row.BaseOffset + i;
                if (byteIdx < bytes.Count)
                {
                    var hexByte = bytes[byteIdx];
                    row.HexCells[i].Background = GetByteBackground(hexByte);
                    row.HexTexts[i].Text = GetHexCellText(hexByte);
                    row.AsciiTexts[i].Text = GetAsciiCellText(hexByte);
                    row.AsciiTexts[i].Foreground = hexByte.IsEditPending ? Brushes.Gray : Brushes.Black;
                }
            }
        }
    }

    /// <summary>
    /// Wireshark-style background colors.
    /// Selected bytes: dark blue
    /// Highlighted bytes: protocol-specific translucent color
    /// Edited bytes: light orange/red (same as Wireshark's modified marker)
    /// </summary>
    private static IBrush GetByteBackground(HexByte hexByte)
    {
        // Selected takes highest priority — dark blue like Wireshark
        if (hexByte.IsSelected)
            return new SolidColorBrush(Color.FromArgb(180, 50, 80, 180));

        // In-progress edit run — pending yellow sits above edited orange so the
        // user can see what is about to be committed before it lands.
        if (hexByte.IsEditPending)
            return new SolidColorBrush(Color.FromArgb(210, 255, 235, 120));

        // Highlighted field range
        if (hexByte.IsHighlighted && hexByte.HighlightColor != "Transparent")
        {
            if (TryParseColor(hexByte.HighlightColor, out var color))
                return new SolidColorBrush(color);
        }

        // Edited byte (user-modified) — light orange-red like Wireshark
        if (hexByte.IsEdited)
            return new SolidColorBrush(Color.FromArgb(120, 255, 180, 100));

        return Brushes.Transparent;
    }

    private static bool TryParseColor(string color, out Color result)
    {
        result = Colors.Transparent;
        if (color.StartsWith('#') && color.Length is 7 or 9)
        {
            result = Color.Parse(color);
            return true;
        }
        return false;
    }
}
