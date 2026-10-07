using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.VisualTree;
using System.Collections;

namespace ProtocolForge.Views.Controls;

/// <summary>
/// Wireshark-style column auto-fit: double-click a DataGrid column
/// separator to size the column to the widest content across all rows
/// (not just virtualized/realized rows). Single-click sorting and drag
/// resizing are left untouched.
/// </summary>
public class DoubleClickAutoFit
{
    private const double ResizeRegionWidth = 5.0;
    private const double FitBuffer = 2.0;
    private const int MaxScanItems = 50_000;

    public static readonly AttachedProperty<bool> IsEnabledProperty =
        AvaloniaProperty.RegisterAttached<DoubleClickAutoFit, DataGrid, bool>("IsEnabled");

    static DoubleClickAutoFit()
    {
        IsEnabledProperty.Changed.AddClassHandler<DataGrid>(OnIsEnabledChanged);
    }

    public static void SetIsEnabled(DataGrid grid, bool value) => grid.SetValue(IsEnabledProperty, value);

    public static bool GetIsEnabled(DataGrid grid) => grid.GetValue(IsEnabledProperty);

    private static void OnIsEnabledChanged(DataGrid grid, AvaloniaPropertyChangedEventArgs e)
    {
        if (e.NewValue is true)
        {
            grid.AddHandler(InputElement.DoubleTappedEvent, OnGridDoubleTapped);
        }
        else
        {
            grid.RemoveHandler(InputElement.DoubleTappedEvent, OnGridDoubleTapped);
        }
    }

    private static void OnGridDoubleTapped(object? sender, TappedEventArgs e)
    {
        var grid = sender as DataGrid;
        if (grid is null || grid.ItemsSource is not IEnumerable items || e.Source is not Visual source)
        {
            return;
        }

        var header = source as DataGridColumnHeader
                     ?? source.GetVisualAncestors().OfType<DataGridColumnHeader>().FirstOrDefault();
        if (header is null)
        {
            return;
        }

        var position = e.GetPosition(header);
        double fromRight = header.Bounds.Width - position.X;
        double fromLeft = position.X;
        var current = DataGridColumn.GetColumnContainingElement(header);

        DataGridColumn? column = fromRight <= ResizeRegionWidth
            ? current
            : fromLeft <= ResizeRegionWidth ? GetPreviousVisibleColumn(grid, current) : null;
        if (column is null || !grid.Columns.Contains(column))
        {
            return;
        }

        FitColumnToContent(grid, column, header);
    }

    private static DataGridColumn? GetPreviousVisibleColumn(DataGrid grid, DataGridColumn? current)
    {
        if (current is null)
        {
            return null;
        }

        var ordered = grid.Columns.Where(c => c.IsVisible).OrderBy(c => c.DisplayIndex).ToList();
        int index = ordered.IndexOf(current);
        return index > 0 ? ordered[index - 1] : null;
    }

    private static void FitColumnToContent(DataGrid grid, DataGridColumn column, DataGridColumnHeader header)
    {
        if (grid.ItemsSource is not IEnumerable items)
        {
            return;
        }

        double cellFont = grid.FontSize;
        FontFamily? cellFamily = grid.FontFamily;
        var realizedCell = grid.GetVisualDescendants().OfType<DataGridCell>().FirstOrDefault(c => c.FontSize > 0);
        if (realizedCell is not null)
        {
            cellFont = realizedCell.FontSize;
            cellFamily = realizedCell.FontFamily;
        }

        var scratch = new TextBlock { FontSize = cellFont, FontFamily = cellFamily };
        var seen = new HashSet<string>();
        double maxWidth = 0;
        int scanned = 0;

        if (column is DataGridBoundColumn bound && bound.Binding is Binding binding && !string.IsNullOrEmpty(binding.Path))
        {
            foreach (var item in items)
            {
                if (++scanned > MaxScanItems)
                {
                    break;
                }

                var text = ResolvePath(item, binding.Path)?.ToString();
                if (text is null || !seen.Add(text))
                {
                    continue;
                }

                scratch.Text = text;
                scratch.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                maxWidth = Math.Max(maxWidth, scratch.DesiredSize.Width);
            }
        }
        else if (column is DataGridTemplateColumn template && template.CellTemplate is not null)
        {
            foreach (var item in items)
            {
                if (++scanned > MaxScanItems)
                {
                    break;
                }

                if (template.CellTemplate.Build(item) is not Control content)
                {
                    continue;
                }

                content.DataContext = item;
                var textBlocks = content.GetVisualDescendants().OfType<TextBlock>().ToList();
                if (content is TextBlock cellRoot)
                {
                    textBlocks.Insert(0, cellRoot);
                }

                foreach (var textBlock in textBlocks)
                {
                    textBlock.FontSize = cellFont;
                    textBlock.FontFamily = cellFamily;
                    textBlock.TextWrapping = TextWrapping.NoWrap;
                }

                content.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                maxWidth = Math.Max(maxWidth, content.DesiredSize.Width);
            }
        }

        if (maxWidth <= 0)
        {
            return;
        }

        double headerWidth = header.DesiredSize.Width > 0 ? header.DesiredSize.Width : 0;
        column.Width = new DataGridLength(Math.Ceiling(Math.Max(maxWidth, headerWidth) + FitBuffer));
    }

    private static object? ResolvePath(object item, string path)
    {
        var current = item;
        foreach (var part in path.Split('.'))
        {
            var property = current.GetType().GetProperty(part);
            if (property is null)
            {
                return null;
            }

            current = property.GetValue(current);
            if (current is null)
            {
                return null;
            }
        }

        return current;
    }
}