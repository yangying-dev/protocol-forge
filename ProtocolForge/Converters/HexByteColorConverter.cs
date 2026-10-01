using Avalonia.Data.Converters;
using Avalonia.Media;
using System.Globalization;

namespace ProtocolForge.Converters;

/// <summary>
/// Converts a HexByte's highlight/selection state into a background brush.
/// Selection overrides highlight; unselected/highlighted uses the field color;
/// default is transparent.
/// </summary>
public sealed class HexByteBackgroundConverter : IValueConverter
{
    private static readonly SolidColorBrush SelectionBrush = new(Color.FromArgb(80, 0, 120, 215));
    private static readonly SolidColorBrush ModifiedBrush = new(Color.FromArgb(60, 255, 200, 0));

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        // Expecting a tuple or composite value — we'll use multi-binding in the control instead
        throw new NotSupportedException("Use HexByteMultiConverter instead.");
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Multi-value converter: [IsSelected, IsHighlighted, HighlightColor, IsModified]
/// Returns appropriate background brush.
/// </summary>
public sealed class HexByteMultiConverter : IMultiValueConverter
{
    private static readonly SolidColorBrush SelectionBrush = new(Color.FromArgb(90, 0, 120, 215));
    private static readonly SolidColorBrush ModifiedBrush = new(Color.FromArgb(70, 255, 200, 0));

    public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
    {
        if (values.Count < 4)
            return Brushes.Transparent;

        bool isSelected = values[0] is true;
        bool isHighlighted = values[1] is true;
        string? highlightColor = values[2] as string;
        bool isModified = values[3] is true;

        // Priority: selected > modified > highlighted > default
        if (isSelected)
            return SelectionBrush;

        if (isModified)
            return ModifiedBrush;

        if (isHighlighted && !string.IsNullOrEmpty(highlightColor) && highlightColor != "Transparent")
        {
            if (TryParseColor(highlightColor, out var color))
                return new SolidColorBrush(color);
        }

        return Brushes.Transparent;
    }

    public object[] ConvertBack(object? value, Type[] targetTypes, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();

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

/// <summary>
/// Maps a boolean to opacity (true = 1.0, false = 0.3) for disabled visual state.
/// </summary>
public sealed class EnabledToOpacityConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is true ? 1.0 : 0.35;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Inverts a boolean value.
/// </summary>
public sealed class InverseBoolConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is bool b ? !b : value;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is bool b ? !b : value;
}

/// <summary>
/// Converts a byte count to a human-readable size string.
/// </summary>
public sealed class ByteCountConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not int bytes)
            return "0 B";

        return bytes switch
        {
            < 1024 => $"{bytes} B",
            < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
            _ => $"{bytes / (1024.0 * 1024.0):F1} MB",
        };
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
