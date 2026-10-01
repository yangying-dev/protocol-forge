using System;
using Avalonia.Data.Converters;

namespace ProtocolForge.Converters;

/// <summary>
/// Converts a boolean to one of two string values.
/// trueValue: shown when true, falseValue: shown when false.
/// </summary>
public sealed class BoolToStringConverter : IValueConverter
{
    public string TrueValue { get; set; } = "True";
    public string FalseValue { get; set; } = "False";

    public object? Convert(object? value, Type targetType, object? parameter, System.Globalization.CultureInfo culture)
    {
        if (value is bool b)
            return b ? TrueValue : FalseValue;
        return FalseValue;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, System.Globalization.CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
