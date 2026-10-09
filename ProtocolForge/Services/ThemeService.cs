using Avalonia;
using Avalonia.Styling;
using SukiUI;
using SukiUI.Enums;

namespace ProtocolForge.Services;

/// <summary>
/// Runtime-switchable theme on top of SukiUI: a base variant (system/light/dark)
/// plus a built-in colour skin, mirroring <see cref="LocalizationService"/> — a single
/// static entry point that pushes the choice onto the Avalonia application and raises
/// <see cref="ThemeVariantChanged"/> when it actually changes. Persistence is not done
/// here; the composition root subscribes and writes the value back through
/// <see cref="TsharkSettingsService"/>, exactly like the UI language.
/// </summary>
public static class ThemeService
{
    public const string BaseDefault = "Default";
    public const string BaseLight = "Light";
    public const string BaseDark = "Dark";

    public static readonly IReadOnlyList<string> BaseKeys = [BaseDefault, BaseLight, BaseDark];
    public static readonly IReadOnlyList<string> ColorKeys = ["Blue", "Green", "Red", "Orange"];

    public static string CurrentBase { get; private set; } = BaseDefault;

    public static string CurrentColor { get; private set; } = "Blue";

    public static string CurrentSerialized => $"{CurrentBase}|{CurrentColor}";

    public static event EventHandler? ThemeVariantChanged;

    /// <summary>
    /// Applies a restored preference at startup without raising <see cref="ThemeVariantChanged"/>
    /// (subscriptions are wired afterwards, so the default is never mis-saved as a user choice).
    /// Null/unknown values fall back to Default|Blue; legacy custom-variant names from the
    /// pre-SukiUI build are mapped onto a base + colour so upgrades keep a sensible look.
    /// </summary>
    public static void Initialize(string? saved)
    {
        (CurrentBase, CurrentColor) = Parse(saved);
        ApplyToAvalonia();
    }

    public static void SetBase(string? baseKey)
    {
        if (!TryCanonical(BaseKeys, baseKey, out string canonical)) return;
        bool changed = !string.Equals(CurrentBase, canonical, StringComparison.Ordinal);
        CurrentBase = canonical;
        ApplyToAvalonia();
        if (changed) ThemeVariantChanged?.Invoke(null, EventArgs.Empty);
    }

    public static void SetColor(string? colorKey)
    {
        if (!TryCanonical(ColorKeys, colorKey, out string canonical)) return;
        bool changed = !string.Equals(CurrentColor, canonical, StringComparison.Ordinal);
        CurrentColor = canonical;
        ApplyToAvalonia();
        if (changed) ThemeVariantChanged?.Invoke(null, EventArgs.Empty);
    }

    /// <summary>
    /// Pushes the current base + colour onto the SukiUI theme. No-op when no Avalonia
    /// application (or no <c>SukiTheme</c> in its styles) is present — e.g. the pf-verify
    /// console harness, which never loads App.axaml.
    /// </summary>
    public static void ApplyToAvalonia()
    {
        var app = Application.Current;
        if (app is null) return;
        if (app.Styles.OfType<SukiTheme>().FirstOrDefault() is not { } suki) return;

        suki.ChangeBaseTheme(ToThemeVariant(CurrentBase));
        if (Enum.TryParse<SukiColor>(CurrentColor, ignoreCase: true, out var color))
            suki.ChangeColorTheme(color);
    }

    private static (string Base, string Color) Parse(string? saved)
    {
        if (string.IsNullOrWhiteSpace(saved))
            return (BaseDefault, "Blue");

        var parts = saved.Split('|', 2);
        if (parts.Length == 2)
        {
            return (
                TryCanonical(BaseKeys, parts[0], out var b) ? b : BaseDefault,
                TryCanonical(ColorKeys, parts[1], out var c) ? c : "Blue");
        }

        return parts[0].Trim().ToLowerInvariant() switch
        {
            "light" or "solaris" or "celadon" or "sakura" => (BaseLight, "Blue"),
            "dark" or "midnight" or "aurora" or "nocturne" or "ember" or "graphite" => (BaseDark, "Blue"),
            _ => (BaseDefault, "Blue"),
        };
    }

    private static bool TryCanonical(IReadOnlyList<string> keys, string? key, out string canonical)
    {
        foreach (var candidate in keys)
        {
            if (string.Equals(candidate, key, StringComparison.OrdinalIgnoreCase))
            {
                canonical = candidate;
                return true;
            }
        }

        canonical = keys[0];
        return false;
    }

    private static ThemeVariant ToThemeVariant(string baseKey) => baseKey switch
    {
        BaseLight => ThemeVariant.Light,
        BaseDark => ThemeVariant.Dark,
        _ => ThemeVariant.Default,
    };
}
