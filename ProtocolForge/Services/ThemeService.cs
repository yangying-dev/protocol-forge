using Avalonia;
using Avalonia.Styling;

namespace ProtocolForge.Services;

/// <summary>
/// Runtime-switchable light/dark/system theme, mirroring <see cref="LocalizationService"/>:
/// a single static entry point that applies <see cref="Application.RequestedThemeVariant"/>
/// and raises <see cref="ThemeVariantChanged"/> when the choice actually changes.
/// Persistence is not done here — the composition root subscribes and writes the value
/// back through <see cref="TsharkSettingsService"/>, exactly like the UI language.
/// </summary>
public static class ThemeService
{
    public const string VariantDefault = "Default";
    public const string VariantLight = "Light";
    public const string VariantDark = "Dark";

    /// <summary>The active theme variant ("Default" / "Light" / "Dark"); Default until set.</summary>
    public static string CurrentVariant { get; private set; } = VariantDefault;

    /// <summary>Fired after the theme variant has actually changed.</summary>
    public static event EventHandler? ThemeVariantChanged;

    /// <summary>
    /// Applies a restored preference at startup without raising <see cref="ThemeVariantChanged"/>
    /// (subscriptions are wired afterwards, so the "system default" is never mis-saved as a
    /// user choice). Null/unknown values fall back to <see cref="VariantDefault"/>.
    /// </summary>
    public static void Initialize(string? savedVariant)
    {
        CurrentVariant = Normalize(savedVariant);
        ApplyToAvalonia();
    }

    /// <summary>
    /// Switches the active theme variant and raises <see cref="ThemeVariantChanged"/>
    /// (no-op when already on that variant).
    /// </summary>
    public static void SetVariant(string? variant)
    {
        var normalized = Normalize(variant);
        bool changed = !string.Equals(CurrentVariant, normalized, StringComparison.Ordinal);
        CurrentVariant = normalized;
        ApplyToAvalonia();
        if (changed)
            ThemeVariantChanged?.Invoke(null, EventArgs.Empty);
    }

    /// <summary>
    /// Pushes <see cref="CurrentVariant"/> onto the Avalonia application. No-op in a
    /// non-Avalonia host (e.g. the pf-verify console harness).
    /// </summary>
    public static void ApplyToAvalonia()
    {
        if (Application.Current is { } app)
            app.RequestedThemeVariant = ToThemeVariant(CurrentVariant);
    }

    private static string Normalize(string? variant)
    {
        if (string.Equals(variant, VariantLight, StringComparison.OrdinalIgnoreCase))
            return VariantLight;
        if (string.Equals(variant, VariantDark, StringComparison.OrdinalIgnoreCase))
            return VariantDark;
        return VariantDefault;
    }

    private static ThemeVariant ToThemeVariant(string variant) => variant switch
    {
        VariantLight => ThemeVariant.Light,
        VariantDark => ThemeVariant.Dark,
        _ => ThemeVariant.Default,
    };
}
