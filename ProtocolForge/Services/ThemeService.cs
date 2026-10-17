using Avalonia;
using Avalonia.Styling;
using SukiUI;

namespace ProtocolForge.Services;

/// <summary>
/// Runtime-switchable theme on top of SukiUI: the base theme variant only
/// (system/light/dark) with a fixed SukiUI Blue colour skin, mirroring
/// <see cref="LocalizationService"/> — a single static entry point that pushes the
/// choice onto the Avalonia application and raises <see cref="ThemeVariantChanged"/>
/// when it actually changes. Persistence is not done here; the composition root
/// subscribes and writes the value back through <see cref="TsharkSettingsService"/>,
/// exactly like the UI language.
/// </summary>
public static class ThemeService
{
    public const string BaseDefault = "Default";
    public const string BaseLight = "Light";
    public const string BaseDark = "Dark";

    public static readonly IReadOnlyList<string> BaseKeys = [BaseDefault, BaseLight, BaseDark];

    public static string CurrentBase { get; private set; } = BaseDefault;

    public static string CurrentSerialized => CurrentBase;

    public static event EventHandler? ThemeVariantChanged;

    /// <summary>
    /// Applies a restored preference at startup without raising <see cref="ThemeVariantChanged"/>
    /// (subscriptions are wired afterwards, so the default is never mis-saved as a user choice).
    /// Null/unknown values fall back to Default; legacy custom-variant names from the
    /// pre-SukiUI build are mapped onto a base so upgrades keep a sensible look.
    /// </summary>
    public static void Initialize(string? saved)
    {
        CurrentBase = Parse(saved);
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

    /// <summary>
    /// Pushes the current base onto the SukiUI theme. No-op when no Avalonia
    /// application (or no <c>SukiTheme</c> in its styles) is present — e.g. the pf-verify
    /// console harness, which never loads App.axaml.
    /// </summary>
    public static void ApplyToAvalonia()
    {
        var app = Application.Current;
        if (app is null) return;
        if (app.Styles.OfType<SukiTheme>().FirstOrDefault() is not { } suki) return;

        suki.ChangeBaseTheme(ToThemeVariant(CurrentBase));
    }

    private static string Parse(string? saved)
    {
        if (string.IsNullOrWhiteSpace(saved))
            return BaseDefault;

        // Legacy values persisted by the pre-removal build are "Base|Color"
        // (e.g. "Dark|Blue"); only the base half is still meaningful.
        var basePart = saved.Split('|', 2)[0];

        return basePart.Trim().ToLowerInvariant() switch
        {
            "light" or "solaris" or "celadon" or "sakura" => BaseLight,
            "dark" or "midnight" or "aurora" or "nocturne" or "ember" or "graphite" => BaseDark,
            _ => BaseDefault,
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
