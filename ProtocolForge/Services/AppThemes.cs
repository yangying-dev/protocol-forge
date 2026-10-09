using System;
using System.Collections.Generic;
using Avalonia.Styling;

namespace ProtocolForge.Services;

/// <summary>
/// 每个自研主题继承 Light/Dark:主题字典未覆盖的框架资源(FluentTheme /
/// DockFluentTheme / DataGrid)自动回退到父变体,新增主题只需提供 <c>Pf*</c> 令牌。
/// </summary>
public static class AppThemes
{
    public const string System = "Default";
    public const string Light = "Light";
    public const string Dark = "Dark";
    public const string Midnight = "Midnight";
    public const string Aurora = "Aurora";
    public const string Nocturne = "Nocturne";
    public const string Ember = "Ember";
    public const string Graphite = "Graphite";
    public const string Solaris = "Solaris";
    public const string Celadon = "Celadon";
    public const string Sakura = "Sakura";

    public static readonly ThemeVariant MidnightVariant = new(Midnight, ThemeVariant.Dark);
    public static readonly ThemeVariant AuroraVariant = new(Aurora, ThemeVariant.Dark);
    public static readonly ThemeVariant NocturneVariant = new(Nocturne, ThemeVariant.Dark);
    public static readonly ThemeVariant EmberVariant = new(Ember, ThemeVariant.Dark);
    public static readonly ThemeVariant GraphiteVariant = new(Graphite, ThemeVariant.Dark);
    public static readonly ThemeVariant SolarisVariant = new(Solaris, ThemeVariant.Light);
    public static readonly ThemeVariant CeladonVariant = new(Celadon, ThemeVariant.Light);
    public static readonly ThemeVariant SakuraVariant = new(Sakura, ThemeVariant.Light);

    /// <summary>菜单展示顺序,也是持久化值的合法取值集合。</summary>
    public static readonly IReadOnlyList<string> OrderedKeys =
    [
        System, Light, Dark,
        Midnight, Aurora, Nocturne, Ember, Graphite,
        Solaris, Celadon, Sakura,
    ];

    public static bool TryCanonical(string? key, out string canonical)
    {
        foreach (var candidate in OrderedKeys)
        {
            if (string.Equals(candidate, key, StringComparison.OrdinalIgnoreCase))
            {
                canonical = candidate;
                return true;
            }
        }

        canonical = System;
        return false;
    }

    public static ThemeVariant ToVariant(string? key) => key switch
    {
        Light => ThemeVariant.Light,
        Dark => ThemeVariant.Dark,
        Midnight => MidnightVariant,
        Aurora => AuroraVariant,
        Nocturne => NocturneVariant,
        Ember => EmberVariant,
        Graphite => GraphiteVariant,
        Solaris => SolarisVariant,
        Celadon => CeladonVariant,
        Sakura => SakuraVariant,
        _ => ThemeVariant.Default,
    };
}
