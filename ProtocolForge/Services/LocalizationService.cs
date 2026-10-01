using System.Globalization;
using System.Reflection;
using System.Text.Json;
using Avalonia;

namespace ProtocolForge.Services;

/// <summary>Supported UI languages.</summary>
public enum AppLanguage
{
    EnUs,
    ZhCn,
}

/// <summary>
/// Runtime-switchable dictionary localization. Single source of truth: the JSON
/// files under Assets/Lang (embedded as .NET manifest resources so both the GUI
/// host and the console verification harness can load them).
/// Fallback chain for any key: current language → en-US → the key itself.
/// </summary>
public sealed class LocalizationService
{
    private static LocalizationService? _current;
    private static LocalizationService? _defaultEnglish;

    /// <summary>Currently active service; null until <see cref="SetCurrent"/> is called.</summary>
    public static LocalizationService? Current => _current;

    /// <summary>The active language; EnUs when nothing has been set yet.</summary>
    public static AppLanguage CurrentLanguage => _current?.Language ?? AppLanguage.EnUs;

    private static readonly Dictionary<AppLanguage, LocalizationService> _instances = new();

    /// <summary>Returns the cached service for a language (never becomes <see cref="Current"/>).</summary>
    public static LocalizationService For(AppLanguage language)
    {
        lock (_instances)
        {
            if (!_instances.TryGetValue(language, out var svc))
                _instances[language] = svc = new LocalizationService(language);
            return svc;
        }
    }

    /// <summary>Fired after the active language has actually changed.</summary>
    public static event EventHandler? LanguageChanged;

    /// <summary>
    /// Switches the active language and raises <see cref="LanguageChanged"/>
    /// (no-op when already on that language).
    /// </summary>
    public static void SetCurrent(AppLanguage language)
    {
        if (_current?.Language == language)
            return;
        _current = new LocalizationService(language);
        ApplyToAvalonia();
        LanguageChanged?.Invoke(null, EventArgs.Empty);
    }

    /// <summary>
    /// Publishes every dictionary entry as an <c>L10n.&lt;key&gt;</c> resource so
    /// XAML can consume them via <c>{DynamicResource L10n.Key}</c>. No-op in a
    /// non-Avalonia host (e.g. the pf-verify console harness).
    /// </summary>
    public static void ApplyToAvalonia()
    {
        if (Application.Current is not { } app || _current is not { } svc)
            return;
        foreach (var (key, value) in svc._strings)
            app.Resources[$"L10n.{key}"] = value;
    }

    /// <summary>
    /// Determines the startup language from the current OS UI culture.
    /// </summary>
    public static AppLanguage DetectSystemLanguage()
        => CultureInfo.CurrentUICulture.Name.StartsWith("zh", StringComparison.OrdinalIgnoreCase)
            ? AppLanguage.ZhCn
            : AppLanguage.EnUs;

    /// <summary>
    /// Console-safe resolver: uses the active service when present, otherwise
    /// lazily loads the embedded English dictionary. Services that produce
    /// user-visible reasons call this so the text is localized at construction
    /// time without requiring DI wiring.
    /// </summary>
    public static string Resolve(string? key, params object?[]? args)
    {
        if (string.IsNullOrEmpty(key))
            return string.Empty;
        var svc = _current ?? (_defaultEnglish ??= new LocalizationService(AppLanguage.EnUs));
        return svc.Get(key, args);
    }

    public AppLanguage Language { get; }

    /// <summary>Immutable key→text snapshot of this language's dictionary.</summary>
    public IReadOnlyDictionary<string, string> Entries => _strings;

    private readonly IReadOnlyDictionary<string, string> _strings;

    public LocalizationService(AppLanguage language)
    {
        Language = language;
        _strings = Load(language);
    }

    /// <summary>Gets the current-language text for a key.</summary>
    public string Get(string key, params object?[]? args)
    {
        if (_strings.TryGetValue(key, out string? value))
            return args is { Length: > 0 } ? string.Format(value, args) : value;

        // Fall back to English (load lazily, never recursively on the zh instance itself).
        if (Language != AppLanguage.EnUs && !ReferenceEquals(_defaultEnglish, this))
        {
            var en = (_defaultEnglish ??= new LocalizationService(AppLanguage.EnUs));
            if (en._strings.TryGetValue(key, out value))
                return args is { Length: > 0 } ? string.Format(value, args) : value;
        }

        return args is { Length: > 0 } ? string.Format(key, args) : key;
    }

    /// <summary>Convenience indexer (no arguments).</summary>
    public string this[string key] => Get(key);

    /// <summary>Counts the {N} format placeholders in a value (used by the verify harness).
    /// Handles format specifiers like {0:X4} and alignment like {0,5}.</summary>
    public static int PlaceholderCount(string value)
    {
        int max = -1;
        for (int i = 0; i < value.Length; i++)
        {
            if (value[i] != '{')
                continue;
            int close = value.IndexOf('}', i + 1);
            if (close < 0)
                break;
            string inner = value.Substring(i + 1, close - i - 1);
            int k = 0;
            while (k < inner.Length && char.IsDigit(inner[k]))
                k++;
            if (k > 0 && int.TryParse(inner.Substring(0, k), out int idx))
                max = Math.Max(max, idx);
            i = close;
        }
        return max + 1;
    }

    private static IReadOnlyDictionary<string, string> Load(AppLanguage language)
    {
        string fileName = language == AppLanguage.ZhCn ? "zh-CN" : "en-US";
        string resource = $"ProtocolForge.Assets.Lang.{fileName}.json";
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource)
            ?? throw new InvalidOperationException($"Missing embedded resource: {resource}");
        using var reader = new StreamReader(stream);
        using var doc = JsonDocument.Parse(reader.ReadToEnd());

        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var prop in doc.RootElement.EnumerateObject())
            dict[prop.Name] = prop.Value.GetString() ?? "";
        return dict;
    }
}