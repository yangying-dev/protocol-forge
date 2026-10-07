using System.Text.Json;

namespace ProtocolForge.Services;

/// <summary>
/// Persists user-level settings (tshark executable path, optional TLS keylog
/// file) to a JSON file in the user's app data directory.
/// </summary>
public sealed class TsharkSettingsService
{
    private readonly string _configPath;

    public TsharkSettingsService()
    {
        var baseDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "ProtocolForge");
        Directory.CreateDirectory(baseDir);
        _configPath = Path.Combine(baseDir, "settings.json");
    }

    public string? LoadTsharkPath()
    {
        try
        {
            if (File.Exists(_configPath))
            {
                var json = File.ReadAllText(_configPath);
                var settings = JsonSerializer.Deserialize<TsharkSettings>(json);
                if (settings != null && !string.IsNullOrWhiteSpace(settings.TsharkPath))
                    return settings.TsharkPath;
            }
        }
        catch { /* corrupt config — use defaults */ }
        return null;
    }

    public void SaveTsharkPath(string? path)
    {
        try
        {
            var settings = LoadAll();
            settings.TsharkPath = path;
            SaveAll(settings);
        }
        catch { /* silently fail — settings save is non-critical */ }
    }

    public string? LoadTlsKeylogPath()
    {
        try
        {
            if (File.Exists(_configPath))
            {
                var json = File.ReadAllText(_configPath);
                var settings = JsonSerializer.Deserialize<TsharkSettings>(json);
                if (settings != null && !string.IsNullOrWhiteSpace(settings.TlsKeylogPath))
                    return settings.TlsKeylogPath;
            }
        }
        catch { /* corrupt config — use defaults */ }
        return null;
    }

    public void SaveTlsKeylogPath(string? path)
    {
        try
        {
            var settings = LoadAll();
            settings.TlsKeylogPath = path;
            SaveAll(settings);
        }
        catch { /* silently fail — settings save is non-critical */ }
    }

    public string? LoadLanguage()
    {
        try
        {
            if (File.Exists(_configPath))
            {
                var json = File.ReadAllText(_configPath);
                var settings = JsonSerializer.Deserialize<TsharkSettings>(json);
                if (settings != null && !string.IsNullOrWhiteSpace(settings.Language))
                    return settings.Language;
            }
        }
        catch { /* corrupt config — use defaults */ }
        return null;
    }

    public void SaveLanguage(string? language)
    {
        try
        {
            var settings = LoadAll();
            settings.Language = language;
            SaveAll(settings);
        }
        catch { /* silently fail — settings save is non-critical */ }
    }

    private TsharkSettings LoadAll()
    {
        try
        {
            if (File.Exists(_configPath))
            {
                var json = File.ReadAllText(_configPath);
                var settings = JsonSerializer.Deserialize<TsharkSettings>(json);
                if (settings != null)
                    return settings;
            }
        }
        catch { /* fall through to fresh defaults */ }
        return new TsharkSettings();
    }

    private void SaveAll(TsharkSettings settings)
    {
        var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_configPath, json);
    }

    private sealed class TsharkSettings
    {
        public string? TsharkPath { get; set; }
        public string? TlsKeylogPath { get; set; }
        public string? Language { get; set; }
    }
}
