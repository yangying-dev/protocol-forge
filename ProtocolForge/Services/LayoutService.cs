using System.Text.Json;

namespace ProtocolForge.Services;

/// <summary>
/// Saves and restores window layout state (splitter positions, panel visibility, window geometry)
/// to a JSON file in the user's app data directory.
/// </summary>
public sealed class LayoutService
{
    private readonly string _configPath;
    private readonly string _dockConfigPath;

    public LayoutService()
    {
        var baseDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "ProtocolForge");
        Directory.CreateDirectory(baseDir);
        _configPath = Path.Combine(baseDir, "layout.json");
        _dockConfigPath = Path.Combine(baseDir, "docklayout.json");
    }

    public LayoutState Load()
    {
        try
        {
            if (File.Exists(_configPath))
            {
                var json = File.ReadAllText(_configPath);
                return JsonSerializer.Deserialize<LayoutState>(json) ?? new LayoutState();
            }
        }
        catch { /* corrupt config — use defaults */ }
        return new LayoutState();
    }

    public void Save(LayoutState state)
    {
        try
        {
            var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_configPath, json);
        }
        catch { /* silently fail — layout save is non-critical */ }
    }

    /// <summary>上次保存的 Dock 停靠布局 JSON;损坏或从未保存过返回 null(调用方回退默认布局)。</summary>
    public string? LoadDockLayout()
    {
        try
        {
            if (File.Exists(_dockConfigPath))
                return File.ReadAllText(_dockConfigPath);
        }
        catch { /* corrupt config — fall back to the default layout */ }
        return null;
    }

    public void SaveDockLayout(string json)
    {
        try
        {
            File.WriteAllText(_dockConfigPath, json);
        }
        catch { /* silently fail — dock layout save is non-critical */ }
    }
}

public sealed class LayoutState
{
    /// <summary>Ratio of the top (packet list) row height to total content area (0.0–1.0).</summary>
    public double TopRowRatio { get; set; } = 0.35;

    /// <summary>Ratio of the bottom-left (protocol tree) column width to bottom area (0.0–1.0).</summary>
    public double BottomLeftRatio { get; set; } = 0.50;

    // Window geometry
    public double WindowX { get; set; } = -1;
    public double WindowY { get; set; } = -1;
    public double WindowWidth { get; set; } = 1200;
    public double WindowHeight { get; set; } = 800;
    public int WindowState { get; set; } = 0; // 0=Normal, 1=Maximized

    // Panel visibility
    public bool ShowPacketList { get; set; } = true;
    public bool ShowProtocolTree { get; set; } = true;
    public bool ShowHexEditor { get; set; } = true;
}
