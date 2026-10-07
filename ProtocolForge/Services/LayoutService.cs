using System.Text.Json;

namespace ProtocolForge.Services;

/// <summary>
/// Saves and restores window layout state (splitter positions, panel visibility, window geometry)
/// to a JSON file in the user's app data directory.
/// </summary>
public sealed class LayoutService
{
    private readonly string _configPath;

    public LayoutService()
    {
        var baseDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "ProtocolForge");
        Directory.CreateDirectory(baseDir);
        _configPath = Path.Combine(baseDir, "layout.json");
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
