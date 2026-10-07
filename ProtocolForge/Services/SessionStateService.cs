using System.Text.Json;

namespace ProtocolForge.Services;

/// <summary>
/// Persists the small amount of state that makes reopening the app useful: the recent
/// capture list and which of them was open. Only file paths are stored: no packet
/// bytes, and nothing from the capture's contents.
/// </summary>
public sealed class SessionStateService
{
    public const int MaxRecentFiles = 10;

    private readonly string _path;
    private readonly object _gate = new();
    private SessionState _state = new();

    public SessionStateService()
    {
        _path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "ProtocolForge", "session.json");
        Load();
    }

    public IReadOnlyList<string> RecentFiles => _state.RecentFiles;

    public string? LastOpenedFile => _state.LastOpenedFile;

    /// <summary>
    /// Records a capture as most-recently-used. The path is stored as given; callers
    /// pass a full path. Failures are swallowed because a session file is a convenience,
    /// not state the app cannot run without.
    /// </summary>
    public void NoteOpened(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return;

        lock (_gate)
        {
            var kept = _state.RecentFiles
                .Where(p => !string.Equals(p, filePath, StringComparison.OrdinalIgnoreCase))
                .ToList();
            kept.Insert(0, filePath);
            _state.RecentFiles = kept.Take(MaxRecentFiles).ToList();
            _state.LastOpenedFile = filePath;
            Save();
        }
    }

    public void RemoveRecent(string filePath)
    {
        lock (_gate)
        {
            _state.RecentFiles = _state.RecentFiles
                .Where(p => !string.Equals(p, filePath, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (string.Equals(_state.LastOpenedFile, filePath, StringComparison.OrdinalIgnoreCase))
                _state.LastOpenedFile = _state.RecentFiles.FirstOrDefault();
            Save();
        }
    }

    public void ClearRecent()
    {
        lock (_gate)
        {
            _state.RecentFiles = [];
            Save();
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_path))
                return;
            var loaded = JsonSerializer.Deserialize<SessionState>(File.ReadAllText(_path));
            if (loaded is not null)
                _state = loaded;
        }
        catch (Exception)
        {
            // Fail open to an empty session: a corrupt convenience file must not stop
            // the app from opening.
            _state = new SessionState();
        }
    }

    private void Save()
    {
        try
        {
            string? dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            File.WriteAllText(_path, JsonSerializer.Serialize(_state));
        }
        catch (Exception)
        {
            // Same reasoning as Load: session persistence is never load-bearing.
        }
    }

    private sealed class SessionState
    {
        public List<string> RecentFiles { get; set; } = [];
        public string? LastOpenedFile { get; set; }
    }
}
