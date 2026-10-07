using System.Diagnostics;

namespace ProtocolForge;

public static class TraceLog
{
    public static string SupportDataDirectory { get; } = ResolveSupportDataDirectory();

    public static string LogDirectory => Path.Combine(SupportDataDirectory, "logs");

    /// <summary>
    /// Log file for this instance: <c>trace.log</c> when alone (keeping the documented
    /// name and its rotation), <c>trace.&lt;pid&gt;.log</c> when siblings are running,
    /// because concurrent appends interleave and cannot be attributed. Two instances
    /// started in the same instant can both probe as alone — accepted, and equivalent to
    /// the previous behaviour.
    /// </summary>
    public static string LogFilePath { get; } = ResolveLogFilePath();

    public static void Write(string message)
    {
        Trace.WriteLine(message);
    }

    private static string ResolveLogFilePath()
    {
        string shared = Path.Combine(LogDirectory, "trace.log");
        return OtherInstancesRunning()
            ? Path.Combine(LogDirectory, $"trace.{Environment.ProcessId}.log")
            : shared;
    }

    private static bool OtherInstancesRunning()
    {
        try
        {
            using Process self = Process.GetCurrentProcess();
            Process[] peers = Process.GetProcessesByName(self.ProcessName);

            int live = 0;
            foreach (Process peer in peers)
            {
                try
                {
                    if (!peer.HasExited)
                        live++;
                }
                catch
                {
                    // The peer exited between enumeration and inspection.
                }
                finally
                {
                    peer.Dispose();
                }
            }

            // > 1 counts this process, so any other live instance means we are not alone.
            return live > 1;
        }
        catch (Exception ex)
        {
            // Probing is best-effort: if it fails, keep the documented single-file name
            // rather than inventing a per-PID path the user was never told to look for.
            Trace.WriteLine($"Could not probe for sibling instances: {ex.Message}");
            return false;
        }
    }

    private static string ResolveSupportDataDirectory()
    {
        string baseDirectory = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData,
            Environment.SpecialFolderOption.Create);
        if (string.IsNullOrWhiteSpace(baseDirectory))
        {
            baseDirectory = Environment.GetFolderPath(
                Environment.SpecialFolder.ApplicationData,
                Environment.SpecialFolderOption.Create);
        }
        if (string.IsNullOrWhiteSpace(baseDirectory))
            baseDirectory = Path.GetTempPath();
        return Path.Combine(baseDirectory, "ProtocolForge");
    }
}