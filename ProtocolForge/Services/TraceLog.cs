namespace ProtocolForge;

public static class TraceLog
{
    public static string SupportDataDirectory { get; } = ResolveSupportDataDirectory();

    public static string LogDirectory => Path.Combine(SupportDataDirectory, "logs");

    public static string LogFilePath => Path.Combine(LogDirectory, "trace.log");

    public static void Write(string message)
    {
        System.Diagnostics.Trace.WriteLine(message);
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
