using System;
using System.Diagnostics;
using System.IO;
using Avalonia;

namespace ProtocolForge
{
    internal sealed class Program
    {
        // Initialization code. Don't use any Avalonia, third-party APIs or any
        // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
        // yet and stuff might break.
        [STAThread]
        public static void Main(string[] args)
        {
            AddFileTraceListener();
            RegisterCrashRecorders();
            BuildAvaloniaApp()
                .StartWithClassicDesktopLifetime(args);
        }

        // Trace output dies without a debugger; persist it for inspection.
        private static void AddFileTraceListener()
        {
            try
            {
                Directory.CreateDirectory(TraceLog.LogDirectory);
                var logPath = TraceLog.LogFilePath;
                TryRotateTraceLog(logPath);
                Trace.Listeners.Add(new TextWriterTraceListener(logPath));
                Trace.AutoFlush = true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Trace listener setup failed: {ex.Message}");
            }
        }

        // trace.log 启动轮转:超 2MB 级联备份成 trace.log.1/.2(保留最近 2 份);
        // 当前会话始终写 trace.log,客户发日志流程不变。
        private static void TryRotateTraceLog(string logPath)
        {
            try
            {
                const long maxBytes = 2L * 1024 * 1024;  // 2MB
                const int keepBackups = 2;                // trace.log.1 / trace.log.2

                if (!File.Exists(logPath))
                    return;
                if (new FileInfo(logPath).Length <= maxBytes)
                    return;

                for (int i = keepBackups; i >= 1; i--)
                {
                    string dst = $"{logPath}.{i}";
                    string src = i == 1 ? logPath : $"{logPath}.{i - 1}";
                    if (File.Exists(dst))
                        File.Delete(dst);
                    if (File.Exists(src))
                        File.Move(src, dst);
                }
            }
            catch (Exception ex)
            {
                // 轮转失败(如另一实例正占用文件)静默降级:沿用旧文件继续追加
                Debug.WriteLine($"Trace log rotation failed: {ex.Message}");
            }
        }

        // 兜底崩溃记录器:进程级未处理异常与未观察任务异常都写入 trace.log,
        // 供客户回传日志远程诊断;仅记录,不改变默认未观察异常语义。
        private static void RegisterCrashRecorders()
        {
            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
                TraceLog.Write($"Unhandled exception: {e.ExceptionObject}");
            TaskScheduler.UnobservedTaskException += (_, e) =>
                TraceLog.Write($"Unobserved task exception: {e.Exception}");
        }

        // Avalonia configuration, don't remove; also used by visual designer.
        public static AppBuilder BuildAvaloniaApp()
            => AppBuilder.Configure<App>()
                .UsePlatformDetect()
#if DEBUG
                .WithDeveloperTools()
#endif
                .WithInterFont()
                .LogToTrace();
    }
}
