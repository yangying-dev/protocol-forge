using System.Runtime.InteropServices;
using System.Text;

namespace ProtocolForge.Services;

/// <summary>
/// Optional BPF-backed L2 injection path for macOS (/dev/bpfN).
///
/// Mirrors <see cref="NpcapSendService"/>: probe device nodes, bind the
/// selected interface with BIOCSETIF, then write() complete Ethernet frames.
/// Requires root (opening /dev/bpf* is privileged by default). Every failure
/// returns null from <see cref="TryOpenRung"/> so the caller degrades to the
/// managed socket ladder. Never throws to the caller.
/// </summary>
public static class BpfSendService
{
    internal const int MaxDeviceCount = 255;
    private const int IfNameMax = 16;
    private const int O_RDWR = 0x0002;

    // macOS ioctl encodings: IOC_IN | (arglen << 16) | ('B' << 8) | command.
    private const int BiocSetIf = unchecked((int)0x8020426c);     // BIOCSETIF  (struct ifreq, 32B)
    private const int BiocShdrCmplt = unchecked((int)0x80044272); // BIOCSHDRCMPLT (u_int)

    /// <summary>
    /// Builds the 32-byte struct ifreq handed to BIOCSETIF: the ASCII
    /// interface name, NUL-terminated and truncated to ifname capacity so the
    /// final byte is always a terminator.
    /// </summary>
    public static byte[] BuildIfreq(string interfaceName)
    {
        var ifreq = new byte[32]; // char ifr_name[16] + sockaddr union
        if (!string.IsNullOrEmpty(interfaceName))
        {
            byte[] name = Encoding.ASCII.GetBytes(interfaceName);
            int copy = Math.Min(name.Length, IfNameMax - 1);
            Array.Copy(name, 0, ifreq, 0, copy);
        }
        return ifreq;
    }

    /// <summary>
    /// Opens the first free /dev/bpfN node and binds it to the interface.
    /// Returns null on any failure (no root, device busy, unknown interface).
    /// </summary>
    internal static BpfRung? TryOpenRung(NetworkInterfaceInfo info)
    {
        try
        {
            if (!OperatingSystem.IsMacOS()) return null;
            // Loopback (lo0) has no Ethernet framing — BPF cannot carry a
            // 14-byte-headered frame onto it, so let the IP/UDP rungs handle it.
            if (info.IsLoopback) return null;

            string basePath = "/dev/bpf";
            for (int i = 0; i < MaxDeviceCount; i++)
            {
                string device = basePath + i;
                int fd = _open(device, O_RDWR);
                if (fd < 0) continue;

                var rung = BindRung(fd, device, info.Name);
                if (rung != null) return rung;
                // Bind failure already closed fd; try the next device node.
            }
            return null;
        }
        catch (Exception ex)
        {
            TraceLog.Write($"BPF probe: disabled — {ex.Message}");
            return null;
        }
    }

    private static BpfRung? BindRung(int fd, string device, string interfaceName)
    {
        byte[] ifreq = BuildIfreq(interfaceName);
        IntPtr pb = Marshal.AllocHGlobal(ifreq.Length);
        try
        {
            Marshal.Copy(ifreq, 0, pb, ifreq.Length);
            if (_ioctl(fd, BiocSetIf, pb) != 0)
            {
                int errno = Marshal.GetLastWin32Error();
                TraceLog.Write($"BPF probe: bind {interfaceName} on {device} failed — {errno}");
                _close(fd);
                return null;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pb);
        }

        // Header-complete mode: leave our Ethernet header untouched. Default BPF
        // fills the interface's source MAC into every written frame, which would
        // undo the source-address rewrite PrepareFrame already performed.
        int headerComplete = 1;
        IntPtr pm = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            Marshal.WriteInt32(pm, headerComplete);
            _ioctl(fd, BiocShdrCmplt, pm); // best-effort; failure is non-fatal
        }
        finally
        {
            Marshal.FreeHGlobal(pm);
        }

        return new BpfRung(fd, device, interfaceName);
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int _open(string path, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int _ioctl(int fd, int request, IntPtr arg);

    [DllImport("libc", SetLastError = true)]
    private static extern int _close(int fd);
}

/// <summary>
/// An open BPF device bound to one macOS interface. Injects complete Ethernet
/// frames with write(); requires root to have opened the device.
/// </summary>
internal sealed class BpfRung : IL2SendRung
{
    private readonly int _fd;
    private bool _disposed;

    internal BpfRung(int fd, string deviceName, string interfaceName)
    {
        _fd = fd;
        DeviceName = $"{deviceName} ({interfaceName})";
    }

    /// <summary>BPF device node this rung sends on.</summary>
    public string DeviceName { get; }

    /// <summary>
    /// Writes one frame. A null result means this rung cannot deliver the
    /// packet — the caller descends to the next ladder rung as usual.
    /// </summary>
    public (PacketSendResult? Result, string? Error) TrySend(byte[] frame, int index, string interfaceName)
    {
        if (!NpcapSendService.CanSendFrame(frame))
            return (null, "Frame too short for BPF Ethernet injection");

        int written = _write(_fd, frame, frame.Length);
        if (written == frame.Length)
        {
            return (new PacketSendResult(index, true,
                $"Sent {frame.Length} bytes on {interfaceName} (bpf)"), null);
        }

        int errno = Marshal.GetLastWin32Error();
        string error = Marshal.PtrToStringAnsi(_strerror(errno)) ?? $"errno {errno}";
        return (null, $"BPF send failed: {error} ({errno})");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _close(_fd);
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int _write(int fd, byte[] buffer, int size);

    [DllImport("libc", SetLastError = true)]
    private static extern int _close(int fd);

    [DllImport("libc")]
    private static extern IntPtr _strerror(int errnum);
}