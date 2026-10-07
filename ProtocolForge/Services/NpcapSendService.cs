using System.Runtime.InteropServices;

namespace ProtocolForge.Services;

/// <summary>
/// Optional Npcap-backed L2 injection path for Windows.
///
/// Npcap is never bundled or redistributed: this service only probes the
/// user-installed wpcap.dll (free SDK use per Npcap's license terms) and opens
/// a raw capture handle with pcap_open_live. Every failure — missing DLL,
/// load/export error, no matching device, access denied — returns null from
/// <see cref="TryOpenRung"/>, so the caller silently degrades to the managed
/// socket ladder. The probe never throws and never blocks startup: it runs
/// once per send session.
/// </summary>
public static class NpcapSendService
{
    private const int ErrBufSize = 256;
    private const int SnapshotLength = 65536;
    private const int ReadTimeoutMs = 1000;

    private static readonly object ApiLock = new();
    private static IntPtr _dllHandle;
    private static LoadedApi? _api;

    // ─── Pure probe logic (unit-testable without Npcap) ───

    /// <summary>
    /// Resolves the Npcap wpcap.dll path under a given system directory and
    /// verifies the file exists. Callers pass the process-bitness system
    /// directory — normally <c>Environment.GetFolderPath(SpecialFolder.System)</c>,
    /// which Windows redirects to SysWOW64 for 32-bit processes automatically.
    /// Returns null when Npcap is not installed.
    /// </summary>
    public static string? ResolveWpcapPath(string systemDirectory)
    {
        try
        {
            string candidate = Path.Combine(systemDirectory, "Npcap", "wpcap.dll");
            return File.Exists(candidate) ? candidate : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// True when the bytes are long enough to form a complete Ethernet frame
    /// (14-byte header). Npcap injects whole frames as-is, so anything shorter
    /// (a bare IP datagram) must descend to the IP/UDP rungs instead.
    /// </summary>
    public static bool CanSendFrame(byte[] data) => data.Length >= 14;

    /// <summary>
    /// Matches an Npcap device name ("\Device\NPF_{GUID}") against the managed
    /// <see cref="NetworkInterfaceInfo.Id"/>. Windows adapter Ids carry the same
    /// GUID as the NPF device, with or without the surrounding braces.
    /// </summary>
    public static bool DeviceMatchesIdentifier(string npfDeviceName, string interfaceId)
    {
        const string Prefix = """\Device\NPF_""";
        if (!npfDeviceName.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            return false;

        string npfGuid = StripOuterBraces(npfDeviceName[Prefix.Length..].Trim());
        return string.Equals(npfGuid, StripOuterBraces(interfaceId.Trim()), StringComparison.OrdinalIgnoreCase);
    }

    private static string StripOuterBraces(string value)
    {
        int openBrace = value.IndexOf('{');
        int closeBrace = value.LastIndexOf('}');
        return openBrace >= 0 && closeBrace > openBrace
            ? value[(openBrace + 1)..closeBrace]
            : value;
    }

    // ─── Native API surface (cdecl, Npcap exports) ───

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int FindAllDevsDelegate(out IntPtr alldevs, IntPtr errbuf);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void FreeAllDevsDelegate(IntPtr alldevs);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate IntPtr OpenLiveDelegate(
        [MarshalAs(UnmanagedType.LPStr)] string device, int snaplen, int promisc, int toMs, IntPtr errbuf);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int SendPacketDelegate(IntPtr handle, byte[] buffer, int size);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate IntPtr GetErrDelegate(IntPtr handle);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void CloseDelegate(IntPtr handle);

    /// <summary>Tightly bound set of resolved wpcap.dll entry points.</summary>
    internal sealed class LoadedApi
    {
        internal LoadedApi(
            FindAllDevsDelegate findAlldevs,
            FreeAllDevsDelegate freeAlldevs,
            OpenLiveDelegate openLive,
            SendPacketDelegate sendPacket,
            GetErrDelegate getErr,
            CloseDelegate close)
        {
            FindAllDevs = findAlldevs;
            FreeAllDevs = freeAlldevs;
            OpenLive = openLive;
            SendPacket = sendPacket;
            GetErr = getErr;
            Close = close;
        }

        internal FindAllDevsDelegate FindAllDevs { get; }
        internal FreeAllDevsDelegate FreeAllDevs { get; }
        internal OpenLiveDelegate OpenLive { get; }
        internal SendPacketDelegate SendPacket { get; }
        internal GetErrDelegate GetErr { get; }
        internal CloseDelegate Close { get; }
    }

    // ─── Probe + rung factory ───

    /// <summary>
    /// Opens an Npcap rung bound to the selected interface, or returns null
    /// when Npcap is unavailable (not installed, access denied, no device
    /// match). A null result is a normal condition that selects the managed
    /// socket ladder — it is never reported as an error.
    /// </summary>
    internal static NpcapRung? TryOpenRung(NetworkInterfaceInfo info)
    {
        try
        {
            var api = GetApi();
            if (api == null) return null;

            IntPtr errbuf = Marshal.AllocHGlobal(ErrBufSize);
            try
            {
                string? deviceName = FindMatchingDevice(api, info, errbuf);
                if (deviceName == null) return null;

                // Opens a send-capable handle; promiscuous mode is off (we only
                // inject) and the read timeout only matters for capture callbacks.
                IntPtr handle = api.OpenLive(deviceName, SnapshotLength, 0, ReadTimeoutMs, errbuf);
                if (handle == IntPtr.Zero)
                {
                    TraceLog.Write($"Npcap probe: pcap_open_live failed for {deviceName}");
                    return null;
                }

                return new NpcapRung(api, handle, deviceName);
            }
            finally
            {
                Marshal.FreeHGlobal(errbuf);
            }
        }
        catch (Exception ex)
        {
            TraceLog.Write($"Npcap probe: disabled — {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Loads wpcap.dll once (cached) and resolves the six entry points this
    /// service uses. Any missing export releases the library and yields null.
    /// </summary>
    private static LoadedApi? GetApi()
    {
        lock (ApiLock)
        {
            if (_api != null) return _api;

            string? dllPath = ResolveWpcapPath(Environment.GetFolderPath(Environment.SpecialFolder.System));
            if (dllPath == null) return null;

            if (!NativeLibrary.TryLoad(dllPath, out IntPtr handle))
            {
                TraceLog.Write($"Npcap probe: cannot load {dllPath}");
                return null;
            }

            if (!TryGetExport(handle, "pcap_findalldevs", out FindAllDevsDelegate findAll) ||
                !TryGetExport(handle, "pcap_freealldevs", out FreeAllDevsDelegate freeAll) ||
                !TryGetExport(handle, "pcap_open_live", out OpenLiveDelegate openLive) ||
                !TryGetExport(handle, "pcap_sendpacket", out SendPacketDelegate sendPacket) ||
                !TryGetExport(handle, "pcap_geterr", out GetErrDelegate getErr) ||
                !TryGetExport(handle, "pcap_close", out CloseDelegate close))
            {
                NativeLibrary.Free(handle);
                TraceLog.Write("Npcap probe: wpcap.dll missing expected exports");
                return null;
            }

            _dllHandle = handle;
            _api = new LoadedApi(findAll, freeAll, openLive, sendPacket, getErr, close);
            return _api;
        }
    }

    private static bool TryGetExport<T>(IntPtr handle, string name, out T function) where T : Delegate
    {
        if (NativeLibrary.TryGetExport(handle, name, out IntPtr address))
        {
            function = Marshal.GetDelegateForFunctionPointer<T>(address);
            return true;
        }
        function = null!;
        return false;
    }

    /// <summary>
    /// Walks pcap_findalldevs' device list, matching the adapter GUID embedded
    /// in the NPF device name against <see cref="NetworkInterfaceInfo.Id"/>, with
    /// a description-equality fallback. Returns null when nothing matches.
    /// </summary>
    private static string? FindMatchingDevice(LoadedApi api, NetworkInterfaceInfo info, IntPtr errbuf)
    {
        IntPtr alldevs = IntPtr.Zero;
        if (api.FindAllDevs(out alldevs, errbuf) != 0)
        {
            TraceLog.Write($"Npcap probe: pcap_findalldevs failed — {Marshal.PtrToStringAnsi(errbuf)}");
            return null;
        }

        try
        {
            // Primary key: the NPF_{GUID} in the device name equals the
            // adapter Id's GUID — an exact identity match, brace-insensitive.
            for (IntPtr current = alldevs; current != IntPtr.Zero; current = ReadNext(current))
            {
                string? name = ReadDeviceName(current);
                if (name != null && DeviceMatchesIdentifier(name, info.Id))
                    return name;
            }

            // Fallback: compare descriptions case-insensitively (older adapter
            // drivers may expose a different Id surface to .NET than to NDIS).
            for (IntPtr current = alldevs; current != IntPtr.Zero; current = ReadNext(current))
            {
                string? name = ReadDeviceName(current);
                string? description = ReadDeviceDescription(current);
                if (name != null && description != null &&
                    string.Equals(description.Trim(), info.Description?.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    return name;
                }
            }

            return null;
        }
        finally
        {
            api.FreeAllDevs(alldevs);
        }
    }

    // pcap_if struct layout: four pointers, then bpf_u_int32 flags (Sequential
    // layout auto-sizes for both 32- and 64-bit processes).
    [StructLayout(LayoutKind.Sequential)]
    private struct PcapIf
    {
        public IntPtr Next;
        public IntPtr Name;
        public IntPtr Description;
        public IntPtr Addresses;
        public uint Flags;
    }

    private static IntPtr ReadNext(IntPtr device) => Marshal.PtrToStructure<PcapIf>(device).Next;

    private static string? ReadDeviceName(IntPtr device) =>
        Marshal.PtrToStringAnsi(Marshal.PtrToStructure<PcapIf>(device).Name);

    private static string? ReadDeviceDescription(IntPtr device) =>
        Marshal.PtrToStringAnsi(Marshal.PtrToStructure<PcapIf>(device).Description);
}

/// <summary>
/// An open Npcap send handle bound to one network interface. Injects complete
/// Ethernet frames via pcap_sendpacket; the kernel driver performs the actual
/// NDIS send, which is also the only Windows path that can emit TCP segments.
/// </summary>
internal sealed class NpcapRung : IL2SendRung
{
    private readonly NpcapSendService.LoadedApi _api;
    private readonly IntPtr _handle;

    internal NpcapRung(NpcapSendService.LoadedApi api, IntPtr handle, string deviceName)
    {
        _api = api;
        _handle = handle;
        DeviceName = deviceName;
    }

    /// <summary>Npcap device name this rung sends on (e.g. \Device\NPF_{GUID}).</summary>
    public string DeviceName { get; }

    /// <summary>
    /// Sends one frame. A null result means this rung cannot deliver the packet
    /// (frame shorter than an Ethernet header, or the driver rejected the send)
    /// — the caller descends to the next ladder rung as usual.
    /// </summary>
    public (PacketSendResult? Result, string? Error) TrySend(byte[] frame, int index, string interfaceName)
    {
        if (!NpcapSendService.CanSendFrame(frame))
            return (null, "Frame too short for Npcap Ethernet injection");

        int rc = _api.SendPacket(_handle, frame, frame.Length);
        if (rc == 0)
        {
            return (new PacketSendResult(index, true,
                $"Sent {frame.Length} bytes on {interfaceName} (npcap)"), null);
        }

        string error = Marshal.PtrToStringAnsi(_api.GetErr(_handle)) ?? "unknown Npcap error";
        return (null, $"Npcap send failed: {error}");
    }

    public void Dispose()
    {
        _api.Close(_handle);
    }
}