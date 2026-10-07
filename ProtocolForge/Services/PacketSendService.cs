using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using ProtocolForge.Models;

namespace ProtocolForge.Services;

/// <summary>
/// Status of a packet send operation.
/// </summary>
public sealed record PacketSendResult(int PacketIndex, bool Success, string Message);

/// <summary>
/// Sends raw packet bytes over the selected network interface.
/// Managed sockets plus an optional Npcap L2 rung on Windows.
///
/// Strategy (descended per packet, highest fidelity first):
///   0. L2 native rung (optional) — Npcap on Windows, BPF on macOS — sends
///      complete Ethernet frames; silently absent when the native path is
///      unavailable
///   1. AF_PACKET raw socket (Linux) — sends complete Ethernet frames
///   2. IP-level raw socket (all OS) — sends IP datagrams
///   3. UDP socket — sends at transport layer (fallback)
/// </summary>
public sealed class PacketSendService
{
    private CancellationTokenSource? _sendCts;
    private readonly object _lock = new();

    /// <summary>True while a send operation is actively transmitting packets.</summary>
    public bool IsRunning { get; private set; }

    /// <summary>True when the send operation is paused (can be resumed).</summary>
    public bool IsPaused { get; private set; }

    /// <summary>Total packets sent in the current session.</summary>
    public int TotalSent { get; private set; }

    /// <summary>Total send failures in the current session.</summary>
    public int TotalFailed { get; private set; }

    /// <summary>
    /// Event raised when an individual packet send completes.
    /// </summary>
    public event Action<PacketSendResult>? PacketSent;

    /// <summary>
    /// Event raised when the send session completes (all packets sent or cancelled).
    /// </summary>
    public event Action? SendCompleted;

    /// <summary>
    /// Starts sending packets from the list sequentially.
    /// </summary>
    /// <param name="packets">Packets to send, in list order.</param>
    /// <param name="interfaceInfo">Selected network interface.</param>
    /// <param name="loopCount">Number of full passes through the list; values &lt;= 0 are treated as 1.</param>
    /// <param name="intervalMs">Delay between consecutive packet sends.</param>
    /// <param name="autoFixFrames">Rewrite source MAC/IP and checksums before each send.</param>
    public Task StartSendAsync(
        IReadOnlyList<Packet> packets,
        NetworkInterfaceInfo interfaceInfo,
        int loopCount = 1,
        int intervalMs = 0,
        bool autoFixFrames = true,
        VlanMode vlanMode = VlanMode.Leave,
        ushort vlanId = 0,
        CancellationToken ct = default) =>
        StartSendAsync(packets, [interfaceInfo], loopCount, intervalMs, autoFixFrames, vlanMode, vlanId, ct);

    /// <summary>
    /// Starts sending packets from the list sequentially, fanning each packet out to
    /// every selected interface in list order.
    /// </summary>
    /// <param name="packets">Packets to send, in list order.</param>
    /// <param name="interfaceInfos">Target interfaces; an empty list is a no-op.</param>
    /// <param name="loopCount">Number of full passes through the list; values &lt;= 0 are treated as 1.</param>
    /// <param name="intervalMs">Delay between consecutive packet sends.</param>
    /// <param name="autoFixFrames">Rewrite source MAC/IP and checksums before each send.</param>
    /// <param name="vlanMode">Insert, replace, or remove an 802.1Q tag on the way out.</param>
    /// <param name="vlanId">VID used by <paramref name="vlanMode"/>; 0-4095.</param>
    public async Task StartSendAsync(
        IReadOnlyList<Packet> packets,
        IReadOnlyList<NetworkInterfaceInfo> interfaceInfos,
        int loopCount = 1,
        int intervalMs = 0,
        bool autoFixFrames = true,
        VlanMode vlanMode = VlanMode.Leave,
        ushort vlanId = 0,
        CancellationToken ct = default)
    {
        if (interfaceInfos.Count == 0)
            return;

        lock (_lock)
        {
            if (IsRunning) return;
            IsRunning = true;
            IsPaused = false;
            _sendCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            TotalSent = 0;
            TotalFailed = 0;
        }

        var cts = _sendCts;
        if (cts == null) return;

        // One target per interface: each owns its sockets and its native L2 rung, so a
        // NIC that cannot be opened is reported on its own instead of silently taking
        // the whole send down with it.
        var targets = new List<SendTarget>();
        try
        {
            foreach (var iface in interfaceInfos)
            {
                var target = CreateSendTarget(iface);
                targets.Add(target);

                if (!target.CanSend)
                    OnPacketSent(new PacketSendResult(-1, false,
                        LocalizationService.Resolve("Send.NoSocketType", iface.Name)));
            }

            if (!targets.Any(t => t.CanSend))
                return;

            WarnWhenVlanCannotBeSent(targets, packets, vlanMode, vlanId);
            WarnWhenEgressCannotBePinned(targets);

            int total = packets.Count;
            int rounds = loopCount <= 0 ? 1 : loopCount;
            for (int round = 0; round < rounds; round++)
            {
                if (cts.IsCancellationRequested) break;

                for (int i = 0; i < total; i++)
                {
                    if (cts.IsCancellationRequested) break;

                    // Pause support: wait until resumed or cancelled
                    while (IsPaused && !cts.IsCancellationRequested)
                    {
                        await Task.Delay(100, cts.Token);
                    }

                    if (cts.IsCancellationRequested) break;

                    var packet = packets[i];
                    foreach (var target in targets)
                        await SendPacketAsync(target, packet, i, autoFixFrames, vlanMode, vlanId);

                    if (intervalMs > 0)
                    {
                        try { await Task.Delay(intervalMs, cts.Token); }
                        catch (OperationCanceledException) { }
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal cancellation — handled
        }
        catch (Exception ex)
        {
            OnPacketSent(new PacketSendResult(-1, false, LocalizationService.Resolve("Send.Error", ex.Message)));
        }
        finally
        {
            foreach (var target in targets) target.Dispose();
            lock (_lock)
            {
                IsRunning = false;
                IsPaused = false;
                _sendCts?.Dispose();
                _sendCts = null;
            }
            SendCompleted?.Invoke();
        }
    }

    /// <summary>
    /// Tells the user when the VLAN they selected will not survive to the wire. The tag
    /// only reaches the network if a rung transmits the whole Ethernet frame; on the UDP
    /// and IP-raw rungs the kernel builds the header itself and our tag is silently
    /// discarded, which would otherwise look like the setting simply did nothing.
    /// </summary>
    private void WarnWhenVlanCannotBeSent(
        List<SendTarget> targets, IReadOnlyList<Packet> packets, VlanMode vlanMode, ushort vlanId)
    {
        if (vlanMode == VlanMode.Leave)
            return;

        int affected = CountVlanAffected(packets, vlanMode, vlanId);
        if (affected == 0)
            return; // nothing to tag anyway — e.g. bare IP datagrams only

        foreach (var target in targets)
        {
            if (!target.CanSend || target.CanCarryVlan)
                continue;

            SendWarning?.Invoke(LocalizationService.Resolve(
                "Send.VlanNotCarried", target.Interface.Name, affected));
        }
    }

    /// <summary>
    /// Windows sockets cannot pin the egress adapter, so a target without a native L2
    /// rung sends through sockets the kernel may route out of another NIC. Once per
    /// affected target, like the VLAN warning: nothing failed, the route is just not forced.
    /// </summary>
    private void WarnWhenEgressCannotBePinned(List<SendTarget> targets)
    {
        if (!OperatingSystem.IsWindows())
            return;

        foreach (var target in targets)
        {
            if (!target.CanSend || target.L2Rung != null)
                continue;

            SendWarning?.Invoke(LocalizationService.Resolve(
                "Send.EgressNotPinnable", target.Interface.Name));
        }
    }

    /// <summary>Sockets and native L2 rung for one interface, plus its egress pinning.</summary>
    private sealed class SendTarget : IDisposable
    {
        public required NetworkInterfaceInfo Interface { get; init; }
        public required List<Socket> Sockets { get; init; }
        public IL2SendRung? L2Rung { get; init; }
        public bool CanSend => Sockets.Count > 0 || L2Rung != null;

        /// <summary>
        /// Whether this target transmits the whole Ethernet frame we hand it. The UDP
        /// and IP-raw rungs do not: they pass only the IP datagram and let the kernel
        /// synthesise the Ethernet header, so an 802.1Q tag we inserted is dropped on
        /// the way out.
        /// </summary>
        public bool CanCarryVlan =>
            L2Rung != null || Sockets.Any(s => s.AddressFamily == AddressFamily.Packet);

        public void Dispose()
        {
            foreach (var socket in Sockets) socket.Dispose();
            L2Rung?.Dispose();
        }
    }

    /// <summary>
    /// Opens the send sockets for one interface and pins them to it.
    ///
    /// Binding the source address alone does NOT pick the egress adapter: the kernel
    /// still routes by its own table, so selecting NIC-A could transmit out of NIC-B.
    /// Only AF_PACKET (per-frame sockaddr_ll) and the native L2 rungs genuinely force
    /// the adapter. For the IP-raw and UDP rungs the adapter is pinned with
    /// SO_BINDTODEVICE on Linux and IP_BOUND_IF on macOS. Windows has no equivalent for
    /// a normal socket, so there the source-address bind is all that is available —
    /// see SECURITY.md.
    /// </summary>
    private static SendTarget CreateSendTarget(NetworkInterfaceInfo interfaceInfo)
    {
        var sockets = CreateSendSockets(interfaceInfo);
        var l2Rung = OperatingSystem.IsWindows()
            ? NpcapSendService.TryOpenRung(interfaceInfo)
            : OperatingSystem.IsMacOS()
                ? BpfSendService.TryOpenRung(interfaceInfo)
                : (IL2SendRung?)null;

        foreach (var socket in sockets)
        {
            if (socket.AddressFamily == AddressFamily.Packet)
                continue; // selects its own interface per frame

            if (TryPinToDevice(socket, interfaceInfo))
                continue;

            if (interfaceInfo.IPv4Address != null)
            {
                try { socket.Bind(new IPEndPoint(interfaceInfo.IPv4Address, 0)); }
                catch { /* best-effort bind */ }
            }
        }

        return new SendTarget { Interface = interfaceInfo, Sockets = sockets, L2Rung = l2Rung };
    }

    /// <summary>
    /// Pauses the ongoing send operation. Resume with <see cref="ResumeSend"/>.
    /// </summary>
    public void PauseSend()
    {
        lock (_lock)
        {
            if (!IsRunning) return;
            IsPaused = true;
        }
    }

    /// <summary>
    /// Resumes a paused send operation.
    /// </summary>
    public void ResumeSend()
    {
        lock (_lock)
        {
            if (!IsRunning) return;
            IsPaused = false;
        }
    }

    /// <summary>
    /// Stops (cancels) the ongoing send operation.
    /// </summary>
    public void StopSend()
    {
        lock (_lock)
        {
            if (!IsRunning) return;
            _sendCts?.Cancel();
            IsPaused = false;
        }
    }

    // ─── Socket Creation ───

    /// <summary>
    /// Builds a Linux sockaddr_ll (AF_PACKET) socket address for raw frame delivery:
    /// family, ETH_P_ALL protocol, interface index, and the frame's dest MAC.
    /// </summary>
    /// <summary>How the send path should treat 802.1Q tags.</summary>
    public enum VlanMode
    {
        /// <summary>Send the frame exactly as captured.</summary>
        Leave,
        /// <summary>Add a tag when the frame has none; leave an existing one alone.</summary>
        Insert,
        /// <summary>Set the tag's VID, adding a tag when the frame has none.</summary>
        Replace,
        /// <summary>Remove the outermost tag.</summary>
        Remove,
    }

    /// <summary>
    /// How many of the selected packets a VLAN mode would actually change. A bare IP
    /// datagram has no Ethernet header to tag, so warning about it would be a false
    /// alarm; this is what keeps the warning tied to real taggable frames.
    /// </summary>
    public static int CountVlanAffected(IReadOnlyList<Packet> packets, VlanMode mode, ushort vid) =>
        packets.Count(p => IsVlanAffected(p.EffectiveData, mode, vid));

    private static bool IsVlanAffected(byte[] frame, VlanMode mode, ushort vid) => mode switch
    {
        VlanMode.Insert => PacketPrepareService.HasEthernetHeader(frame)
                          && !PacketPrepareService.HasVlanTag(frame),
        VlanMode.Replace => PacketPrepareService.HasEthernetHeader(frame)
                            && PacketPrepareService.GetVlanId(frame) != vid,
        VlanMode.Remove => PacketPrepareService.HasVlanTag(frame),
        _ => false,
    };

    private static byte[] ApplyVlan(VlanMode mode, ushort vid, byte[] frame) => mode switch
    {
        VlanMode.Insert when !PacketPrepareService.HasVlanTag(frame) => PacketPrepareService.ApplyVlanTag(frame, vid),
        VlanMode.Replace => PacketPrepareService.ApplyVlanTag(frame, vid),
        VlanMode.Remove => PacketPrepareService.StripVlanTag(frame),
        _ => frame,
    };


    private static SocketAddress? BuildSockAddrLl(int ifindex, byte[] frame)
    {
        if (frame.Length < 14)
            return null;

        var sa = new SocketAddress(AddressFamily.Packet, 20);
        sa[2] = 0x00;                                  // sll_protocol = ETH_P_ALL (network order)
        sa[3] = 0x03;
        var ifindexBytes = BitConverter.GetBytes(ifindex);
        for (int k = 0; k < 4; k++)
            sa[4 + k] = ifindexBytes[k];               // sll_ifindex (native)
        sa[8] = 0x01;                                  // sll_hatype = ARPHRD_ETHER
        sa[9] = 0x00;
        sa[10] = 0x00;                                 // sll_pkttype
        sa[11] = 0x06;                                 // sll_halen
        for (int k = 0; k < 6; k++)
            sa[12 + k] = frame[k];                     // sll_addr = destination MAC
        return sa;
    }

    // .NET exposes neither SO_BINDTODEVICE nor IP_BOUND_IF, so both are issued through
    // libc directly. The value is a native string for the first and an interface index
    // for the second, hence two entry points over the same option name.
    private const int SOL_SOCKET = 1;
    private const int SO_BINDTODEVICE = 25;
    private const int IPPROTO_IP = 0;
    private const int IP_BOUND_IF = 25;

    [DllImport("libc", EntryPoint = "setsockopt", SetLastError = true)]
    private static extern int SetsockoptBytes(int fd, int level, int name, byte[] value, int len);

    [DllImport("libc", EntryPoint = "setsockopt", SetLastError = true)]
    private static extern int SetsockoptInt(int fd, int level, int name, ref int value, int len);

    /// <summary>
    /// Pins a managed socket to one adapter so the kernel cannot route the frame out of a
    /// different interface. Returns false when the platform offers no way to do it, and
    /// the caller then falls back to a source-address bind.
    /// </summary>
    private static bool TryPinToDevice(Socket socket, NetworkInterfaceInfo interfaceInfo)
    {
        try
        {
            int fd = (int)socket.Handle;

            if (OperatingSystem.IsLinux())
            {
                byte[] name = System.Text.Encoding.ASCII.GetBytes(interfaceInfo.Name + "\0");
                return SetsockoptBytes(fd, SOL_SOCKET, SO_BINDTODEVICE, name, name.Length) == 0;
            }

            if (OperatingSystem.IsMacOS())
            {
                int index = MacInterfaceIndex(interfaceInfo.Name);
                if (index <= 0)
                    return false;
                return SetsockoptInt(fd, IPPROTO_IP, IP_BOUND_IF, ref index, sizeof(int)) == 0;
            }
        }
        catch (DllNotFoundException)
        {
        }
        catch (EntryPointNotFoundException)
        {
        }
        return false;
    }

    /// <summary>
    /// macOS interface index for a name. .NET exposes it on the IPv4 interface info,
    /// which is why this cannot reuse the Linux /sys lookup.
    /// </summary>
    private static int MacInterfaceIndex(string name)
    {
        foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!string.Equals(nic.Name, name, StringComparison.Ordinal))
                continue;
            if (nic.GetIPProperties()?.GetIPv4Properties() is { } p)
                return p.Index;
        }
        return -1;
    }

    private static bool TryGetLsIfindex(string name, out int ifindex)
    {
        try
        {
            var path = $"/sys/class/net/{name}/ifindex";
            if (File.Exists(path) && int.TryParse(File.ReadAllText(path).Trim(), out ifindex))
                return true;
        }
        catch
        {
            // fall through to error path
        }
        ifindex = -1;
        return false;
    }

    private static bool TryExtractUdpTarget(byte[] data, int ipOffset, out IPEndPoint endpoint, out byte[] payload)
    {
        endpoint = null!;
        payload = [];
        if (ipOffset < 0 || data.Length < ipOffset + 20 || ((data[ipOffset] >> 4) & 0x0F) != 4)
            return false;
        int ihl = (data[ipOffset] & 0x0F) * 4;
        if (data[ipOffset + 9] != 17 || data.Length < ipOffset + ihl + 8)
            return false;
        var destIp = new IPAddress(data[(ipOffset + 16)..(ipOffset + 20)]);
        if (destIp.Equals(IPAddress.Any))
            return false;
        int destPort = (data[ipOffset + ihl + 2] << 8) | data[ipOffset + ihl + 3];
        payload = data[(ipOffset + ihl + 8)..];
        endpoint = new IPEndPoint(destIp, destPort);
        return true;
    }

    /// <summary>
    /// Creates every socket type the local OS supports, in descending fidelity
    /// order. Each packet descends this ladder until one rung delivers it;
    /// rungs needing privileges are simply absent when creation fails.
    /// </summary>
    private static List<Socket> CreateSendSockets(NetworkInterfaceInfo info)
    {
        var sockets = new List<Socket>();

        // Strategy 1: AF_PACKET (Linux) — raw Ethernet frames
        if (OperatingSystem.IsLinux())
        {
            try
            {
                sockets.Add(new Socket(AddressFamily.Packet, SocketType.Raw, ProtocolType.Raw));
            }
            catch
            {
                // Fall through — may need root
            }
        }

        // Strategy 2: IP-level raw socket — requires admin/root. We supply complete
        // IP datagrams, so the kernel must not prepend its own header. Windows
        // requires IP_HDRINCL; Linux defaults it off too, so set it there as well.
        // Windows/macOS/BSD raw sockets already expect the caller's IP header by default.
        // Windows raw sockets use IPPROTO_IP (0); Linux/macOS reject protocol 0 with
        // EPROTONOSUPPORT, so they must use IPPROTO_RAW (ProtocolType.Raw) instead
        // (verified by pf-verify G27 N-10 ladder-descent).
        try
        {
            var raw = new Socket(AddressFamily.InterNetwork, SocketType.Raw,
                OperatingSystem.IsWindows() ? ProtocolType.IP : ProtocolType.Raw);
            if (OperatingSystem.IsWindows() || OperatingSystem.IsLinux())
            {
                try { raw.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true); }
                catch { /* keep socket if option unsupported */ }
            }
            sockets.Add(raw);
        }
        catch
        {
            // Fall through — may need admin
        }

        // Strategy 3: Standard UDP socket (works without privileges)
        try
        {
            var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            if (OperatingSystem.IsWindows())
            {
                // Windows surfaces a queued ICMP "Port Unreachable" as WSAECONNRESET
                // (10054) on the NEXT send of the same socket (KB 263823). Disable so
                // one dead receiver cannot break the whole send run.
                try
                {
                    const int sioUdpConnReset = unchecked((int)0x9800000C);
                    udp.IOControl(sioUdpConnReset, new byte[4], null);
                }
                catch { /* older Windows may not support the ioctl */ }
            }
            sockets.Add(udp);
        }
        catch
        {
            // no fallback below UDP
        }

        return sockets;
    }

    private async Task SendPacketAsync(
        SendTarget target,
        Packet packet,
        int index,
        bool autoFixFrames,
        VlanMode vlanMode,
        ushort vlanId)
    {
        var sockets = target.Sockets;
        var interfaceInfo = target.Interface;
        var l2Rung = target.L2Rung;

        byte[] data;
        int ipOffset;
        try
        {
            data = ApplyVlan(vlanMode, vlanId, packet.EffectiveData);
            // VLAN changes the frame, so the checksums the adapter is about to validate
            // are computed from the tagged bytes, not from the bytes as captured.
            data = autoFixFrames
                ? PacketPrepareService.PrepareFrame(data, interfaceInfo)
                : data;
            ipOffset = PacketPrepareService.FindIpOffset(data);
        }
        catch (Exception ex)
        {
            OnPacketSent(new PacketSendResult(index, false, ex.Message));
            return;
        }

        int protocol = ipOffset >= 0 && data.Length > ipOffset + 9 ? data[ipOffset + 9] : 0;
        string? lastError = null;

        // Rung 0 (optional): a native L2 path (Npcap on Windows, BPF on macOS)
        // injects whole Ethernet frames — also the only Windows path for TCP.
        // A null result means the rung cannot deliver; descend as usual.
        if (l2Rung != null)
        {
            try
            {
                var (result, error) = l2Rung.TrySend(data, index, interfaceInfo.Name);
                if (result != null)
                {
                    OnPacketSent(result);
                    return;
                }
                if (error != null)
                {
                    lastError = error;
                    TraceLog.Write($"Send rung L2 ({l2Rung.DeviceName}) failed for packet {index}: {error}");
                }
            }
            catch (Exception ex)
            {
                lastError = ex.Message;
                TraceLog.Write($"Send rung L2 ({l2Rung.DeviceName}) failed for packet {index}: {ex.Message}");
            }
        }

        // Descend the ladder per packet: a rung returns null + error when it cannot
        // deliver (e.g. a bare IP datagram has no Ethernet frame) — move to the next.
        foreach (var socket in sockets)
        {
            string rungLabel = socket.AddressFamily == AddressFamily.Packet
                ? "AF_PACKET"
                : socket.SocketType == SocketType.Dgram && socket.ProtocolType == ProtocolType.Udp
                    ? "UDP"
                    : "IP raw";
            try
            {
                var (result, error) = socket.AddressFamily == AddressFamily.Packet
                    ? await TrySendEthernetFrameAsync(socket, data, interfaceInfo, index)
                    : socket.SocketType == SocketType.Dgram && socket.ProtocolType == ProtocolType.Udp
                        ? await TrySendUdpPayloadAsync(socket, data, ipOffset, protocol, index)
                        : await TrySendIpDatagramAsync(socket, data, ipOffset, index);

                if (result != null)
                {
                    OnPacketSent(result);
                    return;
                }
                if (error != null)
                {
                    lastError = error;
                    TraceLog.Write($"Send rung {rungLabel} failed for packet {index}: {error}");
                }
            }
            catch (SocketException sex)
            {
                // Windows kernels block TCP segments on raw IP sockets outright
                // (since XP SP2); privileges never help, so say so explicitly.
                bool windowsTcpBlocked = OperatingSystem.IsWindows()
                    && socket.SocketType == SocketType.Raw
                    && protocol == 6;
                lastError = windowsTcpBlocked
                    ? LocalizationService.Resolve("Send.WindowsTcpBlocked")
                    : sex.SocketErrorCode == SocketError.AccessDenied
                        ? LocalizationService.Resolve("Send.AccessDenied")
                        : LocalizationService.Resolve("Send.SocketError", sex.Message);
                TraceLog.Write($"Send rung {rungLabel} failed for packet {index}: {lastError}");
            }
            catch (Exception ex)
            {
                lastError = ex.Message;
                TraceLog.Write($"Send rung {rungLabel} failed for packet {index}: {ex.Message}");
            }
        }

        string finalError = lastError ?? LocalizationService.Resolve("Send.NoPath");
        TraceLog.Write($"Send failed on all rungs for packet {index}: {finalError}");
        OnPacketSent(new PacketSendResult(index, false, finalError));
    }

    /// <summary>
    /// AF_PACKET rung: sends the whole Ethernet frame via sockaddr_ll. Null result
    /// = not sendable as a frame (no ifindex, or shorter than an Ethernet header).
    /// </summary>
    private static async Task<(PacketSendResult? Result, string? Error)> TrySendEthernetFrameAsync(
        Socket socket, byte[] data, NetworkInterfaceInfo info, int index)
    {
        if (!TryGetLsIfindex(info.Name, out int ifindex))
            return (null, LocalizationService.Resolve("Send.NoIfIndex", info.Name));

        var target = BuildSockAddrLl(ifindex, data);
        if (target == null)
            return (null, LocalizationService.Resolve("Send.FrameTooShort"));

        await socket.SendToAsync(data, SocketFlags.None, target);
        return (new PacketSendResult(index, true,
            LocalizationService.Resolve("Send.SentRaw", data.Length, info.Name)), null);
    }

    /// <summary>
    /// Raw IP rung: sends the IP datagram (Ethernet header stripped). All OSes
    /// expect the caller-supplied header on this path.
    /// </summary>
    private static async Task<(PacketSendResult? Result, string? Error)> TrySendIpDatagramAsync(
        Socket socket, byte[] data, int ipOffset, int index)
    {
        byte[] ipData = ipOffset > 0 ? data[ipOffset..] : data;
        if (ipOffset >= 0 && (data[ipOffset] >> 4) == 4)
        {
            var dest = new IPEndPoint(new IPAddress(data[(ipOffset + 16)..(ipOffset + 20)]), 0);
            await socket.SendToAsync(ipData, SocketFlags.None, dest);
        }
        else
        {
            await socket.SendAsync(ipData, SocketFlags.None);
        }
        return (new PacketSendResult(index, true, LocalizationService.Resolve("Send.SentIp", ipData.Length)), null);
    }

    /// <summary>
    /// UDP rung: sends only the transport payload. Last rung — failure here is final.
    /// </summary>
    private static async Task<(PacketSendResult? Result, string? Error)> TrySendUdpPayloadAsync(
        Socket socket, byte[] data, int ipOffset, int protocol, int index)
    {
        if (TryExtractUdpTarget(data, ipOffset, out var endpoint, out byte[] udpPayload))
        {
            await socket.SendToAsync(udpPayload, SocketFlags.None, endpoint);
            return (new PacketSendResult(index, true,
                LocalizationService.Resolve("Send.SentUdp", udpPayload.Length, endpoint)), null);
        }

        string error = protocol == 6
            ? OperatingSystem.IsWindows()
                ? LocalizationService.Resolve("Send.TcpBlockedWin")
                : LocalizationService.Resolve("Send.TcpNeedsPriv")
            : LocalizationService.Resolve("Send.UdpParseFailed");
        return (null, error);
    }

    /// <summary>
    /// Raised for a condition that does not stop the send but changes what the user
    /// should expect from it. Deliberately separate from <see cref="PacketSent"/> so a
    /// warning never counts as a failed packet.
    /// </summary>
    public event Action<string>? SendWarning;

    private void OnPacketSent(PacketSendResult result)
    {
        if (result.Success)
            TotalSent++;
        else
            TotalFailed++;

        PacketSent?.Invoke(result);
    }
}
