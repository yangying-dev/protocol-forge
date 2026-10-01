using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
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
    public async Task StartSendAsync(
        IReadOnlyList<Packet> packets,
        NetworkInterfaceInfo interfaceInfo,
        int loopCount = 1,
        int intervalMs = 0,
        bool autoFixFrames = true,
        CancellationToken ct = default)
    {
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

        var sockets = CreateSendSockets(interfaceInfo);
        using var l2Rung = OperatingSystem.IsWindows()
            ? NpcapSendService.TryOpenRung(interfaceInfo)
            : OperatingSystem.IsMacOS()
                ? BpfSendService.TryOpenRung(interfaceInfo)
                : (IL2SendRung?)null;
        try
        {
            if (sockets.Count == 0 && l2Rung == null)
            {
                OnPacketSent(new PacketSendResult(-1, false,
                    LocalizationService.Resolve("Send.NoSocketType", interfaceInfo.Name)));
                return;
            }

            // Bind send sockets to the selected interface IP (best effort; the
            // AF_PACKET socket selects its interface per frame via sockaddr_ll).
            foreach (var socket in sockets)
            {
                if (socket.AddressFamily != AddressFamily.Packet && interfaceInfo.IPv4Address != null)
                {
                    try { socket.Bind(new IPEndPoint(interfaceInfo.IPv4Address, 0)); }
                    catch { /* best-effort bind */ }
                }
            }

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
                    await SendPacketAsync(sockets, packet, i, interfaceInfo, autoFixFrames, l2Rung);

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
            foreach (var socket in sockets) socket.Dispose();
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
        IReadOnlyList<Socket> sockets,
        Packet packet,
        int index,
        NetworkInterfaceInfo interfaceInfo,
        bool autoFixFrames,
        IL2SendRung? l2Rung)
    {
        byte[] data;
        int ipOffset;
        try
        {
            data = autoFixFrames
                ? PacketPrepareService.PrepareFrame(packet.EffectiveData, interfaceInfo)
                : packet.EffectiveData;
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

    private void OnPacketSent(PacketSendResult result)
    {
        if (result.Success)
            TotalSent++;
        else
            TotalFailed++;

        PacketSent?.Invoke(result);
    }
}
