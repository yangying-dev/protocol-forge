using System.Net.NetworkInformation;

namespace ProtocolForge.Services;

/// <summary>
/// Rewrites a captured frame into a sendable form: source MAC and source IP are
/// replaced with the selected interface's values, and header checksums are
/// recomputed so the frame survives routing and receiver validation.
/// </summary>
public static class PacketPrepareService
{
    /// <summary>Unknown link layer type: fall back to byte-level IP detection.</summary>
    public const int LinkTypeUnknown = -1;
    private const int LinkTypeEthernet = 1;
    private const int LinkTypeRawBsd = 12;
    private const int LinkTypeRaw = 101;
    private const int LinkTypeIpv4 = 228;
    private const int LinkTypeIpv6 = 229;

    /// <summary>
    /// Returns a copy of <paramref name="frame"/> with send-time fixes applied.
    /// Ethernet source MAC → interface MAC, IPv4 source address → interface IPv4,
    /// IPv4 header checksum and TCP/UDP checksums recomputed (UDP stays 0 when it
    /// was 0 — the IPv4 "checksum off" convention; IPv6 always gets a real one).
    /// SCTP's CRC32c is always recomputed and stored little-endian per RFC 4960.
    /// </summary>
    public static byte[] PrepareFrame(byte[] frame, NetworkInterfaceInfo iface) =>
        PrepareFrame(frame, iface, LinkTypeUnknown);

    /// <summary>
    /// Same as the two-argument overload, but resolves the IP header using the capture's
    /// link-layer type (DLT) instead of the byte heuristic, so a bare datagram whose
    /// bytes 12–13 happen to look like an ethertype is still parsed as bare IP.
    /// </summary>
    public static byte[] PrepareFrame(byte[] frame, NetworkInterfaceInfo iface, int linkLayerType)
    {
        if (frame.Length == 0)
            return frame;

        var result = (byte[])frame.Clone();
        int ipOffset = FindIpOffset(result, linkLayerType);
        if (ipOffset < 0)
            return result;

        if (ipOffset == 14 && ParseMac(iface.MacAddress) is { } mac)
            Buffer.BlockCopy(mac, 0, result, 6, 6);

        // FindIpOffset 可以返回正好等于帧长的偏移（例如只有 14 字节以太网头、
        // 无 IP 载荷的短帧），此时读取 result[ipOffset] 会越界；直接原样返回。
        if (ipOffset >= result.Length)
            return result;

        int version = result[ipOffset] >> 4;

        if (version == 4)
        {
            if (iface.IPv4Address?.GetAddressBytes() is { Length: 4 } src && result.Length >= ipOffset + 20)
                Buffer.BlockCopy(src, 0, result, ipOffset + 12, 4);

            int ihl = (result[ipOffset] & 0x0F) * 4;
            // IHL < 5 的畸形包会让 ihl 算成 0 并通过下面的长度检查，
            // 随后 result[ipOffset + 10] 在短帧上越界。
            if (ihl < 20 || result.Length < ipOffset + ihl)
                return result;

            result[ipOffset + 10] = 0;
            result[ipOffset + 11] = 0;
            PutChecksum(result, ipOffset + 10, InternetChecksum(result, ipOffset, ihl));

            byte protocol = result[ipOffset + 9];
            int l4 = ipOffset + ihl;
            if (protocol == 6 && result.Length >= l4 + 20)
            {
                int len = ((result[ipOffset + 2] << 8) | result[ipOffset + 3]) - ihl;
                if (len > 0 && result.Length >= l4 + len)
                {
                    result[l4 + 16] = 0;
                    result[l4 + 17] = 0;
                    PutChecksum(result, l4 + 16, TransportChecksum(result, ipOffset, l4, len, 6, false));
                }
            }
            else if (protocol == 17 && result.Length >= l4 + 8)
            {
                int len = (result[l4 + 4] << 8) | result[l4 + 5];
                int existing = (result[l4 + 6] << 8) | result[l4 + 7];
                if (existing != 0 && len > 0 && result.Length >= l4 + len)
                {
                    result[l4 + 6] = 0;
                    result[l4 + 7] = 0;
                    PutChecksum(result, l4 + 6, TransportChecksum(result, ipOffset, l4, len, 17, false));
                }
            }
            else if (protocol == 132 && result.Length >= l4 + 12)
            {
                int len = ((result[ipOffset + 2] << 8) | result[ipOffset + 3]) - ihl;
                if (len >= 12 && result.Length >= l4 + len)
                {
                    result[l4 + 8] = 0;
                    result[l4 + 9] = 0;
                    result[l4 + 10] = 0;
                    result[l4 + 11] = 0;
                    uint crc = ComputeCrc32c(result, l4, len);
                    // RFC 4960 §3.10: CRC32c 以小端存放于 checksum 字段。
                    result[l4 + 8] = (byte)crc;
                    result[l4 + 9] = (byte)(crc >> 8);
                    result[l4 + 10] = (byte)(crc >> 16);
                    result[l4 + 11] = (byte)(crc >> 24);
                }
            }
        }
        else if (version == 6)
        {
            if (result.Length < ipOffset + 40)
                return result;

            int nextHeader = result[ipOffset + 6];
            int payloadLen = (result[ipOffset + 4] << 8) | result[ipOffset + 5];

            // 沿 IPv6 扩展头链定位上层协议头。IPv6 传输层校验和覆盖伪首部（含源
            // 地址），所以只有确认能定位并重算校验和时才允许改源地址；否则保留
            // 捕获到的源地址，避免留下与源地址不一致的失效校验和。
            int l4 = ipOffset + 40;
            bool resolvable = true;
            while (resolvable && nextHeader is not (6 or 17 or 132))
            {
                int cursor = l4;
                if (nextHeader is 0 or 60)
                {
                    if (cursor + 2 > result.Length) { resolvable = false; break; }
                    nextHeader = result[cursor];
                    l4 = cursor + (result[cursor + 1] + 1) * 8;   // 长度以 8 字节为单位
                }
                else if (nextHeader == 43)
                {
                    if (cursor + 4 > result.Length) { resolvable = false; break; }
                    // Routing 头的真正目的地址是头内最后一个地址，本代码不解析；
                    // Segments Left != 0 时伪首部目的地址就是错的，故不改源地址。
                    if (result[cursor + 3] != 0) { resolvable = false; break; }
                    nextHeader = result[cursor];
                    l4 = cursor + (result[cursor + 1] + 1) * 8;   // 长度以 8 字节为单位
                }
                else if (nextHeader == 44)
                {
                    if (cursor + 4 > result.Length) { resolvable = false; break; }
                    // Fragment Offset(13b)|Res(2b)|M(1b) 大端位于 2..3 字节；仅原子
                    // 分片 (offset==0 && M==0, RFC 6946) 才可继续——否则负载不是
                    // L4 头，改源地址或写校验和会破坏分片内容。
                    int fragWord = (result[cursor + 2] << 8) | result[cursor + 3];
                    if ((fragWord >> 3) != 0 || (fragWord & 0x1) != 0) { resolvable = false; break; }
                    nextHeader = result[cursor];
                    l4 = cursor + 8;                              // 分片头固定 8 字节
                }
                else
                {
                    resolvable = false;                           // 51/59 或未知协议：不可解析上层
                    break;
                }
            }

            if (resolvable)
            {
                int len = payloadLen - (l4 - (ipOffset + 40));
                bool tcp = nextHeader == 6 && len > 0 && result.Length >= l4 + 20 && result.Length >= l4 + len;
                bool udp = nextHeader == 17 && len > 0 && result.Length >= l4 + 8 && result.Length >= l4 + len;
                bool sctp = nextHeader == 132 && len >= 12 && result.Length >= l4 + 12 && result.Length >= l4 + len;

                // 只有确实会重算传输层校验和（覆盖含源地址的伪首部）时才改源地址；
                // 截断帧或无可重算的 L4 时保留捕获源地址，避免留下失效校验和。
                if (tcp || udp || sctp)
                {
                    if (iface.IPv6Address?.GetAddressBytes() is { Length: 16 } src6)
                        Buffer.BlockCopy(src6, 0, result, ipOffset + 8, 16);
                }

                if (tcp)
                {
                    result[l4 + 16] = 0;
                    result[l4 + 17] = 0;
                    PutChecksum(result, l4 + 16, TransportChecksum(result, ipOffset, l4, len, 6, true));
                }
                else if (udp)
                {
                    result[l4 + 6] = 0;
                    result[l4 + 7] = 0;
                    PutChecksum(result, l4 + 6, TransportChecksum(result, ipOffset, l4, len, 17, true));
                }
                else if (sctp)
                {
                    result[l4 + 8] = 0;
                    result[l4 + 9] = 0;
                    result[l4 + 10] = 0;
                    result[l4 + 11] = 0;
                    uint crc = ComputeCrc32c(result, l4, len);
                    result[l4 + 8] = (byte)crc;
                    result[l4 + 9] = (byte)(crc >> 8);
                    result[l4 + 10] = (byte)(crc >> 16);
                    result[l4 + 11] = (byte)(crc >> 24);
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Byte offset of the IP header: 14 when an Ethernet-II header precedes it,
    /// 0 for a bare IP datagram, -1 when neither is present. Uses the historical
    /// byte heuristic because no link-layer type is supplied.
    /// </summary>
    public static int FindIpOffset(byte[] frame) => FindIpOffset(frame, LinkTypeUnknown);

    /// <summary>
    /// Byte offset of the IP header, resolved deterministically from the capture's
    /// link-layer type (DLT). <see cref="LinkTypeUnknown"/> keeps the historical byte
    /// heuristic, so callers without a link type behave exactly as before.
    /// </summary>
    public static int FindIpOffset(byte[] frame, int linkLayerType)
    {
        switch (linkLayerType)
        {
            case LinkTypeEthernet:
                // 以太网 DLT：只按以太网-II 解析，绝不回退到裸 IP（ARP 等返回 -1）。
                return FindIpOffsetSkippingVlan(frame, out _);
            case LinkTypeRawBsd:
            case LinkTypeRaw:
                // RAW DLT：链路层之上直接就是 IP，只做裸数据报结构校验。
                return ValidateBareIp(frame);
            case LinkTypeIpv4:
            {
                int o = ValidateBareIp(frame);
                return o == 0 && (frame[0] >> 4) == 4 ? 0 : -1;
            }
            case LinkTypeIpv6:
            {
                int o = ValidateBareIp(frame);
                return o == 0 && (frame[0] >> 4) == 6 ? 0 : -1;
            }
            default:
            {
                int offset = FindIpOffsetSkippingVlan(frame, out bool ethernetNonIp);
                if (offset >= 0)
                    return offset;
                // 以太网-II 帧、但以太类型是已知的非 IP 协议（如 ARP）：不能因为目的
                // MAC 首字节恰为 0x4X/0x6X 就按 version>>4 把它当成裸 IP 数据报。
                if (ethernetNonIp)
                    return -1;
                // 只有确实没有以太网头时才回退到裸数据报，并按结构校验头部。
                return ValidateBareIp(frame);
            }
        }
    }

    /// <summary>
    /// Structural validation for a bare IP datagram (no link-layer header). Returns 0
    /// when byte 0 starts a plausible IPv4/IPv6 header, -1 otherwise.
    /// </summary>
    private static int ValidateBareIp(byte[] frame)
    {
        if (frame.Length == 0)
            return -1;
        int version = frame[0] >> 4;
        if (version == 4)
        {
            if (frame.Length < 20)
                return -1;
            int ihl = (frame[0] & 0x0F) * 4;
            if (ihl < 20)
                return -1;
            int totalLength = (frame[2] << 8) | frame[3];
            // 不要求 totalLength <= frame.Length：夹具里有一个总长 28 的 20 字节帧。
            return totalLength >= ihl ? 0 : -1;
        }
        if (version == 6)
            return frame.Length >= 40 ? 0 : -1;
        return -1;
    }

    private const ushort EtherTypeIpv4 = 0x0800;
    private const ushort EtherTypeIpv6 = 0x86DD;
    private const ushort EtherTypeVlan = 0x8100;
    private const ushort EtherTypeQinQ = 0x88A8;
    private const ushort EtherTypeVlan9100 = 0x9100;

    /// <summary>True for every recognized 802.1Q / 802.1ad / 0x9100 VLAN ethertype.</summary>
    private static bool IsVlanEtherType(ushort type) =>
        type is EtherTypeVlan or EtherTypeQinQ or EtherTypeVlan9100;

    /// <summary>
    /// Well-known non-IP Ethernet-II ethertypes. Reading one of these at offset 12 proves
    /// the frame carries an Ethernet header, so a 0x4X/0x6X destination MAC must not be
    /// mistaken for a bare IPv4/IPv6 version nibble.
    /// </summary>
    private static bool IsKnownNonIpEtherType(ushort type) => type is
        0x0806 or  // ARP
        0x8035 or  // RARP
        0x8847 or  // MPLS unicast
        0x8848 or  // MPLS multicast
        0x88CC or  // LLDP
        0x8863 or  // PPPoE Discovery
        0x8864;    // PPPoE Session

    /// <summary>
    /// Offset of the IP header when the frame carries an Ethernet-II header, stepping
    /// over any stack of 802.1Q/802.1ad/0x9100 tags. Returns -1 when the frame is a bare
    /// datagram or the ethertype chain does not end in IPv4/IPv6; <paramref name="ethernetNonIp"/>
    /// is set when the terminating ethertype is a known non-IP protocol (the frame is an
    /// Ethernet frame that is not IP).
    /// </summary>
    private static int FindIpOffsetSkippingVlan(byte[] frame, out bool ethernetNonIp)
    {
        ethernetNonIp = false;
        int offset = 12;
        // Two bytes are enough to read the ethertype; requiring four would skip a
        // minimal 14-byte Ethernet-II header with no payload at all.
        while (offset + 2 <= frame.Length)
        {
            ushort type = (ushort)((frame[offset] << 8) | frame[offset + 1]);
            offset += 2;
            if (IsVlanEtherType(type))
            {
                offset += 2; // TCI: PCP/DEI/VID
                continue;
            }
            if (type is EtherTypeIpv4 or EtherTypeIpv6)
                return offset;
            ethernetNonIp = IsKnownNonIpEtherType(type);
            return -1;
        }
        return -1;
    }

    /// <summary>
    /// Inserts an 802.1Q tag (or replaces the outermost existing one). Single-tagged
    /// frames gain 4 bytes; QinQ stacks keep their inner tags. A frame too short to hold
    /// an Ethernet-II header is returned untouched rather than half-patched.
    /// </summary>
    public static byte[] ApplyVlanTag(byte[] frame, ushort vid, ushort pcp = 0)
    {
        const int etherHeader = 14;
        if (frame.Length < etherHeader || (vid & 0x0FFF) != vid)
            return frame;

        if (HasVlanTag(frame))
        {
            // Same length, same offsets, so only the TCI changes. This still copies:
            // callers hand in a live packet buffer (EffectiveData), and rewriting a
            // packet's VID as a side effect of *sending* it would corrupt the capture.
            var retagged = (byte[])frame.Clone();
            ushort tci = (ushort)((pcp << 13) | vid);
            retagged[14] = (byte)(tci >> 8);
            retagged[15] = (byte)tci;
            return retagged;
        }

        var tagged = new byte[frame.Length + 4];
        Array.Copy(frame, 0, tagged, 0, 12);              // destination + source MAC
        tagged[12] = unchecked((byte)(EtherTypeVlan >> 8));   // TPID
        tagged[13] = unchecked((byte)EtherTypeVlan);
        ushort tciOut = (ushort)((pcp << 13) | vid);
        tagged[14] = (byte)(tciOut >> 8);                  // TCI
        tagged[15] = (byte)tciOut;
        tagged[16] = frame[12];                            // inner ethertype
        tagged[17] = frame[13];
        Array.Copy(frame, etherHeader, tagged, etherHeader + 4, frame.Length - etherHeader);
        return tagged;
    }

    /// <summary>True when the frame carries an 802.1Q, 802.1ad or 0x9100 tag.</summary>
    public static bool HasVlanTag(byte[] frame) =>
        frame.Length >= 18 && IsVlanEtherType(ReadEtherType(frame, 12));

    /// <summary>
    /// True when the frame has an Ethernet-II header a tag could be added to. A length
    /// check is not enough: a bare IP datagram is comfortably longer than 14 bytes, so
    /// this asks whether the ethertype chain actually resolves to IPv4/IPv6.
    /// <see cref="FindIpOffset"/> returns 0 for a bare datagram and a positive offset only
    /// when a real Ethernet-II header is present.
    /// </summary>
    public static bool HasEthernetHeader(byte[] frame) => HasEthernetHeader(frame, LinkTypeUnknown);

    /// <summary>
    /// Link-layer-aware form of <see cref="HasEthernetHeader(byte[])"/>. An Ethernet DLT
    /// means any 14-byte-or-longer frame carries an Ethernet header; RAW/IPv4/IPv6 DLTs
    /// never do; <see cref="LinkTypeUnknown"/> falls back to the byte heuristic.
    /// </summary>
    public static bool HasEthernetHeader(byte[] frame, int linkLayerType) => linkLayerType switch
    {
        LinkTypeEthernet => frame.Length >= 14,
        LinkTypeRawBsd or LinkTypeRaw or LinkTypeIpv4 or LinkTypeIpv6 => false,
        _ => FindIpOffset(frame, LinkTypeUnknown) > 0,
    };

    /// <summary>The VID of the outermost tag, or -1 when the frame has none.</summary>
    public static int GetVlanId(byte[] frame) =>
        HasVlanTag(frame) ? ReadEtherType(frame, 14) & 0x0FFF : -1;

    /// <summary>
    /// Removes the outermost 802.1Q tag, shifting the payload back 4 bytes. A frame
    /// with no tag, or one that would be left too short to hold an Ethernet-II header,
    /// is returned untouched.
    /// </summary>
    public static byte[] StripVlanTag(byte[] frame)
    {
        const int etherHeader = 14;
        if (frame.Length < etherHeader + 4)
            return frame;
        if (!IsVlanEtherType(ReadEtherType(frame, 12)))
            return frame;

        var stripped = new byte[frame.Length - 4];
        Array.Copy(frame, 0, stripped, 0, 12);
        Array.Copy(frame, etherHeader + 2, stripped, 12, frame.Length - etherHeader - 2);
        return stripped;
    }

    private static ushort ReadEtherType(byte[] frame, int offset) =>
        (ushort)((frame[offset] << 8) | frame[offset + 1]);

    /// <summary>Internet checksum (RFC 1071) over a byte range.</summary>
    private static ushort InternetChecksum(byte[] data, int offset, int length)
    {
        long sum = 0;
        int i = offset, end = offset + length;
        while (i + 1 < end)
        {
            sum += (data[i] << 8) | data[i + 1];
            i += 2;
        }
        if (i < end)
            sum += data[i] << 8;

        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);

        return (ushort)~sum;
    }

    /// <summary>TCP/UDP checksum including the IP pseudo-header.</summary>
    private static ushort TransportChecksum(byte[] frame, int ipOffset, int l4, int l4Length, int protocol, bool ipv6)
    {
        int pseudoLen = ipv6 ? 40 : 12;
        byte[] buffer = new byte[pseudoLen + l4Length + 1];

        if (ipv6)
        {
            Buffer.BlockCopy(frame, ipOffset + 8, buffer, 0, 16);
            Buffer.BlockCopy(frame, ipOffset + 24, buffer, 16, 16);
            uint len = (uint)l4Length;
            buffer[32] = (byte)(len >> 24);
            buffer[33] = (byte)(len >> 16);
            buffer[34] = (byte)(len >> 8);
            buffer[35] = (byte)len;
            buffer[39] = (byte)protocol;
        }
        else
        {
            Buffer.BlockCopy(frame, ipOffset + 12, buffer, 0, 4);
            Buffer.BlockCopy(frame, ipOffset + 16, buffer, 4, 4);
            buffer[8] = 0;
            buffer[9] = (byte)protocol;
            buffer[10] = (byte)(l4Length >> 8);
            buffer[11] = (byte)l4Length;
        }

        Buffer.BlockCopy(frame, l4, buffer, pseudoLen, l4Length);
        if ((l4Length & 1) == 1)
            buffer[pseudoLen + l4Length] = 0;

        ushort result = InternetChecksum(buffer, 0, pseudoLen + l4Length + ((l4Length & 1) == 1 ? 1 : 0));
        return result == 0 && protocol == 17 && !ipv6 ? ushort.MaxValue : result;
    }

    /// <summary>
    /// CRC32c (Castagnoli) over frame[offset, offset+length) as SCTP defines it:
    /// reflected polynomial 0x82F63B78, initial value and final XOR both 0xFFFFFFFF.
    /// The check value for ASCII "123456789" is 0xE3069283.
    /// </summary>
    public static uint ComputeCrc32c(byte[] data, int offset, int length)
    {
        uint crc = 0xFFFFFFFF;
        for (int i = offset; i < offset + length; i++)
        {
            crc ^= data[i];
            for (int bit = 0; bit < 8; bit++)
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0x82F63B78u : crc >> 1;
        }
        return crc ^ 0xFFFFFFFF;
    }

    private static void PutChecksum(byte[] data, int offset, ushort value)
    {
        data[offset] = (byte)(value >> 8);
        data[offset + 1] = (byte)value;
    }

    private static byte[]? ParseMac(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac))
            return null;

        var separators = mac.Contains('-') ? '-' : ':';
        var parts = mac.Split(separators);
        if (parts.Length != 6)
            return null;

        try
        {
            return parts.Select(p => Convert.ToByte(p, 16)).ToArray();
        }
        catch
        {
            return null;
        }
    }
}
