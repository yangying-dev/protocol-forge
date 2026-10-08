using System.Net.NetworkInformation;

namespace ProtocolForge.Services;

/// <summary>
/// Rewrites a captured frame into a sendable form: source MAC and source IP are
/// replaced with the selected interface's values, and header checksums are
/// recomputed so the frame survives routing and receiver validation.
/// </summary>
public static class PacketPrepareService
{
    /// <summary>
    /// Returns a copy of <paramref name="frame"/> with send-time fixes applied.
    /// Ethernet source MAC → interface MAC, IPv4 source address → interface IPv4,
    /// IPv4 header checksum and TCP/UDP checksums recomputed (UDP stays 0 when it
    /// was 0 — the IPv4 "checksum off" convention; IPv6 always gets a real one).
    /// SCTP's CRC32c is always recomputed and stored little-endian per RFC 4960.
    /// </summary>
    public static byte[] PrepareFrame(byte[] frame, NetworkInterfaceInfo iface)
    {
        if (frame.Length == 0)
            return frame;

        var result = (byte[])frame.Clone();
        int ipOffset = FindIpOffset(result);
        if (ipOffset < 0)
            return result;

        if (ipOffset == 14 && ParseMac(iface.MacAddress) is { } mac)
            Buffer.BlockCopy(mac, 0, result, 6, 6);

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
            if (iface.IPv6Address?.GetAddressBytes() is { Length: 16 } src6)
                Buffer.BlockCopy(src6, 0, result, ipOffset + 8, 16);

            // With extension headers present the transport offset is unknown, so only
            // handle the common no-extension-header case here.
            int l4 = ipOffset + 40;
            if (nextHeader == 6 && result.Length >= l4 + 20)
            {
                int len = (result[ipOffset + 4] << 8) | result[ipOffset + 5];
                if (len > 0 && result.Length >= l4 + len)
                {
                    result[l4 + 16] = 0;
                    result[l4 + 17] = 0;
                    PutChecksum(result, l4 + 16, TransportChecksum(result, ipOffset, l4, len, 6, true));
                }
            }
            else if (nextHeader == 17 && result.Length >= l4 + 8)
            {
                int len = (result[ipOffset + 4] << 8) | result[ipOffset + 5];
                if (len > 0 && result.Length >= l4 + len)
                {
                    result[l4 + 6] = 0;
                    result[l4 + 7] = 0;
                    PutChecksum(result, l4 + 6, TransportChecksum(result, ipOffset, l4, len, 17, true));
                }
            }
            else if (nextHeader == 132 && result.Length >= l4 + 12)
            {
                int len = (result[ipOffset + 4] << 8) | result[ipOffset + 5];
                if (len >= 12 && result.Length >= l4 + len)
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
    /// 0 for a bare IP datagram, -1 when neither is present.
    /// </summary>
    public static int FindIpOffset(byte[] frame)
    {
        int offset = FindIpOffsetSkippingVlan(frame);
        if (offset >= 0)
            return offset;
        int version = frame[0] >> 4;
        return version is 4 or 6 ? 0 : -1;
    }

    private const ushort EtherTypeIpv4 = 0x0800;
    private const ushort EtherTypeIpv6 = 0x86DD;
    private const ushort EtherTypeVlan = 0x8100;
    private const ushort EtherTypeQinQ = 0x88A8;
    private const ushort EtherTypeVlan9100 = 0x9100;

    /// <summary>
    /// Offset of the IP header when the frame carries an Ethernet-II header, stepping
    /// over any stack of 802.1Q/802.1ad tags. Returns -1 when the frame is a bare
    /// datagram or the ethertype chain does not end in IPv4/IPv6.
    /// </summary>
    private static int FindIpOffsetSkippingVlan(byte[] frame)
    {
        int offset = 12;
        // Two bytes are enough to read the ethertype; requiring four would skip a
        // minimal 14-byte Ethernet-II header with no payload at all.
        while (offset + 2 <= frame.Length)
        {
            ushort type = (ushort)((frame[offset] << 8) | frame[offset + 1]);
            offset += 2;
            if (type is EtherTypeVlan or EtherTypeQinQ or EtherTypeVlan9100)
            {
                offset += 2; // TCI: PCP/DEI/VID
                continue;
            }
            return type is EtherTypeIpv4 or EtherTypeIpv6 ? offset : -1;
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

    /// <summary>True when the frame carries an 802.1Q or 802.1ad tag.</summary>
    public static bool HasVlanTag(byte[] frame) =>
        frame.Length >= 18 && ReadEtherType(frame, 12) is EtherTypeVlan or EtherTypeQinQ;

    /// <summary>
    /// True when the frame has an Ethernet-II header a tag could be added to. A length
    /// check is not enough: a bare IP datagram is comfortably longer than 14 bytes, so
    /// this asks whether the ethertype chain actually resolves to IPv4/IPv6.
    /// <see cref="FindIpOffset"/> returns 0 for a bare datagram and a positive offset only
    /// when a real Ethernet-II header is present.
    /// </summary>
    public static bool HasEthernetHeader(byte[] frame) => FindIpOffset(frame) > 0;

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
        if (ReadEtherType(frame, 12) is not (EtherTypeVlan or EtherTypeQinQ))
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
