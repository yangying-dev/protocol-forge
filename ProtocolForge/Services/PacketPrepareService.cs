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
        }

        return result;
    }

    /// <summary>
    /// Byte offset of the IP header: 14 when an Ethernet-II header precedes it,
    /// 0 for a bare IP datagram, -1 when neither is present.
    /// </summary>
    public static int FindIpOffset(byte[] frame)
    {
        if (frame.Length >= 14 && frame[12] == 0x08 && frame[13] == 0x00)
            return 14;
        if (frame.Length >= 14 && frame[12] == 0x86 && frame[13] == 0xDD)
            return 14;
        int version = frame[0] >> 4;
        return version is 4 or 6 ? 0 : -1;
    }

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
