using ProtocolForge.Models;

namespace ProtocolForge.Services;

/// <summary>
/// Reads raw packet bytes from a PCAP/PCAPNG file without relying on Tshark.
/// Handles little-endian and big-endian classic PCAP formats (microsecond and nanosecond timestamps)
/// and PCAPNG (sections, interfaces, enhanced/simple/packet blocks, per-interface timestamps).
/// This gives us raw frame bytes that Tshark's JSON output doesn't include.
/// </summary>
public sealed class PcapIngestService
{
    /// <summary>
    /// Reads the PCAP/PCAPNG file and all packet records.
    /// Returns raw packet data ready to be merged with Tshark-parsed protocol trees.
    /// </summary>
    public async Task<PcapReadResult> ReadPacketsAsync(string filePath, CancellationToken ct = default)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("PCAP file not found", filePath);

        var rawBytes = await File.ReadAllBytesAsync(filePath, ct);
        return ParseRawPcap(rawBytes);
    }

    private static PcapReadResult ParseRawPcap(byte[] data)
    {
        if (data.Length < 24)
            throw new InvalidDataException("File too small to be a valid PCAP.");

        // --- Parse global header ---
        // Read magic as little-endian first to determine file endianness
        uint magic = (uint)(data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24));

        // PCAPNG: Section Header Block magic 0x0A0D0D0A is byte-order palindromic,
        // so a little-endian read of the first 4 bytes always yields 0x0A0D0D0A.
        if (magic == 0x0A0D0D0A)
            return ParsePcapNg(data);

        bool littleEndian;
        bool nanoSeconds;

        switch (magic)
        {
            case 0xa1b2c3d4: littleEndian = true; nanoSeconds = false; break;
            case 0xd4c3b2a1: littleEndian = false; nanoSeconds = false; break;
            case 0xa1b23c4d: littleEndian = true; nanoSeconds = true; break;
            case 0x4d3cb2a1: littleEndian = false; nanoSeconds = true; break;
            default:
                throw new InvalidDataException($"Unknown PCAP magic: 0x{magic:X8}.");
        }

        ushort versionMajor = ReadU16(data, 4, littleEndian);
        ushort versionMinor = ReadU16(data, 6, littleEndian);
        int snaplen = (int)ReadU32(data, 16, littleEndian);
        int linkLayerType = (int)ReadU32(data, 20, littleEndian);

        // --- Parse packet records (starts at offset 24) ---
        int offset = 24;
        var packets = new List<(long Timestamp, byte[] Data)>();

        while (offset + 16 <= data.Length)
        {
            uint tsSec = ReadU32(data, offset, littleEndian);
            uint tsFrac = ReadU32(data, offset + 4, littleEndian);
            uint inclLen = ReadU32(data, offset + 8, littleEndian);
            uint origLen = ReadU32(data, offset + 12, littleEndian);

            offset += 16;

            if (offset + inclLen > data.Length)
                break; // Truncated file

            long timestamp = tsSec * 1_000_000L + (nanoSeconds ? tsFrac / 1000L : tsFrac);
            var packetData = new byte[inclLen];
            Array.Copy(data, offset, packetData, 0, inclLen);

            packets.Add((timestamp, packetData));
            offset += (int)inclLen;
        }

        return new PcapReadResult
        {
            Packets = packets,
            LinkLayerType = linkLayerType,
            Snaplen = snaplen,
            VersionMajor = versionMajor,
            VersionMinor = versionMinor,
            IsLittleEndian = littleEndian,
            IsNanoSeconds = nanoSeconds
        };
    }

    /// <summary>
    /// Parses a PCAPNG file: section headers, interface descriptions, and packet blocks
    /// (enhanced, simple, and legacy). Handles per-section byte order, per-interface
    /// timestamp resolution (10^-n or 2^-n), and multiple sections/interfaces.
    /// </summary>
    private static PcapReadResult ParsePcapNg(byte[] data)
    {
        var packets = new List<(long Timestamp, byte[] Data)>();
        var interfaces = new List<(int LinkType, int Snaplen, int TsResolExp, bool TsResolPow2)>();
        bool littleEndian = true;
        ushort versionMajor = 1, versionMinor = 0;
        int linkLayerType = 1; // LinkType of interface 0; Ethernet default
        int snaplen = 65535;
        long prevTimestamp = 0;

        // 不变式：下面的循环只保证 offset+12 可读，但各 block 的固定字段最远读到
        // offset+32。因此每种 block 都必须先按下限校验 totalLen，再读块内字段，
        // 否则畸形/截断文件会越界抛异常，导致整个抓包打不开而非优雅截断。
        // 下限取自 PCAPNG 规范：SHB 28 / IDB 20 / EPB 32 / SPB 16 / LPB 32。
        int offset = 0;
        while (offset + 12 <= data.Length)
        {
            uint blockTypeLe = ReadU32(data, offset, littleEndian: true);
            bool isSectionHeader = blockTypeLe == 0x0A0D0D0A;

            if (isSectionHeader)
            {
                // Byte-order magic determines the section's endianness.
                uint bom = ReadU32(data, offset + 8, littleEndian: true);
                if (bom == 0x1A2B3C4D)
                    littleEndian = true;
                else if (bom == 0x4D3C2B1A)
                    littleEndian = false;
                else
                    break;

                uint shbLen = ReadU32(data, offset + 4, littleEndian);
                if (shbLen < 28 || offset + shbLen > data.Length)
                    break;

                interfaces.Clear(); // Interface IDs restart per section
                versionMajor = ReadU16(data, offset + 12, littleEndian);
                versionMinor = ReadU16(data, offset + 14, littleEndian);
            }

            uint blockType = isSectionHeader ? 0x0A0D0D0A : ReadU32(data, offset, littleEndian);
            uint totalLen = ReadU32(data, offset + 4, littleEndian);
            if (totalLen < 12 || offset + totalLen > data.Length)
                break;

            switch (blockType)
            {
                case 0x00000001: // Interface Description Block
                    if (totalLen < 20) break;
                    int linkType = ReadU16(data, offset + 8, littleEndian);
                    int snap = (int)ReadU32(data, offset + 12, littleEndian);
                    int resolExp = 6; // Default: 10^-6 s (microseconds)
                    bool resolPow2 = false;
                    ParseInterfaceOptions(data, offset, (int)totalLen, littleEndian, ref resolExp, ref resolPow2);
                    if (interfaces.Count == 0)
                    {
                        linkLayerType = linkType;
                        snaplen = snap;
                    }
                    interfaces.Add((linkType, snap, resolExp, resolPow2));
                    break;

                case 0x00000006: // Enhanced Packet Block
                {
                    if (totalLen < 32) break;
                    uint ifaceId = ReadU32(data, offset + 8, littleEndian);
                    uint tsHigh = ReadU32(data, offset + 12, littleEndian);
                    uint tsLow = ReadU32(data, offset + 16, littleEndian);
                    uint capLen = ReadU32(data, offset + 20, littleEndian);
                    int dataStart = offset + 28;
                    if ((long)dataStart + capLen > (long)offset + totalLen - 4)
                        break; // Captured length exceeds block body
                    long tsMicros = ConvertTimestamp(
                        ((ulong)tsHigh << 32) | tsLow, ifaceId, interfaces);
                    var packetData = new byte[capLen];
                    Array.Copy(data, dataStart, packetData, 0, capLen);
                    packets.Add((tsMicros, packetData));
                    prevTimestamp = tsMicros;
                    break;
                }

                case 0x00000003: // Simple Packet Block (no timestamp, no interface id)
                {
                    if (totalLen < 16) break;
                    uint origLen = ReadU32(data, offset + 8, littleEndian);
                    int avail = (int)totalLen - 16; // 8-byte header + 4-byte origLen + 4-byte trailer
                    int capLen = avail > 0 ? (int)Math.Min(origLen, (uint)avail) : 0;
                    var packetData = new byte[capLen];
                    Array.Copy(data, offset + 12, packetData, 0, capLen);
                    packets.Add((prevTimestamp, packetData));
                    break;
                }

                case 0x00000002: // Legacy Packet Block
                {
                    if (totalLen < 32) break;
                    uint ifaceId = ReadU16(data, offset + 8, littleEndian);
                    uint tsHigh = ReadU32(data, offset + 12, littleEndian);
                    uint tsLow = ReadU32(data, offset + 16, littleEndian);
                    uint capLen = ReadU32(data, offset + 20, littleEndian);
                    int dataStart = offset + 28;
                    if ((long)dataStart + capLen > (long)offset + totalLen - 4)
                        break;
                    long tsMicros = ConvertTimestamp(
                        ((ulong)tsHigh << 32) | tsLow, ifaceId, interfaces);
                    var packetData = new byte[capLen];
                    Array.Copy(data, dataStart, packetData, 0, capLen);
                    packets.Add((tsMicros, packetData));
                    prevTimestamp = tsMicros;
                    break;
                }

                // Other block types (NRB, ISB, DSB, obsolete) carry no packets — skip.
                default:
                    break;
            }

            offset += (int)totalLen;
        }

        return new PcapReadResult
        {
            Packets = packets,
            LinkLayerType = linkLayerType,
            Snaplen = snaplen,
            VersionMajor = versionMajor,
            VersionMinor = versionMinor,
            IsLittleEndian = littleEndian,
            IsNanoSeconds = false // PCAPNG timestamps are normalized to microseconds
        };
    }

    /// <summary>
    /// Scans interface description options for if_tsresol (code 9), which selects the
    /// timestamp unit. MSB set → 2^-n seconds; otherwise 10^-n seconds.
    /// </summary>
    private static void ParseInterfaceOptions(byte[] data, int blockOffset, int blockLen, bool littleEndian, ref int resolExp, ref bool resolPow2)
    {
        int pos = blockOffset + 16;
        int end = blockOffset + blockLen - 4; // Skip trailing block length
        while (pos + 4 <= end)
        {
            ushort code = ReadU16(data, pos, littleEndian);
            ushort len = ReadU16(data, pos + 2, littleEndian);
            if (code == 9 && len >= 1)
            {
                byte b = data[pos + 4];
                resolPow2 = (b & 0x80) != 0;
                resolExp = b & 0x7F;
                return;
            }
            pos += 4 + ((len + 3) & ~3); // Options are padded to 4-byte alignment
        }
    }

    /// <summary>
    /// Converts a raw PCAPNG timestamp to microseconds using the interface's resolution.
    /// </summary>
    private static long ConvertTimestamp(ulong raw, uint ifaceId, List<(int, int, int, bool)> interfaces)
    {
        if (ifaceId < (uint)interfaces.Count)
        {
            var (_, _, resolExp, resolPow2) = interfaces[(int)ifaceId];
            if (resolPow2)
                return (long)Math.Round((double)raw * Math.Pow(2, resolExp) / 1_000_000.0);
            if (resolExp <= 6)
                return (long)Math.Round((double)raw * Math.Pow(10, 6 - resolExp));
            return (long)(raw / Pow10((ulong)(resolExp - 6)));
        }
        return (long)raw; // Unknown interface: assume microseconds
    }

    private static ulong Pow10(ulong exp)
    {
        ulong result = 1;
        for (ulong i = 0; i < exp && result <= ulong.MaxValue / 10; i++)
            result *= 10;
        return result;
    }

    private static ushort ReadU16(byte[] data, int offset, bool littleEndian) =>
        littleEndian
            ? (ushort)(data[offset] | (data[offset + 1] << 8))
            : (ushort)((data[offset] << 8) | data[offset + 1]);

    private static uint ReadU32(byte[] data, int offset, bool littleEndian) =>
        littleEndian
            ? (uint)(data[offset]
                | (data[offset + 1] << 8)
                | (data[offset + 2] << 16)
                | (data[offset + 3] << 24))
            : (uint)((data[offset] << 24)
                | (data[offset + 1] << 16)
                | (data[offset + 2] << 8)
                | data[offset + 3]);
}

/// <summary>
/// Raw PCAP read result with packet data and file metadata.
/// </summary>
public sealed class PcapReadResult
{
    public required List<(long Timestamp, byte[] Data)> Packets { get; init; }
    public int LinkLayerType { get; init; }
    public int Snaplen { get; init; }
    public ushort VersionMajor { get; init; }
    public ushort VersionMinor { get; init; }
    public bool IsLittleEndian { get; init; }
    public bool IsNanoSeconds { get; init; }
}
