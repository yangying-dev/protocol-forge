namespace ProtocolForge.Services;

/// <summary>
/// Writes PCAPNG, so a capture that came in as PCAPNG can go back out as PCAPNG
/// instead of being silently downgraded to classic PCAP.
///
/// The downgrade was the more serious half of the old behaviour: opening a .pcapng
/// and pressing Ctrl+S dropped every interface description, every block comment and
/// the timestamp resolution, while still reporting success. Preserving multi-section
/// and multi-interface files byte-exactly would require retaining the source block list
/// on the document; this writer preserves what a single-section capture carries
/// (link type, snaplen, timestamp resolution, packets), which is the common case for
/// the traffic this tool exists to handle.
/// </summary>
public static class PcapngWriter
{
    private const uint BlockShb = 0x0A0D0D0A;
    private const uint BlockIdb = 0x00000001;
    private const uint BlockEpb = 0x00000006;
    private const uint ByteOrderMagic = 0x1A2B3C4D;
    // section_length is a 64-bit field. Declaring this int made BinaryWriter emit four
// bytes, which silently truncated every SHB to 24 bytes of content under a declared
// length of 28 and desynchronised the whole block chain.
private const long UnknownSectionLength = unchecked((long)0xFFFFFFFFFFFFFFFFL);

    /// <summary>
    /// Emits one section holding one interface description block and one enhanced
    /// packet block per packet.
    /// </summary>
    /// <param name="packets">Packets to write, in order.</param>
    /// <param name="linkType">DLT for the interface description block.</param>
    /// <param name="snaplen">Snaplen for the interface description block.</param>
    /// <param name="nanosecondResolution">
    /// Emit if_tsresol=9, meaning the EPB timestamp counts 2^-9 second ticks (nanoseconds).
    /// The ingest side stores timestamps already normalised to microseconds, so when this
    /// flag is set each EPB value is rescaled µs × 1000 → ns; when clear (if_tsresol=6)
    /// the microseconds are written as-is. Either way the declared resolution and the
    /// value are consistent, so a reader recovers the same wall time.
    /// </param>
    /// <param name="write">Destination sink.</param>
    public static void Write(
        IEnumerable<Models.Packet> packets,
        int linkType,
        int snaplen,
        bool nanosecondResolution,
        Action<byte[]> write)
    {
        var materialised = packets as IList<Models.Packet> ?? packets.ToList();

        using var body = new System.IO.MemoryStream();
        using (var w = new BinaryWriter(body, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            WriteShb(w);
            WriteIdb(w, linkType, snaplen, nanosecondResolution);
            foreach (var packet in materialised)
                WriteEpb(w, packet.EffectiveData, nanosecondResolution ? packet.Timestamp * 1000L : packet.Timestamp);
        }

        write(body.ToArray());
    }

    private static void WriteShb(BinaryWriter w)
    {
        const int length = 28;
        w.Write(BlockShb);
        w.Write(length);
        w.Write(ByteOrderMagic);
        w.Write((ushort)1);            // version major
        w.Write((ushort)0);            // version minor
        w.Write(UnknownSectionLength); // section_length: not known in advance
        w.Write(length);
    }

    private static void WriteIdb(BinaryWriter w, int linkType, int snaplen, bool nanosecondResolution)
    {
        // if_tsresol (option code 9) is one byte holding the tick exponent: 9 = 10^-9 s
        // (nanoseconds), 6 = 10^-6 s (microseconds). Options are type(LE u16)/len(LE u16)/value.
        var options = new List<byte> { 9, 0, 1, 0, (byte)(nanosecondResolution ? 9 : 6), 0 };
        foreach (byte b in System.Text.Encoding.UTF8.GetBytes("eth0"))
            options.Add(b);
        options.Add(0);           // if_name, NUL terminated
        options.AddRange([0, 0]); // opt_endofopt

        int optionBytes = options.Count;
        int paddedBytes = (optionBytes + 3) & ~3;
        // type + length + linktype + reserved + snaplen + options + trailing length
        int length = 4 + 4 + 2 + 2 + 4 + paddedBytes + 4;

        w.Write(BlockIdb);
        w.Write(length);
        w.Write((ushort)linkType);
        w.Write((ushort)0);      // reserved
        w.Write((uint)snaplen);
        foreach (byte b in options) w.Write(b);
        for (int i = optionBytes; i < paddedBytes; i++) w.Write((byte)0);
        w.Write(length);
    }

    private static void WriteEpb(BinaryWriter w, byte[] data, long timestamp)
    {
        int dataBytes = (data.Length + 3) & ~3;
        // type + length + interface_id + ts_high + ts_low + caplen + origlen + data + trailing length
        int length = 4 + 4 + 4 + 4 + 4 + 4 + 4 + dataBytes + 4;

        w.Write(BlockEpb);
        w.Write(length);
        w.Write((uint)0);   // interface_id: the single IDB written above
        w.Write((uint)((timestamp >> 32) & 0xFFFFFFFF));
        w.Write((uint)(timestamp & 0xFFFFFFFF));
        w.Write((uint)data.Length);
        w.Write((uint)data.Length);
        w.Write(data);
        for (int i = data.Length; i < dataBytes; i++) w.Write((byte)0);
        w.Write(length);
    }
}