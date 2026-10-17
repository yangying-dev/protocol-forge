using System.Text;

namespace ProtocolForge.Services;

/// <summary>
/// Invoked by a context provider to run one tshark fields pass over the capture.
/// Returns the raw output lines; providers own the tab/field parsing.
/// </summary>
public delegate Task<IReadOnlyList<string>> TsharkFieldsReader(
    string displayFilter,
    IReadOnlyList<string> fields,
    CancellationToken ct);

/// <summary>
/// Discovers frames that must precede a target frame in a per-packet temp PCAP so
/// tshark can dissect the target with cross-frame state (an RTP codec mapping carried
/// in an earlier SDP body, the sibling fragments of an IP datagram, etc.).
///
/// Providers own BOTH their whole-capture scan and the decision of when it runs:
/// scanning is deferred until the first <see cref="CollectFramesAsync"/> call, so
/// captures that never need a given context pay no tshark processes for it at load
/// time. Adding a new context dependency means adding a new provider implementation
/// to the document's provider list — no caller logic changes.
/// </summary>
public interface IPacketContextProvider
{
    /// <summary>Short name used in diagnostics/logging.</summary>
    string Name { get; }

    /// <summary>
    /// Frame numbers (1-based) that this provider contributes as context for
    /// <paramref name="targetFrame"/>. <paramref name="seedFrames"/> carries the
    /// frames already selected by earlier providers in the chain; a provider whose
    /// closure depends on other frames (e.g. the IP-fragment provider expands over
    /// any seed that is itself fragmented) uses them as extra BFS seeds. The target
    /// frame is never included in the result.
    /// </summary>
    Task<IReadOnlyList<int>> CollectFramesAsync(
        int targetFrame,
        IReadOnlyCollection<int> seedFrames,
        CancellationToken ct = default);
}

/// <summary>
/// Context provider for SDP signaling frames. RTP payload types are dynamic: the
/// codec mapping (e.g. AMR-WB = 104) is carried in SDP offer/answer bodies earlier
/// in the capture. Prepending those SDP frames lets tshark dissect the RTP payload
/// of the target packet correctly. The whole-capture SDP scan runs lazily on the
/// first <see cref="CollectFramesAsync"/> call.
/// </summary>
public sealed class SdpContextProvider : IPacketContextProvider
{
    private readonly TsharkFieldsReader _reader;
    private readonly object _gate = new();
    private Task<List<int>>? _scan;

    public SdpContextProvider(TsharkFieldsReader reader)
    {
        _reader = reader;
    }

    public string Name => "sdp";

    public async Task<IReadOnlyList<int>> CollectFramesAsync(
        int targetFrame,
        IReadOnlyCollection<int> seedFrames,
        CancellationToken ct = default)
    {
        var frames = await GetOrStartScanAsync(ct);
        return frames.Where(f => f > 0 && f != targetFrame).ToList();
    }

    private Task<List<int>> GetOrStartScanAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            if (_scan is null || _scan.IsFaulted)
                _scan = ScanAsync(ct);
            return _scan;
        }
    }

    private async Task<List<int>> ScanAsync(CancellationToken ct)
    {
        var lines = await _reader("sdp", ["frame.number"], ct);
        var frames = new List<int>(lines.Count);
        foreach (var line in lines)
        {
            if (int.TryParse(line, out int frameNumber) && frameNumber > 0)
                frames.Add(frameNumber);
        }
        return frames;
    }
}

/// <summary>
/// Context provider for IP fragmentation. A fragmented datagram can only be
/// reassembled by tshark when all of its members precede the target frame. The
/// provider indexes fragment groups by <c>ip.id|ip.src|ip.dst</c> and computes a
/// closure over the groups seeded by the target frame plus any already-selected
/// context frames — covering nested outer+inner fragmentation (e.g. GTP-tunneled
/// SIP split across multiple IP fragments). The whole-capture fragment scan runs
/// lazily on the first <see cref="CollectFramesAsync"/> call.
/// </summary>
public sealed class FragmentContextProvider : IPacketContextProvider
{
    private readonly TsharkFieldsReader _reader;
    private readonly object _gate = new();
    private Task<Dictionary<string, List<int>>>? _scan;

    public FragmentContextProvider(TsharkFieldsReader reader)
    {
        _reader = reader;
    }

    public string Name => "ip-fragment";

    public async Task<IReadOnlyList<int>> CollectFramesAsync(
        int targetFrame,
        IReadOnlyCollection<int> seedFrames,
        CancellationToken ct = default)
    {
        var groups = await GetOrStartScanAsync(ct);
        if (groups.Count == 0)
            return [];

        // BFS closure: for each frame we know must be in the temp pcap, pull in
        // that frame's fragment-group members with a lower frame number, expanding
        // transitively so a fragment of a fragment also brings its own siblings.
        var selected = new HashSet<int>();
        var known = new HashSet<int>();
        var queue = new Queue<int>();

        foreach (var seed in seedFrames)
        {
            if (seed > 0 && known.Add(seed))
                queue.Enqueue(seed);
        }
        known.Add(targetFrame);
        queue.Enqueue(targetFrame);

        while (queue.Count > 0)
        {
            int fn = queue.Dequeue();
            foreach (var members in groups.Values)
            {
                if (!members.Contains(fn))
                    continue;
                foreach (var m in members)
                {
                    if (m >= fn || !known.Add(m))
                        continue; // only earlier members; never the target
                    selected.Add(m);
                    queue.Enqueue(m);
                }
            }
        }

        return selected.OrderBy(x => x).ToList();
    }

    private Task<Dictionary<string, List<int>>> GetOrStartScanAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            if (_scan is null || _scan.IsFaulted)
                _scan = ScanAsync(ct);
            return _scan;
        }
    }

    private async Task<Dictionary<string, List<int>>> ScanAsync(CancellationToken ct)
    {
        var lines = await _reader(
            "ip.flags.mf==1 || ip.frag_offset>0",
            ["frame.number", "ip.id", "ip.src", "ip.dst"],
            ct);

        var groups = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        foreach (var line in lines)
        {
            var cols = line.Split('\t');
            if (cols.Length < 4 || !int.TryParse(cols[0], out int frameNumber))
                continue;

            var ids = cols[1].Split(',');
            var srcs = cols[2].Split(',');
            var dsts = cols[3].Split(',');
            int count = Math.Min(ids.Length, Math.Min(srcs.Length, dsts.Length));

            for (int i = 0; i < count; i++)
            {
                string key = $"{ids[i]}|{srcs[i]}|{dsts[i]}";
                if (!groups.TryGetValue(key, out var list))
                {
                    list = [];
                    groups[key] = list;
                }
                if (!list.Contains(frameNumber))
                    list.Add(frameNumber);
            }
        }

        foreach (var list in groups.Values)
            list.Sort();

        return groups;
    }
}

/// <summary>One transport stream: its tshark stream id, the frames belonging to it, and the protocol it was indexed under (tcp or udp).</summary>
public sealed record StreamIndex(string StreamId, IReadOnlyList<int> Frames, string Protocol);

/// <summary>
/// Whole-capture stream index shared by the TCP and UDP stream providers: one lazy
/// tshark fields pass keyed by the protocol's stream field, plus the id↔frame lookups
/// both providers expose. The scan runs once on first query and is dropped by
/// <see cref="Invalidate"/>, after which the next query re-reads the capture.
/// </summary>
internal sealed class StreamIndexScanner
{
    private readonly TsharkFieldsReader _reader;
    private readonly string _filter;
    private readonly string _streamField;
    private readonly string _protocol;
    private readonly object _gate = new();
    private Dictionary<string, List<int>>? _streamFrames;
    private Dictionary<int, string>? _frameStreams;
    private Task? _scan;

    public StreamIndexScanner(TsharkFieldsReader reader, string filter, string streamField, string protocol)
    {
        _reader = reader;
        _filter = filter;
        _streamField = streamField;
        _protocol = protocol;
    }

    /// <summary>Streams by id after a scan; null before the first one.</summary>
    public Dictionary<string, List<int>>? StreamFrames => _streamFrames;

    /// <summary>Frame → stream id after a scan; null before the first one.</summary>
    public Dictionary<int, string>? FrameStreams => _frameStreams;

    public async Task<IReadOnlyList<StreamIndex>> GetStreamsAsync(CancellationToken ct = default)
    {
        await EnsureScannedAsync(ct);
        if (_streamFrames is null)
            return [];

        return _streamFrames
            .OrderBy(kv => kv.Key, StringComparer.Ordinal)
            .Select(kv => new StreamIndex(kv.Key, kv.Value.OrderBy(n => n).ToList(), _protocol))
            .ToList();
    }

    public async Task<string?> GetStreamOfFrameAsync(int frameNumber, CancellationToken ct = default)
    {
        await EnsureScannedAsync(ct);
        return _frameStreams is not null && _frameStreams.TryGetValue(frameNumber, out string? s) ? s : null;
    }

    public void Invalidate()
    {
        lock (_gate)
        {
            _scan = null;
            _streamFrames = null;
            _frameStreams = null;
        }
    }

    public async Task EnsureScannedAsync(CancellationToken ct)
    {
        Task scan;
        lock (_gate)
        {
            if (_scan is null || _scan.IsFaulted)
                _scan = ScanAsync(ct);
            scan = _scan;
        }
        await scan;
    }

    private async Task ScanAsync(CancellationToken ct)
    {
        var lines = await _reader(_filter, ["frame.number", _streamField], ct);

        var streamFrames = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        var frameStreams = new Dictionary<int, string>();
        foreach (var line in lines)
        {
            var cols = line.Split('\t');
            if (cols.Length < 2 || !int.TryParse(cols[0], out int frameNumber))
                continue;

            // The stream field is a single scalar per frame; take the first token to
            // stay robust against any multi-value or empty output form.
            string sid = cols[1].Split(',')[0];
            if (sid.Length == 0)
                continue;

            // tshark emits frames in capture order, so appending keeps the
            // stream lists ascending without a sort pass.
            if (!streamFrames.TryGetValue(sid, out var list))
            {
                list = [];
                streamFrames[sid] = list;
            }
            list.Add(frameNumber);
            frameStreams[frameNumber] = sid;
        }

        _streamFrames = streamFrames;
        _frameStreams = frameStreams;
    }
}

/// <summary>
/// Context provider for TCP stream reassembly. When a packet is a segment of a
/// multi-segment TCP message (an HTTP body spanning thousands of segments, a SIP
/// INVITE split over TCP segments, a Diameter message across segments, etc.),
/// tshark can only reassemble and dissect the full message when its preceding
/// segments ride along in the per-packet temp PCAP. This provider indexes every
/// TCP stream (keyed by <c>tcp.stream</c>) and contributes, for the target frame
/// and any seed frames, that stream's segments that precede the target — so the
/// message containing the target, and the conversation state before it, are
/// present for tshark's transport-layer reassembly.
///
/// A budget bounds how many context segments are contributed per build: a
/// multi-thousand-segment download must not make every per-packet tshark pass
/// chew through an enormous temp PCAP. Segments nearest the target are kept
/// first; when the budget cuts in, tshark dissects what it can and reports the
/// remainder as "TCP segment of a reassembled PDU" in the tree instead of a
/// fully reassembled message. The whole-capture stream scan runs lazily on the
/// first <see cref="CollectFramesAsync"/> call.
/// </summary>
public sealed class TcpStreamContextProvider : IPacketContextProvider
{
    public const int DefaultBudget = 2000;

    private readonly StreamIndexScanner _scanner;
    private readonly int _budget;

    public TcpStreamContextProvider(TsharkFieldsReader reader, int budget = DefaultBudget)
    {
        _scanner = new StreamIndexScanner(reader, "tcp", "tcp.stream", "tcp");
        _budget = budget;
    }

    public string Name => "tcp-stream";

    /// <summary>
    /// Every TCP stream in the capture with its frame numbers, ordered by stream id.
    ///
    /// The scan that builds this already runs for reassembly, so exposing it costs
    /// nothing extra; it was simply being thrown away. Returns empty until
    /// <see cref="CollectFramesAsync"/> has triggered the lazy scan.
    /// </summary>
    public Task<IReadOnlyList<StreamIndex>> GetStreamsAsync(CancellationToken ct = default) =>
        _scanner.GetStreamsAsync(ct);

    /// <summary>
    /// Drops the cached scan so the next query re-reads the capture. A committed edit
    /// can move a frame between streams — tshark keys streams on the four-tuple and its
    /// SYN/FIN boundaries, so editing a port or address rewrites the answer — and a
    /// length-changing edit shifts which frames exist in the index at all. Cheap by
    /// design: it only drops state, the rescan happens on the next query.
    /// </summary>
    public void Invalidate() => _scanner.Invalidate();

    /// <summary>The stream a given frame belongs to, or null when it is not TCP.</summary>
    public Task<string?> GetStreamOfFrameAsync(int frameNumber, CancellationToken ct = default) =>
        _scanner.GetStreamOfFrameAsync(frameNumber, ct);

    public async Task<IReadOnlyList<int>> CollectFramesAsync(
        int targetFrame,
        IReadOnlyCollection<int> seedFrames,
        CancellationToken ct = default)
    {
        await _scanner.EnsureScannedAsync(ct);
        var streamFrames = _scanner.StreamFrames;
        var frameStreams = _scanner.FrameStreams;
        if (streamFrames is null || frameStreams is null)
            return [];

        var wanted = new HashSet<string>(StringComparer.Ordinal);
        if (frameStreams.TryGetValue(targetFrame, out var stream))
            wanted.Add(stream);
        foreach (var seed in seedFrames)
        {
            if (seed > 0 && frameStreams.TryGetValue(seed, out var seedStream))
                wanted.Add(seedStream);
        }

        var selected = new HashSet<int>();
        foreach (var sid in wanted)
        {
            // Walk the stream's ascending frame list backwards from the first
            // segment at/after the target, keeping the NEAREST segments first so
            // a small budget protects the reassembly of the immediate message.
            var frames = streamFrames[sid];
            int idx = frames.BinarySearch(targetFrame);
            int start = (idx >= 0 ? idx : ~idx) - 1;
            for (int k = start; k >= 0 && selected.Count < _budget; k--)
                selected.Add(frames[k]);
        }

        return selected.OrderBy(x => x).ToList();
    }
}

/// <summary>
/// Stream index for UDP conversations (tshark's <c>udp.stream</c>) so the
/// follow-stream UI covers protocols that run over UDP (GTP-U, PFCP, …), not only
/// TCP. UDP is stateless at the transport layer — no datagram needs another to be
/// dissected (IP fragments are already covered by <see cref="FragmentContextProvider"/>)
/// — so unlike the TCP provider this one contributes no context frames and exists
/// purely to expose the conversation index. The scan runs lazily on the first query.
/// </summary>
public sealed class UdpStreamContextProvider : IPacketContextProvider
{
    private readonly StreamIndexScanner _scanner;

    public UdpStreamContextProvider(TsharkFieldsReader reader) =>
        _scanner = new StreamIndexScanner(reader, "udp", "udp.stream", "udp");

    public string Name => "udp-stream";

    public Task<IReadOnlyList<int>> CollectFramesAsync(
        int targetFrame,
        IReadOnlyCollection<int> seedFrames,
        CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<int>>([]);

    public Task<IReadOnlyList<StreamIndex>> GetStreamsAsync(CancellationToken ct = default) =>
        _scanner.GetStreamsAsync(ct);

    public void Invalidate() => _scanner.Invalidate();

    public Task<string?> GetStreamOfFrameAsync(int frameNumber, CancellationToken ct = default) =>
        _scanner.GetStreamOfFrameAsync(frameNumber, ct);
}