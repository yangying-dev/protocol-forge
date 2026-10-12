using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Collections.ObjectModel;
using ProtocolForge.Models;
using ProtocolForge;
using Avalonia.Media.Imaging;
using Avalonia.VisualTree;
using Avalonia.Headless;
using Avalonia.Controls;
using Avalonia;
using ProtocolForge.Services;
using ProtocolForge.ViewModels;
using Dock.Model.Core;
using Dock.Avalonia.Controls;
using Dock.Avalonia.Contract;
using Dock.Settings;
using Avalonia.Input;

// ── Path resolution: locate repo root by walking up to ProtocolForge.sln ──
static string FindRepoRoot()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir != null)
    {
        if (File.Exists(Path.Combine(dir.FullName, "ProtocolForge.sln")))
            return dir.FullName;
        dir = dir.Parent;
    }
    throw new InvalidOperationException("Cannot locate repo root (ProtocolForge.sln)");
}

// Real captures are local-only and CI forbids committing them, so the groups that need
// one are skipped rather than failed. PF_CAPTURE points the harness at a local fixture.
// There is deliberately no fallback path: a hardcoded default would be a dead string that
// looks like it works, and any real name in it would disclose operator details.
static string? ResolveCapturePath(string root)
{
    string? configured = Environment.GetEnvironmentVariable("PF_CAPTURE");
    if (string.IsNullOrWhiteSpace(configured))
        return null;
    return Path.IsPathRooted(configured) ? configured : Path.Combine(root, configured);
}

string repoRoot = FindRepoRoot();
// G1/G2/G16/G19 index frame 4413 unconditionally, so a generated fixture must be at
// least that long or those groups fail instead of reporting a short file.
const int RequiredCaptureFrames = 4413;
// Keep the guard a null test, not a separate bool: a bool cannot narrow the type
// and every call site then fails with CS8604.
string? PcapPath = ResolveCapturePath(repoRoot);
if (PcapPath is not null && !File.Exists(PcapPath)) PcapPath = null;

// `--ui` needs no capture fixture, and building a 4413-frame one for a UI check is
// pure waste.
bool uiOnly = args.Contains("--ui", StringComparer.Ordinal);
string? generatedCapture = null;
if (PcapPath is null && !uiOnly)
{
    // The capture groups used to skip here, which meant the headline behaviour —
    // edit fence, Verify-Before-Commit, address re-extraction — never ran in CI.
    // A synthetic fixture built from the same bytes as the other groups closes
    // that gap without committing a capture: the no-pcap rule stays absolute
    // because the file is generated into the temp directory and deleted after.
    generatedCapture = Path.Combine(Path.GetTempPath(), $"pf_verify_capture_{Guid.NewGuid():N}.pcap");
    await File.WriteAllBytesAsync(generatedCapture, BuildGeneratedCaptureFixture());
    PcapPath = generatedCapture;
    Console.WriteLine($"PF_CAPTURE unset — generated a {RequiredCaptureFrames}-frame synthetic capture for the capture-dependent groups.");
}
const string CaptureHint = "capture fixture absent — set PF_CAPTURE to a local .pcap";
string ProjectDir = Path.Combine(repoRoot, "ProtocolForge");

var reportLines = new List<string>();
var failures = 0;
var skipped = 0;
// Skipped groups are named with their real reason. The old footer claimed every
// skip was "no capture fixture", which is wrong: G17-13 needs a specific large
// local capture that PF_CAPTURE cannot satisfy, so setting PF_CAPTURE does not
// clear it. Reporting the actual per-group reason keeps a green run honest.
var skipReasons = new List<string>();

// Filtered runs still print the usual footer. When the filter matched nothing, the
// footer alone would read like a successful verification run — so count the PASS lines
// the filter actually printed and say explicitly that the run proved nothing.
var printedPasses = 0;

// ── Output filter: --only <group#> / --group <title-substring> ──
// Output-only: groups still execute, so the exit code and report.txt stay full-run.
// FAIL lines print even when filtered — a filtered run must never look green.
int? onlyGroup = null;
string? titleFilter = null;
for (int i = 0; i + 1 < args.Length; i++)
{
    if (args[i] == "--only" && int.TryParse(args[i + 1], out int parsedOnly)) { onlyGroup = parsedOnly; i++; }
    else if (args[i] == "--group") titleFilter = args[++i];
}
bool GroupSelected(int n, string title) =>
    (!onlyGroup.HasValue || onlyGroup.Value == n) &&
    (titleFilter is null || title.Contains(titleFilter, StringComparison.OrdinalIgnoreCase));
int currentGroup = 0;
string currentTitle = "";
void Banner(int n, string title)
{
    currentGroup = n;
    currentTitle = title;
    if (GroupSelected(n, title)) Console.WriteLine($"\nGROUP {n}: {title}");
}
void Detail(string text)
{
    if (GroupSelected(currentGroup, currentTitle)) Console.WriteLine(text);
}

void Report(string name, bool ok, string? detail = null)
{
    string line = ok ? $"PASS {name}" : $"FAIL {name}: {detail ?? "assertion failed"}";
    reportLines.Add(line);
    bool show = !ok || GroupSelected(currentGroup, currentTitle);
    if (show) { Console.WriteLine(line); if (ok) printedPasses++; }
    if (!ok) failures++;
}

// Skipped groups must not be mistaken for passed ones: they stay out of `failures`
// so a capture-less run still exits 0, but they are counted and named in the footer.
void Skip(string name, string why)
{
    string line = $"SKIP {name}: {why}";
    reportLines.Add(line);
    if (GroupSelected(currentGroup, currentTitle)) Console.WriteLine(line);
    skipped++;
    skipReasons.Add(why);
}

// `--ui` runs the headless render as the process's only job. Dispatched after the
// reporting helpers exist and before the capture fixture is built, because top-level
// statements execute in written order and the UI check needs none of the capture groups.
if (args.Contains("--ui", StringComparer.Ordinal))
    return RunHeadlessRenderOnly();

const int TargetIndex = 4412; // frame number 4413

try
{
    if (PcapPath is null) Skip("G1/G2 tree-edit fence verdicts (frame 4413)", CaptureHint);
    else
    {
        var ingest = new PcapIngestService();
        var export = new PcapExportService();
        var tshark = new TsharkService(ingest, export);

        // ══ GROUP 1: tree-edit fence verdicts (frame 4413) ══
        Banner(1, "tree-edit fence verdicts (frame 4413)");
        var readResult = await ingest.ReadPacketsAsync(PcapPath);
        Report("G1 load pcap has >=4413 packets", readResult.Packets.Count >= 4413,
            $"count={readResult.Packets.Count}");
        if (readResult.Packets.Count > TargetIndex)
        {
            var (timestamp, rawData) = readResult.Packets[TargetIndex];
            var packet = new Packet { Index = TargetIndex, Timestamp = timestamp, RawData = rawData };
            Report("G1 effective data length > 0", packet.EffectiveData.Length > 0,
                $"EffectiveData.Length={packet.EffectiveData.Length}");

            string tempPath = Path.Combine(Path.GetTempPath(), $"pf_verify_{Guid.NewGuid():N}.pcap");
            try
            {
                await export.SavePacketAsync(packet, tempPath, linkLayerType: readResult.LinkLayerType);
                bool parsed = await tshark.ParsePacketFromPcapFileAsync(packet, tempPath);
                Report("G1 tshark parses frame 4413 into layer tree", parsed && packet.Layers.Count > 0,
                    $"parsed={parsed}, layers={packet.Layers.Count}");

                var editor = new ProtocolEditorService();
                var blockedByReason = new Dictionary<string, int>();
                var allowedFields = new List<ProtocolField>();
                int totalFields = 0;

                void WalkFields(IEnumerable<ProtocolField> fields)
                {
                    foreach (var field in fields)
                    {
                        totalFields++;
                        var fence = editor.CheckTreeEditFence(packet, field);
                        if (!fence.Allowed)
                        {
                            blockedByReason.TryGetValue(fence.Reason, out int n);
                            blockedByReason[fence.Reason] = n + 1;
                        }
                        else if (field.RawBytes.Length > 0 && field.Length > 0)
                        {
                            allowedFields.Add(field);
                        }
                        if (field.Children.Count > 0)
                            WalkFields(field.Children);
                    }
                }
                foreach (var layer in packet.Layers)
                    WalkFields(layer.Fields);

                Detail($"    total fields walked = {totalFields}, allowed-with-bytes = {allowedFields.Count}, blocked reasons:");
                foreach (var (r, c) in blockedByReason)
                    Detail($"        {c,3}x  {r}");

                Report("G1a fence blocks metadata/bit-level fields", blockedByReason.Count > 0,
                    $"reasonCount={blockedByReason.Count}");
                Report("G1b fence allows >=1 normal in-frame field", allowedFields.Count > 0,
                    $"allowed={allowedFields.Count}");
                Report("G1c fence discriminates (both verdict classes present)", blockedByReason.Count > 0 && allowedFields.Count > 0,
                    $"blockedReasons={blockedByReason.Count}, allowed={allowedFields.Count}");

                // ══ GROUP 2: P2 Verify-Before-Commit transaction (service layer) ══
                Banner(2, "P2 VBC transaction");
                var tx = new EditTransactionService(export, tshark);

                var target = allowedFields.FirstOrDefault();
                if (target == null)
                {
                    Report("G2a no candidate field to edit", false, "allowedFields empty");
                }
                else
                {
                    Detail($"    candidate = {target.OriginalPdmlName} @{target.Offset} len={target.Length} raw={string.Join(" ", target.RawBytes.Select(b => b.ToString("X2")))}");
                    Report("G2a candidate field has concrete bytes", target.RawBytes.Length == target.Length,
                        $"rawBytes={target.RawBytes.Length}, field.Length={target.Length}");

                    // Legal edit: flip the lowest bit of the first byte -> reparse must land.
                    var newValue = (byte[])target.RawBytes.Clone();
                    newValue[0] ^= 0x01;
                    byte[] before = (byte[])packet.EffectiveData.Clone();

                    var legal = await tx.CommitFieldEditAsync(packet, target, newValue, null, readResult.LinkLayerType);
                    Detail($"    legal edit verdict: Success={legal.Success} Reason={legal.Reason}");
                    if (legal.Success)
                    {
                        byte[] after = packet.EffectiveData;
                        bool prefixSame = after.Take(target.Offset).SequenceEqual(before.Take(target.Offset));
                        bool suffixSame = after.Skip(target.Offset + 1).SequenceEqual(before.Skip(target.Offset + 1));
                        bool mutated = after.Length == before.Length &&
                                       after[target.Offset] == newValue[0] &&
                                       prefixSame && suffixSame;
                        Report("G2b legal edit commits: byte at offset flipped, rest identical", mutated,
                            $"off={target.Offset} expected={newValue[0]:X2} got={after[target.Offset]:X2}");
                        Report("G2c legal edit returns fresh PdmlData", legal.Fresh != null, legal.Fresh == null ? "Fresh=null" : $"pdml fields={legal.Fresh.FieldLookup.Count}");
                    }
                    else
                    {
                        byte[] after = packet.EffectiveData;
                        Report("G2b legal edit blocked with reason (env tshark 3.6.2 < 4.0 may limit pdml)", false,
                            $"Reason={legal.Reason}");
                        Report("G2c packet byte-identical on block", after.SequenceEqual(before), "packet mutated on blocked edit");
                    }

                    // Offset-drift simulation: clone the field, shift its Offset, expect ABORT + no mutation.
                    var driftField = new ProtocolField
                    {
                        OriginalPdmlName = target.OriginalPdmlName,
                        Offset = target.Offset + 100,
                        Length = target.Length,
                        RawBytes = (byte[])target.RawBytes.Clone(),
                        Kind = target.Kind,
                    };
                    byte[] beforeDrift = (byte[])packet.EffectiveData.Clone();
                    var drift = await tx.CommitFieldEditAsync(packet, driftField, newValue, null, readResult.LinkLayerType);
                    Detail($"    drift verdict: Success={drift.Success} Reason={drift.Reason}");
                    Report("G2d wrong-position edit aborted", !drift.Success,
                        $"Success={drift.Success} Reason={drift.Reason}");
                    Report("G2e abort leaves packet byte-identical", packet.EffectiveData.SequenceEqual(beforeDrift),
                        "packet mutated on drift abort");

                    // Length-changing edit: field.Length 1 but newValue 4 bytes -> must reject.
                    var longValue = new byte[] { 0x01, 0x02, 0x03, 0x04 };
                    byte[] beforeLen = (byte[])packet.EffectiveData.Clone();
                    var lenEdit = await tx.CommitFieldEditAsync(packet, target, longValue, null, readResult.LinkLayerType);
                    Detail($"    length-edit verdict: Success={lenEdit.Success} Reason={lenEdit.Reason}");
                    Report("G2f length-changing edit rejected", !lenEdit.Success,
                        $"Success={lenEdit.Success} Reason={lenEdit.Reason}");
                    Report("G2g length-reject leaves packet byte-identical", packet.EffectiveData.SequenceEqual(beforeLen),
                        "packet mutated on length-reject");
                }
            }
            finally
            {
                try { File.Delete(tempPath); } catch (Exception) { }
            }
        }
    }
}
catch (Exception ex)
{
    Report("G1/G2 group execution", false, ex.ToString());
}

// ══ GROUP 3: tshark version gate — real env (any tshark >= min 2.6 → gate PASSes) ══
Banner(3, "tshark version gate (real env)");
try
{
    var detection = TsharkService.DetectTshark();
    Report("G3 real tshark >= min 2.6 gives Ok=true", detection.Ok,
        $"Ok={detection.Ok}, Version={detection.Version}, Msg={detection.Message}");
    bool versionParsed = Version.TryParse(detection.Version, out var detected);
    bool meetsMinimum = versionParsed && detected >= new Version(2, 6, 0);
    Report("G3 detected version parses and >= min 2.6", meetsMinimum,
        $"Parsed={versionParsed}, Version={detection.Version}");
}
catch (Exception ex)
{
    Report("G3 group execution", false, ex.ToString());
}

// ══ GROUP 4: tshark version gate — fake old 2.5 via TSHARK_PATH (gate FAIL branch) ══
Banner(4, "tshark version gate (fake tshark 2.5 via TSHARK_PATH)");
try
{
    string fakePath = Path.Combine(Path.GetTempPath(), "pf_fake_tshark");
    if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
    {
        await File.WriteAllTextAsync(fakePath,
            "#!/usr/bin/env bash\n" +
            "if [ \"$1\" = \"-v\" ]; then\n" +
            "  echo \"TShark (Wireshark) 2.5.0 (Git v2.5.0).\"\n" +
            "  exit 0\n" +
            "fi\n" +
            "exit 0\n");
        await BashAsync($"chmod +x {fakePath}");
    }
    else
    {
        fakePath += ".cmd";
        await File.WriteAllTextAsync(fakePath,
            "@echo off\nif \"%1\"==\"-v\" (echo TShark (Wireshark) 2.5.0 & exit /b 0)\nexit /b 0\n");
    }

    Environment.SetEnvironmentVariable("TSHARK_PATH", fakePath);
    var fakeDetection = TsharkService.RedetectTshark();
    Detail($"    fake detect: Ok={fakeDetection.Ok}, Version={fakeDetection.Version}, Path={fakeDetection.Path}");
    Report("G4 fake tshark 2.5 < min 2.6 gives Ok=false", fakeDetection.Ok == false,
        $"Ok={fakeDetection.Ok}, Msg={fakeDetection.Message}");
    Report("G4 fake version parsed as 2.5.0", fakeDetection.Version == "2.5.0", $"Version={fakeDetection.Version}");

    // Now flip to a fake 4.2 (>= min 2.6 → gate PASS branch) via the same path
    if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
    {
        await File.WriteAllTextAsync(fakePath,
            "#!/usr/bin/env bash\n" +
            "if [ \"$1\" = \"-v\" ]; then\n" +
            "  echo \"TShark (Wireshark) 4.2.6 (Git v4.2.6-0-ga1b2c3d4).\"\n" +
            "  exit 0\n" +
            "fi\n" +
            "exit 0\n");
        await BashAsync($"chmod +x {fakePath}");
    }
    else
    {
        await File.WriteAllTextAsync(fakePath,
            "@echo off\nif \"%1\"==\"-v\" (echo TShark (Wireshark) 4.2.6 & exit /b 0)\nexit /b 0\n");
    }

    var newDetection = TsharkService.RedetectTshark();
    Detail($"    fake detect: Ok={newDetection.Ok}, Version={newDetection.Version}");
    Report("G4 fake tshark 4.2 >= min 2.6 gives Ok=true", newDetection.Ok,
        $"Ok={newDetection.Ok}, Msg={newDetection.Message}");

    Environment.SetEnvironmentVariable("TSHARK_PATH", null);
    _ = TsharkService.RedetectTshark();
}
catch (Exception ex)
{
    Report("G4 group execution", false, ex.ToString());
}

// ══ GROUP 5: read-only raw load ══
Banner(5, "read-only load");
try
{
    if (PcapPath is null) Skip("G5 read-only raw load", CaptureHint);
    else
    {
        var ingest = new PcapIngestService();
        var export = new PcapExportService();
        var tshark = new TsharkService(ingest, export);
        var doc = await tshark.LoadPcapReadOnlyAsync(new PacketDocument(), PcapPath);
        Report("G5 read-only doc has packets", doc.Packets.Count > 0, $"count={doc.Packets.Count}");
        int notNA = doc.Packets.Count(p => p.SourceAddress != "N/A");
        int nonEmptyProto = doc.Packets.Count(p => p.ProtocolName != "");
        Report("G5 all packets SourceAddress==N/A (raw mode)", notNA == 0, $"mismatches={notNA}");
        Report("G5 all packets ProtocolName==empty (raw mode)", nonEmptyProto == 0, $"mismatches={nonEmptyProto}");
    }
}
catch (Exception ex)
{
    Report("G5 group execution", false, ex.ToString());
}

// ══ GROUP 6: P3 hex-editing code surface (static, no GUI allowed) ══
Banner(6, "P3 hex-edit REPLACE-only code surface");
try
{
    string vmPath = Path.Combine(ProjectDir, "ViewModels/HexEditorViewModel.cs");
    string viewPath = Path.Combine(ProjectDir, "Views/Controls/HexEditor.axaml.cs");
    string modelPath = Path.Combine(ProjectDir, "Models/HexByte.cs");
    string treePath = Path.Combine(ProjectDir, "Views/Controls/ProtocolTreeView.axaml.cs");
    string mwPath = Path.Combine(ProjectDir, "ViewModels/MainWindowViewModel.cs");

    string vm = await File.ReadAllTextAsync(vmPath);
    string view = await File.ReadAllTextAsync(viewPath);
    string model = await File.ReadAllTextAsync(modelPath);
    string tree = await File.ReadAllTextAsync(treePath);
    string mw = await File.ReadAllTextAsync(mwPath);

    Report("G6 HexByte has IsEditPending", model.Contains("IsEditPending"), "missing IsEditPending");
    Report("G6 VM has HandleHexInput + CommitHexEditAsync + CancelHexEdit",
        vm.Contains("HandleHexInput") && vm.Contains("CommitHexEditAsync") && vm.Contains("CancelHexEdit"), "missing hex-edit methods");
    Report("G6 VM has HexEdited + FieldFoundAtOffset events",
        vm.Contains("event Action<(Packet Packet, int Offset, int Length)>? HexEdited") && vm.Contains("FieldFoundAtOffset"), "missing events");
    Report("G6 VM honors IsReadOnly", vm.Contains("IsReadOnly"), "missing read-only gate");
    Report("G6 view routes hex digits", view.Contains("Key.A") && view.Contains("Key.NumPad0"), "missing digit routing");
    Report("G6 view commit=calls VM async, cancel=Esc", view.Contains("CommitHexEditAsync") && view.Contains("CancelHexEdit"), "missing commit/cancel wiring");
    Report("G6 reverse sync: tree SelectFieldOnTree + view walk",
        mw.Contains("HexEditor.FieldFoundAtOffset") && tree.Contains("ContainerFromItem") && tree.Contains("TreeContainerFromItem"), "missing reverse sync");
    Report("G6 reverse sync bounded retry", tree.Contains("MaxSelectAttempts"), "missing retry bound");
    Report("G6 reverse sync clears the previously revealed node",
        tree.Contains("ProtocolTree.SelectedItem = null"), "stale tree highlight guard missing");
}
catch (Exception ex)
{
    Report("G6 group execution", false, ex.ToString());
}

// ══ GROUP 7: Npcap probe pure logic (no Npcap needed — degradation contract) ══
Banner(7, "Npcap probe pure logic (degradation contract)");
try
{
    string fakeRoot = Path.Combine(Path.GetTempPath(), "pf_npcap_" + Guid.NewGuid().ToString("N"));
    string dllPath = Path.Combine(fakeRoot, "Npcap", "wpcap.dll");
    Directory.CreateDirectory(Path.GetDirectoryName(dllPath)!);
    await File.WriteAllTextAsync(dllPath, string.Empty);

    string? found = NpcapSendService.ResolveWpcapPath(fakeRoot);
    Report("G7 resolves Npcap wpcap.dll when installed",
        string.Equals(found, dllPath, StringComparison.OrdinalIgnoreCase), $"found={found}");

    string? missing = NpcapSendService.ResolveWpcapPath(Path.Combine(fakeRoot, "absent"));
    Report("G7 returns null when Npcap absent", missing == null, $"missing={missing}");

    Report("G7 frame boundary falls at 14 bytes (Ethernet header)",
        !NpcapSendService.CanSendFrame(new byte[13]) && NpcapSendService.CanSendFrame(new byte[14]),
        "CanSendFrame(13B)/CanSendFrame(14B) boundary wrong");

    Report("G7 NPF device GUID matches braced interface Id",
        NpcapSendService.DeviceMatchesIdentifier(
            @"\Device\NPF_{A1B2C3D4-1234-5678-9ABC-DEF012345678}",
            "{A1B2C3D4-1234-5678-9ABC-DEF012345678}"),
        "braced Id failed");
    Report("G7 NPF device GUID matches unbraced lowercase interface Id",
        NpcapSendService.DeviceMatchesIdentifier(
            @"\Device\NPF_{A1B2C3D4-1234-5678-9ABC-DEF012345678}",
            "a1b2c3d4-1234-5678-9abc-def012345678"),
        "unbraced/lowercase Id failed");
    Report("G7 NPF GUID mismatch rejected",
        !NpcapSendService.DeviceMatchesIdentifier(
            @"\Device\NPF_{00000000-0000-0000-0000-000000000000}",
            "{A1B2C3D4-1234-5678-9ABC-DEF012345678}"),
        "mismatch accepted");
    Report("G7 non-NPF device name rejected",
        !NpcapSendService.DeviceMatchesIdentifier(
            @"\Device\Other_{A1B2C3D4-1234-5678-9ABC-DEF012345678}",
            "{A1B2C3D4-1234-5678-9ABC-DEF012345678}"),
        "foreign device name accepted");

    try { Directory.Delete(fakeRoot, true); } catch { }
}
catch (Exception ex)
{
    Report("G7 group execution", false, ex.ToString());
}

// ══ GROUP 8: BPF probe pure logic (no BPF needed — macOS degradation contract) ══
Banner(8, "BPF pure logic (macOS degradation contract)");
try
{
    byte[] ifreq = BpfSendService.BuildIfreq("en0");
    bool nameOk = ifreq.Length == 32
        && ifreq[0] == (byte)'e' && ifreq[1] == (byte)'n' && ifreq[2] == (byte)'0'
        && ifreq[3] == 0
        && ifreq.Skip(16).All(b => b == 0);
    Report("G8 BuildIfreq(\"en0\") = name + NUL + zeroed union", nameOk,
        $"head=[{string.Join(",", ifreq.Take(4))}] size={ifreq.Length}");

    byte[] longIfreq = BpfSendService.BuildIfreq(new string('x', 30));
    Report("G8 BuildIfreq truncates to 15 chars + NUL terminator",
        longIfreq[15] == 0 && longIfreq[14] == (byte)'x',
        $"byte14={longIfreq[14]}, byte15={longIfreq[15]}");

    Report("G8 empty name yields zeroed ifreq",
        BpfSendService.BuildIfreq("").All(b => b == 0), "empty ifreq not all-zero");
}
catch (Exception ex)
{
    Report("G8 group execution", false, ex.ToString());
}



// ══ GROUP 11: i18n localization — en/zh dictionaries + runtime switching (console host, no Avalonia) ══
Banner(11, "localization (dictionary parity / placeholders / runtime switching)");
try
{
    var en = LocalizationService.For(AppLanguage.EnUs);
    var zh = LocalizationService.For(AppLanguage.ZhCn);

    // G11a: dictionary parity — identical key sets (same count, same keys)
    bool sameCount = en.Entries.Count == zh.Entries.Count;
    bool sameKeys = en.Entries.Keys.ToHashSet().SetEquals(zh.Entries.Keys);
    Detail($"    en={en.Entries.Count} keys, zh={zh.Entries.Count} keys");
    Report("G11a en/zh key sets identical (count + keys)", sameCount && sameKeys,
        $"en={en.Entries.Count}, zh={zh.Entries.Count}, sameKeys={sameKeys}");

    // G11b: placeholder parity — every key formats with the same arg count in both languages
    int checkedKeys = 0;
    var placeholderMismatches = new List<string>();
    foreach (string key in en.Entries.Keys)
    {
        int enCount = LocalizationService.PlaceholderCount(en.Entries[key]);
        int zhCount = LocalizationService.PlaceholderCount(zh.Entries[key]);
        checkedKeys++;
        if (enCount != zhCount)
            placeholderMismatches.Add($"{key}: en={enCount} zh={zhCount}");
    }
    Report("G11b placeholder parity across all keys", placeholderMismatches.Count == 0,
        $"checked={checkedKeys}, mismatches=[{string.Join("; ", placeholderMismatches)}]");

    // G11c: Chinese content really exists (CJK ideograph U+4E00–U+9FFF)
    bool hasCjk = zh.Entries.Values.Any(v => v.Any(c => c >= 0x4E00 && c <= 0x9FFF));
    var cjkSample = zh.Entries.FirstOrDefault(kv => kv.Value.Any(c => c >= 0x4E00 && c <= 0x9FFF));
    if (cjkSample.Key != null)
        Detail($"    zh CJK sample: \"{cjkSample.Key}\" = \"{cjkSample.Value}\"");
    Report("G11c zh dictionary contains CJK ideographs (U+4E00–U+9FFF)", hasCjk,
        cjkSample.Key == null ? "no CJK value found" : $"sample=\"{cjkSample.Key}\"");

    // G11d: runtime switching — Resolve follows SetCurrent, round-trips back to English
    string defaultReady = LocalizationService.Resolve("Status.Ready");
    bool defaultIsEn = defaultReady == en.Get("Status.Ready");
    LocalizationService.SetCurrent(AppLanguage.EnUs);
    string enReady = LocalizationService.Resolve("Status.Ready");
    bool enMatches = enReady == en.Get("Status.Ready");
    LocalizationService.SetCurrent(AppLanguage.ZhCn);
    string zhReady = LocalizationService.Resolve("Status.Ready");
    bool zhMatches = zhReady == zh.Get("Status.Ready") && zhReady != enReady;
    LocalizationService.SetCurrent(AppLanguage.EnUs);
    string enReadyAgain = LocalizationService.Resolve("Status.Ready");
    bool roundTrip = enReadyAgain == enReady;
    Report("G11d runtime switching: default=en, SetCurrent(zh) differs, round-trip back to en",
        defaultIsEn && enMatches && zhMatches && roundTrip,
        $"default=\"{defaultReady}\", en=\"{enReady}\", zh=\"{zhReady}\", enAgain=\"{enReadyAgain}\"");

    // G11e: missing-key fallback — current → en-US → bare key
    LocalizationService.SetCurrent(AppLanguage.ZhCn);
    string missingZh = LocalizationService.Resolve("Nope.DoesNotExist");
    LocalizationService.SetCurrent(AppLanguage.EnUs);
    string missingEn = LocalizationService.Resolve("Nope.DoesNotExist");
    Report("G11e missing key falls back to bare key (zh→en→key chain)",
        missingZh == "Nope.DoesNotExist" && missingEn == "Nope.DoesNotExist",
        $"zh=\"{missingZh}\", en=\"{missingEn}\"");

    // G11f: placeholder formatting — Status.ParseFailed has {0}/{1} in both languages
    string fmtKey = "Status.ParseFailed";
    if (LocalizationService.PlaceholderCount(en.Entries[fmtKey]) != 2
        || LocalizationService.PlaceholderCount(zh.Entries[fmtKey]) != 2)
    {
        // defensive: pick any 2-placeholder key present in both languages
        fmtKey = en.Entries.Keys.FirstOrDefault(k =>
            LocalizationService.PlaceholderCount(en.Entries[k]) == 2
            && LocalizationService.PlaceholderCount(zh.Entries[k]) == 2) ?? fmtKey;
    }
    string enFmt = en.Get(fmtKey, 123, "boom");
    string zhFmt = zh.Get(fmtKey, 123, "boom");
    bool fmtOk = enFmt.Contains("123") && enFmt.Contains("boom")
        && zhFmt.Contains("123") && zhFmt.Contains("boom");
    Report("G11f placeholder formatting (2-arg key formats both languages)",
        fmtOk, $"key={fmtKey}, en=\"{enFmt}\", zh=\"{zhFmt}\"");
}
catch (Exception ex)
{
    Report("G11 group execution", false, ex.ToString());
}

// ══ GROUP 12–20: B-class service-layer coverage (fence / convert / apply / layers / prepare / VBC / ingest / export / addresses / settings / send) ══
// G12–G20 need the real capture + services; G1/G2 scoped theirs inside its try, so declare fresh here.
var ing12 = new PcapIngestService();
var exp12 = new PcapExportService();
var tsh12 = new TsharkService(ing12, exp12);
PcapReadResult? read12 = PcapPath is { } p12 ? await ing12.ReadPacketsAsync(p12) : null;
Banner(12, "12a+12b: edit fence gates + raw-value conversion");
try
{
    LocalizationService.SetCurrent(AppLanguage.EnUs);

    // Synthetic 60-byte Ethernet/IPv4/UDP frame (fixed layout used by G12a & G13)
    byte[] g12Frame = Concat(
        new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },             // eth dst
        new byte[] { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB },             // eth src
        U16(0x0800, littleEndian: false),                               // ethertype IPv4
        new byte[] { 0x45, 0x00 }, U16(46, false), U16(1, false), U16(0x4000, false),
        new byte[] { 0x40, 0x11, 0x00, 0x00 },
        new byte[] { 10, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 },
        U16(1234, false), U16(5678, false), U16(26, false), U16(0, false),
        new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12 });

    var g12pkt = new Packet { Index = 1, Timestamp = 1000, RawData = (byte[])g12Frame.Clone() };
    var g12pdu = new Packet { Index = 2, Timestamp = 1001, RawData = (byte[])g12Frame.Clone() };
    g12pdu.Layers.Add(new ProtocolLayer { ProtocolName = "udp", DisplayText = "User Datagram Protocol", Offset = 34 });
    var g12ed = new ProtocolEditorService();
    byte[] g12src = g12Frame.AsSpan(26, 4).ToArray();

    var fU = new ProtocolField { Name = "Src", OriginalPdmlName = "ip.src", Offset = 26, Length = 4, Kind = FieldKind.Unknown, RawBytes = g12src };
    Report("G12a-01 unknown kind → fence rejects (UnknownField)",
        !g12ed.CheckTreeEditFence(g12pkt, fU).Allowed
        && g12ed.CheckTreeEditFence(g12pkt, fU).Reason == LocalizationService.Resolve("Fence.UnknownField"),
        g12ed.CheckTreeEditFence(g12pkt, fU).Reason);

    var fBit = new ProtocolField { Name = "Src", OriginalPdmlName = "ip.src", Offset = 26, Length = 4, LengthBits = 1, Kind = FieldKind.UInt, RawBytes = g12src };
    Report("G12a-02 bit-level field → fence rejects (BitLevel)",
        !g12ed.CheckTreeEditFence(g12pkt, fBit).Allowed
        && g12ed.CheckTreeEditFence(g12pkt, fBit).Reason == LocalizationService.Resolve("Fence.BitLevel"),
        g12ed.CheckTreeEditFence(g12pkt, fBit).Reason);

    var fOut = new ProtocolField { Name = "Src", OriginalPdmlName = "ip.src", Offset = 1000, Length = 4, Kind = FieldKind.UInt, RawBytes = g12src };
    Report("G12a-03 out-of-frame (no PDU hint) → fence rejects (OutOfFrame)",
        !g12ed.CheckTreeEditFence(g12pkt, fOut).Allowed
        && g12ed.CheckTreeEditFence(g12pkt, fOut).Reason == LocalizationService.Resolve("Fence.OutOfFrame", 1000, 4, 60, ""),
        g12ed.CheckTreeEditFence(g12pkt, fOut).Reason);

    Report("G12a-04 out-of-frame with layers → PDU hint appended",
        !g12ed.CheckTreeEditFence(g12pdu, fOut).Allowed
        && g12ed.CheckTreeEditFence(g12pdu, fOut).Reason == LocalizationService.Resolve("Fence.OutOfFrame", 1000, 4, 60, LocalizationService.Resolve("Fence.PduHint")),
        g12ed.CheckTreeEditFence(g12pdu, fOut).Reason);

    var fEv = new ProtocolField { Name = "Src", OriginalPdmlName = "ip.src", Offset = 26, Length = 4, Kind = FieldKind.UInt, RawBytes = new byte[] { 0x01 } };
    Report("G12a-05 RawBytes missing evidence → fence rejects (NoByteEvidence)",
        !g12ed.CheckTreeEditFence(g12pkt, fEv).Allowed
        && g12ed.CheckTreeEditFence(g12pkt, fEv).Reason == LocalizationService.Resolve("Fence.NoByteEvidence", 1, 4),
        g12ed.CheckTreeEditFence(g12pkt, fEv).Reason);

    var fDis = new ProtocolField { Name = "Src", OriginalPdmlName = "ip.src", Offset = 26, Length = 4, Kind = FieldKind.UInt, RawBytes = g12src.Select(b => (byte)~b).ToArray() };
    Report("G12a-06 RawBytes disagree with frame bytes → fence rejects (BytesDisagree)",
        !g12ed.CheckTreeEditFence(g12pkt, fDis).Allowed
        && g12ed.CheckTreeEditFence(g12pkt, fDis).Reason == LocalizationService.Resolve("Fence.BytesDisagree"),
        g12ed.CheckTreeEditFence(g12pkt, fDis).Reason);

    var fOk = new ProtocolField { Name = "Src", OriginalPdmlName = "ip.src", Offset = 26, Length = 4, Kind = FieldKind.IPv4, RawBytes = g12src };
    var fenceOk = g12ed.CheckTreeEditFence(g12pkt, fOk);
    Report("G12a-07 consistent IPv4 field → fence allows",
        fenceOk.Allowed && fenceOk.Reason == "OK",
        fenceOk.Reason);

    // ── G12b: ConvertRawValue matrix (positive → exact bytes; negative → exception fragment) ──
    bool g12ok = true; string g12detail = "";
    (bool Ok, byte[]? Bytes, string? Error) Conv(FieldKind k, string input, int expLen)
    {
        try { return (true, ProtocolEditorService.ConvertRawValue(k, input, expLen), null); }
        catch (Exception ex) { return (false, null, ex.Message); }
    }
    void G12Vector(string ctx, FieldKind k, string input, int expLen, bool expectThrow, byte[]? expectBytes, string? expectFrag)
    {
        var r = Conv(k, input, expLen);
        bool pass = r.Ok == !expectThrow;
        string detail = $"{input} → {(r.Ok ? BytesHex(r.Bytes!) : "throws: " + r.Error)}";
        if (pass && r.Ok && expectBytes != null)
            pass = BytesEq(r.Bytes!, expectBytes);
        if (pass && !r.Ok && expectFrag != null)
            pass = r.Error!.Contains(expectFrag, StringComparison.OrdinalIgnoreCase);
        Report($"G12b {ctx}", pass, detail);
        g12ok &= pass; if (!pass) g12detail += ctx + "; ";
    }

    G12Vector("UInt 0x10 → 1 byte", FieldKind.UInt, "0x10", 1, false, new byte[] { 0x10 }, null);
    G12Vector("UInt 10 decimal → 1 byte", FieldKind.UInt, "10", 1, false, new byte[] { 0x0A }, null);
    G12Vector("UInt 300 over 1 byte → rejects", FieldKind.UInt, "300", 1, true, null, "exceeds 1-byte unsigned range");
    G12Vector("UInt 65535 → 2 bytes", FieldKind.UInt, "65535", 2, false, new byte[] { 0xFF, 0xFF }, null);
    G12Vector("Int -5 → 1 byte two's complement", FieldKind.Int, "-5", 1, false, new byte[] { 0xFB }, null);
    G12Vector("Int -5 → 2 bytes", FieldKind.Int, "-5", 2, false, new byte[] { 0xFF, 0xFB }, null);
    G12Vector("Int 0xFB → raw byte", FieldKind.Int, "0xFB", 1, false, new byte[] { 0xFB }, null);
    G12Vector("Int 999 → truncates to 1 byte (no signed range check)", FieldKind.Int, "999", 1, false, new byte[] { 0xE7 }, null);
    G12Vector("IPv4 10.0.0.1 → 4 bytes", FieldKind.IPv4, "10.0.0.1", 4, false, new byte[] { 10, 0, 0, 1 }, null);
    G12Vector("IPv4 300.1.1.1 → rejects", FieldKind.IPv4, "300.1.1.1", 4, true, null, "not a valid IPv4");
    G12Vector("IPv4 ::1 → rejects", FieldKind.IPv4, "::1", 4, true, null, "not a valid IPv4");
    G12Vector("IPv6 fe80::1 → 16 bytes", FieldKind.IPv6, "fe80::1", 16, false, IPAddress.Parse("fe80::1").GetAddressBytes(), null);
    G12Vector("IPv6 10.0.0.1 → rejects", FieldKind.IPv6, "10.0.0.1", 16, true, null, "not a valid IPv6");
    G12Vector("MAC 6-part", FieldKind.Mac, "aa:bb:cc:dd:ee:ff", 6, false, new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, null);
    G12Vector("MAC 4-part (802.3)", FieldKind.Mac, "aa:bb:cc:dd", 4, false, new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }, null);
    G12Vector("MAC 3-part → rejects", FieldKind.Mac, "aa:bb:cc", 6, true, null, "not a valid MAC");
    G12Vector("MAC bad hex → rejects", FieldKind.Mac, "zz:bb:cc:dd:ee:ff", 6, true, null, "not a valid MAC");
    G12Vector("BCD 12345678 → swapped nibbles", FieldKind.Bcd, "12345678", 4, false, new byte[] { 0x21, 0x43, 0x65, 0x87 }, null);
    G12Vector("BCD odd digits → 0xF filler", FieldKind.Bcd, "123456789", 5, false, new byte[] { 0x21, 0x43, 0x65, 0x87, 0xF9 }, null);
    G12Vector("BCD single digit 9 → fills 0xF9", FieldKind.Bcd, "9", 1, false, new byte[] { 0xF9 }, null);
    G12Vector("BCD digit count vs field length → rejects", FieldKind.Bcd, "12", 4, true, null, "BCD");
    G12Vector("String AB → 2 bytes", FieldKind.String, "AB", 2, false, new byte[] { 0x41, 0x42 }, null);
    G12Vector("String AB → zero-padded to 5", FieldKind.String, "AB", 5, false, new byte[] { 0x41, 0x42, 0x00, 0x00, 0x00 }, null);
    G12Vector("String too long → rejects", FieldKind.String, "ABCDEF", 2, true, null, "Value too long");
    G12Vector("String empty → rejects", FieldKind.String, "", 2, true, null, "Value cannot be empty");
    G12Vector("Unknown kind → rejects", FieldKind.Unknown, "5", 1, true, null, "is not editable");
    G12Vector("Bytes colon-hex → 3 bytes", FieldKind.Bytes, "0a:0b:0c", 3, false, new byte[] { 0x0A, 0x0B, 0x0C }, null);
    G12Vector("Bytes plain hex → 4 bytes", FieldKind.Bytes, "aabbccdd", 4, false, new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }, null);
    G12Vector("Bytes 0x-prefixed → 2 bytes", FieldKind.Bytes, "0xAABB", 2, false, new byte[] { 0xAA, 0xBB }, null);
    G12Vector("Bytes length mismatch → rejects", FieldKind.Bytes, "aabb", 4, true, null, "field holds");
    G12Vector("Bytes non-hex → rejects", FieldKind.Bytes, "zz", 1, true, null, "not valid hex bytes");
    G12Vector("Bytes odd digit count → rejects", FieldKind.Bytes, "abc", 2, true, null, "not valid hex bytes");
    Report("G12b full conversion matrix", g12ok, g12detail.Length == 0 ? "all vectors passed" : g12detail);
}
catch (Exception ex)
{
    Report("G12 group execution", false, ex.ToString());
}

Banner(13, "field edit application — offsets, length guards, hex apply");
try
{
    byte[] g13Frame = Concat(
        new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        new byte[] { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB }, U16(0x0800, false),
        new byte[] { 0x45, 0x00 }, U16(46, false), U16(1, false), U16(0x4000, false),
        new byte[] { 0x40, 0x11, 0x00, 0x00 }, new byte[] { 10, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 },
        U16(1234, false), U16(5678, false), U16(26, false), U16(0, false),
        new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12 });
    var ed13 = new ProtocolEditorService();
    byte[] f13Src = g13Frame.AsSpan(26, 4).ToArray();

    var p13a = new Packet { Index = 1, Timestamp = 1000, RawData = (byte[])g13Frame.Clone() };
    var f13a = new ProtocolField { Name = "Source", OriginalPdmlName = "ip.src", Offset = 26, Length = 4, Kind = FieldKind.IPv4, RawBytes = f13Src };
    byte[] ret13 = ed13.ApplyFieldEdit(p13a, f13a, new byte[] { 0x11, 0x22, 0x33, 0x44 });
    Report("G13-01 apply writes bytes at offset and marks dirty",
        BytesEq(p13a.EffectiveData.AsSpan(26, 4).ToArray(), new byte[] { 0x11, 0x22, 0x33, 0x44 }) && p13a.IsModified,
        BytesHex(p13a.EffectiveData.AsSpan(26, 4).ToArray()));
    Report("G13-02 field RawBytes + DisplayValue updated",
        BytesEq(f13a.RawBytes, new byte[] { 0x11, 0x22, 0x33, 0x44 }) && f13a.DisplayValue == "11 22 33 44",
        $"raw={BytesHex(f13a.RawBytes)}, display=\"{f13a.DisplayValue}\"");
    Report("G13-03 ApplyFieldEdit returns EffectiveData reference",
        ReferenceEquals(ret13, p13a.EffectiveData), "");

    bool thr13a = false; string msg13a = "";
    try { ed13.ApplyFieldEdit(p13a, f13a, new byte[] { 1, 2, 3 }); }
    catch (Exception ex) { thr13a = true; msg13a = ex.Message; }
    Report("G13-04 length mismatch rejects and leaves packet unchanged",
        thr13a && msg13a.Contains("field expects 4 bytes but value is 3 bytes")
        && BytesEq(p13a.EffectiveData.AsSpan(26, 4).ToArray(), new byte[] { 0x11, 0x22, 0x33, 0x44 }),
        msg13a);

    bool thr13b = false; string msg13b = "";
    var f13Neg = new ProtocolField { Name = "Neg", Offset = -1, Length = 4, Kind = FieldKind.UInt, RawBytes = f13Src };
    try { ed13.ApplyFieldEdit(p13a, f13Neg, new byte[] { 1, 2, 3, 4 }); }
    catch (Exception ex) { thr13b = true; msg13b = ex.Message; }
    Report("G13-05 negative offset rejects (no valid offset)",
        thr13b && msg13b.Contains("Field has no valid offset."), msg13b);

    bool thr13c = false; string msg13c = ""; bool isRange13c = false;
    var f13Out = new ProtocolField { Name = "Out", Offset = 100, Length = 4, Kind = FieldKind.UInt, RawBytes = f13Src };
    try { ed13.ApplyFieldEdit(p13a, f13Out, new byte[] { 1, 2, 3, 4 }); }
    catch (Exception ex) { thr13c = true; msg13c = ex.Message; isRange13c = ex is ArgumentOutOfRangeException; }
    Report("G13-06 out-of-frame offset rejects (ArgumentOutOfRange)",
        thr13c && isRange13c && msg13c.Contains("exceeds packet data"), msg13c);

    var p13b = new Packet { Index = 2, Timestamp = 1001, RawData = (byte[])g13Frame.Clone() };
    var f13b = new ProtocolField { Name = "Source", OriginalPdmlName = "ip.src", Offset = 26, Length = 4, Kind = FieldKind.IPv4, RawBytes = f13Src };
    var hexRet = ed13.ApplyHexStringEdit(p13b, f13b, "0x11 22 33 44");
    Report("G13-07 hex apply strips spaces and 0x prefix",
        BytesEq(hexRet.AsSpan(26, 4).ToArray(), new byte[] { 0x11, 0x22, 0x33, 0x44 })
        && BytesEq(f13b.RawBytes, new byte[] { 0x11, 0x22, 0x33, 0x44 }),
        BytesHex(p13b.EffectiveData.AsSpan(26, 4).ToArray()));

    bool thr13d = false; string msg13d = "";
    try { ed13.ApplyHexStringEdit(p13b, f13b, "112233444"); }
    catch (Exception ex) { thr13d = true; msg13d = ex.Message; }
    Report("G13-08 odd-length hex rejects", thr13d && msg13d.Contains("even number of characters"), msg13d);

    var p13c = new Packet { Index = 3, Timestamp = 1002, RawData = (byte[])g13Frame.Clone() };
    var f13c = new ProtocolField { Name = "Source", OriginalPdmlName = "ip.src", Offset = 26, Length = 4, Kind = FieldKind.IPv4, RawBytes = f13Src };
    p13c.Layers.Add(new ProtocolLayer { ProtocolName = "ip", DisplayText = "Internet Protocol", Offset = 14 });
    p13c.Layers[0].Fields.Add(f13c);
    Report("G13-09 FindFieldAtOffset hits interior / misses outside",
        ReferenceEquals(ed13.FindFieldAtOffset(p13c, 27), f13c)
        && ReferenceEquals(ed13.FindFieldAtOffset(p13c, 29), f13c)
        && ed13.FindFieldAtOffset(p13c, 25) == null
        && ed13.FindFieldAtOffset(p13c, 30) == null,
        "offset 27/29 → field, 25/30 → null");
}
catch (Exception ex)
{
    Report("G13 group execution", false, ex.ToString());
}

Banner(14, "protocol layers on parsed frame (frame 2 of real capture)");
try
{
    if (read12 is null) Skip("G14 protocol layers on parsed frame", CaptureHint);
    else
    {
        var g14Pkt = new Packet
        {
            Index = 1,
            Timestamp = read12.Packets[1].Timestamp,
            RawData = (byte[])read12.Packets[1].Data.Clone(),
        };
        string g14Temp = Path.Combine(Path.GetTempPath(), $"pf_g14_{Guid.NewGuid():N}.pcap");
        bool g14ok = false;
        try
        {
            await exp12.SavePacketAsync(g14Pkt, g14Temp);
            g14ok = await tsh12.ParsePacketFromPcapFileAsync(g14Pkt, g14Temp);
            Report("G14-01 single-frame parse succeeds", g14ok, $"layers={g14Pkt.Layers.Count}");
            Report("G14-02 layer tree non-empty", g14ok && g14Pkt.Layers.Count > 0, g14Pkt.Layers.Count.ToString());
            Report("G14-03 eth + ip layers present",
                g14Pkt.Layers.Any(l => l.ProtocolName == "eth") && g14Pkt.Layers.Any(l => l.ProtocolName == "ip"),
                string.Join(", ", g14Pkt.Layers.Select(l => l.ProtocolName)));
            int g14parents = g14Pkt.Layers.Count(l => l.ParentPacket == g14Pkt);
            Report("G14-04 layer↔packet parent linkage (all-or-none tolerant)",
                g14parents == g14Pkt.Layers.Count || g14parents == 0,
                $"{g14parents}/{g14Pkt.Layers.Count} linked");
            // TR-03: tshark may report the same protocol twice (a tunnelled frame has
            // two IP layers). Both must survive as separate, independently addressable
            // rows — a collapse onto one offset would make the outer layer unreachable
            // and the inner layer's fields would highlight the wrong bytes.
            var g14Dupes = g14Pkt.Layers
                .GroupBy(l => l.ProtocolName)
                .Where(g => g.Count() > 1)
                .ToList();
            bool g14DupeOffsetsDistinct = g14Dupes.All(g =>
                g.Select(l => l.Offset).Distinct().Count() == g.Count());
            bool g14EveryLayerAddressable = g14Pkt.Layers.All(l => l.ParentPacket == g14Pkt);
            Report("G14-05 same-named layers stay distinct rows, each addressable (TR-03)",
                g14DupeOffsetsDistinct && g14EveryLayerAddressable,
                g14Dupes.Count == 0
                    ? "no duplicated layer name in this fixture"
                    : $"dupes={string.Join(";", g14Dupes.Select(g => $"{g.Key}x{g.Count()}@[{string.Join(",", g.Select(l => l.Offset))}]"))}, linked={g14EveryLayerAddressable}");
            int g14bits;
            int g14total = CountFields(g14Pkt.Layers.SelectMany(l => l.Fields).ToArray(), out g14bits);
            Report("G14-06 nested fields walkable (incl. bit-level)",
                g14total > 0, $"fields={g14total}, bit-level={g14bits}");
            Report("G14-07 ProtocolStack assembled", g14Pkt.ProtocolStack.Contains("IP"), g14Pkt.ProtocolStack);
        }
        finally
        {
            try { File.Delete(g14Temp); } catch { }
        }
    }
}
catch (Exception ex)
{
    Report("G14 group execution", false, ex.ToString());
}

Banner(15, "pre-send packet preparation — checksum repair + source rewrite (static)");
try
{
    var g15iface = new NetworkInterfaceInfo(
        "test0", "lo", "Test loopback",
        IPAddress.Parse("10.1.2.3"), IPAddress.Parse("fe80::1"),
        "AA:BB:CC:DD:EE:FF", true, true);
    var g15ifaceBad = g15iface with { MacAddress = "not-a-mac" };

    // Vector 1: eth/ipv4/udp with wrong UDP checksum (0xFFFF) — must be recomputed
    byte[] g15udp1 = Concat(U16(1234, false), U16(80, false), U16(12, false), U16(0xFFFF, false), new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });
    byte[] g15ip1 = Concat(new byte[] { 0x45, 0x00 }, U16(32, false), U16(1, false), U16(0x4000, false),
        new byte[] { 0x40, 0x11, 0x00, 0x00 }, new byte[] { 10, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 });
    byte[] g15f1 = Concat(new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00 }, g15ip1, g15udp1);
    byte[] g15p1 = PacketPrepareService.PrepareFrame(g15f1, g15iface);
    Report("G15a frame length preserved (46B)", g15p1.Length == 46, g15p1.Length.ToString());
    Report("G15b eth src MAC rewritten to iface",
        BytesEq(g15p1.AsSpan(6, 6).ToArray(), new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }),
        BytesHex(g15p1.AsSpan(6, 6).ToArray()));
    Report("G15c eth dst MAC preserved", BytesEq(g15p1.AsSpan(0, 6).ToArray(), g15f1.AsSpan(0, 6).ToArray()), "");
    Report("G15d ethertype preserved", BytesEq(g15p1.AsSpan(12, 2).ToArray(), new byte[] { 0x08, 0x00 }), BytesHex(g15p1.AsSpan(12, 2).ToArray()));
    Report("G15e IPv4 src rewritten to iface IP",
        BytesEq(g15p1.AsSpan(26, 4).ToArray(), IPAddress.Parse("10.1.2.3").GetAddressBytes()),
        BytesHex(g15p1.AsSpan(26, 4).ToArray()));
    Report("G15f IPv4 header checksum recomputed (fold == 0xFFFF)",
        FoldSum(g15p1, 14, 20) == 0xFFFF, $"fold=0x{FoldSum(g15p1, 14, 20):X4}");
    Report("G15g UDP checksum recomputed over pseudo-header (was 0xFFFF)",
        FoldSum(Concat(Pseudo4(g15p1, 26, 30, 17, 12), g15p1.AsSpan(34, 12).ToArray()), 0, 24) == 0xFFFF,
        $"fold=0x{FoldSum(Concat(Pseudo4(g15p1, 26, 30, 17, 12), g15p1.AsSpan(34, 12).ToArray()), 0, 24):X4}");

    // Vector 2: UDP checksum 0x0000 — must stay 0 (UDP-off convention)
    byte[] g15udp2 = Concat(U16(1234, false), U16(80, false), U16(12, false), U16(0, false), new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });
    byte[] g15f2 = Concat(new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00 }, g15ip1, g15udp2);
    byte[] g15p2 = PacketPrepareService.PrepareFrame(g15f2, g15iface);
    Report("G15h UDP checksum 0 stays 0 (UDP-off preserved)",
        BytesEq(g15p2.AsSpan(40, 2).ToArray(), new byte[] { 0x00, 0x00 }),
        BytesHex(g15p2.AsSpan(40, 2).ToArray()));

    // Vector 3: IPv4 + TCP (checksum always recomputed)
    byte[] g15tcp = Concat(U16(1234, false), U16(80, false), U32(0, false), U32(0, false),
        new byte[] { 0x50, 0x18 }, U16(0x4000, false), U16(0x1234, false), U16(0, false),
        new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF });
    byte[] g15ipT = Concat(new byte[] { 0x45, 0x00 }, U16(46, false), U16(1, false), U16(0x4000, false),
        new byte[] { 0x40, 0x06, 0x00, 0x00 }, new byte[] { 10, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 });
    byte[] g15f3 = Concat(new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00 }, g15ipT, g15tcp);
    byte[] g15p3 = PacketPrepareService.PrepareFrame(g15f3, g15iface);
    Report("G15i IPv4 TCP checksum recomputed",
        FoldSum(g15p3, 14, 20) == 0xFFFF && FoldSum(Concat(Pseudo4(g15p3, 26, 30, 6, 26), g15p3.AsSpan(34, 26).ToArray()), 0, 38) == 0xFFFF,
        $"ipFold=0x{FoldSum(g15p3, 14, 20):X4}");

    // Vector 4: IPv6 + TCP
    byte[] g15ip6 = Concat(new byte[] { 0x60, 0x00, 0x00, 0x00 }, U16(26, false), new byte[] { 6, 64 },
        IPAddress.Parse("fe80::2").GetAddressBytes(), IPAddress.Parse("fe80::3").GetAddressBytes());
    byte[] g15f4 = Concat(new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x86, 0xDD }, g15ip6, g15tcp);
    byte[] g15p4 = PacketPrepareService.PrepareFrame(g15f4, g15iface);
    Report("G15j IPv6 src rewritten to iface (at ipOffset+8)",
        BytesEq(g15p4.AsSpan(22, 16).ToArray(), IPAddress.Parse("fe80::1").GetAddressBytes()),
        BytesHex(g15p4.AsSpan(22, 16).ToArray()));
    Report("G15k IPv6 TCP checksum recomputed",
        FoldSum(Concat(Pseudo6(g15p4, 22, 38, 6, 26), g15p4.AsSpan(54, 26).ToArray()), 0, 66) == 0xFFFF,
        $"fold=0x{FoldSum(Concat(Pseudo6(g15p4, 22, 38, 6, 26), g15p4.AsSpan(54, 26).ToArray()), 0, 66):X4}");

    // Vector 5: bare IPv4 (no Ethernet) — ipOffset = 0, src rewrite at 12, no MAC rewrite
    byte[] g15f5 = Concat(g15ip1, g15udp1);
    byte[] g15p5 = PacketPrepareService.PrepareFrame(g15f5, g15iface);
    Report("G15l bare-IP src rewritten at offset 12",
        BytesEq(g15p5.AsSpan(12, 4).ToArray(), IPAddress.Parse("10.1.2.3").GetAddressBytes()),
        BytesHex(g15p5.AsSpan(12, 4).ToArray()));
    Report("G15m bare-IP bytes 6–7 untouched (no MAC rewrite)",
        BytesEq(g15p5.AsSpan(6, 2).ToArray(), new byte[] { 0x40, 0x00 }), BytesHex(g15p5.AsSpan(6, 2).ToArray()));
    Report("G15n bare-IP checksums valid",
        FoldSum(g15p5, 0, 20) == 0xFFFF && FoldSum(Concat(Pseudo4(g15p5, 12, 16, 17, 12), g15p5.AsSpan(20, 12).ToArray()), 0, 24) == 0xFFFF,
        $"ipFold=0x{FoldSum(g15p5, 0, 20):X4}");

    // Vector 6: unparseable MAC → no rewrite
    byte[] g15p6 = PacketPrepareService.PrepareFrame(g15f1, g15ifaceBad);
    Report("G15o invalid iface MAC → eth src left intact",
        BytesEq(g15p6.AsSpan(6, 6).ToArray(), g15f1.AsSpan(6, 6).ToArray()),
        BytesHex(g15p6.AsSpan(6, 6).ToArray()));

    // Vector 7: empty frame passes through untouched
    byte[] g15empty = Array.Empty<byte>();
    byte[] g15p7 = PacketPrepareService.PrepareFrame(g15empty, g15iface);
    Report("G15p empty frame passes through (same instance)",
        g15p7.Length == 0 && ReferenceEquals(g15p7, g15empty), "len=0, same ref");

    Report("G15q FindIpOffset matrix (eth0400→14, bare4→0, bare6→0, unknown→-1)",
        PacketPrepareService.FindIpOffset(Concat(new byte[12], new byte[] { 0x08, 0x00 })) == 14
        && PacketPrepareService.FindIpOffset(Concat(new byte[12], new byte[] { 0x86, 0xDD })) == 14
        && PacketPrepareService.FindIpOffset(Concat(new byte[] { 0x45, 0x00, 0x00, 0x1C }, new byte[16])) == 0
        && PacketPrepareService.FindIpOffset(Concat(new byte[] { 0x60, 0x00, 0x00, 0x00 }, new byte[36])) == 0
        && PacketPrepareService.FindIpOffset(Concat(new byte[12], new byte[] { 0x08, 0x01 })) == -1
        && PacketPrepareService.FindIpOffset(new byte[13]) == -1
        && PacketPrepareService.FindIpOffset(new byte[] { 0x00 }) == -1,
        "0800→14, 86DD→14, 45xx→0, 60xx→0, 0801→-1, short→-1, zero→-1");

    // Vector 8: IHL=4 (below the RFC 791 minimum of 5) → ihl computes to 16, which used to
    // pass the length check and then be checksummed as if it were a valid header. The guard
    // must skip the whole checksum path; the src rewrite above it is separately length-guarded.
    byte[] g15ipIhl4 = Concat(new byte[] { 0x44, 0x00 }, U16(20, false), U16(1, false), U16(0x4000, false),
        new byte[] { 0x40, 0x11, 0xDE, 0xAD }, new byte[] { 10, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 });
    byte[] g15f8 = Concat(new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00 }, g15ipIhl4, new byte[8]);
    byte[] g15p8 = PacketPrepareService.PrepareFrame(g15f8, g15iface);
    Report("G15r IHL<5 malformed IPv4 → header checksum left untouched",
        BytesEq(g15p8.AsSpan(24, 2).ToArray(), new byte[] { 0xDE, 0xAD }) && g15p8.Length == g15f8.Length,
        $"cksum={BytesHex(g15p8.AsSpan(24, 2).ToArray())}, len={g15p8.Length}");

    // Vector 9: IHL=5 is legal but the frame stops inside the IP header, so the checksum
    // write at ipOffset+10 used to throw IndexOutOfRange. The IPv4 area must survive intact;
    // the eth src MAC above ipOffset is still rewritten (that rewrite precedes the guard,
    // same as G15o asserts for a valid iface), so compare from ipOffset, not the whole frame.
    byte[] g15f9 = Concat(new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00 },
        new byte[] { 0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x40, 0x00 });
    byte[] g15p9 = PacketPrepareService.PrepareFrame(g15f9, g15iface);
    Report("G15s IHL=5 but IP header truncated → IPv4 area left untouched",
        g15p9.Length == g15f9.Length
        && BytesEq(g15p9.AsSpan(14).ToArray(), g15f9.AsSpan(14).ToArray())
        && BytesEq(g15p9.AsSpan(6, 6).ToArray(), new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }),
        $"len={g15p9.Length}, ip area intact, eth src rewritten");

    // Vector 10: the RFC 4960 §A.5 check value — CRC32c over ASCII "123456789"
    // must be 0xE3069283, pinning polynomial/init/final-XOR in one constant.
    byte[] g15crcCheck = System.Text.Encoding.ASCII.GetBytes("123456789");
    uint g15crcCheckGot = PacketPrepareService.ComputeCrc32c(g15crcCheck, 0, g15crcCheck.Length);
    Report("G15t ComputeCrc32c matches the RFC 4960 check value",
        g15crcCheckGot == 0xE3069283u, $"0x{g15crcCheckGot:X8}");

    // Vector 11: IPv4 + SCTP with a bogus checksum — PrepareFrame must rewrite it,
    // stored little-endian per RFC 4960 §3.10, consistent with a fresh recomputation
    // over the checksum-zeroed SCTP section.
    byte[] g15sctp = Concat(U16(1234, false), U16(5678, false), U32(0x11223344, false), U32(0xDEADBEEF, false));
    byte[] g15ipS = Concat(new byte[] { 0x45, 0x00 }, U16(32, false), U16(1, false), U16(0x4000, false),
        new byte[] { 0x40, 0x84, 0x00, 0x00 }, new byte[] { 10, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 });
    byte[] g15fS = Concat(new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00 }, g15ipS, g15sctp);
    byte[] g15pS = PacketPrepareService.PrepareFrame(g15fS, g15iface);
    byte[] g15sctpSection = g15pS.AsSpan(34, 12).ToArray();
    uint g15stored = (uint)(g15sctpSection[8] | (g15sctpSection[9] << 8) | (g15sctpSection[10] << 16) | (g15sctpSection[11] << 24));
    g15sctpSection[8] = 0; g15sctpSection[9] = 0; g15sctpSection[10] = 0; g15sctpSection[11] = 0;
    uint g15crcRe = PacketPrepareService.ComputeCrc32c(g15sctpSection, 0, g15sctpSection.Length);
    Report("G15u IPv4 SCTP CRC32c rewritten little-endian and self-consistent",
        g15stored == g15crcRe && g15stored != 0xDEADBEEFu,
        $"stored=0x{g15stored:X8}, recomputed=0x{g15crcRe:X8}");

    // Vector 12 (P0-1): an exactly-14-byte Ethernet-II frame whose ethertype is IPv4 but
    // that carries no payload — FindIpOffset returns 14 == frame.Length and the old
    // result[14] read threw IndexOutOfRange.
    byte[] g15f14 = Concat(new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00 });
    bool g15Threw14 = false;
    byte[] g15p14 = Array.Empty<byte>();
    try { g15p14 = PacketPrepareService.PrepareFrame(g15f14, g15iface); }
    catch (Exception) { g15Threw14 = true; }
    Report("G15v PrepareFrame on a 14-byte Ethernet-II frame does not throw and preserves length",
        !g15Threw14 && g15p14.Length == 14,
        $"threw={g15Threw14}, len={g15p14.Length}");

    // Vector 13 (P0-2a): IPv6 + Hop-by-Hop extension header + TCP. The source rewrite must
    // still occur AND the TCP checksum must be recomputed, since it covers the IPv6
    // pseudo-header (which contains the source address). Payload Length = 8 (HbH) + 20 (TCP).
    byte[] g15hbh = new byte[] { 0x06, 0x00, 0x01, 0x04, 0, 0, 0, 0 };
    byte[] g15tcp20 = BuildTcpSegment(1234, 80, 0, 0, 0x18, Array.Empty<byte>());
    byte[] g15ip6hb = Concat(new byte[] { 0x60, 0x00, 0x00, 0x00 }, U16(8 + g15tcp20.Length, false),
        new byte[] { 0, 64 }, IPAddress.Parse("fe80::2").GetAddressBytes(), IPAddress.Parse("fe80::3").GetAddressBytes());
    byte[] g15f6hb = Concat(new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x86, 0xDD },
        g15ip6hb, g15hbh, g15tcp20);
    byte[] g15p6hb = PacketPrepareService.PrepareFrame(g15f6hb, g15iface);
    Report("G15w IPv6 + Hop-by-Hop + TCP rewrites source and fixes the TCP checksum",
        BytesEq(g15p6hb.AsSpan(22, 16).ToArray(), IPAddress.Parse("fe80::1").GetAddressBytes())
        && FoldSum(Concat(Pseudo6(g15p6hb, 22, 38, 6, g15tcp20.Length), g15p6hb.AsSpan(62, g15tcp20.Length).ToArray()), 0, 40 + g15tcp20.Length) == 0xFFFF,
        $"src={BytesHex(g15p6hb.AsSpan(22, 16).ToArray())}, " +
        $"fold=0x{FoldSum(Concat(Pseudo6(g15p6hb, 22, 38, 6, g15tcp20.Length), g15p6hb.AsSpan(62, g15tcp20.Length).ToArray()), 0, 40 + g15tcp20.Length):X4}");

    // Vector 14 (P0-2b): IPv6 + ICMPv6 (Next Header 58). ICMPv6's checksum is not recomputed
    // here, so the source address must be left exactly as captured — rewriting it would strand
    // a checksum that covers the old source address.
    byte[] g15icmp6 = new byte[] { 0x80, 0x00, 0x00, 0x00, 0, 0, 0, 0 };
    byte[] g15ip6ic = Concat(new byte[] { 0x60, 0x00, 0x00, 0x00 }, U16(g15icmp6.Length, false),
        new byte[] { 58, 64 }, IPAddress.Parse("fe80::2").GetAddressBytes(), IPAddress.Parse("fe80::3").GetAddressBytes());
    byte[] g15f6ic = Concat(new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x86, 0xDD },
        g15ip6ic, g15icmp6);
    byte[] g15p6ic = PacketPrepareService.PrepareFrame(g15f6ic, g15iface);
    Report("G15x IPv6 + ICMPv6 (Next Header 58) leaves the source address untouched",
        BytesEq(g15p6ic.AsSpan(22, 16).ToArray(), IPAddress.Parse("fe80::2").GetAddressBytes()),
        $"src={BytesHex(g15p6ic.AsSpan(22, 16).ToArray())}");

    // Vector 15 (P0-3): an ARP Ethernet frame whose destination MAC starts with 0x45. The
    // version-nibble fallback used to misread it as a bare IPv4 datagram (offset 0); the
    // positive Ethernet/non-IP detection must return -1 and PrepareFrame must not touch it.
    byte[] g15arp = Concat(new byte[] { 0x45, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x06 },
        new byte[] { 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01 }, new byte[10]);
    byte[] g15pArp = PacketPrepareService.PrepareFrame(g15arp, g15iface);
    Report("G15y ARP Ethernet frame with 0x45 dst MAC → FindIpOffset -1 and frame unchanged",
        PacketPrepareService.FindIpOffset(g15arp) == -1 && BytesEq(g15pArp, g15arp),
        $"ipOffset={PacketPrepareService.FindIpOffset(g15arp)}, unchanged={BytesEq(g15pArp, g15arp)}");

    // Vector 16 (P0-3): the bare-datagram fallback still validates structurally — a valid
    // bare IPv4 returns 0 (the G15q contract), a bad-IHL one returns -1.
    Report("G15z bare-IP fallback still returns 0 for valid IPv4 and -1 for a bad IHL",
        PacketPrepareService.FindIpOffset(Concat(new byte[] { 0x45, 0x00, 0x00, 0x1C }, new byte[16])) == 0
        && PacketPrepareService.FindIpOffset(Concat(new byte[] { 0x44, 0x00, 0x00, 0x1C }, new byte[16])) == -1,
        "valid=0, IHL<5=-1");

    // 源 MAC 取接口自身 MAC，使 PrepareFrame 的源 MAC 改写（偏移 6）成为空操作，
    // G15aa 才能断言“整帧未改动”。后续向量只检查源地址区，共用该以太头无碍。
    byte[] g15ethHdr = new byte[] { 0x02, 0, 0, 0, 0, 1, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x86, 0xDD };
    byte[] g15src6 = IPAddress.Parse("fe80::2").GetAddressBytes();
    byte[] g15dst6 = IPAddress.Parse("fe80::3").GetAddressBytes();
    byte[] g15ip6Hdr(int next, int payload) => Concat(new byte[] { 0x60, 0x00, 0x00, 0x00 }, U16(payload, false),
        new byte[] { (byte)next, 64 }, g15src6, g15dst6);

    // Vector 17 (FIX-1): a non-atomic Fragment header (offset=1) means the bytes after it
    // are fragment payload, not a transport header — nothing may be rewritten, including
    // the two bytes the old code mistook for a TCP checksum.
    byte[] g15fFrag1 = Concat(g15ethHdr, g15ip6Hdr(44, 8 + g15tcp20.Length),
        new byte[] { 0x06, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01 }, g15tcp20);
    byte[] g15pFrag1 = PacketPrepareService.PrepareFrame(g15fFrag1, g15iface);
    Report("G15aa non-atomic IPv6 fragment (offset=1) leaves the whole frame untouched",
        BytesEq(g15pFrag1, g15fFrag1),
        $"unchanged={BytesEq(g15pFrag1, g15fFrag1)}, src={BytesHex(g15pFrag1.AsSpan(22, 16).ToArray())}");

    // Vector 18 (FIX-1): an atomic Fragment header (offset=0 && M=0, RFC 6946) is
    // transparent, so the walk reaches TCP and both the source rewrite and the checksum
    // recompute still happen.
    byte[] g15fFrag0 = Concat(g15ethHdr, g15ip6Hdr(44, 8 + g15tcp20.Length),
        new byte[] { 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, g15tcp20);
    byte[] g15pFrag0 = PacketPrepareService.PrepareFrame(g15fFrag0, g15iface);
    Report("G15ab atomic IPv6 fragment (offset=0,M=0) rewrites source and fixes TCP checksum",
        BytesEq(g15pFrag0.AsSpan(22, 16).ToArray(), IPAddress.Parse("fe80::1").GetAddressBytes())
        && FoldSum(Concat(Pseudo6(g15pFrag0, 22, 38, 6, g15tcp20.Length), g15pFrag0.AsSpan(62, g15tcp20.Length).ToArray()), 0, 40 + g15tcp20.Length) == 0xFFFF,
        $"src={BytesHex(g15pFrag0.AsSpan(22, 16).ToArray())}");

    // Vector 19 (FIX-2): a truncated frame (Payload Length 200 > captured 20) cannot have
    // its transport checksum recomputed, so the source stays exactly as captured.
    byte[] g15fTrunc = Concat(g15ethHdr, g15ip6Hdr(6, 200), g15tcp20);
    byte[] g15pTrunc = PacketPrepareService.PrepareFrame(g15fTrunc, g15iface);
    Report("G15ac IPv6 with PayloadLength past the frame leaves the source unchanged",
        BytesEq(g15pTrunc.AsSpan(22, 16).ToArray(), g15src6),
        $"src={BytesHex(g15pTrunc.AsSpan(22, 16).ToArray())}");

    // Vector 20 (FIX-3): AH authenticates the IPv6 header (including the source), so the
    // walk must treat it as non-resolvable and never touch the source.
    byte[] g15fAh = Concat(g15ethHdr, g15ip6Hdr(51, 12 + g15tcp20.Length),
        new byte[] { 0x06, 0x01, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0 }, g15tcp20);
    byte[] g15pAh = PacketPrepareService.PrepareFrame(g15fAh, g15iface);
    Report("G15ad IPv6 + AH (next=51) leaves the source unchanged",
        BytesEq(g15pAh.AsSpan(22, 16).ToArray(), g15src6),
        $"src={BytesHex(g15pAh.AsSpan(22, 16).ToArray())}");

    // Vector 21 (FIX-4): a Routing header with Segments Left > 0 has a pseudo-header
    // destination that is the last address in the header, not the IPv6 destination, so the
    // source must not change.
    byte[] g15fRt = Concat(g15ethHdr, g15ip6Hdr(43, 24 + g15tcp20.Length),
        new byte[] { 0x06, 0x02, 0x00, 0x01, 0, 0, 0, 0 }, IPAddress.Parse("fe80::9").GetAddressBytes(),
        g15tcp20);
    byte[] g15pRt = PacketPrepareService.PrepareFrame(g15fRt, g15iface);
    Report("G15ae IPv6 + Routing (SegmentsLeft=1) leaves the source unchanged",
        BytesEq(g15pRt.AsSpan(22, 16).ToArray(), g15src6),
        $"src={BytesHex(g15pRt.AsSpan(22, 16).ToArray())}");

    // Vector 22 (方案 B): DLT 感知的 IP 定位。裸 IPv4 的 12–13 字节恰为 0x0800 时，
    // 字节启发式会误判为以太网(offset 14)；RAW DLT 下必须仍按裸数据报处理(offset 0)，
    // 源地址改写在 12，且不动 6–7 字节（不发散为 MAC 改写）。
    byte[] g15dcls = Concat(
        new byte[] { 0x45, 0x00 }, U16(20, false), U16(1, false), U16(0x4000, false),
        new byte[] { 0x40, 0x11, 0x00, 0x00 }, new byte[] { 8, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 });
    byte[] g15dclsOut = PacketPrepareService.PrepareFrame(g15dcls, g15iface, 101);
    Report("G15af RAW DLT: bare IPv4 with bytes12-13=0x0800 stays bare (offset 0, src at 12, no MAC)",
        PacketPrepareService.FindIpOffset(g15dcls, 101) == 0
        && BytesEq(g15dclsOut.AsSpan(12, 4).ToArray(), IPAddress.Parse("10.1.2.3").GetAddressBytes())
        && BytesEq(g15dclsOut.AsSpan(6, 2).ToArray(), new byte[] { 0x40, 0x00 }),
        $"ipOffset={PacketPrepareService.FindIpOffset(g15dcls, 101)}, src={BytesHex(g15dclsOut.AsSpan(12, 4).ToArray())}");

    Report("G15ag RAW DLT: a real Ethernet frame is not Ethernet-parsed (offset -1)",
        PacketPrepareService.FindIpOffset(g15f1, 101) == -1,
        $"ipOffset={PacketPrepareService.FindIpOffset(g15f1, 101)}");

    Report("G15ah Ethernet DLT: a real Ethernet frame resolves to offset 14",
        PacketPrepareService.FindIpOffset(g15f1, 1) == 14,
        $"ipOffset={PacketPrepareService.FindIpOffset(g15f1, 1)}");

    Report("G15ai Ethernet DLT: ARP frame returns -1 (no bare fallback)",
        PacketPrepareService.FindIpOffset(g15arp, 1) == -1,
        $"ipOffset={PacketPrepareService.FindIpOffset(g15arp, 1)}");

    byte[] g15bare6 = g15ip6Hdr(6, 0);
    Report("G15aj IPv4/IPv6 DLTs are version-gated (228→v4 only, 229→v6 only)",
        PacketPrepareService.FindIpOffset(g15dcls, 228) == 0
        && PacketPrepareService.FindIpOffset(g15bare6, 228) == -1
        && PacketPrepareService.FindIpOffset(g15bare6, 229) == 0
        && PacketPrepareService.FindIpOffset(g15dcls, 229) == -1,
        $"v4@228={PacketPrepareService.FindIpOffset(g15dcls, 228)}, v6@229={PacketPrepareService.FindIpOffset(g15bare6, 229)}");

    Report("G15ak HasEthernetHeader is DLT-aware",
        PacketPrepareService.HasEthernetHeader(g15f1, 1)
        && !PacketPrepareService.HasEthernetHeader(g15dcls, 101),
        $"eth@1={PacketPrepareService.HasEthernetHeader(g15f1, 1)}, bare@101={PacketPrepareService.HasEthernetHeader(g15dcls, 101)}");

    Report("G15al unknown DLT keeps the historical heuristic (eth→14, bare→0)",
        PacketPrepareService.FindIpOffset(g15f1, PacketPrepareService.LinkTypeUnknown) == 14
        && PacketPrepareService.FindIpOffset(g15ip1, PacketPrepareService.LinkTypeUnknown) == 0,
        $"eth={PacketPrepareService.FindIpOffset(g15f1, PacketPrepareService.LinkTypeUnknown)}, bare={PacketPrepareService.FindIpOffset(g15ip1, PacketPrepareService.LinkTypeUnknown)}");
}
catch (Exception ex)
{
    Report("G15 group execution", false, ex.ToString());
}

Banner(16, "verify-before-commit — abort reasons byte-identical, legal commit lands");
try
{
    if (read12 is null) Skip("G16 verify-before-commit", CaptureHint);
    else
    {
        byte[] g16Raw = read12.Packets[TargetIndex].Data;
        var g16Pkt = new Packet
        {
            Index = TargetIndex,
            Timestamp = read12.Packets[TargetIndex].Timestamp,
            RawData = (byte[])g16Raw.Clone(),
        };
        byte[] vSrc = g16Raw.AsSpan(26, 4).ToArray();
        var g16tx = new EditTransactionService(exp12, tsh12);
        byte[] g16Before = (byte[])g16Pkt.EffectiveData.Clone();

        // 1. Drift: field claims offset 34 but ip.src really lives at 26
        var fDrift = new ProtocolField { Name = "Source", OriginalPdmlName = "ip.src", Offset = 34, Length = 4, Kind = FieldKind.IPv4, RawBytes = vSrc };
        var rDrift = await g16tx.CommitFieldEditAsync(g16Pkt, fDrift, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, null, read12.LinkLayerType);
        string expDrift = LocalizationService.Resolve("Vbc.OffsetDrift", "ip.src", 26, 34);
        Report("G16a offset drift aborts with OffsetDrift(26→34)",
            !rDrift.Success && rDrift.Reason == expDrift, $"success={rDrift.Success} reason=\"{rDrift.Reason}\"");
        Report("G16b drift abort leaves packet byte-identical",
            BytesEq(g16Pkt.EffectiveData, g16Before) && !g16Pkt.IsModified, "unchanged");

        // 2. Nonexistent field name → NotLanding
        var fNo = new ProtocolField { Name = "Bogus", OriginalPdmlName = "nonexistent.field", Offset = 0, Length = 4, Kind = FieldKind.UInt, RawBytes = g16Raw.AsSpan(0, 4).ToArray() };
        var rNo = await g16tx.CommitFieldEditAsync(g16Pkt, fNo, new byte[] { 1, 2, 3, 4 }, null, read12.LinkLayerType);
        string expNo = LocalizationService.Resolve("Vbc.NotLanding", "nonexistent.field", 0);
        Report("G16c unknown field name aborts with NotLanding",
            !rNo.Success && rNo.Reason == expNo, $"reason=\"{rNo.Reason}\"");
        Report("G16d notlanding abort leaves packet byte-identical",
            BytesEq(g16Pkt.EffectiveData, g16Before) && !g16Pkt.IsModified, "unchanged");

        // 3. Container field (Length 0) with child at 26 → ValueMismatch
        var fChild = new ProtocolField { Name = "Source", OriginalPdmlName = "ip.src", Offset = 26, Length = 4, Kind = FieldKind.IPv4, RawBytes = vSrc };
        var fCont = new ProtocolField { Name = "Source", OriginalPdmlName = "ip.src", Offset = 30, Length = 0, Kind = FieldKind.IPv4, RawBytes = vSrc };
        fCont.Children.Add(fChild);
        var rCont = await g16tx.CommitFieldEditAsync(g16Pkt, fCont, new byte[] { 0x11, 0x22, 0x33, 0x44 }, null, read12.LinkLayerType);
        string expCont = LocalizationService.Resolve("Vbc.ValueMismatch", BytesHex(vSrc).ToLowerInvariant(), 26, "11223344");
        Report("G16e container field resolves to child offset then aborts on ValueMismatch",
            !rCont.Success && rCont.Reason == expCont, $"reason=\"{rCont.Reason}\"");
        Report("G16f container abort leaves packet byte-identical",
            BytesEq(g16Pkt.EffectiveData, g16Before) && !g16Pkt.IsModified, "unchanged");

        // 4. Length mismatch (checksum.status has no value attr → LengthMismatch reached)
        var fLen = new ProtocolField { Name = "CksumStatus", OriginalPdmlName = "ip.checksum.status", Offset = 24, Length = 3, Kind = FieldKind.UInt, RawBytes = g16Raw.AsSpan(24, 3).ToArray() };
        var rLen = await g16tx.CommitFieldEditAsync(g16Pkt, fLen, new byte[] { 3, 3, 3, 3, 3 }, null, read12.LinkLayerType);
        string expLen = LocalizationService.Resolve("Vbc.LengthMismatch", 3, 5);
        Report("G16g length change aborts with LengthMismatch(3,5)",
            !rLen.Success && rLen.Reason == expLen, $"reason=\"{rLen.Reason}\"");
        Report("G16h length abort leaves packet byte-identical",
            BytesEq(g16Pkt.EffectiveData, g16Before) && !g16Pkt.IsModified, "unchanged");

        // 5. Value mismatch (ip.hdr_len stays 0x45, expected 4500003c)
        var fVal = new ProtocolField { Name = "HdrLen", OriginalPdmlName = "ip.hdr_len", Offset = 14, Length = 1, Kind = FieldKind.UInt, HexPreferred = true, RawBytes = new byte[] { g16Raw[14] } };
        var rVal = await g16tx.CommitFieldEditAsync(g16Pkt, fVal, new byte[] { 0x45, 0x00, 0x00, 0x3C }, null, read12.LinkLayerType);
        string expVal = LocalizationService.Resolve("Vbc.ValueMismatch", Convert.ToHexString(new byte[] { g16Raw[14] }).ToLowerInvariant(), 14, "4500003c");
        Report("G16i value mismatch aborts with ValueMismatch",
            !rVal.Success && rVal.Reason == expVal, $"reason=\"{rVal.Reason}\"");
        Report("G16j value abort leaves packet byte-identical",
            BytesEq(g16Pkt.EffectiveData, g16Before) && !g16Pkt.IsModified, "unchanged");

        // 6. Legal commit: flip one bit of ip.src
        byte[] vLegal = (byte[])vSrc.Clone();
        vLegal[3] ^= 0x01;
        var fLegal = new ProtocolField { Name = "Source", OriginalPdmlName = "ip.src", Offset = 26, Length = 4, Kind = FieldKind.IPv4, RawBytes = vSrc };
        var rLegal = await g16tx.CommitFieldEditAsync(g16Pkt, fLegal, vLegal, null, read12.LinkLayerType);
        Report("G16k legal commit succeeds with Reason OK",
            rLegal.Success && rLegal.Reason == "OK", $"success={rLegal.Success} reason=\"{rLegal.Reason}\"");
        Report("G16l legal commit lands bytes at offset 26",
            BytesEq(g16Pkt.EffectiveData.AsSpan(26, 4).ToArray(), vLegal)
            && BytesEq(fLegal.RawBytes, vLegal),
            $"new={BytesHex(g16Pkt.EffectiveData.AsSpan(26, 4).ToArray())}");
        Report("G16m packet marked modified after commit", g16Pkt.IsModified && g16Pkt.EffectiveData.Length == g16Pkt.RawData.Length, "");
    }
}
catch (Exception ex)
{
    Report("G16 group execution", false, ex.ToString());
}

Banner(17, "PCAP/PCAPNG ingestion — classic endianness/ns, pcapng sections, resolutions");
{
    var g17Ing = new PcapIngestService();
    var g17Temps = new List<string>();
    try
    {
        async Task<PcapReadResult> G17Read(byte[] file)
        {
            string p = Path.Combine(Path.GetTempPath(), $"pf_g17_{Guid.NewGuid():N}.pcap");
            g17Temps.Add(p);
            await File.WriteAllBytesAsync(p, file);
            return await g17Ing.ReadPacketsAsync(p);
        }

        // P-01a: little-endian µs classic
        var p01a = await G17Read(Concat(ClassicHeader(false, true), ClassicRecord(1_000_005, new byte[] { 0xAA, 0x55, 0x00, 0xFF }, false, true)));
        Report("G17-01 LE µs classic header + record",
            p01a.Packets.Count == 1 && p01a.Packets[0].Timestamp == 1_000_005
            && BytesEq(p01a.Packets[0].Data, new byte[] { 0xAA, 0x55, 0x00, 0xFF })
            && p01a.IsLittleEndian && !p01a.IsNanoSeconds
            && p01a.VersionMajor == 2 && p01a.VersionMinor == 4
            && p01a.LinkLayerType == 1 && p01a.Snaplen == 65535,
            $"{p01a.Packets.Count} pkts, ts={p01a.Packets[0].Timestamp}, le={p01a.IsLittleEndian}, ns={p01a.IsNanoSeconds}");

        // P-01b: big-endian µs classic
        var p01b = await G17Read(Concat(ClassicHeader(false, false), ClassicRecord(1_000_005, new byte[] { 0xAA, 0x55, 0x00, 0xFF }, false, false)));
        Report("G17-02 BE µs classic",
            p01b.Packets.Count == 1 && p01b.Packets[0].Timestamp == 1_000_005
            && BytesEq(p01b.Packets[0].Data, new byte[] { 0xAA, 0x55, 0x00, 0xFF })
            && !p01b.IsLittleEndian && !p01b.IsNanoSeconds,
            $"le={p01b.IsLittleEndian}");

        // P-03: multiple records
        var p03 = await G17Read(Concat(ClassicHeader(false, true), ClassicRecord(500, new byte[] { 0x01 }, false, true), ClassicRecord(600, new byte[] { 0x02, 0x03 }, false, true)));
        Report("G17-03 multiple classic records ordered",
            p03.Packets.Count == 2 && p03.Packets[0].Timestamp == 500 && p03.Packets[1].Timestamp == 600
            && BytesEq(p03.Packets[1].Data, new byte[] { 0x02, 0x03 }),
            $"count={p03.Packets.Count}, ts=[{p03.Packets[0].Timestamp},{p03.Packets[1].Timestamp}]");

        // P-04a/b: nanosecond classic
        var p04a = await G17Read(Concat(ClassicHeader(true, true), ClassicRecord(1_123_456, new byte[] { 0x10 }, true, true)));
        var p04b = await G17Read(Concat(ClassicHeader(true, false), ClassicRecord(1_123_456, new byte[] { 0x10 }, true, false)));
        Report("G17-04 LE/BE ns classic flags + fractional conversion",
            p04a.Packets[0].Timestamp == 1_123_456 && p04a.IsNanoSeconds && p04a.IsLittleEndian
            && p04b.Packets[0].Timestamp == 1_123_456 && p04b.IsNanoSeconds && !p04b.IsLittleEndian,
            $"le_ns={p04a.Packets[0].Timestamp}, be_ns={p04b.Packets[0].Timestamp}");

        // P-05: dual-section pcapng (BE section 101/4096, LE section 1/65535)
        var p05 = await G17Read(Concat(
            MkShb(false), MkIdb(101, 4096, false), MkEpb(111, new byte[] { 0x01, 0x02 }, false),
            MkShb(true), MkIdb(1, 65535, true), MkEpb(222, new byte[] { 0x03, 0x04 }, true)));
        Report("G17-05 dual-section pcapng — last section wins",
            p05.Packets.Count == 2 && p05.Packets[0].Timestamp == 111 && p05.Packets[1].Timestamp == 222
            && BytesEq(p05.Packets[0].Data, new byte[] { 0x01, 0x02 })
            && BytesEq(p05.Packets[1].Data, new byte[] { 0x03, 0x04 })
            && p05.LinkLayerType == 1 && p05.Snaplen == 65535 && p05.IsLittleEndian && p05.VersionMajor == 1,
            $"count={p05.Packets.Count}, link={p05.LinkLayerType}, snap={p05.Snaplen}, le={p05.IsLittleEndian}, ver={p05.VersionMajor}");

        // P-06a: tsresol 0x03 (decimal exponent) raw=5 → 5000
        var p06a = await G17Read(Concat(MkShb(true), MkIdb(1, 65535, true, 0x03), MkEpb(5, new byte[] { 0xAA }, true)));
        Report("G17-06 decimal tsresol exponent (0x03): raw 5 → 5000 µs",
            p06a.Packets.Count == 1 && p06a.Packets[0].Timestamp == 5_000, $"ts={p06a.Packets[0].Timestamp}");

        // P-06b: tsresol 0x83 (power-of-two, n=3) raw=125000 → 1 µs
        var p06b = await G17Read(Concat(MkShb(true), MkIdb(1, 65535, true, 0x83), MkEpb(125_000, new byte[] { 0xBB }, true)));
        Report("G17-07 power-of-two tsresol (0x83): raw 125000 → 1 µs",
            p06b.Packets.Count == 1 && p06b.Packets[0].Timestamp == 1, $"ts={p06b.Packets[0].Timestamp}");

        // P-07: truncated record tail tolerated
        var p07 = await G17Read(Concat(ClassicHeader(false, true), ClassicRecord(100, new byte[] { 0xAA, 0x55, 0x00, 0xFF }, false, true), new byte[10]));
        Report("G17-08 truncated trailing record → 1 packet, ts 100",
            p07.Packets.Count == 1 && p07.Packets[0].Timestamp == 100, $"count={p07.Packets.Count}, ts={p07.Packets[0].Timestamp}");

        // P-08: unknown magic
        bool threwBad = false; string msgBad = "";
        try { await G17Read(Concat(new byte[] { 0x11, 0x22, 0x33, 0x44 }, new byte[20])); }
        catch (Exception ex) { threwBad = true; msgBad = ex.Message; }
        Report("G17-09 unknown magic rejected with hex value",
            threwBad && msgBad.Contains("44332211"), msgBad);

        // P-09: too small
        bool threwSmall = false; string msgSmall = "";
        try { await G17Read(new byte[20]); }
        catch (Exception ex) { threwSmall = true; msgSmall = ex.Message; }
        Report("G17-10 undersized file rejected (too small)",
            threwSmall && msgSmall.Contains("File too small"), msgSmall);

        // P-10: missing file
        bool threwMiss = false;
        try { await g17Ing.ReadPacketsAsync(Path.Combine(Path.GetTempPath(), $"pf_missing_{Guid.NewGuid():N}.pcap")); }
        catch (Exception ex) { threwMiss = ex is System.IO.FileNotFoundException; }
        Report("G17-11 missing file → FileNotFoundException", threwMiss, "");

        // P-11: EPB + SPB in one file (SPB inherits EPB timestamp)
        var p11 = await G17Read(Concat(
            MkShb(true), MkIdb(1, 65535, true),
            MkEpb(5_000_000, new byte[] { 0x01, 0x02, 0x03, 0x04 }, true),
            MkSpb(4, new byte[] { 0x05, 0x06, 0x07, 0x08 }, true)));
        Report("G17-12 EPB + SPB mix — SPB inherits previous timestamp",
            p11.Packets.Count == 2 && p11.Packets[0].Timestamp == 5_000_000 && p11.Packets[1].Timestamp == 5_000_000
            && BytesEq(p11.Packets[0].Data, new byte[] { 0x01, 0x02, 0x03, 0x04 })
            && BytesEq(p11.Packets[1].Data, new byte[] { 0x05, 0x06, 0x07, 0x08 }),
            $"count={p11.Packets.Count}, ts[0]={p11.Packets[0].Timestamp}, ts[1]={p11.Packets[1].Timestamp}");

        // P-12: each truncated block is sized so the loop guard (offset+12) passes but the
        // block's fixed fields do not fit. Pre-fix these read past data.Length and threw,
        // failing the whole load; each type now has its own minimum (SHB 28 / IDB 20 / EPB 32 /
        // SPB 16 / LPB 32). The BOM stays valid in the short SHB so it is the version read that
        // used to go out of bounds.
        var g17BadShb = await G17Read(Concat(MkShb(true), U32(0x0A0D0D0Au, true), U32(12, true), U32(0x1A2B3C4Du, true)));
        Report("G17-14 truncated SHB (totalLen 12) tolerated", g17BadShb.Packets.Count == 0, $"count={g17BadShb.Packets.Count}");

        var g17BadIdb = await G17Read(Concat(MkShb(true), U32(1, true), U32(12, true), U32(0, true)));
        Report("G17-15 truncated IDB (totalLen 12) tolerated", g17BadIdb.Packets.Count == 0, $"count={g17BadIdb.Packets.Count}");

        var g17BadEpb = await G17Read(Concat(MkShb(true), MkIdb(1, 65535, true), U32(6, true), U32(12, true), U32(0, true)));
        Report("G17-16 truncated EPB (totalLen 12) tolerated", g17BadEpb.Packets.Count == 0, $"count={g17BadEpb.Packets.Count}");

        // SPB was the one type that did not throw — totalLen 12 underflows its avail
        // computation to -4 and silently emitted a zero-length packet. Now skipped.
        var g17BadSpb = await G17Read(Concat(MkShb(true), MkIdb(1, 65535, true), U32(3, true), U32(12, true), U32(0, true)));
        Report("G17-17 undersized SPB (totalLen 12) skipped, not an empty packet",
            g17BadSpb.Packets.Count == 0, $"count={g17BadSpb.Packets.Count}");

        var g17BadLpb = await G17Read(Concat(MkShb(true), MkIdb(1, 65535, true), U32(2, true), U32(12, true), U32(0, true)));
        Report("G17-18 truncated legacy PB (totalLen 12) tolerated", g17BadLpb.Packets.Count == 0, $"count={g17BadLpb.Packets.Count}");

        // P-02: real-world pcapng — optional, needs a separate large local capture.
        // Deliberately not PF_CAPTURE: this group needs the >=180k-packet file, and
        // pointing PF_CAPTURE at a small capture makes G1/G16/G19 fail instead.
        string? largeEnv = Environment.GetEnvironmentVariable("PF_CAPTURE_LARGE");
        string? g17Pcapng = string.IsNullOrWhiteSpace(largeEnv)
            ? null
            : Path.IsPathRooted(largeEnv) ? largeEnv : Path.Combine(repoRoot, largeEnv);
        if (g17Pcapng is not null && File.Exists(g17Pcapng))
        {
            var p02 = await g17Ing.ReadPacketsAsync(g17Pcapng);
            Report("G17-13 real pcapng loads (>=180k packets, link type set)",
                p02.Packets.Count >= 180_000 && p02.LinkLayerType > 0,
                $"count={p02.Packets.Count}, link={p02.LinkLayerType}, snap={p02.Snaplen}");
        }
        else
        {
            Skip("G17-13 real pcapng loads", "PF_CAPTURE_LARGE unset — the large local capture is not committed");
        }
    }
    catch (Exception ex)
    {
        Report("G17 group execution", false, ex.ToString());
    }
    finally
    {
        foreach (var t in g17Temps) { try { File.Delete(t); } catch { } }
    }
}

Banner(18, "PCAP export — byte-exact header/records, modified-only, round trip");
{
    var g18Exp = new PcapExportService();
    var g18Ing = new PcapIngestService();
    string g18Path = Path.Combine(Path.GetTempPath(), $"pf_g18_{Guid.NewGuid():N}.pcap");
    string g18Path2 = Path.Combine(Path.GetTempPath(), $"pf_g18b_{Guid.NewGuid():N}.pcap");
    string g18Path3 = Path.Combine(Path.GetTempPath(), $"pf_g18c_{Guid.NewGuid():N}.pcap");
    string g18Path4 = Path.Combine(Path.GetTempPath(), $"pf_g18d_{Guid.NewGuid():N}.pcap");
    try
    {
        var xPkts = new List<Packet>
        {
            new Packet { Timestamp = 1_000_005, RawData = new byte[] { 0xAA, 0x55 } },
            new Packet { Timestamp = 1_000_010, RawData = new byte[] { 0x01, 0x02, 0x03 } },
        };
        xPkts[1].ApplyModification(0, new byte[] { 0xFF });

        await g18Exp.ExportAsync(xPkts, new PacketExportOptions { OutputPath = g18Path, ExportOnlyModified = false });
        byte[] xBytes = await File.ReadAllBytesAsync(g18Path);
        byte[] xExpected = Concat(ClassicHeader(false, true),
            ClassicRecord(1_000_005, new byte[] { 0xAA, 0x55 }, false, true),
            ClassicRecord(1_000_010, new byte[] { 0xFF, 0x02, 0x03 }, false, true));
        Report("G18-01 byte-exact export (global header + 2 records)",
            BytesEq(xBytes, xExpected) && xBytes.Length == 24 + 18 + 19,
            $"len={xBytes.Length} (expected {24 + 18 + 19})");
        Report("G18-02 record field spot-check (tsSec/tsUsec/incl/orig/data)",
            BytesEq(xBytes.AsSpan(24, 4).ToArray(), new byte[] { 0x01, 0x00, 0x00, 0x00 })   // tsSec = 1
            && BytesEq(xBytes.AsSpan(28, 4).ToArray(), new byte[] { 0x05, 0x00, 0x00, 0x00 }) // tsUsec = 5
            && BytesEq(xBytes.AsSpan(32, 4).ToArray(), new byte[] { 0x02, 0x00, 0x00, 0x00 }) // incl_len
            && BytesEq(xBytes.AsSpan(36, 4).ToArray(), new byte[] { 0x02, 0x00, 0x00, 0x00 }) // orig_len
            && xBytes[40] == 0xAA && xBytes[41] == 0x55,
            BytesHex(xBytes.AsSpan(24, 18).ToArray()));
        Report("G18-03 global header spot-check (magic/ver/snaplen/linktype)",
            xBytes[0] == 0xD4 && xBytes[1] == 0xC3 && xBytes[2] == 0xB2 && xBytes[3] == 0xA1
            && xBytes[4] == 0x02 && xBytes[5] == 0x00 && xBytes[6] == 0x04 && xBytes[7] == 0x00
            && BytesEq(xBytes.AsSpan(16, 4).ToArray(), new byte[] { 0xFF, 0xFF, 0x00, 0x00 }) // snaplen 65535
            && BytesEq(xBytes.AsSpan(20, 4).ToArray(), new byte[] { 0x01, 0x00, 0x00, 0x00 }), // linktype 1
            BytesHex(xBytes.AsSpan(0, 24).ToArray()));

        await g18Exp.ExportAsync(xPkts, new PacketExportOptions { OutputPath = g18Path2, ExportOnlyModified = true });
        byte[] xBytes2 = await File.ReadAllBytesAsync(g18Path2);
        Report("G18-04 ExportOnlyModified → only modified packet",
            BytesEq(xBytes2, Concat(ClassicHeader(false, true), ClassicRecord(1_000_010, new byte[] { 0xFF, 0x02, 0x03 }, false, true)))
            && xBytes2.Length == 24 + 19,
            $"len={xBytes2.Length}");

        bool thrWhitespace = false; string msgWs = "";
        try { await g18Exp.ExportAsync(xPkts, new PacketExportOptions { OutputPath = "   " }); }
        catch (Exception ex) { thrWhitespace = true; msgWs = ex.Message; }
        Report("G18-05 whitespace output path rejected (ExportAsync)",
            thrWhitespace && msgWs.Contains("Output path is required."), msgWs);

        bool thrNoPath = false; string msgNoPath = "";
        try { await g18Exp.SavePacketAsync(new Packet { Timestamp = 0, RawData = new byte[] { 1, 2, 3 } }); }
        catch (Exception ex) { thrNoPath = true; msgNoPath = ex.Message; }
        Report("G18-06 SavePacketAsync without path rejected",
            thrNoPath && msgNoPath.Contains("No save path specified for packet."), msgNoPath);

        var rnd = await g18Ing.ReadPacketsAsync(g18Path);
        Report("G18-07 export round-trip (ts + data preserved)",
            rnd.Packets.Count == 2 && rnd.Packets[0].Timestamp == 1_000_005 && rnd.Packets[1].Timestamp == 1_000_010
            && BytesEq(rnd.Packets[0].Data, new byte[] { 0xAA, 0x55 })
            && BytesEq(rnd.Packets[1].Data, new byte[] { 0xFF, 0x02, 0x03 }),
            $"count={rnd.Packets.Count}");

        string g18Path101 = Path.Combine(Path.GetTempPath(), $"pf_g18d_{Guid.NewGuid():N}.pcap");
        try
        {
            await g18Exp.SavePacketAsync(new Packet { Timestamp = 42, RawData = new byte[] { 0x10 } }, g18Path101, linkLayerType: 101);
            var p101 = await g18Ing.ReadPacketsAsync(g18Path101);
            Report("G18-08 custom linkLayerType 101 preserved",
                p101.LinkLayerType == 101 && p101.Packets.Count == 1 && p101.Packets[0].Timestamp == 42,
                $"link={p101.LinkLayerType}");
        }
        finally { try { File.Delete(g18Path101); } catch { } }

        await g18Exp.SavePacketWithContextAsync(
            new Packet { Timestamp = 1_000_002, RawData = new byte[] { 0x04, 0x05, 0x06 } },
            new List<(long Timestamp, byte[] Data)> { (1_000_000, new byte[] { 0x01 }), (1_000_001, new byte[] { 0x02, 0x03 }) },
            g18Path3);
        var pCtx = await g18Ing.ReadPacketsAsync(g18Path3);
        Report("G18-09 context-first export (3 records in order)",
            pCtx.Packets.Count == 3 && pCtx.Packets[0].Timestamp == 1_000_000 && pCtx.Packets[2].Timestamp == 1_000_002
            && BytesEq(pCtx.Packets[1].Data, new byte[] { 0x02, 0x03 }),
            $"count={pCtx.Packets.Count}");

        byte[] g18Sentinel = { 0x50, 0x46, 0x2D, 0x4B, 0x45, 0x45, 0x50 };
        await File.WriteAllBytesAsync(g18Path4, g18Sentinel);
        bool g18AtomicThrew = false;
        string g18AtomicError = "";
        try
        {
            await g18Exp.ExportAsync(
                ThrowAfterFirst(xPkts),
                new PacketExportOptions { OutputPath = g18Path4, ExportOnlyModified = false });
        }
        catch (IOException ex)
        {
            g18AtomicThrew = true;
            g18AtomicError = ex.Message;
        }
        byte[] g18AfterFailure = await File.ReadAllBytesAsync(g18Path4);
        string g18TempPattern = $".{Path.GetFileName(g18Path4)}.*.tmp";
        int g18TempCount = Directory.EnumerateFiles(Path.GetDirectoryName(g18Path4)!, g18TempPattern).Count();
        Report("G18-10 atomic export failure preserves destination and removes temp file",
            g18AtomicThrew && BytesEq(g18AfterFailure, g18Sentinel) && g18TempCount == 0,
            $"threw={g18AtomicThrew}, error={g18AtomicError}, tempFiles={g18TempCount}");
    }
    catch (Exception ex)
    {
        Report("G18 group execution", false, ex.ToString());
    }
    finally
    {
        foreach (var t in new[] { g18Path, g18Path2, g18Path3, g18Path4 }) { try { File.Delete(t); } catch { } }
    }
}

Banner(19, "address/port extraction + edit→reparse refresh on a real frame (4413)");
try
{
    if (read12 is null) Skip("G19 address/port extraction + reparse refresh", CaptureHint);
    else
    {
        var g19Pkt = new Packet
        {
            Index = TargetIndex,
            Timestamp = read12.Packets[TargetIndex].Timestamp,
            RawData = (byte[])read12.Packets[TargetIndex].Data.Clone(),
        };
        string g19Temp = Path.Combine(Path.GetTempPath(), $"pf_g19_{Guid.NewGuid():N}.pcap");
        try
        {
            await exp12.SavePacketAsync(g19Pkt, g19Temp);
            bool g19parsed = await tsh12.ParsePacketFromPcapFileAsync(g19Pkt, g19Temp);
            Report("G19-01 frame 4413 parses", g19parsed && g19Pkt.Layers.Count > 0, $"layers={g19Pkt.Layers.Count}");
            Report("G19-02 source address extracted", g19Pkt.SourceAddress != "N/A", g19Pkt.SourceAddress);
            Report("G19-03 destination address extracted", g19Pkt.DestinationAddress != "N/A", g19Pkt.DestinationAddress);
            Report("G19-04 ports extracted", g19Pkt.SourcePort > 0 && g19Pkt.DestinationPort > 0, $"src:{g19Pkt.SourcePort} dst:{g19Pkt.DestinationPort}");
            Report("G19-05 protocol stack", g19Pkt.ProtocolStack.Contains("IP"), g19Pkt.ProtocolStack);

            string g19OldSrc = g19Pkt.SourceAddress;
            byte[] g19NewSrc = read12.Packets[TargetIndex].Data.AsSpan(26, 4).ToArray();
            g19NewSrc[3] ^= 0x01;
            var g19Field = new ProtocolField { Name = "Source", OriginalPdmlName = "ip.src", Offset = 26, Length = 4, Kind = FieldKind.IPv4, RawBytes = read12.Packets[TargetIndex].Data.AsSpan(26, 4).ToArray() };
            var g19Ed = new ProtocolEditorService();
            g19Ed.ApplyHexStringEdit(g19Pkt, g19Field, Convert.ToHexString(g19NewSrc));
            Report("G19-06 tree edit applied to real frame",
                g19Pkt.IsModified && BytesEq(g19Pkt.EffectiveData.AsSpan(26, 4).ToArray(), g19NewSrc),
                $"newSrc={BytesHex(g19NewSrc)}");

            string g19Temp2 = Path.Combine(Path.GetTempPath(), $"pf_g19b_{Guid.NewGuid():N}.pcap");
            try
            {
                // Re-parse into a fresh packet: ParseLayers() appends to the existing collection and
                // ExtractAddressInfo's first-match-wins would surface the stale first-parse layer.
                var g19Re = new Packet
                {
                    Index = TargetIndex,
                    Timestamp = g19Pkt.Timestamp,
                    RawData = (byte[])g19Pkt.EffectiveData.Clone(),
                };
                await exp12.SavePacketAsync(g19Re, g19Temp2);
                bool g19reparsed = await tsh12.ParsePacketFromPcapFileAsync(g19Re, g19Temp2);
                string g19Expect = new IPAddress(g19NewSrc).ToString();
                Report("G19-07 re-extraction reflects edited bytes",
                    g19reparsed && g19Re.SourceAddress != "N/A" && g19Re.SourceAddress.StartsWith(g19Expect) && g19Re.SourceAddress != g19OldSrc,
                    $"old={g19OldSrc}, new={g19Re.SourceAddress}, expect={g19Expect}");
            }
            finally { try { File.Delete(g19Temp2); } catch { } }
        }
        finally
        {
            try { File.Delete(g19Temp); } catch { }
        }
    }

    // Structural port-pair gate (fixture-independent): ports must be extracted for
    // any layer carrying tshark's srcport/dstport signature — not only udp/tcp/sctp —
    // and a lone "port" field on an application layer must not pollute the columns.
    var g19Syn = new Packet { RawData = new byte[8] };
    g19Syn.RawData[0] = 0x04; g19Syn.RawData[1] = 0xD2; // src 1234
    g19Syn.RawData[2] = 0x00; g19Syn.RawData[3] = 0x50; // dst 80
    var g19Lay = new ProtocolLayer { ProtocolName = "dccp" };
    var g19Hdr = new ProtocolField { Name = "hdr", Offset = -1, Length = 0 };
    g19Hdr.Children.Add(new ProtocolField { Name = "srcport", Offset = 0, Length = 2 });
    g19Hdr.Children.Add(new ProtocolField { Name = "dstport", Offset = 2, Length = 2 });
    g19Lay.Fields.Add(g19Hdr);
    g19Syn.Layers.Add(g19Lay);
    HexEditorViewModel.ReExtractAddressInfo(g19Syn);
    Report("G19-08 non-listed transport (dccp) nested port pair extracted",
        g19Syn.SourcePort == 1234 && g19Syn.DestinationPort == 80,
        $"src={g19Syn.SourcePort} dst={g19Syn.DestinationPort}");

    var g19Pol = new Packet { RawData = new byte[4] };
    g19Pol.RawData[0] = 0x16; g19Pol.RawData[1] = 0x2E; // lone 5678
    var g19App = new ProtocolLayer { ProtocolName = "app" };
    g19App.Fields.Add(new ProtocolField { Name = "port", Offset = 0, Length = 2 });
    g19Pol.Layers.Add(g19App);
    HexEditorViewModel.ReExtractAddressInfo(g19Pol);
    Report("G19-09 lone port field cannot pass the pair gate",
        g19Pol.SourcePort == -1 && g19Pol.DestinationPort == -1,
        $"src={g19Pol.SourcePort} dst={g19Pol.DestinationPort}");

    var g19Tcp = new Packet { RawData = new byte[4] };
    g19Tcp.RawData[0] = 0x1F; g19Tcp.RawData[1] = 0x90; // src 8080
    g19Tcp.RawData[2] = 0x00; g19Tcp.RawData[3] = 0x50; // dst 80
    var g19TcpLay = new ProtocolLayer { ProtocolName = "tcp" };
    g19TcpLay.Fields.Add(new ProtocolField { Name = "srcport", Offset = 0, Length = 2 });
    g19TcpLay.Fields.Add(new ProtocolField { Name = "dstport", Offset = 2, Length = 2 });
    g19Tcp.Layers.Add(g19TcpLay);
    HexEditorViewModel.ReExtractAddressInfo(g19Tcp);
    Report("G19-10 flat tcp port pair still extracted",
        g19Tcp.SourcePort == 8080 && g19Tcp.DestinationPort == 80,
        $"src={g19Tcp.SourcePort} dst={g19Tcp.DestinationPort}");
}
catch (Exception ex)
{
    Report("G19 group execution", false, ex.ToString());
}

Banner(20, "layout + settings persistence (ApplicationData, snapshot/restore)");
{
    string g20Dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ProtocolForge");
    string g20Layout = Path.Combine(g20Dir, "layout.json");
    string g20Settings = Path.Combine(g20Dir, "settings.json");
    byte[]? g20LayoutBackup = File.Exists(g20Layout) ? File.ReadAllBytes(g20Layout) : null;
    byte[]? g20SettingsBackup = File.Exists(g20Settings) ? File.ReadAllBytes(g20Settings) : null;
    try
    {
        var layoutSvc = new LayoutService();
        layoutSvc.Save(new LayoutState
        {
            TopRowRatio = 0.42, BottomLeftRatio = 0.61, WindowX = 17, WindowY = 23,
            WindowWidth = 1333, WindowHeight = 777, WindowState = 1,
            ShowPacketList = false, ShowProtocolTree = true, ShowHexEditor = false,
        });
        var loadedLayout = new LayoutService().Load();
        Report("G20-01 layout round trip",
            loadedLayout.TopRowRatio == 0.42 && loadedLayout.BottomLeftRatio == 0.61 && loadedLayout.WindowWidth == 1333
            && loadedLayout.WindowState == 1 && !loadedLayout.ShowPacketList && loadedLayout.ShowProtocolTree && !loadedLayout.ShowHexEditor,
            $"ratio={loadedLayout.TopRowRatio}, w={loadedLayout.WindowWidth}, state={loadedLayout.WindowState}");

        File.WriteAllText(g20Layout, "{ corrupt json !!!");
        var corrupted = new LayoutService().Load();
        Report("G20-02 corrupt layout → defaults (fail-open)",
            corrupted.TopRowRatio == 0.35 && corrupted.WindowWidth == 1200 && corrupted.WindowState == 0 && corrupted.ShowHexEditor,
            $"ratio={corrupted.TopRowRatio}, w={corrupted.WindowWidth}");

        File.Delete(g20Layout);
        Report("G20-03 missing layout → defaults",
            new LayoutService().Load().TopRowRatio == 0.35, $"ratio={new LayoutService().Load().TopRowRatio}");

        var settingsSvc = new TsharkSettingsService();
        settingsSvc.SaveTsharkPath("/usr/bin/tshark");
        settingsSvc.SaveLanguage("zh-CN");
        settingsSvc.SaveTlsKeylogPath("/tmp/pf.keylog");
        var round2 = new TsharkSettingsService();
        Report("G20-04 settings round trip (3 fields)",
            round2.LoadTsharkPath() == "/usr/bin/tshark" && round2.LoadLanguage() == "zh-CN" && round2.LoadTlsKeylogPath() == "/tmp/pf.keylog",
            $"path={round2.LoadTsharkPath()}, lang={round2.LoadLanguage()}, keylog={round2.LoadTlsKeylogPath()}");

        settingsSvc.SaveTsharkPath(null);
        Report("G20-05 cleared tshark path → null", new TsharkSettingsService().LoadTsharkPath() == null, "");

        File.WriteAllText(g20Settings, "{ nope }");
        var corrupt2 = new TsharkSettingsService();
        Report("G20-06 corrupt settings → null everywhere (fail-open)",
            corrupt2.LoadTsharkPath() == null && corrupt2.LoadLanguage() == null && corrupt2.LoadTlsKeylogPath() == null,
            $"path={corrupt2.LoadTsharkPath()}");
    }
    catch (Exception ex)
    {
        Report("G20 group execution", false, ex.ToString());
    }
    finally
    {
        try { if (g20LayoutBackup != null) File.WriteAllBytes(g20Layout, g20LayoutBackup); else if (File.Exists(g20Layout)) File.Delete(g20Layout); } catch { }
        try { if (g20SettingsBackup != null) File.WriteAllBytes(g20Settings, g20SettingsBackup); else if (File.Exists(g20Settings)) File.Delete(g20Settings); } catch { }
    }
}

if (OperatingSystem.IsLinux())
{
    Banner(21, "loopback injection on Linux (rung ladder)");
    try
    {
        var gNIface = new NetworkInterfaceService().GetInterfaces().FirstOrDefault(i => i.Name == "lo");
        if (gNIface == null)
        {
            Report("G21 loopback injection: no 'lo' interface (skipped)", true, "lo not found");
        }
        else
        {
            byte[] nUdp = Concat(
                new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00 },
                new byte[] { 0x45, 0x00 }, U16(46, false), U16(1, false), U16(0x4000, false),
                new byte[] { 0x40, 0x11, 0x00, 0x00 }, new byte[] { 10, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 },
                U16(4000, false), U16(5000, false), U16(26, false), U16(0, false),
                new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x11, 0x22, 0x33 });
            byte[] nTcp = Concat(
                new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00 },
                new byte[] { 0x45, 0x00 }, U16(46, false), U16(1, false), U16(0x4000, false),
                new byte[] { 0x40, 0x06, 0x00, 0x00 }, new byte[] { 10, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 },
                U16(4000, false), U16(5000, false), U32(0, false), U32(0, false),
                new byte[] { 0x50, 0x18 }, U16(0x4000, false), U16(0, false), U16(0, false),
                new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 });
            byte[] nBare = Concat(
                new byte[] { 0x45, 0x00 }, U16(32, false), U16(1, false), U16(0x4000, false),
                new byte[] { 0x40, 0x11, 0x00, 0x00 }, new byte[] { 10, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 },
                U16(4000, false), U16(5000, false), U16(12, false), U16(0, false),
                new byte[] { 0x99, 0x99, 0x99, 0x99 });

            var nUdpPkt = new Packet { Index = 0, Timestamp = 100, RawData = nUdp };
            var nTcpPkt = new Packet { Index = 0, Timestamp = 100, RawData = nTcp };
            var nBarePkt = new Packet { Index = 0, Timestamp = 100, RawData = nBare };

            var nR1 = await RunSendAsync(new PacketSendService(), new[] { nUdpPkt }, gNIface);
            Report("G21-01 eth/ipv4/udp frame sent (any rung, strict counts)",
                nR1.Sent == 1 && nR1.Failed == 0 && nR1.TotalSent == 1 && nR1.Done,
                $"sent={nR1.Sent}, failed={nR1.Failed}, total={nR1.TotalSent}, last=\"{nR1.LastMsg}\"");

            var nR2 = await RunSendAsync(new PacketSendService(), new[] { nTcpPkt }, gNIface);
            Report("G21-02 eth/ipv4/tcp frame sent (any rung, strict counts)",
                nR2.Sent == 1 && nR2.Failed == 0 && nR2.TotalSent == 1 && nR2.Done,
                $"sent={nR2.Sent}, failed={nR2.Failed}, total={nR2.TotalSent}, last=\"{nR2.LastMsg}\"");

            var nR3 = await RunSendAsync(new PacketSendService(), new[] { nBarePkt }, gNIface);
            Report("G21-03 bare-ip/udp frame sent (any rung, strict counts)",
                nR3.Sent == 1 && nR3.Failed == 0 && nR3.TotalSent == 1 && nR3.Done,
                $"sent={nR3.Sent}, failed={nR3.Failed}, total={nR3.TotalSent}, last=\"{nR3.LastMsg}\"");


            var nGarbage = new Packet { Index = 0, Timestamp = 100, RawData = new byte[] { 0x55, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 } };
            var nR5 = await RunSendAsync(new PacketSendService(), new[] { nGarbage }, gNIface);
            Report("G21-05 undissectable payload → exact UdpParseFailed",
                nR5.Sent == 0 && nR5.Failed == 1 && nR5.LastMsg == LocalizationService.Resolve("Send.UdpParseFailed"),
                $"sent={nR5.Sent}, failed={nR5.Failed}, last=\"{nR5.LastMsg}\"");
        }
    }
    catch (Exception ex)
    {
        Report("G21+N loopback injection group execution", false, ex.ToString());
    }
}
else
{
    Report("G21 loopback injection (Linux-only rung ladder; skipped on this OS)", true, Environment.OSVersion.Platform.ToString());
}

// ══ GROUP 22: HexPreferred hex-native field detection/display (source surface, G6 模式) ══
Banner(22, "HexPreferred hex-native field editing code surface");
try
{
    string g22Tshark = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Services/TsharkService.cs"));
    string g22Tree = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "ViewModels/ProtocolTreeViewModel.cs"));
    string g22Editor = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Services/ProtocolEditorService.cs"));

    int detectSites = Regex.Matches(g22Tshark, @"HexPreferred\s*=\s*[^;]*StartsWith\(""0x""").Count;
    Report("G22 PDML showname 0x 前缀 → HexPreferred 检测（≥1 处）",
        detectSites >= 1, $"detectSites={detectSites}");

    Report("G22 提交路径解析 0x 前缀 hex（ConvertUInt/ConvertInt 大端输出）",
        g22Editor.Contains("StartsWith(\"0x\"") && g22Editor.Contains("LengthCheckedBigEndian"),
        "missing 0x hex parse in commit path");

    Report("G22 UInt 字段 hex 默认显示（FormatForEdit）",
        g22Tree.Contains("field.HexPreferred ? \"0x\" + ToBigEndianUInt64"),
        "missing UInt hex display");

    Report("G22 Int 字段 hex 默认显示（FormatForEdit）",
        g22Tree.Contains("field.HexPreferred ? \"0x\" + ToBigEndianInt64"),
        "missing Int hex display");
}
catch (Exception ex)
{
    Report("G22 group execution", false, ex.ToString());
}

// ══ GROUP 23: trace.log startup rotation + crash recorders (source surface) ══
Banner(23, "trace.log startup rotation + crash recorders code surface");
try
{
    string g23 = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Program.cs"));
    string g23Trace = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Services", "TraceLog.cs"));

    Report("G23 轮转阈值 2MB、保留 2 份备份（.1/.2）",
        g23.Contains("2L * 1024 * 1024") && g23.Contains("keepBackups = 2"),
        "missing 2MB threshold / keepBackups=2");

    Report("G23 级联轮转循环（keepBackups→1, 新→旧）",
        g23.Contains("for (int i = keepBackups; i >= 1; i--)") && g23.Contains("$\"{logPath}.{i}\""),
        "missing cascade loop");

    Report("G23 日志写入 LocalApplicationData/ProtocolForge/logs 的 TextWriterTraceListener",
        g23.Contains("TextWriterTraceListener(logPath)")
            && g23.Contains("AutoFlush = true")
            && g23Trace.Contains("SpecialFolder.LocalApplicationData")
            && g23Trace.Contains("\"logs\""),
        "missing file listener or LocalApplicationData/logs path");

    bool logPathShape = ProtocolForge.TraceLog.LogDirectory
            == Path.Combine(ProtocolForge.TraceLog.SupportDataDirectory, "logs")
        && ProtocolForge.TraceLog.LogFilePath
            == Path.Combine(ProtocolForge.TraceLog.LogDirectory, "trace.log");
    Report("G23 trace.log path resolves under logs directory", logPathShape,
        $"support={ProtocolForge.TraceLog.SupportDataDirectory}, log={ProtocolForge.TraceLog.LogFilePath}");

    Report("G23 崩溃兜底：AppDomain.UnhandledException → TraceLog",
        g23.Contains("AppDomain.CurrentDomain.UnhandledException") && g23.Contains("TraceLog.Write"),
        "missing AppDomain recorder");

    Report("G23 崩溃兜底：TaskScheduler.UnobservedTaskException → TraceLog",
        g23.Contains("TaskScheduler.UnobservedTaskException") && g23.Contains("TraceLog.Write"),
        "missing TaskScheduler recorder");

    Report("G23 轮转失败静默降级（catch → Debug.WriteLine）",
        g23.Contains("Trace log rotation failed") && g23.Contains("Debug.WriteLine"),
        "missing silent degradation");
}
catch (Exception ex)
{
    Report("G23 group execution", false, ex.ToString());
}

// ══ GROUP 24: jsonraw 三遍解析专项 — fixture pcaps driven through the real
// parse path (ParsePacketFromPcapFileAsync / BuildPacketTreeAsync + tshark) ══
Banner(24, "jsonraw 3-pass parse — fixture pcaps (TR-02..TR-09)");
var g24Tsh = new TsharkService(new PcapIngestService(), new PcapExportService());
try
{
    // ── Fixture 1: DHCP with TWO duplicate option-55 (request list) — duplicate
    //    jsonraw keys (_raw x3 / _tree x3) exercise the twin-consumption logic.
    byte[] bootp = Concat(
        new byte[] { 0x02, 0x01, 0x06, 0x00 },          // op / htype / hlen / hops
        new byte[] { 0x39, 0x03, 0xF3, 0x26 },          // xid
        U16(0, false), U16(0x8000, false),              // secs, flags (broadcast)
        new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, // chaddr
        new byte[] { 0, 0, 0, 0 },                      // ciaddr
        new byte[] { 0xC0, 0, 2, 1 },                   // yiaddr
        new byte[] { 0x0A, 0, 2, 1 },                   // siaddr
        new byte[] { 0, 0, 0, 0 },                      // giaddr
        new byte[64], new byte[128]);                   // sname, file
    byte[] dhcpOpts = Concat(
        new byte[] { 0x63, 0x82, 0x53, 0x63 },          // DHCP magic cookie
        new byte[] { 55, 3, 1, 3, 6 },                  // option 55 #1: requests [1, 3, 6]
        new byte[] { 55, 2, 15, 42 },                   // option 55 #2: requests [15, 42]
        new byte[] { 255 });                            // end
    byte[] dhcpFrame = FixtureEth(FixtureIpv4(FixtureUdp(68, 67, Concat(bootp, dhcpOpts)),
        src: "0.0.0.0", dst: "255.255.255.255"));

    // ── Fixture 2: plain IPv4+UDP with payload (aggregate alias + payload casing).
    byte[] plFrame = FixtureEth(FixtureIpv4(FixtureUdp(4000, 5000,
        new byte[] { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45 })));

    // ── Fixture 3: truncated Ethernet frame (tshark marks it malformed).
    byte[] malFrame = new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00, 0x45 };

    // ── Fixture 4: two IPv4 fragments of one datagram (reassembly region).
    byte[] fragPayload = new byte[]
    {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x22, 0x33,
    };
    byte[] frag0Frame = FixtureEth(FixtureIpv4(fragPayload[..16], id: 7, frag: 0x2000));
    byte[] frag1Frame = FixtureEth(FixtureIpv4(fragPayload[16..], id: 7, frag: 0x0002));

    string fx1 = Path.Combine(Path.GetTempPath(), $"pf_tr_dhcp_{Guid.NewGuid():N}.pcap");
    string fx2 = Path.Combine(Path.GetTempPath(), $"pf_tr_pl_{Guid.NewGuid():N}.pcap");
    string fx3 = Path.Combine(Path.GetTempPath(), $"pf_tr_mal_{Guid.NewGuid():N}.pcap");
    string fx4 = Path.Combine(Path.GetTempPath(), $"pf_tr_frag0_{Guid.NewGuid():N}.pcap");
    string fx5 = Path.Combine(Path.GetTempPath(), $"pf_tr_frag1_{Guid.NewGuid():N}.pcap");
    try
    {
        await File.WriteAllBytesAsync(fx1, BuildFixturePcap(dhcpFrame));
        await File.WriteAllBytesAsync(fx2, BuildFixturePcap(plFrame));
        await File.WriteAllBytesAsync(fx3, BuildFixturePcap(malFrame));
        await File.WriteAllBytesAsync(fx4, BuildFixturePcap(frag0Frame));
        await File.WriteAllBytesAsync(fx5, BuildFixturePcap(frag1Frame));

        // ── TR-02/03/07/09: DHCP packet (duplicate keys + aggregates + masks).
        var dhcpPkt = new Packet { Index = 0, Timestamp = 0, RawData = dhcpFrame };
        bool dhcpOk = await g24Tsh.ParsePacketFromPcapFileAsync(dhcpPkt, fx1);
        Report("TR-02 parse of fixture DHCP packet (BuildPacketTree path)",
            dhcpOk && dhcpPkt.Layers.Count > 0, $"layers={dhcpPkt.Layers.Count}, ok={dhcpOk}");

        var dhcpLayer = dhcpPkt.Layers.FirstOrDefault(l => l.ProtocolName == "dhcp");
        var ipLayer = dhcpPkt.Layers.FirstOrDefault(l => l.ProtocolName == "ip");

        Report("TR-02 pass-1/2 all *_raw reach the tree (dhcp.type/hops/ip.client present)",
            dhcpLayer != null && Flatten(dhcpLayer.Fields).Any(f => f.OriginalPdmlName == "dhcp.type")
                && dhcpLayer != null && Flatten(dhcpLayer.Fields).Any(f => f.OriginalPdmlName == "dhcp.hops")
                && Flatten(dhcpLayer.Fields).Any(f => f.OriginalPdmlName == "dhcp.ip.client"),
            "missing dhcp.type / dhcp.hops / dhcp.ip.client leaves");

        Report("TR-07 aggregate aliases skipped (ip.addr/ip.host/udp.port/tcp.port)",
            ipLayer != null && !Flatten(ipLayer.Fields).Any(f => IsAggregateAlias(f.OriginalPdmlName))
                && dhcpLayer != null && !Flatten(dhcpLayer.Fields).Any(f => f.OriginalPdmlName == "udp.port"),
            "aggregate pseudo-field leaked into tree");

        // TR-03: duplicate-key containers are collected in order; each instance
        // consumes its OWN twin raw — option #1 items [1,3,6], option #2 [15,42] (NOT last-wins).
        // (tshark 3.6 emits each option twice: a container WITH children + a childless twin row;
        // the canonical rows are the HasChildren containers — see doc honest-note.)
        var optContainers = (dhcpLayer?.Fields ?? [])
            .Where(f => f.Name == "Option" && f.HasChildren)
            .OrderBy(f => f.Offset).ToList();
        Report("TR-03 duplicate option twins collected in order (3 containers, distinct byte spans)",
            optContainers.Count == 3 && optContainers[0].Offset == 282 && optContainers[1].Offset == 287 && optContainers[2].Offset == 291,
            $"containers={optContainers.Count}, offsets=[{string.Join(",", optContainers.Select(f => f.Offset))}]");
        static byte[] OptItems(ObservableCollection<ProtocolField> children) =>
            children.Where(f => f.OriginalPdmlName == "dhcp.option.request_list_item").Select(f => f.RawBytes[0]).ToArray();
        byte[] optOne = optContainers.Count > 0 ? OptItems(optContainers[0].Children) : [];
        byte[] optTwo = optContainers.Count > 1 ? OptItems(optContainers[1].Children) : [];
        Report("TR-03 per-instance twin consumption (option#1 [01 03 06] vs option#2 [0F 2A], NOT last-wins)",
            BytesEq(optOne, new byte[] { 1, 3, 6 }) && BytesEq(optTwo, new byte[] { 0x0F, 0x2A }),
            $"opt1=[{string.Join(" ", optOne.Select(b => b.ToString("X2")))}], opt2=[{string.Join(" ", optTwo.Select(b => b.ToString("X2")))}]");

        // ── TR-06/07: payload casing + aggregates on the plain UDP fixture.
        var plPkt = new Packet { Index = 0, Timestamp = 0, RawData = plFrame };
        bool plOk = await g24Tsh.ParsePacketFromPcapFileAsync(plPkt, fx2);
        var plIp = plPkt.Layers.FirstOrDefault(l => l.ProtocolName == "ip");
        var udpLayer = plPkt.Layers.FirstOrDefault(l => l.ProtocolName == "udp");
        var payloadField = Flatten(udpLayer?.Fields ?? [])
            .FirstOrDefault(f => f.Name == "UDP payload" || f.Name == "payload");
        Report("TR-06 payload fallback renamed 'UDP payload' (ShowHex=false, Kind=Unknown, (6 bytes))",
            plOk && payloadField != null && !payloadField.ShowHex
                && payloadField.Kind == FieldKind.Unknown
                && payloadField.DisplayValue == "(6 bytes)",
            $"name={payloadField?.Name}, showHex={payloadField?.ShowHex}, kind={payloadField?.Kind}, display=\"{payloadField?.DisplayValue}\"");

        bool plIpHasSrc = Flatten(plIp?.Fields ?? []).Any(f => f.OriginalPdmlName == "ip.src");
        Report("TR-06/07 plain UDP fixture parsed (ip layer + src leaf present, udp layer present)",
            plOk && plIp != null && plIpHasSrc && udpLayer != null,
            $"ok={plOk}, ip={plIp != null}, src={plIpHasSrc}, udp={udpLayer != null}");

        // ── TR-09: MaskToLengthBits — bit-level subfields carry LengthBits, byte-aligned -1.
        var dscp = ipLayer != null ? Flatten(ipLayer.Fields).FirstOrDefault(f => f.OriginalPdmlName == "ip.dsfield.dscp") : null;
        var ecn = ipLayer != null ? Flatten(ipLayer.Fields).FirstOrDefault(f => f.OriginalPdmlName == "ip.dsfield.ecn") : null;
        var ipSrc = ipLayer != null ? Flatten(ipLayer.Fields).FirstOrDefault(f => f.OriginalPdmlName == "ip.src") : null;
        var flagsRb = ipLayer != null ? Flatten(ipLayer.Fields).FirstOrDefault(f => f.OriginalPdmlName == "ip.flags.rb") : null;
        Report("TR-09 MaskToLengthBits (dscp=6b, ecn=2b, rb=1b; ip.src byte-aligned → -1)",
            dscp != null && dscp.LengthBits == 6
                && ecn != null && ecn.LengthBits == 2
                && flagsRb != null && flagsRb.LengthBits == 1
                && ipSrc != null && ipSrc.LengthBits == -1,
            $"dscp={dscp?.LengthBits}, ecn={ecn?.LengthBits}, rb={flagsRb?.LengthBits}, src={ipSrc?.LengthBits}");

        // ── TR-08: malformed — _ws.malformed dropped, note appended to innermost layer.
        var malPkt = new Packet { Index = 0, Timestamp = 0, RawData = malFrame };
        bool malOk = await g24Tsh.ParsePacketFromPcapFileAsync(malPkt, fx3);
        bool noWsLayer = !malPkt.Layers.Any(l => l.ProtocolName.StartsWith("_ws.", StringComparison.Ordinal));
        bool malNote = malPkt.Layers.Count > 0 && malPkt.Layers[^1].DisplayText.Contains("Malformed Packet", StringComparison.Ordinal);
        string malLast = malPkt.Layers.Count > 0 ? malPkt.Layers[^1].DisplayText : "no layers";
        Report("TR-08 malformed: _ws.* layers dropped, '[Malformed Packet…]' appended to innermost layer",
            malOk && noWsLayer && malNote,
            $"ok={malOk}, noWs={noWsLayer}, note=\"{malLast}\"");

        // ── TR-05: reassembly — frag1 parsed with fragment siblings as context.
        var fragPkt = new Packet { Index = 1, Timestamp = 1, RawData = frag1Frame };
        bool fragOk = await g24Tsh.BuildPacketTreeAsync(fragPkt, 1,
            new[] { ((long)0, frag0Frame) });
        var fragIp = fragPkt.Layers.FirstOrDefault(l => l.ProtocolName == "ip");
        bool fragIndicator = fragIp != null && Flatten(fragIp.Fields)
            .Any(f => f.Name is "Fragmented" or "fragment" || f.OriginalPdmlName.Contains("fragment", StringComparison.Ordinal));
        Report("TR-05 IP fragment reassembly region (fragment fields present, parse ok)",
            fragOk && fragIndicator,
            $"ok={fragOk}, frag={fragIndicator}, ipLayers={fragPkt.Layers.Count(l => l.ProtocolName == "ip")}");
    }
    finally
    {
        foreach (var p in new[] { fx1, fx2, fx3, fx4, fx5 })
        {
            try { File.Delete(p); } catch { /* best-effort */ }
        }
    }
}
catch (Exception ex)
{
    Report("G24 group execution", false, ex.ToString());
}

// ══ GROUP 25: V-08 (Vbc.NoPdmlName, behavioral) + A-02 (address re-extraction) ══
Banner(25, "V-08 empty-pdmlName abort + A-02 address re-extraction");
var g25Tsh = new TsharkService(new PcapIngestService(), new PcapExportService());
try
{
    byte[] aFrame = FixtureEth(FixtureIpv4(FixtureUdp(4000, 5000,
        new byte[] { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45 })));
    string aFx = Path.Combine(Path.GetTempPath(), $"pf_a_{Guid.NewGuid():N}.pcap");
    try
    {
        await File.WriteAllBytesAsync(aFx, BuildFixturePcap(aFrame));
        var aPkt = new Packet { Index = 0, Timestamp = 0, RawData = aFrame };
        bool aOk = await g25Tsh.ParsePacketFromPcapFileAsync(aPkt, aFx);

        // A-02 behavioral: the live extraction pipeline passes dotted display values
        // straight through (TryConvertHexToIp contains-'.' branch).
        Report("A-02 dotted display passes through extraction (SourceAddress/DestinationAddress filled)",
            aOk && aPkt.SourceAddress == "10.0.0.1" && aPkt.DestinationAddress == "10.0.0.2",
            $"src={aPkt.SourceAddress}, dst={aPkt.DestinationAddress}");

        // A-02 source surface: hex→dotted conversion applies ONLY to 8-hex-char inputs.
        string aTshark = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Services/TsharkService.cs"));
        Report("A-02 hex→dotted conversion gated on exactly 8 hex chars (source: TryConvertHexToIp)",
            aTshark.Contains("!isV6 && hex.Length == 8") && aTshark.Contains("string.Join(\".\", bytes)"),
            "missing 8-hex gate / dotted join");
        Report("A-02 already-dotted values bypass conversion (source: hex.Contains('.') early return)",
            aTshark.Contains("TryConvertHexToIp") && aTshark.Contains("hex.Contains('.')"),
            "missing dotted pass-through");

        // V-08 behavioral: a field with empty pdmlName aborts the commit with
        // Vbc.NoPdmlName and leaves the packet byte-identical.
        var ipLayer = aPkt.Layers.FirstOrDefault(l => l.ProtocolName == "ip");
        var ipSrc = ipLayer != null ? Flatten(ipLayer.Fields).FirstOrDefault(f => f.OriginalPdmlName == "ip.src") : null;
        bool v08FieldReady = ipSrc != null && ipSrc.RawBytes.Length == 4;
        var anonField = new ProtocolField
        {
            Name = ipSrc?.Name ?? "Source Address",
            DisplayValue = ipSrc?.DisplayValue ?? string.Empty,
            Offset = ipSrc?.Offset ?? -1,
            Length = ipSrc?.Length ?? 0,
            RawBytes = ipSrc?.RawBytes ?? [],
            Kind = FieldKind.IPv4,
        };
        var vbcSvc = new EditTransactionService(new PcapExportService(), new TsharkService(new PcapIngestService(), new PcapExportService()));
        var v08Edit = await vbcSvc.CommitFieldEditAsync(aPkt, anonField, new byte[] { 11, 0, 0, 1 }, null, 1);
        LocalizationService.SetCurrent(AppLanguage.EnUs);
        string v08Expected = LocalizationService.Resolve("Vbc.NoPdmlName");
        Report("V-08 empty pdmlName → Vbc.NoPdmlName abort, packet byte-identical",
            v08FieldReady && !v08Edit.Success && v08Edit.Reason == v08Expected
                && aPkt.EffectiveData.SequenceEqual(aFrame),
            $"fieldReady={v08FieldReady}, success={v08Edit.Success}, reason=\"{v08Edit.Reason}\"");
    }
    finally
    {
        try { File.Delete(aFx); } catch { /* best-effort */ }
    }
}
catch (Exception ex)
{
    Report("G25 group execution", false, ex.ToString());
}

// ══ GROUP 27: N-10..N-13 send ladder directed descent (rung order / FrameTooShort /
// UDP fallback / TCP platform text) — trace-captured behavioral proofs + source gates ══
Banner(27, "send ladder directed descent (N-10..N-13)");
try
{
    string nSrc = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Services/PacketSendService.cs"));

    // The guard moved onto SendTarget.CanSend when multi-NIC fan-out was added, so this
    // checks the new shape: a target counts as sendable only with sockets or an L2 rung,
    // and the aggregate bail-out still reports Send.NoSocketType.
    Report("N-10 no-socket guard → Send.NoSocketType (source)",
        nSrc.Contains("Sockets.Count > 0 || L2Rung != null")
        && nSrc.Contains("!targets.Any(t => t.CanSend)")
        && nSrc.Contains("Send.NoSocketType"),
        "missing NoSocketType guard");
    int pk = nSrc.IndexOf("new Socket(AddressFamily.Packet,", StringComparison.Ordinal);
    int ip = nSrc.IndexOf("new Socket(AddressFamily.InterNetwork, SocketType.Raw,", StringComparison.Ordinal);
    int ud = nSrc.IndexOf("new Socket(AddressFamily.InterNetwork, SocketType.Dgram,", StringComparison.Ordinal);
    Report("N-10 socket ladder order in CreateSendSockets (AF_PACKET → IP raw → UDP)",
        pk >= 0 && pk < ip && ip < ud, $"pk={pk}, ip={ip}, ud={ud}");
    Report("N-10 native L2 rung only on Windows/macOS (source: OS-gated probe)",
        nSrc.Contains("OperatingSystem.IsWindows()") && nSrc.Contains("OperatingSystem.IsMacOS()")
            && nSrc.Contains("NpcapSendService.TryOpenRung") && nSrc.Contains("BpfSendService.TryOpenRung"),
        "missing L2 rung OS gate");
    Report("N-12 UDP fallback rung + SentUdp result (source)",
        nSrc.Contains("TrySendUdpPayloadAsync") && nSrc.Contains("Send.SentUdp")
            && nSrc.Contains("TryExtractUdpTarget"),
        "missing UDP rung");
    Report("N-13 TCP platform texts (source: protocol==6 → TcpBlockedWin/TcpNeedsPriv)",
        nSrc.Contains("protocol == 6") && nSrc.Contains("Send.TcpBlockedWin") && nSrc.Contains("Send.TcpNeedsPriv"),
        "missing TCP branch");

    var g27Iface = new NetworkInterfaceService().GetInterfaces().FirstOrDefault(i => i.Name == "lo");
    if (g27Iface == null)
    {
        Report("N-10/11 ladder descent (skipped: no 'lo' interface)", true, "lo not found");
    }
    else
    {
        bool g27Root = Environment.IsPrivilegedProcess;
        LocalizationService.SetCurrent(AppLanguage.EnUs);
        string frameTooShort = LocalizationService.Resolve("Send.FrameTooShort");
        string udpParseFailed = LocalizationService.Resolve("Send.UdpParseFailed");

        byte[] gGarbage = new byte[] { 0x55, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
        byte[] gEthUdp = FixtureEth(FixtureIpv4(FixtureUdp(4000, 5000, new byte[18])));
        byte[] gTcp = Concat(
            new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00 },
            new byte[] { 0x45, 0x00 }, U16(46, false), U16(1, false), U16(0x4000, false),
            new byte[] { 0x40, 0x06, 0x00, 0x00 }, new byte[] { 10, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 },
            U16(4000, false), U16(5000, false), U32(0, false), U32(0, false),
            new byte[] { 0x50, 0x18 }, U16(0x4000, false), U16(0, false), U16(0, false),
            new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 });

        var n27Trace = new BufferingTraceListener();
        System.Diagnostics.Trace.Listeners.Add(n27Trace);
        try
        {
            var rG = await RunSendAsync(new PacketSendService(), new[] { new Packet { Index = 0, Timestamp = 100, RawData = gGarbage } }, g27Iface);
            var rU = await RunSendAsync(new PacketSendService(), new[] { new Packet { Index = 0, Timestamp = 100, RawData = gEthUdp } }, g27Iface);
            var rT = await RunSendAsync(new PacketSendService(), new[] { new Packet { Index = 0, Timestamp = 100, RawData = gTcp } }, g27Iface);

            var rungLines = n27Trace.Lines.Where(l => l.Contains("Send rung")).ToList();

            bool garbageExhaustsLadder = rG.Failed == 1 && rG.Sent == 0 && rG.LastMsg == udpParseFailed;
            Report("N-11 <14B frame → AF_PACKET FrameTooShort on the FIRST rung, then descends",
                rungLines.Count >= 1 && rungLines[0].Contains("AF_PACKET") && rungLines[0].Contains(frameTooShort)
                    && garbageExhaustsLadder,
                $"first=\"{(rungLines.Count > 0 ? rungLines[0] : "(none)")}\", sent={rG.Sent}, failed={rG.Failed}, last=\"{rG.LastMsg}\"");

            int aIdx = rungLines.FindIndex(l => l.Contains("AF_PACKET"));
            int bIdx = rungLines.FindIndex(l => l.Contains("IP raw"));
            int cIdx = rungLines.FindIndex(l => l.Contains("UDP"));
            Report("N-10 ladder descent order visible in trace (AF_PACKET → IP raw → UDP failures)",
                garbageExhaustsLadder && aIdx >= 0 && bIdx > aIdx && cIdx > bIdx,
                $"idx=({aIdx},{bIdx},{cIdx}), trace=[{string.Join(" | ", n27Trace.Lines)}]");

            if (g27Root)
            {
                Report("N-12 highest-fidelity rung wins on privileged run (eth frame → AF_PACKET SentRaw)",
                    rU.Sent == 1 && rU.Failed == 0
                        && rU.LastMsg == LocalizationService.Resolve("Send.SentRaw", 60, g27Iface.Name),
                    $"sent={rU.Sent}, last=\"{rU.LastMsg}\"");
                Report("N-13 TCP platform text NOT reachable under root (AF_PACKET delivers first) — source-gated",
                    rT.Sent == 1, $"tcp sent={rT.Sent}, last=\"{rT.LastMsg}\"");
            }
            else
            {
                Report("N-12 UDP fallback succeeds without privileges (SentUdp)",
                    rU.Sent == 1 && rU.LastMsg.Contains("(fallback)"),
                    $"sent={rU.Sent}, last=\"{rU.LastMsg}\"");
                Report("N-13 TCP frame → TcpNeedsPriv on unprivileged run",
                    rT.Failed == 1 && rT.LastMsg == LocalizationService.Resolve("Send.TcpNeedsPriv"),
                    $"failed={rT.Failed}, last=\"{rT.LastMsg}\"");
            }
        }
        finally
        {
            System.Diagnostics.Trace.Listeners.Remove(n27Trace);
        }
    }
}
catch (Exception ex)
{
    Report("G27 group execution", false, ex.ToString());
}

// ══ GROUP 28: ST-03 settings save failure is silently swallowed (behavioral) ══
Banner(28, "ST-03 settings save failure silent (behavioral)");
try
{
    string stSrc = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Services/TsharkSettingsService.cs"));
    Report("ST-03 source: universal catch on every Save (silently fail — non-critical)",
        stSrc.Contains("catch { /* silently fail — settings save is non-critical */ }"),
        "missing silent-fail catch");

    var stSvc = new TsharkSettingsService();
    string stPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "ProtocolForge", "settings.json");
    byte[]? stOriginal = File.Exists(stPath) ? await File.ReadAllBytesAsync(stPath) : null;
    try
    {
        File.Delete(stPath);
        Directory.CreateDirectory(stPath);
        bool threw = false;
        try
        {
            stSvc.SaveTsharkPath("/usr/bin/tshark");
        }
        catch (Exception ex)
        {
            threw = true;
            Report("ST-03 save failure swallowed", false, $"threw: {ex.Message}");
        }
        Report("ST-03 SaveTsharkPath does not throw when the config path is a directory",
            !threw, $"threw={threw}");
        Report("ST-03 unreadable config fails open (LoadTsharkPath → null)",
            stSvc.LoadTsharkPath() == null && stSvc.LoadLanguage() == null,
            $"path={stSvc.LoadTsharkPath()}, lang={stSvc.LoadLanguage()}");
        stSvc.SaveLanguage("zh-CN");
        bool tlsThrew = false;
        try { stSvc.SaveTlsKeylogPath("/tmp/k.log"); }
        catch { tlsThrew = true; }
        Report("ST-03 SaveTlsKeylogPath / SaveLanguage also silent under the same failure",
            !tlsThrew, $"tlsThrew={tlsThrew}");
    }
    finally
    {
        Directory.Delete(stPath);
        if (stOriginal != null)
            await File.WriteAllBytesAsync(stPath, stOriginal);
    }
}
catch (Exception ex)
{
    Report("G28 group execution", false, ex.ToString());
}

// ══ GROUP 29: TR-04 PFCP 匿名容器（合成夹具）+ H-13 RefreshEditedFieldBytes ══
Banner(29, "TR-04 PFCP anonymous containers + H-13 hex refresh");
var g29Ing = new PcapIngestService();
var g29Exp = new PcapExportService();
var g29Tsh = new TsharkService(g29Ing, g29Exp);
try
{
    const long g29Timestamp = 1_000_000;
    byte[] g29Frame = BuildSyntheticPfcpAssociationResponse();
    string g29Tmp = Path.Combine(Path.GetTempPath(), $"pf-g29-{Guid.NewGuid():N}.pcap");
    await File.WriteAllBytesAsync(g29Tmp, BuildFixturePcap(g29Frame));
    try
    {
        var g29Pkt = new Packet { Index = 0, Timestamp = g29Timestamp, RawData = g29Frame };
        bool g29ParseOk = await g29Tsh.ParsePacketFromPcapFileAsync(g29Pkt, g29Tmp);
        // given: tshark 输出 “Node ID : IPv4 address: …” 这类含空格/冒号/多大写字段
        // when: 树构建判定其为匿名容器 → OriginalPdmlName 清空
        var g29Anon = g29Pkt.Layers.SelectMany(l => Flatten(l.Fields))
            .Where(f => f.OriginalPdmlName == "" && f.Children.Count > 0).ToList();
        string g29AnonNames = string.Join(", ", g29Anon.Select(f => f.Name));
        Report("TR-04 PFCP 匿名容器被识别（OriginalPdmlName=\"\" 且带子节点）",
            g29ParseOk && g29Anon.Count >= 3,
            $"parse={g29ParseOk}, anon={g29Anon.Count}, names=[{g29AnonNames}]");

        var g29NodeId = g29Anon.FirstOrDefault(f => f.Name == "Node ID");
        Report("TR-04 匿名键拆分: Name = \"Node ID\"",
            g29NodeId != null && g29NodeId.OriginalPdmlName == "",
            $"name={g29NodeId?.Name ?? "(null)"}, orig={g29NodeId?.OriginalPdmlName ?? "(null)"}");
        Report("TR-04 “Node ID : IPv4 address: …” → DisplayValue 保留细分文本",
            g29NodeId != null && g29NodeId.DisplayValue.Contains("IPv4 address", StringComparison.Ordinal),
            $"display={g29NodeId?.DisplayValue ?? "(null)"}");

        var g29Cause = g29Anon.FirstOrDefault(f => f.Name == "Cause");
        Report("TR-04 “Cause : Service not supported” 拆分正确",
            g29Cause != null && g29Cause.OriginalPdmlName == ""
                && g29Cause.DisplayValue.Contains("Service not supported", StringComparison.Ordinal),
            $"name={g29Cause?.Name ?? "(null)"}, display={g29Cause?.DisplayValue ?? "(null)"}");

        Report("TR-04 (名称,偏移) 定位键可用: 匿名容器均带 Offset >= 0",
            g29Anon.Count > 0 && g29Anon.All(f => f.Offset >= 0),
            $"bad-offsets={g29Anon.Count(f => f.Offset < 0)}");
    }
    finally { File.Delete(g29Tmp); }

    // ── H-13: 十六进制提交后字段字节刷新（字节级字段） ──
    byte[] g29h13 = FixtureEth(FixtureIpv4(FixtureUdp(4000, 5000, new byte[18]), 17, 7, 0, "10.0.0.1", "10.0.0.2"));
    string g29h13Tmp = Path.Combine(Path.GetTempPath(), $"pf-h13-{Guid.NewGuid():N}.pcap");
    await File.WriteAllBytesAsync(g29h13Tmp, BuildFixturePcap(g29h13));
    try
    {
        var g29h13Pkt = new Packet { Index = 0, Timestamp = 0, RawData = g29h13 };
        bool g29h13Ok = await g29Tsh.ParsePacketFromPcapFileAsync(g29h13Pkt, g29h13Tmp);
        var g29h13All = g29h13Pkt.Layers.SelectMany(l => Flatten(l.Fields)).ToList();
        var g29Src = g29h13All.First(f => f.OriginalPdmlName == "ip.src");
        byte[] g29SrcBefore = (byte[]?)g29Src.RawBytes?.Clone() ?? Array.Empty<byte>();
        byte[] g29NewIp = { 10, 0, 0, 99 };
        g29h13Pkt.ApplyModification(g29Src.Offset, g29NewIp);   // HexEditor 提交路径（只改字节，不动字段）
        Report("H-13 hex 提交前字段 RawBytes 保持旧值（等刷新）",
            g29h13Ok && g29Src.RawBytes != null && g29Src.RawBytes.SequenceEqual(g29SrcBefore)
                && g29h13Pkt.IsModified,
            $"stale={BytesHex(g29Src.RawBytes ?? [])}, modified={g29h13Pkt.IsModified}");
        ProtocolEditorService.RefreshEditedFieldBytes(g29h13Pkt, g29Src.Offset, g29NewIp.Length);
        Report("H-13 RefreshEditedFieldBytes 回写重叠字段的 RawBytes",
            g29Src.RawBytes != null && g29Src.RawBytes.SequenceEqual(g29NewIp),
            $"got={BytesHex(g29Src.RawBytes ?? [])}, want={BytesHex(g29NewIp)}");
        Report("H-13 刷新不改 DisplayValue（文本刷新由 VBC reparse 统一负责）",
            g29Src.DisplayValue == "10.0.0.1", $"display={g29Src.DisplayValue}");

        // 位级字段（dscp 6bit 掩码）不得回填整字节证据
        var g29h13bPkt = new Packet { Index = 0, Timestamp = 0, RawData = (byte[])g29h13.Clone() };
        await g29Tsh.ParsePacketFromPcapFileAsync(g29h13bPkt, g29h13Tmp);
        var g29Dscp = g29h13bPkt.Layers.SelectMany(l => Flatten(l.Fields)).First(f => f.OriginalPdmlName == "ip.dsfield.dscp");
        byte[]? g29DscpBefore = (byte[]?)g29Dscp.RawBytes?.Clone();
        g29h13bPkt.ApplyModification(1, new byte[] { 0xC0 });
        ProtocolEditorService.RefreshEditedFieldBytes(g29h13bPkt, 1, 1);
        bool g29DscpUnchanged = g29DscpBefore == null
            ? g29Dscp.RawBytes == null
            : g29Dscp.RawBytes != null && g29Dscp.RawBytes.SequenceEqual(g29DscpBefore);
        Report("H-13 位级字段（dscp 6bit）不被回填",
            g29DscpUnchanged,
            $"before={(g29DscpBefore == null ? "(null)" : BytesHex(g29DscpBefore))}, "
                + $"after={(g29Dscp.RawBytes == null ? "(null)" : BytesHex(g29Dscp.RawBytes))}");
        ProtocolEditorService.RefreshEditedFieldBytes(g29h13bPkt, -5, 2);    // 负偏移 → 早退
        ProtocolEditorService.RefreshEditedFieldBytes(g29h13bPkt, 9999, 2);   // 超范围 → 早退
        Report("H-13 越界/负偏移刷新安全早退（不抛异常、数据不变）",
            (g29Dscp.RawBytes ?? []).SequenceEqual(g29DscpBefore ?? []) && g29h13bPkt.EffectiveData[1] == 0xC0,
            "no-crash");
    }
    finally { File.Delete(g29h13Tmp); }
}
catch (Exception ex)
{
    Report("G29 group execution", false, ex.ToString());
}

// ══ GROUP 30: CP-01..04 context providers（mock 逻辑 + 真实 tshark 夹具） ══
Banner(30, "CP-01..04 context providers (mock + real fixtures)");
try
{
    // ── mock: SDP 懒扫描一次 + 结果缓存 + 失败自动重试 ──
    int g30SdpCalls = 0;
    TsharkFieldsReader g30SdpReader = (f, fs, ct) =>
    {
        g30SdpCalls++;
        return Task.FromResult<IReadOnlyList<string>>(new string[] { "5", "8" });
    };
    var g30Sdp = new SdpContextProvider(g30SdpReader);
    var g30s1 = await g30Sdp.CollectFramesAsync(8, new HashSet<int>());
    var g30s2 = await g30Sdp.CollectFramesAsync(5, new HashSet<int>());
    Report("CP-01 SDP 懒扫描只执行一次且结果缓存（目标帧排除）",
        g30s1.SequenceEqual(new[] { 5 }) && g30s2.SequenceEqual(new[] { 8 }) && g30SdpCalls == 1,
        $"calls={g30SdpCalls}, r1=[{string.Join(",", g30s1)}], r2=[{string.Join(",", g30s2)}]");

    int g30Fail = 1;
    TsharkFieldsReader g30SdpFlaky = (f, fs, ct) =>
    {
        if (--g30Fail >= 0) throw new IOException("simulated scan failure");
        return Task.FromResult<IReadOnlyList<string>>(new string[] { "4" });
    };
    var g30SdpF = new SdpContextProvider(g30SdpFlaky);
    try { await g30SdpF.CollectFramesAsync(4, new HashSet<int>()); }
    catch { /* 首次扫描故障 → 调用方抖动一次 */ }
    var g30s3 = await g30SdpF.CollectFramesAsync(1, new HashSet<int>());
    Report("CP-01 扫描失败后下次调用自动重试（失败不永久缓存）",
        g30s3.SequenceEqual(new[] { 4 }), $"r=[{string.Join(",", g30s3)}]");

    // ── mock: 分片 BFS 闭包 + 传递扩展（帧11 嵌套属两个片组） ──
    TsharkFieldsReader g30FragReader = (f, fs, ct) => Task.FromResult<IReadOnlyList<string>>(new string[]
    {
        "10\t0x123\t10.0.0.1\t10.0.0.2",
        "11\t0x123,0x999\t10.0.0.1,10.0.0.3\t10.0.0.2,10.0.0.4",
        "12\t0x123\t10.0.0.1\t10.0.0.2",
        "5\t0x999\t10.0.0.3\t10.0.0.4",
        "7\t0x999\t10.0.0.3\t10.0.0.4",
    });
    var g30Frag = new FragmentContextProvider(g30FragReader);
    var g30f1 = await g30Frag.CollectFramesAsync(12, new HashSet<int>());
    Report("CP-02 分片闭包: BFS + 传递扩展 + 仅更早帧 + 升序 + 目标排除",
        g30f1.SequenceEqual(new[] { 5, 7, 10, 11 }), $"r=[{string.Join(",", g30f1)}]");
    var g30f2 = await g30Frag.CollectFramesAsync(100, new HashSet<int> { 11 });
    Report("CP-02 种子帧把相关片组拉进结果",
        g30f2.SequenceEqual(new[] { 5, 7, 10 }), $"r=[{string.Join(",", g30f2)}]");
    var g30f3 = await g30Frag.CollectFramesAsync(5, new HashSet<int>());
    Report("CP-02 目标帧为组内首包 → 空结果（自身永不出现在结果）",
        g30f3.Count == 0, $"r=[{string.Join(",", g30f3)}]");

    // ── mock: TCP 同流最近帧 + 预算 ──
    TsharkFieldsReader g30TcpReader = (f, fs, ct) => Task.FromResult<IReadOnlyList<string>>(
        Enumerable.Range(100, 11).Select(i => $"{i}\t0").ToArray());
    var g30Tcp = new TcpStreamContextProvider(g30TcpReader, budget: 3);
    var g30t1 = await g30Tcp.CollectFramesAsync(108, new HashSet<int>());
    Report("CP-03 TCP 同流: 按帧号最近优先（升序返回），预算内 3 帧",
        g30t1.SequenceEqual(new[] { 105, 106, 107 }), $"r=[{string.Join(",", g30t1)}]");
    var g30Tcp1 = new TcpStreamContextProvider(g30TcpReader, budget: 1);
    var g30t2 = await g30Tcp1.CollectFramesAsync(108, new HashSet<int>());
    Report("CP-03 自定义预算生效（budget=1 仅取 1 帧）",
        g30t2.SequenceEqual(new[] { 107 }), $"r=[{string.Join(",", g30t2)}]");

    // CP-04: Provider 类型/类名映射 + 默认预算常数
    Report("CP-04 Sdp / Fragment 上下文 Provider 类型就位",
        typeof(SdpContextProvider).Name == "SdpContextProvider"
            && typeof(FragmentContextProvider).Name == "FragmentContextProvider",
        "types ok");
    Report("CP-04 TcpStream Provider 类型 + DefaultBudget == 2000",
        typeof(TcpStreamContextProvider).Name == "TcpStreamContextProvider"
            && TcpStreamContextProvider.DefaultBudget == 2000,
        $"budget={TcpStreamContextProvider.DefaultBudget}");

    // ── real: 真实 tshark 驱动（python 预验证过的三夹具） ──
    var g30Det = TsharkService.DetectTshark();
    if (g30Det.Ok && g30Det.Path != null)
    {
        string g30Tp = g30Det.Path;
        // SIP INVITE + SDP body（Content-Length 精确）
        string g30SdpBody = "v=0\r\no=a 0 0 IN IP4 10.0.0.1\r\ns=call\r\nc=IN IP4 10.0.0.1\r\nm=audio 49152 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n";
        string g30Sip = $"INVITE sip:bob@10.0.0.2 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060\r\nFrom: <sip:alice@10.0.0.1>\r\nTo: <sip:bob@10.0.0.2>\r\nCall-ID: abc123@10.0.0.1\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: {g30SdpBody.Length}\r\n\r\n{g30SdpBody}";
        byte[] g30SipBytes = System.Text.Encoding.UTF8.GetBytes(g30Sip);
        byte[] g30SipFrame = FixtureEth(FixtureIpv4(FixtureUdp(5060, 5060, g30SipBytes), 17, 0x1000, 0));
        string g30SipTmp = Path.Combine(Path.GetTempPath(), $"pf-cp-sip-{Guid.NewGuid():N}.pcap");
        await File.WriteAllBytesAsync(g30SipTmp, BuildFixturePcap(g30SipFrame));
        try
        {
            var g30SipReal = new SdpContextProvider((f, fs, ct) => RunTsharkFieldsAsync(g30Tp, g30SipTmp, f, fs));
            Report("CP-01 real: 真实 tshark 从 SIP/SDP 夹具发现 SDP 帧 1",
                (await g30SipReal.CollectFramesAsync(99, new HashSet<int>())).SequenceEqual(new[] { 1 }),
                "collect(99) = [1]");
            Report("CP-01 real: 目标帧被排除（collect(1) 为空）",
                (await g30SipReal.CollectFramesAsync(1, new HashSet<int>())).Count == 0,
                "collect(1) = []");
        }
        finally { File.Delete(g30SipTmp); }

        // 分片: ip.id=0x2A3B 两组（首片 MF=1 offset0 / 尾片 offset2）
        byte[] g30UdpD = Enumerable.Range(0, 24).Select(i => (byte)i).ToArray();
        byte[] g30UdpF = FixtureUdp(1234, 5678, g30UdpD);
        string g30FragTmp = Path.Combine(Path.GetTempPath(), $"pf-cp-frag-{Guid.NewGuid():N}.pcap");
        await File.WriteAllBytesAsync(g30FragTmp, BuildFixturePcap(
            FixtureEth(FixtureIpv4(g30UdpF[..16], 17, 0x2A3B, 0x2000)),
            FixtureEth(FixtureIpv4(g30UdpF[16..], 17, 0x2A3B, 0x0002))));
        try
        {
            var g30FragReal = new FragmentContextProvider((f, fs, ct) => RunTsharkFieldsAsync(g30Tp, g30FragTmp, f, fs));
            Report("CP-02 real: 分片闭包 collect(2) = [1]（两帧同属一台 id）",
                (await g30FragReal.CollectFramesAsync(2, new HashSet<int>())).SequenceEqual(new[] { 1 }),
                "collect(2) = [1]");
        }
        finally { File.Delete(g30FragTmp); }

        // TCP: 同四元组两段（SYN → ACK+PSH）→ tcp.stream=0
        byte[] g30Seg1 = BuildTcpSegment(4000, 5000, 100, 0, 0x02, new byte[] { 0xAA, 0xBB });
        byte[] g30Seg2 = BuildTcpSegment(4000, 5000, 108, 101, 0x18, new byte[] { 0xCC, 0xDD });
        string g30TcpTmp = Path.Combine(Path.GetTempPath(), $"pf-cp-tcp-{Guid.NewGuid():N}.pcap");
        await File.WriteAllBytesAsync(g30TcpTmp, BuildFixturePcap(
            FixtureEth(FixtureIpv4(g30Seg1, 6, 0x1001, 0)),
            FixtureEth(FixtureIpv4(g30Seg2, 6, 0x1002, 0))));
        try
        {
            var g30TcpReal = new TcpStreamContextProvider((f, fs, ct) => RunTsharkFieldsAsync(g30Tp, g30TcpTmp, f, fs));
            Report("CP-03 real: 同流最早帧 collect(2) = [1]",
                (await g30TcpReal.CollectFramesAsync(2, new HashSet<int>())).SequenceEqual(new[] { 1 }),
                "collect(2) = [1]");
            Report("CP-03 real: collect(1) 无更早同流帧 → 空",
                (await g30TcpReal.CollectFramesAsync(1, new HashSet<int>())).Count == 0,
                "collect(1) = []");
        }
        finally { File.Delete(g30TcpTmp); }
    }
    else
    {
        Report("CP-real: tshark not available", false, g30Det.Message);
    }
}
catch (Exception ex)
{
    Report("G30 group execution", false, ex.ToString());
}

// ══ GROUP 31: TL-01..03 TLS keylog 参数注入（argv 捕获式假 tshark） ══
Banner(31, "TL-01..03 tls/ssl keylog args (argv-capture fake tshark)");
string? g31TshEnv = Environment.GetEnvironmentVariable("TSHARK_PATH");
string? g31KlogEnv = Environment.GetEnvironmentVariable("SSLKEYLOGFILE");
string g31Dir = Path.Combine(Path.GetTempPath(), "pf-g31");
try
{
    Directory.CreateDirectory(g31Dir);
    string g31Fake3 = Path.Combine(g31Dir, "tshark3");
    string g31Fake29 = Path.Combine(g31Dir, "tshark29");
    string g31ArgvLog = Path.Combine(g31Dir, "argv.log");
    string g31Klog = Path.Combine(g31Dir, "klog.txt");
    string g31One = Path.Combine(g31Dir, "one.pcap");
    string g31Sh = $"#!/usr/bin/env bash\nif [ \"$1\" = \"-v\" ]; then echo \"tshark 3.2.1\"; exit 0; fi\necho \"$@\" > '{g31ArgvLog}'\nif [[ \"$*\" == *\"-T pdml\"* ]]; then echo '<pdml version=\"0.0\"><packet/></pdml>'; else echo '[]'; fi\n";
    await File.WriteAllTextAsync(g31Fake3, g31Sh);
    await File.WriteAllTextAsync(g31Fake29, g31Sh.Replace("tshark 3.2.1", "tshark 2.9.9"));
    if (!OperatingSystem.IsWindows())
    {
        File.SetUnixFileMode(g31Fake3, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        File.SetUnixFileMode(g31Fake29, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
    await File.WriteAllTextAsync(g31Klog, "client_random,server_random\n");
    byte[] g31Frame = FixtureEth(FixtureIpv4(FixtureUdp(4000, 5000, new byte[4]), 17, 9, 0));
    await File.WriteAllBytesAsync(g31One, BuildFixturePcap(g31Frame));

    // 每次换假 tshark 版本 + 重建检测缓存；解析后 argv 日志 = 最后一次调用参数
    async Task<string> RunKeylogProbeAsync(string fake, string? keylogPath, string? klogEnv)
    {
        Environment.SetEnvironmentVariable("TSHARK_PATH", fake);
        Environment.SetEnvironmentVariable("SSLKEYLOGFILE", klogEnv);
        TsharkService.RedetectTshark();
        var svc = new TsharkService(new PcapIngestService(), new PcapExportService());
        if (keylogPath != null) svc.SetTlsKeylogPath(keylogPath);
        var pkt = new Packet { Index = 0, Timestamp = 0, RawData = g31Frame };
        await svc.ParsePacketFromPcapFileAsync(pkt, g31One);
        return await File.ReadAllTextAsync(g31ArgvLog);
    }

    string g31Args3 = await RunKeylogProbeAsync(g31Fake3, g31Klog, null);
    Report("TL-01 tls.keylog_file 参数注入（tshark >= 3.0.0）",
        g31Args3.Contains($"tls.keylog_file:{g31Klog}") && !g31Args3.Contains("ssl.keylog_file"),
        $"argv=[{g31Args3.Trim()}]");

    string g31Args29 = await RunKeylogProbeAsync(g31Fake29, g31Klog, null);
    Report("TL-02 ssl.keylog_file 参数注入（tshark < 3.0.0 回退）",
        g31Args29.Contains($"ssl.keylog_file:{g31Klog}") && !g31Args29.Contains("tls.keylog_file"),
        $"argv=[{g31Args29.Trim()}]");

    string g31ArgsEnv = await RunKeylogProbeAsync(g31Fake3, null, g31Klog);
    Report("TL-03 SSLKEYLOGFILE 环境变量回退注入",
        g31ArgsEnv.Contains($"tls.keylog_file:{g31Klog}"),
        $"argv=[{g31ArgsEnv.Trim()}]");

    string g31ArgsNone = await RunKeylogProbeAsync(g31Fake3, null, null);
    Report("TL-03 无 keylog 配置 → 不注入任何 -o keylog 参数",
        !g31ArgsNone.Contains("keylog_file"),
        $"argv=[{g31ArgsNone.Trim()}]");

    string g31Axaml = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Views/MainWindow.axaml"));
    string g31CodeBehind = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Views/MainWindow.axaml.cs"));
    string g31Zh = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Assets/Lang/zh-CN.json"));
    string g31En = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Assets/Lang/en-US.json"));
    string g31Svc = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Services/TsharkService.cs"));
    string[] g31RemovedKeys = ["Mnu.TlsKeylog", "Dlg.PickTlsKeylog", "Dlg.KeyLogFiles", "Status.TlsSet", "Status.TlsCleared"];
    bool g31UiGone = !g31Axaml.Contains("Mnu.TlsKeylog")
        && !g31CodeBehind.Contains("OnPickTlsKeylogClicked")
        && !g31Zh.Contains("Mnu.TlsKeylog") && !g31En.Contains("Mnu.TlsKeylog")
        && g31RemovedKeys.All(k => !g31Zh.Contains(k) && !g31En.Contains(k));
    Report("TL-05 keylog 选择菜单已移除（无谎报成功的 UI 入口）", g31UiGone,
        $"axaml={!g31Axaml.Contains("Mnu.TlsKeylog")}, handler={!g31CodeBehind.Contains("OnPickTlsKeylogClicked")}, lang={g31RemovedKeys.Count(k => !g31Zh.Contains(k) && !g31En.Contains(k))}/{g31RemovedKeys.Length} 键已清");

    Report("TL-05 服务层能力保留：SSLKEYLOGFILE 回退 + settings.json 恢复路径仍在",
        g31Svc.Contains("SSLKEYLOGFILE") && g31Svc.Contains("SetTlsKeylogPath"),
        "无 UI 入口但解密能力未丢失");
}
catch (Exception ex)
{
    Report("G31 group execution", false, ex.ToString());
}
finally
{
    Environment.SetEnvironmentVariable("TSHARK_PATH", g31TshEnv);
    Environment.SetEnvironmentVariable("SSLKEYLOGFILE", g31KlogEnv);
    try { TsharkService.RedetectTshark(); } catch { /* restore best effort */ }
    try { Directory.Delete(g31Dir, recursive: true); } catch { /* temp cleanup */ }
}

// ══ GROUP 32: N-17 网卡枚举 ══
Banner(32, "N-17 interfaces");
try
{

    // N-17: 真实网卡枚举（本容器固定 eth0 + lo）
    var g32Net = new NetworkInterfaceService();
    var g32Ifs = g32Net.GetInterfaces();
    Report("N-17 网卡枚举非空且全部 Up（IPv4 或回环）",
        g32Ifs.Count > 0 && g32Ifs.All(i => i.IsUp && (i.IPv4Address != null || i.IsLoopback)),
        $"count={g32Ifs.Count}, ifs=[{string.Join("; ", g32Ifs.Select(i => $"{i.Name}({i.Id},up={i.IsUp},loop={i.IsLoopback},ip={i.IPv4Address})"))}]");

    int g32MaxNonLoop = -1, g32MinLoop = int.MaxValue;
    for (int i = 0; i < g32Ifs.Count; i++)
    {
        if (g32Ifs[i].IsLoopback) g32MinLoop = Math.Min(g32MinLoop, i);
        else g32MaxNonLoop = Math.Max(g32MaxNonLoop, i);
    }
    var g32Nl = g32Ifs.Where(i => !i.IsLoopback).Select(i => i.Name).ToList();
    var g32Ll = g32Ifs.Where(i => i.IsLoopback).Select(i => i.Name).ToList();
    Report("N-17 排序: 非回环在前、回环殿后，各组内按名称升序",
        (g32MinLoop == int.MaxValue || g32MaxNonLoop == -1 || g32MinLoop > g32MaxNonLoop)
            && g32Nl.SequenceEqual(g32Nl.OrderBy(n => n, StringComparer.Ordinal))
            && g32Ll.SequenceEqual(g32Ll.OrderBy(n => n, StringComparer.Ordinal)),
        $"nonloop=[{string.Join(",", g32Nl)}], loop=[{string.Join(",", g32Ll)}]");

    if (g32Ifs.Count > 0)
    {
        var g32Ip = g32Net.GetInterfaceIP(g32Ifs[0].Id);
        Report("N-17 GetInterfaceIP(首个接口) 返回其 IP",
            g32Ip != null, $"id={g32Ifs[0].Id}, ip={g32Ip}");
    }
    else
    {
        Report("N-17 GetInterfaceIP(首个接口) 返回其 IP", false, "no interfaces");
    }
    Report("N-17 GetInterfaceIP(未知 Id) → null",
        g32Net.GetInterfaceIP("pf-no-such-id") == null, "null ok");

    string g32NifSrc = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Services/NetworkInterfaceService.cs"));
    Report("N-17 源码: 扫描异常 → 返回空集合（UI 显示无接口而非崩溃）",
        g32NifSrc.Contains("Return empty list"),
        "missing empty-list fallback");
}
catch (Exception ex)
{
    Report("G32 group execution", false, ex.ToString());
}

// ══ GROUP 26: T-08/T-09/T-12 detection order, version gate, cache (LAST, env-probed) ══
Banner(26, "detection env-first + version gate + cache (T-08/T-09/T-12)");
try
{
    string tshSrc = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Services/TsharkService.cs"));
    Report("T-09 source: gate floor is exactly 2.6.0 (VersionCompare(version, \"2.6.0\") < 0)",
        tshSrc.Contains("VersionCompare(version, \"2.6.0\") < 0"),
        "gate constant drift");
    Report("T-08 source: FindTshark checks TSHARK_PATH env before PATH tiers",
        tshSrc.Contains("TSHARK_PATH"),
        "env probing missing");

    string? tshEnv = Environment.GetEnvironmentVariable("TSHARK_PATH");
    string g26Dir = Path.Combine(Path.GetTempPath(), "pf-g26");
    Directory.CreateDirectory(g26Dir);
    string fakeA = Path.Combine(g26Dir, "fakeA-tshark");
    string fakeB = Path.Combine(g26Dir, "fakeB-tshark");
    string fakeOld = Path.Combine(g26Dir, "fakeOld-tshark");
    try
    {
        await File.WriteAllTextAsync(fakeA, "#!/usr/bin/env bash\necho 'tshark 2.9.9'\n");
        await File.WriteAllTextAsync(fakeB, "#!/usr/bin/env bash\necho 'tshark 2.10.0'\n");
        await File.WriteAllTextAsync(fakeOld, "#!/usr/bin/env bash\necho 'tshark 1.12.6'\n");
        if (!OperatingSystem.IsWindows())
                foreach (var f in new[] { fakeA, fakeB, fakeOld })
                    File.SetUnixFileMode(f, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        Environment.SetEnvironmentVariable("TSHARK_PATH", fakeA);
        var detA = TsharkService.RedetectTshark();
        Report("T-08 env-first: TSHARK_PATH beats PATH even though real tshark exists",
            detA.Ok && string.Equals(detA.Path, fakeA, StringComparison.Ordinal) && detA.Version == "2.9.9",
            $"ok={detA.Ok}, path={detA.Path}, ver={detA.Version}");
        Report("T-09 gate: 2.9.9 (numeric minor 9) ≥ 2.6.0 → accepted",
            detA.Ok && detA.Version == "2.9.9",
            $"ok={detA.Ok}");

        Environment.SetEnvironmentVariable("TSHARK_PATH", fakeB);
        var detB2 = TsharkService.DetectTshark();
        Report("T-12 cache: DetectTshark ignores env change (stale cached path)",
            string.Equals(detB2.Path, fakeA, StringComparison.Ordinal),
            $"cached path={detB2.Path}");
        var detB3 = TsharkService.RedetectTshark();
        Report("T-12 re-detect: RedetectTshark picks up the new env",
            string.Equals(detB3.Path, fakeB, StringComparison.Ordinal) && detB3.Ok && detB3.Version == "2.10.0",
            $"path={detB3.Path}, ok={detB3.Ok}");
        Report("T-09 gate: 2.10.0 (numeric minor 10) ≥ 2.6.0 → accepted (string compare would reject \"2.1\")",
            detB3.Ok && detB3.Version == "2.10.0",
            $"ok={detB3.Ok}, ver={detB3.Version}");

        Environment.SetEnvironmentVariable("TSHARK_PATH", fakeOld);
        var detOld = TsharkService.RedetectTshark();
        Report("T-09 gate reject: 1.12.6 < 2.6.0 → Tsh.TooOld, env path still reported",
            !detOld.Ok && detOld.MessageKey == "Tsh.TooOld" && detOld.Version == "1.12.6"
                && string.Equals(detOld.Path, fakeOld, StringComparison.Ordinal),
            $"ok={detOld.Ok}, key={detOld.MessageKey}, ver={detOld.Version}, path={detOld.Path}");
    }
    finally
    {
        Environment.SetEnvironmentVariable("TSHARK_PATH", tshEnv);
        try { TsharkService.RedetectTshark(); } catch { /* restore best effort */ }
        try { Directory.Delete(g26Dir, recursive: true); } catch { /* temp cleanup */ }
    }
}
catch (Exception ex)
{
    Report("G26 group execution", false, ex.ToString());
}

Banner(33, "direct send state, no-op tree edit, and close guard");
try
{
    var g33Packets = new PacketListViewModel();
    g33Packets.Packets.Add(new Packet
    {
        Timestamp = 1_000_000,
        RawData = BuildSyntheticPfcpAssociationResponse(),
        SendSelected = true,
    });
    var g33Toolbar = new ToolBarViewModel(
        new NetworkInterfaceService(),
        new PacketSendService(),
        g33Packets);
    g33Toolbar.SelectedInterface = new NetworkInterfaceInfo(
        "g33-test",
        "g33-test-nic",
        "Synthetic non-loopback interface",
        IPAddress.Parse("192.0.2.10"),
        null,
        "02:00:00:00:00:10",
        IsLoopback: false,
        IsUp: true);

    string g33ToolbarSource = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "ViewModels/ToolBarViewModel.cs"));
    string g33WindowSource = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Views/MainWindow.axaml.cs"));
    string g33TreeSource = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Views/Controls/ProtocolTreeView.axaml"));
    string g33HexSource = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Views/Controls/HexEditor.axaml.cs"));
    Report("G33-01 direct physical-NIC send stays available without an extra gate",
        g33Toolbar.CanSend
            && !g33Toolbar.AutoFixFrames
            && !g33ToolbarSource.Contains("ProductionSendEnabled", StringComparison.Ordinal)
            && !g33ToolbarSource.Contains("SendApprovalHandler", StringComparison.Ordinal),
        $"canSend={g33Toolbar.CanSend}, autoFix={g33Toolbar.AutoFixFrames}");

    // G33-05/06:发送门禁的可执行断言。G33-01 只断言 CanSend 与「不存在门禁标识符」,
    // 与右键路径是否被拦住无关,因此门禁本身必须在这里真正跑一次。
    // 两者都在真正开 socket 之前就 return false,不产生任何网络流量。
    var g33GatePacket = new Packet
    {
        Index = 0,
        Timestamp = 1_000_000,
        RawData = BuildSyntheticPfcpAssociationResponse(),
        SendSelected = true,
    };
    var g33GateList = new PacketListViewModel();
    g33GateList.Packets.Add(g33GatePacket);
    var g33GateToolbar = new ToolBarViewModel(
        new NetworkInterfaceService(),
        new PacketSendService(),
        g33GateList);

    // (a) 只读态必须拒绝发送,并给出只读原因。
    g33GateToolbar.SelectedInterface = new NetworkInterfaceInfo(
        "g33-gate", "g33-gate-nic", "Synthetic non-loopback interface",
        IPAddress.Parse("192.0.2.10"), null, "02:00:00:00:00:aa",
        IsLoopback: false, IsUp: true);
    g33GateToolbar.IsReadOnly = true;
    bool g33ReadOnlyBlocked = !await g33GateToolbar.SendPacketsAsync(new[] { g33GatePacket })
                              && g33GateToolbar.StatusKey == "Status.SendBlockedReadOnly"
                              && !g33GateToolbar.IsSending;
    Report("G33-05 SendPacketsAsync refuses to send while read-only",
        g33ReadOnlyBlocked,
        $"blocked={g33ReadOnlyBlocked}, statusKey={g33GateToolbar.StatusKey}, isSending={g33GateToolbar.IsSending}");
    g33GateToolbar.IsReadOnly = false;

    // (b) 回环网卡必须被拒绝 —— 工具栏一直是这么做的,右键路径过去没有。
    g33GateToolbar.SelectedInterface = new NetworkInterfaceInfo(
        "g33-lo", "g33-lo-nic", "Synthetic loopback interface",
        IPAddress.Parse("127.0.0.1"), null, "02:00:00:00:00:bb",
        IsLoopback: true, IsUp: true);
    bool g33LoopbackBlocked = !await g33GateToolbar.SendPacketsAsync(new[] { g33GatePacket })
                              && g33GateToolbar.StatusKey == "Status.SendBlockedLoopback"
                              && !g33GateToolbar.IsSending;
    Report("G33-06 SendPacketsAsync refuses to send on a loopback interface",
        g33LoopbackBlocked,
        $"blocked={g33LoopbackBlocked}, statusKey={g33GateToolbar.StatusKey}, isSending={g33GateToolbar.IsSending}");

    // (c) 防回归:门禁不得依赖复选框。右键「发送此报文」按设计忽略 SendSelected
    //     (en-US Tip.SendRow),所以未勾选任何行时,选中行仍必须能发出去。
    g33GateToolbar.SelectedInterface = new NetworkInterfaceInfo(
        "g33-ok", "g33-ok-nic", "Synthetic non-loopback interface",
        IPAddress.Parse("192.0.2.11"), null, "02:00:00:00:00:cc",
        IsLoopback: false, IsUp: true);
    g33GatePacket.SendSelected = false;
    g33GateToolbar.RefreshGate();
    bool g33GateIgnoresCheckmarks = !g33GateToolbar.CanSend;   // 工具栏按钮:应为灰(合理)
    Report("G33-07 gate predicate excludes the SendSelected term (right-click sends the selected row)",
        g33GateIgnoresCheckmarks,
        $"canSendWithoutCheckbox={g33GateToolbar.CanSend} (expected False: toolbar greys out, but the right-click path must still be allowed)");
    g33GatePacket.SendSelected = true;

    var g33Editor = new ProtocolEditorService();
    var g33Export = new PcapExportService();
    var g33Tsh = new TsharkService(new PcapIngestService(), g33Export);
    var g33Packet = new Packet
    {
        Index = 0,
        Timestamp = 1_000_000,
        RawData = BuildSyntheticPfcpAssociationResponse(),
    };
    string g33Tmp = Path.Combine(Path.GetTempPath(), $"pf-g33-tree-{Guid.NewGuid():N}.pcap");
    try
    {
        await File.WriteAllBytesAsync(g33Tmp, BuildFixturePcap(g33Packet.RawData));
        bool g33Parsed = await g33Tsh.ParsePacketFromPcapFileAsync(g33Packet, g33Tmp);
        var g33Fields = g33Parsed
            ? g33Packet.Layers.SelectMany(layer => Flatten(layer.Fields)).ToList()
            : new List<ProtocolField>();
        var g33Field = g33Fields.FirstOrDefault(field => g33Editor.CheckTreeEditFence(g33Packet, field).Allowed);
        int g33EditEvents = 0;
        var g33Tree = new ProtocolTreeViewModel(
            g33Editor,
            new EditTransactionService(g33Export, g33Tsh),
            new EditHistoryService());
        g33Tree.FieldEdited += _ => g33EditEvents++;
        if (g33Field != null)
        {
            g33Tree.LoadPacket(g33Packet);
            g33Tree.BeginFieldEdit(g33Packet, g33Field);
            await g33Tree.CommitFieldEditAsync();
        }
        Report("G33-02 double-click with unchanged text does not mark packet or emit edit event",
            g33Field != null && !g33Packet.IsModified && g33EditEvents == 0 && !g33Field.IsEditing,
            $"parsed={g33Parsed}, field={g33Field?.Name ?? "(null)"}, modified={g33Packet.IsModified}, events={g33EditEvents}");
    }
    finally
    {
        try { File.Delete(g33Tmp); } catch (Exception cleanupError) { Console.WriteLine(cleanupError.Message); }
    }

    Report("G33-03 close guard remains while tree and hex horizontal scrollbars are disabled",
        g33WindowSource.Contains("e.Cancel = true", StringComparison.Ordinal)
            && g33TreeSource.Contains("ScrollViewer.HorizontalScrollBarVisibility=\"Disabled\"", StringComparison.Ordinal)
            && g33HexSource.Contains("HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled", StringComparison.Ordinal),
        "close guard and horizontal scrollbar source markers");
}
catch (Exception ex)
{
    Report("G33 group execution", false, ex.ToString());
}


  Banner(34, "reset-modifications repaints, restores the tree, and unlocks the fence");
  try
  {
      var g34Editor = new ProtocolEditorService();
      var g34Export = new PcapExportService();
      var g34Tsh = new TsharkService(new PcapIngestService(), g34Export);
      var g34Packet = new Packet
      {
          Index = 0,
          Timestamp = 1_000_000,
          RawData = BuildSyntheticPfcpAssociationResponse(),
      };
      string g34Tmp = Path.Combine(Path.GetTempPath(), $"pf-g34-tree-{Guid.NewGuid():N}.pcap");
      try
      {
          await File.WriteAllBytesAsync(g34Tmp, BuildFixturePcap(g34Packet.RawData));
          bool g34Parsed = await g34Tsh.ParsePacketFromPcapFileAsync(g34Packet, g34Tmp);
          int g34LayersAfterFirstParse = g34Parsed ? g34Packet.Layers.Count : 0;

          var g34Fields = g34Parsed
              ? g34Packet.Layers.SelectMany(layer => Flatten(layer.Fields)).ToList()
              : new List<ProtocolField>();
          var g34Field = g34Fields.FirstOrDefault(field => g34Editor.CheckTreeEditFence(g34Packet, field).Allowed);

          // The hex grid is built in view code-behind, so updating HexByte.Value does not
          // repaint on its own. Without an explicit repaint request the user sees the old
          // bytes until they click another cell.
          var g34Hex = new HexEditorViewModel(g34Editor, new EditHistoryService());
          int g34Repaints = 0;
          g34Hex.RefreshVisualRequested += () => g34Repaints++;
          g34Hex.LoadPacket(g34Packet);
          g34Repaints = 0;
          g34Hex.RefreshBytes();
          Report("G34-01 hex RefreshBytes requests a repaint",
              g34Repaints > 0,
              $"repaints={g34Repaints}");

          // Reverting the bytes alone leaves the cached tree holding the edited RawBytes.
          // The fence's byte-agreement check then rejects the field for the rest of the
          // session, so a re-parse is what makes the field editable again.
          bool g34StaleLocksFence = false;
          bool g34ReparseRestores = false;
          if (g34Parsed && g34Field != null)
          {
              byte[] g34Edited = g34Field.RawBytes.ToArray();
              g34Edited[^1] ^= 0xFF;
              g34Editor.ApplyFieldEdit(g34Packet, g34Field, g34Edited);
              g34Packet.ResetModifications();
              g34StaleLocksFence = !g34Editor.CheckTreeEditFence(g34Packet, g34Field).Allowed;

              bool g34Reparsed = await g34Tsh.BuildPacketTreeAsync(g34Packet, 1);
              // Several fields can share one byte span (an SDP codec id, a MAC and an
              // address all landing on 6 bytes), so a span is not a field identity, and a
              // reparse yields new instances. Match the edited field by stable PDML name.
              string g34Key = g34Field.OriginalPdmlName.Length > 0 ? g34Field.OriginalPdmlName : g34Field.Name;
              g34ReparseRestores = g34Reparsed
                  && g34Packet.Layers.SelectMany(layer => Flatten(layer.Fields))
                      .Any(field => (field.OriginalPdmlName.Length > 0 ? field.OriginalPdmlName : field.Name) == g34Key
                                    && g34Editor.CheckTreeEditFence(g34Packet, field).Allowed);
          }
          Report("G34-02 a stale tree locks the fence; re-parse restores editability",
              g34Parsed && g34Field != null && g34StaleLocksFence && g34ReparseRestores,
              $"parsed={g34Parsed}, field={g34Field?.Name ?? "(null)"}, staleLocks={g34StaleLocksFence}, reparseRestores={g34ReparseRestores}");

          // Every surface the edit touched has to come back: packet-list columns, the orange
          // edited marks, the tree itself, plus a read-only guard and a confirmation.
          string g34Mw = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "ViewModels/MainWindowViewModel.cs"));
          string g34HexSrc = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "ViewModels/HexEditorViewModel.cs"));
          string g34Win = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Views/MainWindow.axaml.cs"));
          bool g34Wired =
              g34Mw.Contains("ReExtractAddressInfo(packet)", StringComparison.Ordinal)
              && g34Mw.Contains("ClearEditedMarks()", StringComparison.Ordinal)
              && g34Mw.Contains("BuildTreeAsync(shown, seq)", StringComparison.Ordinal)
              && g34Mw.Contains("Status.ResetReadOnly", StringComparison.Ordinal)
              && g34Mw.Contains("HexEditor.CancelHexEdit()", StringComparison.Ordinal)
              && g34HexSrc.Contains("public void ClearEditedMarks()", StringComparison.Ordinal)
              && g34Win.Contains("ConfirmResetModificationsAsync", StringComparison.Ordinal);
          Report("G34-03 reset restores columns/marks/tree, guards read-only, and confirms first",
              g34Wired,
              $"columns={g34Mw.Contains("ReExtractAddressInfo(packet)", StringComparison.Ordinal)}, marks={g34Mw.Contains("ClearEditedMarks()", StringComparison.Ordinal)}, tree={g34Mw.Contains("BuildTreeAsync(shown, seq)", StringComparison.Ordinal)}");

          string g34View = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Views/MainWindow.axaml"));
          Report("G34-04 reset menu item still wired to the async command",
              g34View.Contains("OnResetClicked", StringComparison.Ordinal)
              && g34Win.Contains("ResetModificationsCommand.ExecuteAsync(null)", StringComparison.Ordinal),
              "menu=OnResetClicked, awaited=ExecuteAsync");

          // Regression: re-parsing a packet whose tree already exists must REPLACE the
          // layer list, not append. The reset path re-parses the shown packet, and a
          // build without an initial clear doubled every layer on each reset press.
          Report("G34-05 re-parse keeps a single layer copy (no duplication)",
              g34LayersAfterFirstParse > 0 && g34Packet.Layers.Count == g34LayersAfterFirstParse,
              $"first={g34LayersAfterFirstParse}, afterReparse={g34Packet.Layers.Count}");

          // G34-06: hex-editing a Data-layer byte must refresh the Data node's display via
          // the single-packet reparse. tshark wraps the data pseudo-protocol in a pos-less
          // fake-field-wrapper, whose positioned children (data.data/data.len) used to be
          // skipped by the reparse lookup, leaving the tree stale after an edit. A
          // synthetic IPv4 proto 253 (experimental — tshark has no upper dissector)
          // reliably surfaces a 16-byte Data payload for the scenario.
          string g34DataTmp = Path.Combine(Path.GetTempPath(), $"pf-g34-data-{Guid.NewGuid():N}.pcap");
          bool g34DataRefreshOk = false;
          string g34DataDetail = "no data layer";
          try
          {
              var g34DataPacket = new Packet
              {
                  Index = 0,
                  Timestamp = 2_000_000,
                  RawData = FixtureEth(FixtureIpv4(System.Text.Encoding.ASCII.GetBytes("0123456789abcdef"), 253)),
              };
              await File.WriteAllBytesAsync(g34DataTmp, BuildFixturePcap(g34DataPacket.RawData));
              bool g34DataParsed = await g34Tsh.ParsePacketFromPcapFileAsync(g34DataPacket, g34DataTmp);
              var g34DataField = g34DataParsed
                  ? g34DataPacket.Layers.FirstOrDefault(layer => layer.ProtocolName == "data")?
                      .Fields.FirstOrDefault(field => field.OriginalPdmlName == "data.data")
                  : null;
              if (g34DataParsed && g34DataField != null)
              {
                  g34DataField.DisplayValue = "stale-marker";
                  g34DataPacket.ApplyModification(g34DataField.Offset, new byte[] { 0xAA, 0xBB });
                await g34Export.SavePacketAsync(g34DataPacket, g34DataTmp, linkLayerType: 1);
                PdmlData? g34DataFresh = await g34Tsh.ReparseSinglePacketAsync(g34DataTmp);
                if (g34DataFresh != null)
                {
                    var g34DataTree = new ProtocolTreeViewModel(g34Editor, new EditTransactionService(g34Export, g34Tsh), new EditHistoryService());
                    foreach (var layer in g34DataPacket.Layers) g34DataTree.Layers.Add(layer);
                    int g34DataMisses = g34DataTree.RefreshFieldDisplays(g34DataPacket, g34DataFresh);
                    var g34DataAfter = g34DataTree.Layers.FirstOrDefault(layer => layer.ProtocolName == "data")?
                        .Fields.FirstOrDefault(field => field.OriginalPdmlName == "data.data");
                    g34DataRefreshOk = g34DataMisses == 0
                        && g34DataAfter?.DisplayValue?.StartsWith("aabb", StringComparison.OrdinalIgnoreCase) == true;
                    g34DataDetail = $"misses={g34DataMisses}, display={g34DataAfter?.DisplayValue}";
                }
                else
                {
                    g34DataDetail = "reparse returned no PDML data";
                }
              }
              else
              {
                  g34DataDetail = $"parsed={g34DataParsed}, dataField={(g34DataField is null ? "(null)" : g34DataField.OriginalPdmlName)}";
              }
          }
          finally
          {
              try { File.Delete(g34DataTmp); } catch (Exception cleanupError) { Console.WriteLine(cleanupError.Message); }
          }
          Report("G34-06 hex-edit on a Data byte refreshes the Data-node display via reparse",
              g34DataRefreshOk,
              g34DataDetail);
      }
      finally { try { File.Delete(g34Tmp); } catch (Exception cleanupError) { Console.WriteLine(cleanupError.Message); } }
  }
  catch (Exception ex)
  {
      Report("G34 group execution", false, ex.ToString());
  }

  Banner(35, "reset-modifications end-to-end through the real command");
  try
  {
      var g35Editor = new ProtocolEditorService();
      var g35Export = new PcapExportService();
      var g35Tsh = new TsharkService(new PcapIngestService(), g35Export);
      var g35Tree = new ProtocolTreeViewModel(g35Editor, new EditTransactionService(g35Export, g35Tsh), new EditHistoryService());
      var g35Hex = new HexEditorViewModel(g35Editor, new EditHistoryService());
      var g35List = new PacketListViewModel();
      var g35Toolbar = new ToolBarViewModel(
          new NetworkInterfaceService(),
          new PacketSendService(),
          g35List);
      var g35Doc = new PacketDocument();
      var g35Vm = new MainWindowViewModel(g35Tsh, g35Export, g35Editor, g35List, g35Tree, g35Hex, g35Toolbar);
      g35Vm.Document = g35Doc;

      var g35Packet = new Packet
      {
          Index = 0,
          Timestamp = 1_000_000,
          RawData = BuildSyntheticPfcpAssociationResponse(),
      };
      string g35Tmp = Path.Combine(Path.GetTempPath(), $"pf-g35-tree-{Guid.NewGuid():N}.pcap");
      try
      {
          await File.WriteAllBytesAsync(g35Tmp, BuildFixturePcap(g35Packet.RawData));
          bool g35Parsed = await g35Tsh.ParsePacketFromPcapFileAsync(g35Packet, g35Tmp);
          g35Doc.Packets.Add(g35Packet);
          g35List.Packets.Add(g35Packet);
          g35Hex.LoadPacket(g35Packet);

          ProtocolField? g35Field = g35Parsed
              ? g35Packet.Layers.SelectMany(layer => Flatten(layer.Fields))
                  .FirstOrDefault(field => g35Editor.CheckTreeEditFence(g35Packet, field).Allowed)
              : null;

          if (g35Parsed && g35Field != null)
          {
              byte[] g35Edited = g35Field.RawBytes.ToArray();
              g35Edited[^1] ^= 0xFF;
              g35Editor.ApplyFieldEdit(g35Packet, g35Field, g35Edited);
              g35Vm.ModifiedPackets = 1;
              g35Doc.HasUnsavedChanges = true;
              g35Hex.MarkFieldEdited(g35Field);

              await g35Vm.ResetModificationsCommand.ExecuteAsync(null);

              // Match the field that was edited by offset+length: "any editable field"
              // would pass even while the edited one is still locked out.
              // A byte span is not a field identity (several fields can share one), and a
              // reparse produces new instances — so match the edited field by its
              // stable PDML name plus its span.
              // One name+span can still be shared by several nodes (a real span and a
              // virtual reassembly span), and the fence rightly rejects the virtual one. What
              // the user needs is that SOME node at the edited identity is clickable again.
              string g35Key = g35Field.OriginalPdmlName.Length > 0 ? g35Field.OriginalPdmlName : g35Field.Name;
              int g35Off = g35Field.Offset, g35Len = g35Field.Length;
              var g35AtIdentity = g35Packet.Layers.SelectMany(layer => Flatten(layer.Fields))
                  .Where(f => (f.OriginalPdmlName.Length > 0 ? f.OriginalPdmlName : f.Name) == g35Key
                              && f.Offset == g35Off && f.Length == g35Len).ToList();
              bool g35EditableAgain = g35AtIdentity.Any(f => g35Editor.CheckTreeEditFence(g35Packet, f).Allowed);
              bool g35BytesRestored = g35Packet.EffectiveData.AsSpan().SequenceEqual(g35Packet.RawData);
              bool g35MarksCleared = g35Hex.Bytes.All(b => !b.IsEdited);

              Report("G35-01 command restores bytes, clears marks, and re-unlocks the tree",
                  !g35Packet.IsModified
                  && g35BytesRestored
                  && g35MarksCleared
                  && g35EditableAgain
                  && g35Vm.ModifiedPackets == 0
                  && !g35Doc.HasUnsavedChanges,
                  $"modified={g35Packet.IsModified}, bytesRestored={g35BytesRestored}, marksCleared={g35MarksCleared}, atIdentity={g35AtIdentity.Count}, editableAgain={g35EditableAgain}, vmCount={g35Vm.ModifiedPackets}, docDirty={g35Doc.HasUnsavedChanges}");
          }
          else
          {
              Report("G35-01 command restores bytes, clears marks, and re-unlocks the tree", false,
                  $"parsed={g35Parsed}, field={(g35Field?.Name ?? "(null)")}");
          }
      }
      finally { try { File.Delete(g35Tmp); } catch (Exception cleanupError) { Console.WriteLine(cleanupError.Message); } }
  }
  catch (Exception ex)
  {
      Report("G35 group execution", false, ex.ToString());
  }

// ══ GROUP 36: DI-01..03 重复容器不得补出幽灵兄弟节点 ══
Banner(36, "DI-01..03 paired repeated containers must not emit a phantom twin row");
try
{
    string g36Tmp = Path.Combine(Path.GetTempPath(), "pf-g36-diameter.pcap");
    File.WriteAllBytes(g36Tmp, BuildFixturePcap(BuildSyntheticDiameterDwr()));
    var g36Ingest = new PcapIngestService();
    var g36Read = await g36Ingest.ReadPacketsAsync(g36Tmp);
    var g36Svc = new TsharkService(g36Ingest, new PcapExportService());
    var g36Pkt = new Packet { Index = 0, Timestamp = 0, RawData = g36Read.Packets[0].Data };
    await g36Svc.ParsePacketFromPcapFileAsync(g36Pkt, g36Tmp);

    var g36Dia = g36Pkt.Layers.FirstOrDefault(l => l.ProtocolName == "diameter");
    var g36Avps = g36Dia?.Fields.Where(f => f.OriginalPdmlName == "diameter.avp").ToList() ?? [];
    var g36LeafNames = g36Avps.SelectMany(a => a.Children.Select(c => c.OriginalPdmlName)).ToList();

    Report("DI-01 夹具前提：tshark 将其 dissect 为 diameter 且两个 AVP 均可解析",
        g36Dia is not null
        && g36LeafNames.Contains("diameter.Origin-Host")
        && g36LeafNames.Contains("diameter.Origin-Realm"),
        $"layer={(g36Dia is null ? "缺失" : "存在")}, AVP={g36Avps.Count}, 含Origin-Host={g36LeafNames.Contains("diameter.Origin-Host")}, 含Origin-Realm={g36LeafNames.Contains("diameter.Origin-Realm")}");

    // The defect: tshark emits N avp_raw + N avp_tree as duplicate JSON keys. The
    // surplus-twin pass read rawPosition (raws consumed so far) as "raws nobody will
    // claim", so after the first of two containers it re-emitted avp_raw[1] as a
    // childless third AVP row. Wireshark shows exactly two.
    Report("DI-02 协议树的 AVP 行数与 PDML 一致（无幽灵补写行）",
        g36Avps.Count == 2,
        $"顶层 AVP 行数={g36Avps.Count}（tshark PDML=2）");

    int g36Phantom = 0;
    string g36PhantomDetail = "";
    foreach (var layer in g36Pkt.Layers)
    {
        foreach (var grp in layer.Fields.GroupBy(f => (f.Name, f.Offset)).Where(g => g.Count() > 1))
        {
            var kids = grp.Select(x => x.Children.Count).Distinct().ToList();
            if (kids.Count < 2) continue;
            g36Phantom++;
            g36PhantomDetail += $"[{layer.ProtocolName}]{grp.Key.Name}@off{grp.Key.Offset}×{grp.Count()}(kids {string.Join("/", kids)}) ";
        }
    }
    Report("DI-03 无同名同偏移而子节点数不同的重复行", g36Phantom == 0,
        g36Phantom == 0 ? "整棵树无幽灵签名" : g36PhantomDetail);
}
catch (Exception ex)
{
    Report("G36 group execution", false, ex.ToString());
}
finally
{
    try { File.Delete(Path.Combine(Path.GetTempPath(), "pf-g36-diameter.pcap")); } catch { }
}

// ══ GROUP 37: LB-01..03 位域标签人文化 + SP-01..02 匿名容器字节跨度 ══
Banner(37, "LB/SP bitfield labels and anonymous-container spans");
try
{
    // ── LB: bitfield leaves must carry Wireshark's label, not the field abbreviation.
    // Wireshark renders them as "<bit pattern> = <Label>: <value>"; splitting that on
    // the first ": " leaves "0100 .... = Version" in the name half, so the previous
    // guard rejected every bitfield and the tree showed "version" / "df" / "s".
    string g37Ip = Path.Combine(Path.GetTempPath(), "pf-g37-ip.pcap");
    File.WriteAllBytes(g37Ip, BuildFixturePcap(FixtureEth(FixtureIpv4(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }))));
    var g37Ingest = new PcapIngestService();
    var g37Read = await g37Ingest.ReadPacketsAsync(g37Ip);
    var g37Svc = new TsharkService(g37Ingest, new PcapExportService());
    var g37Pkt = new Packet { Index = 0, Timestamp = 0, RawData = g37Read.Packets[0].Data };
    await g37Svc.ParsePacketFromPcapFileAsync(g37Pkt, g37Ip);

    var g37IpLayer = g37Pkt.Layers.FirstOrDefault(l => l.ProtocolName == "ip");
    var g37Labels = new Dictionary<string, string>();
    void Collect(ProtocolField f)
    {
        if (f.OriginalPdmlName.Length > 0) g37Labels[f.OriginalPdmlName] = f.Name;
        foreach (var c in f.Children) Collect(c);
    }
    if (g37IpLayer is not null) foreach (var f in g37IpLayer.Fields) Collect(f);

    // ip.version / ip.hdr_len / ip.flags.df are the canonical bitfield rows.
    string[] g37Bitfields = ["ip.version", "ip.hdr_len", "ip.flags.df", "ip.flags.mf", "ip.dsfield.ecn"];
    var g37Bad = g37Bitfields
        .Where(n => g37Labels.TryGetValue(n, out var lbl) && lbl == n[(n.LastIndexOf('.') + 1)..])
        .ToList();
    Report("LB-01 位域叶子显示 Wireshark 标签而非字段缩写",
        g37Bad.Count == 0,
        string.Join(", ", g37Bitfields.Select(n =>
            $"{n}='{(g37Labels.TryGetValue(n, out var l) ? l : "缺失")}'")));

    Report("LB-02 ip.flags 容器仍带人类标签 Flags",
        g37Labels.TryGetValue("ip.flags", out var g37Flags) && g37Flags == "Flags",
        $"ip.flags='{(g37Labels.TryGetValue("ip.flags", out var l) ? l : "缺失")}'");

    // A non-bitfield " = " head must still fall back to the abbreviation rather than
    // being split into something misleading. No field in the fixtures above reaches
    // that path, so assert the whitelist itself is still there: relaxing it to an
    // unconditional LastIndexOf(" = ") would silently re-break every other shape.
    string g37SvcSrc = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Services/TsharkService.cs"));
    Report("LB-03 位域白名单仍在（非位域 \" = \" 形态仍回退到字段缩写）",
        g37SvcSrc.Contains("c is '0' or '1' or '#' or '.' or ' '"),
        "TrySplitShowname 仅接受 0/1/#/. 与空格构成的位模式头；无条件 LastIndexOf 会让本断言变红");

    // ── SP: tshark keys an anonymous container by its rendered text ("F-SEID : SEID: …")
    // and gives it no _raw twin, so its span is only knowable from PDML. Without it the
    // row renders zero-length: no hex highlight, not editable, unreachable by hex→tree
    // sync. PFCP IEs are the common case, so the synthetic association response is the
    // fixture — a Diameter fixture would not do, its AVPs are named containers.
    string g37Pfcp = Path.Combine(Path.GetTempPath(), "pf-g37-pfcp.pcap");
    File.WriteAllBytes(g37Pfcp, BuildFixturePcap(BuildSyntheticPfcpAssociationResponse()));
    var g37PfcpRead = await g37Ingest.ReadPacketsAsync(g37Pfcp);
    var g37PfcpSvc = new TsharkService(g37Ingest, new PcapExportService());
    var g37PfcpPkt = new Packet { Index = 0, Timestamp = 0, RawData = g37PfcpRead.Packets[0].Data };
    await g37PfcpSvc.ParsePacketFromPcapFileAsync(g37PfcpPkt, g37Pfcp);

    var g37PfcpLayer = g37PfcpPkt.Layers.FirstOrDefault(l => l.ProtocolName == "pfcp");
    var g37Ies = g37PfcpLayer?.Fields
        .Where(f => f.OriginalPdmlName.Length == 0 && f.Children.Count > 0).ToList() ?? [];
    Report("SP-00 夹具前提：PFCP 层解析出带子节点的匿名 IE 容器",
        g37Ies.Count > 0,
        $"匿名容器={g37Ies.Count}, 名称=[{string.Join(", ", g37Ies.Select(x => x.Name))}]");

    Report("SP-01 带子节点的匿名容器不再零跨度",
        g37Ies.Count > 0 && g37Ies.All(x => x.Length > 0 && x.Offset > 0),
        string.Join(" | ", g37Ies.Select(x => $"'{x.Name}' off={x.Offset} len={x.Length}")));

    Report("SP-02 容器跨度覆盖其子节点字节范围",
        g37Ies.Count > 0 && g37Ies.All(x =>
        {
            int lo = x.Children.Min(c => c.Offset);
            int hi = x.Children.Max(c => c.Offset + c.Length);
            return x.Offset <= lo && x.Offset + x.Length >= hi;
        }),
        "容器 [off, off+len) 必须完整包住所有子节点");

    Report("SP-03 容器带真实字节（可被 hex 查看器高亮）",
        g37Ies.Count > 0 && g37Ies.All(x => x.RawBytes.Length == x.Length && x.Length > 0),
        string.Join(" | ", g37Ies.Select(x => $"{x.Name}:{x.RawBytes.Length}B")));
}
catch (Exception ex)
{
    Report("G37 group execution", false, ex.ToString());
}
finally
{
    foreach (var leftover in new[] { "pf-g37-ip.pcap", "pf-g37-pfcp.pcap" })
    {
        try { File.Delete(Path.Combine(Path.GetTempPath(), leftover)); } catch { }
    }
}

// ══ GROUP 38: EI-01..04 专家信息（异常/校验和告警）必须透出 ══
Banner(38, "EI-01..04 expert info rows surface (wireshark keeps them)");
try
{
    // An IPv4 packet with TTL=1 makes tshark attach an expert-info subtree under ip.ttl:
    // <field name="_ws.expert" showname='Expert Info (Note/Sequence): "Time To Live" only 1'>
    // whose children (_ws.expert.severity / .group, ip.ttl.too_small) carry [0,0,0,N] —
    // a number first, not hex — so the scalar branch used to drop all of them.
    byte[] g38Ip = Concat(
        new byte[] { 0x45, 0x00, 0x00, 0x14, 0x12, 0x34, 0x00, 0x00, 0x01, 0x06, 0x00, 0x00 },
        new byte[] { 10, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 },
        new byte[8]);
    string g38Path = Path.Combine(Path.GetTempPath(), "pf-g38-expert.pcap");
    File.WriteAllBytes(g38Path, BuildFixturePcap(FixtureEth(g38Ip)));
    var g38Ingest = new PcapIngestService();
    var g38Read = await g38Ingest.ReadPacketsAsync(g38Path);
    var g38Svc = new TsharkService(g38Ingest, new PcapExportService());
    var g38Pkt = new Packet { Index = 0, Timestamp = 0, RawData = g38Read.Packets[0].Data };
    await g38Svc.ParsePacketFromPcapFileAsync(g38Pkt, g38Path);

    var g38All = new List<ProtocolField>();
    void G38Walk(ProtocolField f)
    {
        g38All.Add(f);
        foreach (var c in f.Children) G38Walk(c);
    }
    foreach (var l in g38Pkt.Layers) foreach (var f in l.Fields) G38Walk(f);

    var g38Expert = g38All.FirstOrDefault(f => f.OriginalPdmlName == "_ws.expert");
    Report("EI-00 夹具前提：tshark 为 TTL=1 的 IPv4 报文挂出 _ws.expert 子树",
        g38Expert is not null,
        $"_ws.expert={(g38Expert is null ? "缺失" : $"kids={g38Expert.Children.Count}")}");

    Report("EI-01 专家信息容器显示 Wireshark 标签而非 _ws.expert 缩写",
        g38Expert is not null && g38Expert.Name.StartsWith("Expert Info", StringComparison.Ordinal),
        $"name='{g38Expert?.Name}'");

    var g38TtlSmall = g38All.FirstOrDefault(f => f.OriginalPdmlName == "ip.ttl.too_small");
    Report("EI-02 告警正文透出（Wireshark 同样显示该行）",
        g38TtlSmall is not null && g38TtlSmall.DisplayValue.Contains("Time To Live", StringComparison.Ordinal),
        $"ip.ttl.too_small='{g38TtlSmall?.DisplayValue}'");

    var g38Sev = g38All.FirstOrDefault(f => f.OriginalPdmlName == "_ws.expert.severity");
    var g38Grp = g38All.FirstOrDefault(f => f.OriginalPdmlName == "_ws.expert.group");
    Report("EI-03 告警级别与分组透出",
        g38Sev is not null && g38Sev.DisplayValue == "Note" && g38Grp is not null && g38Grp.DisplayValue == "Sequence",
        $"severity='{g38Sev?.DisplayValue}', group='{g38Grp?.DisplayValue}'");

    // Wireshark marks _ws.expert.message hide="yes" — the message duplicates the
    // container's own value, so it must stay out of the tree.
    Report("EI-04 Wireshark 隐藏的 _ws.expert.message 仍不透出（不制造重复行）",
        g38All.All(f => f.OriginalPdmlName != "_ws.expert.message"),
        "hide=yes 的行不得出现");
}
catch (Exception ex)
{
    Report("G38 group execution", false, ex.ToString());
}
finally
{
    try { File.Delete(Path.Combine(Path.GetTempPath(), "pf-g38-expert.pcap")); } catch { }
}

// ══ GROUP 39: DF-01..04 display filter narrows the grid + EN-01..03 enum catalog ══
Banner(39, "display filter + enum catalog");
try
{
    var g39Src = Path.Combine(Path.GetTempPath(), "pf-g39.pcap");
    var g39Pfcp = BuildSyntheticPfcpAssociationResponse();
    var g39Udp = FixtureEth(FixtureIpv4(FixtureUdp(5000, 5001, new byte[] { 0x0a, 0x0b, 0x0c, 0x0d })));
    var g39Frames = new byte[40][];
    for (int i = 0; i < g39Frames.Length - 1; i++) g39Frames[i] = g39Udp;
    g39Frames[g39Frames.Length - 1] = g39Pfcp;
    await File.WriteAllBytesAsync(g39Src, BuildFixturePcap(g39Frames));

    var g39Ingest = new PcapIngestService();
    var g39Tshark = new TsharkService(g39Ingest, new PcapExportService());

    async Task<int> LoadAsync(string? filter)
    {
        var doc = new PacketDocument { FilePath = g39Src };
        await g39Tshark.LoadPcapAsync(doc, g39Src, null, filter);
        return doc.Packets.Count;
    }

    int unfiltered = await LoadAsync(null);
    int onlyPfcp = await LoadAsync("pfcp");
    Report("DF-01 unfiltered load sees every frame", unfiltered == g39Frames.Length,
        $"loaded={unfiltered}, expected={g39Frames.Length}");
    Report("DF-02 display filter narrows the grid", onlyPfcp > 0 && onlyPfcp < unfiltered,
        $"filtered={onlyPfcp}, unfiltered={unfiltered}");
    Report("DF-03 filter selecting the only PFCP frame keeps exactly it", onlyPfcp == 1,
        $"filtered={onlyPfcp}");

    // Rows keep their original frame.number, which is what makes sparse indices safe.
    var g39Doc = new PacketDocument { FilePath = g39Src };
    await g39Tshark.LoadPcapAsync(g39Doc, g39Src, null, "pfcp");
    var g39Kept = g39Doc.Packets.Single();
    Report("DF-04 filtered row keeps its original frame number and bytes",
        g39Kept.PacketNumber == g39Frames.Length && g39Kept.RawData.AsSpan().SequenceEqual(g39Pfcp),
        $"number={g39Kept.PacketNumber}, bytesMatch={g39Kept.RawData.AsSpan().SequenceEqual(g39Pfcp)}");

    // Enum catalog: the PFCP tree carries integer fields whose PDML showname names
    // the value, so after dissection the field must carry at least one option.
    EnumCatalog.Reset();
    var g39Pkt = new Packet { Index = 0, Timestamp = 0, RawData = (byte[])g39Pfcp.Clone() };
    await g39Tshark.ParsePacketFromPcapFileAsync(g39Pkt, g39Src);
    var g39EnumFields = g39Pkt.Layers
        .SelectMany(l => l.Fields)
        .Concat(g39Pkt.Layers.SelectMany(l => Flatten(l.Fields)))
        .Where(f => f.HasEnumOptions)
        .ToList();
    Report("EN-01 enum catalog attaches options to numeric fields", g39EnumFields.Count > 0,
        $"fieldsWithOptions={g39EnumFields.Count}");

    var g39Named = g39EnumFields.FirstOrDefault(f => f.EnumOptions.Any(o => o.Label != f.DisplayValue));
    Report("EN-02 option label differs from the bare value it replaces",
        g39Named is not null,
        g39Named is null ? "no labeled enum field found"
                         : $"{g39Named.OriginalPdmlName}: {g39Named.EnumOptions[0].Label}");

    var g39Match = g39EnumFields.FirstOrDefault(f =>
        f.RawBytes.Length > 0 && f.EnumOptions.Any(o =>
            o.RawHex.Equals(Convert.ToHexString(f.RawBytes), StringComparison.OrdinalIgnoreCase)));
    Report("EN-03 current bytes resolve to one of the offered options", g39Match is not null,
        g39Match is null ? "no option matched the current bytes"
                         : $"{g39Match.OriginalPdmlName} matched");
}
catch (Exception ex)
{
    Report("G39 group execution", false, ex.ToString());
}
finally
{
    try { File.Delete(Path.Combine(Path.GetTempPath(), "pf-g39.pcap")); } catch { }
}

// ══ GROUP 40: TP-01..05 statistics taps ══
Banner(40, "statistics taps");
try
{
    var g40Src = Path.Combine(Path.GetTempPath(), "pf-g40.pcap");
    var g40Frames = new byte[30][];
    byte[] g40Udp = FixtureEth(FixtureIpv4(FixtureUdp(5000, 5001, new byte[] { 0x01, 0x02, 0x03, 0x04 })));
    for (int i = 0; i < g40Frames.Length - 1; i++) g40Frames[i] = g40Udp;
    g40Frames[g40Frames.Length - 1] = BuildSyntheticPfcpAssociationResponse();
    await File.WriteAllBytesAsync(g40Src, BuildFixturePcap(g40Frames));

    var g40Tshark = new TsharkService(new PcapIngestService(), new PcapExportService());

    var conv = await g40Tshark.RunStatisticsTapAsync(g40Src, "conv,udp");
    Report("TP-01 conv,udp returns output lines", conv.Count > 0, $"lines={conv.Count}");
    Report("TP-02 the Wireshark banner and ==== separators are stripped",
        conv.All(l => !l.StartsWith("Wireshark ") && !l.StartsWith("====")),
        $"first='{conv.FirstOrDefault()}'");
    Report("TP-03 a conversation row reports frame and byte counts",
        conv.Any(l => l.Contains("Frames") && l.Contains("Bytes")),
        string.Join(" | ", conv.Take(4)));

    // The filter belongs to the tap argument, not -Y: a tap post-filters nothing.
    var filtered = await g40Tshark.RunStatisticsTapAsync(g40Src, "conv,udp", "frame.number > 999999");
    Report("TP-04 tap-argument filter is accepted (tshark reports it, not \"No Filter\")",
        filtered.Any(l => l.StartsWith("Filter:")) && !filtered.Any(l => l.Contains("<No Filter>")),
        filtered.FirstOrDefault(l => l.StartsWith("Filter:")) ?? "no Filter: line");

    // io,phs is the protocol-hierarchy tap; a display filter must NOT be appended
    // because io,phs rejects the argument outright.
    var phs = await g40Tshark.RunStatisticsTapAsync(g40Src, "io,phs", "frame.number > 999999");
    Report("TP-05 io,phs ignores the filter instead of rejecting the tap",
        phs.Any(l => l.Contains("frames:")), $"lines={string.Join(" | ", phs.Take(3))}");

    var bad = await g40Tshark.RunStatisticsTapAsync(g40Src, "protocols");
    Report("TP-06 an invalid tap name yields no lines rather than throwing",
        bad.Count == 0, $"lines={bad.Count}");
}
catch (Exception ex)
{
    Report("G40 group execution", false, ex.ToString());
}
finally
{
    try { File.Delete(Path.Combine(Path.GetTempPath(), "pf-g40.pcap")); } catch { }
}

// ══ GROUP 41: NG-01..05 PCAPNG write-back round-trip ══
Banner(41, "PCAPNG writer round-trip");
try
{
    var g41Src = Path.Combine(Path.GetTempPath(), "pf-g41-in.pcap");
    var g41Out = Path.Combine(Path.GetTempPath(), "pf-g41-out.pcapng");
    var g41Frames = new byte[12][];
    byte[] g41Udp = FixtureEth(FixtureIpv4(FixtureUdp(5000, 5001, new byte[] { 0x0a, 0x0b, 0x0c, 0x0d })));
    for (int i = 0; i < g41Frames.Length - 1; i++) g41Frames[i] = g41Udp;
    g41Frames[g41Frames.Length - 1] = BuildSyntheticPfcpAssociationResponse();
    await File.WriteAllBytesAsync(g41Src, BuildFixturePcap(g41Frames));

    var g41Ingest = new PcapIngestService();
    var g41Export = new PcapExportService();
    var g41Read = await g41Ingest.ReadPacketsAsync(g41Src);

    var g41Doc = new PacketDocument { FilePath = g41Src };
    await g41Export.ExportAsync(g41Read.Packets.Select((p, i) => new Packet
    {
        Index = i,
        Timestamp = p.Timestamp,
        RawData = p.Data,
    }), new PacketExportOptions
    {
        OutputPath = g41Out,
        LinkLayerType = g41Read.LinkLayerType,
        Snaplen = g41Read.Snaplen,
        Pcapng = true,
    });

    byte[] g41Bytes = await File.ReadAllBytesAsync(g41Out);
    Report("NG-01 output starts with the PCAPNG section header block magic",
        g41Bytes.Length > 12 &&
        BitConverter.ToUInt32(g41Bytes, 0) == 0x0A0D0D0A &&
        BitConverter.ToUInt32(g41Bytes, 8) == 0x1A2B3C4D,
        $"len={g41Bytes.Length}, first={BitConverter.ToUInt32(g41Bytes, 0):X8}, bom={BitConverter.ToUInt32(g41Bytes, 8):X8}");

    var g41Back = await g41Ingest.ReadPacketsAsync(g41Out);
    Report("NG-02 the app's own reader reads it back as PCAPNG",
        g41Back.IsPcapNg, $"IsPcapNg={g41Back.IsPcapNg}");
    Report("NG-03 packet count survives the round-trip",
        g41Back.Packets.Count == g41Read.Packets.Count,
        $"in={g41Read.Packets.Count}, out={g41Back.Packets.Count}");
    Report("NG-04 every frame's bytes are byte-identical after the round-trip",
        g41Back.Packets.Count == g41Read.Packets.Count &&
        g41Back.Packets.Select((p, i) => p.Data.AsSpan().SequenceEqual(g41Read.Packets[i].Data)).All(x => x),
        "byte comparison over all frames");

    var g41Ts = new TsharkService(g41Ingest, g41Export);
    bool g41Parsed = await g41Ts.ParsePacketFromPcapFileAsync(
        new Packet { Index = 0, Timestamp = g41Back.Packets[0].Timestamp, RawData = g41Back.Packets[0].Data },
        g41Out);
    Report("NG-05 tshark dissects the written PCAPNG", g41Parsed, $"parsed={g41Parsed}");

    // Classic PCAP must stay classic: the format flag cannot leak into the default path.
    var g41Classic = Path.Combine(Path.GetTempPath(), "pf-g41-classic.pcap");
    await g41Export.ExportAsync(g41Read.Packets.Select((p, i) => new Packet
    {
        Index = i,
        Timestamp = p.Timestamp,
        RawData = p.Data,
    }), new PacketExportOptions
    {
        OutputPath = g41Classic,
        LinkLayerType = g41Read.LinkLayerType,
        Snaplen = g41Read.Snaplen,
    });
    var g41ClassicBack = await g41Ingest.ReadPacketsAsync(g41Classic);
    Report("NG-06 the default path still writes classic PCAP",
        !g41ClassicBack.IsPcapNg && g41ClassicBack.Packets.Count == g41Read.Packets.Count,
        $"IsPcapNg={g41ClassicBack.IsPcapNg}, packets={g41ClassicBack.Packets.Count}");

    // ns-declared export must round-trip microsecond timestamps precisely; the buggy
    // writer emitted µs values under a ns declaration, a 1000× wall-time error that
    // only shows when the file is re-read with its true resolution.
    var g41Ns = Path.Combine(Path.GetTempPath(), "pf-g41-ns.pcapng");
    await g41Export.ExportAsync(g41Read.Packets.Select((p, i) => new Packet
    {
        Index = i,
        Timestamp = p.Timestamp,
        RawData = p.Data,
    }), new PacketExportOptions
    {
        OutputPath = g41Ns,
        LinkLayerType = g41Read.LinkLayerType,
        Snaplen = g41Read.Snaplen,
        Pcapng = true,
        NanosecondResolution = true,
    });
    var g41NsBack = await g41Ingest.ReadPacketsAsync(g41Ns);
    Report("NG-07 ns-declared PCAPNG round-trips timestamps in microseconds, precisely",
        g41NsBack.Packets.Count == g41Read.Packets.Count &&
        g41NsBack.Packets.Select((p, i) => p.Timestamp == g41Read.Packets[i].Timestamp).All(x => x),
        $"first: in={g41Read.Packets[0].Timestamp}µs, out={g41NsBack.Packets[0].Timestamp}µs");

    try { File.Delete(g41Classic); } catch { }
    try { File.Delete(g41Ns); } catch { }
}
catch (Exception ex)
{
    Report("G41 group execution", false, ex.ToString());
}
finally
{
    try { File.Delete(Path.Combine(Path.GetTempPath(), "pf-g41-in.pcap")); } catch { }
    try { File.Delete(Path.Combine(Path.GetTempPath(), "pf-g41-out.pcapng")); } catch { }
}

// ══ GROUP 42: LC-01..08 length-changing edit (splice + compound) ══
Banner(42, "length-changing edit");
try
{
    var g42Src = Path.Combine(Path.GetTempPath(), "pf-g42.pcap");
    // A UDP payload of 4 bytes: the variable-width field tshark sizes by the buffer,
    // which is what makes a genuine insert possible.
    byte[] g42Frame = FixtureEth(FixtureIpv4(FixtureUdp(5000, 5001, new byte[] { 0x0a, 0x0b, 0x0c, 0x0d })));
    await File.WriteAllBytesAsync(g42Src, BuildFixturePcap(g42Frame));

    var g42Ingest = new PcapIngestService();
    var g42Export = new PcapExportService();
    var g42Tshark = new TsharkService(g42Ingest, g42Export);
    var g42Tx = new EditTransactionService(g42Export, g42Tshark);

    var g42Read = await g42Ingest.ReadPacketsAsync(g42Src);
    var g42Pkt = new Packet { Index = 0, Timestamp = g42Read.Packets[0].Timestamp, RawData = g42Read.Packets[0].Data };
    await g42Tshark.ParsePacketFromPcapFileAsync(g42Pkt, g42Src);
    int g42OrigLen = g42Pkt.EffectiveData.Length;

    var g42All = Flatten(g42Pkt.Layers.SelectMany(l => l.Fields)).ToList();
    var g42Len = g42All.FirstOrDefault(f => f.OriginalPdmlName == "udp.length");
    var g42IpLen = g42All.FirstOrDefault(f => f.OriginalPdmlName == "ip.len");
    var g42Payload = g42All.FirstOrDefault(f => f.OriginalPdmlName == "udp.payload");
    Report("LC-00 fixture exposes ip.len, udp.length and udp.payload",
        g42Len is not null && g42Payload is not null && g42IpLen is not null,
        $"ip.len={g42IpLen?.OriginalPdmlName}, udp.length={g42Len?.OriginalPdmlName}, payload={g42Payload?.OriginalPdmlName}");

    if (g42Len is not null && g42Payload is not null && g42IpLen is not null)
    {
        // Grow the payload by 3 and declare the new UDP length in the SAME transaction.
        // One at a time cannot work: the frame is malformed in between.
        byte[] g42NewPayload = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
        // udp.length is a 16-bit big-endian field, not a single byte.
        int g42OldLen = (g42Len.RawBytes[0] << 8) | g42Len.RawBytes[1];
        byte[] g42NewLen = ProtocolEditorService.ConvertRawValue(
            g42Len.Kind, (g42OldLen + 3).ToString(), g42Len.Length);

        // Every enclosing length has to move in the same transaction: IP total length,
        // then UDP length, then the payload bytes.
        int g42OldIpLen = (g42IpLen.RawBytes[0] << 8) | g42IpLen.RawBytes[1];
        byte[] g42NewIpLen = ProtocolEditorService.ConvertRawValue(
            g42IpLen.Kind, (g42OldIpLen + 3).ToString(), g42IpLen.Length);

        var g42Res = await g42Tx.CommitCompoundEditAsync(g42Pkt,
            [(g42Payload, g42NewPayload), (g42Len, g42NewLen), (g42IpLen, g42NewIpLen)],
            null, g42Read.LinkLayerType);

        Report("LC-01 compound edit (payload + both enclosing lengths) commits", g42Res.Success,
            $"Success={g42Res.Success} Reason={g42Res.Reason}");
        Report("LC-02 the frame is exactly three bytes longer",
            g42Pkt.EffectiveData.Length == g42OrigLen + 3,
            $"len={g42Pkt.EffectiveData.Length}, expected={g42OrigLen + 3}");
        Report("LC-03 both edited fields report their new bytes",
            g42Payload.RawBytes.Length == 7 && ((g42Len.RawBytes[0] << 8) | g42Len.RawBytes[1]) == g42OldLen + 3,
            $"payloadLen={g42Payload.RawBytes.Length}, udpLen={(g42Len.RawBytes[0] << 8) | g42Len.RawBytes[1]}, expected={g42OldLen + 3}");

        var g42Tmp = Path.Combine(Path.GetTempPath(), "pf-g42-out.pcap");
        await g42Export.SavePacketAsync(
            new Packet { Index = 0, Timestamp = g42Pkt.Timestamp, RawData = g42Pkt.EffectiveData },
            g42Tmp, g42Read.LinkLayerType);
        var g42Re = new Packet { Index = 0, Timestamp = g42Pkt.Timestamp, RawData = g42Pkt.EffectiveData };
        bool g42Parsed = await g42Tshark.ParsePacketFromPcapFileAsync(g42Re, g42Tmp);
        var g42RePayload = Flatten(g42Re.Layers.SelectMany(l => l.Fields))
            .FirstOrDefault(f => f.OriginalPdmlName == "udp.payload");
        Report("LC-04 tshark dissects the grown frame and sees the wider payload",
            g42Parsed && g42RePayload is not null && g42RePayload.RawBytes.Length == 7,
            $"parsed={g42Parsed}, payloadLen={g42RePayload?.RawBytes.Length}");
        try { File.Delete(g42Tmp); } catch { }

        // A payload grown WITHOUT its length field must be refused, not committed.
        var g42Pkt2 = new Packet { Index = 0, Timestamp = g42Read.Packets[0].Timestamp, RawData = g42Read.Packets[0].Data };
        await g42Tshark.ParsePacketFromPcapFileAsync(g42Pkt2, g42Src);
        var g42All2 = Flatten(g42Pkt2.Layers.SelectMany(l => l.Fields)).ToList();
        var g42Payload2 = g42All2.First(f => f.OriginalPdmlName == "udp.payload");
        byte[] g42Before = (byte[])g42Pkt2.EffectiveData.Clone();
        var g42Lone = await g42Tx.CommitCompoundEditAsync(g42Pkt2,
            [(g42Payload2, new byte[] { 1, 2, 3, 4, 5, 6, 7 })], null, g42Read.LinkLayerType);
        Report("LC-05 a payload grown without its length field is refused",
            !g42Lone.Success, $"Success={g42Lone.Success} Reason={g42Lone.Reason}");
        Report("LC-06 the refused edit leaves the frame byte-identical",
            g42Pkt2.EffectiveData.AsSpan().SequenceEqual(g42Before),
            $"unchanged={g42Pkt2.EffectiveData.AsSpan().SequenceEqual(g42Before)}");

        // An impossible splice must also leave the frame untouched.
        var g42Before3 = (byte[])g42Pkt.EffectiveData.Clone();
        var g42Huge = await g42Tx.CommitCompoundEditAsync(g42Pkt,
            [(g42Payload, new byte[512])], null, g42Read.LinkLayerType);
        Report("LC-07 an impossible splice aborts and leaves the frame untouched",
            !g42Huge.Success && g42Pkt.EffectiveData.AsSpan().SequenceEqual(g42Before3),
            $"Success={g42Huge.Success} unchanged={g42Pkt.EffectiveData.AsSpan().SequenceEqual(g42Before3)}");
    }
}
catch (Exception ex)
{
    Report("G42 group execution", false, ex.ToString());
}
finally
{
    try { File.Delete(Path.Combine(Path.GetTempPath(), "pf-g42.pcap")); } catch { }
}

// ══ GROUP 43: UH-01..07 undo/redo history ══
Banner(43, "undo/redo history");
try
{
    var g43 = new EditHistoryService();
    var g43Pkt = new Packet
    {
        Index = 3,
        RawData = new byte[] { 0x01, 0x02, 0x03, 0x04 },
    };

    Report("UH-01 a fresh history can neither undo nor redo",
        !g43.CanUndo && !g43.CanRedo, $"undo={g43.CanUndo}, redo={g43.CanRedo}");

    byte[] v0 = (byte[])g43Pkt.EffectiveData.Clone();
    g43Pkt.ApplyModification(1, new byte[] { 0xAA });
    g43.Record(g43Pkt.Index, g43Pkt.PacketNumber, v0, g43Pkt.EffectiveData, "edit 1");
    Report("UH-02 an edit makes the history undoable", g43.CanUndo && !g43.CanRedo,
        $"undo={g43.CanUndo}, redo={g43.CanRedo}");

    byte[] v1 = (byte[])g43Pkt.EffectiveData.Clone();
    g43Pkt.ApplyModification(2, new byte[] { 0xBB, 0xCC });
    g43.Record(g43Pkt.Index, g43Pkt.PacketNumber, v1, g43Pkt.EffectiveData, "edit 2");

    g43.Undo(g43Pkt);
    Report("UH-03 undo restores the intermediate state, not the original",
        g43Pkt.EffectiveData.AsSpan().SequenceEqual(v1) && !g43Pkt.EffectiveData.AsSpan().SequenceEqual(v0),
        $"bytes={Convert.ToHexString(g43Pkt.EffectiveData)}");

    g43.Undo(g43Pkt);
    Report("UH-04 a second undo reaches the original bytes",
        g43Pkt.EffectiveData.AsSpan().SequenceEqual(v0) && !g43Pkt.IsModified,
        $"bytes={Convert.ToHexString(g43Pkt.EffectiveData)}, modified={g43Pkt.IsModified}");

    g43.Redo(g43Pkt);
    Report("UH-05 redo replays the first edit",
        g43Pkt.EffectiveData.AsSpan().SequenceEqual(v1), $"bytes={Convert.ToHexString(g43Pkt.EffectiveData)}");

    g43.Redo(g43Pkt);
    Report("UH-06 redo replays the second edit",
        g43Pkt.EffectiveData.AsSpan().SequenceEqual(v1) is false &&
        Convert.ToHexString(g43Pkt.EffectiveData) == "01AABBCC",
        $"bytes={Convert.ToHexString(g43Pkt.EffectiveData)}");

    // A fresh edit must invalidate the redo branch.
    g43.Undo(g43Pkt);
    byte[] vNow = (byte[])g43Pkt.EffectiveData.Clone();
    g43Pkt.ApplyModification(0, new byte[] { 0xFF });
    g43.Record(g43Pkt.Index, g43Pkt.PacketNumber, vNow, g43Pkt.EffectiveData, "edit 3");
    Report("UH-07 a new edit discards the redo branch", !g43.CanRedo, $"redo={g43.CanRedo}");

    Report("UH-08 undo past the beginning is refused, not thrown",
        g43.Undo(g43Pkt) is not null && g43.Undo(g43Pkt) is not null && g43.Undo(g43Pkt) is null,
        "third undo returns null");

    // Capacity: the stack must not grow without bound.
    var g43Big = new EditHistoryService();
    for (int i = 0; i < EditHistoryService.Capacity + 50; i++)
        g43Big.Record(i, i + 1, new byte[] { 0x00 }, new byte[] { 0x01 }, $"e{i}");
    Report("UH-09 the stack is capped at its capacity",
        g43Big.UndoStack.Count == EditHistoryService.Capacity,
        $"count={g43Big.UndoStack.Count}, capacity={EditHistoryService.Capacity}");

    var g43Forget = new EditHistoryService();
    g43Forget.Record(7, 8, new byte[] { 0 }, new byte[] { 1 }, "a");
    g43Forget.Record(9, 10, new byte[] { 0 }, new byte[] { 1 }, "b");
    g43Forget.Forget(7);
    Report("UH-10 forgetting one packet leaves the other packet's history alone",
        g43Forget.UndoStack.Count == 1 && g43Forget.UndoStack[0].PacketIndex == 9,
        $"count={g43Forget.UndoStack.Count}");
}
catch (Exception ex)
{
    Report("G43 group execution", false, ex.ToString());
}

// ══ GROUP 44: FS-01..07 follow-stream index is exposed ══
Banner(44, "follow-stream index");
try
{
    var g44Src = Path.Combine(Path.GetTempPath(), "pf-g44.pcap");
    // Two TCP conversations on different ports, so the index must report two streams.
    byte[] g44Req = BuildTcpSegment(80, 1234, 1, 0, 0x18,
        System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n\r\n"));
    byte[] g44Req2 = BuildTcpSegment(80, 1234, 100, 200, 0x18,
        System.Text.Encoding.ASCII.GetBytes("GET /x HTTP/1.1\r\n\r\n"));
    byte[] g44Other = BuildTcpSegment(80, 5555, 1, 0, 0x18,
        System.Text.Encoding.ASCII.GetBytes("GET /y HTTP/1.1\r\n\r\n"));
    byte[] g44A = FixtureEth(FixtureIpv4(g44Req, 6, 1), 0x0800);
    byte[] g44A2 = FixtureEth(FixtureIpv4(g44Req2, 6, 2), 0x0800);
    byte[] g44B = FixtureEth(FixtureIpv4(g44Other, 6, 3), 0x0800);
    // One UDP conversation (same 5-tuple twice) — frames 4 and 5 of the fixture.
    byte[] g44U1 = FixtureEth(FixtureIpv4(FixtureUdp(5000, 5001, new byte[] { 1, 2, 3, 4 }), 17, 4), 0x0800);
    byte[] g44U2 = FixtureEth(FixtureIpv4(FixtureUdp(5000, 5001, new byte[] { 5, 6, 7, 8 }), 17, 5), 0x0800);
    await File.WriteAllBytesAsync(g44Src, BuildFixturePcap(g44A, g44A2, g44B, g44U1, g44U2));

    var g44Doc = new PacketDocument { FilePath = g44Src };
    var g44Tshark = new TsharkService(new PcapIngestService(), new PcapExportService());
    await g44Tshark.LoadPcapAsync(g44Doc, g44Src, null);

    var g44Provider = g44Doc.ContextProviders.OfType<TcpStreamContextProvider>().FirstOrDefault();
    Report("FS-00 the document carries a TCP stream provider", g44Provider is not null,
        g44Provider is null ? "missing" : g44Provider.Name);

    if (g44Provider is not null)
    {
        var g44Streams = await g44Provider.GetStreamsAsync();
        Report("FS-01 the stream index reports both conversations", g44Streams.Count == 2,
            $"streams={g44Streams.Count}");

        bool g44FramesLookRight = g44Streams.All(s => s.Frames.Count > 0)
            && g44Streams.Sum(s => s.Frames.Count) == 3;
        Report("FS-02 every frame is attributed to exactly one stream", g44FramesLookRight,
            $"totalFrames={g44Streams.Sum(s => s.Frames.Count)}");

        var g44First = g44Streams.OrderBy(s => s.Frames[0]).First();
        var g44Owner = await g44Provider.GetStreamOfFrameAsync(g44First.Frames[0]);
        Report("FS-03 a frame maps back to its own stream",
            g44Owner == g44First.StreamId, $"frame={g44First.Frames[0]}, owner={g44Owner}");

        var g44None = await g44Provider.GetStreamOfFrameAsync(9999);
        Report("FS-04 a frame that is not TCP maps to no stream", g44None is null, $"owner={g44None}");

        var g44UdpFrame = await g44Provider.GetStreamOfFrameAsync(4);
        Report("FS-05 the TCP index does not claim UDP frames", g44UdpFrame is null,
            $"owner={g44UdpFrame}");
    }

    var g44UdpProvider = g44Doc.ContextProviders.OfType<UdpStreamContextProvider>().FirstOrDefault();
    Report("FS-06 the document carries a UDP stream provider", g44UdpProvider is not null,
        g44UdpProvider is null ? "missing" : g44UdpProvider.Name);

    if (g44UdpProvider is not null)
    {
        var g44UdpStreams = await g44UdpProvider.GetStreamsAsync();
        var g44UdpOne = g44UdpStreams.Count == 1 ? g44UdpStreams[0] : null;
        Report("FS-07 the UDP index reports one conversation covering both UDP frames",
            g44UdpOne is not null
            && g44UdpOne.Protocol == "udp"
            && g44UdpOne.Frames.Count == 2
            && g44UdpOne.Frames.Contains(4) && g44UdpOne.Frames.Contains(5),
            g44UdpOne is null
                ? $"streams={g44UdpStreams.Count}"
                : $"protocol={g44UdpOne.Protocol}, frames=[{string.Join(",", g44UdpOne.Frames)}]");
    }
}
catch (Exception ex)
{
    Report("G44 group execution", false, ex.ToString());
}
finally
{
    try { File.Delete(Path.Combine(Path.GetTempPath(), "pf-g44.pcap")); } catch { }
}

// ══ GROUP 49: VL-01..07 VLAN tagging ══
Banner(49, "VLAN tagging");
try
{
    byte[] g49Ip = FixtureIpv4(FixtureUdp(5000, 5001, new byte[] { 1, 2, 3, 4 }));
    byte[] g49Plain = FixtureEth(g49Ip);

    Report("VL-00 the untagged fixture is Ethernet-II/IPv4 with the IP header at 14",
        PacketPrepareService.FindIpOffset(g49Plain) == 14,
        $"ipOffset={PacketPrepareService.FindIpOffset(g49Plain)}");

    byte[] g49Tagged = PacketPrepareService.ApplyVlanTag(g49Plain, 100);
    Report("VL-01 inserting a tag adds exactly four bytes", g49Tagged.Length == g49Plain.Length + 4,
        $"len={g49Tagged.Length}, was={g49Plain.Length}");
    Report("VL-02 the tag's TPID is 802.1Q and the VID reads back",
        ((ushort)((g49Tagged[12] << 8) | g49Tagged[13])) == 0x8100 &&
        (((g49Tagged[14] << 8) | g49Tagged[15]) & 0x0FFF) == 100,
        $"tpid=0x{((g49Tagged[12] << 8) | g49Tagged[13]):X4}, vid={((g49Tagged[14] << 8) | g49Tagged[15]) & 0x0FFF}");
    Report("VL-03 the inner ethertype survives tagging",
        ((ushort)((g49Tagged[16] << 8) | g49Tagged[17])) == 0x0800,
        $"inner=0x{((g49Tagged[16] << 8) | g49Tagged[17]):X4}");
    Report("VL-04 the IP header is found past the tag",
        PacketPrepareService.FindIpOffset(g49Tagged) == 18,
        $"ipOffset={PacketPrepareService.FindIpOffset(g49Tagged)}");
    Report("VL-05 the payload after the tag is byte-identical",
        g49Tagged.AsSpan(22).SequenceEqual(g49Plain.AsSpan(18)),
        "bytes after the tag match the original payload");

    // Replacing an existing tag keeps the length, so no offset downstream moves.
    byte[] g49Retag = PacketPrepareService.ApplyVlanTag((byte[])g49Tagged.Clone(), 200);
    Report("VL-06 replacing the VID keeps the frame length and moves the VID",
        g49Retag.Length == g49Tagged.Length &&
        (((g49Retag[14] << 8) | g49Retag[15]) & 0x0FFF) == 200,
        $"len={g49Retag.Length}, vid={((g49Retag[14] << 8) | g49Retag[15]) & 0x0FFF}");

    byte[] g49Stripped = PacketPrepareService.StripVlanTag(g49Tagged);
    Report("VL-07 stripping the tag restores the original frame byte-for-byte",
        g49Stripped.AsSpan().SequenceEqual(g49Plain),
        $"len={g49Stripped.Length}, identical={g49Stripped.AsSpan().SequenceEqual(g49Plain)}");

    Report("VL-08 stripping a frame that has no tag is a no-op",
        PacketPrepareService.StripVlanTag(g49Plain).AsSpan().SequenceEqual(g49Plain),
        "untouched");

    // 0x9100 is a third VLAN TPID. Detection, VID read, strip and retag must all treat it
    // the same as 0x8100/0x88A8 — the ethertype walk already did, but HasVlanTag,
    // GetVlanId, StripVlanTag and ApplyVlanTag did not.
    byte[] g49Tag9100 = Concat(g49Plain.AsSpan(0, 12).ToArray(), new byte[] { 0x91, 0x00 },
        U16(100, false), g49Plain.AsSpan(12).ToArray());
    Report("VL-11 a 0x9100-tagged frame is detected and its VID read back",
        PacketPrepareService.HasVlanTag(g49Tag9100) && PacketPrepareService.GetVlanId(g49Tag9100) == 100,
        $"tag={PacketPrepareService.HasVlanTag(g49Tag9100)}, vid={PacketPrepareService.GetVlanId(g49Tag9100)}");
    Report("VL-12 stripping a 0x9100 tag restores the plain frame",
        PacketPrepareService.StripVlanTag(g49Tag9100).AsSpan().SequenceEqual(g49Plain),
        "stripped == plain");
    byte[] g49Retag9100 = PacketPrepareService.ApplyVlanTag(g49Tag9100, 200);
    Report("VL-13 re-tagging a 0x9100 frame keeps the length (no double tag) and moves the VID",
        g49Retag9100.Length == g49Tag9100.Length && PacketPrepareService.GetVlanId(g49Retag9100) == 200,
        $"len={g49Retag9100.Length}, was={g49Tag9100.Length}, vid={PacketPrepareService.GetVlanId(g49Retag9100)}");

    // tshark must agree the tagged frame is VLAN with the right VID.
    try
    {
        var g49Src = Path.Combine(Path.GetTempPath(), "pf-g49.pcap");
        await File.WriteAllBytesAsync(g49Src, BuildFixturePcap(g49Tagged));
        var g49Tshark = new TsharkService(new PcapIngestService(), new PcapExportService());
        var g49Pkt = new Packet { Index = 0, Timestamp = 0, RawData = g49Tagged };
        await g49Tshark.ParsePacketFromPcapFileAsync(g49Pkt, g49Src);
        var g49All = Flatten(g49Pkt.Layers.SelectMany(l => l.Fields)).ToList();
        var g49Vlan = g49All.FirstOrDefault(f => f.OriginalPdmlName is "vlan.id" or "vlan.vid");
        int.TryParse(g49Vlan?.DisplayValue, out int g49Vid);
        Report("VL-09 tshark dissects the tag and reports the VID",
            g49Vlan is not null && g49Vid == 100,
            $"layers={string.Join(",", g49Pkt.Layers.Select(l => l.ProtocolName))}, " +
            $"field={g49Vlan?.OriginalPdmlName ?? "none"}, display={g49Vlan?.DisplayValue ?? "none"}");
        Report("VL-10 the tagged frame dissects to vlan between eth and ip",
            g49Pkt.Layers.Select(l => l.ProtocolName).ToList() is var g49Names &&
            g49Names.IndexOf("vlan") == g49Names.IndexOf("eth") + 1 &&
            g49Names.IndexOf("ip") == g49Names.IndexOf("vlan") + 1,
            $"order={string.Join(",", g49Pkt.Layers.Select(l => l.ProtocolName))}");
    }
    catch (Exception ex)
    {
        Report("VL-09 tshark dissects the tag and reports the VID", false, ex.ToString());
    }
}
catch (Exception ex)
{
    Report("G49 group execution", false, ex.ToString());
}
finally
{
    try { File.Delete(Path.Combine(Path.GetTempPath(), "pf-g49.pcap")); } catch { }
}

// Runs the headless UI render as the process's only job, invoked by `--ui`.
//
// Kept out of the main flow on purpose: initialising the Avalonia platform and Skia
// inside a process that then executes thousands of assertions and tshark round-trips
// crashes it, and a UI check that can take the whole harness down is worse than none.
int RunHeadlessRenderOnly()
{
    try
    {
    // through Skia with no X server and no GL, which turns "the XAML compiled" into
    // "the window rendered and these controls resolved".
    Banner(54, "headless render of the real window");
    try
    {
        try
        {
            AppBuilder.Configure<App>()
                .UseSkia()
                .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
                .SetupWithoutStarting();
        }
        catch (Exception ex)
        {
            Report("HG-01 the headless platform initialises", false, ex.ToString());
            throw;
        }

        string g54DockPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "ProtocolForge", "docklayout.json");
        byte[]? g54DockBackup = File.Exists(g54DockPath) ? File.ReadAllBytes(g54DockPath) : null;

        var g54Window = App.ComposeMainWindow(null);
        g54Window.Width = 1400;
        g54Window.Height = 900;
        g54Window.Show();

        // Headless has no compositor clock, so frames only appear when the platform's render
        // timer is ticked by hand; RunJobs alone never rasterises.
        for (int i = 0; i < 5; i++) Pump();

        Report("HG-02 the real window mounts and renders without throwing",
            g54Window.IsLoaded && g54Window.DataContext is MainWindowViewModel,
            $"IsLoaded={g54Window.IsLoaded}, dataContext={g54Window.DataContext?.GetType().Name ?? "null"}");

        var g54Vm = (MainWindowViewModel)g54Window.DataContext!;
        var g54Bar = g54Vm.ToolBar!;

        static T? ByName<T>(Visual root, string name) where T : Visual =>
            root.GetVisualDescendants().OfType<T>().FirstOrDefault(c => c.Name == name);

        static void Pump()
        {
            for (int i = 0; i < 3; i++)
            {
                Avalonia.Threading.Dispatcher.UIThread.RunJobs();
                AvaloniaHeadlessPlatform.ForceRenderTimerTick();
            }
        }

        bool g54StatsShownInitially = g54Vm.ShowStatistics;
        var g54Stats = ByName<ListBox>(g54Window, "StatisticsList");
        var g54Reasm = ByName<ListBox>(g54Window, "ReassembledList");

        // The statistics pane is hidden by default, and Dock materialises a pane's
        // content only while it is visible — so presence must track ShowStatistics
        // in both states, and showing it via the menu must realise both lists.
        bool g54PresenceTracksFlag =
            (g54Stats is not null) == g54Vm.ShowStatistics &&
            (g54Reasm is not null) == g54Vm.ShowStatistics;
        if (!g54Vm.ShowStatistics)
        {
            g54Vm.ToggleStatisticsCommand.Execute(null);
            Pump();
            g54Stats = ByName<ListBox>(g54Window, "StatisticsList");
            g54Reasm = ByName<ListBox>(g54Window, "ReassembledList");
        }
        bool g54Shown = g54Vm.ShowStatistics && g54Stats is not null && g54Reasm is not null;
        Report("HG-03 the statistics pane materialises when the View menu shows it",
            g54PresenceTracksFlag && g54Shown,
            $"defaultHidden={g54StatsShownInitially == false}, presenceMatchedFlag={g54PresenceTracksFlag}, shownAfterToggle={g54Shown}");

        // The regression a compiled-XAML check cannot catch: both lists sit in Grid.Row=1
        // and used to paint on top of each other.
        bool g54Initial = g54Stats is not null && g54Reasm is not null && g54Stats.IsVisible && !g54Reasm.IsVisible;
        g54Vm.ShowReassembled = true;
        Pump();
        bool g54Swapped = g54Stats is not null && g54Reasm is not null && !g54Stats.IsVisible && g54Reasm.IsVisible;
        g54Vm.ShowReassembled = false;
        Pump();
        bool g54Restored = g54Stats is not null && g54Reasm is not null && g54Stats.IsVisible && !g54Reasm.IsVisible;
        Report("HG-04 statistics and reassembled panels are mutually exclusive",
            g54Initial && g54Swapped && g54Restored,
            $"initial={g54Initial}, swapped={g54Swapped}, restored={g54Restored}");

        var g54VlanBox = ByName<TextBox>(g54Window, "VlanIdBox");
        g54Bar.VlanMode = PacketSendService.VlanMode.Insert;
        Pump();
        bool g54VlanShown = g54VlanBox is not null && g54VlanBox.IsVisible;
        g54Bar.VlanMode = PacketSendService.VlanMode.Leave;
        Pump();
        bool g54VlanHidden = g54VlanBox is not null && !g54VlanBox.IsVisible;
        Report("HG-05 the VLAN id box follows the VLAN mode",
            g54VlanShown && g54VlanHidden,
            $"shownOnInsert={g54VlanShown}, hiddenOnLeave={g54VlanHidden}");

        var g54VlanCombo = ByName<ComboBox>(g54Window, "VlanModeCombo");
        var g54VlanOptions = g54VlanCombo?.ItemsSource?.Cast<object>()
            .OfType<ToolBarViewModel.VlanModeOption>().ToList() ?? [];
        Report("HG-05a VLAN mode combo labels resolve from the localization dictionary",
            g54VlanOptions.Count == 4
            && g54VlanOptions[0].Label == LocalizationService.Resolve("Vlan.Mode.Leave")
            && g54VlanOptions[1].Label == LocalizationService.Resolve("Vlan.Mode.Insert")
            && g54VlanOptions[2].Label == LocalizationService.Resolve("Vlan.Mode.Replace")
            && g54VlanOptions[3].Label == LocalizationService.Resolve("Vlan.Mode.Remove"),
            $"count={g54VlanOptions.Count}, labels=[{string.Join(", ", g54VlanOptions.Select(o => o.Label))}]");

        var g54VlanLang = LocalizationService.CurrentLanguage;
        string g54VlanBefore = g54Bar.VlanModes[0].Label;
        LocalizationService.SetCurrent(g54VlanLang == AppLanguage.ZhCn ? AppLanguage.EnUs : AppLanguage.ZhCn);
        Pump();
        string g54VlanAfter = g54Bar.VlanModes[0].Label;
        LocalizationService.SetCurrent(g54VlanLang);
        Pump();
        Report("HG-05b VLAN mode combo labels follow a runtime language switch",
            g54Bar.VlanModes.Count == 4 && g54VlanAfter != g54VlanBefore,
            $"lang={g54VlanLang}, before=\"{g54VlanBefore}\", after=\"{g54VlanAfter}\"");

        var g54FixBox = ByName<CheckBox>(g54Window, "AutoFixCheckBox");
        var g54MultiBox = ByName<CheckBox>(g54Window, "MultiNicCheckBox");
        string g54FixText = g54FixBox?.Content as string ?? "";
        string g54MultiText = g54MultiBox?.Content as string ?? "";
        Report("HG-06 toolbar checkbox labels resolve from the localization dictionary",
            g54FixText.Length > 0 && g54MultiText.Length > 0
            && g54FixBox!.Bounds.Width > 40 && g54MultiBox!.Bounds.Width > 40,
            $"autoFix='{g54FixText}' ({g54FixBox?.Bounds.Width}px), multiNic='{g54MultiText}' ({g54MultiBox?.Bounds.Width}px)");

        g54Bar.MultiNicSend = true;
        Pump();
        bool g54MultiOn = g54MultiBox?.IsChecked == true;
        bool g54Targets = g54Bar.TargetInterfaces.Count > 0;
        g54Bar.MultiNicSend = false;
        Pump();
        bool g54MultiOff = g54MultiBox?.IsChecked == false;
        Report("HG-07 multi-NIC mode drives the checkbox and resolves targets",
            g54MultiOn && g54MultiOff && g54Targets,
            $"on={g54MultiOn}, off={g54MultiOff}, targets={g54Bar.TargetInterfaces.Count}");

        // Back to the pre-HG-03 visibility so the screenshot shows the default layout.
        if (g54StatsShownInitially != g54Vm.ShowStatistics)
        {
            g54Vm.ToggleStatisticsCommand.Execute(null);
            Pump();
        }

        Pump();
        var g54Frame = g54Window.CaptureRenderedFrame();
        Report("HG-08 the platform produced a rendered frame",
            g54Frame is not null,
            g54Frame is null ? "CaptureRenderedFrame returned null" : $"{g54Frame.PixelSize.Width}x{g54Frame.PixelSize.Height}");

        string g54Dir = Path.Combine(Path.GetTempPath(), "pf-g54");
        Directory.CreateDirectory(g54Dir);
        string g54Png = Path.Combine(g54Dir, "main-window.png");
        if (g54Frame is null)
        {
            Report("HG-09 the frame is rendered content, not a blank surface", false, "no frame captured");
            Report("HG-10 the capture saved as a real PNG", false, "no frame captured");
            return 0;
        }

        g54Frame.Save(g54Png, new PngBitmapEncoderOptions());

        int g54W = g54Frame.PixelSize.Width, g54H = g54Frame.PixelSize.Height;
        int g54Colors = 0;
        using (var g54Locked = g54Frame.Lock())
        {
            if (g54Locked is not null && g54Locked.Address != IntPtr.Zero)
            {
                var g54Bytes = new byte[g54Locked.RowBytes * g54H];
                System.Runtime.InteropServices.Marshal.Copy(g54Locked.Address, g54Bytes, 0, g54Bytes.Length);

                var g54Distinct = new HashSet<uint>();
                for (int y = 0; y < g54H; y++)
                {
                    int row = y * g54Locked.RowBytes;
                    for (int x = 0; x < g54W; x++)
                    {
                        int i = row + x * 4;
                        if (i + 3 < g54Bytes.Length)
                            g54Distinct.Add((uint)(g54Bytes[i] | (g54Bytes[i + 1] << 8) | (g54Bytes[i + 2] << 16)));
                    }
                }
                g54Colors = g54Distinct.Count;
            }
        }

        Report("HG-09 the frame is rendered content, not a blank surface",
            g54W > 800 && g54H > 500 && g54Colors > 16,
            $"{g54W}x{g54H}, distinctColors={g54Colors}");

        Report("HG-10 the capture saved as a real PNG",
            File.Exists(g54Png) && new FileInfo(g54Png).Length > 3000,
            $"{g54Png} ({new FileInfo(g54Png).Length} bytes)");

        Detail($"    headless render: {g54Png}");

        var g54TreeVm = g54Vm.ProtocolTree;
        g54TreeVm.Layers.Clear();
        var g54Layer = new ProtocolLayer { ProtocolName = "g54", DisplayText = "G54 reveal layer" };
        var g54FieldA = new ProtocolField { Name = "g54.field.a", DisplayValue = "first", ParentLayer = g54Layer };
        var g54FieldB = new ProtocolField { Name = "g54.field.b", DisplayValue = "second", ParentLayer = g54Layer };
        g54Layer.Fields.Add(g54FieldA);
        g54Layer.Fields.Add(g54FieldB);
        g54TreeVm.Layers.Add(g54Layer);
        g54TreeVm.IsEnabled = true;
        for (int i = 0; i < 6; i++) Pump();

        var g54Tree = ByName<TreeView>(g54Window, "ProtocolTree");
        g54TreeVm.SelectFieldOnTree(g54FieldA);
        for (int i = 0; i < 6; i++) Pump();
        var g54AfterA = g54Tree?.GetRealizedTreeContainers().OfType<TreeViewItem>()
            .Where(t => t.IsSelected).ToList() ?? [];

        Report("HG-11 the first reveal highlights the target node",
            g54AfterA.Count == 1 && ReferenceEquals(g54AfterA[0].DataContext, g54FieldA),
            $"selectedCount={g54AfterA.Count}");

        g54TreeVm.SelectFieldOnTree(g54FieldB);
        for (int i = 0; i < 6; i++) Pump();
        var g54AfterB = g54Tree?.GetRealizedTreeContainers().OfType<TreeViewItem>()
            .Where(t => t.IsSelected).ToList() ?? [];

        Report("HG-12 the second reveal leaves exactly one highlighted node",
            g54AfterB.Count == 1,
            $"selectedCount={g54AfterB.Count}, stale nodes would still be selected");
        Report("HG-13 the highlighted node is the second field",
            g54AfterB.Count == 1 && ReferenceEquals(g54AfterB[0].DataContext, g54FieldB),
            $"selected={g54AfterB.FirstOrDefault()?.DataContext?.ToString() ?? "none"}");

        g54TreeVm.LoadPacket(null);
        for (int i = 0; i < 3; i++) Pump();

        // ── HG-14/15: a closed pane must uncheck the View menu and stay re-openable.
        if (!g54Vm.ShowProtocolTree)
        {
            g54Vm.ToggleProtocolTreeCommand.Execute(null);
            Pump();
        }
        var g54Pane = g54Vm.Factory.Find(g54Vm.Layout!, d => d.Id == DockLayoutFactory.ProtocolTreeId)
            .OfType<PaneDock>().FirstOrDefault();

        g54Vm.Factory.CloseDockable(g54Pane!);
        Pump();
        bool g54HiddenAfterClose = g54Vm.Layout!.HiddenDockables?.Any(d => d.Id == DockLayoutFactory.ProtocolTreeId) == true;
        bool g54UncheckedAfterClose = !g54Vm.ShowProtocolTree;

        g54Vm.ToggleProtocolTreeCommand.Execute(null);
        Pump();
        var g54PaneBack = g54Vm.Factory.Find(g54Vm.Layout!, d => d.Id == DockLayoutFactory.ProtocolTreeId)
            .OfType<PaneDock>().FirstOrDefault();
        bool g54Reopened = g54PaneBack is not null && g54Vm.ShowProtocolTree;
        Report("HG-14 closing a pane unchecks the View menu and the menu re-opens it",
            g54Pane is not null && g54HiddenAfterClose && g54UncheckedAfterClose && g54Reopened
            && g54PaneBack?.Host is not null,
            $"hiddenAfterClose={g54HiddenAfterClose}, uncheckedAfterClose={g54UncheckedAfterClose}, reopened={g54Reopened}, host={(g54PaneBack?.Host is null ? "null" : "set")}");

        // A pane hidden in a restored docklayout.json used to keep Host == null, so the
        // pane DataTemplate (DataContext="{Binding Host}") rendered it blank on re-open.
        g54Vm.Factory.CloseDockable(g54PaneBack!);
        Pump();
        g54Vm.SaveLayout();
        Pump();

        var g54Window2 = App.ComposeMainWindow(null);
        g54Window2.Width = 1400;
        g54Window2.Height = 900;
        g54Window2.Show();
        for (int i = 0; i < 5; i++) Pump();
        var g54Vm2 = (MainWindowViewModel)g54Window2.DataContext!;
        var g54HiddenPane2 = g54Vm2.Layout!.HiddenDockables?.OfType<PaneDock>()
            .FirstOrDefault(d => d.Id == DockLayoutFactory.ProtocolTreeId);
        bool g54HostRestored = g54HiddenPane2 is not null && g54HiddenPane2.Host is not null;
        bool g54FlagHidden = !g54Vm2.ShowProtocolTree;

        g54Vm2.ToggleProtocolTreeCommand.Execute(null);
        for (int i = 0; i < 5; i++) Pump();
        bool g54Reopened2 = g54Vm2.ShowProtocolTree
            && g54Vm2.Factory.Find(g54Vm2.Layout!, d => d.Id == DockLayoutFactory.ProtocolTreeId).Any();
        bool g54ContentMaterialised = ByName<TreeView>(g54Window2, "ProtocolTree") is not null;
        Report("HG-15 a pane hidden across a restart keeps its Host and re-opens with content",
            g54HiddenPane2 is not null && g54HostRestored && g54FlagHidden && g54Reopened2 && g54ContentMaterialised,
            $"hiddenPaneFound={g54HiddenPane2 is not null}, hostRestored={g54HostRestored}, menuUnchecked={g54FlagHidden}, reopened={g54Reopened2}, content={g54ContentMaterialised}");

        g54Window2.Close();
        Pump();

        // Restore the pre-test visibility so the persisted layout is not left mutated.
        if (!g54Vm.ShowProtocolTree)
        {
            g54Vm.ToggleProtocolTreeCommand.Execute(null);
            Pump();
        }
        g54Vm.SaveLayout();
        Pump();

        // ── HG-18/19: the pin button parks a pane in RootDock.*PinnedDockables, which the
        // menu logic used to ignore; pinning must uncheck the menu, and the menu must re-home
        // every pinned pane into its own ToolDock — surviving a restart that persists the pin.
        // The pinned edge strip must also RENDER a real tab (a ToolPinItemControl with size),
        // gating the DockDensity.axaml ToolPinnedControl/DockTarget overrides of SukiUI.Dock 7.0.1
        // (upstream shipped an ItemsSource-less strip and a DockTarget without IndicatorDockOperation).
        static string G54HomeOf(string id) => id switch
        {
            DockLayoutFactory.PacketListId => DockLayoutFactory.TopDockId,
            DockLayoutFactory.ProtocolTreeId => DockLayoutFactory.TreeDockId,
            DockLayoutFactory.HexEditorId => DockLayoutFactory.HexDockId,
            _ => "",
        };
        static PaneDock? G54Pane(MainWindowViewModel vm, string id) =>
            vm.Factory.Find(vm.Layout!, d => d.Id == id).OfType<PaneDock>().FirstOrDefault();
        static bool G54Rehomed(MainWindowViewModel vm, string id) =>
            vm.Factory.Find(vm.Layout!, d => d.Id == G54HomeOf(id)).OfType<IDock>().FirstOrDefault()
                ?.VisibleDockables?.Any(d => d.Id == id) == true;
        string[] g54PinIds = [DockLayoutFactory.PacketListId, DockLayoutFactory.ProtocolTreeId, DockLayoutFactory.HexEditorId];

        foreach (var id in g54PinIds)
            g54Vm.Factory.PinDockable(G54Pane(g54Vm, id)!);
        Pump();
        for (int i = 0; i < 6; i++) { AvaloniaHeadlessPlatform.ForceRenderTimerTick(); Pump(); }
        bool g54AllPinned = g54PinIds.All(id => g54Vm.Layout!.LeftPinnedDockables?.Any(d => d.Id == id) == true);
        bool g54MenuUnchecked = !g54Vm.ShowPacketList && !g54Vm.ShowProtocolTree && !g54Vm.ShowHexEditor;
        static bool G54StripTabRendered(Visual v)
        {
            if (v is ToolPinItemControl tab && tab.IsVisible && tab.Bounds.Width > 0 && tab.Bounds.Height > 0)
                return true;
            foreach (var child in v.GetVisualChildren())
                if (G54StripTabRendered(child)) return true;
            return false;
        }
        bool g54StripTabRendered = G54StripTabRendered(g54Window);

        // HG-21: the auto-hide edge tab must be a real toggle. SukiUI.Dock 7.0.1's
        // ToolPinItemControl binds the tab to PreviewPinnedDockable (show-only), whereas the
        // upstream Fluent theme binds TogglePreviewPinnedDockable; DockDensity.axaml overrides
        // the tab back to the toggle. Executing the tab's command twice must return the pane
        // to its pinned-not-previewing state (leaving HG-18's rehome flow untouched).
        static ToolPinItemControl? G54FirstPinTab(Visual v)
        {
            if (v is ToolPinItemControl tab && tab.IsVisible && tab.Bounds.Width > 0 && tab.Bounds.Height > 0)
                return tab;
            foreach (var child in v.GetVisualChildren())
                if (G54FirstPinTab(child) is { } found) return found;
            return null;
        }
        var g54PinTab = G54FirstPinTab(g54Window);
        var g54PinTabBtn = g54PinTab?.GetVisualDescendants().OfType<Button>().FirstOrDefault();
        var g54PinTabDockable = g54PinTab?.DataContext;
        bool G54PinPreviewing() => g54PinTabDockable is null
            ? false
            : g54Vm.Layout!.PinnedDock?.VisibleDockables?.Contains(g54PinTabDockable) == true;
        bool g54TabCommandBound = g54PinTabBtn?.Command is not null;
        g54PinTabBtn?.Command?.Execute(g54PinTabBtn.CommandParameter);
        Pump();
        bool g54TabClickShows = G54PinPreviewing();
        g54PinTabBtn?.Command?.Execute(g54PinTabBtn.CommandParameter);
        Pump();
        bool g54TabClickHides = !G54PinPreviewing();
        Report("HG-21 the auto-hide edge tab toggles the preview (click shows, re-click hides)",
            g54TabCommandBound && g54TabClickShows && g54TabClickHides,
            $"tabFound={g54PinTab is not null}, tabBtn={g54PinTabBtn is not null}, commandBound={g54TabCommandBound}, clickShows={g54TabClickShows}, reClickHides={g54TabClickHides}");

        // HG-22: the edge tab must carry the localized context menu on the whole tab
        // (the Button), not just on the label (the TextBlock): SukiUI.Dock attaches the
        // menu to the TextBlock only, so a right-click on the tab strip outside the label
        // lands on the Command Button and bubbles to menu-less ancestors -- real-device
        // report. Assert the tab Button now owns the 3-item menu with all items visible.
        var g54TabMenu = g54PinTabBtn?.ContextMenu;
        var g54TabMenuItems = g54TabMenu?.Items.OfType<MenuItem>().ToList();
        bool g54TabMenuOk =
            g54PinTabBtn is not null &&
            g54TabMenu is not null &&
            g54TabMenuItems is not null && g54TabMenuItems.Count == 3 &&
            g54TabMenuItems.All(m => m.IsVisible);
        Report("HG-22 the edge tab's context menu covers the whole tab with 3 visible items",
            g54TabMenuOk,
            $"btn={g54PinTabBtn is not null}, menu={g54TabMenu is not null}, items=[{string.Join("|", (g54TabMenuItems ?? new List<MenuItem>()).Select(m => m.IsVisible))}]");

        g54Vm.TogglePacketListCommand.Execute(null);
        g54Vm.ToggleProtocolTreeCommand.Execute(null);
        g54Vm.ToggleHexEditorCommand.Execute(null);
        Pump();
        bool g54AllRehomed = g54PinIds.All(id => G54Rehomed(g54Vm, id));
        bool g54NonePinned = g54PinIds.All(id => g54Vm.Layout!.LeftPinnedDockables?.Any(d => d.Id == id) != true);
        bool g54MenuCheckedAgain = g54Vm.ShowPacketList && g54Vm.ShowProtocolTree && g54Vm.ShowHexEditor;
        bool g54HostsSet = g54PinIds.All(id => G54Pane(g54Vm, id)?.Host is not null);
        Report("HG-18 pinning panes unchecks the View menu, renders an edge tab, and the menu re-homes each into its own dock",
            g54AllPinned && g54MenuUnchecked && g54StripTabRendered && g54AllRehomed && g54NonePinned && g54MenuCheckedAgain && g54HostsSet,
            $"allPinned={g54AllPinned}, menuUnchecked={g54MenuUnchecked}, stripTabRendered={g54StripTabRendered}, allRehomed={g54AllRehomed}, nonePinned={g54NonePinned}, menuCheckedAgain={g54MenuCheckedAgain}, hosts={g54HostsSet}");

        // HG-24: SukiUI 7.0.1 的 SukiWindow 模板未包含 VisualLayerManager(标准 Window 模板内嵌),
        // 窗口树因此缺少 LightDismissOverlayLayer 宿主,所有浮层(ContextMenu/Flyout/ComboBox 下拉/
        // ToolTip)都无法「点击外部关闭」——实机报告 packet 列表右键菜单点哪儿都不消失。MainWindow
        // 内容外层已补 VisualLayerManager;断言浮层放置目标(DataGrid)确能解析到该层管理器。
        var g54GridMenuHost = ByName<DataGrid>(g54Window!, "PacketListView");
        if (g54GridMenuHost is not null)
            for (int i = 0; i < 3; i++) { AvaloniaHeadlessPlatform.ForceRenderTimerTick(); Pump(); }
        var g54LayerManager = g54GridMenuHost?.FindAncestorOfType<Avalonia.Controls.Primitives.VisualLayerManager>();
        Report("HG-24 the packet-list DataGrid resolves a VisualLayerManager (menus close on outside click)",
            g54LayerManager is not null,
            $"grid={g54GridMenuHost is not null}, layerManager={g54LayerManager is not null}");

        foreach (var id in g54PinIds)
            g54Vm.Factory.PinDockable(G54Pane(g54Vm, id)!);
        Pump();
        g54Vm.SaveLayout();
        Pump();

        var g54Window3 = App.ComposeMainWindow(null);
        g54Window3.Width = 1400;
        g54Window3.Height = 900;
        g54Window3.Show();
        for (int i = 0; i < 5; i++) Pump();
        var g54Vm3 = (MainWindowViewModel)g54Window3.DataContext!;
        bool g54PinnedRestored = g54PinIds.All(id => g54Vm3.Layout!.LeftPinnedDockables?.Any(d => d.Id == id) == true);
        bool g54RestartMenuUnchecked = !g54Vm3.ShowPacketList && !g54Vm3.ShowProtocolTree && !g54Vm3.ShowHexEditor;
        bool g54RestartHosts = g54PinIds.All(id =>
            g54Vm3.Layout!.LeftPinnedDockables?.OfType<PaneDock>().FirstOrDefault(d => d.Id == id)?.Host is not null);

        g54Vm3.TogglePacketListCommand.Execute(null);
        g54Vm3.ToggleProtocolTreeCommand.Execute(null);
        g54Vm3.ToggleHexEditorCommand.Execute(null);
        for (int i = 0; i < 5; i++) Pump();
        bool g54Rehomed3 = g54PinIds.All(id => G54Rehomed(g54Vm3, id))
            && g54Vm3.ShowPacketList && g54Vm3.ShowProtocolTree && g54Vm3.ShowHexEditor;
        bool g54Content3 = ByName<TreeView>(g54Window3, "ProtocolTree") is not null
            && ByName<Control>(g54Window3, "PacketListView") is not null;
        Report("HG-19 pinned panes survive a restart, stay menu-restorable and re-open with content",
            g54PinnedRestored && g54RestartMenuUnchecked && g54RestartHosts && g54Rehomed3 && g54Content3,
            $"pinnedRestored={g54PinnedRestored}, menuUnchecked={g54RestartMenuUnchecked}, hosts={g54RestartHosts}, rehomed={g54Rehomed3}, content={g54Content3}");

        g54Window3.Close();
        Pump();

        if (!g54Vm.ShowPacketList || !g54Vm.ShowProtocolTree || !g54Vm.ShowHexEditor)
        {
            if (!g54Vm.ShowPacketList) g54Vm.TogglePacketListCommand.Execute(null);
            if (!g54Vm.ShowProtocolTree) g54Vm.ToggleProtocolTreeCommand.Execute(null);
            if (!g54Vm.ShowHexEditor) g54Vm.ToggleHexEditorCommand.Execute(null);
            Pump();
        }
        g54Vm.SaveLayout();
        Pump();

        g54Vm.SaveLayout();
        Pump();

        // Avalonia's MenuItem.InputGesture is display-only, so the window must route these
        // itself; raising the real event proves the accelerators are wired, not just shown.
        var g54KeyZ = new KeyEventArgs { RoutedEvent = InputElement.KeyDownEvent, Key = Key.Z, KeyModifiers = KeyModifiers.Control };
        g54Window.RaiseEvent(g54KeyZ);
        var g54KeyF = new KeyEventArgs { RoutedEvent = InputElement.KeyDownEvent, Key = Key.F, KeyModifiers = KeyModifiers.Control };
        g54Window.RaiseEvent(g54KeyF);
        Pump();
        Report("HG-16 the window routes Ctrl+Z / Ctrl+F itself, so the menu shortcuts fire",
            g54KeyZ.Handled && g54KeyF.Handled,
            $"ctrlZ={g54KeyZ.Handled}, ctrlF={g54KeyF.Handled}");

        // ── HG-17: 基色切换必须真正作用到运行中的应用(ThemeService → SukiTheme)。──
        string g54OrigBase = ThemeService.CurrentBase;
        ThemeService.SetBase("Dark");
        Pump();
        // 断言 CurrentBase 已切换,且 SukiTheme.ChangeBaseTheme 已把请求变体写到
        // Application.RequestedThemeVariant(无头平台无 IPlatformSettings,默认解析为 Light,
        // 故 ChangeBaseTheme(Dark) 必然写入 RequestedThemeVariant=Dark)。
        bool g54BaseSwitched = ThemeService.CurrentBase == "Dark"
            && Application.Current?.RequestedThemeVariant == Avalonia.Styling.ThemeVariant.Dark;
        Report("HG-17 SetBase(\"Dark\") 切换持久化基色并作用到运行中的应用",
            g54BaseSwitched,
            $"currentBase={ThemeService.CurrentBase}, requestedVariant={Application.Current?.RequestedThemeVariant}");
        // 还原原基色:仅当确实发生切换时才触发持久化,不会泄漏 settings.json 副作用。
        ThemeService.SetBase(g54OrigBase);
        Pump();

        // ── HG-20: 拖动窗格 chrome 标题栏必须出现 DockTarget 停靠指示。───────────────
        // 根因(指示层宿主):SukiUI 7.0.1 的窗口模板删除了 VisualLayerManager(6.1.1 尚有)。
        // AdornerLayer 由窗口模板里的 VisualLayerManager 惰性创建——整个窗口树都没有它时
        // AdornerLayer.GetAdornerLayer(visual) 返回 null,AdornerHelper.AddRegularAdorner
        // 随即静默返回,DockTarget/GlobalDockTarget 永不挂载 → 拖动窗格无方向提示。
        // App.axaml.cs 以 UseFloatingDockAdorner=true 走 AddFloatingAdorner 分支,把指示器
        // 挂进以主窗为 owner 的顶层 DockAdornerWindow,绕开窗口树中缺失的 AdornerLayer。
        // 附带(DockDensity.axaml):chrome 头 PART_Grip 的 DataContext 由 ToolDock 改指
        // ActiveDockable(窗格),使拖拽源与 Fluent TabStrip 语义对齐;IToolDock:IDock:
        // IDockable 本就通过 ValidateLocal 源侧闸,故这是语义对齐而非指示器恢复的关键。
        // 无头模拟用户手势:按下 chrome 头 → 越过最小拖距 → 移到窗格本体 → 断言
        // DockTarget 挂载、五个方向选择器均已注册(DockOperation)、中心选择器为 Fill、
        // 主题为我们覆盖的 DockTarget、释放后指示器随浮动窗关闭移除。
        {
            // GripMode=AutoHide 下未悬停时 chrome 头整体折叠,没有可见的 PART_Grip——真实交互是
            // 「鼠标移到窗格顶部 1px 标题条 → 标题栏浮出 → 拖动重排」。先复现悬停那一步
            // (移到仍可见的 1px PART_Panel)让标题栏展开,再采集 grip 并拖动。
            var g54Strip = g54Window.GetVisualDescendants().OfType<Control>()
                .FirstOrDefault(c => c.Name == "PART_Panel" && c.IsVisible && c.Bounds.Width > 0
                    && c.FindAncestorOfType<ToolChromeControl>() is { } ch
                    && (ch.DataContext as IDock)?.ActiveDockable is PaneDock);
            if (g54Strip is not null
                && g54Strip.TranslatePoint(new Point(g54Strip.Bounds.Width / 2, g54Strip.Bounds.Height / 2), g54Window) is { } g54Hover)
            {
                g54Window.MouseMove(g54Hover, Avalonia.Input.RawInputModifiers.None);
                Pump();
            }
            Detail($"HG-20 hover-strip: {(g54Strip is null ? "absent" : "found")}");

            var g54AllGrips = g54Window.GetVisualDescendants().OfType<Control>()
                .Where(c => c.Name == "PART_Grip" && c.IsVisible && c.Bounds.Width > 0).ToList();
            var g54GripRow = g54AllGrips.Select(g =>
            {
                var ch = g.FindAncestorOfType<ToolChromeControl>();
                var dockable = (g.DataContext as IDockable ?? (ch?.DataContext as IDock)?.ActiveDockable as IDockable);
                return $"grip:{g.DataContext?.GetType().Name ?? "null"} ch:{ch?.DataContext?.GetType().Name ?? "null"} act:{dockable?.GetType().Name ?? "null"}";
            });
            Detail($"HG-20 grips({g54AllGrips.Count}): {string.Join(" | ", g54GripRow)}");
            var g54Grip = g54AllGrips.FirstOrDefault(g => g.DataContext is IDockable);

            Detail($"HG-20 grip ctx: {(g54Grip is null ? "absent" : g54Grip.DataContext is PaneDock gpd ? $"{gpd.Id}:{gpd.Title}" : g54Grip.DataContext?.GetType().Name ?? "null")}");

            bool g54GripIsDockable = g54Grip?.DataContext is PaneDock;
            string g54DragOut = "no-grip";
            if (g54Grip is not null)
            {
                var chrome = g54Grip.FindAncestorOfType<ToolChromeControl>();
                var g54Bodies = g54Window.GetVisualDescendants().OfType<ToolControl>()
                    .Where(t => t.IsVisible && t.Bounds.Width > 0).ToList();
                var ownBody = g54Bodies.FirstOrDefault(t => ReferenceEquals(chrome, t.FindAncestorOfType<ToolChromeControl>()))
                    ?? g54Bodies.FirstOrDefault();
                var targetChrome = g54Window.GetVisualDescendants().OfType<ToolChromeControl>()
                    .FirstOrDefault(c => c.IsVisible && !ReferenceEquals(c, chrome) && c.DataContext is not null);
                var targetBody = targetChrome is null ? null : g54Bodies.FirstOrDefault(t => ReferenceEquals(targetChrome, t.FindAncestorOfType<ToolChromeControl>()));

                if (chrome is not null && ownBody is not null && targetBody is not null
                    && g54Grip.TranslatePoint(new Point(g54Grip.Bounds.Width / 2, g54Grip.Bounds.Height / 2), g54Window) is { } gripCenter
                    && ownBody.TranslatePoint(new Point(ownBody.Bounds.Width / 2, ownBody.Bounds.Height / 2), g54Window) is { } bodyCenter
                    && targetBody.TranslatePoint(new Point(targetBody.Bounds.Width / 2, targetBody.Bounds.Height / 2), g54Window) is { } targetCenter)
                {
                    var g54DockLog = new List<string>();
                    bool g54PrevDiag = DockSettings.EnableDiagnosticsLogging;
                    Action<string>? g54PrevHandler = DockSettings.DiagnosticsLogHandler;
                    DockSettings.EnableDiagnosticsLogging = true;
                    DockSettings.DiagnosticsLogHandler = m => { lock (g54DockLog) g54DockLog.Add(m); };

                    g54Window.MouseDown(gripCenter, MouseButton.Left);
                    Pump();
                    foreach (var m in new[]
                    {
                        new Point(gripCenter.X, gripCenter.Y + 20),
                        new Point(gripCenter.X, gripCenter.Y + 44),
                        new Point(gripCenter.X - 16, gripCenter.Y + 72)
                    })
                    {
                        g54Window.MouseMove(m, Avalonia.Input.RawInputModifiers.LeftMouseButton);
                        Pump();
                    }
                    g54Window.MouseMove(targetCenter, Avalonia.Input.RawInputModifiers.LeftMouseButton); // 悬停另一窗格本体 → 本地停靠解析 + 指示层
                    Pump();

                    DockSettings.DiagnosticsLogHandler = g54PrevHandler;
                    DockSettings.EnableDiagnosticsLogging = g54PrevDiag;

                    IEnumerable<Visual> Hg20AllWindows()
                    {
                        // 浮动停靠指示(UseFloatingDockAdorner)把 DockTarget/GlobalDockTarget
                        // 放进以主窗口为 owner 的顶层 DockAdornerWindow,不能只扫主窗口树。
                        foreach (var v in g54Window.GetVisualDescendants())
                            yield return v;
                        foreach (var w in g54Window.OwnedWindows)
                        foreach (var v in w.GetVisualDescendants())
                            yield return v;
                    }

                    var g54Dock = g54Window.GetVisualDescendants().OfType<DockControl>().FirstOrDefault();
                    Detail($"HG-20 adorner: floating={DockSettings.UseFloatingDockAdorner} layer={(g54Dock is null ? "?" : Avalonia.Controls.Primitives.AdornerLayer.GetAdornerLayer(g54Dock)?.GetType().Name ?? "null")}");

                    var dt = Hg20AllWindows().OfType<DockTarget>().FirstOrDefault();
                    if (dt is null)
                    {
                        g54DragOut = "dt=absent";
                    }
                    else
                    {
                        var dtParts = dt.GetVisualDescendants().OfType<Control>().ToList();
                        var selOps = string.Join(" ",
                            dtParts.Where(c => c.Name is { } n && n.StartsWith("PART_", StringComparison.Ordinal) && n.EndsWith("Selector", StringComparison.Ordinal))
                                .Select(c => $"{c.Name!.Replace("PART_", "").Replace("Selector", "")}={DockProperties.GetIndicatorDockOperation(c)}"));
                        g54DragOut = $"ops=[{selOps}] theme={(dtParts.OfType<Image>().Any(i => i.Name == "PART_CenterSelector") ? "ours" : "stock")}";
                    }

                    g54Window.MouseMove(bodyCenter, Avalonia.Input.RawInputModifiers.LeftMouseButton); // 移回自身体:自停靠为全局 no-op
                    Pump();
                    g54Window.MouseUp(bodyCenter, MouseButton.Left); // 释放:不改变布局
                    Pump();
                    bool g54ReleasedGone = !Hg20AllWindows().Any(v => v is DockTarget or GlobalDockTarget);
                    g54DragOut += $" releasedGone={g54ReleasedGone}";

                    Detail($"HG-20 drag: {g54DragOut}");
                    Detail($"HG-20 docktrace: {string.Join(" | ", g54DockLog.TakeLast(24))}");
                }
            }

            bool g54GuidesShown = g54DragOut.StartsWith("ops=", StringComparison.Ordinal)
                && g54DragOut.Contains("Top=Top", StringComparison.Ordinal)
                && g54DragOut.Contains("Center=Fill", StringComparison.Ordinal)
                && g54DragOut.Contains("theme=ours", StringComparison.Ordinal)
                && g54DragOut.Contains("releasedGone=True", StringComparison.Ordinal);
            Report("HG-20 拖动窗格 chrome 标题栏显示停靠指示(五方向选择器已注册 + 指示器点亮 + 释放移除)",
                g54GripIsDockable && g54GuidesShown,
                $"gripIsDockable={g54GripIsDockable}; {g54DragOut}");
        }

        // HG-23: 关闭浮动窗口时,其中的面板必须移回主布局(PaneDock 不能随浮动根被丢弃成孤儿)。
        // 根因:Dock 关闭窗口会把面板 HideDockable 进「浮动根」的 HiddenDockables,随后 RemoveWindow
        // 丢弃整棵浮动根。修复:MainWindowViewModel 订阅 Factory.WindowClosing,在丢弃前把面板移回
        // 其 HomeDock。这里浮出 packet-list,再触发 WindowClosing,断言面板回到主布局可见树。
        if (G54Pane(g54Vm, DockLayoutFactory.PacketListId) is { } g54FloatPane)
        {
            bool g54HomeBefore = g54Vm.Factory.Find(g54Vm.Layout!, d => d.Id == DockLayoutFactory.TopDockId).OfType<IDock>().Any();
            g54Vm.Factory.FloatDockable(g54FloatPane);
            for (int i = 0; i < 5; i++) Pump();
            var g54FloatRoot = g54Vm.Factory.FindRoot(g54FloatPane);
            var g54FloatWin = g54FloatRoot?.Window;
            bool g54Floated = g54FloatWin is not null
                && !ReferenceEquals(g54FloatRoot, g54Vm.Layout)
                && g54Vm.Factory.Find(g54FloatRoot!, d => d.Id == DockLayoutFactory.PacketListId).Any()
                && !G54Rehomed(g54Vm, DockLayoutFactory.PacketListId);
            bool g54HomeAfterFloat = g54Vm.Factory.Find(g54Vm.Layout!, d => d.Id == DockLayoutFactory.TopDockId).OfType<IDock>().Any();
            bool g54CanClose = g54FloatWin is not null && g54Vm.Factory.OnWindowClosing(g54FloatWin);
            Pump();
            bool g54RehomedAfterClose = G54Rehomed(g54Vm, DockLayoutFactory.PacketListId);
            bool g54PaneInFloat = g54FloatRoot is not null && g54Vm.Factory.Find(g54FloatRoot, d => d.Id == DockLayoutFactory.PacketListId).Any();
            bool g54PaneAnywhereInMain = g54Vm.Factory.Find(g54Vm.Layout!, d => d.Id == DockLayoutFactory.PacketListId).Any();
            var g54MainOrder = g54Vm.Factory.Find(g54Vm.Layout!, d => d.Id == DockLayoutFactory.MainLayoutId)
                .OfType<IDock>().FirstOrDefault()?.VisibleDockables;
            bool g54TopRestored = g54MainOrder is { Count: >= 2 }
                && g54MainOrder[0].Id == DockLayoutFactory.TopDockId
                && g54MainOrder[1] is Dock.Model.Controls.IProportionalDockSplitter;
            Report("HG-23 closing a floating pane's window re-homes the pane instead of orphaning it",
                g54Floated && g54CanClose && g54RehomedAfterClose && g54TopRestored,
                $"floated={g54Floated}, canClose={g54CanClose}, rehomedAfterClose={g54RehomedAfterClose}, topRestored={g54TopRestored}, homeBefore={g54HomeBefore}, homeAfterFloat={g54HomeAfterFloat}, paneInFloat={g54PaneInFloat}, paneAnywhereInMain={g54PaneAnywhereInMain}");
        }
        else
        {
            Report("HG-23 closing a floating pane's window re-homes the pane instead of orphaning it",
                false, "packet-list pane not found in main layout");
        }

        // HG-25a/HG-25:菜单栏悬停切换。SukiUI 7.0.1 的 SukiTopLevelMenuItem 用 light-dismiss
        // 悬浮层(LightDismissOverlayLayer)实现「点击外部关闭」,靠 OverlayInputPassThroughElement
        // 决定哪些点穿透。原绑定是 $parent[MenuItem](仅当前打开项 A),但仅改绑定不足以修复:
        // 主窗口内容外层内联的 VisualLayerManager 位于 38px 标题栏之下,浮层坐标原点比窗口根偏
        // 39px,Avalonia 12.1.3 的 LightDismissOverlayLayer.HitTest 用窗口根坐标去调用
        // VisualRoot.InputHitTest 做穿透判定,拿到的却是层坐标 → 菜单栏上任何点都被判「不穿透」,
        // 浮层吞掉悬停兄弟项 B 的指针事件,PointerEnteredItemEvent 到不了 Menu,
        // DefaultMenuInteractionHandler 的悬停切换分支不执行 → 必须点两次。
        // 真正生效的修复是 App.axaml 的 PfTopLevelMenuItem 把 PART_Popup 的 IsLightDismissEnabled
        // 由 True 改为 False(顶层不再注册该浮层);OverlayInputPassThroughElement 语义上也改绑
        // $parent[Menu](与 Avalonia 默认 FluentTopLevelMenuItem 一致)。「点外部关闭」不依赖该浮层:
        // DefaultMenuInteractionHandler 用 TopLevel 上的 RootPointerPressed(tunnel)+
        // RawInput(NonClientLeftButtonDown)+WindowDeactivated 关闭 Menu(实机验证通过)。
        // HG-25a(结构断言,headless 可验、不打开浮层):顶层 popup 必须关闭 light-dismiss,
        // 且穿透元素为整条菜单栏,防回归。
        // HG-25(行为断言):真实点击 item0 打开下拉、悬停 item1 应一次切换。但 SukiUI 菜单
        // popup 在 headless 平台无法承载——`CreatePopupHost` 需要 IPopupImpl(Headless 无)
        // 或 EnablePopupOverlayLayer=true 的 VisualLayerManager(internal 属性,默认 false,
        // SukiWindow 模板无 VLM、内联 VLM 也无法从 XAML 置位)→ 打开即抛
        // InvalidOperationException,故行为断言在 headless 必然 SKIP,需实机验证;
        // HG-25a 是 headless 下的回归门禁。
        {
            var g54Menu = g54Window.GetVisualDescendants().OfType<Menu>().FirstOrDefault(m => m.Classes.Contains("main-menu"));
            var g54TopItems = g54Menu?.Items.OfType<MenuItem>().ToList() ?? new List<MenuItem>();
            var g54M0 = g54TopItems.FirstOrDefault();
            var g54M1 = g54TopItems.Skip(1).FirstOrDefault();
            var g54Popup = g54M0?.GetVisualDescendants().OfType<Avalonia.Controls.Primitives.Popup>().FirstOrDefault();
            string g54PassThrough = g54Popup?.OverlayInputPassThroughElement is null
                ? "none"
                : ReferenceEquals(g54Popup.OverlayInputPassThroughElement, g54Menu) ? "Menu"
                : ReferenceEquals(g54Popup.OverlayInputPassThroughElement, g54M0) ? "item0(自身,即原绑定)"
                : g54Popup.OverlayInputPassThroughElement.GetType().Name;
            bool g54PassThroughIsMenu = g54Popup is not null && ReferenceEquals(g54Popup.OverlayInputPassThroughElement, g54Menu);
            bool g54LightDismissOff = g54Popup is not null && !g54Popup.IsLightDismissEnabled;
            Report("HG-25a top-level submenu disables light-dismiss and targets the whole menu bar",
                g54PassThroughIsMenu && g54LightDismissOff,
                $"menu={g54Menu is not null}, items={g54TopItems.Count}, popup={g54Popup is not null}, passThrough={g54PassThrough}, lightDismiss={g54Popup?.IsLightDismissEnabled}");

            bool g54HoverSwitched = false;
            bool g54OpenBlocked = false;
            string g54BehaviorDetail = $"menu={g54Menu is not null}, items={g54TopItems.Count}";
            if (g54Menu is not null && g54M0 is not null && g54M1 is not null)
            {
                g54BehaviorDetail += " [" + string.Join(", ", g54TopItems.Select(i => $"'{i.Header}' {i.Bounds.Width}x{i.Bounds.Height}")) + "]";
                try
                {
                    if (g54M0.TranslatePoint(new Point(g54M0.Bounds.Width / 2, g54M0.Bounds.Height / 2), g54Window) is { } g54P0)
                    {
                        g54Window.MouseDown(g54P0, MouseButton.Left);
                        Pump();
                        g54Window.MouseUp(g54P0, MouseButton.Left);
                        Pump();
                    }
                }
                catch (InvalidOperationException)
                {
                    // headless 无法承载 SukiUI 菜单 popup(无 IPopupImpl / 无启用 popup 层的 VLM)。
                    g54OpenBlocked = true;
                }
                g54BehaviorDetail += $" | afterClick item0.Open={g54M0.IsSubMenuOpen} popup.Open={g54Popup?.IsOpen}";
                if (!g54OpenBlocked && g54M0.IsSubMenuOpen
                    && g54M1.TranslatePoint(new Point(g54M1.Bounds.Width / 2, g54M1.Bounds.Height / 2), g54Window) is { } g54P1)
                {
                    g54Window.MouseMove(g54P1, Avalonia.Input.RawInputModifiers.None);
                    Pump();
                    g54HoverSwitched = g54M1.IsSubMenuOpen && !g54M0.IsSubMenuOpen;
                    g54BehaviorDetail += $" | afterHover item0={g54M0.IsSubMenuOpen} item1={g54M1.IsSubMenuOpen}";
                }
            }
            if (g54OpenBlocked)
            {
                Skip("HG-25 hovering a sibling top-level item switches the open submenu",
                    "headless 无法承载 SukiUI 菜单 popup(无 IPopupImpl 且 EnablePopupOverlayLayer=false),行为验证需实机;HG-25a 结构断言为回归门禁");
            }
            else
            {
                Report("HG-25 hovering a sibling top-level item switches the open submenu (one hover, no second click)",
                    g54HoverSwitched,
                    g54BehaviorDetail);
            }
            // 清理:收拢可能仍打开的下拉,免得影响关闭后的后续断言。
            if (g54Menu is not null)
            {
                g54Menu.Close();
                Pump();
            }
        }

        // ── HG-26..HG-29b: 报文列表显示过滤器的真实交互验证。────────────────────
        // 无头平台同样走真实的 TextChanged → 去抖 → tshark 路径与真实键盘事件,
        // 因此断言的是运行中控件的类绑定(绿/红边框)与光标行为;引擎层由 GROUP 55 覆盖。
        {
            var g54FilterBox = ByName<TextBox>(g54Window, "FilterBox");
            Report("HG-26 the packet-list filter box is mounted",
                g54FilterBox is not null,
                g54FilterBox is null ? "FilterBox not found" : $"width={g54FilterBox.Bounds.Width}");

            if (g54FilterBox is not null)
            {
                // 真实等待:去抖(200/400ms)+ tshark 子进程都在真实时间轴上,
                // 必须在 Pump 之外真正睡一会儿,否则 continuation 永不回到 UI 线程。
                bool PumpUntil(Func<bool> cond, int timeoutMs)
                {
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    while (sw.ElapsedMilliseconds < timeoutMs)
                    {
                        Pump();
                        if (cond()) return true;
                        Thread.Sleep(25);
                    }
                    Pump();
                    return cond();
                }

                // 采样渲染帧里 FilterBox 边框区域的像素,确认绿/红边框真的画出来了。
                // 类名绑定 ≠ 视觉渲染:SukiUI 模板曾无视某些属性(App.axaml 中 ComboBox 的 Padding
                // 就因模板局部值而失效),所以类断言之外必须再验一次真实像素。
                (int NearA, int NearB, double MinA, double MinB) SampleColors(
                    Avalonia.Media.Imaging.WriteableBitmap? frame, (int R, int G, int B) cA, (int R, int G, int B) cB)
                {
                    if (frame is null) return (0, 0, double.MaxValue, double.MaxValue);
                    var origin = g54FilterBox.TranslatePoint(new Point(0, 0), g54Window) ?? new Point(-9999, -9999);
                    double scale = g54Window.RenderScaling <= 0 ? 1 : g54Window.RenderScaling;
                    int x0 = Math.Max(0, (int)Math.Floor((origin.X - 2) * scale));
                    int y0 = Math.Max(0, (int)Math.Floor((origin.Y - 2) * scale));
                    int x1 = Math.Min(frame.PixelSize.Width, (int)Math.Ceiling((origin.X + g54FilterBox.Bounds.Width + 2) * scale));
                    int y1 = Math.Min(frame.PixelSize.Height, (int)Math.Ceiling((origin.Y + g54FilterBox.Bounds.Height + 2) * scale));
                    int na = 0, nb = 0; double ma = double.MaxValue, mb = double.MaxValue;
                    using var fb = frame.Lock();
                    if (fb is null || fb.Address == IntPtr.Zero) return (0, 0, ma, mb);
                    var buf = new byte[fb.RowBytes * frame.PixelSize.Height];
                    System.Runtime.InteropServices.Marshal.Copy(fb.Address, buf, 0, buf.Length);
                    for (int y = y0; y < y1; y++)
                        for (int x = x0; x < x1; x++)
                        {
                            int i = y * fb.RowBytes + x * 4;
                            if (i + 2 >= buf.Length) continue;
                            int b = buf[i], g = buf[i + 1], r = buf[i + 2];
                            double da = Math.Sqrt((r - cA.R) * (r - cA.R) + (g - cA.G) * (g - cA.G) + (b - cA.B) * (b - cA.B));
                            double db = Math.Sqrt((r - cB.R) * (r - cB.R) + (g - cB.G) * (g - cB.G) + (b - cB.B) * (b - cB.B));
                            if (da < ma) ma = da;
                            if (db < mb) mb = db;
                            if (da < 80) na++;
                            if (db < 80) nb++;
                        }
                    return (na, nb, ma, mb);
                }

                // 诊断:把 TextBox → GlassCard → 三个 BorderPart 的 BorderBrush/可见性/透明度
                // 依次打印,定位绿框在哪一环丢失(样式 vs 模板链路 vs 主题分支)。
                void DumpBorderChain(string label)
                {
                    var sb = new System.Text.StringBuilder();
                    sb.Append($"{label}: TextBox.BorderBrush={g54FilterBox.BorderBrush}");
                    var glass = g54FilterBox.GetVisualDescendants()
                        .OfType<SukiUI.Controls.GlassCard>().FirstOrDefault();
                    if (glass is null)
                    {
                        sb.Append(" | GlassCard=<none>");
                    }
                    else
                    {
                        sb.Append($" | GlassCard(BorderBrush={glass.BorderBrush}, vis={glass.IsVisible})");
                        foreach (var bn in new[] { "PART_BorderCardLight", "PART_BorderCardDark", "PART_ClipBorder" })
                        {
                            var b = glass.GetVisualDescendants().OfType<Avalonia.Controls.Border>()
                                .FirstOrDefault(x => x.Name == bn);
                            sb.Append($" | {bn}({b?.BorderBrush}, vis={b?.IsVisible}, op={b?.Opacity})");
                        }
                    }
                    Detail(sb.ToString());
                }

                var g54Green = (R: 79, G: 175, B: 80);
                var g54Red = (R: 244, G: 67, B: 54);
                var g54Magenta = (R: 255, G: 0, B: 255);

                // 合法表达式 → 绿框(类 + 渲染像素双重确认)。
                g54Vm.FilterText = "frame.number == 1";
                bool g54ValidSettled = PumpUntil(() => g54Vm.IsFilterValid, 15000);
                Report("HG-27 a parseable filter turns the box green (filter-valid class)",
                    g54ValidSettled
                    && g54FilterBox.Classes.Contains("filter-valid")
                    && !g54FilterBox.Classes.Contains("filter-invalid"),
                    $"settled={g54ValidSettled}, valid={g54Vm.IsFilterValid}, "
                    + $"classes=[{string.Join(",", g54FilterBox.Classes)}], msg=\"{g54Vm.FilterValidationMessage}\"");

                for (int i = 0; i < 24; i++) { Pump(); Thread.Sleep(25); }
                var g54FbOrigin = g54FilterBox.TranslatePoint(new Point(0, 0), g54Window) ?? new Point(-9999, -9999);
                string g54GreenPng = Path.Combine(g54Dir, "filter-valid.png");
                var g54GreenFrame = g54Window.CaptureRenderedFrame();
                g54GreenFrame?.Save(g54GreenPng, new PngBitmapEncoderOptions());
                var g54GreenPx = SampleColors(g54GreenFrame, g54Green, g54Red);
                Detail($"HG-diag valid: borderBrush={g54FilterBox.BorderBrush}, thickness={g54FilterBox.BorderThickness}, "
                    + $"focused={g54FilterBox.IsFocused}, cls=[{string.Join(",", g54FilterBox.Classes)}]");
                Report("HG-27a the rendered filter border is green, not just the binding (border pixels)",
                    File.Exists(g54GreenPng) && g54GreenPx.NearA > 0 && g54GreenPx.NearB == 0,
                    $"{g54GreenPng}, rect={g54FbOrigin}({g54FilterBox.Bounds.Width}x{g54FilterBox.Bounds.Height})"
                    + $"@{g54Window.RenderScaling}x, nearGreen={g54GreenPx.NearA}, nearRed={g54GreenPx.NearB}, "
                    + $"minGreen={g54GreenPx.MinA:F1}, minRed={g54GreenPx.MinB:F1}");
                DumpBorderChain("HG-diag valid-chain");

                // 诊断探针:强制局部值(优先级高于样式 setter)确认 TextBox 模板是否真的渲染 BorderBrush。
                g54FilterBox.BorderBrush = Avalonia.Media.Brushes.Magenta;
                for (int i = 0; i < 12; i++) { Pump(); Thread.Sleep(25); }
                string g54MagentaPng = Path.Combine(g54Dir, "filter-forced-magenta.png");
                var g54MagentaFrame = g54Window.CaptureRenderedFrame();
                g54MagentaFrame?.Save(g54MagentaPng, new PngBitmapEncoderOptions());
                var g54MagentaPx = SampleColors(g54MagentaFrame, g54Magenta, g54Magenta);
                Report("HG-27b probe: a forced local BorderBrush is painted by the template",
                    g54MagentaPx.NearA > 0,
                    $"forced magenta local value → nearMagenta={g54MagentaPx.NearA}, minDist={g54MagentaPx.MinA:F1} ({g54MagentaPng})");
                g54FilterBox.ClearValue(Avalonia.Controls.Primitives.TemplatedControl.BorderBrushProperty);

                // 语法错误的表达式 → 红框(类 + 渲染像素双重确认)+ 原因文本。
                g54Vm.FilterText = "ip.src ==";
                bool g54InvalidSettled = PumpUntil(() => g54Vm.IsFilterInvalid, 15000);
                Report("HG-28 a syntax-error filter turns the box red with a reason (filter-invalid class)",
                    g54InvalidSettled
                    && g54FilterBox.Classes.Contains("filter-invalid")
                    && !g54FilterBox.Classes.Contains("filter-valid")
                    && !string.IsNullOrEmpty(g54Vm.FilterValidationMessage),
                    $"settled={g54InvalidSettled}, invalid={g54Vm.IsFilterInvalid}, "
                    + $"classes=[{string.Join(",", g54FilterBox.Classes)}], msg=\"{g54Vm.FilterValidationMessage}\"");

                for (int i = 0; i < 24; i++) { Pump(); Thread.Sleep(25); }
                string g54RedPng = Path.Combine(g54Dir, "filter-invalid.png");
                var g54RedFrame = g54Window.CaptureRenderedFrame();
                g54RedFrame?.Save(g54RedPng, new PngBitmapEncoderOptions());
                var g54RedPx = SampleColors(g54RedFrame, g54Green, g54Red);
                Detail($"HG-diag invalid: borderBrush={g54FilterBox.BorderBrush}, thickness={g54FilterBox.BorderThickness}, "
                    + $"focused={g54FilterBox.IsFocused}, cls=[{string.Join(",", g54FilterBox.Classes)}]");
                Report("HG-28a the rendered filter border turns red (border pixels, not just the class)",
                    File.Exists(g54RedPng) && g54RedPx.NearB > 0 && g54RedPx.NearA == 0,
                    $"{g54RedPng}, rect={g54FbOrigin}({g54FilterBox.Bounds.Width}x{g54FilterBox.Bounds.Height}), "
                    + $"nearGreen={g54RedPx.NearA}, nearRed={g54RedPx.NearB}, "
                    + $"minGreen={g54RedPx.MinA:F1}, minRed={g54RedPx.MinB:F1}");
                DumpBorderChain("HG-diag invalid-chain");

                g54FilterBox.BorderBrush = Avalonia.Media.Brushes.Magenta;
                for (int i = 0; i < 12; i++) { Pump(); Thread.Sleep(25); }
                string g54MagentaInvPng = Path.Combine(g54Dir, "filter-invalid-forced-magenta.png");
                var g54MagentaInvFrame = g54Window.CaptureRenderedFrame();
                g54MagentaInvFrame?.Save(g54MagentaInvPng, new PngBitmapEncoderOptions());
                var g54MagentaInvPx = SampleColors(g54MagentaInvFrame, g54Magenta, g54Magenta);
                Report("HG-28b probe: forced local magenta in the invalid state",
                    g54MagentaInvPx.NearA > 0,
                    $"nearMagenta={g54MagentaInvPx.NearA}, minDist={g54MagentaInvPx.MinA:F1} ({g54MagentaInvPng})");
                g54FilterBox.ClearValue(Avalonia.Controls.Primitives.TemplatedControl.BorderBrushProperty);

                // 自动补全数据路径:字段前缀 → 建议列表填充匹配的完整字段名。
                // Popup 的可视打开无法在无头平台断言——无宿主时其 IsOpen 双向绑定会被立即写回
                // false(与 HG-25 同类限制);可视打开与真实 Tab 采纳见 HG-29c 的实机 SKIP。
                g54Vm.FilterText = "frame.num";
                g54FilterBox.CaretIndex = (g54FilterBox.Text ?? string.Empty).Length;
                bool g54SuggestionsShown = PumpUntil(() => g54Vm.FilterSuggestions.Count > 0, 60000);
                Report("HG-29 typing a field prefix fills the autocomplete list with matching field names",
                    g54SuggestionsShown && g54Vm.FilterSuggestions.Contains("frame.number"),
                    $"count={g54Vm.FilterSuggestions.Count}, first3=[{string.Join(",", g54Vm.FilterSuggestions.Take(3))}], "
                    + $"openOnVm={g54Vm.IsFilterSuggestionOpen}");

                // 视图采纳路径 = ApplyFilterSuggestion(令牌替换),在真实 "frame.num" 令牌上驱动。
                g54Vm.ApplyFilterSuggestion("frame.number", 0, "frame.num".Length);
                Pump();
                Report("HG-29b accepting a suggestion replaces the token with the full field name",
                    g54FilterBox.Text == "frame.number" && !g54Vm.IsFilterSuggestionOpen,
                    $"text=\"{g54FilterBox.Text}\", open={g54Vm.IsFilterSuggestionOpen}");

                // 弹窗可视打开 + Tab 键采纳需要真实 popup 宿主,无头无法承载(同 HG-25)。
                Skip("HG-29c the popup opens on screen and Tab accepts the highlighted suggestion",
                    "headless 无法承载 Popup 宿主(IsOpen 双向绑定被立即写回 false),可视打开与 Tab 采纳需实机");

                // 复位,避免过滤文本泄漏进后续断言。
                g54Vm.FilterText = string.Empty;
                Pump();
            }
        }

        g54Window.Close();
        Pump();

        if (g54DockBackup is not null)
            File.WriteAllBytes(g54DockPath, g54DockBackup);
        else if (File.Exists(g54DockPath))
            File.Delete(g54DockPath);
    }
    catch (Exception ex)
    {
        Report("G54 group execution", false, ex.ToString());
    }
        return 0;
    }
    catch (Exception ex)
    {
        Report("G54 headless-only run", false, ex.ToString());
        return 1;
    }
}


// ══ GROUP 53: IF-01..04 multi-interface detection and trace-log naming ══
Banner(53, "multi-interface detection");
try
{
    string g53Dir = Path.Combine(Path.GetTempPath(), "pf-g53");
    Directory.CreateDirectory(g53Dir);
    try
    {
        // Two IDBs in one section: this is what a multi-adapter capture looks like.
        static byte[] EthIp(byte[] ip) =>
            [.. new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00 }, .. ip];

        var g53Ip = new byte[20];
        g53Ip[0] = 0x45; g53Ip[2] = 20; g53Ip[8] = 64; g53Ip[9] = 17;
        byte[] g53Frame = EthIp(g53Ip);

        byte[] OneIdb()
        {
            using var ms = new MemoryStream();
            using var w = new BinaryWriter(ms);
            void Shb(ushort maj, ushort min)
            {
                // type(4) len(4) magic(4) major(2) minor(2) section_len(8) len(4) = 28
                w.Write(0x0A0D0D0A); w.Write(28u); w.Write(0x1A2B3C4Du);
                w.Write(maj); w.Write(min);
                w.Write(unchecked((uint)-1L)); w.Write(0xFFFFFFFFu);
                w.Write(28u);
            }
            void Idb(ushort link)
            {
                // type(4) len(4) link(2) reserved(2) snaplen(4) len(4) = 20
                w.Write(0x00000001u); w.Write(20u); w.Write(link); w.Write((ushort)0);
                w.Write(65535u); w.Write(20u);
            }
            Shb(1, 0); Idb(1);
            return ms.ToArray();
        }

        byte[] TwoIdbs()
        {
            using var ms = new MemoryStream();
            using var w = new BinaryWriter(ms);
            void Shb()
            {
                w.Write(0x0A0D0D0A); w.Write(28u); w.Write(0x1A2B3C4Du);
                w.Write((ushort)1); w.Write((ushort)0);
                w.Write(unchecked((uint)-1L)); w.Write(0xFFFFFFFFu);
                w.Write(28u);
            }
            void Idb(ushort link)
            {
                w.Write(0x00000001u); w.Write(20u); w.Write(link); w.Write((ushort)0);
                w.Write(65535u); w.Write(20u);
            }
            void Epb(uint ifaceId)
            {
                int pad = (4 - g53Frame.Length % 4) % 4;
                uint len = 28u + (uint)g53Frame.Length + (uint)pad + 4u;
                w.Write(0x00000006u); w.Write(len); w.Write(ifaceId);
                w.Write(0u); w.Write(0u); w.Write((uint)g53Frame.Length); w.Write((uint)g53Frame.Length);
                w.Write(g53Frame);
                for (int i = 0; i < pad; i++) w.Write((byte)0);
                w.Write(len);
            }
            Shb(); Idb(1); Idb(1); Epb(0); Epb(1);
            return ms.ToArray();
        }

        string g53One = Path.Combine(g53Dir, "one.pcapng");
        string g53Two = Path.Combine(g53Dir, "two.pcapng");
        await File.WriteAllBytesAsync(g53One, OneIdb());
        await File.WriteAllBytesAsync(g53Two, TwoIdbs());

        var g53Svc = new PcapIngestService();
        var g53R1 = await g53Svc.ReadPacketsAsync(g53One);
        var g53R2 = await g53Svc.ReadPacketsAsync(g53Two);

        Report("IF-01 a single-IDB PCAPNG reports one interface",
            g53R1.IsPcapNg && g53R1.InterfaceCount == 1,
            $"isPcapNg={g53R1.IsPcapNg}, interfaces={g53R1.InterfaceCount}");

        Report("IF-02 a two-IDB PCAPNG reports two interfaces, so the caller can warn",
            g53R2.IsPcapNg && g53R2.InterfaceCount == 2,
            $"isPcapNg={g53R2.IsPcapNg}, interfaces={g53R2.InterfaceCount}");

        Report("IF-03 both IDB files still yield their packets and first link type",
            g53R1.Packets.Count == 0 && g53R2.Packets.Count == 2
            && g53R1.LinkLayerType == 1 && g53R2.LinkLayerType == 1,
            $"one={g53R1.Packets.Count} pkts, two={g53R2.Packets.Count} pkts, "
            + $"link={g53R1.LinkLayerType}/{g53R2.LinkLayerType}");

        // Classic PCAP has no IDB concept and must stay at the default so the save path
        // never mistakes it for a merged capture.
        string g53Pcap = Path.Combine(g53Dir, "classic.pcap");
        await File.WriteAllBytesAsync(g53Pcap, BuildFixturePcap([g53Frame]));
        var g53R3 = await g53Svc.ReadPacketsAsync(g53Pcap);
        Report("IF-04 classic PCAP reports one interface and no merge warning",
            !g53R3.IsPcapNg && g53R3.InterfaceCount == 1,
            $"isPcapNg={g53R3.IsPcapNg}, interfaces={g53R3.InterfaceCount}");

        Report("IF-05 the log name splits only when a sibling instance is alive",
            Path.GetFileName(TraceLog.LogFilePath) is string g53Name
            && (g53Name == "trace.log" || g53Name.StartsWith("trace.")),
            $"logFile={TraceLog.LogFilePath}");
    }
    catch (Exception ex)
    {
        Report("G53 group execution", false, ex.ToString());
    }
    finally
    {
        try { Directory.Delete(g53Dir, true); } catch { /* best-effort */ }
    }
}
catch (Exception ex)
{
    Report("G53 group execution", false, ex.ToString());
}

// ══ GROUP 52: SI-01..05 stream index invalidation semantics ══// ══ GROUP 52: SI-01..05 stream index invalidation semantics ══
// The rebuild is tied to save, not to edit. These assertions pin the tshark behaviour
// that decision rests on, so a future tshark change cannot quietly invalidate it.
Banner(52, "stream index invalidation semantics");
try
{
    string g52Dir = Path.Combine(Path.GetTempPath(), "pf-g52");
    Directory.CreateDirectory(g52Dir);
    try
    {
        // Three same-stream TCP segments: SYN, ACK, FIN.
        static byte[] Seg(int sp, int dp, byte flags, uint seq, byte[]? pad = null)
        {
            byte[] data = pad ?? [];
            var t = new byte[20 + data.Length];
            t[0] = (byte)(sp >> 8); t[1] = (byte)sp;
            t[2] = (byte)(dp >> 8); t[3] = (byte)dp;
            t[4] = (byte)(seq >> 24); t[5] = (byte)(seq >> 16); t[6] = (byte)(seq >> 8); t[7] = (byte)seq;
            t[12] = (byte)((5 << 4) | (data.Length >> 8)); t[13] = flags;
            data.CopyTo(t, 20);
            return t;
        }

        byte[][] Segs(int dport3, byte flags2, byte[] pad2, byte[] dst3)
        {
            byte[][] tcp =
            [
                Seg(1234, 4321, 0x02, 1000),
                Seg(1234, 4321, flags2, 1001, pad2),
                Seg(1234, dport3, 0x11, 2002),
            ];
            var frames = new byte[tcp.Length][];
            for (int i = 0; i < tcp.Length; i++)
            {
                var ip = new byte[20 + tcp[i].Length];
                ip[0] = 0x45;
                ip[2] = (byte)((20 + tcp[i].Length) >> 8); ip[3] = (byte)(20 + tcp[i].Length);
                ip[8] = 64; ip[9] = 6;
                ip[12] = 10; ip[14] = 1;
                ip[16] = dst3[0]; ip[17] = dst3[1]; ip[18] = dst3[2]; ip[19] = dst3[3];
                tcp[i].CopyTo(ip, 20);
                frames[i] = FixtureEth(ip);
            }
            return frames;
        }

        async Task<string> Streams(string name, byte[][] frames)
        {
            string path = Path.Combine(g52Dir, name);
            await File.WriteAllBytesAsync(path, BuildFixturePcap(frames));
            var svc = new TsharkService(new PcapIngestService(), new PcapExportService());
            var doc = new PacketDocument { FilePath = path };
            await svc.LoadPcapAsync(doc, path, null);
            var tcp = doc.ContextProviders.OfType<TcpStreamContextProvider>().First();
            var all = await tcp.GetStreamsAsync();
            string text = string.Join(",", all.Select(s => $"{s.StreamId}=[{string.Join("/", s.Frames)}]"));
            string single = "";
            try
            {
                // The same frame on its own: does it keep its capture-wide stream id?
                string solo = Path.Combine(g52Dir, name.Replace(".pcap", "-solo.pcap"));
                await File.WriteAllBytesAsync(solo, BuildFixturePcap([frames[1]]));
                var soloDoc = new PacketDocument { FilePath = solo };
                await svc.LoadPcapAsync(soloDoc, solo, null);
                var soloTcp = soloDoc.ContextProviders.OfType<TcpStreamContextProvider>().First();
                var soloAll = await soloTcp.GetStreamsAsync();
                single = string.Join(",", soloAll.Select(s => s.StreamId));
            }
            catch (Exception ex) { single = "err:" + ex.Message; }
            return text + " | solo=" + single;
        }

        string g52Base = await Streams("g52-base.pcap", Segs(4321, 0x10, [], [10, 0, 0, 2]));
        string g52Len = await Streams("g52-len.pcap", Segs(4321, 0x18, new byte[40], [10, 0, 0, 2]));
        string g52Port = await Streams("g52-port.pcap", Segs(7777, 0x10, [], [10, 0, 0, 2]));

        Report("SI-01 a payload-length edit leaves stream numbering untouched",
            g52Base == g52Len && g52Base.Contains("0=[1/2/3]"),
            $"base={g52Base} len={g52Len}");

        Report("SI-02 a four-tuple edit does move a frame to a new stream",
            g52Port.Contains("1=[3]") && !g52Base.Contains("1=[3]"),
            $"base={g52Base} port={g52Port}");

        // This is the fact the save-time rebuild rests on: a lone frame cannot report the
        // stream it belongs to, so the per-packet reparse an edit performs is useless here.
        string g52SoloBase = g52Base.Split("| solo=")[1];
        string g52SoloPort = g52Port.Split("| solo=")[1];
        Report("SI-03 a lone frame reports stream 0 whatever stream it really belongs to",
            g52SoloBase == "0" && g52SoloPort == "0",
            $"base-solo={g52SoloBase}, port-solo={g52SoloPort}");

        // Invalidate must actually force a re-read: overwrite the capture behind the
        // provider's closed-over path with a *different* stream layout and confirm the
        // next query sees it. Without a real rescan this would still report 0=[1/2/3].
        string g52Live = Path.Combine(g52Dir, "g52-live.pcap");
        await File.WriteAllBytesAsync(g52Live, BuildFixturePcap(Segs(4321, 0x10, [], [10, 0, 0, 2])));
        var g52Svc = new TsharkService(new PcapIngestService(), new PcapExportService());
        var g52Doc = new PacketDocument { FilePath = g52Live };
        await g52Svc.LoadPcapAsync(g52Doc, g52Live, null);
        var g52Prov = g52Doc.ContextProviders.OfType<TcpStreamContextProvider>().First();

        string g52Before = string.Join(",", (await g52Prov.GetStreamsAsync()).Select(s => s.StreamId + "=" + string.Join("/", s.Frames)));
        await File.WriteAllBytesAsync(g52Live, BuildFixturePcap(Segs(7777, 0x10, [], [10, 0, 0, 2])));
        string g52Cached = string.Join(",", (await g52Prov.GetStreamsAsync()).Select(s => s.StreamId + "=" + string.Join("/", s.Frames)));
        g52Prov.Invalidate();
        string g52After = string.Join(",", (await g52Prov.GetStreamsAsync()).Select(s => s.StreamId + "=" + string.Join("/", s.Frames)));

        Report("SI-04 the index is cached until invalidated, then re-read from disk",
            g52Before == "0=1/2/3"
            && g52Cached == g52Before                 // cache still serving the old file
            && g52After.Contains("1=3"),              // after Invalidate the new layout appears
            $"before={g52Before}, cached={g52Cached}, after={g52After}");
    }
    catch (Exception ex)
    {
        Report("G52 group execution", false, ex.ToString());
    }
    finally
    {
        try { Directory.Delete(g52Dir, true); } catch { /* best-effort */ }
    }
}
catch (Exception ex)
{
    Report("G52 group execution", false, ex.ToString());
}

// ══ GROUP 51: VW-01..06 VLAN reachability warning + non-mutating tag ops ══// ══ GROUP 51: VW-01..06 VLAN reachability warning + non-mutating tag ops ══
Banner(51, "VLAN warning and non-mutating tag ops");
try
{
    byte[] g51Eth = FixtureEth(FixtureIpv4(FixtureUdp(5000, 5001, new byte[] { 7, 7 })));
    byte[] g51Tagged = PacketPrepareService.ApplyVlanTag((byte[])g51Eth.Clone(), 100);

    // REGRESSION: EffectiveData hands out the live buffer, so a tag op that rewrote its
    // argument would change the packet as a side effect of merely sending it.
    var g51Packet = new Packet { Index = 0, Timestamp = 0, RawData = (byte[])g51Tagged.Clone() };
    byte[] g51Before = (byte[])g51Packet.EffectiveData.Clone();
    PacketPrepareService.ApplyVlanTag(g51Packet.EffectiveData, 200);
    Report("VW-01 re-tagging does not mutate the packet it was handed",
        g51Packet.EffectiveData.AsSpan().SequenceEqual(g51Before),
        $"vid now {PacketPrepareService.GetVlanId(g51Packet.EffectiveData)}, was 100");

    PacketPrepareService.StripVlanTag(g51Packet.EffectiveData);
    Report("VW-02 stripping does not mutate the packet it was handed",
        g51Packet.EffectiveData.AsSpan().SequenceEqual(g51Before),
        $"still tagged: {PacketPrepareService.HasVlanTag(g51Packet.EffectiveData)}");

    Report("VW-03 the new tag ops agree on whether a frame carries a tag",
        PacketPrepareService.HasVlanTag(g51Eth) == false
        && PacketPrepareService.HasVlanTag(g51Tagged) == true
        && PacketPrepareService.GetVlanId(g51Tagged) == 100
        && PacketPrepareService.GetVlanId(g51Eth) == -1,
        $"plain={PacketPrepareService.HasVlanTag(g51Eth)}, tagged={PacketPrepareService.GetVlanId(g51Tagged)}");

    // The warning must count only frames a VLAN mode would really change.
    var g51PlainOnly = new[] { new Packet { RawData = g51Eth } };
    var g51TaggedOnly = new[] { new Packet { RawData = g51Tagged } };
    Report("VW-04 Insert counts untagged frames and ignores already-tagged ones",
        PacketSendService.CountVlanAffected(g51PlainOnly, PacketSendService.VlanMode.Insert, 100) == 1
        && PacketSendService.CountVlanAffected(g51TaggedOnly, PacketSendService.VlanMode.Insert, 100) == 0,
        $"plain={PacketSendService.CountVlanAffected(g51PlainOnly, PacketSendService.VlanMode.Insert, 100)}, " +
        $"tagged={PacketSendService.CountVlanAffected(g51TaggedOnly, PacketSendService.VlanMode.Insert, 100)}");

    Report("VW-05 Replace counts a frame only when the VID actually changes",
        PacketSendService.CountVlanAffected(g51TaggedOnly, PacketSendService.VlanMode.Replace, 200) == 1
        && PacketSendService.CountVlanAffected(g51TaggedOnly, PacketSendService.VlanMode.Replace, 100) == 0,
        $"to200={PacketSendService.CountVlanAffected(g51TaggedOnly, PacketSendService.VlanMode.Replace, 200)}, " +
        $"to100={PacketSendService.CountVlanAffected(g51TaggedOnly, PacketSendService.VlanMode.Replace, 100)}");

    // Leave must never warn, and bare-IP packets have no header to tag.
    var g51Bare = new[] { new Packet { RawData = FixtureIpv4(FixtureUdp(5000, 5001, new byte[] { 7 })) } };
    Report("VW-06 Leave and bare-IP selections are both silent",
        PacketSendService.CountVlanAffected(g51TaggedOnly, PacketSendService.VlanMode.Leave, 100) == 0
        && PacketSendService.CountVlanAffected(g51Bare, PacketSendService.VlanMode.Insert, 100) == 0,
        $"leave={PacketSendService.CountVlanAffected(g51TaggedOnly, PacketSendService.VlanMode.Leave, 100)}, " +
        $"bareIp={PacketSendService.CountVlanAffected(g51Bare, PacketSendService.VlanMode.Insert, 100)}");
}
catch (Exception ex)
{
    Report("G51 group execution", false, ex.ToString());
}

// ══ GROUP 50: MN-01..05 multi-NIC fan-out ══// ══ GROUP 50: MN-01..05 multi-NIC fan-out ══
Banner(50, "multi-NIC fan-out");
try
{
    // Fan-out is the service's contract with the caller, so it is verified against
    // the real entry point the toolbar uses: a list of targets, not one target.
    var g50Lo = new NetworkInterfaceInfo("g50-lo", "g50-lo0", "loopback", null, null, null, true, true);
    var g50A = new NetworkInterfaceInfo("g50-a", "g50-a0", "nic a", IPAddress.Parse("192.0.2.1"), null, "02:00:00:00:00:01", false, true);
    var g50B = new NetworkInterfaceInfo("g50-b", "g50-b0", "nic b", IPAddress.Parse("198.51.100.1"), null, "02:00:00:00:00:02", false, true);

    var g50Svc = new PacketSendService();
    var g50Results = new List<PacketSendResult>();
    g50Svc.PacketSent += r => g50Results.Add(r);
    var g50Done = new TaskCompletionSource();
    g50Svc.SendCompleted += () => g50Done.TrySetResult();

    var g50Packet = new Packet
    {
        Index = 0,
        Timestamp = 0,
        RawData = FixtureEth(FixtureIpv4(FixtureUdp(5000, 5001, new byte[] { 9, 9 }))),
    };

    // No packets and no targets must both be inert: a send that cannot do anything
    // should finish and release the gate rather than hang or throw.
    await g50Svc.StartSendAsync(Array.Empty<Packet>(), g50A);
    Report("MN-01 an empty target list completes instead of throwing", true,
        $"completed={g50Done.Task.IsCompleted}");

    var g50Cts = new CancellationTokenSource();
    await g50Svc.StartSendAsync(new[] { g50Packet }, g50A, loopCount: 1, ct: g50Cts.Token);
    await g50Done.Task.WaitAsync(TimeSpan.FromSeconds(30));
    // SendPacketAsync reports exactly once per packet per target, so the result count
    // is the fan-out width — that is what makes these assertions non-vacuous.
    Report("MN-02 one packet on one target produces exactly one send attempt",
        g50Results.Count == 1,
        $"results={g50Results.Count} (want 1), first={(g50Results.Count > 0 ? g50Results[0].Message : "none")}");

    // Two targets, one packet: the packet must be offered to both, and the gate must be
    // released afterwards so a second send is possible.
    g50Results.Clear();
    var g50Done2 = new TaskCompletionSource();
    g50Svc.SendCompleted += () => g50Done2.TrySetResult();
    await g50Svc.StartSendAsync(new[] { g50Packet }, new[] { g50A, g50B }, loopCount: 1, ct: g50Cts.Token);
    await g50Done2.Task.WaitAsync(TimeSpan.FromSeconds(30));
    Report("MN-03 one packet on two targets produces two send attempts (true fan-out)",
        g50Results.Count == 2,
        $"results={g50Results.Count} (want 2)");
    Report("MN-03b both fan-out attempts carry the packet's index",
        g50Results.Count == 2 && g50Results.All(r => r.PacketIndex == 0),
        $"indices={string.Join(",", g50Results.Select(r => r.PacketIndex))}");

    var g50Done3 = new TaskCompletionSource();
    g50Svc.SendCompleted += () => g50Done3.TrySetResult();
    await g50Svc.StartSendAsync(new[] { g50Packet }, g50Lo, loopCount: 1, ct: g50Cts.Token);
    bool g50LoopbackReleased = await Task.WhenAny(g50Done3.Task, Task.Delay(15000)) == g50Done3.Task;
    Report("MN-04 an unusable target still completes and releases the gate",
        g50LoopbackReleased,
        $"completed={g50LoopbackReleased}");

    Report("MN-05 a second send is allowed after the previous one finished",
        !g50Svc.IsRunning,
        $"IsRunning={g50Svc.IsRunning}");
}
catch (Exception ex)
{
    Report("G50 group execution", false, ex.ToString());
}

// ══ GROUP 48: EP-01..04 egress adapter pinning ══// ══ GROUP 48: EP-01..04 egress adapter pinning ══
Banner(48, "egress adapter pinning");
try
{
    // Binding the source address does not choose the egress adapter: the kernel routes
    // by its own table. These assertions check that a managed socket really can be pinned
    // to the chosen adapter, and that the platform reports honestly when it cannot.
    var g48Ifaces = new NetworkInterfaceService().GetInterfaces();
    var g48Target = g48Ifaces.FirstOrDefault(i => !i.IsLoopback && i.IPv4Address != null);

    if (g48Target is null || !OperatingSystem.IsLinux())
    {
        Report("EP-00 a non-loopback adapter with an address is available to pin to",
            true, "skipped: needs Linux and a non-loopback adapter");
    }
    else
    {
        using var g48Sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        bool g48Pinned = TryPinForTest(g48Sock, g48Target.Name);
        Report("EP-01 SO_BINDTODEVICE accepts the chosen adapter", g48Pinned,
            $"device={g48Target.Name}, pinned={g48Pinned}");

        using var g48Bad = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        Report("EP-02 a non-existent adapter is rejected rather than silently accepted",
            !TryPinForTest(g48Bad, "pf-no-such-device0"),
            "pinning an unknown name must fail");

        Report("EP-03 AF_PACKET needs no pin because it selects per frame",
            System.Net.Sockets.AddressFamily.Packet != System.Net.Sockets.AddressFamily.InterNetwork,
            "AF_PACKET is a distinct address family, so the per-frame sockaddr_ll path is used instead of a pin");

        // Pinning is adapter-generic, so loopback pins too. Refusing to SEND on loopback
        // is a separate policy in ToolBarViewModel, asserted by G33-06.
        var g48Lo = g48Ifaces.FirstOrDefault(i => i.IsLoopback);
        using var g48Sock2 = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        Report("EP-04 pinning is adapter-generic (loopback pins as well; the send refusal is G33-06)",
            g48Lo is null || TryPinForTest(g48Sock2, g48Lo.Name),
            g48Lo is null ? "no loopback adapter present" : $"pinned {g48Lo.Name}");
    }
}
catch (Exception ex)
{
    Report("G48 group execution", false, ex.ToString());
}

// ══ GROUP 47: RV-01..06 reassembled stream bytes ══// ══ GROUP 47: RV-01..06 reassembled stream bytes ══
Banner(47, "reassembled stream bytes");
try
{
    var g47Src = Path.Combine(Path.GetTempPath(), "pf-g47.pcap");
    byte[] g47Body = System.Text.Encoding.ASCII.GetBytes(
        "HELLO-WORLD-THIS-IS-A-LONG-DIAMETER-MESSAGE-SPLIT-ACROSS-TCP-SEGMENTS");
    byte[] g47F1 = FixtureEth(FixtureIpv4(BuildTcpSegment(80, 1234, 1, 1, 0x18, g47Body[..20]), 6, 1), 0x0800);
    byte[] g47F2 = FixtureEth(FixtureIpv4(BuildTcpSegment(80, 1234, 21, 1, 0x18, g47Body[20..]), 6, 2), 0x0800);
    await File.WriteAllBytesAsync(g47Src, BuildFixturePcap(g47F1, g47F2));

    var g47Tshark = new TsharkService(new PcapIngestService(), new PcapExportService());

    // Only the second frame is dissected in the app; the first has to ride along for
    // tshark to reassemble, which is exactly the context-provider behaviour.
    var g47Doc = new PacketDocument { FilePath = g47Src };
    await g47Tshark.LoadPcapAsync(g47Doc, g47Src, null);

    var g47Bytes = await g47Tshark.GetReassembledStreamAsync(g47Src, "tcp", "0");
    Report("RV-00 the reassembled stream is returned as bytes", g47Bytes is not null,
        g47Bytes is null ? "null" : $"len={g47Bytes.Length}");
    Report("RV-01 reassembly recovers the whole message, not one segment",
        g47Bytes is not null && g47Bytes.Length == g47Body.Length,
        $"got={g47Bytes?.Length}, expected={g47Body.Length}");
    Report("RV-02 the reassembled bytes match the original payload",
        g47Bytes is not null && g47Bytes.AsSpan().SequenceEqual(g47Body),
        $"match={g47Bytes is not null && g47Bytes.AsSpan().SequenceEqual(g47Body)}");

    // The follow tap wraps at 32 columns; this payload is deliberately an odd length
    // (69), so a naive per-line decode would drop or misalign the tail byte.
    Report("RV-03 an odd-length payload survives the 32-column hex wrap intact",
        g47Body.Length % 2 == 1 && g47Bytes is not null && g47Bytes.Length == g47Body.Length,
        $"payloadLen={g47Body.Length}, reassembledLen={g47Bytes?.Length}");

    var g47Bad = await g47Tshark.GetReassembledStreamAsync(g47Src, "tcp", "99");
    Report("RV-04 an unknown stream yields nothing rather than throwing",
        g47Bad is null, $"len={g47Bad?.Length}");

    bool g47Threw = false;
    try { await g47Tshark.GetReassembledStreamAsync(g47Src, "sctp", "0"); }
    catch (ArgumentException) { g47Threw = true; }
    Report("RV-05 a protocol that cannot be followed is refused explicitly", g47Threw,
        "sctp throws ArgumentException");

    // http passes the follow gate but has no stream 99 — the tap returns nothing
    // rather than failing, same as RV-04 for tcp.
    byte[]? g47Http = null;
    bool g47HttpThrew = false;
    try { g47Http = await g47Tshark.GetReassembledStreamAsync(g47Src, "http", "99"); }
    catch (ArgumentException) { g47HttpThrew = true; }
    Report("RV-06 a followable protocol past the gate yields nothing for an unknown stream",
        !g47HttpThrew && g47Http is null, g47HttpThrew ? "threw" : $"len={g47Http?.Length}");
}
catch (Exception ex)
{
    Report("G47 group execution", false, ex.ToString());
}
finally
{
    try { File.Delete(Path.Combine(Path.GetTempPath(), "pf-g47.pcap")); } catch { }
}

// ══ GROUP 46: every advertised fence check is reachable ══// ══ GROUP 46: every advertised fence check is reachable ══
Banner(46, "all six fence checks are reachable");
try
{
    var g46Editor = new ProtocolEditorService();
    // Bytes 4..7 are 00 01 02 03 so the happy-path field below genuinely agrees
    // with the frame; an all-zero frame would make the last check fail correctly.
    var g46Bytes = new byte[32];
    g46Bytes[4] = 0; g46Bytes[5] = 1; g46Bytes[6] = 2; g46Bytes[7] = 3;
    var g46Packet = new Packet { Index = 0, RawData = g46Bytes };

    // 1. Unknown type.
    var g46Unknown = new ProtocolField { Name = "x", Kind = FieldKind.Unknown, Offset = 4, Length = 2 };
    var g46F1 = g46Editor.CheckTreeEditFence(g46Packet, g46Unknown);
    Report("FE-01 unknown type is refused", !g46F1.Allowed, g46F1.Reason);

    // 2. No byte span. This is the branch that used to be unreachable.
    var g46NoSpan = new ProtocolField { Name = "x", Kind = FieldKind.UInt, Offset = 4, Length = 0 };
    var g46F2 = g46Editor.CheckTreeEditFence(g46Packet, g46NoSpan);
    Report("FE-02 a zero-length field is refused with the no-byte-span reason",
        !g46F2.Allowed && g46F2.Reason.Contains("byte span", StringComparison.OrdinalIgnoreCase),
        $"allowed={g46F2.Allowed}, reason={g46F2.Reason}");

    var g46NegOffset = new ProtocolField { Name = "x", Kind = FieldKind.UInt, Offset = -1, Length = 2 };
    var g46F2b = g46Editor.CheckTreeEditFence(g46Packet, g46NegOffset);
    Report("FE-03 a negative offset is refused with the no-byte-span reason",
        !g46F2b.Allowed && g46F2b.Reason.Contains("byte span", StringComparison.OrdinalIgnoreCase),
        $"allowed={g46F2b.Allowed}, reason={g46F2b.Reason}");

    // 3. Bit-level.
    var g46Bits = new ProtocolField { Name = "x", Kind = FieldKind.UInt, Offset = 4, Length = 1, LengthBits = 3, RawBytes = new byte[] { 1 } };
    var g46F3 = g46Editor.CheckTreeEditFence(g46Packet, g46Bits);
    Report("FE-04 a bit-level field is refused", !g46F3.Allowed, g46F3.Reason);

    // 4. Out of frame.
    var g46Past = new ProtocolField { Name = "x", Kind = FieldKind.UInt, Offset = 30, Length = 8, RawBytes = new byte[8] };
    var g46F4 = g46Editor.CheckTreeEditFence(g46Packet, g46Past);
    Report("FE-05 a field running past the frame is refused", !g46F4.Allowed, g46F4.Reason);

    // 5. No byte evidence.
    var g46NoBytes = new ProtocolField { Name = "x", Kind = FieldKind.UInt, Offset = 4, Length = 4, RawBytes = [] };
    var g46F5 = g46Editor.CheckTreeEditFence(g46Packet, g46NoBytes);
    Report("FE-06 a field with no byte evidence is refused", !g46F5.Allowed, g46F5.Reason);

    // 6. Bytes disagree with the frame.
    var g46Disagree = new ProtocolField { Name = "x", Kind = FieldKind.UInt, Offset = 4, Length = 4, RawBytes = new byte[] { 9, 9, 9, 9 } };
    var g46F6 = g46Editor.CheckTreeEditFence(g46Packet, g46Disagree);
    Report("FE-07 bytes disagreeing with the frame is refused", !g46F6.Allowed, g46F6.Reason);

    // And the happy path still works.
    var g46Good = new ProtocolField { Name = "x", Kind = FieldKind.UInt, Offset = 4, Length = 4, RawBytes = new byte[] { 0, 1, 2, 3 } };
    var g46F7 = g46Editor.CheckTreeEditFence(g46Packet, g46Good);
    Report("FE-08 a well-formed field is still allowed", g46F7.Allowed, g46F7.Reason);

    // The relaxation must not have made the menu offer an editor for junk.
    Report("FE-09 an undecoded marker is never offered an editor",
        !new ProtocolField { Name = "x", Kind = FieldKind.UInt, Offset = 4, Length = 2, IsUndecodedMarker = true }.IsTreeEditable,
        "undecoded marker");
    Report("FE-10 a field with a valid type but no span IS offered, so the fence can explain",
        new ProtocolField { Name = "x", Kind = FieldKind.UInt, Offset = 4, Length = 0 }.IsTreeEditable,
        "the fence reports the precise reason instead of the menu hiding it");
}
catch (Exception ex)
{
    Report("G46 group execution", false, ex.ToString());
}

// ══ GROUP 45: the duplicate-layer predicate can actually fail ══// ══ GROUP 45: the duplicate-layer predicate can actually fail ══
Banner(45, "duplicate-layer predicate is not vacuous");
try
{
    // G14-05 is only worth having if it can fail. Feed the same predicate two layer
    // lists by hand: one healthy, one with a same-named pair collapsed onto a single
    // offset, which is the defect TR-03 guards against.
    static bool LayersAreDistinct(IEnumerable<ProtocolLayer> layers, Packet owner) =>
        layers.GroupBy(l => l.ProtocolName)
              .Where(g => g.Count() > 1)
              .All(g => g.Select(l => l.Offset).Distinct().Count() == g.Count())
        && layers.All(l => l.ParentPacket == owner);

    var g45Owner = new Packet { Index = 0, RawData = new byte[64] };
    var g45Healthy = new List<ProtocolLayer>
    {
        new ProtocolLayer { ProtocolName = "ip",   Offset = 14, ParentPacket = g45Owner },
        new ProtocolLayer { ProtocolName = "gtp",  Offset = 34, ParentPacket = g45Owner },
        new ProtocolLayer { ProtocolName = "ip",   Offset = 42, ParentPacket = g45Owner },
    };
    Report("NG-00 a healthy tunnelled layer list passes the predicate",
        LayersAreDistinct(g45Healthy, g45Owner),
        string.Join(",", g45Healthy.Select(l => $"{l.ProtocolName}@{l.Offset}")));

    var g45Collapsed = new List<ProtocolLayer>
    {
        new ProtocolLayer { ProtocolName = "ip",  Offset = 14, ParentPacket = g45Owner },
        new ProtocolLayer { ProtocolName = "gtp", Offset = 34, ParentPacket = g45Owner },
        new ProtocolLayer { ProtocolName = "ip",  Offset = 14, ParentPacket = g45Owner },
    };
    Report("NG-01 the predicate rejects a collapsed duplicate offset",
        !LayersAreDistinct(g45Collapsed, g45Owner),
        "both ip layers share offset 14");

    var g45Orphan = new List<ProtocolLayer>
    {
        new ProtocolLayer { ProtocolName = "ip",  Offset = 14, ParentPacket = g45Owner },
        new ProtocolLayer { ProtocolName = "gtp", Offset = 34, ParentPacket = null },
    };
    Report("NG-02 the predicate rejects a layer with no owning packet",
        !LayersAreDistinct(g45Orphan, g45Owner),
        "gtp layer has ParentPacket=null");
}
catch (Exception ex)
{
    Report("G45 group execution", false, ex.ToString());
}

static bool TryPinForTest(Socket sock, string device)
{
    try
    {
        byte[] name = System.Text.Encoding.ASCII.GetBytes(device + "\0");
        return SetsockoptBytesForTest((int)sock.Handle, 1, 25, name, name.Length) == 0;
    }
    catch { return false; }
}

[DllImport("libc", EntryPoint = "setsockopt", SetLastError = true)]
static extern int SetsockoptBytesForTest(int fd, int level, int name, byte[] value, int len);

// ── G12–G32 helpers (hoisted local functions) ──
// Frame 4413 carries PFCP so the fence, VBC and address-extraction groups walk a
// dissection-rich tree with editable leaves rather than an empty payload. The
// fillers are ordinary UDP so the file is not 4413 copies of the same IE layout,
// which would let a repeated-container defect hide.
static byte[] BuildGeneratedCaptureFixture()
{
    var frames = new byte[RequiredCaptureFrames][];
    byte[] filler = FixtureEth(FixtureIpv4(FixtureUdp(5000, 5001, new byte[] { 0x01, 0x02, 0x03, 0x04 })));
    for (int i = 0; i < RequiredCaptureFrames - 1; i++)
        frames[i] = filler;
    frames[RequiredCaptureFrames - 1] = BuildSyntheticPfcpAssociationResponse();
    return BuildFixturePcap(frames);
}

static byte[] BuildFixturePcap(params byte[][] frames)
{
    using var ms = new MemoryStream();
    using var bw = new BinaryWriter(ms);
    bw.Write(0xA1B2C3D4u); bw.Write((ushort)2); bw.Write((ushort)4);
    bw.Write(0); bw.Write(0); bw.Write(65535); bw.Write((uint)1);
    for (int i = 0; i < frames.Length; i++)
    {
        bw.Write(i); bw.Write(0);
        bw.Write(frames[i].Length); bw.Write(frames[i].Length);
        bw.Write(frames[i]);
    }
    return ms.ToArray();
}

// A Device-Watchdog Request carrying two AVPs (Origin-Host, Origin-Realm), wrapped in
// the same SCTP DATA-chunk + PPID 46 transport tshark keys its Diameter dissector on.
// Two AVPs make tshark emit avp_raw/avp_tree twice each as duplicate JSON keys — the
// exact shape that made the surplus-twin pass append a phantom third AVP row.
static byte[] BuildSyntheticDiameterDwr()
{
    static byte[] Avp(int code, string val)
    {
        var body = System.Text.Encoding.ASCII.GetBytes(val);
        // RFC 6733 4.1: every AVP is padded up to a 4-byte boundary and the declared AVP
        // Length INCLUDES that padding. Declaring the unpadded length desynchronises the
        // next AVP, and tshark then rejects the message and dissects the payload as raw
        // data - which is why the old fixed single pad byte only ever worked for value
        // lengths where 8+len happened to land 1 short of a boundary.
        int padBytes = (4 - (body.Length & 3)) & 3;
        int len = 8 + body.Length + padBytes;
        return Concat(new byte[] { (byte)(code >> 24), (byte)(code >> 16), (byte)(code >> 8), (byte)code },
                      new byte[] { 0x40 },
                      new byte[] { (byte)(len >> 16), (byte)(len >> 8), (byte)len },
                      body, new byte[padBytes]);
    }

    byte[] a1 = Avp(264, "pf-nms-01.node.epc.mnc001.mcc001.3gppnetwork.org");
    byte[] a2 = Avp(296, "node.epc.mnc001.mcc001.3gppnetwork.org");
    int total = 20 + a1.Length + a2.Length;
    byte[] id = { 0x01, 0x95, 0x49, 0x9d };
    byte[] dwr = Concat(new byte[] { 0x01 },
                        new byte[] { (byte)(total >> 16), (byte)(total >> 8), (byte)total },
                        new byte[] { 0x80 },
                        new byte[] { 0x00, 0x01, 0x18 },
                        new byte[] { 0, 0, 0, 0 },
                        id, id, a1, a2);

    byte[] dataChunk = Concat(new byte[] { 0x00, 0x03 },
                              U16(16 + dwr.Length, false),
                              U32(0, false), U16(0, false), U16(46740, false), U32(46, false), dwr);
    byte[] sctp = Concat(U16(10114, false), U16(5014, false),
                         new byte[] { 0xa0, 0x85, 0x49, 0xa6 }, new byte[4], dataChunk);

    // 地址用 FixtureIpv4 默认的私有段，夹具里不写真实公网 IP。
    return FixtureEth(FixtureIpv4(sctp, 132, 0x1234, 0));
}

static byte[] BuildSyntheticPfcpAssociationResponse()
{
    byte[] pfcp = Concat(
        new byte[] { 0x20, 0x06, 0x00, 0x24, 0x00, 0x00, 0x01, 0x00 },
        U16(60, false), U16(5, false), new byte[] { 0x00, 127, 0, 0, 1 },
        U16(19, false), U16(1, false), new byte[] { 0x4C },
        U16(96, false), U16(4, false), new byte[4],
        U16(43, false), U16(6, false), new byte[] { 0x01, 0, 0, 0, 0, 0 });

    return FixtureEth(FixtureIpv4(
        FixtureUdp(8805, 8805, pfcp),
        17,
        0x1234,
        0x4000,
        "192.0.2.1",
        "192.0.2.2"));
}

static byte[] FixtureEth(byte[] payload, ushort etherType = 0x0800) =>
    Concat(new byte[] { 0x02, 0, 0, 0, 0, 1, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB },
           U16(etherType, false), payload);

static byte[] FixtureIpv4(byte[] payload, byte proto = 17, ushort id = 1, ushort frag = 0,
                          string src = "10.0.0.1", string dst = "10.0.0.2")
{
    byte[] Src(string a) => a.Split('.').Select(byte.Parse).ToArray();
    return Concat(
        new byte[] { 0x45, 0x00 }, U16((ushort)(20 + payload.Length), false),
        U16(id, false), U16(frag, false),
        new byte[] { 64, proto, 0, 0 }, Src(src), Src(dst), payload);
}

static byte[] FixtureUdp(ushort sport, ushort dport, byte[] payload) =>
    Concat(U16(sport, false), U16(dport, false), U16((ushort)(8 + payload.Length), false),
           U16(0, false), payload);

static byte[] BuildTcpSegment(ushort sport, ushort dport, uint seq, uint ack, byte flags, byte[] payload) =>
    Concat(U16(sport, false), U16(dport, false), U32(seq, false), U32(ack, false),
           new byte[] { 0x50, flags }, U16(0x4000, false), U16(0, false), U16(0, false), payload);

static async Task<IReadOnlyList<string>> RunTsharkFieldsAsync(
    string tsharkPath, string capture, string filter, IReadOnlyList<string> fields)
{
    var psi = new System.Diagnostics.ProcessStartInfo
    {
        FileName = tsharkPath,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
    };
    psi.ArgumentList.Add("-r"); psi.ArgumentList.Add(capture);
    psi.ArgumentList.Add("-Y"); psi.ArgumentList.Add(filter);
    psi.ArgumentList.Add("-T"); psi.ArgumentList.Add("fields");
    foreach (var f in fields) { psi.ArgumentList.Add("-e"); psi.ArgumentList.Add(f); }
    using var proc = System.Diagnostics.Process.Start(psi)!;
    string stdout = await proc.StandardOutput.ReadToEndAsync();
    await proc.WaitForExitAsync();
    return stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
}

static IEnumerable<Packet> ThrowAfterFirst(IEnumerable<Packet> packets)
{
    foreach (var packet in packets)
        yield return packet;

    throw new IOException("synthetic export failure");
}

static IEnumerable<ProtocolField> Flatten(IEnumerable<ProtocolField> fields) =>
    fields.SelectMany(f => new[] { f }.Concat(Flatten(f.Children)));

static bool IsAggregateAlias(string pdmlName)
{
    string part = pdmlName.Contains('.') ? pdmlName[(pdmlName.LastIndexOf('.') + 1)..] : pdmlName;
    return part is "addr" or "host" or "port" or "src_host" or "dst_host";
}

static byte[] Concat(params byte[][] parts)
{
    int total = 0;
    foreach (var p in parts) total += p.Length;
    var result = new byte[total];
    int off = 0;
    foreach (var p in parts) { Buffer.BlockCopy(p, 0, result, off, p.Length); off += p.Length; }
    return result;
}

static string BytesHex(byte[] b) => Convert.ToHexString(b);

static bool BytesEq(byte[] a, byte[] b) => a.AsSpan().SequenceEqual(b);

static byte[] U16(int value, bool littleEndian) => littleEndian
    ? new byte[] { (byte)value, (byte)(value >> 8) }
    : new byte[] { (byte)(value >> 8), (byte)value };

static byte[] U32(uint value, bool littleEndian) => littleEndian
    ? new byte[] { (byte)value, (byte)(value >> 8), (byte)(value >> 16), (byte)(value >> 24) }
    : new byte[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value };

static byte[] ClassicHeader(bool nanoSeconds, bool littleEndian, int linkType = 1, int snaplen = 65535)
{
    byte[] magic = (nanoSeconds, littleEndian) switch
    {
        (false, true) => new byte[] { 0xD4, 0xC3, 0xB2, 0xA1 },  // LE µs
        (false, false) => new byte[] { 0xA1, 0xB2, 0xC3, 0xD4 },  // BE µs
        (true, true) => new byte[] { 0x4D, 0x3C, 0xB2, 0xA1 },    // LE ns
        (true, false) => new byte[] { 0xA1, 0xB2, 0x3C, 0x4D },   // BE ns
    };
    return Concat(magic,
        U16(2, littleEndian), U16(4, littleEndian),
        U32(0, littleEndian), U32(0, littleEndian),
        U32((uint)snaplen, littleEndian), U32((uint)linkType, littleEndian));
}

static byte[] ClassicRecord(long tsMicros, byte[] data, bool nanoSeconds, bool littleEndian)
{
    long tsSec = tsMicros / 1_000_000;
    long frac = nanoSeconds ? (tsMicros % 1_000_000) * 1000L : tsMicros % 1_000_000;
    return Concat(
        U32((uint)tsSec, littleEndian), U32((uint)frac, littleEndian),
        U32((uint)data.Length, littleEndian), U32((uint)data.Length, littleEndian),
        data);
}

static byte[] MkShb(bool littleEndian = true, ushort versionMajor = 1, ushort versionMinor = 0)
{
    const uint total = 28;
    return Concat(
        U32(0x0A0D0D0Au, littleEndian), U32(total, littleEndian),
        U32(0x1A2B3C4Du, littleEndian),
        U16(versionMajor, littleEndian), U16(versionMinor, littleEndian),
        U32(0xFFFFFFFF, littleEndian), U32(0xFFFFFFFF, littleEndian),
        U32(total, littleEndian));
}

static byte[] MkIdb(int linkType, int snaplen, bool littleEndian = true, int? tsresol = null)
{
    int total = tsresol.HasValue ? 28 : 20;
    var parts = new List<byte[]>
    {
        U32(1, littleEndian), U32((uint)total, littleEndian),
        U16(linkType, littleEndian), U16(0, littleEndian),
        U32((uint)snaplen, littleEndian),
    };
    if (tsresol.HasValue)
        parts.Add(Concat(U16(9, littleEndian), U16(1, littleEndian), new byte[] { (byte)tsresol.Value, 0, 0, 0 }));
    parts.Add(U32((uint)total, littleEndian));
    return Concat(parts.ToArray());
}

static byte[] MkEpb(long tsMicros, byte[] data, bool littleEndian = true)
{
    int pad = (4 - (data.Length % 4)) % 4;
    uint total = (uint)(32 + data.Length + pad);
    return Concat(
        U32(6, littleEndian), U32(total, littleEndian),
        U32(0, littleEndian),
        U32((uint)((ulong)tsMicros >> 32), littleEndian), U32((uint)tsMicros, littleEndian),
        U32((uint)data.Length, littleEndian),
        new byte[4], data,
        pad > 0 ? new byte[pad] : Array.Empty<byte>(),
        U32(total, littleEndian));
}

static byte[] MkSpb(uint origLen, byte[] data, bool littleEndian = true)
{
    uint total = (uint)(16 + data.Length);
    return Concat(
        U32(3, littleEndian), U32(total, littleEndian),
        U32(origLen, littleEndian), data,
        U32(total, littleEndian));
}

static int FoldSum(byte[] data, int offset, int len)
{
    long sum = 0;
    int i = offset, end = offset + len;
    while (i + 1 < end) { sum += (data[i] << 8) | data[i + 1]; i += 2; }
    if (i < end) sum += data[i] << 8;
    while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return (int)sum;
}

static byte[] Pseudo4(byte[] frame, int srcOff, int dstOff, int proto, int len) =>
    Concat(frame.AsSpan(srcOff, 4).ToArray(), frame.AsSpan(dstOff, 4).ToArray(),
        new byte[] { 0, (byte)proto }, U16(len, false));

static byte[] Pseudo6(byte[] frame, int srcOff, int dstOff, int proto, int len) =>
    Concat(frame.AsSpan(srcOff, 16).ToArray(), frame.AsSpan(dstOff, 16).ToArray(),
        U32((uint)len, false), new byte[] { 0, 0, 0, (byte)proto });

static int CountFields(IReadOnlyList<ProtocolField> fields, out int bitCount)
{
    bitCount = 0;
    int total = 0;
    foreach (var f in fields)
    {
        total++;
        if (f.LengthBits >= 0) bitCount++;
        int childBits;
        total += CountFields(f.Children, out childBits);
        bitCount += childBits;
    }
    return total;
}

static async Task<(int Sent, int Failed, string LastMsg, int TotalSent, bool Done)> RunSendAsync(
    PacketSendService svc, IReadOnlyList<Packet> packets, NetworkInterfaceInfo iface)
{
    int sent = 0, failed = 0;
    string lastMsg = "";
    bool done = false;
    svc.PacketSent += res => { if (res.Success) sent++; else failed++; lastMsg = res.Message; };
    svc.SendCompleted += () => done = true;
    await svc.StartSendAsync(packets, iface, loopCount: 1, intervalMs: 0, autoFixFrames: true);
    return (sent, failed, lastMsg, svc.TotalSent, done);
}

// ══ GROUP 55: display filter validation + field-name catalog ══
// No capture fixture: the validation probe writes its own empty pcap internally and
// `-G fields` needs no `-r`, so this group never depends on PcapPath and never skips.
Banner(55, "display filter validation + field-name catalog");
try
{
    var g55 = new TsharkService(new PcapIngestService(), new PcapExportService());

    // Blank filters mean "no filter": valid with no error, and tshark is never spawned.
    var g55Empty = await g55.ValidateDisplayFilterAsync("");
    Report("FV-01 an empty filter is valid without an error",
        g55Empty.IsValid && g55Empty.Error is null,
        $"IsValid={g55Empty.IsValid}, Error={g55Empty.Error ?? "<null>"}");

    var g55Spaces = await g55.ValidateDisplayFilterAsync("   ");
    Report("FV-02 a whitespace-only filter is valid without an error",
        g55Spaces.IsValid && g55Spaces.Error is null,
        $"IsValid={g55Spaces.IsValid}, Error={g55Spaces.Error ?? "<null>"}");

    var g55Valid = await g55.ValidateDisplayFilterAsync("frame.number == 1");
    Report("FV-03 a real display filter validates as valid", g55Valid.IsValid,
        $"IsValid={g55Valid.IsValid}, Error={g55Valid.Error ?? "<null>"}");

    var g55Invalid = await g55.ValidateDisplayFilterAsync("this.field.does.not.exist == 1");
    Report("FV-04 an unknown field is rejected with a non-empty error",
        !g55Invalid.IsValid && !string.IsNullOrEmpty(g55Invalid.Error),
        $"IsValid={g55Invalid.IsValid}, Error={g55Invalid.Error ?? "<null>"}");

    // The verdict is cached per filter string, so the repeat probe must be byte-identical
    // without another tshark run.
    var g55InvalidAgain = await g55.ValidateDisplayFilterAsync("this.field.does.not.exist == 1");
    Report("FV-05 repeating an invalid filter returns the identical cached verdict",
        !g55InvalidAgain.IsValid && g55InvalidAgain.Error == g55Invalid.Error,
        $"IsValid={g55InvalidAgain.IsValid}, sameError={g55InvalidAgain.Error == g55Invalid.Error}");

    var g55Fields = await g55.GetFieldNamesAsync();
    Report("FN-01 the field catalog is large", g55Fields.Count > 100000,
        $"count={g55Fields.Count}");
    Report("FN-02 the catalog contains frame.number", g55Fields.Contains("frame.number"),
        $"count={g55Fields.Count}");
    Report("FN-03 the catalog contains ip.src", g55Fields.Contains("ip.src"),
        $"count={g55Fields.Count}");
    Report("FN-04 the catalog is de-duplicated",
        g55Fields.Distinct().Count() == g55Fields.Count,
        $"count={g55Fields.Count}, distinct={g55Fields.Distinct().Count()}");
    Report("FN-05 the catalog is Ordinal-sorted",
        g55Fields.SequenceEqual(g55Fields.OrderBy(n => n, StringComparer.Ordinal)),
        "SequenceEqual(OrderBy(n, Ordinal))");

    bool g55HasGtpuPlaceholder = g55Fields.Contains("gtpu");
    bool g55HasGtp = g55Fields.Contains("gtp");
    Report("FN-06 the catalog has no placeholder 'gtpu', only the real 'gtp'",
        !g55HasGtpuPlaceholder && g55HasGtp,
        $"gtpu={g55HasGtpuPlaceholder}, gtp={g55HasGtp}");
}
catch (Exception ex)
{
    Report("G55 group execution", false, ex.ToString());
}

string skipNote = "";
if (skipped > 0)
{
    // Group identical reasons so the footer reads as "5x the fixture, 1x the big capture"
    // instead of repeating the same sentence five times.
    var byReason = skipReasons
        .GroupBy(r => r, StringComparer.Ordinal)
        .Select(g => $"x{g.Count()} {g.First()}");
    skipNote = $" — {skipped} GROUP(S) SKIPPED, so this is NOT full coverage: {string.Join("; ", byReason)}";
}
string footer = failures == 0
    ? $"ALL GROUPS PASS{skipNote}"
    : $"{failures} assertion(s) failed{skipNote}";
reportLines.Add(footer);
Console.WriteLine($"\n{footer}");

if (failures == 0 && (onlyGroup.HasValue || titleFilter is not null) && printedPasses == 0)
{
    string filterNote = "note: the active filter printed no PASS lines — this run proves nothing beyond the footer.";
    reportLines.Add(filterNote);
    Console.WriteLine(filterNote);
}
await File.WriteAllLinesAsync(Path.Combine(AppContext.BaseDirectory, "report.txt"), reportLines);

if (generatedCapture is not null)
{
    try { File.Delete(generatedCapture); } catch (IOException) { }
}
// Opt-in strictness: a run that skipped anything is not a full-coverage run.
// Default stays lenient so an ordinary clone without fixtures still reports usefully.
bool strict = !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PF_STRICT_CAPTURE"))
              && Environment.GetEnvironmentVariable("PF_STRICT_CAPTURE") != "0";
if (failures == 0 && skipped > 0 && strict)
{
      Console.WriteLine("PF_STRICT_CAPTURE is set and groups were skipped -> failing this run.");
      Console.WriteLine("  Set PF_CAPTURE=<path to a local .pcap> to enable the capture-dependent groups.");
      Console.WriteLine("  G17-13 needs the separate large capture: PF_CAPTURE_LARGE=<path to .pcapng>.");
      Console.WriteLine("  Unset PF_STRICT_CAPTURE to accept a partial run.");
    return 2;
}
return failures == 0 ? 0 : 1;

// Helper for chmod (bash on unix)
static async Task BashAsync(string command)
{
    var psi = new System.Diagnostics.ProcessStartInfo
    {
        FileName = "bash",
        Arguments = $"-c \"{command}\"",
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true,
    };
    using var p = System.Diagnostics.Process.Start(psi);
    if (p == null) return;
    await p.WaitForExitAsync();
}

// Captures Trace.WriteLine output (PacketSendService per-rung failure lines) so the
// send-ladder assertions can verify the AF_PACKET → IP raw → UDP descent order.
sealed class BufferingTraceListener : System.Diagnostics.TraceListener
{
    public readonly List<string> Lines = new();

    public override void Write(string? message) => Lines.Add(message ?? string.Empty);

    public override void WriteLine(string? message) => Lines.Add(message ?? string.Empty);
}
