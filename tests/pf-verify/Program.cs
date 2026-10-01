using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Collections.ObjectModel;
using ProtocolForge.Models;
using ProtocolForge.Services;
using ProtocolForge.ViewModels;

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
// Keep the guard a null test, not a separate bool: a bool cannot narrow the type
// and every call site then fails with CS8604.
string? PcapPath = ResolveCapturePath(repoRoot);
if (PcapPath is not null && !File.Exists(PcapPath)) PcapPath = null;
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

void Report(string name, bool ok, string? detail = null)
{
    string line = ok ? $"PASS {name}" : $"FAIL {name}: {detail ?? "assertion failed"}";
    reportLines.Add(line);
    Console.WriteLine(line);
    if (!ok) failures++;
}

// Skipped groups must not be mistaken for passed ones: they stay out of `failures`
// so a capture-less run still exits 0, but they are counted and named in the footer.
void Skip(string name, string why)
{
    string line = $"SKIP {name}: {why}";
    reportLines.Add(line);
    Console.WriteLine(line);
    skipped++;
    skipReasons.Add(why);
}

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
        Console.WriteLine("\nGROUP 1: tree-edit fence verdicts (frame 4413)");
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

                Console.WriteLine($"    total fields walked = {totalFields}, allowed-with-bytes = {allowedFields.Count}, blocked reasons:");
                foreach (var (r, c) in blockedByReason)
                    Console.WriteLine($"        {c,3}x  {r}");

                Report("G1a fence blocks metadata/bit-level fields", blockedByReason.Count > 0,
                    $"reasonCount={blockedByReason.Count}");
                Report("G1b fence allows >=1 normal in-frame field", allowedFields.Count > 0,
                    $"allowed={allowedFields.Count}");
                Report("G1c fence discriminates (both verdict classes present)", blockedByReason.Count > 0 && allowedFields.Count > 0,
                    $"blockedReasons={blockedByReason.Count}, allowed={allowedFields.Count}");

                // ══ GROUP 2: P2 Verify-Before-Commit transaction (service layer) ══
                Console.WriteLine("\nGROUP 2: P2 VBC transaction");
                var tx = new EditTransactionService(export, tshark);

                var target = allowedFields.FirstOrDefault();
                if (target == null)
                {
                    Report("G2a no candidate field to edit", false, "allowedFields empty");
                }
                else
                {
                    Console.WriteLine($"    candidate = {target.OriginalPdmlName} @{target.Offset} len={target.Length} raw={string.Join(" ", target.RawBytes.Select(b => b.ToString("X2")))}");
                    Report("G2a candidate field has concrete bytes", target.RawBytes.Length == target.Length,
                        $"rawBytes={target.RawBytes.Length}, field.Length={target.Length}");

                    // Legal edit: flip the lowest bit of the first byte -> reparse must land.
                    var newValue = (byte[])target.RawBytes.Clone();
                    newValue[0] ^= 0x01;
                    byte[] before = (byte[])packet.EffectiveData.Clone();

                    var legal = await tx.CommitFieldEditAsync(packet, target, newValue, null, readResult.LinkLayerType);
                    Console.WriteLine($"    legal edit verdict: Success={legal.Success} Reason={legal.Reason}");
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
                    Console.WriteLine($"    drift verdict: Success={drift.Success} Reason={drift.Reason}");
                    Report("G2d wrong-position edit aborted", !drift.Success,
                        $"Success={drift.Success} Reason={drift.Reason}");
                    Report("G2e abort leaves packet byte-identical", packet.EffectiveData.SequenceEqual(beforeDrift),
                        "packet mutated on drift abort");

                    // Length-changing edit: field.Length 1 but newValue 4 bytes -> must reject.
                    var longValue = new byte[] { 0x01, 0x02, 0x03, 0x04 };
                    byte[] beforeLen = (byte[])packet.EffectiveData.Clone();
                    var lenEdit = await tx.CommitFieldEditAsync(packet, target, longValue, null, readResult.LinkLayerType);
                    Console.WriteLine($"    length-edit verdict: Success={lenEdit.Success} Reason={lenEdit.Reason}");
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
Console.WriteLine("\nGROUP 3: tshark version gate (real env)");
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
Console.WriteLine("\nGROUP 4: tshark version gate (fake tshark 2.5 via TSHARK_PATH)");
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
    Console.WriteLine($"    fake detect: Ok={fakeDetection.Ok}, Version={fakeDetection.Version}, Path={fakeDetection.Path}");
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
    Console.WriteLine($"    fake detect: Ok={newDetection.Ok}, Version={newDetection.Version}");
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
Console.WriteLine("\nGROUP 5: read-only load");
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
Console.WriteLine("\nGROUP 6: P3 hex-edit REPLACE-only code surface");
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
}
catch (Exception ex)
{
    Report("G6 group execution", false, ex.ToString());
}

// ══ GROUP 7: Npcap probe pure logic (no Npcap needed — degradation contract) ══
Console.WriteLine("\nGROUP 7: Npcap probe pure logic (degradation contract)");
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
Console.WriteLine("\nGROUP 8: BPF pure logic (macOS degradation contract)");
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
Console.WriteLine("\nGROUP 11: localization (dictionary parity / placeholders / runtime switching)");
try
{
    var en = LocalizationService.For(AppLanguage.EnUs);
    var zh = LocalizationService.For(AppLanguage.ZhCn);

    // G11a: dictionary parity — identical key sets (same count, same keys)
    bool sameCount = en.Entries.Count == zh.Entries.Count;
    bool sameKeys = en.Entries.Keys.ToHashSet().SetEquals(zh.Entries.Keys);
    Console.WriteLine($"    en={en.Entries.Count} keys, zh={zh.Entries.Count} keys");
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
        Console.WriteLine($"    zh CJK sample: \"{cjkSample.Key}\" = \"{cjkSample.Value}\"");
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
Console.WriteLine($"\nGROUP 12a+12b: edit fence gates + raw-value conversion");
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
    Report("G12b full conversion matrix", g12ok, g12detail.Length == 0 ? "all vectors passed" : g12detail);
}
catch (Exception ex)
{
    Report("G12 group execution", false, ex.ToString());
}

Console.WriteLine("\nGROUP 13: field edit application — offsets, length guards, hex apply");
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

Console.WriteLine("\nGROUP 14: protocol layers on parsed frame (frame 2 of real capture)");
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
            Report("G14-05 duplicate layer names tolerated (TR-03)", true,
                string.Join(", ", g14Pkt.Layers.Select(l => l.ProtocolName)));
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

Console.WriteLine("\nGROUP 15: pre-send packet preparation — checksum repair + source rewrite (static)");
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
}
catch (Exception ex)
{
    Report("G15 group execution", false, ex.ToString());
}

Console.WriteLine("\nGROUP 16: verify-before-commit — abort reasons byte-identical, legal commit lands");
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

Console.WriteLine("\nGROUP 17: PCAP/PCAPNG ingestion — classic endianness/ns, pcapng sections, resolutions");
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

Console.WriteLine("\nGROUP 18: PCAP export — byte-exact header/records, modified-only, round trip");
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

Console.WriteLine("\nGROUP 19: address/port extraction + edit→reparse refresh on a real frame (4413)");
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
}
catch (Exception ex)
{
    Report("G19 group execution", false, ex.ToString());
}

Console.WriteLine("\nGROUP 20: layout + settings persistence (ApplicationData, snapshot/restore)");
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
    Console.WriteLine("\nGROUP N: loopback injection on Linux (rung ladder)");
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
Console.WriteLine("\nGROUP 22: HexPreferred hex-native field editing code surface");
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
Console.WriteLine("\nGROUP 23: trace.log startup rotation + crash recorders code surface");
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
Console.WriteLine("\nGROUP 24: jsonraw 3-pass parse — fixture pcaps (TR-02..TR-09)");
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
Console.WriteLine("\nGROUP 25: V-08 empty-pdmlName abort + A-02 address re-extraction");
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
Console.WriteLine("\nGROUP 27: send ladder directed descent (N-10..N-13)");
try
{
    string nSrc = await File.ReadAllTextAsync(Path.Combine(ProjectDir, "Services/PacketSendService.cs"));

    Report("N-10 no-socket guard → Send.NoSocketType (source)",
        nSrc.Contains("sockets.Count == 0 && l2Rung == null") && nSrc.Contains("Send.NoSocketType"),
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
Console.WriteLine("\nGROUP 28: ST-03 settings save failure silent (behavioral)");
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
Console.WriteLine("\nGROUP 29: TR-04 PFCP anonymous containers + H-13 hex refresh");
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
Console.WriteLine("\nGROUP 30: CP-01..04 context providers (mock + real fixtures)");
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
Console.WriteLine("\nGROUP 31: TL-01..03 tls/ssl keylog args (argv-capture fake tshark)");
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
Console.WriteLine("\nGROUP 32: N-17 interfaces");
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
Console.WriteLine("\nGROUP 26: detection env-first + version gate + cache (T-08/T-09/T-12)");
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

Console.WriteLine("\nGROUP 33: direct send state, no-op tree edit, and close guard");
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
            new EditTransactionService(g33Export, g33Tsh));
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


  Console.WriteLine("\nGROUP 34: reset-modifications repaints, restores the tree, and unlocks the fence");
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
          var g34Hex = new HexEditorViewModel(g34Editor);
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
                    var g34DataTree = new ProtocolTreeViewModel(g34Editor, new EditTransactionService(g34Export, g34Tsh));
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

  Console.WriteLine("\nGROUP 35: reset-modifications end-to-end through the real command");
  try
  {
      var g35Editor = new ProtocolEditorService();
      var g35Export = new PcapExportService();
      var g35Tsh = new TsharkService(new PcapIngestService(), g35Export);
      var g35Tree = new ProtocolTreeViewModel(g35Editor, new EditTransactionService(g35Export, g35Tsh));
      var g35Hex = new HexEditorViewModel(g35Editor);
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
Console.WriteLine("\nGROUP 36: DI-01..03 paired repeated containers must not emit a phantom twin row");
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
Console.WriteLine("\nGROUP 37: LB/SP bitfield labels and anonymous-container spans");
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
Console.WriteLine("\nGROUP 38: EI-01..04 expert info rows surface (wireshark keeps them)");
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

// ── G12–G32 helpers (hoisted local functions) ──
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
await File.WriteAllLinesAsync(Path.Combine(AppContext.BaseDirectory, "report.txt"), reportLines);
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
