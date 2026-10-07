# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - unreleased

### Added

- **Headless UI verification.** The harness can now mount the real `MainWindow` with the
  real view models under `Avalonia.Headless` and render it through Skia with no X server
  and no GL, then assert on the result: the window mounts, the panels the reassembly work
  touched are in the visual tree and are mutually exclusive, the VLAN id box follows the
  VLAN mode, the checkbox labels resolve from the localization dictionary, and the captured
  frame is real rendered content rather than a blank surface. Run it with
  `dotnet run --project tests/pf-verify -- --ui`. It is a separate process and a separate
  CI step on purpose — initialising Avalonia and Skia inside the process that then runs the
  tshark-backed groups crashes it. This raises the guarantee from "the XAML compiled" to
  "the window rendered", and it is deliberately the framework-free `Avalonia.Headless`
  package rather than the xUnit/NUnit integration, so the harness keeps its hand-rolled
  assertions.

**Editing**

- **Length-changing edits.** A field's value may now be a different length: the frame is spliced, every later field is shifted, and fields the splice pushed outside the frame are pruned from the tree. This is gated behind an explicit per-editor "allow length change" opt-in, is hex-only, and resets each time an editor opens.
- **Compound edits.** Several fields are edited in one transaction. This is what makes an insert usable at all: growing a payload and correcting the enclosing length fields cannot be done one transaction at a time, because the frame is malformed in between and each transaction would correctly refuse it. Verified end-to-end by growing a UDP payload together with `udp.length` and `ip.len`.
- **Undo / redo** over committed edits, per packet, capped at 200 entries with a visible bound. A new edit discards the redo branch. Ctrl+Z / Ctrl+Y, also on the File menu. Undo and redo reload the capture so the protocol tree matches the restored bytes.
- **Recent files** persisted per user, capped at 10.

**Analysis**

- **Multi-interface capture files are reported, not silently merged.** A PCAPNG file can
  declare several Interface Description Blocks, one per adapter. The writer emits a single
  interface, so which adapter each packet came from cannot survive a save. The app now
  reports the interface count when the file is opened and again when it is saved, naming
  one-instance-per-adapter as the alternative.
- **`trace.log` splits by PID when other instances are running.** A single instance keeps
  the documented `trace.log` name and its rotation; siblings write `trace.<pid>.log`, so
  concurrent instances no longer interleave lines in one file.
- **Follow TCP stream.** The stream index built for reassembly is now exposed instead of discarded; picking a stream filters the packet list to it. The index is rebuilt after a save, which is the only moment it is well defined: `tcp.stream` is assigned across the whole file by tshark, so a capture-wide scan reads the bytes on disk, and a frame on its own always reports stream 0 no matter which stream it belongs to.
- **Reassembled stream bytes.** A Follow Stream stream can now be viewed as reassembled payload — hex dump included — instead of only being used to filter the list. The payload is read from tshark's own `follow,tcp,raw` output, so what is shown is what tshark reconstructed. A stream that cannot be reassembled says so rather than showing an empty pane.

**Sending**

- **Egress interface is actually pinned.** Binding the source address did not choose the outgoing NIC; the kernel still routed by its own table, so selecting NIC-A could transmit out of NIC-B. The IP-raw and UDP sockets are now pinned with `SO_BINDTODEVICE` on Linux and `IP_BOUND_IF` on macOS, and the target is reported in the status line before sending. AF_PACKET and the native L2 rungs already selected per frame. **Windows has no equivalent for a normal socket**, so there the source-address bind remains the only option.
- **VLAN tag control on send.** Frames can be sent untagged as captured, tagged with a chosen VID, re-tagged to a new VID, or stripped of an existing tag. Tagging is applied before the send-time MAC/IP/checksum fixups, so the checksums the receiver validates are computed over the bytes actually transmitted. A QinQ stack keeps its inner tags, and a frame with no Ethernet-II header is left alone rather than half-patched.
- **The VLAN setting says so when it cannot take effect.** An 802.1Q tag only reaches the network if a rung transmits the whole Ethernet frame; on the UDP and IP-raw rungs the kernel builds the header itself and the tag is discarded, which looked like the setting simply did nothing. The send now warns once per affected adapter, naming the adapter and how many frames are involved, and points at the native L2 / AF_PACKET path. The warning is raised separately from send results, so it never inflates the failed-packet count. Frames that have no Ethernet header to tag — bare IP datagrams — stay silent rather than raising a false alarm.
- **Multi-NIC fan-out.** A send can target every usable adapter instead of only the selected one, offering each checked packet to each target in turn. A NIC that cannot be opened is reported on its own and does not abort the other targets. The target list is shown in the status line before the send, and the packet count reported to the user is the number of transmissions rather than the number of checked packets.

**Housekeeping**

- **Rescan network adapters** button on the send toolbar. The command existed but was bound to nothing, so plugging in an adapter required restarting the app.
- **Export-as offers PCAPNG.** The writer shipped in this release was unreachable from the file dialog, which only listed `*.pcap`.
- **Harness output filter.** `dotnet run --project tests/pf-verify -- --only <组号>` (or `--group <标题子串>`) prints a single group while iterating. It suppresses **output only** — every group still executes, FAIL lines always print, and the footer and exit code still judge the whole run, so a filtered run cannot look green when something failed. Group banners and in-group detail lines are emitted through `Banner(n, title)` / `Detail(text)` helpers so nothing slips past the filter.
- **The harness is part of `ProtocolForge.sln`.** `dotnet build` now compiles `tests/pf-verify`, so harness compile errors surface in a plain build instead of only when someone remembers to run it. Building is not running: the harness still has to be executed explicitly.

### Fixed

- **The Follow Stream combo did nothing.** `ApplySelectedStreamFilterAsync` existed but no generated-property hook called it, so selecting a stream changed the label without filtering the list.
- **The reassembled viewer and the statistics list were drawn in the same grid cell.** Showing reassembled bytes left the statistics table painted underneath, so the two overlapped.
- **`--help` started the desktop app.** Only the four documented verbs were recognised as headless; any other first argument was treated as a file path to open, so `--help` opened a window a script could neither see nor close. It now prints usage and exits 2.
- **Fields with no byte span could not be edited.** The tree edit fence excluded them before any check ran, so the field just looked uneditable with no reason given. The exclusion was moved into the fence itself, which now reports "this field has no bytes to edit" specifically.
- **`FindIpOffset` stepped over VLAN tags but no longer found a minimal 14-byte Ethernet header** (regression found and fixed by the existing `G15q` matrix while adding VLAN support).
- **Sending a VLAN-tagged packet rewrote the packet.** `ApplyVlanTag` set the new VID directly in the array it was given, and `EffectiveData` hands out the packet's live buffer — so choosing "replace VID" and sending mutated the in-memory packet as a side effect of a read-only operation, which a later export or save would then persist. Tagging now always works on a copy.
- **`G14-05` was a tautology.** The assertion was `Report(..., true, ...)`, so it could never fail. It now checks that same-named protocol layers (a tunnelled frame has two `ip` layers) keep distinct offsets and stay linked to their packet. A companion group proves the predicate rejects a collapsed duplicate and an orphaned layer, so the assertion is not vacuous.
- **`LocalizationService.SetCurrent` returned early when the language did not change, without ever attaching the dictionaries to the Avalonia application.** If the first call happened before the `Application` object existed, the publish went nowhere and the same-language call that ran *after* composition returned without retrying — every `{DynamicResource}` label then rendered blank, silently, with no error anywhere. The app's own call order never hit this, but group order in the harness could; the early exit is gone, re-publishing is idempotent, and the harness's defensive re-publish call was deleted. `HG-06` (toolbar checkbox labels resolve from the localization dictionary) now pins it.
- **PCAPNG export wrote microsecond values under a nanosecond declaration.** Two stacked defects in `PcapngWriter`: the `if_tsresol` option was emitted as bytes `09 01 …`, which little-endian readers decode as code `0x0109` — a nonexistent option, so consumers always fell back to microsecond ticks and the nanosecond declaration never took effect; and the EPB timestamp field was written as plain microseconds, so a file that did declare nanoseconds showed a 1000× wrong wall time. The option is now written as `09 00 01 00 <exp> 00` as the spec requires, and the EPB timestamp is scaled to the declared tick unit before writing. A new `NG-07` harness assertion round-trips a ns-declared export and pins the microsecond timestamp down to the unit.

### Removed

- `ViewLocator` and the two value converters. All three were registered or defined but referenced nowhere: the app constructs its views directly. `ViewLocator` was additionally annotated by its own author as a trimming hazard.
- `OpenPcapAsync` and `ExportPcapAsync`. Both were `[RelayCommand]` wrappers that no XAML or code-behind referenced; the first was an empty stub and the second duplicated `ExportToFileAsync`.
- `docs/PfcheckUserManual.md`, which documented a CLI that did not exist and described a GUI feature as paid. Replaced by `docs/pfcheck-cli.md`, written against the tool that now ships.

### Changed

- **One adapter per instance is the supported shape.** Capturing several NICs is done by
  running several instances, not by teaching one instance to handle several. Accordingly
  the per-PID `trace.log` split and the multi-interface notice below exist to make that
  workable, not to grow multi-NIC support. Multi-interface PCAPNG write-back is therefore
  out of scope: a file that merged several adapters is reported on load and again on save,
  so the merge is never silent.

- The verification harness generates its own capture. With `PF_CAPTURE` unset it builds a 4413-frame synthetic capture into the temp directory and deletes it afterwards, so the capture-dependent groups — the edit fence, Verify-Before-Commit, address re-extraction — run in CI instead of skipping. A bare run reports 378 PASS / 0 FAIL / 1 SKIP (+ HG-01..10 headless UI); the one skip is `G17-13`, which needs the ≥180k-packet pcapng that cannot be synthesised. No capture is committed and the no-pcap rule is unchanged.

### Not done in this release

- `v0.2.0` has **no git tag**. The repository previously claimed a 0.1.0 release that was never tagged, so `release.yml` never produced an artifact from this history. The tag is deliberately left for a maintainer to cut after review, not created here.


### Added

**Editing**

- **Enumerated-value dropdown.** Integer fields tshark renders a name for are now edited from a list instead of a bare number. The interpretations are harvested from PDML during dissection, so the list holds values observed in the session — tshark has no enum-dump facility and its `show` attribute only ever describes the value present in that one packet. `Kind` is deliberately unchanged, so the edit fence and every value converter keep working as before.

**Capture handling**

- **Display filter.** A tshark display filter can be applied to the packet list. The filter is evaluated by tshark at load time rather than by post-filtering rows, so filtered rows keep their original frame numbers and still map to the correct bytes.
- **Find.** Search across the packet list columns and the selected packet's protocol tree, forward and backward. Tree hits reuse the existing select-and-reveal path.
- **Statistics panel.** Runs `conv,*`, `endpoints,ip`, `io,phs`, `io,stat` and `expert` taps, honouring the display filter where the tap accepts one. tshark pads its own output, so it is shown verbatim rather than re-laid-out.
- **PCAPNG write-back.** A capture opened as `.pcapng` is saved as PCAPNG instead of being downgraded to classic PCAP, which silently discarded every interface description, block comment and the timestamp resolution. Export-as follows the extension you actually choose.

**Sending**

- **Send history and CSV export.** Per-packet results are buffered instead of only the last one being visible, with a 5000-row cap whose truncation is surfaced. Exportable as CSV from the packet-list context menu.

**Command line**

- **Headless CLI.** `validate`, `edit`, `send` and `stats` run without a GUI. Edits go through the same Verify-Before-Commit transaction as the GUI, so a scripted edit gets the identical guarantee. Exit codes: 0 ok, 1 failed or verification aborted, 2 bad usage. Documented in [`docs/pfcheck-cli.md`](docs/pfcheck-cli.md).

### Fixed

- **Verify-Before-Commit threw instead of returning a verdict.** The candidate-frame copy ran before the length guard, so a length-changing edit overrunning the frame raised `ArgumentException` out of a method whose contract is to return an `EditResult`. The packet is now left byte-identical and the reason reported.
- **The `edit` CLI verb dropped every packet but the edited one.** It now writes the whole capture with the target frame substituted.
- **Statistics taps ignored the display filter.** tshark's `-z` taps post-filter nothing and reported `Filter:<No Filter>`; the filter is now passed as the tap's own argument, and taps that reject one are left unfiltered rather than failing.
- **PCAPNG `section_length` was written as 4 bytes instead of 8**, truncating every section header and desynchronising the block chain. Files written by the affected build were rejected by tshark and read back as empty by the app.

### Changed

- **The verification harness generates its own capture.** With `PF_CAPTURE` unset it builds a 4413-frame synthetic capture into the temp directory and deletes it afterwards, so the capture-dependent groups — the edit fence, Verify-Before-Commit, address re-extraction — run in CI instead of skipping. A bare run reports 325 PASS / 0 FAIL / 1 SKIP; the one skip is `G17-13`, which needs the ≥180k-packet pcapng that cannot be synthesised. No capture is committed and the no-pcap rule is unchanged.
- Removed `docs/PfcheckUserManual.md`, which documented a CLI that did not exist and described a GUI feature as paid. It is replaced by `docs/pfcheck-cli.md`, written against the tool that now ships.

## [0.1.0] - 2026-09-30

First public release. Apache-2.0, self-contained, cross-platform.

### Added

**Capture ingestion and dissection**

- PCAP and PCAPNG reading with a native C# parser: little- and big-endian classic PCAP, and PCAPNG section, interface and packet blocks, with per-interface timestamp resolution. Both microsecond and nanosecond timestamp formats.
- **Streamed packet list.** A single `tshark -T fields` pass is read line by line, so the DataGrid fills progressively instead of waiting on the whole file. Captures well past 180k packets open in seconds.
- **Per-packet protocol tree, built on demand.** Selecting a packet writes that single packet to a temp PCAP and reparses it with `-T jsonraw`, `-T json` and `-T pdml` in parallel. The tree is never built for the whole file. A sequence guard discards stale results when the operator moves faster than the parse.
- Three-pass jsonraw parser: collect `*_raw` arrays, walk `*_tree` containers recursively, then emit orphaned `_raw` entries that have no `_tree` parent.
- `tshark` version gate at **2.6.0**. Below that, or when tshark is missing, the app opens the capture **read-only**: packets load, tree and hex editing, export and sending are disabled, and a banner explains why. The tshark path is re-selectable at runtime and the choice is persisted. `TSHARK_PATH` overrides it.
- Address and port re-extraction from parsed fields after edits, reflected in the packet list columns.

**Editing**

- **Hex viewer** with a Wireshark-style layout: 16 bytes per row, offset column, hex grouped 8+8, ASCII pane. Click or arrow-key navigation, selected bytes highlighted, protocol field ranges highlighted per protocol, edited bytes marked.
- **REPLACE-only inline hex editing.** Start typing hex digits over any byte, the pending value previews in place, Enter commits the whole run as a single replace, Esc cancels. Each run is built from full hex-digit pairs, so **packet length never changes** and every offset outside the edited span stays valid.
- **Six-check edit fence** (`CheckTreeEditFence`) gating every field edit: a resolvable field type, a non-negative byte span, byte alignment rather than a bit-level sub-field, an in-frame span (fanning into a reassembled PDU fails), concrete byte evidence with `RawBytes.Length` matching the field length, and recorded bytes agreeing with the actual frame bytes. Blocked fields report the reason and refuse to open an editor.
- **Verify-Before-Commit.** A proposed edit is not written straight into the packet. The candidate frame is saved to a temp PCAP with surrounding context frames where available, reparsed by tshark, and the field's new hex value must land at the expected `(PDML name, byte offset)`. Offset drift, a wrong value, or a length mismatch aborts the commit and leaves the packet byte-identical. Applies to both tree and hex edits.
- **Container auto-relink.** After a committed field edit the packet is reparsed once in the background and the tree's container and layer header texts are patched in place, so editing a PFCP SEID refreshes the surrounding `F-SEID : SEID: 0x…, IPv4 …` display without rebuilding the tree. Anonymous IE containers are matched by effective offset.
- Hex-native field editing: fields Wireshark renders in hexadecimal, such as PFCP SEID and TEID, are detected from the PDML showname and edited as hex, round-tripping big-endian bytes exactly as tshark displays them.
- **Bidirectional tree and hex sync.** Selecting a field highlights its byte range in the hex viewer; selecting bytes resolves the owning field and reveals the matching node in the tree.
- PCAP export: overwrite-save, export-as, unsaved-change tracking and a warning on close.

**Sending**

- **Four-rung injection ladder**, probed once per session and descended per packet when a rung cannot deliver:
  0. Native L2 via Npcap (Windows) or `/dev/bpf` (macOS), optional
  1. `AF_PACKET` raw socket (Linux)
  2. IP-level raw socket (all platforms)
  3. UDP socket fallback
- A rung that cannot deliver a given frame descends to the next; L2 failures are no exception. On the UDP fallback the service extracts the destination IP and port from the raw packet's headers and sends the payload, losing the outer headers but requiring no privileges.
- Per-packet opt-in sending with a network adapter dropdown, send interval and loop count, an **Auto-fix** toggle that repairs IPv4/IPv6 and TCP/UDP checksums and normalises the source address to the selected interface's own, live sent and failed counters, and Start / Pause / Stop controls.
- The native L2 rung is never bundled and never silently installed. On Windows the app only probes a user-installed Npcap; on macOS it only opens an existing `/dev/bpfN`. When it is unavailable, sending degrades silently to pure-managed sockets.

**Interface and packaging**

- Bilingual UI, 简体中文 and English, with instant runtime switching from the language menu and system-locale detection on first run. All strings live in `Assets/Lang/en-US.json` and `Assets/Lang/zh-CN.json` as matching key sets.
- Sortable packet list DataGrid: click a column header to cycle ascending and descending, double-click a header divider to auto-fit the column.
- Layout persistence: window geometry, splitter positions and panel visibility are saved and restored.
- Self-contained builds, so end users install nothing but Wireshark. Linux x64 AppImage and `deb` from `packaging/linux/publish-linux.sh`, Windows x64 ZIP from `packaging/windows/publish-windows.ps1`, each shipped with `SHA256SUMS`.
- Runtime diagnostics in a local `trace.log` under `LocalApplicationData/ProtocolForge/logs/`.
- Continuous integration building with warnings as errors, running the standalone `pf-verify` assertion harness, and rejecting any added or modified `.pcap` / `.pcapng`.

### Removed

- Pre-release-only subsystems that gated nothing were removed before the first public release. Nothing in 0.1.0 is gated: **no feature in 0.1.0 is gated.** There is no feature gate, no send quota, no telemetry, and no network call of any kind. Everything currently shipped is free and unlimited.

### Notes

- tshark / Wireshark (**GPL-2.0-or-later**) is the only external runtime dependency, is not bundled, and is invoked as a separate subprocess over documented output formats. ProtocolForge does not link `libwireshark` and does not embed Wireshark as a library, so it is not a GPL derivative work. See [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) for the full argument, including the contested edge.
- Npcap (Windows, optional) is not bundled, not redistributed, and not installed by the application. See [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
- Security reporting channels, intended use, and the disclosed limits of the send path are in [`SECURITY.md`](SECURITY.md).

[Unreleased]: https://github.com/yangying-dev/protocol-forge/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yangying-dev/protocol-forge/releases/tag/v0.1.0
