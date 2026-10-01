# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

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
