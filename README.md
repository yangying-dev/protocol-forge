# ProtocolForge

**3GPP Protocol Simulation & Debugging Workbench**

ProtocolForge is a cross-platform desktop application for inspecting, editing, and replaying 3GPP protocol packets (PFCP, NGAP, GTP-U, NAS, S1AP, Diameter, etc.) captured in PCAP files. It combines Wireshark's parsing engine (tshark) with a native packet editor and raw socket injection — all in a single .NET 8 + Avalonia UI application.

> **Free and open source (Apache-2.0).** Everything currently shipped is free and unlimited — there is no feature gate and no send quota. On Windows, install Wireshark yourself and keep the Npcap option enabled during installation (it is selected by default); ProtocolForge does not bundle or silently install Npcap.

![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4)
![Avalonia](https://img.shields.io/badge/Avalonia-12.0.5-8B5CF6)
![Platform](https://img.shields.io/badge/platform-Windows%20%2F%20Linux%20%2F%20macOS-lightgrey)

---

## Screenshots

Open a synthetic capture and select a PFCP Association Setup Response. The protocol tree is expanded to the
parsed PFCP AVP, and the hex editor highlights the bytes occupied by the focused field.

![Protocol tree and hex editor (parsed PFCP Association Setup Response)](docs/images/protocol-tree-hex.png)

The Simplified Chinese version of the same screen — the UI is fully bilingual and switchable at runtime.

![协议树与十六进制编辑器](docs/images/protocol-tree-hex-zh.png)

Both images are rendered from a synthetic capture produced by [`docs/make-synthetic-capture.py`](docs/make-synthetic-capture.py),
so no real operator capture is involved and reproducing them does not require committing one.

---

## Features

- **PCAP Ingestion** — Read PCAP and PCAPNG files (both µs and ns timestamp formats) with a native C# parser: little/big-endian classic PCAP and PCAPNG section/interface/packet blocks, with per-interface timestamp resolution support.
- **Tshark Integration** — Two-mode tshark use: one streamed `-T fields` pass fills the packet list (Source/Destination/Protocol/Info columns, progressively as tshark dissects), and the protocol detail tree is parsed per-packet on demand with `-T jsonraw`/`json`/`pdml` for byte-offset accuracy. Supports any protocol Wireshark knows (PFCP, NGAP, GTP-U, NAS, S1AP, HTTP/2, Diameter, SCTP, etc.).
- **Tshark Environment Gate** — On startup and on path change, the installed tshark's version is checked against a minimum of 2.6.0. If tshark is missing or too old, the app still opens the capture in **read-only mode**: the warning banner is shown, raw packet data loads normally (`N/A` columns), but tree/hex editing, export, and packet injection are disabled. A tshark path can be re-selected at runtime via **File → Tshark Path…**, which re-detects and lifts the gate when a valid tshark is found. The chosen path is persisted (and can be overridden by the `TSHARK_PATH` environment variable).
- **Bilingual UI (简体中文 / English)** — Full UI localization with instant runtime language switching via the **语言 / Language** menu (between View and Help); the preference is persisted and the system locale is auto-detected on first run.
- **Three-Pass jsonraw Parser** — Walks tshark's JSON structure for the *selected* packet only (not the whole file):
  1. Collect all `_raw` arrays (hex value, offset, length)
  2. Process `_tree` containers and sub-objects with recursive field nesting
  3. Emit orphaned `_raw` entries (fields like `ip.src_raw` without a `_tree` parent)
- **Hex Viewer + Inline Editing** — Wireshark-style hex dump: 16 bytes per row with offset column, hex (grouped 8+8) and ASCII panes. Click a cell or use arrow keys to navigate; selected bytes render dark blue, protocol field ranges are highlighted in a protocol-specific color, and bytes modified via the tree or the hex editor are marked in orange. Bytes can also be **edited directly in the hex pane**: start typing hex digits (0-9/A-F or NumPad) over any byte, the pending value is previewed in place (yellow background, grey ASCII), press Enter to commit the whole run as a single replace, or Esc to cancel. Editing is **REPLACE-only** — each run is built from full hex-digit pairs, so the packet never changes length and every offset outside the edited span stays valid.
- **Tree ↔ Hex Bidirectional Sync** — Clicking a field in the protocol tree highlights its byte range in the hex viewer. Conversely, selecting/editing bytes in the hex pane resolves the owning field and scrolls + selects the matching node in the tree (`FieldFoundAtOffset` → tree reveal).
- **Protocol Tree** — Hierarchical tree view of parsed Information Elements. Click any field to highlight its byte range in the hex viewer. Right-click a field (or double-click it) to open an inline value editor: type the value in its natural form (decimal, dotted IP, MAC, string, or hex) and press Enter (or click elsewhere) to apply, Esc to cancel. Editing is gated by an **edit fence** (`CheckTreeEditFence`) — six checks must all hold for a field to be editable: a resolvable field type, a non-negative byte span, byte-aligned (not a bit-level sub-field), an in-frame span (fanning into a reassembled PDU fails), concrete byte evidence (`RawBytes.Length` matches the field length), and recorded bytes agreeing with the actual frame bytes (catches masked/offset-drifted values). Blocked fields show the reason (`Not editable: …`) in the status area and refuse to open an editor.
- **Verify-Before-Commit (VBC)** — Applies to both tree and hex edits. A proposed edit is not written straight into the packet: the candidate frame is saved to a temp PCAP (with surrounding context frames when available), **re-parsed via tshark**, and the field's new hex value must land at the expected `(PDML name, byte offset)` position. Offset drift, wrong values, or length mismatches abort the commit with a reason and leave the packet byte-identical.
- **Container Auto-Relink** — After a committed field edit, the edited packet is re-parsed once in the background (single-packet PDML re-parse) and the tree's container/layer header texts are patched back in place, so e.g. editing a PFCP SEID immediately refreshes the surrounding `F-SEID : SEID: 0x…, IPv4 …` display without rebuilding the tree. Matches fields by PDML name + byte offset, and falls back to the effective (min-descendant) offset for anonymous IE containers.
- **Hex-Native Field Editing** — Fields Wireshark renders in hexadecimal (PFCP SEID/TEID, address ranges, etc.) are auto-detected from the PDML showname (`0x…` prefix) and edited as hex by default, round-tripping big-endian bytes exactly as tshark displays them.
- **Address/Port Re-extraction** — After byte edits, IP addresses and port numbers are automatically re-parsed from the modified bytes and reflected in the packet list columns.
- **Packet DataGrid** — The packet list is a sortable DataGrid: click any column header to cycle ascending/descending sort, or double-click a column header divider to auto-fit that column's width (all columns supported).
- **Selective Sending** — Per-packet checkboxes plus a right-click context menu (Select All / Invert / Clear / Send Selected) control exactly which packets get injected.
- **PCAP Export** — Save modified packets back to standard PCAP format. Supports overwrite-save (Ctrl+S) and export-as (Ctrl+Shift+S). Tracks unsaved changes and warns on close.
- **Packet Injection** — Send packets over a selected network interface using a probe-and-fallthrough rung ladder:
  0. **Npcap / BPF** (Windows / macOS, optional) — complete Ethernet frames when the native L2 path is available; silently skipped otherwise
  1. **AF_PACKET** raw socket (Linux) — complete Ethernet frames
  2. **IP raw socket** (Windows/Linux/macOS) — IP datagrams
  3. **UDP socket** — transport-layer fallback (no privileges required)
  Sending is driven by a configurable **interval (ms)** and **loop count**. An **Auto-fix** toggle repairs IPv4/IPv6 and TCP/UDP checksums before injection, and rewrites the source address to the selected interface's own.
- **Toolbar UI** — Start/Pause/Stop send controls with a network adapter dropdown, send interval and loop count inputs, an Auto-fix toggle, live sent/failed counters, and a status bar.
- **Layout Persistence** — Window geometry, splitter positions, and panel visibility are saved to `%APPDATA%/ProtocolForge/layout.json` and restored on next launch.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    MainWindow                       │
│  ┌───────────────┬────────────────┬──────────────┐  │
│  │  Packet List   │ Protocol Tree  │  Hex Viewer  │  │
│  │  (DataGrid)    │  (TreeView)    │  (Custom)    │  │
│  └───────┬───────┴───────┬────────┴──────┬───────┘  │
│          │               │               │          │
│  ┌───────▼───────────────▼───────────────▼───────┐  │
│  │           MainWindowViewModel                  │  │
│  │  PacketList │ ProtocolTree │ HexEditor │ ToolBar│  │
│  └───────┬───────────┬───────────┬──────────┬─────┘  │
│          │           │           │          │        │
└──────────┼───────────┼───────────┼──────────┼────────┘
           │           │           │          │
     ┌─────▼───┐ ┌────▼────┐ ┌───▼────┐ ┌───▼─────────┐
     │Tshark   │ │Protocol  │ │Pcap    │ │NetworkInterf.│
     │Service  │ │Editor    │ │Export  │ │PacketSend    │
     └─────────┘ └─────────┘ └────────┘ └──────────────┘
```

### Design Principles

- **MVVM with Manual DI** — No external IoC container. Services are instantiated in `App.axaml.cs` in dependency order. ViewModels receive their dependencies via constructor injection.
- **Zero Native Dependencies** — Pure C#, no bundled native libraries. The single exception is an *optional* L2 path: on Windows the app probes the user-installed Npcap (`wpcap.dll`) via P/Invoke, and on macOS it probes `/dev/bpfN` — either path delivers full L2 injection when present, and sending silently degrades to pure-managed sockets otherwise. Only external requirement is **tshark** (from Wireshark) for protocol parsing.
- **Cross-Platform** — Targets net8.0, runs on Windows, Linux, and macOS. Socket strategies adapt per OS.
- **Minimal Coupling** — Services are standalone; ViewModels communicate via events (`PacketSelected`, `FieldSelected`, `FieldEdited`, `LayerSelected`, `HexEdited`, `FieldFoundAtOffset`).

---

## Project Structure

```
ProtocolForge/
├── App.axaml.cs              # Application entry — manual DI composition
├── Program.cs                 # Avalonia bootstrap
├── ProtocolForge.csproj       # .NET 8, Avalonia 12.0.5, CommunityToolkit.Mvvm 8.4.2, DataGrid 12.0.1
│
├── Assets/Lang/               # Localization dictionaries — en-US.json + zh-CN.json (embedded as resources)
│   ├── en-US.json            # English UI strings (148 keys)
│   └── zh-CN.json            # 简体中文 UI strings (148 keys, identical key set)
│
├── Models/                    # Domain objects
│   ├── Packet.cs              # Single packet: raw data, modifications, address/port, layers
│   ├── PacketDocument.cs      # PCAP document: packet collection, dirty tracking
│   ├── HexByte.cs             # Byte in hex viewer: value, selection, highlight, edited marker, pending-edit state
│   ├── ProtocolField.cs       # Protocol Information Element: offset, length, raw bytes, children, PDML name/hex pref for re-link
│   ├── ProtocolLayer.cs       # Protocol layer container for fields
│   ├── PacketExportOptions.cs # Export configuration
│   └── TsharkJsonModels.cs    # JSON deserialization models (legacy, most parsing is manual)
│
├── Services/                  # Business logic
│   ├── TsharkService.cs       # Streamed `-T fields` list loading + per-packet on-demand jsonraw/json/pdml tree build + single-packet pdml reparse + tshark detection/version gate
│   ├── EditTransactionService.cs # Verify-Before-Commit: candidate frame → tshark reparse → (name, offset) hex verification → commit or abort
│   ├── TsharkSettingsService.cs # Persists the user-chosen tshark path and UI language (settings.json) across sessions
│   ├── LocalizationService.cs # Runtime localization core: Resolve(key, args), SetCurrent(AppLanguage), LanguageChanged event, DynamicResource publishing
│   ├── PcapIngestService.cs   # Raw PCAP byte reader (handles endianness, µs/ns timestamps)
│   ├── PcapExportService.cs   # PCAP writer — overwrite save, export-as, and single-packet reparse temp files
│   ├── ProtocolEditorService.cs # Edit fence (CheckTreeEditFence), field-level edits, offset lookup, hex ↔ byte conversion (0x-prefixed hex)
│   ├── LayoutService.cs       # Window layout persistence (JSON in %APPDATA%)
│   ├── NetworkInterfaceService.cs  # Cross-platform network adapter scanner
│   ├── PacketSendService.cs   # Raw packet injection with rung ladder fallback (L2 → IP → UDP)
│   ├── PacketPrepareService.cs # Pre-send preparation: checksum/length repair, source address injection
│   ├── IL2SendRung.cs         # Contract for native L2 senders (Npcap on Windows, BPF on macOS)
│   ├── NpcapSendService.cs    # Windows L2 rung — probes user-installed wpcap.dll, GUID-matched send device
│   ├── BpfSendService.cs      # macOS L2 rung — probes /dev/bpfN, BIOCSETIF bind, header-complete write
│   └── TraceLog.cs            # Lightweight runtime trace logging (trace.log under LocalApplicationData/ProtocolForge/logs)
│
├── ViewModels/                # MVVM ViewModels
│   ├── MainWindowViewModel.cs # Orchestrator: commands (open/save/export), cross-panel wiring, read-only propagation, hex↔tree sync
│   ├── PacketListViewModel.cs # Packet selection, document binding
│   ├── ProtocolTreeViewModel.cs # Protocol layer/field tree, field click → hex highlight, inline value editing (Enter/Esc/click-away), VBC commit, tree reveal for hex selection
│   ├── HexEditorViewModel.cs  # Hex rendering + REPLACE-only inline hex editing, selection/highlight, edited-byte marking, reverse-sync events
│   ├── ToolBarViewModel.cs    # Start/Pause/Stop send commands, interval/loops, interface dropdown
│   └── ViewModelBase.cs       # Common ObservableObject base class
│
├── Views/                     # Avalonia XAML + code-behind
│   ├── MainWindow.axaml       # Full window layout: menu, toolbar, packet list, splitter, tree, hex
│   ├── MainWindow.axaml.cs    # File dialogs, layout restore/save, menu handlers
│   └── Controls/
│       ├── HexEditor.axaml.cs # Custom hex viewer: 16-byte rows, click/keyboard navigation, visual state
│       ├── HexEditor.axaml    # Minimal XAML — everything built in code-behind
│       ├── ProtocolTreeView.axaml  # TreeView with field data templates
│       ├── ProtocolTreeView.axaml.cs # Click/double-click/context-menu handlers for selection and inline editing
│       └── DoubleClickAutoFit.cs  # Double-click column divider → auto-fit column width (attached behavior)
│
├── Converters/                # XAML value converters
│   ├── HexByteColorConverter.cs    # Multi-converters for byte backgrounds (selected/highlighted/modified)
│   └── BoolToStringConverter.cs    # Pause/Resume button text
│
└── ViewLocator.cs             # Convention-based View → ViewModel resolution
```

A standalone verification harness lives in `tests/pf-verify/` (an independent console
project referencing `ProtocolForge`). It exercises the runtime service layer against the
sample capture (supply one with `PF_CAPTURE`; capture-dependent groups are skipped when absent) — edit-fence verdicts on a fixed frame, Verify-Before-Commit
legal/illegal scenarios (commit, offset-drift abort, length-change rejection, byte-identity
guarantees), the tshark version gate (real env + fake old/current binaries via `TSHARK_PATH`),
read-only loading, hex-edit code-surface checks, and localization dictionary checks (GROUP 11). Run with
`dotnet run --project tests/pf-verify`; every assertion passes with tshark 3.6.2+ installed.

---

## Tshark Integration (Streaming List + On-Demand Tree)

Loading a capture is split into two stages so even large files (180k+ packets) open in seconds instead of minutes. Both stages are preceded by a **version gate**: on startup and after any path change, `TsharkService.DetectTshark()` runs `tshark -v` and compares the parsed version against 2.6.0. If the check fails the app falls into read-only mode (banner + disabled editors); if it passes, normal editing is unlocked.

### Stage 1 — Packet list: one streamed `-T fields` pass

1. `PcapIngestService` natively reads the PCAP/PCAPNG headers and raw packet bytes (fast, no tshark).
2. `TsharkService.LoadPcapAsync()` then runs a **single** `tshark -T fields` process and streams its rows line-by-line:
   `-e frame.number -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -e _ws.col.Info`
   Each row is split on tabs (max 5 splits — the Info column may contain tabs) and appended to the document's packet collection as it arrives, so the DataGrid fills progressively and the UI stays responsive.
3. Progress is reported every 500 packets (`0.05 + 0.9·count/total`), and the frame numbers from tshark align rows to the raw-ingested packets, tolerating skipped/malformed frames.

### Stage 2 — Protocol tree: per-packet, on demand

The tree is not built for the whole file. When a packet is selected:

1. `PcapExportService.SavePacketAsync()` writes **that single packet** (using its effective, possibly edited bytes) to a temp PCAP.
2. `TsharkService.BuildPacketTreeAsync()` runs `-T jsonraw`, `-T json`, and `-T pdml` **in parallel** on that temp file (~0.4s per packet).
3. The three-pass jsonraw parser merges the results into the packet's `Layers`; `ExtractAddressInfo()` updates the address/port columns from the parsed fields.
4. A per-selection sequence guard (`_treeBuildSeq`) discards stale results if the user clicks another packet while a build is in flight.

Tshark's `-T jsonraw` output for a packet has this format:

```json
{
  "_source": {
    "layers": {
      "ip": {
        "ip.src_raw": ["ac1583a8", 26, 4, 0, 1],
        "ip.src_tree": { ... },
        "ip.dst_raw": ["ac1583a8", 30, 4, 0, 1]
      }
    }
  }
}
```

The core jsonraw parser (`TsharkService.ParseJsonrawObject()`) handles the raw JSON in three passes:

| Pass | What | Why |
|------|------|-----|
| **1** | Collect all `*_raw` arrays into a dictionary | Index raw byte info (hex, offset, length) by base field name |
| **2** | Process `*_tree` objects and nested sub-objects recursively | Build the hierarchical protocol field tree; attach raw info from pass 1 |
| **3** | Emit orphaned `_raw` entries | Fields like `ip.src_raw` that have no `_tree` parent still get a `ProtocolField` entry |

Address and port extraction runs inside the on-demand tree build: `ExtractAddressInfo()` scans the parsed fields of the selected packet for `src`/`dst` IPs and `srcport`/`dstport` numbers, converting hex to human-readable form and refreshing the packet-list columns.

### Post-Edit Refresh (Single-Packet Reparse)

Tree and hex edits both flow through `EditTransactionService` (Verify-Before-Commit):

1. `PcapExportService.SavePacketAsync()` writes the single modified packet to a temp PCAP (with surrounding context frames when the packet needs SDP/IP-fragment context for correct dissection)
2. `TsharkService.ReparseSinglePacketAsync()` runs tshark `-T pdml` on that temp file and collects a `(field name, byte offset) → showname` + raw value lookup table
3. Before committing, the reparse must show the **new value landing at the expected position** — offset drift, a value mismatch, or a length change aborts the transaction and the packet stays byte-identical
4. On success, `ProtocolTreeViewModel.RefreshFieldDisplays()` walks the existing tree in place, patching each field's Name/DisplayValue from the fresh PDML text

This keeps the tree stable (selection, expansion state preserved) while the displayed texts catch up to edited bytes. Anonymous IE containers — PFCP/NGAP IEs emitted by tshark as `<field name="" show="…">`, whose rendered text like `F-SEID : SEID: 0x…, IPv4 …` changes with their children's bytes — are matched by offset only (empty name key), so a SEID edit propagates into the surrounding container display without touching the tree structure.

---

## Packet Injection Strategy

`PacketSendService` probes a native L2 rung once per session (Npcap on Windows, BPF on macOS), then tries the available send rungs in order, falling through when a rung cannot deliver:

```
┌─────────────────────────────────────────┐
│       Send Rung Strategy                │
├─────────────────────────────────────────┤
│ 0. Npcap (Windows) / BPF (macOS), opt.  │
│    → Sends complete Ethernet frames     │
│    → Npcap: user-installed wpcap.dll    │
│    → BPF: /dev/bpfN, requires root      │
│    → Absent when the native path is     │
│    → unavailable; Npcap enables Win TCP │
├─────────────────────────────────────────┤
│ 1. AF_PACKET raw (Linux only)           │
│    → Sends complete Ethernet frames     │
│    → Requires CAP_NET_RAW / root        │
├─────────────────────────────────────────┤
│ 2. IP raw socket (cross-platform)        │
│    → Sends IP datagrams                 │
│    → Requires admin/root                │
├─────────────────────────────────────────┤
│ 3. UDP socket (always works)             │
│    → Sends only UDP payload             │
│    → No privileges needed               │
│    → Extracts destination from IP hdr   │
└─────────────────────────────────────────┘
```

The native L2 rung is never bundled or silently installed: on Windows the app only detects an existing user Npcap install (per Npcap's free SDK license terms), on macOS it only opens an existing `/dev/bpfN` device. The socket ladder takes over whenever the probe fails — missing DLL, no root, access denied, or no matching device all produce the same pure-managed behavior as before. Per-packet, a rung that cannot deliver (e.g. a bare IP datagram has no Ethernet frame) descends to the next rung; L2 failures are no exception. When using UDP fallback, the service extracts the destination IP and port from the raw packet's IP/UDP headers, sending only the payload — losing outer headers but working without privileges.

---

## Getting Started

### Prerequisites

> **End users**: download a **self-contained** release — the .NET 8 runtime is bundled, so you install **nothing** but Wireshark (below). No separate .NET install needed.
- **Wireshark / tshark (≥ 2.6.0)** — Protocol parsing requires tshark 2.6.0 or later on PATH (or via `TSHARK_PATH`). Older tshark versions open the app in read-only mode. Download from [wireshark.org](https://www.wireshark.org/download.html).
- **.NET 8 SDK** (8.0.421 or later, **builders/contributors only**) — required to compile from source; not needed to run a self-contained build.
  - Linux: `sudo apt install tshark`
  - macOS: `brew install wireshark`
  - Windows 10/11 x64: install Wireshark; keep the Npcap option enabled (selected by default). The app does not bundle Npcap.

### Build & Run

```bash
# From the repository root
dotnet build ProtocolForge.sln

# Run
dotnet run --project ProtocolForge/ProtocolForge.csproj

# Open a PCAP file from the command line
dotnet run --project ProtocolForge/ProtocolForge.csproj -- path/to/capture.pcap

# Run the verification harness (requires tshark >= 2.6.0)
dotnet run --project tests/pf-verify/PfVerify.csproj
```

### First Run

1. Launch the application
2. Use **File → Open PCAP** (Ctrl+O) to load a `.pcap` file
3. Click packets in the list to inspect their protocol tree and hex bytes
4. Edit packet content in either panel:
   - **Protocol tree**: right-click an editable field (or double-click it) and type a new value — decimal, IP/MAC, string, or `0x…` hex; press Enter to apply, Esc to cancel. Fields that fail the edit fence show `Not editable: …` and refuse to open.
   - **Hex viewer**: click a byte offset, then type hex digits (0-9/A-F/NumPad) to start a replace run; the pending value previews in yellow, Enter commits the whole run at once, Esc cancels.
   Both routes run the Verify-Before-Commit reparse — committed edits that don't land are rejected. Modified bytes are marked in orange in the hex viewer.
5. Save modifications with **File → Save PCAP** (Ctrl+S) or **Export PCAP As** (Ctrl+Shift+S)
6. Check the packets you want to send (per-packet checkboxes, or the packet list's right-click context menu), select a network adapter, and set interval/loop count. Click **Start** to send directly through the selected physical adapter. Auto-fix is off by default and only changes the frame preparation behavior.

> If tshark is missing or older than 2.6.0, a banner appears and the app runs read-only: packets load, but the tree/hex editors, export, and send are disabled until a valid tshark is configured via **File → Tshark Path…**.

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `TSHARK_PATH` | Override tshark executable location (auto-detect falls back to PATH and common install paths). The path chosen via **File → Tshark Path…** is also persisted across sessions. |

### CI and release packages

- GitHub Actions: `.github/workflows/ci.yml`
- The workflow builds with warnings treated as errors, runs the `pf-verify` harness, rejects newly added or modified `.pcap`/`.pcapng` files, produces the Windows x64 artifact, and builds Linux x64 multi-file packages.
- Linux packages are generated by [`packaging/linux/publish-linux.sh`](packaging/linux/publish-linux.sh):
  - `ProtocolForge-<version>-linux-x86_64.AppImage`
  - `protocolforge_<version>_amd64.deb`
  - `SHA256SUMS`
- The Linux publish is multi-file (`PublishSingleFile=false`); the AppImage hides the multi-file layout behind one launcher.
- Local Linux package build:

```bash
./packaging/linux/publish-linux.sh
```

- Windows multi-file package is generated by [`packaging/windows/publish-windows.ps1`](packaging/windows/publish-windows.ps1) on Windows or [`publish-windows.sh`](packaging/windows/publish-windows.sh) on a Linux CI runner. It produces `ProtocolForge-<version>-win-x86_64.zip` and `SHA256SUMS`.
- Local Windows PowerShell build:

```powershell
./packaging/windows/publish-windows.ps1
```

- The packaging scripts ship an **unobfuscated** assembly by default. If you produce an obfuscated `ProtocolForge.dll` yourself, point `OBFUSCATED_DLL` at it and the AppImage, deb, and Windows ZIP will carry that assembly instead (verified by comparing the md5 printed by the packaging script against the file you supplied):

```bash
OBFUSCATED_DLL=/path/to/ProtocolForge.dll ./packaging/linux/publish-linux.sh
OBFUSCATED_DLL=/path/to/ProtocolForge.dll ./packaging/windows/publish-windows.sh
```

Obfuscate only this project's assembly, and preserve public type/member names — XAML bindings, `ViewLocator` reflection, and JSON persistence all resolve members by name at runtime and will fail to bind if they are renamed. Pointing `OBFUSCATED_DLL` at a missing file fails the build rather than silently shipping a clean assembly. CI does not set it, so published artifacts stay unobfuscated.

Real captures remain local-only. Use generated fixtures for CI, tests, screenshots, and marketing material; sanitize any real capture before it is used outside the workstation.

---

## Secondary Development Guide

### Adding a New Protocol Parser

ProtocolForge doesn't ship protocol parsers — it relies entirely on tshark. To add support for a new protocol:

1. Ensure tshark has a dissector for it (most 3GPP protocols are supported in recent Wireshark)
2. The three-pass jsonraw parser automatically handles any protocol tshark outputs
3. To customize highlighting: add a color entry in `HexEditorViewModel.GetHighlightColor()` for the protocol name

### Adding a New Service

1. Create the service class in `Services/`
2. Instantiate it in `App.axaml.cs` in the correct dependency order
3. Inject it into the relevant ViewModel(s) via constructor parameter
4. Wire event handlers in the ViewModel constructor

### Localizing New Strings

All user-visible strings are externalized into the localization dictionaries in `Assets/Lang/`. To localize a new string, add the key to **both** `en-US.json` and `zh-CN.json` (identical key, matching placeholder count), then reference it from XAML as `{DynamicResource L10n.Key}` or from C# as `LocalizationService.Resolve("Key", args…)`. Switching the language via the **语言 / Language** menu needs no extra wiring — `SetCurrent` persists the choice automatically.

### Adding a New ViewModel

1. Inherit from `ObservableObject` (CommunityToolkit.Mvvm)
2. Use `[ObservableProperty]` for bindable properties
3. Use `[RelayCommand]` for commands
4. Expose as a public property on an existing ViewModel or register in DI
5. Create the corresponding View XAML control (by convention, `FooViewModel` → `FooView`)

### Cross-Platform Considerations

- **File paths**: Use `Path.Combine()` and `Environment.GetFolderPath(SpecialFolder.ApplicationData)` — never hardcode paths.
- **Network interfaces**: `NetworkInterfaceService` uses `System.Net.NetworkInformation` which is fully cross-platform.
- **Socket types**: `PacketSendService` uses `OperatingSystem.IsLinux()` to select AF_PACKET, `OperatingSystem.IsMacOS()` to probe the `/dev/bpfN` L2 rung; IP raw sockets work on Windows, Linux, and macOS.
- **Conditional compilation**: Minimized — only `OperatingSystem.IsWindows()`/`IsLinux()`/`IsMacOS()` runtime checks.

### Trace Log

Runtime diagnostics are written to `trace.log` under the local application data folder (`%LOCALAPPDATA%/ProtocolForge/logs/trace.log` on Windows, `~/.local/share/ProtocolForge/logs/trace.log` on Linux, `~/Library/Application Support/ProtocolForge/logs/trace.log` on macOS). It records packet loads, selections, and send activity — consult it when investigating behavioral issues.

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| Avalonia | 12.0.5 | Cross-platform UI framework |
| Avalonia.Desktop | 12.0.5 | Desktop backend |
| Avalonia.Themes.Fluent | 12.0.5 | Fluent design theme |
| Avalonia.Fonts.Inter | 12.0.5 | Inter font |
| Avalonia.Controls.DataGrid | 12.0.1 | Packet list grid: sorting + double-click column auto-fit |
| AvaloniaUI.DiagnosticsSupport | 2.2.1 | Dev-only diagnostics integration (Debug builds) |
| CommunityToolkit.Mvvm | 8.4.2 | MVVM source generators (ObservableProperty, RelayCommand) |

External runtime dependency: **tshark ≥ 2.6.0** (part of Wireshark) for protocol parsing.

---

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) for the full text.

**Everything currently shipped in this repository is free and unlimited.** The daily send quota was removed on 2026-09-29; there is no feature gate, no telemetry, and no network call of any kind in the license path.

A dev-time offline signed-license subsystem existed during development and was **removed before public release**. It never gated any feature to begin with, and because Apache-2.0 requires any distributed derivative work to remain Apache-2.0, retaining a proprietary license path would only create a licensing contradiction rather than a business model.

### Third-party components

- **tshark / Wireshark** (≥ 2.6.0) is the only runtime dependency and is **not bundled** — you install it yourself. ProtocolForge runs it as a separate process and communicates over pipes; it does not link `libwireshark`. See [`docs/Npcap-Attribution.md`](docs/Npcap-Attribution.md) for attribution and the Npcap distribution terms.
- **Npcap** is never bundled or silently installed, per its free-sdk license terms.
