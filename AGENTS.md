# PROJECT KNOWLEDGE BASE

**Generated:** 2026-09-17
**Commit:** 44dd21a
**Branch:** main

## OVERVIEW
ProtocolForge is a cross-platform .NET 10 + Avalonia desktop app for inspecting, editing, and replaying 3GPP protocol packets (PFCP, NGAP, GTP-U, NAS, S1AP, Diameter) from PCAP files. Combines tshark's dissection engine with a native hex/tree editor and raw socket injection. UI text is Chinese (zh-CN).

## STRUCTURE
```
protocol-forge/
├── ProtocolForge/         # Main app: Models, Services, ViewModels, Views (MVVM)
├── tests/pf-verify/       # Standalone console assertion harness (no test framework)
├── packaging/linux/       # Multi-file Linux AppImage + deb packaging
├── packaging/windows/     # Multi-file Windows x64 ZIP packaging
├── docs/                  # Npcap attribution + real-device QA notes
├── ProtocolForge.sln      # Single-project solution (Debug/Release × Any CPU)
└── README.md / README.zh-CN.md
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| tshark integration, tree building, version gate | `ProtocolForge/Services/TsharkService.cs` | 2156 lines — largest file |
| Edit fence + field-level edits | `ProtocolForge/Services/ProtocolEditorService.cs`, `EditTransactionService.cs` | VBC reparse verification |
| Hex display + inline hex editing | `ProtocolForge/ViewModels/HexEditorViewModel.cs`, `Views/Controls/HexEditor.axaml.cs` | REPLACE-only editing |
| Packet injection rung ladder | `ProtocolForge/Services/PacketSendService.cs` | Npcap/BPF/AF_PACKET/IP/UDP fallback |
| Manual DI composition | `ProtocolForge/App.axaml.cs` | All services constructed here in order |
| Cross-panel orchestration | `ProtocolForge/ViewModels/MainWindowViewModel.cs` | Event wiring, read-only propagation, dock pane toggles/persistence |
| Dock layout (panes, factory) | `ProtocolForge/ViewModels/Panes.cs`, `DockLayoutFactory.cs` | Dock 12.1.0.7; pane ids `pane.packet-list/-tree/-editor/-statistics`; hidden-pane restore tracked via `PaneDock.OriginalOwnerId` (Dock's `OriginalOwner` is not serialized) |
| Verification harness | `tests/pf-verify/Program.cs` | Run: `dotnet run --project tests/pf-verify`. Generates its own 4413-frame fixture when `PF_CAPTURE` is unset |
| Headless CLI | `ProtocolForge/Cli/HeadlessCli.cs` | `validate`/`edit`/`send`/`stats`; branched from `Program.Main` before Avalonia starts. Exit 0/1/2 |
| Statistics taps | `ProtocolForge/Services/TsharkService.cs` → `RunStatisticsTapAsync` | tshark `-z`. Taps ignore `-Y`; the filter goes in the tap argument |
| PCAPNG writing | `ProtocolForge/Services/PcapngWriter.cs` | SHB/IDB/EPB, single section. `PacketExportOptions.Pcapng` selects it |
| Enum interpretations | `ProtocolForge/Services/EnumCatalog.cs` | Session-scoped, harvested from PDML during dissection. Not a spec table |
| Marker types | `ProtocolForge/Models/TsharkJsonModels.cs` | "legacy" — most parsing is manual |
| User manual | `ProtocolForge/Manual/UserManual.html` (shipped; source `docs/manual/`) | Single self-contained bilingual HTML, base64 screenshots; ships via csproj `<Content Include="Manual\**">` and opens from **帮助 → 用户手册** in the default browser. Regenerate from `docs/manual/` + inlining rather than hand-editing |

## CONVENTIONS

- **MVVM + Manual DI** — No IoC container. Services instantiated in `App.axaml.cs`; ViewModels get dependencies via constructor. New service = add to App.axaml.cs in dependency order.
- **CommunityToolkit.Mvvm source generators** — `[ObservableProperty]` on private fields (generated public property), `[RelayCommand]`/`[AsyncRelayCommand]` for commands.
- **Views use code-behind** for event handling (Avalonia XAML + `.axaml.cs`); views are constructed directly — there is no `ViewLocator`.
- **Runtime OS checks only** — `OperatingSystem.IsWindows()/IsLinux()/IsMacOS()`. `#if` conditional compilation minimized (only `DEBUG` for dev tools).
- **net10.0, nullable enable, ImplicitUsings enable, AvaloniaUseCompiledBindingsByDefault=true**.
- **Windows-style formatting** — CRLF line endings for `*.cs`/`*.axaml`/etc. and UTF-8 (Chinese comments and strings in source), per `.gitattributes` + `.editorconfig`. Not yet uniform on disk: a handful of `.cs` files are LF-only in the working tree and a few carry a stray UTF-8 BOM.
- **Events over references** — ViewModels communicate via events (`PacketSelected`, `FieldSelected`, `FieldEdited`, `HexEdited`, `FieldFoundAtOffset`), not direct references.

## ANTI-PATTERNS (THIS PROJECT)

- **DO NOT add an IoC container** — project deliberately uses manual DI.
- **DO NOT bundle native libraries** — Npcap/BPF are probed at runtime on Windows/macOS only; L2 rung must be optional. The app silently degrades to managed sockets when native L2 is unavailable.
- **DO NOT hardcode file paths** — use `Path.Combine()` + `Environment.GetFolderPath(SpecialFolder.ApplicationData)`.
- **DO NOT break packet length on edits** — hex editing is REPLACE-only; length-changing edits are rejected by design (offsets must stay valid).
- **DO NOT bypass the edit fence** — field edits must pass `CheckTreeEditFence` and go through `EditTransactionService` (Verify-Before-Commit tshark reparse).
- **Editing/parsing must respect the sequence guards** — `_treeBuildSeq`, `_reparseVersions`, `_prefetchSeq` exist to prevent stale async results overwriting newer state.

## UNIQUE STYLES

- Commit messages are in Chinese, `file(s) +Δlines` summary format (e.g. `TsharkService.cs +187:版本检测/门禁…`).
- README is fully bilingual (README.md EN, README.zh-CN.md ZH).
- tshark version gate minimum is **2.6.0** everywhere — code (`TsharkService.VersionCompare`, `TsharkService.cs:373`) and README agree; there is no 4.0 gate anywhere in the app. The only textual "4.0" left in the code is the G2b assertion's detail string in `tests/pf-verify/Program.cs` (not a gate).
- Packet send failures / status text mixed Chinese/English in UI.

## COMMANDS

```bash
dotnet build                              # Build solution (compiles tests/pf-verify too; does not run it)
dotnet run --project ProtocolForge        # Run app
dotnet run --project ProtocolForge -- path/to/capture.pcap   # Open file on launch
dotnet run --project tests/pf-verify      # Verify harness (needs tshark ≥3.6.2; PF_CAPTURE=<file.pcap> enables capture-dependent groups)
dotnet run --project tests/pf-verify -- --only 54   # Print only GROUP 54 (--group <title-text> matches banner titles)
./packaging/linux/publish-linux.sh        # Multi-file Linux AppImage + deb (requires appimagetool)
./packaging/windows/publish-windows.ps1   # Multi-file Windows x64 ZIP (PowerShell)
```

`OBFUSCATED_DLL=<混淆后 ProtocolForge.dll>` 可让三个打包脚本把混淆程序集注入客户安装包；不设则产出未混淆包（CI 亦如此）。

## NOTES

- **tshark is the only external runtime dependency** (≥2.6.0, code + README + FullFunctionTest 三方一致). Detect via `TSHARK_PATH` env var → saved user path → PATH → known install locations.
- **Free tier** — everything currently shipped is free and unlimited; the daily send cap was removed on 2026-09-29. `Packet.SendSelected` defaults to false.
- **trace.log** is written under `LocalApplicationData/ProtocolForge/logs/` (`%LOCALAPPDATA%/ProtocolForge/logs/trace.log` on Windows, `~/.local/share/ProtocolForge/logs/trace.log` on Linux, `~/Library/Application Support/ProtocolForge/logs/trace.log` on macOS) via a `TextWriterTraceListener`; settings remain under ApplicationData.
- Capture files can exceed 180k packets; list loading is streamed (`-T fields` line-by-line) and protocol trees build per-packet on demand (~0.4s/packet) — never design for full-file tree parsing.
- **Real captures are local-only and never committed** — `.gitignore` ignores `*.pcap`/`*.pcapng` and CI rejects new or modified ones. When `PF_CAPTURE` is unset the harness **generates** a 4413-frame synthetic capture into the temp directory and deletes it after, so the capture-dependent groups run in CI; a bare run reports 414 PASS / 0 FAIL / 1 SKIP, the one skip being `G17-13` (needs the ≥180k-packet pcapng that cannot be synthesised). Point `PF_CAPTURE` at a capture **smaller than 4413 frames** and `G1`/`G16`/`G19` fail rather than skip.
- **`tests/pf-verify` is in the solution** — `dotnet build` compiles it (harness compile errors surface in the default build) but does not run it; run it explicitly (`dotnet run --project tests/pf-verify`). Its output can be filtered with `--only <group#>` / `--group <title-text>`; filtering is **output-only** — every group still executes and FAIL lines always print, so a filtered run can never look green. New group banners and detail lines must go through the harness's `Banner(n, title)` / `Detail(text)` helpers, otherwise they leak through the filter. `LocalizationService.SetCurrent` re-publishes even when the language is unchanged (the Avalonia `Application` can appear after the first call), so group order cannot leave XAML resources empty.
- **QA gate (docs/RealDeviceQA.md)**: `dotnet build` must be 0 warnings / 0 errors, and `tests/pf-verify` must print "ALL GROUPS PASS" (it may append a `(N group(s) skipped — no capture fixture)` note when `PF_CAPTURE` is unset).
- **Two layout files** — `layout.json` holds window geometry + `ShowX` pane-visibility flags (LayoutService.LayoutState, still harness-tested directly); `docklayout.json` holds the serialized Dock tree (DockSerializer/System.Text.Json). Restored-hidden panes are re-wired to their owner via `OriginalOwnerId` after `InitLayout`, since `OriginalOwner` is `[IgnoreDataMember]`. Headless UI group G54 only runs via `dotnet run --project tests/pf-verify -- --ui` (separate process to avoid Avalonia init inside the assertion run), and it snapshots/restores `docklayout.json` around the run.
- **`.gitignore` and `.editorconfig` both exist** — `.gitignore` covers `bin/ obj/ artifacts/ release/`, IDE/OS files, `.env*`, `*.log`, agent working state (`.omo/ .gstack/ .workflow/`), and `*.pcap`/`*.pcapng` (real captures are local-only and CI rejects them). `.editorconfig` mirrors `.gitattributes` exactly (LF for `*.sh`/`*.yml`/`*.yaml`, CRLF for `*.cs`/`*.axaml`/etc., with deliberately no global `[*] end_of_line` rule). There is still no analyzer or lint config, so style is otherwise matched by hand (4-space indent, file-scoped namespaces, Chinese comments).
- **Localization dictionaries hold 229 keys each** (`Assets/Lang/en-US.json` + `zh-CN.json`, identical key sets).
- **CI** — `.github/workflows/ci.yml` builds with warnings-as-errors, runs the `pf-verify` harness, and rejects added or modified `.pcap`/`.pcapng`. `pf-verify` is a hand-rolled assertion console app (not xUnit/NUnit); it is part of the solution, so `dotnet build` compiles it, but `dotnet build` alone does not run it.