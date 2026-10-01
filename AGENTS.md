# PROJECT KNOWLEDGE BASE

**Generated:** 2026-09-17
**Commit:** 44dd21a
**Branch:** main

## OVERVIEW
ProtocolForge is a cross-platform .NET 8 + Avalonia desktop app for inspecting, editing, and replaying 3GPP protocol packets (PFCP, NGAP, GTP-U, NAS, S1AP, Diameter) from PCAP files. Combines tshark's dissection engine with a native hex/tree editor and raw socket injection. UI text is Chinese (zh-CN).

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
| Cross-panel orchestration | `ProtocolForge/ViewModels/MainWindowViewModel.cs` | Event wiring, read-only propagation |
| Verification harness | `tests/pf-verify/Program.cs` | Run: `dotnet run --project tests/pf-verify` |
| Marker types | `ProtocolForge/Models/TsharkJsonModels.cs` | "legacy" — most parsing is manual |

## CONVENTIONS

- **MVVM + Manual DI** — No IoC container. Services instantiated in `App.axaml.cs`; ViewModels get dependencies via constructor. New service = add to App.axaml.cs in dependency order.
- **CommunityToolkit.Mvvm source generators** — `[ObservableProperty]` on private fields (generated public property), `[RelayCommand]`/`[AsyncRelayCommand]` for commands.
- **Views use code-behind** for event handling (Avalonia XAML + `.axaml.cs`); `ViewLocator.cs` maps `FooViewModel` → `FooView` by convention.
- **Runtime OS checks only** — `OperatingSystem.IsWindows()/IsLinux()/IsMacOS()`. `#if` conditional compilation minimized (only `DEBUG` for dev tools).
- **net8.0, nullable enable, ImplicitUsings enable, AvaloniaUseCompiledBindingsByDefault=true**.
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
- tshark version gate minimum is **2.6.0** everywhere — code (`TsharkService.VersionCompare`, `TsharkService.cs:373`) and README agree; there is no 4.0 gate anywhere in the app. The only textual "4.0" left in the repo is a comment in `tests/pf-verify/Program.cs:169` (not a gate).
- Packet send failures / status text mixed Chinese/English in UI.

## COMMANDS

```bash
dotnet build                              # Build solution (does NOT build tests/pf-verify)
dotnet run --project ProtocolForge        # Run app
dotnet run --project ProtocolForge -- path/to/capture.pcap   # Open file on launch
dotnet run --project tests/pf-verify      # Verify harness (needs tshark ≥3.6.2; PF_CAPTURE=<file.pcap> enables capture-dependent groups)
./packaging/linux/publish-linux.sh        # Multi-file Linux AppImage + deb (requires appimagetool)
./packaging/windows/publish-windows.ps1   # Multi-file Windows x64 ZIP (PowerShell)
```

`OBFUSCATED_DLL=<混淆后 ProtocolForge.dll>` 可让三个打包脚本把混淆程序集注入客户安装包；不设则产出未混淆包（CI 亦如此）。

## NOTES

- **tshark is the only external runtime dependency** (≥2.6.0, code + README + FullFunctionTest 三方一致). Detect via `TSHARK_PATH` env var → saved user path → PATH → known install locations.
- **Free tier** — everything currently shipped is free and unlimited; the daily send cap was removed on 2026-09-29. `Packet.SendSelected` defaults to false.
- **trace.log** is written under `LocalApplicationData/ProtocolForge/logs/` (`%LOCALAPPDATA%/ProtocolForge/logs/trace.log` on Windows, `~/.local/share/ProtocolForge/logs/trace.log` on Linux, `~/Library/Application Support/ProtocolForge/logs/trace.log` on macOS) via a `TextWriterTraceListener`; settings remain under ApplicationData.
- Capture files can exceed 180k packets; list loading is streamed (`-T fields` line-by-line) and protocol trees build per-packet on demand (~0.4s/packet) — never design for full-file tree parsing.
- **Real captures are local-only and never committed** — `.gitignore` ignores `*.pcap`/`*.pcapng` and CI rejects new or modified ones. Exercise capture-dependent code paths with `PF_CAPTURE=<path>`; a capture-less run reports those groups as `SKIP` and still exits 0.
- **`tests/pf-verify` is NOT in the solution** — `dotnet build` skips it; run it explicitly (`dotnet run --project tests/pf-verify`), and `ProtocolForge.sln` only contains the app project.
- **QA gate (docs/RealDeviceQA.md)**: `dotnet build` must be 0 warnings / 0 errors, and `tests/pf-verify` must print "ALL GROUPS PASS" (it may append a `(N group(s) skipped — no capture fixture)` note when `PF_CAPTURE` is unset).
- **`.gitignore` and `.editorconfig` both exist** — `.gitignore` covers `bin/ obj/ artifacts/ release/`, IDE/OS files, `.env*`, `*.log`, agent working state (`.omo/ .gstack/ .workflow/`), and `*.pcap`/`*.pcapng` (real captures are local-only and CI rejects them). `.editorconfig` mirrors `.gitattributes` exactly (LF for `*.sh`/`*.yml`/`*.yaml`, CRLF for `*.cs`/`*.axaml`/etc., with deliberately no global `[*] end_of_line` rule). There is still no analyzer or lint config, so style is otherwise matched by hand (4-space indent, file-scoped namespaces, Chinese comments).
- **Localization dictionaries hold 148 keys each** (`Assets/Lang/en-US.json` + `zh-CN.json`, identical key sets).
- **CI** — `.github/workflows/ci.yml` builds with warnings-as-errors, runs the `pf-verify` harness, and rejects added or modified `.pcap`/`.pcapng`. `pf-verify` is a hand-rolled assertion console app (not xUnit/NUnit) and is not referenced by the solution, so `dotnet build` alone does not run it.