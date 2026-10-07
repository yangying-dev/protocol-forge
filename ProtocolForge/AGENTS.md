# ProtocolForge/ — MVVM Application Core

**Parent:** [`/AGENTS.md`](../AGENTS.md)

## OVERVIEW
The main Avalonia application: packet parsing (tshark), field-level editing (fence + Verify-Before-Commit), hex viewer, and packet injection, wired via manual DI in `App.axaml.cs`.

## STRUCTURE
```
ProtocolForge/
├── Services/      # 16 files — all business logic (largest: TsharkService 2156 lines)
├── ViewModels/    # 6 files — CommunityToolkit.Mvvm; events, not references
├── Models/        # 8 files — domain objects incl. Packet + ProtocolField
├── Views/         # MainWindow + Controls/ (HexEditor, ProtocolTreeView)
├── Converters/    # HexByteColorConverter + BoolToStringConverter
└── App.axaml.cs   # Manual DI composition root (in dependency order)
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Manual DI composition root | `App.axaml.cs` | New service → instantiate here, in dependency order |
| Entry/Program | `Program.cs` | Avalonia bootstrap + trace.log listener setup |
| tshark integration | `Services/TsharkService.cs` | Streamed `-T fields` list, per-packet jsonraw tree, PDML reparse, version gate |
| Verify-Before-Commit | `Services/EditTransactionService.cs` | Candidate → temp PCAP → reparse → verify (name, offset) → commit/abort |
| Edit fence | `Services/ProtocolEditorService.cs` | `CheckTreeEditFence` — 6 checks before a field is editable |
| Send rung ladder | `Services/PacketSendService.cs` + `IL2SendRung.cs`, `NpcapSendService.cs`, `BpfSendService.cs` | L2(native) → AF_PACKET → IP raw → UDP |
| Hex editing | `ViewModels/HexEditorViewModel.cs` + `Views/Controls/HexEditor.axaml.cs` | REPLACE-only runs, pending preview, Enter/Esc |
| Tree ↔ hex sync | `ViewModels/MainWindowViewModel.cs`, `ProtocolTreeViewModel.cs` | `FieldSelected`, `FieldFoundAtOffset`, `_treeBuildSeq` |
| Layout persistence | `Services/LayoutService.cs` | JSON in ApplicationData |

## CONVENTIONS

- **Services are standalone** — no VM references; they expose events/records (`PacketSendResult`, `EditResult`, `PdmlData`) for consumers.
- **Split static/instance services** — instance (`sealed class`, DI'd in `App.axaml.cs`): Tshark, Pcap Ingest/Export, EditTransaction, ProtocolEditor, PacketSend, NetworkInterface, Layout, TsharkSettings. Static (`static class`, no DI): `PacketPrepareService`, `NpcapSendService`, `BpfSendService`, `TraceLog`.
- **No async void** — commands use `[AsyncRelayCommand]`; services return `Task<T>` with `CancellationToken` params.
- **Records for results** — `sealed record` used for DTOs/verdicts (`TsharkDetection`, `EditResult`, `PdmlData`, `PacketSendResult`).
- **Streaming/progressive loading** — packet list fills incrementally; trees build on demand per packet (~0.4s). Never parse full files into memory.
- **Parallel tshark invocations** — `BuildPacketTreeAsync` runs `-T jsonraw`/`json`/`pdml` concurrently.
- **P/Invoke and native probing isolated** — `NpcapSendService`/`BpfSendService` implement `IL2SendRung`; failures degrade silently to managed sockets.
- **ViewModel inheritance is inconsistent** — only `MainWindowViewModel` extends the (empty) `ViewModelBase`; the other four extend `ObservableObject` directly. Follow the file you're editing.

## ANTI-PATTERNS

- **Never mutate packet length** — edits are REPLACE-only; `ProtocolField` offsets must stay valid.
- **Never bypass `EditTransactionService`** for field edits — no direct `ApplyModification` outside VBC.
- **Never rebuild the tree from scratch on edit** — use `RefreshFieldDisplays()` (in-place PDML text patch) to preserve selection/expansion.
- **Never let stale async results clobber UI** — respect `_treeBuildSeq` (selection), `_reparseVersions` (per-packet refresh), `_prefetchSeq` (neighbor prefetch).
- **Don't call tshark at startup repeatedly** — context providers (`dlts`-scoped scans: SDP, IP fragments, TCP reassembly) run lazily on first need.

## NOTES

- `ProtocolField` = offset/length/raw bytes/children + PDML name (for re-link); `Packet.EffectiveData` = `ModifiedData ?? RawData`.
- Threading: ViewModels `await` service calls directly (no `ConfigureAwait(false)`) — Avalonia's UI `SynchronizationContext` resumes on the UI thread. `Dispatcher.UIThread.Post` is only used in View code-behind for view-layer self-sync.
- `app.manifest` is the standard Avalonia manifest (assemblyIdentity + Windows 10 supportedOS for window transparency/compatibility); it does NOT request admin elevation — raw-socket admin rights come from running the app elevated externally.