## What this changes

<!-- One or two sentences. -->

## Related issue

<!-- Closes #123, or "none". -->

## Verification — all Required

- [ ] `dotnet build ProtocolForge.sln` → **0 warnings, 0 errors** (CI builds with `-warnaserror`)
- [ ] `dotnet run --project tests/pf-verify` → **ALL GROUPS PASS**
- [ ] If the footer says `GROUP(S) SKIPPED`, this run is **not** full coverage — say so here and state which groups skipped and why
- [ ] `dotnet run --project ProtocolForge/ProtocolForge.csproj` still launches and the affected flow works

## Conventions

- [ ] New user-visible strings added to **both** `ProtocolForge/Assets/Lang/en-US.json` and `zh-CN.json`, with matching `{0}` placeholder counts
- [ ] New services instantiated in `App.axaml.cs` in dependency order
- [ ] No IoC container introduced (this project uses manual DI by design)
- [ ] Line endings: CRLF for `.cs`/`.axaml`/`.csproj`/`.md`/`.json`; **LF for `.sh` and `.yml`**
- [ ] No real `.pcap`/`.pcapng` added (CI rejects this)

## Screenshots

<!-- Required for any UI change. Use synthetic captures only. -->
