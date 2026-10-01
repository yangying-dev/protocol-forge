# Contributing to ProtocolForge

Thanks for looking at this. ProtocolForge is Apache-2.0 and there is no feature gate, so anything you can build on, you can ship. This document is the practical version: what to install, what to run, how the code is put together, and the one testing trap that has caught out contributors before.

Security reports do not go through the normal PR route. See [`SECURITY.md`](SECURITY.md).

## Prerequisites

| Need | Version | Who needs it |
|---|---|---|
| tshark (part of Wireshark) | **≥ 2.6.0** at runtime | Everyone, including end users. This is the app's tshark version gate. Below 2.6.0 the app opens captures read-only. |
| .NET SDK | **8.0.421 or later** | Builders and contributors only. End users do not need it: releases are self-contained. |
| tshark | **3.6.2 or later** | Contributors only, and only for the verification harness to reach a full pass. |

Those last two tshark floors are different on purpose. The **application** gate is 2.6.0. The **harness** needs 3.6.2. Running the harness on 2.6.x will pass some groups and fail others for reasons that have nothing to do with your change.

- Linux: `sudo apt install tshark`
- macOS: `brew install wireshark`
- Windows: install Wireshark from <https://www.wireshark.org/download.html>. Keep the Npcap option enabled if you want the rung-0 L2 send path; it is selected by default. ProtocolForge does not bundle Npcap and never installs it.

## Commands

```bash
# Build the application
dotnet build ProtocolForge.sln

# Build with warnings as errors (this is what CI does; match it locally)
dotnet build ProtocolForge.sln -c Release -warnaserror

# Run
dotnet run --project ProtocolForge/ProtocolForge.csproj

# Open a capture on launch
dotnet run --project ProtocolForge/ProtocolForge.csproj -- path/to/capture.pcap

# Run the verification harness
dotnet run --project tests/pf-verify/PfVerify.csproj

# Run the harness against a local capture fixture
PF_CAPTURE=/path/to/local.pcap dotnet run --project tests/pf-verify/PfVerify.csproj
```

CI runs the build with warnings as errors, so **`dotnet build ProtocolForge.sln -warnaserror` clean is the bar**, not "it compiled".

## Project conventions

### Architecture

- **MVVM with manual DI. There is deliberately no IoC container.** Do not add one. Services are constructed by hand in `App.axaml.cs`, in dependency order, and handed to ViewModels through constructor parameters. This is a decision, not an oversight.
- **CommunityToolkit.Mvvm source generators.** `[ObservableProperty]` on a private field generates the public bindable property. `[RelayCommand]` and `[AsyncRelayCommand]` generate commands. Do not hand-write `INotifyPropertyChanged` plumbing.
- **Views use code-behind.** Avalonia XAML plus a `.axaml.cs` for event handling. `HexEditor.axaml` is intentionally minimal because the hex view is built in code-behind; that is not an oversight either.
- **Events between ViewModels, not references.** `PacketSelected`, `FieldSelected`, `FieldEdited`, `HexEdited`, `FieldFoundAtOffset` and friends. A ViewModel must not hold a reference to another ViewModel.
- **`ViewLocator` maps `FooViewModel` to `FooView` by convention.** Renaming a ViewModel or its View silently breaks resolution, because the lookup is by name at runtime. This is also why obfuscating the assembly requires preserving public type and member names.

### Platform and filesystem

- **Runtime OS checks only.** Use `OperatingSystem.IsWindows()` / `IsLinux()` / `IsMacOS()`. Conditional compilation is minimized to `DEBUG` alone, for dev tools.
- **Never hardcode paths.** Use `Path.Combine()` with `Environment.GetFolderPath(SpecialFolder…)`. All application writes must stay inside the user profile.

### Sequence guards

`TsharkService` carries `_treeBuildSeq`, `_reparseVersions` and `_prefetchSeq`. They exist to stop a slow async tshark result from overwriting newer state when the operator clicks another packet mid-build. If you add an async tshark call, wire it into the guard. Skipping it will produce a bug that looks like a wrong-offset edit rather than a race, and it will not reproduce reliably.

### Edit safety invariants

Two rules are load-bearing. Breaking either is a correctness regression, not a style issue.

- **Hex editing is REPLACE-only.** Each edit run is built from full hex-digit pairs, so packet length never changes and every offset outside the edited span stays valid. Length-changing edits are rejected by design.
- **Nothing bypasses the edit fence.** Field edits must pass `CheckTreeEditFence` and go through `EditTransactionService`, which reparses with tshark and verifies the new value lands at the expected `(PDML name, byte offset)` before committing. Verify-Before-Commit is the reason this tool can be trusted to edit a capture; do not write a path that writes bytes directly.

### Text and encoding

- 4-space indent, file-scoped namespaces.
- **Chinese comments** in source. That is the house style, not an accident of history.
- **CRLF line endings** for `*.cs`, `*.axaml`, `*.csproj`, `*.sln`, `*.ps1`, `*.md` and `*.json`. **LF** for `*.sh` and `*.yml`. `.gitattributes` is the authority and `.editorconfig` mirrors it; there is deliberately no global CRLF rule, because one would rewrite `packaging/linux/publish-linux.sh` to CRLF on Linux and break it. If your diff shows every line changed, check your line endings first.
- UTF-8, no BOM surprises.

## Adding a new service

1. Put the class in `ProtocolForge/Services/`.
2. Instantiate it in `App.axaml.cs` **in dependency order** (its own dependencies must be constructed before it).
3. Pass it to the ViewModels that need it as a constructor parameter.
4. Wire its events in the ViewModel constructor, not in the view.

## Adding a localized string

1. Add the key to **`ProtocolForge/Assets/Lang/en-US.json`**.
2. Add the **same key** to **`ProtocolForge/Assets/Lang/zh-CN.json`**, with the **same placeholder count**. A key present in one dictionary and missing from the other, or with a different number of `{0}`-style placeholders, is a defect.
3. Reference it from XAML as `{DynamicResource L10n.Key}` or from C# as `LocalizationService.Resolve("Key", args…)`.

The language menu needs no extra wiring; `SetCurrent` persists the choice. The harness checks the two dictionaries against each other, so a mismatch fails the run.

## The verification harness, and the trap

`tests/pf-verify` is a **hand-rolled assertion console app**. It is not xUnit, not NUnit, and not referenced by `ProtocolForge.sln`, which means **`dotnet build` does not build it**. You have to run it explicitly:

```bash
dotnet run --project tests/pf-verify/PfVerify.csproj
```

It contains roughly 300 assertions grouped into numbered groups (G1 through G38, some numbers unused) and covers the tshark version gate, the edit-fence verdicts, Verify-Before-Commit commit / offset-drift abort / length-change rejection, read-only loading, hex-edit code surfaces, the send-ladder descent order, and localization dictionary consistency. It also writes `report.txt` next to the built binary.

### SKIP is not PASS

Read this before you treat a green run as full coverage.

**Six groups SKIP when no capture fixture is present, and the harness still exits 0.** Each skipped group is named with its real reason, and the footer refuses to let a partial run pass as a full one:

```text
ALL GROUPS PASS — 6 GROUP(S) SKIPPED, so this is NOT full coverage: x5 capture fixture absent — set PF_CAPTURE to a local .pcap; x1 large-capture.pcapng absent — large capture is local-only
```

That exit code is 0 by design, so a capture-less checkout still reports usefully. But the string `ALL GROUPS PASS` is not the whole line, and the exit code alone does not mean the capture-dependent groups ran. **Read the footer, and read the SKIP lines.** On a fresh clone with no `PF_CAPTURE`, most of the edit-fence and Verify-Before-Commit coverage is not being exercised at all.

### One group that `PF_CAPTURE` cannot satisfy

`G17-13` needs a specific large local pcapng (the ≥180k-packet real capture). It is not a generic fixture, and `PF_CAPTURE` cannot point at it. **So even with a capture set, one group still skips.** A fully green run with `PF_CAPTURE` set is therefore still short of complete coverage, by exactly this one group.

### Three groups that need the *original* capture, not just any capture

This one surprises people, so read it before pointing `PF_CAPTURE` at a file you generated.

`G1`, `G16` and `G19` are written against one specific capture: they assert the file has **≥ 4413 packets** and then index **frame 4413** by number. Point `PF_CAPTURE` at any smaller capture and those groups stop skipping and then **fail**:

```text
FAIL G1 load pcap has >=4413 packets: count=6
FAIL G16 group execution: System.ArgumentOutOfRangeException: Index was out of range...
FAIL G19 group execution: System.ArgumentOutOfRangeException: Index was out of range...
```

Those three failures mean **the fixture is too small**, not that your change broke something. Verify by checking the reported packet count. The generic synthetic capture in [`docs/make-synthetic-capture.py`](docs/make-synthetic-capture.py) has 6 frames, so it will always trip this; it exists for documentation screenshots and manual UI exploration, not for exercising the harness.

If you want the capture-dependent groups to actually pass, you need a real ≥4413-packet capture of your own. Sanitise it, keep it local, and never commit it.

### `PF_CAPTURE`

```bash
PF_CAPTURE=/absolute/or/repo-relative/path/to/capture.pcap dotnet run --project tests/pf-verify/PfVerify.csproj
```

Points the harness at a local capture. Both absolute and repo-relative values work. There is no fallback path: unset means the capture-dependent groups skip. Nothing is ever read from a built-in default location, so there is no chance of a capture name leaking into the source tree.

### `PF_CAPTURE_LARGE`

```bash
PF_CAPTURE_LARGE=/path/to/large-capture.pcapng dotnet run --project tests/pf-verify/PfVerify.csproj
```

Only for `G17-13`, which asserts on a separate large capture (>=180k packets) and therefore cannot be pointed at by `PF_CAPTURE` — a small capture there would make `G1`/`G16`/`G19` fail instead of skip.

### Real captures must never be committed

`.gitignore` blocks `*.pcap` and `*.pcapng`, and **CI rejects any added or modified pcap or pcapng in the diff.** This is not negotiable and not a style preference. Use generated fixtures. If you need a shape of traffic the harness does not generate, generate it (scapy, text2pcap, or a hand-built write) rather than committing a capture you took off a network. Sanitize anything you do use locally before it leaves your workstation.

### `PF_STRICT_CAPTURE`: turn a partial run into a failure

`PF_STRICT_CAPTURE` makes the harness refuse to exit 0 when anything skipped. Semantics as implemented:

- Set it to any non-empty value other than `0` to enable strict mode. Unset, empty, or `0` leaves the default lenient behaviour alone.
- Strict mode only bites when there are **zero failures but at least one skip**. A run that already failed returns 1 regardless.
- On a strict trip the run **returns exit code 2**, distinct from the 1 that a real assertion failure returns, and prints how to resolve it.
- Strict mode also prints the `G17-13` caveat for you, since setting `PF_CAPTURE` alone still leaves that one group skipped.

```bash
# Fail the run if any group skipped
PF_STRICT_CAPTURE=1 PF_CAPTURE=/path/to/local.pcap dotnet run --project tests/pf-verify/PfVerify.csproj
```

Because `G17-13` is never satisfied by `PF_CAPTURE`, a strict run cannot reach a fully unskipped result on a normal checkout. That is a known limitation of the fixture situation, not a bug in strict mode. Use strict mode to prove your change did not newly break a capture-dependent group, not to claim complete coverage.

## Commit messages

Conventional style is not enforced by tooling; this is house style, and it is quite distinctive:

- **Messages are in Chinese.**
- The subject names the file(s) touched and gives a line delta, then a colon and a short description.

For example: `TsharkService.cs +187：版本检测/门禁/流式列表加载与按需建树`

Follow it. It makes `git log` readable in a way that a conventional-commits subject line does not for this codebase.

## Pull requests

- **`dotnet build ProtocolForge.sln -warnaserror` clean.** 0 warnings, 0 errors. This is the CI gate.
- **`dotnet run --project tests/pf-verify/PfVerify.csproj` prints `ALL GROUPS PASS`.** Read the rest of the footer line too, and tell us in the PR whether any group skipped and why. A bare "harness passes" without that context is not reviewable. If your change touches anything capture-dependent, run it with `PF_STRICT_CAPTURE=1` and paste that output.
- **Say how you tested a change that touches sending.** The send ladder is hard to exercise in CI. If you changed `PacketSendService`, `NpcapSendService`, `BpfSendService` or `PacketPrepareService`, describe the rung and platform you exercised, or say plainly that you did not.
- **No pcap or pcapng in the diff.**
- Keep the PR to one concern. This is a small project and large mixed PRs are hard to review.
- New behaviour, especially anything on the send path, should come with a matching assertion in the harness.
- Note line-ending changes separately from logic changes, so a reviewer can see the real diff.

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), Contributor Covenant 2.1.

---

## 中文

# 参与 ProtocolForge 开发

感谢你关注本项目。ProtocolForge 采用 Apache-2.0 许可，没有任何功能门禁，因此你能基于它构建的东西，你也可以自行发布。本文是实用版：装什么、跑什么、代码怎么组织，以及一个曾让贡献者栽过的测试陷阱。

安全漏洞请不要走常规 PR 流程，见 [`SECURITY.md`](SECURITY.md)。

## 前置依赖

| 需求 | 版本 | 谁需要 |
|---|---|---|
| tshark（Wireshark 组件） | 运行时 **≥ 2.6.0** | 所有人，包括最终用户。这是应用的 tshark 版本门禁。低于 2.6.0 时应用以只读模式打开抓包。 |
| .NET SDK | **8.0.421 或更高** | 仅构建者与贡献者。最终用户不需要：发布包是自包含的。 |
| tshark | **3.6.2 或更高** | 仅贡献者，且仅用于让验证工具跑到完全通过。 |

最后两个 tshark 版本下限不同是刻意的。**应用**门禁是 2.6.0，**验证工具**需要 3.6.2。用 2.6.x 跑验证工具，一部分组会通过、一部分会失败，而失败原因与你的改动无关。

- Linux：`sudo apt install tshark`
- macOS：`brew install wireshark`
- Windows：从 <https://www.wireshark.org/download.html> 安装 Wireshark。若需要第 0 级二层发送路径，请保留 Npcap 选项（默认勾选）。ProtocolForge 不捆绑 Npcap，也从不安装它。

## 命令

```bash
# 构建应用
dotnet build ProtocolForge.sln

# 以警告即错误方式构建（CI 的做法，本地请保持一致）
dotnet build ProtocolForge.sln -c Release -warnaserror

# 运行
dotnet run --project ProtocolForge/ProtocolForge.csproj

# 启动时打开抓包
dotnet run --project ProtocolForge/ProtocolForge.csproj -- path/to/capture.pcap

# 运行验证工具
dotnet run --project tests/pf-verify/PfVerify.csproj

# 用本地抓包夹具运行验证工具
PF_CAPTURE=/path/to/local.pcap dotnet run --project tests/pf-verify/PfVerify.csproj
```

CI 以警告即错误方式构建，所以**「`dotnet build ProtocolForge.sln -warnaserror` 干净」才是标准**，而不是「能编过」。

## 项目约定

### 架构

- **MVVM + 手动 DI。刻意不使用 IoC 容器。** 请不要引入。服务在 `App.axaml.cs` 中按依赖顺序手工构造，再通过构造函数参数交给 ViewModel。这是决定，不是疏漏。
- **使用 CommunityToolkit.Mvvm 源生成器。** 私有字段上加 `[ObservableProperty]` 生成可绑定属性，`[RelayCommand]` / `[AsyncRelayCommand]` 生成命令。不要手写 `INotifyPropertyChanged` 样板。
- **视图使用代码后置。** Avalonia XAML 加 `.axaml.cs` 处理事件。`HexEditor.axaml` 刻意保持极简，因为十六进制视图在代码后置中构建；这同样不是疏漏。
- **ViewModel 之间用事件，不用引用。** `PacketSelected`、`FieldSelected`、`FieldEdited`、`HexEdited`、`FieldFoundAtOffset` 等。ViewModel 不得持有另一个 ViewModel 的引用。
- **`ViewLocator` 按命名约定把 `FooViewModel` 映射到 `FooView`。** 重命名 ViewModel 或其 View 会静默破坏解析，因为查找是运行时按名称进行的。这也是混淆程序集时必须保留公开类型与成员名称的原因。

### 平台与文件系统

- **只做运行时操作系统判断。** 使用 `OperatingSystem.IsWindows()` / `IsLinux()` / `IsMacOS()`。条件编译被压缩到只剩 `DEBUG`，仅用于开发工具。
- **绝不硬编码路径。** 使用 `Path.Combine()` 配合 `Environment.GetFolderPath(SpecialFolder…)`。所有应用写入必须留在用户目录内。

### 时序守卫

`TsharkService` 中存在 `_treeBuildSeq`、`_reparseVersions` 与 `_prefetchSeq`。它们用于防止在操作员于建树途中点击了另一个报文时，缓慢的异步 tshark 结果覆盖较新的状态。新增异步 tshark 调用时，请接入守卫。跳过守卫会产出一个看起来像「偏移量改错了」而非竞态的 bug，而且无法稳定复现。

### 编辑安全不变量

以下两条规则是承重的。任何一条被破坏都是正确性回归，而非风格问题。

- **十六进制编辑仅支持 REPLACE。** 每次编辑串都由完整的十六进制数字对构成，因此报文长度永不改变，编辑跨度之外的每个偏移量都保持有效。改变长度的编辑按设计被拒绝。
- **任何路径都不得绕过编辑围栏。** 字段编辑必须通过 `CheckTreeEditFence` 并经由 `EditTransactionService`，后者会用 tshark 重新解析，验证新值确实落在预期的 `(PDML name, byte offset)` 位置后才提交。Verify-Before-Commit 是这个工具可以被信任用来修改抓包的原因；不要写出直接写字节的路径。

### 文本与编码

- 4 空格缩进，file-scoped 命名空间。
- 源码中**使用中文注释**。这是本仓库的既定风格，不是历史遗留。
- `*.cs`、`*.axaml`、`*.csproj`、`*.sln`、`*.ps1`、`*.md`、`*.json` 使用 **CRLF** 换行；`*.sh` 与 `*.yml` 使用 **LF**。`.gitattributes` 是权威，`.editorconfig` 与之保持一致；刻意不设全局 CRLF 规则，因为那会在 Linux 上把 `packaging/linux/publish-linux.sh` 改写成 CRLF 而使其无法运行。如果你的 diff 显示每一行都变了，先检查换行符。
- UTF-8，不要有意外的 BOM。

## 新增一个 Service

1. 把类放在 `ProtocolForge/Services/`。
2. 在 `App.axaml.cs` 中**按依赖顺序**实例化（它自身的依赖必须先于它构造）。
3. 通过构造函数参数传给需要它的 ViewModel。
4. 在 ViewModel 构造函数中挂接它的事件，而不是在视图里。

## 新增一条本地化字符串

1. 把键加到 **`ProtocolForge/Assets/Lang/en-US.json`**。
2. 把**同一个键**加到 **`ProtocolForge/Assets/Lang/zh-CN.json`**，`{0}` 这类占位符**数量必须一致**。一个字典里有而另一个没有、或占位符数量不同，都是缺陷。
3. 在 XAML 中用 `{DynamicResource L10n.Key}` 引用，或在 C# 中用 `LocalizationService.Resolve("Key", args…)`。

语言菜单无需额外接线，`SetCurrent` 会持久化选择。验证工具会交叉检查这两个字典，不一致会导致运行失败。

## 验证工具，以及那个陷阱

`tests/pf-verify` 是一个**手写的断言控制台程序**。它不是 xUnit，不是 NUnit，而且没有被 `ProtocolForge.sln` 引用，因此 **`dotnet build` 不会构建它**。必须显式运行：

```bash
dotnet run --project tests/pf-verify/PfVerify.csproj
```

其中有约 300 条断言，按编号分组（G1 到 G38，部分编号未使用），覆盖 tshark 版本门禁、编辑围栏裁决、Verify-Before-Commit 的提交 / 偏移漂移中止 / 长度变化拒绝、只读加载、十六进制编辑代码面、发送阶梯的下降顺序，以及本地化字典一致性。同时会在构建产物旁写出 `report.txt`。

### SKIP 不是 PASS

在把一次绿色运行当作完整覆盖之前，请先读完这一节。

**没有抓包夹具时，六个组会 SKIP，而验证工具仍然以 0 退出。** 每个被跳过的组都会带上真实原因被点名，结尾行也不会让一次部分覆盖的运行冒充完整覆盖：

```text
ALL GROUPS PASS — 6 GROUP(S) SKIPPED, so this is NOT full coverage: x5 capture fixture absent — set PF_CAPTURE to a local .pcap; x1 large-capture.pcapng absent — large capture is local-only
```

退出码为 0 是刻意设计的，这样没有抓包的检出依然能给出有用结果。但 `ALL GROUPS PASS` 不是整行的全部内容，单看退出码也不能说明依赖抓包的组真的跑了。**请读完结尾行，也请读 SKIP 行。** 在没有设置 `PF_CAPTURE` 的全新克隆上，编辑围栏与 Verify-Before-Commit 的大部分覆盖根本没有被执行。

### `PF_CAPTURE` 无法满足的一个组

`G17-13` 需要一个特定的本地大型 pcapng（≥18 万包的真实抓包）。它不是通用夹具，`PF_CAPTURE` 指向不了它。**因此即使设置了抓包，仍有一个组会跳过。** 也就是说，设了 `PF_CAPTURE` 的全绿运行，恰好在这一个组上仍不完整。

### 需要「原始抓包」而非任意抓包的三个组

这一点很容易误导，在把 `PF_CAPTURE` 指向你自己生成的文件之前请先读它。

`G1`、`G16`、`G19` 是针对某一个特定抓包编写的：它们断言文件至少有 **4413 个包**，然后按编号取 **第 4413 帧**。把 `PF_CAPTURE` 指向任何更小的抓包，这三个组会从「跳过」变成「**5931败**」：

```text
FAIL G1 load pcap has >=4413 packets: count=6
FAIL G16 group execution: System.ArgumentOutOfRangeException: Index was out of range...
FAIL G19 group execution: System.ArgumentOutOfRangeException: Index was out of range...
```

这三条失败意味着**夹具太小**，而不是你的改动破坏了什么。验证方法：看报错里输出的包数。[`docs/make-synthetic-capture.py`](docs/make-synthetic-capture.py) 里的通用合成抓包只有 6 帧，因此它一定会触发这个问题；它存在的目的是文档截图与手动浏览，而不是验证 harness。

若希望依赖抓包的组真正通过，需要你自己的、至少 4413 个包的真实抓包。请先脱敏，仅本地保存，**绝不提交**。

### `PF_CAPTURE`

```bash
PF_CAPTURE=/absolute/or/repo-relative/path/to/capture.pcap dotnet run --project tests/pf-verify/PfVerify.csproj
```

让验证工具指向一个本地抓包。绝对路径与仓库相对路径都可以。**没有默认兜底路径**：未设置时依赖抓包的分组直接跳过。工具不会去读任何内置的默认位置，因此不存在真实抓包名泄露进源码树的可能。

### `PF_CAPTURE_LARGE`

```bash
PF_CAPTURE_LARGE=/path/to/large-capture.pcapng dotnet run --project tests/pf-verify/PfVerify.csproj
```

仅供 `G17-13` 使用。该组断言的是另一份大型抓包（≥18 万包），因此不能用 `PF_CAPTURE` 指向——把较小的抓包指过去会让 `G1`/`G16`/`G19` 从「跳过」变成「失败」。

### 真实抓包绝不可提交

`.gitignore` 屏蔽 `*.pcap` 与 `*.pcapng`，并且 **CI 会拒绝 diff 中任何新增或修改的 pcap / pcapng。** 这不是可协商的，也不是风格偏好。请使用生成的夹具。如果你需要验证工具没有生成的那种流量形态，就去生成（scapy、text2pcap，或手写文件），而不是提交你从网络上抓下来的包。本地使用过的任何真实抓包，离开你的工作机之前都要脱敏。

### `PF_STRICT_CAPTURE`：把部分覆盖的运行变成失败

`PF_STRICT_CAPTURE` 让验证工具在任何组被跳过时拒绝以 0 退出。按代码中的实际实现：

- 设置为除 `0` 以外的任意非空值即启用严格模式；未设置、为空或为 `0` 则保持默认的宽松行为。
- 严格模式只在「零失败但至少有一个跳过」时生效。已经失败的运行无论如何都返回 1。
- 严格模式触发时返回**退出码 2**，与真实断言失败的 1 区分开，并打印对应的处理办法。
- 严格模式还会替你提醒 `G17-13` 这个坑，因为只设置 `PF_CAPTURE` 仍会留下该组被跳过。

```bash
# 只要有组被跳过就让本次运行失败
PF_STRICT_CAPTURE=1 PF_CAPTURE=/path/to/local.pcap dotnet run --project tests/pf-verify/PfVerify.csproj
```

由于 `G17-13` 永远不会因为 `PF_CAPTURE` 而被满足，普通检出上的严格运行无法达到「零跳过」的结果。这是夹具现状带来的已知限制，不是严格模式的缺陷。请用严格模式来证明你的改动没有新破坏依赖抓包的组，而不是用它来宣称覆盖完整。

## 提交信息

工具层面并不强制某种约定式提交规范；这是本仓库的既定风格，而且相当有辨识度：

- **信息用中文书写。**
- 主题行写出涉及的文件名与行数增量，然后是冒号和一句简短说明。

例如：`TsharkService.cs +187：版本检测/门禁/流式列表加载与按需建树`

请沿用这种写法。对本代码库而言，它能让 `git log` 以约定式提交主题行做不到的方式保持可读。

## Pull Request

- **`dotnet build ProtocolForge.sln -warnaserror` 干净。** 0 警告、0 错误。这是 CI 门禁。
- **`dotnet run --project tests/pf-verify/PfVerify.csproj` 打印 `ALL GROUPS PASS`。** 结尾行的其余部分也要读完，并在 PR 中说明是否有组被跳过、原因是什么。只写「验证通过」而不给这个上下文，是无法评审的。如果你的改动触及任何依赖抓包的部分，请加 `PF_STRICT_CAPTURE=1` 跑一次并贴出输出。
- **凡是改动发送相关的，请说明你是怎么测的。** 发送阶梯在 CI 中很难真正跑通。如果你改了 `PacketSendService`、`NpcapSendService`、`BpfSendService` 或 `PacketPrepareService`，请描述你实际跑过的级数与平台，或者直说你没有跑。
- **diff 中不得有 pcap 或 pcapng。**
- 一个 PR 只做一件事。本项目规模不大，混杂的大 PR 很难评审。
- 新行为，尤其是发送路径上的新行为，应附带验证工具中对应的断言。
- 换行符的改动要与逻辑改动分开说明，让评审者能看到真实 diff。

## 行为准则

参与本项目须遵守 [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)，即 Contributor Covenant 2.1。
