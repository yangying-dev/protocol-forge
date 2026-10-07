# Security Policy

ProtocolForge is a desktop packet workbench for 3GPP protocol engineers, RAN and core-network test engineers, and security researchers. It reads PCAP files, dissects them with tshark, lets you edit fields and bytes with verification before commit, and can inject the result onto a network.

That last capability is the one that matters for a security policy, so this document spends most of its length on what the tool can do, what it deliberately cannot do, and where its limits are.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.0 | Yes |
| Anything older | No |

0.1.0 is the first public release. There is no maintenance branch and no backport channel.

## Reporting a vulnerability

There are **two channels, and they are not interchangeable**. Please use the one that matches your report.

| What you have | Channel | Link |
|---|---|---|
| A **security vulnerability** in ProtocolForge | GitHub Private Vulnerability Reporting | <https://github.com/yangying-dev/protocol-forge/security/advisories/new> |
| Abuse inquiries, feature questions, anything else | A public issue | <https://github.com/yangying-dev/protocol-forge/issues> |

Use Private Vulnerability Reporting for anything an attacker could exploit or that would leak data a user did not intend to expose. A public issue is right for everything else, which is also what GitHub's own dual-use guidance recommends for non-security inquiries. If you are unsure which side of the line a report falls on, use the private channel and say so in the report; nothing is lost by starting private.

## Capabilities and intended use

**ProtocolForge sends real packets onto a network.** Treat it as a transmission tool, not a viewer. It does not sniff, mirror, tap, or snoop. It takes a frame you have selected and puts it on a wire you have selected.

### The injection ladder

Sending descends a four-rung ladder, probed once per session:

| Rung | Path | Requires | Sends |
|---|---|---|---|
| 0 | Native L2 via Npcap (Windows) or `/dev/bpf` (macOS) | Administrator / root, plus a user-installed Npcap on Windows | Complete Ethernet frames |
| 1 | `AF_PACKET` raw socket (Linux) | `CAP_NET_RAW` / root | Complete Ethernet frames |
| 2 | IP-level raw socket (all platforms) | Administrator / root | IP datagrams |
| 3 | UDP socket fallback | No privileges | UDP payload only |

Rung 0 is entirely optional. When it is unavailable for any reason, missing DLL, no elevation, access denied, or no matching device, the app descends silently and nothing is lost. On macOS no third-party component is involved at all: the native path is a `/dev/bpfN` device opened directly. Npcap is never bundled or installed by ProtocolForge. See [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) for the license position.

Sending requires administrator or root. It targets **only explicitly selected interfaces**: you pick the adapter from a dropdown, and there is no broadcast, no wildcard, and no "all interfaces" option. This is a lab and test tool for operators, vendors, and researchers validating UE / eNB / core-network interworking.

### Intended use

- Use ProtocolForge **only on networks you own, or on networks for which you hold explicit written authorization to test.** Not "you think it is fine", not "it is your company's", not "it is a lab so probably nobody minds". Written authorization.
- The send path is **per-packet opt-in**. Packets must be individually checked before they can be sent, and `SendSelected` defaults to `false`. Unchecked packets are never sent.
- ProtocolForge contains **no evasion capability, no credential access, and no payload-fuzzing tooling aimed at production systems.** It is an editor and a transmitter. If you want to fuzz a production UE, write the fuzzer.

You are solely responsible for what you transmit. Sending packets may violate local law, your carrier's terms, or your employment agreement.

## Known limitations

These are real properties of 0.1.0, disclosed rather than smoothed over.

### There is no rate limit and no send quota

Nothing in the application throttles you. Loop count is configurable up to **9999**, and the inter-packet interval can be set to **0 ms**, so total volume is bounded only by your own pacing. There is no built-in cap, no daily budget, and no escalating backoff.

**Mitigation is the operator's.** You are responsible for pacing sends, for choosing an interval that does not saturate a link, and for stopping when something looks wrong. The Start / Pause / Stop controls in the toolbar are the intended means.

### `SendSelected` defaults to `false`

The send gate is closed until you open it. The gate also refuses to send when:

- tshark is missing or older than 2.6.0, in which case the app is in read-only mode, or
- a loopback interface is selected.

### ProtocolForge will run whatever executable it is pointed at

`TSHARK_PATH` and the tshark file picker both accept **any executable path** (the file picker uses `Patterns = ["*"]`, with no extension filter). ProtocolForge then executes that binary as tshark.

This is intentional. Users legitimately ship tshark in non-standard locations, and a hardcoded or extension-filtered picker would break them. The consequence is that ProtocolForge executes whatever file it has been pointed at, and only the operator decides where that pointer goes. If you configure this on a shared or managed workstation, treat the tshark path setting as a privileged configuration item.

### TLS session-key decryption

If the `SSLKEYLOGFILE` environment variable is set, or if a `tls.keylog_file` path is present in `settings.json`, then **every tshark invocation automatically receives `-o tls.keylog_file:<path>`**. That transparently decrypts TLS in any capture tshark is pointed at.

There is no menu item for this. The UI affordance was removed. The behaviour is only reachable by setting the environment variable or by hand-editing `settings.json`. It is disclosed here because an operator should know it exists before sharing a capture or a workstation.

### Source-address normalisation, not spoofing

Before injection, the tool can rewrite the source MAC and source IP to **the selected interface's own address**, and recompute checksums. It does not forge arbitrary source addresses and cannot originate traffic from an address that is not yours. Default is off; it is the **Auto-fix** toggle, and turning it on changes frame preparation only.

## Verified-clean properties

These are the basis for relying on this tool rather than fearing it. Each has been checked by reading the source.

### The application opens no listening socket

There is no `TcpListener`, no `HttpListener`, no `Listen()`, no `Accept*`, no `Socket.Receive*`, no `WebSocket`, no `TcpClient`, and no `UdpClient` anywhere in the codebase. The only `Bind` calls target **port 0**, which asks the OS for an ephemeral source port, and `Bind` is skipped entirely for `AF_PACKET`. **ProtocolForge can only send.** Running it does not make your machine reachable, does not open a backdoor, and does not create a service. If you run it on a laptop in a hotel, it is not listening.

### Npcap is opened with promiscuous mode off

Promiscuous mode is explicitly disabled, and **no capture callback is ever registered**. The Npcap handle exists solely to inject frames. ProtocolForge does not capture traffic through Npcap.

### No command-injection surface

Every tshark invocation uses `ProcessStartInfo.ArgumentList`, never a concatenated command string, so there is no shell to inject into. The two process launches that *do* build an argument string use **100% literal arguments with zero interpolation**. There is no user-controllable tshark display filter: every `-Y` expression in the codebase is hardcoded. A crafted capture cannot become a command line.

### The process does not self-elevate

The Windows application manifest requests **no administrator level**. It has no `requireAdministrator` element and no UAC prompt. Raw-socket rights come from the operator choosing to run the process elevated. The application never asks for more privilege than it was started with.

### All application writes stay inside the user profile

Settings, layout, and logs are written with `Path.Combine` plus `Environment.GetFolderPath(SpecialFolder…)`. **There are no hardcoded absolute write paths.** The app does not write to system directories, does not modify its own installation, and does not touch anything outside the per-user profile. Logs land under `LocalApplicationData/ProtocolForge/logs/`, settings under `ApplicationData/ProtocolForge/`.

### Stack traces never reach the UI

Exceptions are caught and their stack traces are written **only to a local trace log** (`trace.log` under the logs folder above). They are not displayed in the UI, not shown in a dialog, and not transmitted. A crash produces a log line on disk, not a leak.

## What to include in a report

Please include:

- **tshark version** (`tshark -v` output) and the configured tshark path if you changed it.
- **Operating system and version**, and whether the app was run elevated.
- **Whether the app was in read-only mode**, which is the case whenever tshark is missing or older than 2.6.0.
- **A minimal reproduction**: the smallest capture that shows the problem, the UI actions taken, and what you expected instead.
- **The relevant `trace.log` lines** if you can attach them. They often identify the failing send rung or tshark invocation immediately.

**There is no paid support channel and no private support channel.** This is an open-source project maintained in public. Report through the channels above and expect a public, best-effort response.

## 中文

# 安全策略

ProtocolForge 是面向 3GPP 协议工程师、RAN / 核心网测试工程师与安全研究人员的桌面报文工作台。它读取 PCAP，用 tshark 解析，允许你在提交前经过校验的前提下修改字段与字节，并能把结果注入网络。

最后这项能力正是安全策略需要重点说明的部分，因此本文的大部分篇幅用于讲清这个工具能做什么、刻意不做什么、以及边界在哪里。

## 支持的版本

| 版本 | 是否支持 |
|---|---|
| 0.1.0 | 是 |
| 更早的版本 | 否 |

0.1.0 是首个公开版本。没有维护分支，也没有补丁回合渠道。

## 漏洞报告：两个不同的渠道

**请务必按报告内容选择渠道，两者不可互换。**

| 报告内容 | 渠道 | 链接 |
|---|---|---|
| ProtocolForge 自身的**安全漏洞** | GitHub 私密漏洞报告（Private Vulnerability Reporting） | <https://github.com/yangying-dev/protocol-forge/security/advisories/new> |
| 滥用相关咨询、功能问题、其他一切 | 公开 issue | <https://github.com/yangying-dev/protocol-forge/issues> |

攻击者可利用、或会泄露用户本不打算暴露的数据，请走私密漏洞报告渠道。其余情况一律用公开 issue，这也是 GitHub 官方对非安全类咨询的建议做法。如果你不确定属于哪一类，就用私密渠道，并在报告里说明；先从私密开始不会有任何损失。

## 能力与预期用途

**ProtocolForge 会把真实报文发到网络上。** 请把它当作发射工具，而不是查看工具。它不嗅探、不镜像、不旁路监听、不窃听。它做的是：把你选中的帧，送到你选中的线路上。

### 注入阶梯

发送路径是一次探测、四级下降的阶梯：

| 级 | 路径 | 权限要求 | 发送内容 |
|---|---|---|---|
| 0 | Windows 上经 Npcap、macOS 上经 `/dev/bpf` 的原生二层 | 管理员 / root；Windows 还需用户自行安装 Npcap | 完整以太网帧 |
| 1 | `AF_PACKET` 原始套接字（Linux） | `CAP_NET_RAW` / root | 完整以太网帧 |
| 2 | IP 层原始套接字（全平台） | 管理员 / root | IP 数据报 |
| 3 | UDP 套接字兜底 | 无需特权 | 仅 UDP 载荷 |

第 0 级完全可选。任何原因导致它不可用时（缺 DLL、未提权、访问被拒、无匹配设备），应用会静默降级，不丢功能。macOS 上完全不涉及任何第三方组件，原生路径是直接打开 `/dev/bpfN` 设备。ProtocolForge 从不捆绑、也从不安装 Npcap，许可边界见 [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md)。

发送需要管理员或 root 权限。**只会作用于明确选定的网卡**：网卡由下拉框手动选择，没有广播、没有通配、没有「全部网卡」选项。这是供运营商、厂商与研究人员验证 UE / eNB / 核心网互通性的实验室与测试工具。

### 预期用途

- **仅**在你自有的网络，或你持有明确书面测试授权的网络上使用 ProtocolForge。不是「我觉得应该没问题」，不是「这是我们公司的」，也不是「实验室里应该没人管」。必须是书面授权。
- 发送路径是**逐包选择加入**的。报文必须逐个勾选后才能发送，且 `SendSelected` 默认为 `false`。未勾选的报文绝不会被发送。
- ProtocolForge **不包含任何规避能力、不包含任何凭据获取能力，也没有面向生产系统的载荷模糊测试工具**。它是一个编辑器和一台发射器。想对生产网 UE 做模糊测试，请自行写模糊测试工具。

你对自己发出的每一个字节负全责。发送报文可能违反当地法律、你的运营商条款，或你的雇佣协议。

## 已知限制

以下是 0.1.0 的真实属性，据实披露，不做粉饰。

### 没有速率限制，也没有发送配额

应用内没有任何限速。循环次数最高可配到 **9999**，包间隔最小可设为 **0 ms**，因此总发送量只受你自己节流程度的约束。没有内置上限，没有每日额度，没有递增退避。

**缓解责任在操作者。** 发送节奏、避免占满链路、发现异常时及时停止，都是你的责任。工具栏的「开始 / 暂停 / 停止」就是为此设计的。

### `SendSelected` 默认为 `false`

发送闸门默认关闭，需要你手动打开。以下情况闸门也会拒绝发送：

- tshark 缺失或低于 2.6.0，此时应用处于只读模式；
- 选中了 loopback 回环网卡。

### ProtocolForge 会执行被指向的任意可执行文件

`TSHARK_PATH` 与 tshark 文件选择器都接受**任意可执行文件路径**（文件选择器使用 `Patterns = ["*"]`，不限制扩展名）。ProtocolForge 会把该文件当作 tshark 执行。

这是有意为之。用户完全可能把 tshark 放在非标准位置，硬编码或限定扩展名的选择器会直接破坏这类用户。代价是：ProtocolForge 会执行它被指向的那个文件，而这个指针指向哪里只由操作者决定。如果你在共享或受管工作站上配置它，请把 tshark 路径设置视为特权配置项。

### TLS 会话密钥解密

如果设置了 `SSLKEYLOGFILE` 环境变量，或 `settings.json` 中存在 `tls.keylog_file` 路径，那么**每一次 tshark 调用都会自动带上 `-o tls.keylog_file:<path>`**。这会让 tshark 透明地解密其处理的抓包中的 TLS。

界面里没有这个菜单项，该 UI 入口已被移除。只能通过设置环境变量或手工编辑 `settings.json` 触及。在此披露，是因为操作者在分享抓包或共享工作站之前，应当知道它的存在。

### 源地址归一化，而非伪造

注入前，工具可以把源 MAC 与源 IP 改写为**所选网卡自身的地址**，并重算校验和。它不会伪造任意源地址，也无法以不属于你的地址发起流量。默认关闭；它对应「自动修复」开关，打开只改变帧的预处理方式。

## 已核验的干净属性

以下结论是「可以信赖这个工具，而不是需要提防它」的基础，每一条都通过通读源码核验。

### 应用不打开任何监听套接字

整个代码库中不存在 `TcpListener`、`HttpListener`、`Listen()`、`Accept*`、`Socket.Receive*`、`WebSocket`、`TcpClient`、`UdpClient`。仅有的 `Bind` 调用都指向**端口 0**，即请求操作系统分配一个临时源端口；`AF_PACKET` 路径则完全跳过 `Bind`。**ProtocolForge 只能发送。** 运行它不会让你的机器变得可访问，不会开后门，不会创建服务。在酒店笔记本上运行它，它并没有在监听。

### Npcap 以混杂模式关闭的方式打开

混杂模式被显式关闭，且**从未注册任何抓包回调**。Npcap 句柄存在的唯一目的就是注入帧。ProtocolForge 不通过 Npcap 抓包。

### 没有命令注入面

所有 tshark 调用都使用 `ProcessStartInfo.ArgumentList`，从不拼接命令字符串，因此没有可供注入的 shell。确实会拼参数串的那两处进程启动，使用的是 **100% 字面量参数、零字符串插值**。不存在用户可控的 tshark 显示过滤器：代码库中所有 `-Y` 表达式都是硬编码的。构造过的抓包文件无法变成命令行。

### 进程不会自行提权

Windows 应用程序清单**未请求任何管理员级别**，既没有 `requireAdministrator` 元素，也没有 UAC 弹窗。原始套接字权限来自操作者选择以提权方式运行进程。应用永远不会索取超过启动时已有的权限。

### 所有应用写入都留在用户目录内

设置、布局与日志均通过 `Path.Combine` 配合 `Environment.GetFolderPath(SpecialFolder…)` 写入。**不存在硬编码的绝对写入路径。** 应用不写系统目录，不修改自身安装目录，不触碰用户目录以外的任何位置。日志位于 `LocalApplicationData/ProtocolForge/logs/`，设置位于 `ApplicationData/ProtocolForge/`。

### 堆栈信息不会进入界面

异常被捕获，其堆栈信息**仅**写入本地 trace 日志（即上述日志目录下的 `trace.log`）。既不在界面显示，也不在对话框弹出，也不上报。崩溃产生的是磁盘上的一行日志，而不是信息泄露。

## 报告请包含

请附上：

- **tshark 版本**（`tshark -v` 输出）；若改过路径，请说明配置的 tshark 路径。
- **操作系统与版本**，以及是否以提权方式运行。
- **应用是否处于只读模式**。tshark 缺失或低于 2.6.0 时即为只读模式。
- **最小复现**：能触发问题的最小抓包、所执行的界面操作，以及你预期的结果。
- 相关的 **`trace.log` 行**（若可提供）。它通常能直接指出失败的发送级数或 tshark 调用。

**本项目没有付费支持渠道，也没有私密支持渠道。** 这是一个在公开环境中维护的开源项目。请通过上述渠道报告，并预期得到公开的、尽力而为的回应。
