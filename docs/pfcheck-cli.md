# pfcheck — ProtocolForge 命令行工具

`pfcheck` 是 ProtocolForge 的无头（headless）命令行入口。它复用 GUI 使用的同一套服务层，因此**不需要启动界面、不需要显示器**，可以直接放进 CI 流水线或批处理脚本。

编辑操作走的是和 GUI 完全相同的 **Verify-Before-Commit（VBC）** 通道：候选帧先交给 tshark 重新解析，只有新值落在预期的 `(PDML name, byte offset)` 上才会写文件；否则中止，并保持数据包逐字节不变。

---

## 调用方式

编译后（`--self-contained` 发布包）：

```bash
ProtocolForge validate <capture.pcap> [--filter <display-filter>]
ProtocolForge edit <capture.pcap> --offset <n> --length <n> --hex <hex> --out <output.pcap> [--packet <n>]
ProtocolForge send <capture.pcap> --interface <name> [--count <n>] [--interval <ms>] [--all] [--filter <display-filter>]
ProtocolForge stats <capture.pcap> --tap <tap> [--filter <display-filter>]
```

从源码运行：

```bash
dotnet run --project ProtocolForge -- validate <capture.pcap>
```

> **Windows 说明**：项目是 `WinExe`，Windows 上不会附带控制台窗口，输出可能不可见。需要脚本化时请使用发布包里的 `ProtocolForge.exe` 并从 `cmd`/`PowerShell` 调用，或改用 Linux/macOS 构建。

## 退出码

| 码 | 含义 |
|---|---|
| `0` | 成功 |
| `1` | 操作失败，或 VBC 校验中止（文件保持原样） |
| `2` | 参数用法错误 |

---

## validate

打开抓包、报告元数据，并真实解析第一帧来证明解析链路可用。

```bash
ProtocolForge validate capture.pcap
ProtocolForge validate capture.pcap --filter pfcp
```

输出示例：

```
packets: 6
linktype: 1
snaplen: 65535
endianness: little
timestamp resolution: microseconds
filtered rows: 1 (filter: pfcp)
frame 1 dissected: True, layers: 5
  frame
  eth
  ip
  tcp
  http
```

需要 tshark ≥ 2.6.0；缺失或版本过低时返回 `1`。

## edit

按偏移量改写字段，**必须通过 VBC 校验**。

| 参数 | 说明 |
|---|---|
| `--offset` | 目标字段在帧内的起始字节偏移 |
| `--length` | 改写长度，必须与 `--hex` 的字节数一致 |
| `--hex` | 十六进制字节，可带 `0x` 前缀 |
| `--out` | 输出文件路径 |
| `--packet` | 1 起始的帧号；抓包含多帧时必填 |

```bash
# 把第 1 帧的 IPv4 源地址改成 10.0.0.1
ProtocolForge edit capture.pcap --packet 1 --offset 26 --length 4 --hex 0a000001 --out output.pcap
```

输出：

```
target: Source Address (ip.src) at offset 26 length 4
committed and written: output.pcap
frames written: 6 (frame 1 edited)
verified: OK
```

`--out` 的格式跟随扩展名：`.pcapng` 写出 PCAPNG，`.pcap` 写出 classic PCAP。**整个抓包的所有帧都会写出**，只有目标帧被替换。

VBC 中止时返回 `1`，并且**不会**产生输出文件：

```
edit aborted: Offset drift: pfcp.message_type found at position 40 (expected 52); aborting edit
packet left byte-identical
```

## send

经发送阶梯发包，参数与界面工具栏一致。

| 参数 | 说明 |
|---|---|
| `--interface` | 网卡名；省略时选第一个非回环网卡 |
| `--count` | 循环轮数，默认 1 |
| `--interval` | 包间隔毫秒，默认 0（尽快发送） |
| `--all` | 发送全部帧；默认只发第一帧 |
| `--filter` | 先按 display filter 筛选 |

```bash
ProtocolForge send capture.pcap --interface eth0 --count 100 --interval 10
```

回环网卡会被拒绝（`1`），网卡不存在会列出可用网卡并返回 `2`。逐包结果与汇总都会打印。

## stats

运行一个 tshark 统计 tap 并原样输出。

```bash
ProtocolForge stats capture.pcap --tap io,phs
ProtocolForge stats capture.pcap --tap conv,udp
```

可用 tap 由 tshark 决定，常用的有：`conv,ip` / `conv,tcp` / `conv,udp` / `conv,sctp` / `endpoints,ip` / `io,phs`（协议层级）/ `io,stat,0` / `expert`。

> **过滤器只对部分 tap 生效。** tshark 的统计 tap 会忽略 `-Y`，必须作为 tap 自身的参数传入（`conv,`、`endpoints,`、`tree,`、`frame,` 支持）。`io,phs` 与 `io,stat` 不接受过滤参数，硬传会导致 tap 整体失败，因此本工具不会给它们传。界面统计面板行为一致。

---

## 与 GUI 的关系

- 编辑、发送、统计走的是同一批服务（`ProtocolEditorService`、`EditTransactionService`、`PacketSendService`、`TsharkService`），不存在"CLI 有一套简化逻辑"的情况。
- CLI 的编辑**不能改变报文长度**。长度由字段本身决定，`--length` 与 `--hex` 不一致时直接返回 `2`。
- `trace.log` 同样记录 CLI 运行，位置见 [`../SECURITY.md`](../SECURITY.md)。