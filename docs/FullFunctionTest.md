# ProtocolForge 全功能测试用例文档

**版本**: v1.3 ｜ **日期**: 2026-09-24 ｜ **分支**: main

## 0. 文档说明

本文档对 ProtocolForge 的**全部现有功能**输出测试用例，覆盖率达 100%。每个用例标注测试方式：

| 分类 | 含义 | 谁执行 |
|---|---|---|
| **A — 自动化已验证** | 现有 `tests/pf-verify`（G1–G38；G9、G10 已随对应功能下线删除，组号不回收）已覆盖，已实际运行并通过 | 自动化（pf-verify） |
| **B — 可自动化新增** | 服务层逻辑；可新增 pf-verify 测试组覆盖，无需 GUI / 真机 / 网络注入 | 开发者补充实现 |
| **C — 必须人工** | GUI 交互、视觉确认、真实网卡注入、Windows/macOS 专属路径、真机行为 | **人工执行** |

> 说明：A 类用例已用 `dotnet build` + `dotnet run --project tests/pf-verify` 实证通过（见附录 A）。B 类中服务层可自动化部分已全部迁移为 A 类（G24~G32，含 TR-04 / H-13 / CP-01~04 / TL-01~03 / N-17）；不可达分支（root 环境语义）已按诚实注记 13 以源码面板 + 自适应分支覆盖。C 类用例无法在无头环境自动验证，必须人工执行。

---

## 1. 功能覆盖清单（覆盖率索引）

| # | 功能域 | 用例范围 | A/B/C |
|---|---|---|---|
| 1 | 构建与 QA 门禁 | T-01 ~ T-04 | A |
| 2 | 启动流程（语言/检测/布局/命令行参数） | S-01 ~ S-05、S-07 ~ S-08 | A/B/C |
| 3 | tshark 环境检测与版本门禁 | T-05 ~ T-12 | A/C |
| 4 | PCAP 读取（IngestService） | P-01 ~ P-12 | A |
| 5 | 数据包列表加载（流式/只读） | L-01 ~ L-04 | A |
| 6 | 协议树构建（jsonraw 三遍解析） | TR-01 ~ TR-10 | A/C |
| 7 | 编辑围栏（CheckTreeEditFence 六检查） | F-01 ~ F-06 | A |
| 8 | 树字段值编辑（转换/内联编辑器） | CV-01 ~ CV-13 | A/C |
| 9 | Hex 编辑（REPLACE-only） | H-01 ~ H-13 | A/C |
| 10 | Verify-Before-Commit（VBC） | V-01 ~ V-10 | A/C |
| 11 | 保存 / 导出 / 重置 | X-01 ~ X-06 | A/C |
| 12 | 地址/端口重新提取 | A-01 ~ A-02 | A/C |
| 13 | 数据包 DataGrid（排序/自动适配/勾选/右键菜单） | G-01 ~ G-10 | C |
| 14 | 发送（SendService 阶梯 + 工具栏 + 状态） | N-01 ~ N-16 | A/C |
| 15 | 本地化（LocalizationService） | I-01 ~ I-08 | A/B/C |
| 16 | 布局持久化（LayoutService） | LO-01 ~ LO-04 | A/C |
| 17 | 设置持久化（settings.json） | ST-01 ~ ST-06 | A/C |
| 18 | TLS 密钥日志（keylog，仅环境变量/settings.json，无 UI） | TL-01 ~ TL-03 | A |
| 19 | 上下文提供者（SDP/分片/TCP 流） | CP-01 ~ CP-06 | A/C |
| 20 | trace.log 运行时日志 | Z-01 ~ Z-03 | A/C |
| 21 | 菜单 / 对话框 / 横幅 / 状态栏 | M-01 ~ M-12 | C |
| 22 | 已知非功能面（死代码/不存在的功能确认） | D-01 ~ D-08 | A/C |

**覆盖率声明**：上述 22 个功能域对应代码中所有 Service（16 个文件）、ViewModel（6 个）、View/控件（7 个）、Converter（2 个）、Model（8 个）中每个可观察行为点。任何未列出的功能点即视为缺陷（欢迎指出）。

> **变更记录（2026-09-29）**：免费版每日发送配额功能已整体下线并从代码库删除（服务类文件、每日计数 JSON 状态文件、工具栏配额文本、预占/记账/守卫链路全部移除）。原"发送配额"功能域及其 Q-01~Q-14 用例整节移除，本清单与后续章节号顺延一位；用例编号 `N-*` 等**保持原号不重排**，故编号存在空缺。相关自动化断言（pf-verify G9、G10i、G21-04、G32 的 Q-12 子块）同步删除，组号不回收。
>
> **变更记录（2026-09-30）**：离线授权模块已整体从代码库删除（4 个服务类、1 个载荷模型、Help 菜单下的授权子菜单、启动降级弹窗、20 个 `Lic.*` 语言键、pf-verify G10 整组）。原"许可"与"机器标识"两个功能域及其全部用例整节移除；`S-06`、`LIC-09`、`LIC-13`、`LIC-14`、`MF-03`、`M-03`、`M-04` 单条用例移除；章节号自第 16 章起统一前移两位。编号方案不变（`LIC-*`/`MF-*` 整段作废，`S-*`/`M-*` 留空不重排）。

---

## 2. 构建与 QA 门禁

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **T-01** | A | dotnet SDK ≥ 8.0 | 仓库根目录执行 `dotnet build` | 0 错误 0 警告（QA 门禁） |
| **T-02** | A | tshark ≥ 3.6.2 可用 + pcap/ 样本齐全 | `dotnet run --project tests/pf-verify` | 控制台输出 `ALL GROUPS PASS`，退出码 0 |
| **T-03** | A | T-02 通过 | 检查 bin 输出目录 | 生成 `report.txt`，含全部断言行 + `ALL GROUPS PASS` footer（2026-09-30 实测：本地无 `pcap/` 样本时 230 PASS / 0 FAIL / 6 SKIP = 236 行，exit 0；装齐样本后 6 个组一并执行、断言数更多。组号 G9/G10 已删除、G21 独立块并入别组，编号不连续属预期） |
| **T-04** | C | 任一平台 | 检查 `ProtocolForge.sln` | 仅含主项目；`tests/pf-verify` 不在 sln 中（须独立 `dotnet run`） |

---

## 3. 启动流程

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **S-01** | C | 全新环境（无 settings.json） | 首次启动应用 | 语言按系统区域探测（zh 前缀 → 简体中文）；无报错 |
| **S-02** | C | 曾通过菜单切换语言 | 重启应用 | 恢复上次语言偏好 |
| **S-03** | A/C | tshark 正常 | 启动 | DetectTshark Ok；状态栏"就绪（tshark 版本）"；非只读 |
| **S-04** | B/C | tshark 缺失或 < 2.6.0 | 启动 | 只读模式：黄色横幅（警告 + Banner.Text）；树/hex 编辑、导出、发送禁用；包列表仍加载（N/A 列） |
| **S-05** | C | 已构建 | 命令行 `dotnet run --project ProtocolForge -- pcap/capture.pcap` | 窗口打开后自动加载该 pcap |
| **S-07** | C | 有 layout.json | 启动 | 窗口位置/大小/分割条比例/面板可见性恢复 |
| **S-08** | C | 曾设置 TLS keylog | 启动 | 恢复 keylog 路径，启动日志无报错 |

---

## 4. tshark 环境检测与版本门禁

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **T-05** | A | 真实 tshark ≥ 2.6.0 | pf-verify G3 | `DetectTshark()` 返回 Ok=true，版本 ≥ 2.6.0 |
| **T-06** | A | 临时目录造假 tshark 脚本输出 2.5.0 | 设 `TSHARK_PATH` 指向后调用 DetectTshark（pf-verify G4） | Ok=false，版本解析为 2.5.0，MessageKey=Tsh.TooOld |
| **T-07** | A | 同上但输出 4.2.6 | 调用 DetectTshark（pf-verify G4） | Ok=true |
| **T-08** | A | — | pf-verify G26 | 探测顺序：TSHARK_PATH 环境变量 → PATH → Windows Program Files 路径 → Unix 常用路径；返回第一个存在的（env-first 行为断言：假脚本路径击败 PATH 上的真实 tshark） |
| **T-09** | A | — | pf-verify G26（假 tshark 脚本输出 2.9.9 / 2.10.0 / 1.12.6） | 版本解析用正则 `(\d+\.\d+\.\d+)`；`VersionCompare` 组件级数字比较（零填充）——2.9.9/2.10.0 均过门禁（字符串比较"2.1"<"2.6" 会误拒），1.12.6 → Tsh.TooOld 且仍上报环境路径 |
| **T-10** | C | 应用在只读模式 | 菜单 文件 → Tshark 路径... 选择合法 tshark | 运行时重新检测；合法 → 退出只读模式（横幅消失，编辑解锁）；路径持久化到 settings.json |
| **T-11** | C | T-10 完成后 | 重启应用 | 持久化的 tshark 路径被恢复为 TSHARK_PATH；检测仍 Ok |
| **T-12** | A | — | pf-verify G26 | 静态 `_detectionCache` 进程级缓存（换 env 后 DetectTshark 仍返回旧路径）；RedetectTshark() 强制重跑（拿到新 env） |

---

## 5. PCAP 读取（PcapIngestService）

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **P-01** | A | pcap/capture.pcap | pf-verify G1/G5 已通过加载 | 经典小端 µs PCAP 成功读取 |
| **P-02** | A | pcap/large-capture.pcapng | pf-verify G17-13 | PCAPNG 读取，LinkLayerType/Snaplen 正确，≥180k 包（计数走容差 ≥180,000，不做精确相等） |
| **P-03** | A | 构造大端 µs 文件（或反写样本） | pf-verify G17-02 | 魔数 `d4c3b2a1` → 大端解析，时间戳正确 |
| **P-04** | A | 构造 ns 时间戳文件 | pf-verify G17-04 | 魔数 `a1b23c4d`/`4d3cb2a1` → ns 解析，`tsFrac/1000` 归一化 µs |
| **P-05** | A | 构造 PCAPNG 双 section 不同端序 | pf-verify G17-05 | 每 section 独立端序解析；接口 ID 按 section 重置；末 section 的 linkType/snaplen 生效 |
| **P-06** | A | 构造 if_tsresol 选项（code 9） | pf-verify G17-06/G17-07 | 按 `if_tsresol` 换算分辨率（MSB→2^-n，否则 10^-n）：十进 0x03 raw 5→5000µs；2^n 0x83 raw 125000→1µs；未知接口 ID 假定 µs（未单独断言） |
| **P-07** | A | 截断 PCAP（文件不完整） | pf-verify G17-08 | 截断记录静默中断，不抛异常；已读到的包保留 |
| **P-08** | A | 随机字节文件 | pf-verify G17-09 | 魔数无法识别 → `InvalidDataException("Unknown PCAP magic")`（消息含 hex） |
| **P-09** | A | 文件 < 24 字节 | pf-verify G17-10 | `InvalidDataException`（"File too small"） |
| **P-10** | A | 不存在的路径 | pf-verify G17-11 | `FileNotFoundException` |
| **P-11** | A | pcapng 含简单包块(0x3) | pf-verify G17-12 | SPB 复用 `prevTimestamp` |
| **P-12** | A | 端到端往返：读取 → PcapExportService 导出 → 再读 | pf-verify G18-07 | 包数、字节、时间戳一致（round-trip 恒等） |

---

## 6. 数据包列表加载

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **L-01** | A | pcap/capture.pcap | pf-verify G5 | `LoadPcapReadOnlyAsync`：包数齐全；SourceAddress 全为 N/A；ProtocolName 空 |
| **L-02** | C | 正常模式 | 打开 large-capture.pcapng（180k 包） | 列表流式渐进填充（非一次性卡死）；进度条 0.05→1.0；包总数显示正确 |
| **L-03** | C | 已加载 | 观察 1..N 行 | No 列＝包集合索引（PacketNumber，非 tshark 输出）；Time 列＝PcapIngest 原生时间戳（TimestampDisplay）；Source/Destination/Protocol/Info 按 tshark `-T fields` 输出填列（Source/Dest 待树构建后 ExtractAddressInfo 更新，见 L-04） |
| **L-04** | C | 正常模式，打开含 IP/端口的包 | 选中包 | 源/目的地址、端口在列表中被 ExtractAddressInfo 更新 |

---

## 7. 协议树构建（jsonraw 三遍解析）

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **TR-01** | A | pcap/capture.pcap 第 4413 帧 | pf-verify G1 | `BuildPacketTreeAsync` 成功，Layers 非空 |
| **TR-02** | A | 真实 tshark + G24 夹具 | pf-verify G24（BuildFixturePcap/FixtureEth/FixtureIpv4/FixtureUdp 现造样本，三遍 reparse） | 三遍解析：① 所有 `*_raw` 进字典 ② `*_tree` 递归建层/字段 ③ 孤儿 `_raw`（如 ip.src_raw 无树父）补发为字段（三遍机制本身随解析结果断言） |
| **TR-03** | A | 含重复键的包（多次 dhcp.option.type；G24 夹具现造） | pf-verify G24 | 重复键按序收集；每个容器实例消费其第 i 个孪生（非 last-wins）——实证：tshark 3.6 的 `type_tree` 把重复键输出为同名重复对象键，容器的无子孪生行不入树，仅带子容器建层 |
| **TR-04** | A | 匿名容器（PFCP IE 如 F-SEID） | 解析 | 拆成 Name/DisplayValue；`OriginalPdmlName=""` 以便重解析按 (name,pos) 匹配 |
| **TR-05** | A | 重组区域（IP 分片，G24 夹具） | pf-verify G24 | `ip.fragments`/`tcp.segments`/`{name}.reassembled.*` → 子字段偏移叠加 region.Base（frag 子字段按重组区相对偏移，诚实注记 12） |
| **TR-06** | A | 有效载荷字段（G24 夹具） | pf-verify G24 | 捕获兜底字段改名 "UDP payload"/"TCP payload"，`ShowHex=false`，Kind=Unknown（不可数字编辑） |
| **TR-07** | A | 聚合别名（ip.addr 多值，G24 夹具） | pf-verify G24 | 跳过聚合别名（addr/host/port 等），防重复 |
| **TR-08** | A | 隐藏字段（_ws.malformed，G24 夹具） | pf-verify G24 | 名字级全隐藏与位置级孪生隐藏均丢弃；malformed 追加到最内层 "（Malformed Packet: X）"（G24 移除旧 malGoodFrame 冗余样本，夹具单帧聚焦） |
| **TR-09** | A | 位级掩码字段（DSCP，G24 夹具） | pf-verify G24 | `MaskToLengthBits`：掩码满字节 → -1（字节对齐）；否则位计数（位级子字段）——实证 DSCP 位宽 6（MaskToLengthBits 全正确） |
| **TR-10** | C | 正常模式 | 点击不同协议包（PFCP/NGAP/GTP-U/NAS/S1AP/Diameter/SCTP/HTTP2） | 每种协议正确解析出层级与字段；重复协议实例（如 4× http2.stream）编号区分 |

---

## 8. 编辑围栏（CheckTreeEditFence 六检查）

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **F-01** | A | pcap/capture.pcap | pf-verify G1a | 元数据/位级字段被拦截（blockedByReason.Count>0） |
| **F-02** | A | 同上 | pf-verify G1b | ≥1 个常规帧内字段放行 |
| **F-03** | A | 同上 | pf-verify G1c | 放行/拦截两类判定并存（判别力） |
| **F-04** | A | 构造六类字段各一 | pf-verify G12a-01~07 逐一 CheckTreeEditFence | 六检查各自拒绝并返回对应 Reason：UnknownField / BitLevel / OutOfFrame(+PduHint) / NoByteEvidence / BytesDisagree（构造 60B 合成帧；NoByteSpan 因 IsTreeEditable 门在负长度处先拦截而不可达——见附录诚实注记）；合法 IPv4 字段放行 |
| **F-05** | C | 正常模式 | 双击一个不可编辑字段（如位级掩码 / ip.addr） | 状态区显示"不可编辑: {reason}"；不打开编辑器 |
| **F-06** | A | pf-verify 产物 | 检查 trace 日志 | 每次拒绝写 TraceLog 行 |

---

## 9. 树字段值编辑（值转换 + 内联编辑器）

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **CV-01** | A | — | pf-verify G12b | `ConvertRawValue(UInt, "0x10", 1)` → `[0x10]` |
| **CV-02** | A | — | pf-verify G12b | `ConvertRawValue(UInt, "300", 1)` 越界（>255）→ ArgumentException；（Int 999 无符号越界检查——现状注记） |
| **CV-03** | A | — | pf-verify G12b | `ConvertRawValue(Int, "-5", 1)` → 二进制补码 `[0xFB]`；2 字节位宽亦过 |
| **CV-04** | A | — | pf-verify G12b | `ConvertRawValue(IPv4, "10.0.0.1", 4)` → `[0A 00 00 01]`；300.x/::1 拒绝 |
| **CV-05** | A | — | pf-verify G12b | `ConvertRawValue(IPv6, "fe80::1", 16)` → 16 字节；IPv4 串 → 拒绝 |
| **CV-06** | A | — | pf-verify G12b | `ConvertRawValue(Mac, "00:11:22:33:44:55", 6)` → 6 字节；4 组 802.3 可；3 组/坏 hex 拒绝 |
| **CV-07** | A | — | pf-verify G12b | `ConvertRawValue(Bcd, "12345678", 4)` → 交换 BCD `[21 43 65 87]`；奇数位 0xF 高位；位数超长拒绝 |
| **CV-08** | A | — | pf-verify G12b | `ConvertRawValue(String, "AB", 5)` → 零填充 `[41 42 00 00 00]`；过长/空拒绝 |
| **CV-09** | A | — | pf-verify G12b | 未知 Kind → `ArgumentException` |
| **CV-10** | C | 正常模式 | 树中双击数值字段输入十进制 → Enter | VBC 通过后提交；状态"{0} 已设置为 {1}" |
| **CV-11** | C | 同上 | 输入后按 Esc | 取消；无修改 |
| **CV-12** | C | 同上 | 输入后点击编辑框外部 | click-away 提交（IsEditingField 守卫） |
| **CV-13** | A | — | pf-verify G22（源码面板） | Hex-Native 字段编辑：PDML showname `0x…` 前缀 → `HexPreferred` 检测（TsharkService ≥1 处 `StartsWith("0x")` 赋值）；`FormatForEdit` 对 UInt/Int 默认 hex 显示（大端，与 tshark 显示一致）；提交路径解析 0x 前缀输入（配套 G12b CV-01 行为断言） |

---

## 10. Hex 编辑（REPLACE-only）

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **H-01** | A | — | pf-verify G6（静态代码面） | HexByte 有 IsEditPending；VM 有 HandleHexInput/CommitHexEditAsync/CancelHexEdit；事件 HexEdited/FieldFoundAtOffset |
| **H-02** | A | — | pf-verify G6 | REPLACE-only：不改变包长（源码断言 HexByte 无长度变更路径） |
| **H-03** | C | 选中包 | 点击 hex 区某字节，输入 2 个 hex 数字 | 该字节 pending 预览（黄底、灰 ASCII） |
| **H-04** | C | 同上 | 再输入更多"数字对" | 组成连续编辑 run，逐字节前进并预览 |
| **H-05** | C | 有 pending | Enter | 整 run 一次提交；字节橙色标记（已编辑） |
| **H-06** | C | 有 pending | Esc | 取消，恢复原显示，状态"已取消编辑" |
| **H-07** | C | 同上 | 点击另一单元 | 先提交 pending 再切换选择 |
| **H-08** | C | 有 pending，焦点在 hex 外 | LostFocus | 提交 pending run |
| **H-09** | C | 选中出界字节（包尾） | 键入后 Enter | 状态"编辑超出范围…"；拒绝 |
| **H-10** | C | 只读模式 | 尝试键入 | 状态"只读模式：编辑已禁用…"；拒绝 |
| **H-11** | C | 正常模式 | 方向键：←→±1、↑↓±16 移动选择 | 移动正确；有 pending 时先提交 |
| **H-12** | C | 正常模式 | 对照协议树点击字段 | 字段字节范围高亮协议色；反向 FieldFoundAtOffset → 树滚动并选中节点 |
| **H-13** | A/C | 已编辑 IP 地址字节 | 重新地址提取 | `RefreshEditedFieldBytes` 回写 RawBytes（字节级，A）+ 列表列更新（UI 面，C，见 A-01） |

---

## 11. Verify-Before-Commit（VBC）

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **V-01** | A | pcap/capture.pcap | pf-verify G2a | 候选字段有具体字节（RawBytes.Length==Length） |
| **V-02** | A | 同上 | pf-verify G2b | 合法编辑：翻转最低位提交成功；其余字节逐位一致 |
| **V-03** | A | 同上 | pf-verify G2c | 提交返回新 PdmlData（Fresh != null） |
| **V-04** | A | 同上 | pf-verify G2d | 偏移漂移（+100 位）→ 中止 |
| **V-05** | A | 同上 | pf-verify G2e | 中止后包字节恒等（无任何修改） |
| **V-06** | A | 同上 | pf-verify G2f | 长度变更（1 字节字段写 4 字节值）→ 拒绝 |
| **V-07** | A | 同上 | pf-verify G2g | 拒绝后包字节恒等 |
| **V-08** | A | — | pf-verify G25 | 构造 `OriginalPdmlName` 为空的字段提交 → VerifyFieldInReparse → Vbc.NoPdmlName 中止，且中止后包字节恒等 |
| **V-09** | A | — | pf-verify G16e/G16i | 构造 reparse 值 ≠ 期望值 → Vbc.ValueMismatch 中止（含容器字段解析到子偏移后再中止） |
| **V-10** | C | 正常模式 | 编辑 PFCP SEID 后提交 | 容器自动重链：周边文本（如 F-SEID : SEID: 0x…, IPv4 …）原地刷新，无需重建树（RefreshFieldDisplays PDML 名+偏移匹配） |

---

## 12. 保存 / 导出 / 重置

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **X-01** | A | — | pf-verify G18-01/02/03 | PcapExportService.ExportAsync 全量 → 字节级精确写出小端 µs 经典 PCAP（魔数 a1b2c3d4，版本 2.4）；incl_len=orig_len=len |
| **X-02** | A | — | pf-verify G18-04 | ExportOnlyModified=true → 跳过未修改包（仅被改包写出） |
| **X-03** | A | — | pf-verify G18-05/06 | ExportAsync 无输出路径（空白）→ ArgumentException（"Output path is required."）；SavePacketAsync 无路径 → 同拒 |
| **X-04** | C | 有修改未保存 | Ctrl+S | 覆盖保存（若曾打开文件）；状态"已将 {0} 个数据包保存到 {1}" |
| **X-05** | C | 有修改 | Ctrl+Shift+S 或 File→Export PCAP As | 导出到新路径 |
| **X-06** | C | 只读模式 | Ctrl+S | 拒绝："只读模式下无法保存…" |
| **X-07** | C | 有修改后 | File → Reset Modifications | 全部恢复；ModifiedPackets=0；hex 刷新 |
| **X-08** | C | 无文档/无修改 | Ctrl+S | 相应拒绝文案（"没有可保存的数据包…"/"没有需要保存的修改…"） |

---

## 13. 地址/端口重新提取

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **A-01** | A | 构造 IP+UDP 包，改 src IP 字节 | pf-verify G19-07 | 真机解析后经 ApplyHexStringEdit 编辑 ip.src 字节 → 重解析为新 Packet，Source 从旧 IP 更新为新 IP（列表列的 GUI 刷新仍属 L-04/C） |
| **A-02** | A | 构造含 ip.src_raw 等 | pf-verify G25 | hex→点分转换仅当 8 hex 字符（`!isV6 && hex.Length == 8`）；已点分值直通（行为断言 10.0.0.1 直通 + 源码面板两分支） |

---

## 14. 数据包 DataGrid

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **G-01** | C | 已加载 | 点击各列头 | 全部 7 列（No/Time/Source/Dest/Protocol/Length/Info）可排序，点击循环升/降序 |
| **G-02** | C | 已加载 | 双击列头分隔线 | 列宽自动适配（DoubleClickAutoFit，≤50000 行扫描） |
| **G-03** | C | 已加载 | 点击表头三态 CheckBox | 全选/全不选对应全部行 SendSelected；中间态（indeterminate）被忽略 |
| **G-04** | C | 已加载 | 勾选若干行发送框 | Action：表头同步三态；ToolBar.CanSend 随"任一选中"联动 |
| **G-05** | C | 已加载 | 右键包列表 | 菜单四项：全选/反选/清除选择/发送此数据包 |
| **G-06** | C | 选中某行 | 右键 → 发送此数据包 | 无视勾选框，仅发送该行；不受任何数量额度限制；需非回环网卡 |
| **G-07** | C | 已加载 | 点击行 | SelectedPacket 变化 → 树 + hex 加载所选包 |
| **G-08** | C | 大文件 | 快速连续点击不同行 | 无陈旧树覆盖新选择（_treeBuildSeq 守卫）；无重复树层（_buildingPackets 守卫） |
| **G-09** | C | 正常模式 | 选中后等待约 1s | ±3 邻居预取在后台构建（并发 2）；快速点击时预取不覆盖新选择 |
| **G-10** | C | 已加载 | 观察包号列 | 每行含发送 CheckBox + 包号 |

---

## 15. 发送（SendService 阶梯 + 工具栏）

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **N-01** | C | 加载含 UDP 的 pcap | 工具栏选网卡 → 勾选包 → Start | 若选环回网卡：Start 禁用（IsLoopback 拒绝） |
| **N-02** | C | 无网卡时 | 观察 Start 按钮 | 禁用（CanSend=false） |
| **N-03** | C | 只读模式 / 正在发送 | 观察 Start 按钮 | 禁用（CanSend=false；`CanSend` 门 = 只读 + 有非环回网卡 + 有勾选包 + 未在发送，**无任何数量额度条件**） |
| **N-04** | C | 选非环回网卡 + 勾选包 | 点击 Start | IsSending=true；✓/✗ 计数可见；状态"正在通过 {1} 发送 {0} 个数据包…" |
| **N-05** | C | N-04 进行中 | 点击 Pause | 暂停；PauseButtonText 变"继续"；状态"已暂停 — 已发送 {0}，失败 {1}" |
| **N-06** | C | N-05 | 点击 Resume | 继续发送 |
| **N-07** | C | N-04 进行中 | 点击 Stop | 停止；状态"已停止 — 已发送 {0}，失败 {1}" |
| **N-08** | C | 正常 | 设置间隔 500ms / 循环 3 | 包以 500ms 间隔每轮重发，共 3 轮 |
| **N-09** | C | 正常 | 打开 Auto-fix 再发送含坏校验和的包 | 对端收到校验和正确的包；源 IP 被重写为所选网卡 IP |
| **N-10** | A | Linux root | pf-verify G27（定向夹具 + BufferingTraceListener 捕获阶梯行） | rung 阶梯：L2(不存在)→AF_PACKET→IP raw→UDP 逐级下降；无 socket → Send.NoSocketType（root 实机三跳 trace 实证；非 root 分支为源码/自适应断言，诚实注记 13） |
| **N-11** | A | 构造 <14 字节帧（G27 夹具） | pf-verify G27 | FrameTooShort → 下一阶梯（首级失败 + 最终 UdpParseFailed 全降实证） |
| **N-12** | A | 构造 IPv4+UDP 且无权限 | pf-verify G27 | UDP 兜底成功（Send.SentUdp）——root 下不可达（AF_PACKET 先赢，诚实注记 13，非 root 主机自动切行为断言）；root 分支断言最高保真 rung 优先（SentRaw(60, lo)）|
| **N-13** | A | 构造 TCP 帧 | pf-verify G27 | TryExtractUdpTarget 失败 → 平台文案（Windows: TcpBlockedWin；其他: TcpNeedsPriv）——root 下 AF_PACKET 直接投递不触发该文案；源码面板断言两平台文案 + 非 root 行为分支（诚实注记 13） |
| **N-14** | C | 真实网卡存在 | Start 后在对端/回环抓包 | 实际收到注入包（真实设备验证） |
| **N-15** | A | 事件订阅 | pf-verify G21-01~03（RunSendAsync 监听 PacketSent/SendCompleted） | 每次成功发送恰好一次 PacketSent（Sent==循环数）；会话结束 SendCompleted 触发（Done=true，finally 保证） |
| **N-16** | A | — | pf-verify G21（回环注入组） | 发送循环无额度守卫：整批按 `LoopCount` 轮次跑完（仅 Pause/Stop 可中断） |
| **N-17** | A/C | 网卡枚举 | NetworkInterfaceService.GetInterfaces() | 仅返回 Up 且（IPv4 或回环）网卡；排序回环靠后按名；扫描异常 → 空集合不崩溃；GetInterfaceIP 按 Id 匹配返回 IPv4（AI 侧 C 面：真实网卡注入留真人） |

---

## 16. 本地化（LocalizationService）

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **I-01** | A | — | pf-verify G11a | en/zh 键集合一致（148 键完全一致） |
| **I-02** | A | — | pf-verify G11b | 全键占位符数目一致 |
| **I-03** | A | — | pf-verify G11c | zh 含 CJK 象形文字 |
| **I-04** | A | — | pf-verify G11d | 运行时切换：默认 en → SetCurrent(zh) 文案变化 → 回切 |
| **I-05** | A | — | pf-verify G11e | 缺失键回退链：当前 → en → 键名 |
| **I-06** | A | — | pf-verify G11f | 2 参占位符双语格式化 |
| **I-07** | C | 正常 | 语言菜单中文 ↔ English 切换 | 全 UI 即时切换（菜单/工具栏/网格/树/状态/对话框）；菜单勾选同步 |
| **I-08** | C | 发送/编辑进行中 | 切换语言 | 状态文案随切换重新解析（LanguageChanged 事件） |

---

## 17. 布局持久化（LayoutService）

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **LO-01** | A | — | pf-verify G20-01 | Save→Load 往返：TopRowRatio/BottomLeftRatio/WindowWidth/WindowState/三面板可见性一致；损坏或缺失 → 默认（G20-02/03 fail-open） |
| **LO-02** | C | 调整分割条位置 | 关闭应用 → 重启 | 分割比例恢复 |
| **LO-03** | C | View 菜单切换面板可见性 | 重启 | 可见性恢复 |
| **LO-04** | C | 布局乱后 | View → Reset Layout | 分割比例恢复 0.35 / 0.50 默认；窗口默认大小；重新保存 |

---

## 18. 设置持久化（TsharkSettingsService / settings.json）

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **ST-01** | A | — | pf-verify G20-04/05/06 | SaveTsharkPath→LoadTsharkPath 往返一致；清空 → null；损坏配置 → 三字段全 null（fail-open） |
| **ST-02** | A | — | pf-verify G20-04 | SaveLanguage→LoadLanguage 往返一致（zh-CN） |
| **ST-03** | A | — | pf-verify G28（settings.json 路径换成同名目录触发 EISDIR → 写失败） | 保存失败静默吞掉（SaveTsharkPath/SaveTlsKeylogPath/SaveLanguage 均不抛）+ 不可读配置 fail-open（load×2 → null）+ 快照/恢复共享配置 |
| **ST-04** | A | — | pf-verify G20-04 | 读-改-写：连续 Save 三字段后新实例 Load 全读回（read-modify-write 保留） |
| **ST-05** | C | 正常 | File→Tshark Path… 选择路径后重启 | 路径持久化并被采用 |
| **ST-06** | C | 正常 | 语言菜单切换后重启 | 语言持久化 |

---

## 19. TLS 密钥日志（keylog）

无 UI 入口：菜单项已移除，能力改由 `SSLKEYLOGFILE` 环境变量或 `settings.json` 的 `TlsKeylogPath` 提供（见 CodeMap「TLS keylog 无 UI 入口」）。

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **TL-01** | A | — | SetTlsKeylogPath(有效路径) | tshark 参数追加 keylog_file |
| **TL-02** | A | SSLKEYLOGFILE env 设置且未显式设置 | 构造 | 回退使用环境变量；两者皆空 → 无参数 |
| **TL-03** | A | 版本缓存 | 构造 tshark <3.0 | 用 `ssl.keylog_file`；≥3.0 用 `tls.keylog_file` |
| **TL-05** | A | 菜单已移除 | 检查 XAML / 语言键 / 处理器 | 无 `Mnu.TlsKeylog` 菜单项与 `OnPickTlsKeylogClicked`；5 个相关语言键已移除；服务层 `SSLKEYLOGFILE` 路径仍可注入 |

---

## 20. 上下文提供者（PacketContextProvider）

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **CP-01** | A | 含 SDP 包的文件 | SdpContextProvider.CollectFramesAsync | 返回全部 SDP 帧（不含目标帧）；懒扫描 + 失败重扫 |
| **CP-02** | A | 含分片文件 | FragmentContextProvider | 按 ip.id|src|dst 分组；BFS 闭包拉入组内**更早**帧；传递扩展；升序返回 |
| **CP-03** | A | 含 TCP 流文件 | TcpStreamContextProvider | 目标流内最近的段优先；预算上限 DefaultBudget=2000；升序排序 |
| **CP-04** | A | — | 各 Provider 接口 | Name 正确（sdp/ip-fragment/tcp-stream）；目标帧绝不包含在结果中 |
| **CP-05** | C | SDP→RTP 包（含编解码映射） | 直接构建树 | 无上下文时可能解析不全；有上下文时 RTP 显示编解码名 |
| **CP-06** | C | 分片/重组包 | 构建树 | 正确偏移（区域偏置） |

---

## 21. trace.log 运行时日志

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **Z-01** | C | 完成若干操作 | 打开 `%LOCALAPPDATA%/ProtocolForge/logs/trace.log`（Linux `~/.local/share/ProtocolForge/logs/trace.log`） | 有加载/选择/发送/围栏拒绝记录；可据此排查行为问题 |
| **Z-02** | A | — | pf-verify G23（源码面板） | 启动轮转：trace.log 超 2MB → 级联备份 `trace.log.1`/`.2`（`keepBackups=2`，保留最近 2 份）；当前会话始终写 trace.log，客户回传日志流程不变 |
| **Z-03** | A | — | pf-verify G23（源码面板） | 兜底崩溃记录器：AppDomain.UnhandledException / TaskScheduler.UnobservedTaskException → TraceLog.Write；仅记录，不改变未观察异常默认语义 |

---

## 22. 菜单 / 对话框 / 横幅 / 状态栏

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **M-01** | C | 正常 | File 菜单逐项 | Open(Ctrl+O)/Save(Ctrl+S)/Export(Ctrl+Shift+S)/Reset Mods/Tshark Path/TLS Keylog/Exit 齐全 |
| **M-02** | C | 正常 | View 菜单 | 三面板勾选切换可见性；Reset Layout 生效 |
| **M-04b** | C | 正常 | Help → Open Support Data Folder | 打开本地支持数据根目录（Windows `%LOCALAPPDATA%/ProtocolForge/`，其 `logs/trace.log` 可见；设置仍在 ApplicationData） |
| **M-05** | C | 正常 | Help → About | 对话框显示应用信息（含 Npcap 归属文案） |
| **M-06** | C | Flow | File→Open PCAP | 文件选择器（*.pcap/*.pcapng/*.cap/*）；选择后加载 |
| **M-07** | C | Flow | 打开损坏/非 pcap 文件 | 状态"错误: {0}"，无崩溃 |
| **M-08** | C | 只读模式 | 观察横幅 | 黄色警告 + "只读模式"文案 + 原因 |
| **M-09** | C | 加载 | 观察状态栏 | StatusText + 进度条（IsLoading 时可见） |
| **M-10** | C | 有修改 | 观察状态栏 | "已修改: {n}" 可见（HasUnsavedChanges） |
| **M-11** | A | 有修改 | 关闭窗口（有修改） | 弹出保存/放弃/取消三选一；保存失败保持窗口，放弃或保存成功后关闭 |
| **M-12** | C | 正常 | 打开 large-capture.pcapng 滚动列表 | UI 不冻结；进度流畅（流式设计目标） |

---

## 23. 已知非功能面确认（死代码 / 不存在功能）

| 用例 | 分类 | 前置条件 | 步骤 | 预期 |
|---|---|---|---|---|
| **D-01** | A | — | Grep 源码 | 无拖拽支持（DragDrop/AllowDrop 零匹配）；无搜索/查找功能（无 Ctrl+F） |
| **D-02** | A | — | Grep 源码 | OpenPcapCommand/ExportPcapCommand/RefreshInterfacesCommand 生而未绑定（死命令，实际走 code-behind） |
| **D-03** | A | — | Grep XAML | HexByteColorConverter（5 个）/BoolToStringConverter 未在 XAML 引用（死转换器；hex 背景为 code-behind） |
| **D-04** | A | — | 源码 | ViewLocator 注册但从未触发（所有视图直接构造）；StatusInfo/SelectedIndex/IsEnabled 部分 VM 状态未绑定 |
| **D-06** | A | — | Grep App.axaml | 外观仅跟随系统主题（`RequestedThemeVariant="Default"`）；无自定义主题切换/配色功能 |
| **D-07** | A | — | 查看 app.manifest | 标准 Avalonia 清单（assemblyIdentity + Windows 10 supportedOS，窗口透明/兼容所需）；**无** requireAdministrator 提权声明——原始套接字发送的管理员权限由"以管理员身份运行"外部保障（子 AGENTS.md 的"清单为提权而设"说法不成立，按实际记录） |

---

## 24. 人工测试执行清单（按优先级）

> 以下用例必须人工执行。建议顺序按风险从高到低：

| 优先级 | 用例集合 | 理由 |
|---|---|---|
| **P0** | T-10/T-11（tshark 路径变更恢复编辑）、S-04/S-05（只读/命令行参数）、N-01~N-09（发送闭环）、G-01~G-10（DataGrid 交互） | 核心用户流程 |
| **P1** | H-03~H-12（hex 编辑全交互）、CV-10~CV-12（树编辑）、V-10（SEID 容器重链）、TR-10（多协议解析） | 编辑核心链路 |
| **P2** | I-07/I-08（语言切换）、M-01~M-12（菜单对话框横幅）、LO-02~LO-04、X-04~X-08 | 常规 UI 面 |
| **P3** | Z-01、CP-05/CP-06、TL-04 | 平台/日志专项 |
| **P4** | 真机注入（RealDeviceQA.md W1–W6 Windows/Npcap、M1–M6 macOS/BPF）、真实网卡对端抓包、L7d 生产密钥配对 | 需要真机/真实网络环境 |

---

## 附录 A — 自动化执行证据（2026-09-24）

| 验证项 | 命令 | 结果 |
|---|---|---|
| 构建 | `dotnet build` | **Build succeeded. 0 Warning(s) / 0 Error(s)** |
| 验证基座 | `dotnet run --project tests/pf-verify` | **ALL GROUPS PASS**（G1–G33，276 断言 + footer） |
| G1 编辑围栏 | 同上 | 六类拦截/放行判别 PASS |
| G2 VBC | 同上 | 合法提交/偏移漂移中止/长度变更拒绝 + 字节恒等 PASS |
| G3/G4 版本门禁 | 同上 | 真实 3.6.2 OK；假 2.5.0 拒；假 4.2.6 过 |
| G5 只读加载 | 同上 | N/A 列/空协议名 PASS |
| G6 hex 代码面 | 同上 | REPLACE-only/事件/只读门 PASS |
| G7/G8 Npcap/BPF 纯逻辑 | 同上 | 路径探测/设备匹配/ifreq 构造 PASS |
| G11 本地化 | 同上 | 6 断言全过（键一致性/占位符/切换/回退/格式化） |
| G12a 围栏构造 | 同上 | 7 断言全过（UnknownField/BitLevel/OutOfFrame±PduHint/NoByteEvidence/BytesDisagree/放行） |
| G12b 转换矩阵 | 同上 | 27 断言全过（UInt 越界拒/Int 补码+截断/IPv4/IPv6/MAC/BCD 交换/String 零填充/未知 Kind） |
| G13 字段应用 | 同上 | 9 断言全过（ApplyFieldEdit/ApplyHexStringEdit/FindFieldAtOffset 全矩阵） |
| G14 层树（真实帧2） | 同上 | 7 断言全过（层存在/父链/重复层名/嵌套字段含位级/ProtocolStack） |
| G15 发送准备 | 同上 | 17 断言全过（eth/IPv4/IPv6/bare-IP 源重写 + 校验和重算 + FindIpOffset 矩阵） |
| G16 VBC 细粒度 | 同上 | 13 断言全过（漂移/未知字段/容器 ValueMismatch/长度变更 + 字节恒等 + 合法提交） |
| G17 PCAP 读取矩阵 | 同上 | 13 断言全过（端序/ns/双 section/tsresol/截断/魔数/SPB/真实 pcapng） |
| G18 导出 | 同上 | 10 断言全过（字节级精确/仅修改/round-trip/自定义 linkType/上下文/空路径拒绝/失败保留原文件并清临时文件） |
| G19 地址提取 | 同上 | 7 断言全过（真实帧解析/源目/端口/协议栈/编辑后重解析刷新） |
| G20 布局/设置 | 同上 | 6 断言全过（布局往返/损坏→默认/设置三字段往返/清空→null/损坏→null） |
| G21 回环注入（Linux） | 同上 | eth+udp/tcp/bare-ip 发送 + UdpParseFailed 全过 |
| G22 HexPreferred 代码面 | 同上 | 4 断言全过（0x 前缀检测 ≥1 处 / 提交路径 hex 解析 / FormatForEdit UInt+Int hex 默认显示） |
| G23 trace 轮转+崩溃兜底 | 同上 | 6 断言全过（2MB 阈值+双备份 / 级联循环 / 监听器 / 双崩溃记录器 / 静默降级） |
| G24 三遍解析专项（TR-02~09） | 同上（BuildFixturePcap 现造样本 + 真实 tshark） | 10 断言全过（ETH/IP/UDP 全字段 + DHCP option 重复键孪生消费 + UDP/TCP payload 改名 + 聚合别名跳过 + malformed 追加 + DSCP 位宽 6） |
| G25 VBC 无 PDML 名 + 地址边界（V-08/A-02） | 同上 | 4 断言全过（空 OriginalPdmlName → NoPdmlName + 包字节恒等；10.0.0.1 点分直通 + 8-hex 门源码） |
| G27 发送阶梯定向（N-10~N-13） | 同上（<14B / eth+UDP / TCP 夹具 + BufferingTraceListener） | 9 断言全过（无 socket 守卫 / 构造顺序 / OS 门 / UDP 兜底源码 / TCP 文案；root 三跳 trace 下降实证 + SentRaw(60, lo) + TCP 不可达注记） |
| G28 保存失败静默（ST-03） | 同上（settings.json 路径换同名目录） | 4 断言全过（静默捕获源码 / 三保存不抛 / fail-open load 双 null / 快照恢复） |
| G26 探测顺序/版本/缓存（T-08/09/12，最后） | 同上（临时假 tshark 脚本 2.9.9/2.10.0/1.12.6 + env 快照） | 8 断言全过（env-first 击败 PATH / 门禁 2.6.0 源码常量 / 数字比较过 2.9.9·2.10.0 / TooOld 拒 1.12.6 / 缓存短路 + Redetect 强制重跑） |
| G29 匿名容器 + hex 刷新（TR-04/H-13） | 同上（运行时生成 PFCP Association Setup Response 合成夹具） | 10 断言全过（4 匿名 IE 识别/拆分/DisplayValue 细分/定位偏移；H-13 RawBytes 回写/位级不回填/负偏移安全早退） |
| G30 上下文提供者（CP-01~04） | 同上（mock reader + 真实 SIP/SDP 夹具） | 14 断言全过（SDP 懒扫描缓存 + 失败重扫 / 分片 BFS 闭包 + 种子拉取 + 首包排除 / TCP 同流最近优先 + 预算注入生效 / Provider 类型 + DefaultBudget / real: SDP·分片·同流真实 tshark 三连） |
| G31 keylog 参数（TL-01~03） | 同上（argv 捕获式假 tshark 3.2.1/2.9.9 + SSLKEYLOGFILE） | 4 断言全过（≥3.0 用 tls.keylog_file / <3.0 回退 ssl.keylog_file / env 回退注入 / 无配置不注入） |
| G32 网卡枚举（N-17） | 同上 | 网卡排序回环殿后 / GetInterfaceIP 匹配与未知 Id / 扫描异常空集合全过 |
| G33 直接网卡发送 + no-op 树编辑 + 滚动条 | 同上（合成非回环接口 + 合成 PFCP 树 + 源码标记） | 3 断言全过（发送按钮无额外门禁 / 未修改树字段不触发编辑事件和脏状态 / 关闭拦截与水平滚动条禁用接线） |

**追加记录（2026-09-29，日配额功能下线后重跑）**：上表是 2026-09-24 的原始执行证据，保留不改写。其中 G9（日配额）与 G21-04（发送守卫截断）、G32 的 Q-12 子块已随功能删除，上表对应行已移除。

**追加记录（2026-09-30，公开发布前）**：离线许可模块整体删除，pf-verify 的 G10 整组随之移除，上表对应行已删除。删除后新增 G33-05/G33-06/G33-07 三条断言，覆盖发送门禁（只读态拒绝、回环网卡拒绝、门禁判定不依赖复选框）。

| 验证项 | 命令 | 结果 |
|---|---|---|
| 构建 | `dotnet build` | **Build succeeded. 0 Warning(s) / 0 Error(s)** |
| 验证基座 | `dotnet run --project tests/pf-verify` | **ALL GROUPS PASS**（287 PASS / 0 FAIL / 0 SKIP，exit 0；tshark 3.6.2，无组跳过） |
| 离线授权模块删除后复跑（2026-09-30） | `dotnet build` + `dotnet run --project tests/pf-verify` | **Build succeeded. 0 Warning(s) / 0 Error(s)** + **ALL GROUPS PASS**（230 PASS / 0 FAIL / 6 SKIP，exit 0；本地无 `pcap/` 样本，6 个 capture 相关组跳过；dotnet 8.0.421、tshark 3.6.2） |

**环境**：Linux 容器（root）、dotnet 8.0.424、tshark 4.2.2、pcap/ 四样本齐全。（此为 2026-09-29 那次复跑的环境；2026-09-30 复跑环境见上表最后一行。）

**诚实注记（覆盖边界与现状记录）**：

1. **F-04 的 NoByteSpan 分支不可达**：六 Reason 中 UnknownField / BitLevel / OutOfFrame(+PduHint) / NoByteEvidence / BytesDisagree 由 G12a-01~06 直接断言；`NoByteSpan` 因上游 `IsTreeEditable` 门（长度/偏移前置检查）先行拦截，无法从公开入口构造触发——语义恒"拒绝"但无独立断言行。
2. **Int 无符号越界检查**：CV-02 的越界断言仅对 UInt 成立；Int 路径 `999 → 1 字节截断`（无范围检查，G12b 固化该现状）为当前实现行为，非缺陷主张。
3. **G14-05 为占位断言（恒真）**：`Report("G14-05 duplicate layer names tolerated (TR-03)", true, …)` 的历史占位——TR-03 真实孪生键解析已由 **G24** 行为化覆盖（`dhcp.option.type` 重复键按序消费），G14-05 保留原样不误导（同一代码路径 G14 层树断言照常有效）。G14-06 的位级计数仅证明字段可遍历；`MaskToLengthBits` 语义已由 **G24 TR-09** 断言（DSCP 位宽 6）。
4. **G21 不锁定具体 rung**：仍成立（回环注入断言"任一 rung 成功 + 严格计数"）；N-10~N-13 的阶梯下降现已由 **G27** 定向覆盖（root：AF_PACKET→IP raw→UDP 三跳 trace 实证 + NoSocketType/FrameTooShort/TCP 文案）。
5. **P-02 计数容差**：G17-13 断言 ≥180,000，非精确相等（样本变更健壮性）。
6. **P-06 未知接口 ID 子句**：tsresol 归一化已断言 10^-n（0x03 raw 5→5000µs）与 2^-n（0x83 raw 125000→1µs）；"未知接口 ID 假定 µs"未单独构造（真实文件走已知接口路径）。
7. **EPB 夹具 orig_len=0**：G17-12 的 EPB 构造 caplen=data.Length、origlen=0（规范允许）；SPB 无时间戳字段 → 继承前一包时间戳，为该夹具验证的"缝隙"行为。
8. **G19-07 使用新 Packet 重解析**：绕开 `ParseLayers` 追加语义 + `ExtractAddressInfo` 先到先得（IPv4 仅覆盖 N/A）；`RefreshEditedFieldBytes` 的 DisplayValue 不刷新（显示文本由 VBC reparse 统一负责，H-13 断言该边界）；列表列 GUI 刷新（H-13 / A-01 的 UI 面）仍为 C（L-04）。
9. **导出异常文案**：ExportAsync/SavePacketAsync 无路径的实际文案为 `"Output path is required."` / `"No save path specified for packet."`（X-03 按实际文案记录）。
10. **G20-01 布局字段子集**：断言 ratio/宽度/WindowState/三面板可见性；WindowX/Y/高度未显式断言。
11. **G22/G23 为源码面板断言（G6 模式）**：`FormatForEdit`（打印机显示）与 `TryRotateTraceLog`/`RegisterCrashRecorders`（Program.cs 私有启动路径）无公开入口，采用源码符号断言；行为链末端（`ConvertRawValue` 0x 输入）已由 G12b CV-01 行为断言覆盖。G23 轮转为启动时私有逻辑，未做实际 2MB 文件注入（避免污染 LocalApplicationData）。
12. **TR-05 重组区偏移为相对偏移**：ip.fragments 子字段（header_field off）按**重组区相对位置**（off=0 起）叠加 region.Base，非完整 IP 头绝对偏移——G24 按实际断言并固化该现状。
13. **N-12/N-13 行为分支在 root 下不可达**：AF_PACKET/L2 先赢，UDP 兜底（SentUdp）与 TCP 平台文案（TcpBlockedWin/TcpNeedsPriv）在 root 容器无法从公开入口触达 → G27 以"源码面板断言 + root 自适应分支断言"覆盖，非 root 主机跑 G27 时自动切到行为断言（SentUdp/TcpNeedsPriv）。**同组暴露并修复真实缺陷**：非 Windows 平台 raw socket 原用 `ProtocolType.IP`(0) → Linux/macOS `socket(AF_INET, SOCK_RAW, 0)` 直接 EPROTONOSUPPORT，被 `CreateSendSockets` 静默吞掉 → "IP raw" rung 从未存在（阶梯名存实亡）；已改为非 Windows 用 `ProtocolType.Raw`(IPPROTO_RAW)，修复后 root 实机三跳 trace 实证通过。
14. **G26 使用假 tshark 临时脚本**：临时目录 3 个 bash 脚本（2.9.9 / 2.10.0 / 1.12.6）+ TSHARK_PATH 快照/恢复 + 结尾 `RedetectTshark()` 重校准静态缓存；T-09 门禁断言依赖 `UnixFileMode`（Windows 分支跳过，CA1416 规避）。
15. **G29 使用运行时生成的 PFCP 合成夹具**：测试不再依赖未跟踪的本地抓包。夹具为 Ethernet/IPv4/UDP/8805 + PFCP Association Setup Response，包含 Node ID、Cause、Recovery Time Stamp、UP Function Features，使用 RFC 5737 文档地址段 `192.0.2.1/192.0.2.2`；真实 tshark 可解析匿名容器与细分显示。**同组保留两处历史修复结论**：匿名容器判定不得按 showname 中的点号排除；`TrySplitShowname` 必须对冒号左侧执行 `TrimEnd`。
16. **G30 CP-03 mock 预算注入**：`TcpStreamContextProvider` 预算经构造器参数传入（默认 `DefaultBudget=2000`）；"预算内 3 帧"断言必须显式 `new TcpStreamContextProvider(reader, budget: 3)`，否则构造器默认 2000 返回全部同流帧（实现按 `selected.Count < _budget` 共享计数，行为正确——首版断言漏传 budget 而 FAIL，属测试侧修正）。
17. **G31 假 tshark 脚本须输出合法 pdml**：argv 捕获式假脚本对 `-T pdml` 分支须输出 `<pdml version="0.0"><packet/></pdml>`（`echo '[]'` 是合法 json 但非法 XML，`ParsePacketFromPcapFileAsync` 并行跑 jsonraw/json/pdml 三路 → pdml 解析抛异常）；`-T jsonraw`/`-T json` 维持 `echo '[]'`。

**可新增自动化清单（存量 B 类已全部关闭——G29~G33 已迁移）**：
- 原 B 类存量行已由 **G29~G33** 迁移为 A：**TR-04**（G29，PFCP 合成夹具）、**H-13**（G29，字节级刷新；DisplayValue/列表列 UI 面 → C）、**TL-01~03**（G31，argv 捕获假 tshark）、**CP-01~04**（G30，mock + real 双轨）、**N-17**（G32，网卡枚举；真实网卡注入 → C）、**直接网卡发送/no-op 树编辑/关闭与滚动条**（G33，VM 行为 + 源码接线）。**S-04/部分 H-13/A-01 及真实 Windows UI 确认** 仍为 C。

---

*文档结束。A/B 类用例均有可执行路径；C 类用例需按第 24 节清单人工执行。*