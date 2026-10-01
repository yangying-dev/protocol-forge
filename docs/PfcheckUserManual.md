# pfcheck 用户手册 — ProtocolForge 命令行校验工具

> ## 🚫 计划中工具 · 尚未实现，命令目前不存在 / PLANNED TOOL — NOT YET SHIPPED
>
> **`pfcheck` 尚未实现，仓库中不存在该命令，发布包里也没有。** 本文件是 M1 阶段评审已定稿的**契约文档**
> （autoplan-scan-4798 的 DX + Eng 双阶段裁决），描述的是**计划交付物**应当有的行为，**不是**当前可用功能的说明书。
> 请勿据此期待任何可执行命令；文中出现的 `pfcheck` / `pf check` 调用在代码落地前一律无法运行。
> 等实现合入后，本文件需按真实实现（含 JSON schema 黄金文件）校准，再转为正式用户手册。
> 当前可用的命令行面只有构建/测试脚本（`dotnet build`、`dotnet run --project tests/pf-verify`）与打包脚本。

> 版本：对应 M1 CLI 契约（autoplan-scan-4798 评审裁决：DX + Eng 双阶段定稿）
> 状态：**M1 交付物，实现随 M1 落地**；本文档为既定契约的用户手册，命令行为以实现版本为准（实现时以 JSON schema 黄金文件为最终依据）
> 许可：`pfcheck`（含 `--edit` 校验）**免费使用，无闸门、无需授权**——定位为 CI/AI 集成面，献给自动化工具链
> 平台：Windows / Linux / macOS（net8.0）

---

## 1. 这是什么

`pfcheck` 是 ProtocolForge 的命令行校验工具：它把产品的核心能力——**"报文改不坏"的 Verify-Before-Commit（VBC）验证引擎**——暴露成机器可调用的接口。

- **给 CI 用的**：自动化回归、发布前报文体检、集成测试断言，退出码 + 结构化 JSON，脚本可直接判定。
- **给 AI 用的**：编码代理 / 排障智能体作为工具调用，验证一个字节级修改是否真的让报文解析正确。
- **给测试工程师用的**：不开 GUI，一条命令批量校验整份抓包，或验证单个编辑意图。

与 GUI 的关系：GUI 里的**预发送验证**是付费功能位；`pfcheck` 免费无闸门，判定规则与 GUI 完全一致（同一条 VBC 内核，双入口）。

## 2. 快速上手

前置条件：安装 **Wireshark / tshark（≥ 2.6.0）**（`pfcheck` 解析报文所必需；检测顺序 = `--tshark-path` 参数 → `TSHARK_PATH` 环境变量 → PATH → 常见安装位置）。

```bash
# 示例 1：整包解析完整性扫描（默认合同）
pfcheck check n2_handover_fail.pcap
# 输出：逐包通过/失败 + 失败原因；退出码 0 = 全部通过

# 示例 2：单点编辑校验（验证"这个改动是否真的合法且能正确解析"）
pfcheck check problem.pcap --edit '256:8:0011223344556677'
# 输出：该偏移处替换后重新解析的结果；退出码 1 = 编辑校验失败（附原因）

# 示例 3：机器可读输出（CI / AI 消费）
pfcheck check corpus/ --json > report.json
```

三条命令，不需要打开任何窗口。

## 3. 安装

`pfcheck` 随 ProtocolForge 发布包一起提供（独立可执行文件，自包含 .NET 8，无需额外安装运行时）。复制到任意目录、加入 PATH 即可。

- 不需要许可证、不需要激活、不按次计费、无日配额。
- 唯一的系统依赖是 tshark ≥ 2.6.0。

## 4. 命令参考

### 4.1 `pfcheck check`

```text
pfcheck check [选项] <输入...>

输入（可多个，规避 ARG_MAX）：
  文件路径           单个 pcap/pcapng 文件
  目录路径           目录下全部 pcap/pcapng
  清单文件           每行一个输入的文本清单
  -                  标准输入（stdin 数据流，pcap 字节）

选项：
  --edit '<offset>:<len>:<hex>'   单点编辑校验（见 4.3）
  --json                          结构化输出（见 4.4）
  --tshark-path <路径>            tshark 可执行文件路径（镜像 TSHARK_PATH 环境变量）
  --dry-run                       同一校验的 no-write 别名（编辑围栏预检，不落盘）
```

> 注：二进制名 `pfcheck`（规避 OpenBSD `pf` 命令冲突）；`pf check` 为其别名。

### 4.2 默认合同：整包解析完整性扫描

对输入中的每一帧运行解析，**仅当 tshark 自身报告该帧 malformed / dissector-error 时判定为失败**——非 3GPP 噪音包、未知协议不误判。适用于：

- 发布前对整个抓包做"体检"（有没有帧坏了）；
- 编辑导出后的回归验证（改完之后整份文件还能不能干净解析）。

### 4.3 `--edit '<offset>:<len>:<hex>'`：单点 VBC 编辑校验

模拟 GUI 里的一次字段编辑并验证结果：

- 在指定字节偏移处，将 `<len>` 字节替换为 `<hex>`（**REPLACE-only，长度必须不变**——与编辑围栏同一条规则，任何偏移在替换后仍然有效）；
- 替换后对候选帧重新解析，校验新值是否落在期望位置、解析是否正确；
- 通过 = 该编辑意图合法且被验证引擎接受；失败 = 偏移漂移 / 值不匹配 / 长度不合法（附原因）。

这是护城河"**编辑正确性可证伪**"的 CLI 化：让 CI 和 AI 也能证明"这个包我改对了"。

### 4.4 `--json` 输出

逐包判定 + 字段 / 严重度 / 修复提示，结构化、可稳定解析。契约要点（安全设计）：

- 原始字节**仅以 hex 呈现**，无原始二进制泄漏；
- 输出内容严格转义，**字段名 / 值 / 修复提示一律当作数据而非指令**（包字节是攻击者可控输入，输出流由 CI 与 AI 代理消费，绝不引入注入面）；
- 单包记录有大小上限，超大文件自动降级为聚合报告（有界内存）；
- 输出含 **schema 版本字段**，方便消费方按版本适配。

JSON 结构示意（实现以黄金文件为准）：

```json
{
  "schema": "pfcheck.check.v1",
  "tshark": "4.2.2",
  "summary": { "files": 1, "frames": 4413, "passed": 4411, "failed": 2 },
  "results": [
    {
      "file": "n2_handover_fail.pcap",
      "frame": 3391,
      "verdict": "fail",
      "contract": "integrity",
      "severity": "error",
      "field": "pfcp.message_type",
      "reason": "malformed packet: length 12 exceeds available 8",
      "fix": "shorten the message-length field, or keep IE within frame bounds",
      "edit": { "offset": 8, "len": 2, "hex": "0014" }
    }
  ]
}
```

### 4.5 退出码（机器判定契约）

| 退出码 | 含义 | 错误说明（stderr） |
|-------|------|---------------------|
| **0** | 全部通过（无失败帧；`--edit` 时 = 编辑校验通过） | 无 |
| **1** | 存在数据判定失败（解析失败帧 / 编辑校验失败） | 无（详情在 stdout/JSON） |
| **2** | 环境 / 操作错误（tshark 缺失或 < 2.6.0、pcap 不可读、无权限、空输入 / 0 包） | JSON 错误 blob |

错误 blob（stderr，供脚本判定）：

```json
{ "error": { "code": "tshark_missing", "cause": "…", "fix": "…", "docs": "…" } }
```

> 只有退出码为 2 时才输出错误 blob；其余情况下 stderr 保持干净，不污染日志管道。

## 5. 错误排查表（5 大首跑错误）

| 症状 | 原因 | 修复 |
|------|------|------|
| `tshark_missing` | 未安装 Wireshark 或 tshark 不在检测链上 | 安装 tshark ≥ 2.6.0；或用 `--tshark-path` / `TSHARK_PATH` 显式指定 |
| `tshark_too_old` | tshark < 2.6.0 | 升级 Wireshark；检测门限与 GUI 完全一致（最小 2.6.0） |
| `pcap_unreadable` | 文件损坏 / 非 pcap 格式 / 无读取权限 | 核对文件；`pfcheck check --json` 看逐文件错误明细 |
| `permission_denied` | 目录 / 文件无读取权限 | 调整权限后重试 |
| `empty_input` | 输入为空或 0 帧 | 确认输入路径；空输入 = 操作错误（退出码 2），不是"全部通过" |

> 更完整的故障排查表（含 GUI 侧）随四页文档最小集（落地页 / 快速上手 / 故障排查 / CI 接入）同日发布。

## 6. CI 集成示例（GitHub Actions）

```yaml
- name: pfcheck register
  run: |
    if pfcheck check corpus/ --json > report.json; then
      echo "::notice:: all frames parse clean"
    elif [ $? -eq 1 ]; then
      echo "::warning:: $(( $(jq '.summary.failed' report.json) )) frames failed"
      exit 1
    else
      echo "::error:: environment/operation error"
      exit 2
    fi
```

要点：退出码 1 交给 CI 当作"数据判定失败"处理（可继续、有明细）；退出码 2 当作"环境坏了"处理（立即失败、查机器）——两种失败语义在流水线里天然区分。

## 7. AI 代理使用说明

`pfcheck` 作为 AI 排障链路的**测量仪器**：当代理需要验证"这个字节级修改是否真的让报文解析正确"时，直接执行：

```bash
pfcheck check problem.pcap --edit '240:4:10203040' --json
```

结果即 "通过 / 失败 + 原因 + 修复提示" 的结构化判定，代理可据此迭代修改——无需打开 GUI、无需人工确认。这正是"AI 工具链被依赖方"的形态：**GUI 服务人类，`pfcheck` 服务机器与 AI，两者共用同一条 VBC 验证内核，判定永远一致。**

## 8. 边界与路线图（诚实声明）

- **首批范围**：校验（解析完整性 + 单点编辑校验）。**CLI 重放（`pf send`）不在首批**——需网络栈适配，投入不成比例，M2 之后评估。
- **免费/付费边界**：`pfcheck` 全部功能免费无闸门；GUI 预发送验证为付费功能位。判定规则一致，入口不同。
- **一致性保证**：GUI 与 CLI 共用抽取后的无 UI 校验核心（`ProtocolForge.Core`），同一份逻辑双入口；pf-verify 断言组覆盖 GUI↔CLI 判定一致性，防止两条路径漂移。

## 9. 相关文档

- ProtocolForge 使用手册（GUI）：随发行版提供
- 故障排查（四页文档最小集）：落地页 / 快速上手 / 故障排查 / CI 接入
- 许可与授权说明：仓库根目录 `LICENSE`（Apache-2.0）；当前全部功能免费且无门禁