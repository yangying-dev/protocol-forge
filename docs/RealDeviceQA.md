# Real-Device QA — Npcap (Windows) & BPF (macOS) 真机验证清单

> 目的：验证 rung 0（原生 L2 路径）在真机上的探测、直接注入与降级行为。
> 当前优先支持平台为 Windows 10/11 x64；macOS BPF 项保留为后续兼容性门禁。
> 自动化前置：`dotnet build ProtocolForge.sln` 0 warning/0 error，`dotnet run --project tests/pf-verify` 输出 `ALL GROUPS PASS` 且 footer 中无 `GROUP(S) SKIPPED`。
> 数据安全：真机验证使用合成夹具或已脱敏抓包；原始 PCAP 不得进入 Git、CI 制品、截图或营销材料。

## 观察渠道（每个用例都看）

1. **trace.log**（`%LOCALAPPDATA%/ProtocolForge/logs/trace.log`；Linux `~/.local/share/ProtocolForge/logs/trace.log`；macOS `~/Library/Application Support/ProtocolForge/logs/trace.log`）：探测结果、失败原因、errno。
2. **UI 状态栏/发送计数**：成功消息前缀 `(npcap)` / `(bpf)`；sent/failed 计数器。
3. **抓包验证**：对端或另一台机器用 Wireshark 抓帧，核对 EtherType、src MAC（Auto-fix 开启时应为本机接口 MAC）、帧尾 padding。

---

## A. Windows 10/11 x64 + Npcap（W0–W6）

### W0 安装基线
- 步骤：安装 Wireshark → 确认安装器中的 Npcap 选项保持勾选 → 安装/解压 self-contained ProtocolForge → 启动应用。
- 预期：tshark >= 2.6.0 可被应用发现；应用不尝试安装或捆绑 Npcap；缺少 Npcap 时明确走降级路径。
- 判定：安装说明和发布包可用。

前置：在 Windows 10/11 x64 上安装 Wireshark；安装器中的 Npcap 选项保持默认勾选。应用不捆绑 Npcap。确认 tshark >= 2.6.0。

### W1 已装 Npcap + 管理员运行
- 步骤：管理员启动应用 → 选物理网卡（有线优先）→ 勾选一个 TCP 报文 → Auto-fix 开 → 点击 **开始** 发送。
- 预期：探测成功（trace.log 出现 wpcap.dll 路径）；消息含 `(npcap)`；对端抓包可见完整以太帧且 **src MAC = 本机接口 MAC**、EtherType 正确。
- 判定：真机注入成功页（对端 `tcpdump -i eth0` 或 Wireshark 可解析 TCP payload）。

### W2 已装 Npcap + 非管理员运行
- 步骤：普通用户启动 → 同 W1 发送。
- 预期：`pcap_open_live` 失败（权限）→ rung 0 降级；`(npcap)` 不出现；TCP 发送失败并给出 raw-socket 不支持提示；UDP payload 可发。
- 判定：行为与未装 Npcap 的退化路径一致（对比本机回归 G1–G8）。

### W3 未装 Npcap
- 步骤：卸载 Npcap → 发送。
- 预期：探测返回 null（trace.log 记录 DLL 缺失）；纯托管注入；与 W2 最终效果一致。
- 判定：回归通过，无异常崩溃。

### W4 GUID 匹配（双网卡）
- 步骤：装 Npcap，机器上有 ≥2 个活动网卡（如有线+无线）→ 各选一次发送。
- 预期：每次选择都匹配到正确的 NPF 设备（GUI 显示网卡名，trace.log 记录 `\Device\NPF_{GUID}`）；不出现"错网卡注入"（目的网卡抓不到包）。
- 判定：GUID 归一化（花括号剥离 + OrdinalIgnoreCase）在真机上成立；描述兜底路径不触发或触发时设备正确。

### W5 逐包降级（帧不可发）
- 步骤：发送一个 <14 字节的裸 IP 帧（编辑为长度不足）或超 MTU 帧。
- 预期：`pcap_sendpacket` 失败 → 该包降级到后续 rung（或 UDP 提取），消息含失败原因；不崩溃。
- 判定：sent/failed 计数正确，trace.log 有错误记录。

### W6 运行中卸载 Npcap
- 步骤：应用运行中卸载 Npcap → 再次开始发送（无需重启进程，探测为每会话）。
- 预期：探测重新执行并失败 → 退回纯托管注入；无句柄泄漏崩溃。
- 判定：进程稳定；若在当前会话仍持有旧句柄，仅在闭包后重新探测——记录实际行为作为已知限制。

---

## B. macOS + root BPF（M1–M6）

前置：`sudo` 可用的 Mac（Intel/Apple Silicon 均可）；`en0`（或 Wi-Fi 网卡）存在。

### M1 root 管理员注入（en0）
- 步骤：`sudo` 启动应用 → 选 en0 → 勾选 TCP 报文 → Auto-fix 开 → 发送。
- 预期：探测成功（trace.log 出现 `/dev/bpfN` 与接口名）；消息含 `(bpf)`；对端抓包可见完整以太帧。
- **关键**：验证 **BIOCSHDRCMPLT=1 生效**——帧的 src MAC 应等于 Auto-fix 注入值（本机 MAC），而不是被内核改写为其他地址。若 src MAC 不符合预期，优先怀疑 ioctl 魔数（`0x80044272`）在真机上的字节序。
- 判定：真机注入成功页。

### M2 非 root
- 步骤：普通用户启动 → 发送。
- 预期：`/dev/bpfN` open 失败（EACCES）→ rung 0 判空 → 纯托管注入。
- 判定：与 W3 行为一致；trace.log 记录 errno。

### M3 loopback 跳过
- 步骤：选择 lo0（若 UI 暴露）发送。
- 预期：`BpfSendService` 直接判空（loopback 无以太帧语义）→ 降级；不尝试绑定 lo0。
- 判定：trace.log 有跳过记录（或无 bpf 探测记录），无崩溃。

### M4 Wi-Fi 网卡（en0 不存在）
- 步骤：仅 Wi-Fi 的 Mac（en1/en0 命名不同）→ 选 Wi-Fi 网卡发送。
- 预期：`BuildIfreq(wifi 接口名)`（≤15 字符截断）绑定成功；注入正常。
- 判定：接口名截断在真机上不引发绑定错位；抓包验证帧可达。

### M5 无 root 但进程有 sudo 后 drop？(可选) / 绑定失败路径
- 步骤：用 root 启动但把目标网卡 down（`sudo ifconfig en0 down`）→ 发送。
- 预期：`BIOCSETIF` 失败 → rung 0 判空 → 降级；trace.log 含 ioctl 错误（errno）。
- 判定：绑定失败静默降级成立，无异常。

### M6 超 MTU 帧
- 步骤：发送长度 > 接口 MTU 的帧。
- 预期：`write()` 失败（EMSGSIZE/EIO）→ 该包降级；消息含 strerror 文本。
- 判定：逐包降级正确；与 W5 语义一致。

---

## 完成条件

- [ ] CI 回归：`dotnet build ProtocolForge.sln` 0 警告/0 错误；`pf-verify` 输出 **ALL GROUPS PASS**，且确认 footer 中没有 `GROUP(S) SKIPPED`（本机无抓包夹具时该提示必然出现，不能算全量覆盖）
- [ ] Windows 发布探针：`win-x64` self-contained publish 成功
- [ ] W0–W6 全部通过或行为与预期一致（不符合项记录 trace.log 证据）
- [ ] 直接点击开始即可通过所选物理网卡发送；目标网卡、权限和降级行为与记录一致
- [ ] 真机证据使用合成/脱敏数据，原始 PCAP 未进入仓库或发布制品
- [ ] macOS M1–M6 暂不阻塞 Windows 首发；计划支持 macOS 时再完成