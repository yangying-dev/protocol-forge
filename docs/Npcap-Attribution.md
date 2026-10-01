# Npcap Attribution — 归属声明

> 适用位置：**[`THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md)**（随产物分发的正式第三方声明）+ **About 对话框**。
> 本项目**不再随包分发 EULA**：分发时的第三方义务由 `THIRD-PARTY-NOTICES.md` 承载，Npcap 的使用条款由用户自行在 npcap.com 接受。
> 发布前需核对：① Npcap 版权年份与商标归属以 [npcap.com/license](https://npcap.com/license) 当期为准；② 若未来改为**捆绑分发** Npcap，必须另行购买 Nmap Software 的 OEM Redistribution License（付费、按公司规模分档），本声明不再适用。
> 当前发布主体：ProtocolForge 独立开发者项目；当前年份：2026；应用版本由程序集元数据动态读取。
>
> 客户安装口径：Windows 10/11 x64 客户自行安装 Wireshark，并保留安装器中的 Npcap 选项（默认勾选）。ProtocolForge 不捆绑、不静默安装 Npcap。

---

## 1. 第三方组件声明段落（并入 THIRD-PARTY-NOTICES.md）

### EN

> **Third-Party Component Notice — Npcap**
>
> This software may optionally interface with **Npcap**, a packet capture and
> injection library developed by Nmap Software LLC. Npcap is proprietary
> software and is **NOT distributed with or bundled into this product**.
> ProtocolForge does not install Npcap. ProtocolForge merely detects, at
> runtime, a copy of Npcap that the end user has independently installed, and
> dynamically invokes it via P/Invoke solely for Layer-2 frame injection.
> Use of Npcap is governed exclusively by the license terms accepted by the
> end user during Npcap's own installation process. If Npcap is not present,
> ProtocolForge automatically falls back to pure-managed socket injection and
> does not use Npcap in any way.
>
> Npcap is Copyright © 2013-2026 Nmap Software LLC (Insecure.Com LLC).
> Npcap is a trademark of Insecure.Com LLC. All other trademarks are the
> property of their respective owners.

### 中文

> **第三方组件声明 — Npcap**
>
> 本软件可选地调用 **Npcap**——一款由 Nmap Software LLC 开发的报文捕获与
> 注入库。Npcap 为专有软件，**不随本产品捆绑或分发**，ProtocolForge 也不负责
> 安装 Npcap。ProtocolForge 仅在运行时探测最终用户已单独安装的 Npcap 副本，
> 并通过 P/Invoke 动态调用它，仅用于二层帧注入。Npcap 的使用完全受最终用户在
> Npcap 自身安装过程中所接受的许可条款约束。若未安装 Npcap，ProtocolForge
> 将自动降级为纯托管套接字注入，不以任何方式使用 Npcap。
>
> Npcap 版权归 Nmap Software LLC（Insecure.Com LLC）© 2013-2026 所有。
> Npcap 是 Insecure.Com LLC 的商标。其他商标归各自所有者所有。

## 2. 客户安装说明

1. 下载并安装 Wireshark。
2. 在 Wireshark/Npcap 安装界面确认 **Install Npcap** 已勾选；默认安装流程会勾选该选项。
3. 如组织安全策略要求取消 Npcap，必须提前告知客户：缺少 Npcap 时应用会降级到纯托管发送路径，完整二层帧发送能力可能不可用。
4. 客户不需要单独下载或安装 ARM64 版本；当前商业支持目标为 Windows 10/11 x64。
5. 发送前让客户确认 tshark >= 2.6.0，必要时在 **文件 → Tshark 路径...**（英文界面：File → Tshark Path...）选择 `tshark.exe`。

---

## 3. About 对话框文案（已接入）

`ProtocolForge/Views/MainWindow.axaml.cs` 的 `OnAboutClicked()` 从入口程序集读取三段式版本号，并通过中英文字典显示以下内容：

```text
ProtocolForge v{assembly-version}
3GPP Protocol Simulation & Debugging

Built with Avalonia UI + .NET 8
Protocol parsing: Tshark (Wireshark CLI)
Optional L2 injection: Npcap® by Nmap Software LLC (not bundled)
Npcap is NOT bundled and NOT installed by this app.
Npcap terms: https://npcap.com/license
See THIRD-PARTY-NOTICES.md in your install folder.
```

中文环境显示等价的「可选二层注入 / 不随产品捆绑 / Npcap 不随本产品捆绑，也不会被本应用自动安装」文案。

完整的第三方许可文本与边界论证见仓库根目录的 [`THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md)。

---

## 4. 发布前核对清单（Legal Gate）

| # | 事项 | 状态 |
|---|------|------|
| 1 | 核对 npcap.com/license 当期版权年份与商标表述（本稿用占位符） | ☐ |
| 2 | 确认不捆绑 Npcap（保持“用户自装 + 运行时探测”），客户安装 Wireshark 时保留 Npcap 默认选项 | ☑ |
| 3 | 每日发送配额已于 2026-09-29 下线；当前无任何配额或发送次数限制 | ☑ |
| 4 | About 对话框已接入程序集版本号和 Npcap 归属提示 | ☑ |
| 5 | 本段落并入 `THIRD-PARTY-NOTICES.md`，并随 AppImage / deb / ZIP 一同分发 | ☐ |
| 6 | 若打包工具扫描第三方组件（如 WinGet/OEM 审核），登记 Npcap 动态依赖 | ☐ |