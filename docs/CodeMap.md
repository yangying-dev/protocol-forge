# ProtocolForge 代码地图（CodeMap）

> **用途**：客户报 bug 时，从「用户界面操作」出发，逐层追踪触发了哪些函数、这些函数干什么，快速定位问题代码位置。
> **用法**：先看 [第 10 章 排障速查表](#10-排障速查表symptom--triage)，按症状定位章节，再沿调用链逐层下钻。
> **配套**：`docs/RealDeviceQA.md`（实机 QA 门禁）、`AGENTS.md`（项目约定）。

---

## 目录

- [1. 全局架构速览](#1-全局架构速览)
- [2. 启动与依赖装配](#2-启动与依赖装配)
- [3. 打开文件 → 列表加载](#3-打开文件--列表加载)
- [4. 选择报文 → 树构建 → hex 高亮](#4-选择报文--树构建--hex-高亮)
- [5. 编辑报文（树字段 / hex 字节）](#5-编辑报文树字段--hex-字节)
- [6. 保存 / 另存为 / 重置修改](#6-保存--另存为--重置修改)
- [7. 发送报文（rung 阶梯）](#7-发送报文rung-阶梯)
- [10. 排障速查表（Symptom → Triage）](#10-排障速查表symptom--triage)
- [附录 A：序列守卫](#附录-a序列守卫)
- [附录 B：用户可见错误串全集](#附录-b用户可见错误串全集)
- [附录 C：文档与代码不一致点](#附录-c文档与代码不一致点)
- [附录 D：验证夹具 pf-verify（G1–G8）](#附录-d验证夹具-pf-verifyg1g8)

---

## 1. 全局架构速览

### 1.1 分层与依赖方向

```
MainWindow.axaml (视图)                ← ViewLocator / 代码后置事件
   ↓ DataContext
ViewModels (6 个)                      ← 只持有"命令 + 属性 + 事件"；跨面板用事件通信，不用直接引用
   ↓ 构造函数注入
Services (16 个文件)                   ← 纯业务逻辑，不引用 VM；结果用 sealed record 返回
   ↓
Models (8 个)                          ← Packet / ProtocolField / PacketDocument 等域对象
```

- **MVVM + 手动 DI**：无 IoC 容器。服务在 `App.axaml.cs` 按依赖顺序手工 new；VM 通过构造函数拿依赖。
- **事件通信**（VM 之间唯一耦合方式，`MainWindowViewModel` 构造时订阅）：

| 事件 | 谁触发 | 触发点 | 谁处理 |
|---|---|---|---|
| `PacketSelected` | `PacketListViewModel.OnSelectedPacketChanged` | PacketListViewModel.cs:89 | `MainWindowViewModel.OnPacketSelected` |
| `FieldSelected` | `ProtocolTreeViewModel.OnFieldClicked` | ProtocolTreeViewModel.cs:108 | `OnFieldSelected` → hex 高亮 |
| `LayerSelected` | `ProtocolTreeViewModel.OnLayerClicked` | ProtocolTreeViewModel.cs:118 | `OnLayerSelected` → hex 高亮 |
| `FieldEdited` | `ProtocolTreeViewModel.CommitFieldEditAsync`（VBC 成功后才发） | ProtocolTreeViewModel.cs:312 | `OnFieldEdited` |
| `HexEdited` | `HexEditorViewModel.CommitHexEditAsync`（ApplyModification 后发） | HexEditorViewModel.cs:475 | `OnHexEdited` |
| `FieldFoundAtOffset` | `HexEditorViewModel.SelectByteAtOffset` | HexEditorViewModel.cs:316 | `OnHexFieldFound` → 树定位 |

### 1.2 服务清单（16 文件）

| 类别 | 服务 | 一句话职责 |
|---|---|---|
| instance（sealed class，App.axaml.cs 手工 DI） | `TsharkService` | 列表流式加载 + 按包 jsonraw/json/pdml 树构建 + 单包 pdml 重解析 + 版本门禁（2156 行，最大文件） |
| | `PcapIngestService` | 原生字节读 PCAP/PCAPNG（大小端、µs/ns 时间戳、pcapng 块遍历） |
| | `PcapExportService` | 写标准 libpcap（覆盖保存 / 另存为 / VBC 与刷新用的临时单包文件） |
| | `EditTransactionService` | Verify-Before-Commit：候选帧 → 临时 pcap → tshark 重解析 → (name,offset) 校验 → 提交/中止 |
| | `ProtocolEditorService` | 编辑栅栏 `CheckTreeEditFence`（6 检查）、字段偏移反查、hex↔value 转换 |
| | `PacketSendService` | rung 阶梯注入：L2(Npcap/BPF) → AF_PACKET → IP raw → UDP |
| | `NetworkInterfaceService` | 网卡枚举 + 取 IP |
| | `LayoutService` | 窗口几何/分隔条/面板可见性持久化 |
| | `TsharkSettingsService` | tshark 路径 + TLS keylog 路径持久化 |
| static（无 DI） | `PacketPrepareService` | 发送前帧修复：源 MAC/IP 改写、校验和重算 |
| | `NpcapSendService` / `BpfSendService` | Windows/macOS L2 rung（实现 `IL2SendRung`；失败静默降级） |
| | `TraceLog` | `Trace.WriteLine` 包装 |

### 1.3 序列守卫（防陈旧异步结果覆盖新状态，详见 [附录 A](#附录-a序列守卫)）

`_treeBuildSeq`（选择）· `_reparseVersions`（编辑后刷新）· `_prefetchSeq` + `_prefetchGate`（邻居预取）· `_buildingPackets`（重复构建去重）。

---

## 2. 启动与依赖装配

### 2.1 `Program.Main`（Avalonia 之前）

```
Program.Main [STAThread]
├─ AddFileTraceListener()
│   ├─ TraceLog.LogDirectory = LocalApplicationData/ProtocolForge/logs → Directory.CreateDirectory
│   ├─ TryRotateTraceLog(trace.log)   // >2MB → 级联备份 trace.log.1/.2，保留 2 份；失败 = 静默追加
│   ├─ Trace.Listeners.Add(new TextWriterTraceListener(logPath))
│   └─ Trace.AutoFlush = true
│   (整体 try/catch → Debug.WriteLine)
├─ RegisterCrashRecorders()
│   ├─ AppDomain.CurrentDomain.UnhandledException += → TraceLog.Write("Unhandled exception: …")
│   └─ TaskScheduler.UnobservedTaskException += → TraceLog.Write("Unobserved task exception: …")
└─ BuildAvaloniaApp().StartWithClassicDesktopLifetime(args)
    = AppBuilder.Configure<App>().UsePlatformDetect()
      #if DEBUG .WithDeveloperTools() #endif
      .WithInterFont().LogToTrace()
```

### 2.2 `App.axaml.cs` 组合根（OnFrameworkInitializationCompleted）——构造顺序即 DI 顺序

```
1.  new TsharkSettingsService()      // LoadTsharkPath → 非空则设 TSHARK_PATH 环境变量（先于版本检测）
2.  new PcapIngestService()
3.  new PcapExportService()
4.  new TsharkService(pcapIngest, pcapExport)
5.  new ProtocolEditorService()
6.  new EditTransactionService(pcapExport, tshark)
7.  new NetworkInterfaceService()
8.  new PacketSendService()
9.  new PacketListViewModel()        // 无依赖
10. new ProtocolTreeViewModel(protocolEditor, editTransaction)
11. new HexEditorViewModel(protocolEditor)
12. new ToolBarViewModel(networkInterface, sendService, packetList)
13. new MainWindowViewModel(tshark, pcapExport, protocolEditor, packetList, protocolTree, hexEditor, toolBar)
    // 构造内订阅 6 个事件（见 1.1 表）+ ToolBar.PropertyChanged → 镜像 StatusText
14. Tshark 门禁：TsharkService.DetectTshark()（静态、进程级缓存）
    // !Ok → mainViewModel.IsReadOnly = true; TsharkWarning = message; StatusText = "只读模式 — {msg}"; toolBar.IsReadOnly = true
15. new MainWindow { DataContext = mainViewModel }
16. 命令行参数：desktop.Args[0] 非空
     → mainWindow.Opened += async (_, _) => await mainViewModel.LoadFileAsync(path)     // 窗口显示后才加载
17. desktop.MainWindow = mainWindow
```

### 2.4 窗口布局恢复与菜单

- `MainWindow` 构造：`RestoreLayout()` → `_layoutService.Load()` → 顶部区域钳位 0.15–0.75、左列钳位 0.15–0.85 → 设 Grid star 值；`DataContextChanged += OnDataContextChanged`（一次性挂 `PacketList.SendSelectionChanged → SyncHeaderSelectAllCheckBox`）。
- 退出路径：`OnClosing` / `OnExitClicked` → `SaveLayout()` → `ViewModel.SaveLayout(topRatio, bottomRatio, X, Y, W, H, WindowState)` → `_layoutService.Save`。

**菜单结构**（MainWindow.axaml）：

| 菜单 | 项 | 处理 |
|---|---|---|
| File | Open PCAP (Ctrl+O) / Save PCAP (Ctrl+S) / Export PCAP As (Ctrl+Shift+S) / Reset Modifications / Tshark Path… / Exit | `OnOpenPcapClicked` / `OnSavePcapClicked` / `OnExportPcapClicked` / `OnResetClicked` / `OnPickTsharkClicked` / `OnExitClicked` |
| View | Packet List / Protocol Tree / Hex Editor / Reset Layout | `TogglePacketListCommand` / `ToggleProtocolTreeCommand` / `ToggleHexEditorCommand` / `OnResetLayoutClicked` |
| Help | 打开支持数据目录 / About | `OnOpenLogDirClicked` / `OnAboutClicked` |

**3 大面板**：Row3 ContentGrid = `2*,Auto,3*` — PacketListPanel(DataGrid 名 `PacketListView`) | GridSplitter | BottomGrid(`*,4,*`：ProtocolTreePanel、BottomSplitter、HexEditorPanel)。Row0 菜单、Row1 工具栏、Row2 只读横幅（`IsVisible="{Binding IsReadOnly}"`）、Row4 状态栏（StatusText / LoadProgress / FileName / Modified: N）。

### 2.5 文件对话框统一走 StorageProvider

```
MainWindow.axaml.cs
├─ OpenPcapDialogAsync → StorageProvider.OpenFilePickerAsync(FilePickerOpenOptions{ AllowMultiple=false, FileTypeFilter=[*.pcap;*.pcapng;*.cap, *] })
│                       → IStorageFile.TryGetLocalPath() → ViewModel.LoadFileAsync(path)
 ├─ ExportPcapDialogAsync → StorageProvider.SaveFilePickerAsync(FilePickerSaveOptions{ *.pcap })
 │                          → ViewModel.ExportToFileAsync(path)
 └─ OnPickTsharkClicked → OpenFilePickerAsync(tshark.exe/tshark) → SaveTsharkPath + 设 TSHARK_PATH + RedetectTsharkFromPath
 ```

> **TLS keylog 无 UI 入口（刻意）**：`File → TLS Keylog…` 菜单已移除。原因是它对任意存在的文件都报"已设置"，而 tshark 会静默跳过无法解析的行——用户只看到"没解密"却毫无线索。能力保留，改由 `SSLKEYLOGFILE` 环境变量或 `settings.json` 的 `TlsKeylogPath` 生效（`App` 启动时恢复，见 `TsharkService.SetTlsKeylogPath`）。

### 2.6 `ViewLocator`

`Build(param)`：FullName 里 `"ViewModel"` → `"View"` → `Type.GetType` → `Activator.CreateInstance`；失败回退 `TextBlock "Not Found: {name}"`。`Match(data)`：`data is ViewModelBase`。实际上只有 MainWindowViewModel 继承 ViewModelBase；树/hex VM 在 XAML 里直接 `DataContext="{Binding …}"`，ViewLocator 很少真正生效。

---

## 3. 打开文件 → 列表加载

两个入口汇聚到同一个漏斗 `MainWindowViewModel.LoadFileAsync(filePath)`。

### 3.1 入口 A：菜单 Open PCAP

```
MainWindow.axaml:25 MenuItem "_Open PCAP..." Click=OnOpenPcapClicked InputGesture=Ctrl+O
→ MainWindow.axaml.cs:151 OnOpenPcapClicked (async void)
→ :303 OpenPcapDialogAsync → OpenFilePickerAsync → TryGetLocalPath()
→ ViewModel.LoadFileAsync(path)
```

### 3.2 入口 B：命令行参数

```
Program.Main(args) → StartWithClassicDesktopLifetime(args)
→ App.axaml.cs:93 desktop.Args[0] 非空 → mainWindow.Opened += async (_,_) => await LoadFileAsync(cmdArgs[0])
```

### 3.3 漏斗 `LoadFileAsync`（MainWindowViewModel.cs:145）

```
1. IsLoading = true; StatusText = "Loading {filename}..."
2. document = new PacketDocument { FilePath = filePath }
3. PacketList.LoadFromDocument(document)          // 先绑空文档 → 渐进填充
4. progress = new Progress<double>(p => LoadProgress = p)
5. BRANCH: IsReadOnly ? _tshark.LoadPcapReadOnlyAsync(document, path)
                      : _tshark.LoadPcapAsync(document, path, progress)
6. Document = document; FileName; TotalPackets; ModifiedPackets = 0
7. PacketList.LoadFromDocument(document)          // 绑完整集合 + 选中
8. if (document.SelectedPacket != null) OnPacketSelected(document.SelectedPacket)   // 触发首个树构建
9. StatusText = "Loaded {count} packets from {filename}"
   catch → StatusText = "Error: {ex.Message}"; finally → IsLoading=false; LoadProgress=0
```

### 3.4 全量路径 `TsharkService.LoadPcapAsync`（TsharkService.cs:66）

**阶段 1 — 原生读（不调 tshark）**：`EnsureTsharkAvailable()` → `_pcapIngest.ReadPacketsAsync(filePath)` → 设 `PacketCount/LinkLayerType/Snaplen` → 挂 3 个惰性 `ContextProviders`（`SdpContextProvider`/`FragmentContextProvider`/`TcpStreamContextProvider`，首次需要时才整包扫描）。

**阶段 2 — 单次流式 `-T fields`**：

```
tshark -r "{file}" -T fields -E header=n -E separator=/t \
  -e frame.number -e _ws.col.Source -e _ws.col.Destination \
  -e _ws.col.Protocol -e _ws.col.Info [TLS keylog 参数]
流式循环（批 500）：
  line.Split('\t', 5)                                  // 最大 5 段：Info 可能含 tab
  cols.Length<4 或 frame.number 非数字 → continue      // 畸形行跳过
  idx = frameNumber - 1                                // ★ frame.number 对齐到原生读的包
  idx 越界 → continue
  batch.Add(new Packet{ Index, Timestamp, RawData, SourceAddress=cols[1]空?"N/A":…, … })
  batch ≥500 → document.Packets.AddRange(batch)        // 单次 CollectionChanged（性能关键）
              → progress.Report(0.05 + 0.9*count/total)
flush 余批 → WaitForExitAsync → ExitCode≠0 → throw "Tshark exited with code {code}: {error}"
完成后 if (Packets.Count>0) SelectedPacket = Packets[0]
```

**容错**：无法解析的行、越界 frame.number 静默跳过；tshark 非零退出则整体失败。**进度**：0.05 → 每 500 包 0.05+0.9·count/total → 1.0。**取消**：每行 `ThrowIfCancellationRequested`。

### 3.5 只读路径 `LoadPcapReadOnlyAsync`（TsharkService.cs:377）

纯原生读，不调 tshark：`SourceAddress/DestinationAddress="N/A"`、`ProtocolName=""`、`InfoText=$"(raw {n} bytes)"`。后果：无列、无 ContextProviders、树不可构建。

### 3.6 `PcapIngestService` 原生解析管线

```
ReadPacketsAsync → File.ReadAllBytesAsync → ParseRawPcap
├─ Magic（首 4 字节 LE 读）:
│    0x0A0D0D0A → ParsePcapNg
│    0xa1b2c3d4 → LE µs； 0xd4c3b2a1 → BE µs
│    0xa1b23c4d → LE ns； 0x4d3cb2a1 → BE ns
│    其他 → InvalidDataException("Unknown PCAP magic")
├─ classic 记录（offset 24 起）: tsSec, tsFrac, inclLen, origLen
│    timestamp = tsSec*1_000_000 + (ns ? tsFrac/1000 : tsFrac)     // 统一归一化到 µs
│    截断文件 → break（静默停）
└─ pcapng 块遍历:
      SHB 0x0A0D0D0A（每节 BOM 判定大小端，接口 ID 每节重置）
      IDB 0x1 → 若_tsresol 选项(code 9)；首接口决定全局 linkType/snaplen
      EPB 0x6 → (tsHigh<<32|tsLow)，按接口分辨率换算；越界块跳过
      SPB 0x3 → 复用上一时间戳；capLen=min(origLen,avail)
      PB  0x2 → 同 EPB 但 16 位 ifaceId
      其他块 → skip（NRB/ISB/DSB 无包）
```

时间戳分辨率（`ConvertTimestamp`，按接口 `if_tsresol`）：MSB=1 → 2^-n；exp≤6 → ×10^(6-exp)；exp>6 → ÷10^(exp-6)；未知接口 → 原样按 µs。

### 3.7 `PacketCollection.AddRange`

批量追加并**只触发一次** `CollectionChanged(Add, batch, start)` —— 18 万包也能保持 UI 响应。逐包 Add 会触发 18 万次网格刷新，是性能红线。

### 3.8 tshark 版本门禁（任何加载前）

```
DetectTshark()（静态缓存）→ FindTshark(): TSHARK_PATH env(文件存在) → PATH → Windows Wireshark 目录 → Linux/macOS 常用路径
→ 跑 "tshark -v" 解析 (\d+\.\d+\.\d+) → VersionCompare < 2.6.0 → 失败
!Ok → IsReadOnly=true 链式传播（见 2.2 第 14 步）→ LoadFileAsync 走只读分支
```

> ⚠️ **实际代码门槛是 2.6.0**（TsharkService.cs:340）。根 AGENTS.md 写的 "4.0 enforced" 是陈旧信息，README 的 "≥2.6.0" 才是对的。

### 3.9 列表绑定面（DataGrid `PacketListView`）

`ItemsSource="{Binding PacketList.Packets}"`、`SelectedItem="{Binding PacketList.SelectedPacket}"`（双向 → 选中事件）、排序用原生 DataGrid（`SortMemberPath` + `CanUserSortColumns`），双击列分隔线触发 `DoubleClickAutoFit`（最多扫 5 万行量最宽唯一文本）。

列：No.(含发送三态勾选框) / Time(`TimestampDisplay`,µs 6 位) / Source / Destination / Protocol / Length / Info(`Summary`,Width="*")。

`SendSelected` 三态：`RecomputeAllSelected()` 由各包勾选行汇集头状态（全选 true / 全不选 false / 混合 null）；`OnAllSelectedForSendChanged` 把头状态写回所有包。

---

## 4. 选择报文 → 树构建 → hex 高亮

### 4.1 选择链（DataGrid 行点击）

```
DataGrid SelectedItem（双向）
→ PacketListViewModel.OnSelectedPacketChanged → SelectedIndex=value.Index → PacketSelected?.Invoke(value)
→ MainWindowViewModel.OnPacketSelected(packet)（构造时订阅）
```

**`OnPacketSelected` 内部顺序**（MainWindowViewModel.cs:375）：

```
1. HexEditor.LoadPacket(packet)                // hex 面板先同步加载
2. packet==null || Layers.Count>0 → ProtocolTree.LoadPacket(packet); return   // 树已建好，仅重绑
3. IsReadOnly → ProtocolTree.LoadPacket(null); return                        // 无 tshark
4. _buildingPackets.Add(packet) 失败 → return                                // 去重（打开文件会选中第一包两次）
5. seq = ++_treeBuildSeq                                                     // 升代
6. ProtocolTree.LoadPacket(null)                                             // 立即清空旧树
7. _ = BuildTreeAsync(packet, seq)                                           // 后台按包构建
```

**树构建完成**（`BuildTreeAsync`）：`ResolveContextFramesAsync` → 缓存 `_packetContextFrames` → 设 `PendingContextFrames/PendingLinkLayerType` → `_tshark.BuildPacketTreeAsync(packet, linkType, context)` → **ok 且 `seq == _treeBuildSeq`** → `ProtocolTree.LoadPacket(packet)` + `BumpPrefetch(packet)`。

**上下文帧**（`CollectContextFrameNumbersAsync`）：把全部 `doc.ContextProviders` 的 `CollectFramesAsync` 结果并集，去掉自身，排序。三个 Provider 全部惰性整包扫描：
- `SdpContextProvider`：`-Y sdp -e frame.number`，返回全部 SDP 帧（RTP codec 映射）。
- `FragmentContextProvider`：`-Y "ip.flags.mf==1 || ip.frag_offset>0"` 按 `ip.id|ip.src|ip.dst` 做 BFS 闭包（嵌套内外分片）。
- `TcpStreamContextProvider`：`-Y tcp -e frame.number -e tcp.stream`，取目标同流在前的近邻片段，预算 2000。

### 4.2 `BuildPacketTreeAsync` 内部（TsharkService.cs:188）

- 临时文件：`Path.GetTempPath() + "pf_tree_{Guid:N}.pcap"`。
- 有上下文 → `PcapExportService.SavePacketWithContextAsync`（上下文帧先写、目标包**最后**写）；无 → `SavePacketAsync` 单包。`finally` 删临时文件。
- **三路并行 tshark**（启动三个进程后才 await，~0.4s/包）：

| 路 | 方法 | 参数 |
|---|---|---|
| jsonraw | `RunTsharkJsonRawAsync` | `-r file -T jsonraw` (+keylog) |
| json | `RunTsharkJsonAsync` | `-r file -T json --no-duplicate-keys` |
| pdml | `RunTsharkPdmlAsync` | `-r file -T pdml` |

- 目标包恒为临时文件**最后一帧**，取三份输出的最后元素。PDML 建查找表；jsonraw 走三遍解析；json 提供人类可读显示值。

**jsonraw 三遍解析**（`ParseJsonrawObject`，:1007）：
- **Pass 1**：把所有 `*_raw` 数组收进 `rawFields: Dictionary<baseName, List<(Hex,Offset,Length,Mask)>>`（`ParseRawArray`：[hex, offset, length, mask, field_id]；少于 3 元素或首元素非 hex 串 → 不入表）。重复键（如 7×`dhcp.option.type_raw`）按序保留，多值数组键 & 元键（`tcp.completeness`）不入表。预扫 `containerBases`（剥 `_tree` 后缀的容器键）。
- **Pass 2**：按 JSON 键序（= Wireshark 行序）单遍发射。三支：**容器**（对象/对象数组 → 建 ProtocolField，递归 Children，额外 raw 孪生如 3×`ip.fragment_raw`+1×`ip.fragment_tree` 作为兄弟字段发射）；**raw 孪生**（多值 → 逐实例，跳过 `addr/host/port` 聚合伪字段；payload 兜底改名 "UDP payload"/"TCP payload" 且 ShowHex=false）；**纯标量**（`hf_text_only` 文本伪叶；匿名叶从 PDML `<field name="" …>` 拿字节跨）。
- **Pass 3**：未被访问的 `_raw` 按字节序追加（孤儿，如无 `_tree` 父的 `ip.src_raw`），排除冗余别名。

**层嵌套**（`ParseLayers` → `ParseSingleLayer`）：跳过 `geninfo/raw/*_raw/_ws.*`（`_ws.malformed` 例外，追加到最内层 DisplayText）；重复层键按协议编号（4×`http2.stream`）；层 Offset 取 PDML `protoPositions` 或 `GetLayerOffset`（各 `*_raw` 最小 offset，排除伪字段）；解析完按 Offset 重排 `packet.Layers`（恢复真实线序）；`DisplayText` 来自 `protoShowNames[(proto, offset)]` 否则大写协议名。

### 4.3 序列守卫应用点（详见附录 A）

| 守卫 | 升代点 | 检查点 | 防的坑 |
|---|---|---|---|
| `_treeBuildSeq` | OnPacketSelected | BuildTreeAsync 提交前 | 旧选择构建覆盖新选择 |
| `_buildingPackets` | OnPacketSelected / Prefetch | 各自入口去重 | 同包并发重复构建（打开文件选第一包两次） |
| `_reparseVersions` | RefreshDisplayAfterEditAsync | 临时保存后 / 重解析后 | 旧编辑刷新覆盖新编辑后的树文本 |
| `_prefetchSeq` | BumpPrefetch | PrefetchNeighborsAsync 窗口检查 | 过期预取窗口继续推进 |
| `_prefetchGate`(信号量2) | — | WaitAsync/Release | 预取不饿死选中包的构建 |
| `_packetContextFrames` | BuildTreeAsync | VBC 临时写 / 显示刷新 | 上下文一次性缓存，避免重复整包扫描 |

### 4.4 `ExtractAddressInfo`（TsharkService.cs:891，每次树构建末尾被调）

- `ip/ipv4` 层：`src/ip_src/addr/Source Address` → `packet.SourceAddress`；`dst/ip_dst/Destination Address` → `DestinationAddress`。**IPv6 永远覆盖，IPv4 仅当前为 "N/A" 才写**（内层优先）。hex 值走 `TryConvertHexToIp`。
- `udp/tcp` 层：`srcport/port/Source Port` → `SourcePort`；`dstport/Destination Port` → `DestinationPort`。
- 刷新列表 Source/Destination 两列 + 供 `RefreshLayerDisplayText`（IP/UDP/TCP 层头文本）用的端口。
- **字节编辑后**：走 `HexEditorViewModel.ReExtractAddressInfo`（:517）直接按字段 offset 读 `EffectiveData`（不读 DisplayValue，因为树文本在重解析前是旧的）。

### 4.5 树 VM 与视图

- `ProtocolTreeViewModel.LoadPacket`：清 `Layers/IsEnabled/SelectedFieldInfo`，把 `packet.Layers` 灌进 `ObservableCollection`。树构建本身在 `packet.Layers`（BuildTreeAsync 里）——VM 只负责展示。
- `SelectFieldOnTree(field)`：只设 `SelectedFieldInfo` + 发 `TreeSelectRequested`，不动树内容。视图侧 `TrySelectField`：`BuildAncestorChain`（field→ParentField→ParentLayer 反序）→ 逐层展开 → 选中 + `BringIntoView()`；容器尚未物化时经 `Dispatcher.UIThread.Post(Background)` 重试 ≤4 次。
- 点击路径：`ProtocolTreeView.OnTreePointerPressed`（隧道）→ 视觉树找到 TreeViewItem → DataContext 是 Layer → `OnLayerClicked`；是 Field → `OnFieldClicked`（双击还触发 `BeginFieldEdit`）。右键菜单 `OnEditValueClicked` → `BeginFieldEdit`。

### 4.6 hex 高亮

- `LoadPacket`：源 = `packet.EffectiveData`（= `ModifiedData ?? RawData`）；每字节一个 `HexByte{Offset,Value,IsSelected=false,IsHighlighted=false}`；`RowCount=ceil(len/16)`。
- `HighlightField`：`ClearHighlights` → `ComputeFieldSpan`（叶用自身 Offset/Length；无位容器取后代 min-start→max-end；`IsUndecodedMarker` 叶解析到所在 IE 起始→包尾）→ **越界守卫：`start+length > EffectiveData.Length` 直接 return**（重组虚拟跨永不越界高亮）→ `HighlightRange` → `ScrollToOffsetRequested(start)`。
- `HighlightLayer`：遍历 `layer.Fields` 求 min/max，跳过 payload 兜底与带外跨；`GetProtocolColor` 按协议名给半透明 Material 色（pfcp 绿、ngap 蓝、gtp 橙、nas 粉、s1ap 紫、diameter 青、udp 靛、ip 浅绿、eth 灰、默认深紫）。
- 背景优先级（`GetByteBackground`）：**选中(深蓝) > 待编辑(黄) > 已编辑(橙) > 高亮(协议色) > 透明**。

**hex→树 反查**：`SelectByteAtOffset(offset)` → `ProtocolEditorService.FindFieldAtOffset`（:255，全层 `FindFieldInLayer` 子先递归）→ `IsMoreSpecific`（真解字段 > payload 兜底；最小跨胜；同跨内层胜）→ 找到 → `HighlightField` + `FieldFoundAtOffset` → `OnHexFieldFound` → `SelectFieldOnTree` → 树展开定位。

### 4.7 邻居预取

`BumpPrefetch`：`gen=++_prefetchSeq` → 后台 `PrefetchNeighborsAsync(anchor, gen)` 遍历 ±3 附近未建包 → `_prefetchGate.WaitAsync()` → `gen != _prefetchSeq` 直接放弃窗口 → `PrefetchTreeAsync`（**无 seq 检查**——选中包自己的构建持有当前 seq，预取永不覆盖选中）。预取失败只写 TraceLog（catch）。

---

## 5. 编辑报文（树字段 / hex 字节）

> **两种提交语义（关键架构点）**：
> - **树编辑 = Verify-Before-Commit**：先候选帧 → 临时 pcap → tshark 重解析 → 校验落点，全部通过才 `ApplyModification`；任何中止包字节分毫不动。
> - **hex 编辑 = 立即应用 + 事后刷新**：`ApplyModification` 同步直接改包；单包重解析在提交后跑，只负责刷新树/层显示文本，**不 gate 编辑**。
> 两条路收敛到**同一个**`RefreshDisplayAfterEditAsync`（`_reparseVersions` 守卫）。README 说 "Both routes run the VBC reparse" 只对树编辑成立。

### 5.1 树字段编辑链

**手势 → 内联编辑器**：

```
ProtocolTreeView.OnTreePointerPressed（隧道）
→ 双击 → ProtocolTreeViewModel.BeginFieldEdit(packet, field)
   或右键菜单 "Edit Value" → OnEditValueClicked → BeginFieldEdit
→ TextBox 出现（EditText 绑定，IsEditing 时可见）
→ Enter → CommitFieldEditAsync  |  Esc → CancelFieldEdit  |  LostFocus → CommitFieldEditAsync
   点击编辑器外（窗口级隧道 OnHostPointerPressed，排除编辑器内）→ 提交
```

**`BeginFieldEdit`（ProtocolTreeViewModel.cs:237）**：
1. `CheckTreeEditFence(packet, field)` — !Allowed → `SelectedFieldInfo = $"Not editable: {fence.Reason}"`，**拒绝打开编辑器**。
2. `CancelFieldEdit()`；`_editingField = field; field.EditText = FormatForEdit(field); field.IsEditing = true;`
3. `SelectedFieldInfo = $"Editing {field.Name} — Enter to apply, Esc to cancel"`。

`FormatForEdit` 按 `field.Kind`：UInt/Int → 十进制（`HexPreferred` 时 `0x…`），IPv4 点分，IPv6，MAC 冒号hex，Bcd 交换半字节数字串，String UTF8。

**6 道栅栏（verbatim，`ProtocolEditorService.CheckTreeEditFence` :26-54）**：

```
1. !field.IsTreeEditable        → "Field is not editable (unknown type or undecoded marker)"
2. Offset<0 || Length<=0        → "Field has no valid byte span"
3. LengthBits >= 0              → "Bit-level field cannot be edited from the tree"
4. Offset+Length > 帧大小        → $"Field offset {offset} + length {length} exceeds frame size {size}{hint}"
                                   hint = " (possibly reassembled PDU)"（Layers.Count>0 时）
5. RawBytes.Length != Length    → $"No byte evidence for this field (RawBytes.Length={n}, expected {len})"
6. RawBytes 与帧字节不一致       → "Recorded bytes disagree with frame bytes (offset drift or masked value)"
通过 → EditFence(true, "OK")（UI 前缀 "Not editable: "）
```

**`CommitFieldEditAsync`（VM）**：RO 检查 → `ConvertRawValue(kind, text, length)`（异常 → `SelectedFieldInfo = ex.Message`，编辑器保持打开）→ `_editTransaction.CommitFieldEditAsync(packet, field, bytes, PendingContextFrames, PendingLinkLayerType)` → `!Success` → `SelectedFieldInfo = $"Blocked: {result.Reason}"`（包字节不变，编辑器保持打开）→ `result.Fresh` → `RefreshFieldDisplays` → 关编辑器 → `FieldEdited?.Invoke((packet, edited))`。

**`EditTransactionService.CommitFieldEditAsync`（VBC）**：
```
tempPath = %TEMP%/pf_vbc_{Guid:N}.pcap
candidate = EffectiveData 克隆 + Array.Copy(newValue → field.Offset)      // 候选帧，原包不动
临时写：有上下文 → SavePacketWithContextAsync(上下文帧在前, 目标最后)
       无上下文 → SavePacketAsync
fresh = _tshark.ReparseSinglePacketAsync(tempPath)   // -r -T pdml → ParsePdmlToLookup → 取尾包
fresh==null → abort "Reparse produced no data"
verdict = VerifyFieldInReparse(field, newValue, fresh)                     // 见下
success → packet.ApplyModification(field.Offset, newValue); field.RawBytes = newValue
finally → 删临时文件
```

**`VerifyFieldInReparse` 完整逻辑**（EditTransactionService.cs:85-152）：`pdmlName` 空→abort；`searchPos = Offset>=0 ? Offset : EffectiveStart`，<0→abort；`(name, pos)` 不在 `FieldLookup` 但 fallback 在→改用 fallback；找不到→扫同名最近 `wrongPos`，若 `reparseHexAtWrong` 为空或等于旧 hex → 判定 **offset drift** abort，否则 abort 未落点；找到但 reparse 值 ≠ 期望 hex → abort 值未落；`Length != newValue.Length` → abort 长度。

**7 个 VBC 中止串（verbatim 全集，UI 前缀 "Blocked: "）**：

```
"Reparse produced no data"
"Field has no PDML name to verify against"
"Field has no resolvable position for verification"
$"Offset drift: {pdmlName} found at position {wrongPos} (expected {searchPos}); aborting edit"
$"Field {pdmlName} not found at expected position {searchPos} (edit did not land)"
$"Edit did not land: reparse value \"{reparseValue}\" at offset {searchPos} != expected \"{expectedHex}\""
$"Length mismatch: field expects {field.Length} bytes, newValue is {newValue.Length}"
```

**转换错误串**（`ConvertRawValue`，编辑器保持打开）：`"Value cannot be empty."` / `"'{t}' is not a valid hexadecimal value."` / `"'{t}' is not a valid unsigned integer."` / `"'{t}' is not a valid signed integer."` / `"'{t}' exceeds {len}-byte unsigned range (0..{max})."` / `"'{t}' is not a valid IPv4 address."` / `"'{t}' is not a valid IPv6 address."` / `"'{t}' is not a valid MAC address (expected aa:bb:...)."` / `"'{t}' is not a valid MAC address."` / `"'{t}' is not a valid BCD digit string for a {len}-byte field."` / `"'{t}' is not a valid BCD digit string."` / `"Value too long: {n} bytes, field holds {expected}."` / `"Field type {kind} is not editable."`

### 5.2 hex 字节编辑链

**点击/键盘**（`HexEditor.axaml.cs`）：cell `PointerPressed` → 若 `IsHexEditPending` 先 `CommitHexEditAsync()` → `SelectByteAtOffset` → Focus；`LostFocus` 同样先提交。`OnCellKeyDown`：pending 时 Enter=提交、Esc=取消、Tab 吞掉；非 pending 时方向键先提交再 `MoveSelection`（16 字节行环绕，钳位包界）；hex 键 `TryGetHexKeyChar`（D0-D9/NumPad/A-F，Ctrl/Alt 时拒绝）→ `HandleHexInput`。

**`HandleHexInput` 运行构建**（HexEditorViewModel.cs:364，REPLACE-only）：
```
RO → StatusInfo 只读消息
首字符：_pendingAnchor = SelectedByteOffset；清 _pendingRunBytes/_pendingNibble
REPLACE 钳位：currentOffset = _pendingAnchor + _pendingRunBytes.Count；>= Bytes.Count → return
奇数字（半字节）：当前字节 SetPending(nibble, "?")                       // 黄底、灰 ASCII '?'
偶数字：value = (nibble0<<4)|nibble1；追加 _pendingRunBytes；(nibble 长度=2)
         SetPending(value.ToString("X2"), ToAsciiChar(value))；前进 or RefreshVisualRequested
```

**`CommitHexEditAsync`**（:420）：
```
1. 守卫 packet/anchor；RO → 只读消息 + CancelHexEdit
2. runBytes = _pendingRunBytes；孤立奇数字补零低位（0x4 → 0x40）
3. 空 → CancelHexEdit
4. anchor+count > EffectiveData.Length → StatusInfo="Edit out of range (offset {a}, length {n})" + CancelHexEdit
5. ★ packet.ApplyModification(anchor, newBytes)      // 直接同步改（不走 EditTransaction）
6. 标记 run 字节 IsEdited=true（橙）+ ClearPending
7. ClearPendingRun; RefreshBytes; RefreshAddressInfo
8. StatusInfo = $"Edited {n} byte(s) @ {a:X4}"; RefreshVisualRequested
9. HexEdited?.Invoke((packet, anchor, newBytes.Length))
```

**`CancelHexEdit`**：清 `[anchor, anchor+count)` 的 pending → `"Edit cancelled"`。**包从未被碰过**。长度不变式：每个 run 字节由完整 hex 键对（或补零高半字节）构成 → `ApplyModification` 只覆盖等长区间，任何编辑都不改变包长（offsets 恒有效）。

### 5.3 编辑后传播 / 刷新内部

**`OnFieldEdited`（MainWindowViewModel.cs:535，树编辑 VBC 成功后）**：
`RO 守卫` → `ModifiedPackets + HasUnsavedChanges=true`（脏）→ `HexEditor.RefreshBytes()` → `RefreshAddressInfo()`(→`ReExtractAddressInfo` 按字节重读 → **刷新列表 Source/Destination/端口列**) → `MarkFieldEdited(field)`（橙标记）→ `HighlightField(field)` → `RefreshLayerDisplayText(packet)`（重写 IP/UDP/TCP 层头文本）→ `RefreshEditedFieldBytes(packet, offset, length)` → StatusText → `_ = RefreshDisplayAfterEditAsync(packet)`。

**`OnHexEdited`**：同上但**跳过** hex 自身刷新（VM 已同步做完）与 RO 重检（hex 路径已在 CommitHexEditAsync 内 gate）。

**`RefreshDisplayAfterEditAsync`**（:591）：`++_reparseVersions[packet]` → 临时 pcap（有缓存上下文 `SavePacketWithContextAsync` 否则 `SavePacketAsync`）→ 版本检查 → `_tshark.ReparseSinglePacketAsync` → 版本检查 → `ProtocolTree.RefreshFieldDisplays(packet, fresh)`（miss>0 → TraceLog）；finally 删临时文件。

**`RefreshFieldDisplays`（ProtocolTreeViewModel.cs:154-221，PDML 就地文本补丁，不重建树）**：
- 逐层 `TryGetProtoShowName(proto, offset)` → `layer.DisplayText`；offset 不中时回退首个 `(name,pos)`。
- `PatchFieldTexts`：`matchOffset = Offset>0 ? Offset : EffectiveStart`（**容器 Offset==0 回退后代最小 offset**）；**匿名 IE 容器**（空 `OriginalPdmlName`）经 `("", pos)` 空名查找表键匹配（PDML `<field name="" show="…">`）；命中 → `TrySplitShowname`（按首个 `": "` 切分；含 `" = "` 位域行返回 null）→ 更新 `field.Name/DisplayValue`；未命中 → miss++ 并递归子字段。miss 数仅记日志，不致命。

**`RefreshEditedFieldBytes`（ProtocolEditorService.cs:298-334）**：编辑后把所有层里 `LengthBits<0 && Offset>=0 && Length>0 && 帧内 && 跨重叠` 的字段 `RawBytes` 回填成 `EffectiveData` 当前字节。**位级字段跳过**（RawBytes 载的是带掩码值，回填会伪造栅栏依赖的字节证据）。这让树里灰色 `[HexValue]` 在 hex 编辑后立即新鲜。

### 5.4 脏跟踪

1. **包级**：`Packet.ApplyModification` — `ModifiedData ??= RawData 克隆`（首写克隆）+ `Array.Copy`；`IsModified => ModifiedData != null`；`EffectiveData => ModifiedData ?? RawData`。
2. **文档级**：`Document.HasUnsavedChanges`，在 `OnFieldEdited`/`OnHexEdited` 都设。
3. **窗口标题是静态的**！脏指示在状态栏：`Modified: {ModifiedPackets}`（MainWindow.axaml:368）。
4. `OnClosing` 只在有未存修改时 `Debug.WriteLine` — **没有对话框、不阻止关闭**。
5. 保存/导出前 `await HexEditor.CommitHexEditAsync()`（挂起的 hex run 不丢）；成功 → `HasUnsavedChanges=false; ModifiedPackets=0`。
6. 重置：`ResetModificationsCommand` → `Document.ResetAllModifications()`（清所有包 ModifiedData + HasUnsavedChanges=false）→ `HexEditor.RefreshBytes()`。

> 已废弃（勿当活路径）：`ProtocolEditorService.ApplyFieldEdit` / `ApplyHexStringEdit` 是旧路径，未被调用。

---

## 6. 保存 / 另存为 / 重置修改

### 6.1 Save PCAP（Ctrl+S）→ `MainWindowViewModel.SavePcapAsync`（:230）

```
IsReadOnly → "只读模式下无法保存。请先配置 tshark。\nCannot save in read-only mode. Configure tshark first."
Document==null||TotalPackets==0 → "No packets to save."
await HexEditor.CommitHexEditAsync()                     // 挂起的 hex run 先落盘进候选
!HasUnsavedChanges → "No changes to save."
options = { OutputPath=Document.FilePath, ExportOnlyModified=false, IncludeUnmodified=true,
            LinkLayerType=Document.LinkLayerType, Snaplen=Document.Snaplen }
await _pcapExport.ExportAsync(Document.Packets, options)  // 全量包 → 标准 libpcap
成功 → HasUnsavedChanges=false; ModifiedPackets=0; StatusText=$"Saved {n} packets to {file}"
catch → $"Save failed: {ex.Message}"
```

### 6.2 Export PCAP As（Ctrl+Shift+S）→ 代码后置 → `ExportToFileAsync(path)`（:290）

```
OnExportPcapClicked → ExportPcapDialogAsync → SaveFilePickerAsync(*.pcap) → TryGetLocalPath
→ ViewModel.ExportToFileAsync(path)
  await HexEditor.CommitHexEditAsync()
  options = { OutputPath, ExportOnlyModified=false, IncludeUnmodified=true, LinkLayerType }   // Snaplen 用默认
  await _pcapExport.ExportAsync(Document.Packets, options)   // IncludeUnmodified=true → 全量包
```

### 6.3 `PcapExportService` 写出详情

- `WriteGlobalHeader`：写 `0xa1b2c3d4`（LE µs）、2.4、snaplen、linktype。
- `WriteFrameRecord`：`tsSec = ts/1_000_000; tsUsec = ts%1_000_000`。
- `ExportAsync`：`ExportOnlyModified && !IsModified → continue`；写帧恒用 `packet.EffectiveData`。
- 三个写入口统一 `FileMode.Create`（覆盖）。

### 6.4 死命令

`OpenPcapCommand`（`OpenPcapAsync`）与 `ExportPcapCommand`（`ExportPcapAsync`）是**空实现且从未绑定**的生成命令——真实路径走代码后置对话框。文档与排障时别被它们误导。

---

## 7. 发送报文（rung 阶梯）

### 7.1 工具栏 → 服务链

**`ToolBarViewModel` 构造接线**：`sendService.PacketSent += OnPacketSent`、`SendCompleted += OnSendCompleted`、`packetList.SendSelectionChanged += UpdateCanSend`、`packetList.PropertyChanged(Packets) → UpdateCanSend`、`RefreshInterfaces()`。

**Start**：`StartSendAsync`（[RelayCommand]）→ `toSend = Packets.Where(SendSelected)` → 守卫（无网卡/空集）→ `SendPacketsAsync(toSend)`：

```
守卫 SelectedInterface==null → "Select a network adapter first"
守卫 IsSending||count==0 → return false
IsSending=true; IsPaused=false; TotalSent=0; TotalFailed=0
await _sendService.StartSendAsync(packets, SelectedInterface, loopCount, intervalMs, autoFixFrames)
finally → IsSending=false; IsPaused=false
```

> 免费版无任何发送数量限制：没有预占、没有逐包记账、发送循环内也没有终端守卫——原日配额的软闸整条链路已随功能于 2026-09-29 删除（详见附录 C）。`LoopCount<=0` 由 `PacketSendService` 归一为 1 轮。

**Pause/Resume**（`TogglePauseSend`）：`IsPaused` 翻转 → `_sendService.ResumeSend()` / `PauseSend()` + 状态文案。**Stop**（`StopSend`）：`_sendService.StopSend()` → 状态 `$"Stopped — {n} sent, {m} failed"`。

**逐包回调 `OnPacketSent`**：镜像 `TotalSent/TotalFailed` → 状态 `$"[{result.PacketIndex}] {result.Message}"`。

**完成 `OnSendCompleted`**：`IsSending=false` → `$"Send complete — {n} sent, {m} failed"`。

**`CanSend` 门**：`!IsReadOnly && SelectedInterface != null && !IsLoopback && 任意 SendSelected && !IsSending`。工具栏**不再渲染任何配额文本**（日配额已下线）。

### 7.2 `PacketSendService.StartSendAsync`（:64）

```
lock: IsRunning 检查 → _sendCts = CreateLinkedTokenSource; TotalSent/TotalFailed=0
CreateSendSockets(iface):                                   // 按保真度建全部可用 socket
  Linux → AF_PACKET (Packet/Raw/Raw)                        // catch → 缺席
  全 OS → IP raw (InterNetwork/Raw/IP) + Windows/Linux 设 IP_HDRINCL   // catch → 缺席
  全 OS → UDP (InterNetwork/Dgram/Udp) + Windows SIO_UDP_CONNRESET(0x9800000C) // catch → 缺席
L2 探测（每会话一次）: Windows→NpcapSendService.TryOpenRung; macOS→BpfSendService.TryOpenRung; 其他→null
sockets 全空 && l2Rung==null → OnPacketSent(-1,false,"Cannot send: no suitable socket type for {name}. Try running as administrator/root.")
尽力 Bind(iface.IPv4Address, 0)
rounds = loopCount<=0 ? 1 : loopCount
外循环 for (int round = 0; round < rounds; round++) × 内循环 i:
  暂停等待: while(IsPaused && !cts.IsCancellationRequested) await Task.Delay(100)
  SendPacketAsync(sockets, packet, i, iface, autoFixFrames, l2Rung)
  if (intervalMs>0) await Task.Delay(intervalMs)
finally: dispose sockets; IsRunning=false; SendCompleted?.Invoke()
```

**rung 阶梯（verbatim，PacketSendService.cs:19-25）**：

```
0. L2 原生 rung（可选）— Windows Npcap / macOS BPF — 发完整以太帧；原生路径不可用时静默缺席
1. AF_PACKET raw socket（Linux）— 发完整以太帧
2. IP 级 raw socket（全 OS）— 发 IP 数据报
3. UDP socket（全 OS）— 传输层兜底，无需特权
```

**`SendPacketAsync` 逐包下降**（:336）：
```
data = autoFixFrames ? PacketPrepareService.PrepareFrame(EffectiveData, iface) : EffectiveData
ipOffset = FindIpOffset(data); protocol = data[ipOffset+9]
Rung 0: l2Rung.TrySend(data, index, name) — 非 null → OnPacketSent + return；null+err → lastError+TraceLog
Rungs 1-3（foreach socket，label=AF_PACKET/UDP/IP raw）:
  AF_PACKET → TrySendEthernetFrameAsync:  读 /sys/class/net/{name}/ifindex → 20B sockaddr_ll(ETH_P_ALL, 目的MAC)
                                           → SendToAsync；帧<14B → null
  UDP       → TrySendUdpPayloadAsync:     TryExtractUdpTarget(仅IPv4, proto 17, 从 IP/UDP 头取目的 IP/端口,
                                            payload=data[(ipOffset+ihl+8)..])
                                            TCP+Windows → "TCP packets cannot be sent: Windows raw sockets block TCP,
                                            and UDP fallback only carries UDP"
                                            否则 → "TCP packets require raw socket privileges"
  其他      → TrySendIpDatagramAsync:     去以太头 data[ipOffset..] → SendToAsync(目的IP) / IPv6 SendAsync
  SocketException 特判:
    Windows raw + proto 6 → "Windows raw sockets cannot send TCP segments — L2 injection requires Npcap/WinPcap"
    AccessDenied          → "Access denied: run as administrator/root for raw packet sending"
全 rung 失败 → OnPacketSent(index, false, lastError ?? "No send path available for this packet")
```

**计数器**（OnPacketSent :502）：成功 `TotalSent++`，失败 `TotalFailed++`，然后 `PacketSent?.Invoke`。

### 7.3 `PacketPrepareService` 发送前修复（static）

`PrepareFrame(frame, iface)`：空帧原样返回 → `FindIpOffset`（Ethernet-II 0x0800/0x86DD → 14；裸 IPv4/6 → 0；否则 -1）→ ipOffset==14 且 MAC 可解析 → **改写源 MAC**（偏移 6）→ **IPv4**：改写源 IP(+12)、清零并重算 IP 头校验和（RFC 1071）、TCP(6) 带伪头重算、UDP(17) **仅当原校验和≠0**（保 IPv4 校验和关闭惯例）→ **IPv6**：改写源 IP(+8)、TCP/UDP 恒重算（仅无扩展头情形，nextHeader 在 +6）、UDP 结果为 0 → 0xFFFF（RFC 768）。

### 7.4 `NetworkInterfaceService`

`GetInterfaces()`: `GetAllNetworkInterfaces()` → 过滤 `OperationalStatus.Up` → 映射 `NetworkInterfaceInfo`（IPv4=首个 InterNetwork 单播；IPv6=首个非 link-local；MAC=`XX:XX:…`；IsLoopback=Loopback 类型）→ 过滤 IPv4!=null || IsLoopback → `OrderBy(IsLoopback).ThenBy(Name)`。异常 → 空列表（UI 显示 "No interfaces found"）。

---

## 10. 排障速查表（Symptom → Triage）

> 所有下钻链 #加载 前先确认事件订阅存在（1.1 表）与 DI 构造顺序（2.2）。

| 症状 | 首选排查点 | 关键函数/守卫 |
|---|---|---|
| 打开大文件慢/卡 UI | 3.7 批量 AddRange（逐包 Add 是红线）+ 3.4 进度回调 | `PacketCollection.AddRange`、`LoadPcapAsync` |
| 列表列全空/N/A | tshark 缺失或 <2.6 → 只读（3.8）；tshark 非零退出（3.4）；行解析失败被跳过 | `DetectTshark`、`LoadPcapReadOnlyAsync` |
| 选中包后树不出现 | 4.1 守卫链 + 构建失败（trace.log "tree build failure"） | `_treeBuildSeq`、`BuildTreeAsync` catch、`_buildingPackets` |
| 树显示旧包的包 | 旧选择构建覆盖（`_treeBuildSeq` 未生效） | `BuildTreeAsync` 的 `seq == _treeBuildSeq` 检查 |
| 编辑被拒 "Not editable: …" | 5.1 六道栅栏逐条核对（最常中 4/5/6：越界、无字节证据、漂移） | `CheckTreeEditFence` |
| 编辑被拒 "Blocked: …" | 5.1 七个 VBC 中止串；tshark 重解析异常会落 "Reparse produced no data" | `VerifyFieldInReparse` |
| 编辑后树文本没变 | 5.3 PDML 补丁 miss（trace.log 刷新 miss 数）；`_reparseVersions` 陈旧刷新 | `RefreshFieldDisplays`、`PatchFieldTexts` |
| hex 编辑后列表地址/端口旧 | 5.3 `ReExtractAddressInfo` 未触发/未命中 | `OnHexEdited` → `RefreshAddressInfo` |
| 发送失败 | 7.2 rung 阶梯逐级看 lastError（trace.log send rung failures）；root/管理员权限 | `SendPacketAsync`、`CreateSendSockets` |
| 发送中途停了 | 7.1 Pause/Resume/Stop 路径；`StopSend` 取消 CTS | `StartSendAsync` 的 `cts` 检查 |
| 布局位置/分隔条丢了 | 2.4 `LayoutService`（layout.json 损坏回默认） | `RestoreLayout` 钳位 |
| 重启后 tshark 找不到 | 3.8 `FindTshark` 优先级；设置里存的路径不被检测到（env 优先） | `TsharkSettingsService` + env |
| 崩溃无痕迹 | 2.1 crash recorder + trace.log（`%LOCALAPPDATA%/ProtocolForge/logs/trace.log`；Linux `~/.local/share/ProtocolForge/logs/trace.log`） | `RegisterCrashRecorders` |
| 点击 hex 字节树不定位 | 4.6 反查链：`FindFieldAtOffset` 找不到（payload 兜底胜出）→ `TrySelectField` ≤4 次重试静默放弃 | `IsMoreSpecific`、`SelectByteAtOffset` |

**trace.log 定位要点**：`%LOCALAPPDATA%/ProtocolForge/logs/trace.log`（Windows）/ `~/.local/share/ProtocolForge/logs/trace.log`（Linux）/ `~/Library/Application Support/ProtocolForge/logs/trace.log`（macOS）；2MB 轮转 2 备份；AutoFlush 开启。关注关键字：`tree build failure`、`prefetch failure`、`OnFieldSelected/OnLayerSelected`、`PDML refresh`、`rung`/`Npcap`/`BPF probe`、`MW.RestoreLayout/SaveLayout`。

---

## 附录 A：序列守卫

| 守卫 | 类型 | 升代点 | 检查点 | 防止的陈旧覆盖 |
|---|---|---|---|---|
| `_treeBuildSeq` | int | `OnPacketSelected` `++` | `BuildTreeAsync` 提交前 `seq == _treeBuildSeq`（catch 里 StatusText 也查） | 旧选择的按包构建覆盖新选择树 |
| `_buildingPackets` | HashSet\<Packet\> | 选择 + 预取处 `Add` | 入口 `Add` 失败即 return；`finally` 移除 | 同包并发重复构建（打开文件选第一包两次） |
| `_reparseVersions` | Dictionary\<Packet,int\> | `RefreshDisplayAfterEditAsync` 逐包 `++` | 临时保存后、重解析后版本比对 | 旧编辑的后台显示刷新覆盖新编辑文本 |
| `_prefetchSeq` | int | `BumpPrefetch` `++` | `PrefetchNeighborsAsync` 窗口检查 | 过期预取窗口继续推进 |
| `_prefetchGate` | SemaphoreSlim(2) | — | `WaitAsync`/`Release` | 预取并发上限，不饿死选中构建 |
| `_packetContextFrames` | Dictionary\<Packet,…\> | 树构建缓存 | VBC 临时写 & 显示刷新复用 | 避免重复整包上下文扫描 |

**线程约定**：VM 直接 `await` 服务（无 ConfigureAwait(false)）——Avalonia UI SynchronizationContext 自动续在 UI 线程；`Dispatcher.UIThread.Post` 仅用于视图层自同步（ProtocolTreeView 定位重试、HexEditor 滚动/聚焦）。

---

## 附录 B：用户可见错误串全集

| 场景 | 串（verbatim） |
|---|---|
| 只读模式（4 处：树提交/hex 输入/hex 提交/OnFieldEdited） | `"只读模式：编辑已禁用。请先配置 tshark。\nRead-only mode: editing disabled. Configure tshark first."` |
| 栅栏拒绝前缀 | `"Not editable: {reason}"` |
| VBC 中止前缀 | `"Blocked: {reason}"` |
| 保存只读 | `"只读模式下无法保存。请先配置 tshark。\nCannot save in read-only mode. Configure tshark first."` |
| 发送无 socket | `"Cannot send: no suitable socket type for {name}. Try running as administrator/root."` |
| 列表无包 | `"No packets to save."` / `"No packets to export."` / `"No changes to save."` |
| 版本过低缺 tshark | `"未找到 tshark…"` / `"版本过低，最低支持 2.6"`（DetectTsharkCore） |

完整转换错误串见 5.1，VBC 中止串见 5.1（7 条），hex 越界 `"Edit out of range (offset {a}, length {n})"`。

---

## 附录 C：文档与代码不一致点

| 项 | 事实（以代码为准） |
|---|---|
| tshark 版本门槛 | **2.6.0**（TsharkService.cs:373 `VersionCompare(version, "2.6.0") < 0`）。全仓无 4.0 门禁；`tests/pf-verify/Program.cs:169` 仅有一处文本提及 4.0（注释，非门禁）。 |
| `OpenPcapCommand` / `ExportPcapCommand` | 空实现 + 从未绑定。真实打开/另存路径是代码后置对话框（MainWindow.axaml.cs）→ `LoadFileAsync` / `ExportToFileAsync`。 |
| `ApplyFieldEdit` / `ApplyHexStringEdit` | 旧路径，未调用。活路径：树 = `ConvertRawValue` + `EditTransactionService`；hex = `ApplyModification` 直写。 |
| 窗口标题脏指示 | 标题**静态**；脏显示在状态栏 `Modified: N`；关闭警告仅 `Debug.WriteLine`，**无对话框**。 |
| hex 编辑是否走 VBC | **不走**。README "Both routes run the VBC reparse" 只对树编辑成立；hex 是"立即应用 + 事后只读重解析刷新显示"。 |
| README rung 图 0–3 与代码一致 | 一致：0 L2(Npcap/BPF) → 1 AF_PACKET → 2 IP raw → 3 UDP。 |
| `CanSend` 额外拦回环 | 工具栏禁止 loopback 发送，但 `NetworkInterfaceService` 仍列出回环卡（下拉可见，启动被拦）。 |
| 免费版日发送配额 | **已删除（2026-09-29）**：原日发送配额服务类文件已不存在，`ToolBarViewModel` 无配额预占/记账/`CanSend` 配额子句，`PacketSendService.StartSendAsync` 无守卫参数与中止标志，工具栏无配额文本。本文件原第 8 章已随之移除（章节号 8 留空不重排）。当前代码中不存在任何形式的配额：既无日发送上限，也无功能开关位（相关许可位掩码常量随离线许可模块一并删除）。 |
| `_ws.malformed` 处理 | 追加到最内层 DisplayText，而不是独立的层。 |
| ViewLocator 实际作用 | 仅 MainWindowViewModel 继承 ViewModelBase；树/hex VM 在 XAML 直接绑 DataContext，ViewLocator 很少触发。 |

## 附录 D：验证夹具 pf-verify（G1–G8）

**位置与运行**：`tests/pf-verify/Program.cs`（独立控制台项目，**不在 .sln 内**）。运行 `dotnet run --project tests/pf-verify`，需真实 tshark ≥3.6.2 + `pcap/` 样例；全部通过时打印 `ALL GROUPS PASS`，另写 `report.txt` 到基目录，exit code 0/1。它是唯一的回归防线（无 xUnit/NUnit）。

| 组 | 覆盖（一行） |
|---|---|
| G1 | 帧 4413 的树编辑栅栏判定：被阻原因直方图 + ≥1 个帧内可编辑字段 |
| G2 | VBC 事务：合法提交翻字节且其余字节一致、offset-drift 中止、长度变更拒绝、中止时字节同一性 |
| G3 | 真实环境 tshark 版本门：检到 ≥2.6 → Ok=true |
| G4 | 假 tshark 2.5（经 `TSHARK_PATH`）→ 门禁 FAIL；假 4.2 → PASS |
| G5 | 只读原始加载：全部 SourceAddress==N/A、全部 ProtocolName 空 |
| G6 | hex REPLACE-only 代码面（静态源码断言）：IsEditPending、HandleHexInput/CommitHexEditAsync/CancelHexEdit、HexEdited/FieldFoundAtOffset、数字路由、反查重试上界 |
| G7 | Npcap 探测纯逻辑：ResolveWpcapPath、CanSendFrame 14 字节边界、DeviceMatchesIdentifier（带括号/不带括号/小写/不匹配/异型） |
| G8 | BPF 纯逻辑：BuildIfreq 名字+NUL+清零联合体、15 字符截断、空名 |

> 组号留空说明：G9（日配额）与 G10（许可套件）分别随免费版日发送配额（2026-09-29）和离线许可模块移除而删除，G10i（配额联动）随之删除；编号不回收、不重排。G21-04 的守卫回调用例与 G32 的 Q-12 子块同样移除。**本表只列到 G8**——G11 及之后（本地化、编辑栅栏、发送阶梯、jsonraw 解析、上下文提供者、检测顺序等）的覆盖范围以 `tests/pf-verify/Program.cs` 与 `docs/FullFunctionTest.md` 附录 A 为准。

依赖关系：G2/G3/G4/G5 要真实 tshark。**发版门禁**（docs/RealDeviceQA.md）：`dotnet build` 0 警告 0 错误 + pf-verify `ALL GROUPS PASS`。

---

*CodeMap 生成于 2026-09-23，覆盖提交 9504497 之后的主干代码。行号以生成时为准。*