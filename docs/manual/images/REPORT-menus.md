# Menu / Dialog Screenshot Report

Capture of menus, context menu and dialog that the Avalonia **headless** renderer
cannot draw (popups, menus, dialogs). Captured from a **real X server** (Xvfb)
on DISPLAY `:99` by driving the app with `xdotool` and grabbing with ImageMagick
`import`.

- **Date:** 2026-10-14
- **App:** `/tmp/pf-app/ProtocolForge` (copied out of
  `ProtocolForge/bin/Debug/net10.0/linux-x64` so a parallel rebuild of the repo bin
  could not disturb the run) — version reported by the About dialog: `v0.2.0`.
- **Capture fixture:** `pcap/all-3gpp.pcap` (47 frames loaded).
- **X server:** `Xvfb :99 -screen 0 1440x900x24` (no window manager).
- **Window:** 1400x900 at root (0,0); each PNG is cropped to the window area
  `1400x890+0+0` (the bottom 10 px are off-screen because 900 > 890). The restored
  `layout.json` places the window at (0,0) — the previous run's (10,10) no longer
  applies, so all on-screen coordinates below are 10 px smaller on each axis than
  the previous capture's.
- **Output dir:** `docs/manual/images/` (this directory).

## UI language note

The app launched in **简体中文** by default this run: the language choice is persisted in
`settings.json` (`"Language": "ZhCn"`) and the previous capture had already selected it, so
all five screenshots show the Chinese UI with no runtime switch needed. For reference, the
language picker is a **submenu under 工具 (Tools)** — `工具 → 语言` — not a top-level menu
item between 视图 and 帮助. Screenshot 11 shows this submenu expanded.

## Results

| File | Captured | What is visible | Method |
|------|----------|-----------------|--------|
| `09-file-menu.png` | ✅ yes | **文件** menu open: `打开 PCAP...` (Ctrl+O), `保存 PCAP` (Ctrl+S), `导出 PCAP 为...` (Ctrl+Shift+S), separator, `重置修改`, separator, `撤销` (Ctrl+Z), `重做` (Ctrl+Y), separator, `Tshark 路径...`, separator, `打开支持数据目录`, separator, `退出`. | click menu-bar `文件` at root (22,53), `import -window root`, crop |
| `10-packet-context-menu.png` | ✅ yes | Right-click **context menu** on the packet list: `全选` / `反选` / `清除选择`, separator, `发送此数据包`, separator, `导出发送历史 (CSV)` / `清空发送历史`. | left-click a packet row at (240,190) to focus, then right-click (`xdotool click 3`) at same point |
| `11-language-menu.png` | ✅ yes | **工具** menu open with the **语言** submenu expanded, listing `简体中文` (checked) and `English`, with the `主题` entry visible below the separator. | click `工具` (114,53), hover the `语言` row (~140,94) to open the submenu |
| `12-about-dialog.png` | ✅ yes | **关于 ProtocolForge** dialog open (separate 460x280 window at root 470,310): title `ProtocolForge v0.2.0`, `3GPP 协议仿真与调试`, "基于 Avalonia UI + .NET 10 构建", `协议解析: Tshark（Wireshark CLI）`, Npcap attribution lines, `https://npcap.com/license`, `详见安装目录下的 THIRD-PARTY-NOTICES.md。`, and an OK button. | `帮助` (160,53) → click `关于 ProtocolForge` row (~190,135) |
| `15-help-menu.png` | ✅ yes | **帮助** menu open: `用户手册`, separator, `关于 ProtocolForge`. | click menu-bar `帮助` at (160,53) |

All files are `1400x890`, 8-bit sRGB PNGs with ~9,700–11,900 distinct colours each
(i.e. real rendered screenshots, not 2-colour line art):

| File | Dimensions | Distinct colours | Size |
|------|-----------|------------------|------|
| `09-file-menu.png` | 1400x890 | 10385 | 158,434 B |
| `10-packet-context-menu.png` | 1400x890 | 10611 | 178,403 B |
| `11-language-menu.png` | 1400x890 | 9699 | 165,582 B |
| `12-about-dialog.png` | 1400x890 | 11881 | 172,780 B |
| `15-help-menu.png` | 1400x890 | 9674 | 166,037 B |

The window status bar reads `all-3gpp.pcap`, `共 47 帧` / frame count 47 — the new fixture
was loaded (an earlier line in the status bar also names the tshark path probe).

## Verification

The required `look_at` tool could **not** be used: the multimodal-looker agent returned
"No response from multimodal-looker agent" for every call. Verification was therefore done
with two independent non-visual methods:

1. **OCR (`tesseract -l eng`)** on each PNG (and on enlarged crops of the opened
   menu/dialog). Latin labels read back exactly, e.g.:
   - `12-about-dialog.png`: `ProtocolForge v0.2.0`, `Avalonia Ul + NET 10`,
     `Tshark ( Wireshark CLI)`, `Npcap® ( Nmap Software LLC`, `https://npcap.com/license`,
     `THIRD-PARTY-NOTICES.md`.
   - `09-file-menu.png`: `PCAP... Ctrl+O`, `PCAP Ctrl+S`, `PCAP ¥... Ctrl+Shift+S`,
     `Tshark #8%...` (the shortcut column).
   - `11-language-menu.png`: `English` (and the CJK `简体中文` / `主题` rows).
   - `10-packet-context-menu.png`: `(CSV)` on the export-history row.
   CJK labels are not recoverable with the only installed language pack (`eng`), but their
   presence and row layout confirm the menus/dialog are open and populated.
2. **Pixel row scans (`PIL`)** to confirm the number and vertical position of the popup
   rows in each capture (dark-pixel count per row, bands merged across <=3 px glyph gaps):
   - `09-file-menu.png`: 10 text bands between window-y ≈ 88 and ≈ 455 (all nine File
     items, with the two disabled entries 撤销/重做 still owning rows), matching the
     `<Separator/>` gaps in `MainWindow.axaml:38-55`.
   - `15-help-menu.png`: help rows at window-y ≈ 88–100 and ≈ 128–142 with a separator
     band between (matching `<Separator/>` at `MainWindow.axaml:80`).
   - `11-language-menu.png`: the 工具 title plus the submenu rows (`语言`, `简体中文`,
     `English`) at window-y ≈ 77–103 / 128–146 and the `主题` row below.
   - `12-about-dialog.png`: 8 text bands between window-y ≈ 334 and ≈ 491 (the dialog body).
   - `10-packet-context-menu.png`: six item rows plus separators in the popup region
     (window-y ≈ 219–455).

Cross-check with the XAML: the menu structure used here matches
`ProtocolForge/Views/MainWindow.axaml:38-82` (File/View/Tools/Help + nested 语言 submenu)
and `ProtocolForge/Views/Controls/PacketListPaneView.axaml` (packet-list context menu).

## Reproduction (what was actually run)

```bash
# 1. isolate the pre-built app
cp -r /mnt/d/protocol-forge-pro/ProtocolForge/bin/Debug/net10.0/linux-x64 /tmp/pf-app

# 2. real X server (no WM)
setsid Xvfb :99 -screen 0 1440x900x24 </dev/null >/tmp/xvfb.log 2>&1 &

# 3. launch with the NEW 47-frame fixture
setsid env DISPLAY=:99 /tmp/pf-app/ProtocolForge \
  /mnt/d/protocol-forge-pro/pcap/all-3gpp.pcap </dev/null >/tmp/pf.log 2>&1 &

# 4. drive + grab (example: File menu; window sits at root (0,0) this run)
export DISPLAY=:99
xdotool search --name ProtocolForge            # -> window id
xdotool mousemove 22 53 click 1                # open 文件
import -window root /tmp/raw.png
convert /tmp/raw.png -crop 1400x890+0+0 +repage 09-file-menu.png

# 5. cleanup
pkill -f '/tmp/pf-app/ProtocolForge'; pkill -f 'Xvfb :99'
```

Background processes were always started with the `setsid ... </dev/null >log 2>&1 &`
form; Xvfb and the app were terminated at the end of the run.

## Cleanup

Xvfb (`:99`) and the ProtocolForge instance were killed after capture. No repo source
files were modified; nothing was committed. Files `01-08`, `13`, `14` (owned by the other
agent) were not touched.
