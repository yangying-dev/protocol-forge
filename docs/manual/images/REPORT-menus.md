# Menu / Dialog Screenshot Report

Capture of menus, context menu and dialog that the Avalonia **headless** renderer
cannot draw (popups, menus, dialogs). Captured from a **real X server** (Xvfb)
on DISPLAY `:99` by driving the app with `xdotool` and grabbing with ImageMagick
`import`.

- **Date:** 2026-10-13
- **App:** `/tmp/pf-app/ProtocolForge` (copied out of
  `ProtocolForge/bin/Debug/net10.0/linux-x64` so a parallel rebuild of the repo bin
  could not disturb the run) — version reported by the About dialog: `v0.2.0`.
- **Capture fixture:** `pcap/3gpp-pfcp.pcap` (10 frames loaded).
- **X server:** `Xvfb :99 -screen 0 1440x900x24` (no window manager).
- **Window:** 1400x900 at root (10,10); each PNG is cropped to the window area
  `1400x890+10+10` (the bottom 10 px are off-screen because 10+900 > 900).
- **Output dir:** `docs/manual/images/` (this directory).

## UI language note

The app launched in **English** by default but the manual's Help/About goals reference the
Chinese strings (`用户手册`, `关于 ProtocolForge`) and the repo states the UI is zh-CN, so the
app was switched to **简体中文** at runtime via **工具 → 语言 → 简体中文** before capturing.
All five screenshots therefore show the Chinese UI.

> Note: this build nests the language picker as a **submenu under 工具 (Tools)** —
> `工具 → 语言`. It is *not* a top-level menu item between 视图 and 帮助 (the README text
> still says "between View and Help", which does not match this build). Screenshot 11 shows
> this submenu expanded.

## Results

| File | Captured | What is visible | Method |
|------|----------|-----------------|--------|
| `09-file-menu.png` | ✅ yes | **文件** menu open: `打开 PCAP...` (Ctrl+O), `保存 PCAP` (Ctrl+S), `导出 PCAP 为...` (Ctrl+Shift+S), separator, `重置修改`, `撤销` (Ctrl+Z), `重做` (Ctrl+Y), `Tshark 路径...`, `打开支持数据目录`, `退出`. | click menu-bar `文件` at root (32,63), `import -window root`, crop |
| `10-packet-context-menu.png` | ✅ yes | Right-click **context menu** on the packet list: `全选` / `反选` / `清除选择`, separator, `发送此数据包`, separator, `导出发送历史 (CSV)` / `清空发送历史`. | left-click a packet row at (250,200) to focus, then right-click (`xdotool click 3`) at same point |
| `11-language-menu.png` | ✅ yes | **工具** menu open with the **语言** submenu expanded, highlighting `语言` and listing `简体中文` and `English` (the `主题` entry is visible below). | click `工具` (124,63), hover the `语言` row (~150,104) to open the submenu |
| `12-about-dialog.png` | ✅ yes | **关于 ProtocolForge** dialog open: title `ProtocolForge v0.2.0`, `3GPP 协议仿真与调试`, "基于 Avalonia UI + .NET 10 构建", `协议解析: Tshark（Wireshark CLI）`, Npcap attribution lines, `https://npcap.com/license`, `详见安装目录下的 THIRD-PARTY-NOTICES.md。`, and an OK button. | `帮助` (170,63) → click `关于 ProtocolForge` row (~200,145) |
| `15-help-menu.png` | ✅ yes | **帮助** menu open: `用户手册`, separator, `关于 ProtocolForge`. | click menu-bar `帮助` at (170,63) |

All files are `1400x890`, 8-bit sRGB PNGs with ~10,000–12,700 distinct colours each
(i.e. real rendered screenshots, not 2-colour line art).

## Verification

The required `look_at` tool could **not** be used: the multimodal-looker agent returned
"No response from multimodal-looker agent" for every call (repeatedly, including a batched
call over all five images). Verification was therefore done with two independent
non-visual methods:

1. **OCR (`tesseract`)** on each PNG (and on enlarged crops of the opened
   menu/dialog). Latin labels (`ProtocolForge v0.2.0`, `English`, `(CSV)`,
   `THIRD-PARTY-NOTICES.md`, …) read back exactly; CJK labels are not recoverable with the
   only installed language pack (`eng`), but their presence and row layout confirm the
   menus/dialog are open and populated.
2. **Pixel row/column scans (`PIL`)** to confirm the number and vertical position of the
   popup rows in each capture, e.g.:
   - `11-language-menu.png`: two submenu text rows at window-y ≈ 91–100 and ≈ 133–139
     (`简体中文` / `English`).
   - `15-help-menu.png`: help rows at window-y ≈ 89–100 and ≈ 129–140 with a fainter
     separator band at y ≈ 126–127 (matching `<Separator/>` at `MainWindow.axaml:80`).
   - `12-about-dialog.png`: ~20 text bands between y ≈ 226 and ≈ 599 (the dialog body).
   - `10-packet-context-menu.png`: 5–6 item rows plus separators in the popup region.

Cross-check with the XAML: the menu structure used here matches
`ProtocolForge/Views/MainWindow.axaml:38-82` (File/View/Tools/Help + nested 语言 submenu)
and `ProtocolForge/Views/Controls/PacketListPaneView.axaml:96-110` (packet-list context menu).

## Reproduction (what was actually run)

```bash
# 1. isolate the pre-built app
cp -r /mnt/d/protocol-forge-pro/ProtocolForge/bin/Debug/net10.0/linux-x64 /tmp/pf-app

# 2. real X server (no WM)
setsid Xvfb :99 -screen 0 1440x900x24 </dev/null >/tmp/xvfb.log 2>&1 &

# 3. launch
setsid env DISPLAY=:99 /tmp/pf-app/ProtocolForge \
  /mnt/d/protocol-forge-pro/pcap/3gpp-pfcp.pcap </dev/null >/tmp/pf.log 2>&1 &

# 4. drive + grab (example: File menu)
export DISPLAY=:99
xdotool search --name ProtocolForge            # -> window id
xdotool mousemove 32 63 click 1                # open 文件
import -window root /tmp/raw.png
convert /tmp/raw.png -crop 1400x890+10+10 +repage 09-file-menu.png

# 5. cleanup
pkill -f '/tmp/pf-app/ProtocolForge'; pkill -f 'Xvfb :99'
```

Background processes were always started with the `setsid ... </dev/null >log 2>&1 &`
form; Xvfb and the app were terminated at the end of the run.

## Cleanup

Xvfb (`:99`) and the ProtocolForge instance were killed after capture. No repo source
files were modified; nothing was committed. Files `01-08`, `13`, `14` (owned by the other
agent) were not touched.
