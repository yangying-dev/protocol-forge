---
name: Bug report
about: Something behaves incorrectly
title: "[bug] "
labels: bug
assignees: ''
---

<!-- Please answer these before filing. Required fields are marked Required. -->

**What happened**
Required. What did you observe, including the exact on-screen text.

**What you expected**
Required.

**Reproduction**
Required. Step by step, starting from launching the app.

1.
2.
3.

**Environment** — all Required except where marked optional.
- ProtocolForge version (Help → About):
- OS and version (Windows 10/11 x64, Linux distro, or macOS version):
- tshark version (`tshark -v`):
- Was the app in read-only mode (a warning banner visible at the top)?:
- Were you sending packets? If yes, which rung / interface / loop count / interval:
- Optional: relevant `trace.log` lines from `%LOCALAPPDATA%/ProtocolForge/logs/trace.log` (or the Linux/macOS equivalent)

**PCAP files**
Required if the issue involves opening or parsing a capture. **Do not attach real operator captures.** Real captures must never be committed or uploaded — see `CONTRIBUTING.md`. Describe the capture instead (PCAP vs PCAPNG, approximate packet count, link type, which protocol), or attach a synthetic fixture you generated.
