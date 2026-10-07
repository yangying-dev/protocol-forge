# Third-Party Notices

This file covers every third-party component that ProtocolForge either links into its shipped binary or reaches at runtime, and states the license boundary for each one. Section A covers components redistributed inside the binary. Section B covers components that are **not** redistributed and that the user installs. Section C covers this project's own license. Section D is a short note for downstream redistributors.

ProtocolForge itself is licensed Apache-2.0. See [`LICENSE`](LICENSE).

---

## Section A — Components redistributed inside the binary

These are MIT-licensed NuGet packages linked into the shipped executable. The MIT license requires the copyright notice and permission text to be included **in all copies or substantial portions of the Software**, so the full text is reproduced below.

### A.1 Package inventory

| Package | Version | License | Notes |
|---|---|---|---|
| `Avalonia` | 12.0.5 | MIT | Cross-platform UI framework |
| `Avalonia.Desktop` | 12.0.5 | MIT | Desktop backend |
| `Avalonia.Themes.Fluent` | 12.0.5 | MIT | Fluent design theme |
| `Avalonia.Fonts.Inter` | 12.0.5 | MIT | Inter font |
| `Avalonia.Controls.DataGrid` | 12.0.1 | MIT | Packet list grid: column sorting, double-click column auto-fit |
| `AvaloniaUI.DiagnosticsSupport` | 2.2.1 | MIT | **Debug builds only.** Referenced in `ProtocolForge.csproj` but excluded from the asset list in any configuration other than `Debug`, so it is not part of a Release artifact. It is additionally guarded by `#if DEBUG` at its use site. |
| `CommunityToolkit.Mvvm` | 8.4.2 | MIT | MVVM source generators (`[ObservableProperty]`, `[RelayCommand]`, `[AsyncRelayCommand]`) |

### A.2 Stated copyright lines

MIT requires that the copyright notice travel with the permission text. The lines below are
reproduced from each package's own NuGet metadata (`<copyright>` and `<authors>` in the `.nuspec`),
which is the authoritative statement shipped with the binary you are redistributing:

```text
Avalonia, Avalonia.Desktop, Avalonia.Themes.Fluent,
Avalonia.Fonts.Inter, Avalonia.Controls.DataGrid
    Copyright 2013-2026 © The AvaloniaUI Project
    Authors: Avalonia Team
    License: MIT (SPDX-License-Identifier: MIT)

CommunityToolkit.Mvvm
    Copyright © .NET Foundation and Contributors
    License: MIT (SPDX-License-Identifier: MIT)
```

Two notes on the above, both verifiable:

- The Avalonia packages **do not embed a `license.txt`** in the `.nupkg`. Their MIT grant is asserted
  by the `license type="expression">MIT` expression in the `.nuspec`, which NuGet surfaces at
  <https://licenses.nuget.org/MIT>. The full MIT text is reproduced below so the binary distribution
  carries it regardless.
- `AvaloniaUI.DiagnosticsSupport` 2.2.1 is referenced **only in Debug builds**. Its
  `PackageReference` in `ProtocolForge.csproj` sets `IncludeAssets=None` and `PrivateAssets=All`
  for any configuration other than `Debug`, so a **Release build neither compiles against it nor
  copies it to the output directory**. NuGet still downloads it into the build machine's global
  package cache, which is a local build artifact and not redistribution. It is listed here because
  a Debug build does link it. Its nuspec states MIT, authors "AvaloniaUI DiagnosticsSupport
  contributors".

### How these ship, and why it matters for your notice obligation

ProtocolForge publishes in two shapes, and in both of them the MIT assemblies below are
redistributed:

- **Windows** — `PublishSingleFile=true` and `SelfContained=true` in `ProtocolForge.csproj`, so the
  release is one self-contained `ProtocolForge.exe`. The Avalonia and CommunityToolkit assemblies are
  bundled **inside** that executable; you will not find loose `.dll` files next to it.
- **Linux** — `packaging/linux/publish-linux.sh` overrides with `-p:PublishSingleFile=false`, so the
  AppImage and deb ship a multi-file layout with the managed assemblies as separate `.dll` files
  alongside the launcher.

Either way, ProtocolForge redistributes substantial portions of these MIT works, so the notice and
the permission text must accompany your distribution. Putting this file (and `LICENSE`) in the same
directory as the payload, as all three packaging scripts do, satisfies that for both shapes.

## Section B — Components not redistributed, which the user installs

These are the legally important entries. Neither component is bundled, shipped, downloaded, or installed by ProtocolForge in any release artifact. Both are installed by the user, under the user's own acceptance of their licenses.

### B.1 Npcap (Windows, optional)

- Project home: <https://npcap.com/>
- License terms: <https://npcap.com/license>
- Developed by Nmap Software LLC (Insecure.Com LLC). Npcap is a trademark of Insecure.Com LLC.

**ProtocolForge does not bundle, redistribute, or install Npcap.** No Npcap binary, driver, or DLL ships in any release artifact, and the application has no code path that downloads or installs it.

**The license is free but proprietary.** It is not an OSI-approved open-source license. The user installs Npcap themselves from npcap.com and accepts the Nmap Project License at that time. Use of Npcap is governed by the terms the user accepted, not by this project's terms.

**The license prohibits redistribution.** The operative wording is:

> the Software "may not be redistributed"

and

> "You may not copy any part of the Software except to the extent that licensed use inherently demands the creation of a temporary copy"

This is why the correct integration for this project is detect-and-call, never copy-and-ship. A downstream redistributor must not add Npcap binaries, drivers, or DLLs to a ProtocolForge package, installer, or container image. Doing so would require an OEM redistribution license obtained from Nmap Software directly, and this project does not grant, sell, or convey one.

**How ProtocolForge reaches Npcap.** By runtime detection and P/Invoke only. On Windows the app probes for an already-installed `wpcap.dll` and, when it finds one matching a selected interface, opens it and injects frames. That is use of an independently installed copy on the operator's own machine. No Npcap file is copied into the ProtocolForge installation directory and no Npcap file travels with a ProtocolForge download.

**How Npcap is opened.** With **promiscuous mode off**. ProtocolForge does not capture traffic through Npcap and never registers a capture callback. The Npcap handle exists only to inject frames the operator explicitly selected.

**Degradation.** On macOS the equivalent native L2 path is a `/dev/bpfN` device opened directly, with no third-party component. On Windows, when Npcap is absent, the app uses raw, AF_PACKET-equivalent, IP-level and UDP sockets instead and simply degrades to a lower rung. Npcap is entirely optional. Missing DLL, no elevation, access denied, and no matching device all produce the same pure-managed behaviour as if Npcap were never considered.

**Elevation.** Npcap requires administrator or root. That requirement is on the operator, not on ProtocolForge.

**License seats.** A corporate user who needs more than the seat count the free license allows must obtain an Npcap OEM license directly from Nmap Software. That is the user's responsibility, not this project's, and it is not something this project can proxy or resell.

#### B.1.1 Npcap's acknowledgement requirement

The Npcap license requires that software which includes libpcap, WinPcap or ieee80211_radiotap, **including indirect inclusion through Npcap**, carry an acknowledgement in its documentation. ProtocolForge does not include any of those, directly or through Npcap, so this obligation is not triggered here. It is reproduced anyway, because it costs nothing and because anyone who later changes the integration model needs the text at hand.

ProtocolForge has no control over the wording of the acknowledgement Npcap asks for on a given day. The authoritative text is at <https://npcap.com/license>. What follows is the notice as published in libpcap's own `LICENSE`, which is the upstream source of the acknowledgement wording:

```text
License: BSD

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior written
     permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
```

If you redistribute something that actually incorporates Npcap or libpcap, take the current text from upstream rather than from this snapshot.

### B.2 tshark / Wireshark (all platforms, required)

- Project home: <https://www.wireshark.org/>
- Download: <https://www.wireshark.org/download.html>
- License: **GPL-2.0-or-later.** Developed by the Wireshark Foundation and contributors.

**tshark is the only required external runtime dependency of ProtocolForge. It is not bundled.** ProtocolForge never ships, links, or embeds Wireshark or tshark. There is no Wireshark installer in any release artifact, no `libwireshark`, and no `libwiretap` in any package. The user installs Wireshark themselves.

**How ProtocolForge uses it.** As an external subprocess. ProtocolForge spawns `tshark` and parses its documented, serialized output formats over pipes: `-T fields` for the streamed packet list, `-T jsonraw` and `-T json` for the on-demand protocol tree, and `-T pdml` for the single-packet reparse that backs Verify-Before-Commit. Every invocation goes through `ProcessStartInfo.ArgumentList`; no shell and no command string is involved.

**It does not link `libwireshark`, statically or dynamically, and does not embed Wireshark as a library.** This is the fact the rest of this section turns on.

#### B.2.1 Why this is outside the GPL derivative-work boundary

The reasoning rests on two sources, one from the license text and one from the upstream project itself.

**1. The GPL does not reach the act of running a program.** GNU General Public License, version 2, section 0:

> Activities other than copying, distribution and modification are not
> covered by this License; they are outside its scope.  The act of
> running the Program is not restricted, and the output from the Program
> is covered only if its contents constitute a work based on the
> Program (independent of having been made by running the Program).
> Whether that is true depends on what the Program does.

That is exactly the relationship here. ProtocolForge runs tshark. It does not copy it, distribute it, or modify it. And the output ProtocolForge consumes is not "a work based on the Program": it is a set of factual descriptions of network traffic, in a serialization format Wireshark documents and publishes for third-party consumers.

**2. Wireshark's own stated trigger is integration, not invocation.** From the Wireshark README:

> If you integrate all or part of Wireshark into your own application and you opt to publish or release it then the combined work must be released under the terms of the GPLv2.

"Integrate ... into your own application" is what triggers the obligation. Invoking a separate process and reading its documented output over a pipe is not integration. ProtocolForge takes the narrow reading on that basis, and it is the reading the upstream project itself describes.

#### B.2.2 The contested edge, stated plainly

This project is not going to pretend the boundary is frictionless. The FSF's own GPL FAQ acknowledges a broader reading is arguable:

> if the semantics of the communication are intimate enough, exchanging complex internal data structures, that too could be a basis to consider the two parts as combined into a larger program.

ProtocolForge's position is that the quoted language does not reach this design, for two reasons. First, what crosses the boundary is a **documented, serialized interchange format**, not internal data structures. ProtocolForge consumes tshark's `-T jsonraw`, `-T json`, `-T pdml` and `-T fields` output, all of which are published, versioned output formats intended to be consumed by tools other than Wireshark. Second, the content of that output is **factual description of network traffic**: byte values, field names, offsets, and lengths. That is not Wireshark's creative expression, so the "output is covered only if its contents constitute a work based on the Program" condition is not met.

A reasonable person could read the FSF sentence more broadly. This project takes the narrow reading, and states it openly so that a downstream reuser can make their own assessment rather than inherit a hidden assumption. If you disagree with the reading, the honest thing to do is not to fork the argument but to change the integration model, which is described next.

#### B.2.3 What would change the answer

Any of the following would put ProtocolForge inside the GPL derivative-work boundary, and all of them are things this project does not do:

- Linking `libwireshark` or `libwiretap`, statically or dynamically.
- Embedding Wireshark as a library, for example through a C# or C++ P/Invoke shim into libwireshark rather than a subprocess.
- Bundling Wireshark or tshark in an installer, AppImage, container image, or ZIP.
- Shipping a modified tshark, or shipping a tshark with patches.

#### B.2.4 Consequence: no GPL source-offer obligation

Because nothing covered by the GPL is copied, distributed, or modified by this project, and because nothing is conveyed, **no GPL source-offer obligation is triggered**. ProtocolForge is not required to offer its own source under the GPL, and the whole of ProtocolForge remains under Apache-2.0.

---

## Section C — This project's own license, and Apache-2.0 §4(b)

ProtocolForge is licensed under the Apache License, Version 2.0. The full text is in [`LICENSE`](LICENSE). Copyright 2026 ProtocolForge contributors.

Under Apache-2.0 §4(b), a derivative work must cause any **modified** files to carry prominent notices stating that they were changed. ProtocolForge is original work. It contains no code copied from Wireshark, no code copied from Npcap, and no code copied from any other upstream project; the third-party components listed in Section A arrive through NuGet package references, not through vendored source. To the extent that any modification notice is required or provided, it is recorded per file in that file itself, and no such notice exists elsewhere in the tree. The absence of code reuse is what makes §4(b) a formality here rather than a live obligation.

---

## Section D — If you redistribute ProtocolForge

Two duties travel with the binary.

1. **Apache-2.0.** Keep the Apache-2.0 license text with your distribution. A copy is in this repository as [`LICENSE`](LICENSE). If you modify any file, mark it as changed (Apache-2.0 §4(b)).
2. **MIT terms for anything you still ship.** MIT requires its copyright notice and permission text in all copies or substantial portions of the Software. Section A.3 of this file does that for you for every package in Section A. If you strip a component out, you may drop that component's line from A.1; if you keep it, you must keep the notice, and the notice must name the real copyright holder, filled in from that package's own `LICENSE` as described in A.2.

If you add a dependency, this file is where its notice goes. A dependency that is linked into the binary belongs in Section A with its full license text. A dependency the user installs themselves belongs in Section B, with the boundary reasoning written down rather than assumed.

Do not add Npcap, Wireshark, or tshark binaries to your package. See Section B.
