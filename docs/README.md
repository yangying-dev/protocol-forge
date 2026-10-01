# docs/

Index of the documents in this folder. Almost everything here is **internal-facing engineering reference material for contributors**, not end-user documentation. End users should start at the top-level [`README.md`](../README.md) (English) or [`README.zh-CN.md`](../README.zh-CN.md) (简体中文). The one exception is the attribution material, which is a compliance document.

Language is noted per file. Several of these documents are written in Chinese, matching the project's documentation and UI convention.

| Document | Language | What it is | Who it is for |
|---|---|---|---|
| [`CodeMap.md`](CodeMap.md) | 中文 | Symptom-first map from a UI action down through the functions it triggers, with a triage table for locating the responsible code fast. | **Internal engineering reference.** For contributors diagnosing a bug report: "user clicked X, which file actually handles it". Pair it with `AGENTS.md` for the conventions it assumes. |
| [`FullFunctionTest.md`](FullFunctionTest.md) | 中文 | Full functional test case document: per-feature cases, expected results, and pass criteria across ingestion, editing, export and sending. | **Internal QA reference.** For contributors writing or extending test cases, and for reviewers checking whether a change is covered. Not a user manual. |
| [`RealDeviceQA.md`](RealDeviceQA.md) | 中文 | Real-device QA checklist for the native L2 send rung, covering Npcap on Windows and BPF on macOS: detection, direct injection, and degradation behaviour, with the observation channel for each case. | **Internal QA reference**, with a user-facing section on physical-adapter behaviour. Use it when a change touches the send ladder and you have real hardware. The data-safety rules at the top apply to anyone running it. |
| [`Npcap-Attribution.md`](Npcap-Attribution.md) | 中文 with English notice text | Npcap attribution material: the third-party component notice text used by the About dialog, plus install steps and a legal-review checklist. | **Compliance reference.** The authoritative, released position on Npcap lives in [`../THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md); where the two differ, the latter wins. Do not treat the checklist items as claims about the shipped product. |
| [`make-synthetic-capture.py`](make-synthetic-capture.py) | Python 3, no dependencies | Generates a small **synthetic** PCAP (PFCP, GTP-U, TCP/HTTP) from hand-assembled literal bytes. Used to produce the README screenshots and for manual UI exploration. Writes outside the repository by default, because `.gitignore` blocks `*.pcap` and CI rejects them. | **Anyone who needs a capture to look at.** Run it, then open the result in the app. It is not a test fixture: at 6 frames it is too small for the harness groups that assert on frame 4413 (see [`../CONTRIBUTING.md`](../CONTRIBUTING.md)). |
| [`images/`](images/) | English and Chinese | The README screenshots, generated from the synthetic capture above. | Referenced by both READMEs. Regenerate rather than hand-editing. |
| [`set-repo-metadata.sh`](set-repo-metadata.sh) | Bash, needs `gh` | Sets the GitHub repository `description` and `topics`, which are currently empty. Not run by CI: it needs an authenticated GitHub API client. | **The maintainer**, once, after `gh auth login`. A public repo with no description and no topics is effectively invisible in search. |
| [`README.md`](README.md) | English | This index. | Everyone landing in `docs/` and wondering what is in here. |

## Where things actually live

Not everything documented is in `docs/`. The root-level files carry the load:

- [`../README.md`](../README.md) and [`../README.zh-CN.md`](../README.zh-CN.md): end-user and developer documentation, including the injection-ladder explanation and the secondary development guide.
- [`../SECURITY.md`](../SECURITY.md): intended use, disclosed limits of the send path, verified-clean properties, and reporting channels.
- [`../THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md): the authoritative third-party and license-boundary position.
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md): conventions, the verification harness, and the SKIP-is-not-PASS trap.
- [`../CHANGELOG.md`](../CHANGELOG.md): release history.
- [`../AGENTS.md`](../AGENTS.md): the machine-readable project knowledge base. Read this before editing code; it records where each subsystem lives and which anti-patterns the project has deliberately rejected.

## Conventions for adding to this folder

- Say who a document is **for** in the index row. A contributor should be able to tell from one line whether a file will save them time or waste it.
- Mark clearly whether a document is user-facing, an internal engineering reference, or a draft pending review. A reader who mistakes a draft for settled policy wastes an afternoon.
- Real captures never belong in this folder, or anywhere in the repository. `.gitignore` blocks `*.pcap` and `*.pcapng` and CI rejects them in any diff.

## Deliberately not in this folder

Two documents were removed before the public release rather than published:

- **A user manual for `pfcheck`** — a planned command-line validation tool. The tool does not exist, so the manual documented a command nobody could run, and it referenced internal review identifiers. If the tool is ever built, write the manual then.
- **Project marketing copy** — sales and announcement text. It is not documentation and it is not a source of truth for behaviour. Keep it wherever announcements are drafted, outside the repository.

A document describing something that does not exist yet reads as a shipped feature to anyone who lands on it. That is the failure mode this folder is trying to avoid.
