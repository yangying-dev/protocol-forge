#!/usr/bin/env python3
"""Reject real capture filenames appearing inside tracked text files.

CI already blocks committing *.pcap / *.pcapng binaries. That check is not
enough: a capture can leak through its *name* alone, embedded in source, a
comment, or a test-case table. A capture name alone can disclose the operator,
the radio technology under test and the test intent, with no bytes present.

This scans tracked files for capture-shaped filenames and allows only known
generic placeholders, so a newly added real capture name fails the build
without anyone having to remember to update a denylist.

Usage:
    python3 docs/check-no-capture-names.py
Exit codes: 0 clean, 1 violation, 2 setup problem (nothing scanned).
"""

import pathlib
import re
import subprocess
import sys

# Matches a filename ending in .pcapng/.pcap, including CJK and operator-ish
# characters, so a CJK vendor-and-network name is caught as one token.
# Order matters: pcapng must precede pcap or the shorter suffix wins.
NAME = re.compile(r"[0-9A-Za-z_.\-一-鿿㐀-䶿&+]+(?:/[\w.\-一-鿿㐀-䶿&+]+)*\.(?:pcapng|pcap)")

# Names that carry no information about a real network or capture.
ALLOWED_STEMS = {
    "capture.pcap",
    "capture.pcapng",
    "example.pcap",
    "file.pcap",
    "large-capture.pcapng",
    "local.pcap",
    "one.pcap",
    "output.pcap",
    "protocol-forge-synthetic.pcap",
    "sample.pcap",
}

# Harness-generated temporaries: pf_verify_<guid>.pcap, pf-g29-<guid>.pcap, ...
GENERATED = re.compile(r"^(?:pf[_-]|pf_verify_)")


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [p for p in out.split("\0") if p]


def main() -> int:
    self_path = pathlib.Path(__file__).as_posix()
    suffixes = {
        ".cs", ".md", ".json", ".yml", ".yaml", ".sh", ".ps1", ".axaml",
        ".txt", ".xml", ".csproj", ".sln", ".editorconfig", ".gitignore",
        ".gitattributes", ".py", ".desktop", ".appdata.xml",
    }
    targets = [
        f for f in tracked_files()
        if f != self_path and pathlib.Path(f).suffix.lower() in suffixes
    ]
    if not targets:
        print("error: no files scanned; is this outside a git checkout?", file=sys.stderr)
        return 2

    violations: list[str] = []
    for rel in targets:
        try:
            text = pathlib.Path(rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for match in NAME.findall(line):
                if "vnd." in match:
                    continue
                stem = match.rsplit("/", 1)[-1]
                if stem in ALLOWED_STEMS or GENERATED.match(stem):
                    continue
                violations.append(f"{rel}:{lineno}: {match}")

    if violations:
        print(
            "Real capture filenames must not appear in tracked files.\n"
            "A capture's name alone can disclose the operator and the technology\n"
            "under test. Reference captures generically and pass a real path via\n"
            f"the PF_CAPTURE environment variable.\n\nAllowed names: "
            f"{', '.join(sorted(ALLOWED_STEMS))}\n\nViolations:\n",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    print(f"OK: scanned {len(targets)} tracked files, no capture filenames found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
