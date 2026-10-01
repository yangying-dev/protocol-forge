#!/usr/bin/env bash
# Set the GitHub repository metadata that the public repo currently lacks.
#
# Why this is a script and not a done deal: it needs an authenticated GitHub
# API client, which this environment does not have. The repo is public and its
# `description` and `topics` are both empty, which makes it effectively
# unfindable in search. That is the single highest-value remaining fix.
#
# Usage:
#   gh auth login
#   ./docs/set-repo-metadata.sh
#
# Verify afterwards:
#   curl -s https://api.github.com/repos/yangying-dev/protocol-forge \
#     | jq '{description,topics}'
set -euo pipefail

REPO="yangying-dev/protocol-forge"

command -v gh >/dev/null || {
  echo "error: GitHub CLI not found. Install it, then: gh auth login" >&2
  exit 1
}
gh auth status >/dev/null 2>&1 || {
  echo "error: not authenticated. Run: gh auth login" >&2
  exit 1
}

# English-first: GitHub search indexes the description, and the audience for
# this tool is international even though the UI ships with Chinese.
DESCRIPTION='3GPP protocol workbench: inspect, edit and replay PFCP/NGAP/GTP-U/NAS/S1AP/Diameter packets from PCAP, using tshark for dissection. .NET 8 + Avalonia.'

TOPICS='3gpp,pcap,tshark,wireshark,pfcp,ngap,gtp,protocol-analysis,network-packets,packet-injection,avalonia,dotnet,linux,windows,macos,3gpp-network'

echo "Setting description and topics on $REPO ..."
gh api --method PATCH "repos/$REPO" \
  -f "description=$DESCRIPTION" >/dev/null

# topics needs PUT with a JSON array, not -f.
gh api --method PUT "repos/$REPO/topics" \
  -H "Accept: application/vnd.github+json" \
  --input - <<JSON >/dev/null
{"names":["$(printf '%s' "$TOPICS" | sed 's/,/","/g')"]}
JSON

echo "Done. Current state:"
gh api "repos/$REPO" --jq '{description, visibility, license: .license.spdx_id, homepage, topics}'
