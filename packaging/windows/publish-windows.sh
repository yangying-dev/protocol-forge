#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="${PROTOCOLFORGE_VERSION:-0.1.0}"
OUT="$ROOT/artifacts/windows-x64"
STAGE="$OUT/ProtocolForge"
ZIP="$OUT/ProtocolForge-${VERSION}-win-x86_64.zip"
DOTNET="${DOTNET:-dotnet}"
export PATH="/usr/share/dotnet:$HOME/.dotnet/tools:$PATH"

rm -rf "$OUT"
mkdir -p "$STAGE"

"$DOTNET" restore ProtocolForge/ProtocolForge.csproj
"$DOTNET" publish ProtocolForge/ProtocolForge.csproj \
  -c Release \
  -r win-x64 \
  --self-contained true \
  -p:PublishSingleFile=false \
  -p:IncludeNativeLibrariesForSelfExtract=false \
  -p:DebugType=None \
  -p:DebugSymbols=false \
  -o "$STAGE" \
  --nologo \
  -warnaserror

test -f "$STAGE/ProtocolForge.exe"
find "$STAGE" -type f -name '*.pdb' -delete

# 混淆回填: OBFUSCATED_DLL 指向一个混淆后的 ProtocolForge.dll 则随包发布; 未设置则产出未混淆包。
PKG_DLL="$STAGE/ProtocolForge.dll"
if [ -n "${OBFUSCATED_DLL:-}" ]; then
  if [ ! -f "$OBFUSCATED_DLL" ]; then
    echo "error: OBFUSCATED_DLL 不存在: $OBFUSCATED_DLL" >&2
    exit 1
  fi
  cp -f "$OBFUSCATED_DLL" "$PKG_DLL"
  echo "obfuscated: 已回填 $OBFUSCATED_DLL"
else
  echo "obfuscated: 未启用 (设 OBFUSCATED_DLL=<混淆后 ProtocolForge.dll> 以随包发布混淆版)"
fi
echo "obfuscated: 随包 DLL md5 = $(md5sum "$PKG_DLL" | cut -d' ' -f1)"
cp packaging/windows/CUSTOMER-INSTALL.txt "$STAGE/CUSTOMER-INSTALL.txt"
# Apache-2.0 §4(a) requires the license text to accompany every distributed copy,
# and the bundled MIT components require their license texts in all copies or
# substantial portions. Both must therefore land INSIDE the archive.
cp LICENSE "$STAGE/LICENSE"
cp THIRD-PARTY-NOTICES.md "$STAGE/THIRD-PARTY-NOTICES.md"
cat > "$STAGE/RELEASE-MANIFEST.txt" <<EOF
ProtocolForge $VERSION
Target: Windows 10/11 x64
Publish: multi-file self-contained .NET 8
Build date: $(date +%F)
Customer dependency: Wireshark/tshark >= 2.6.0; customer-installed Npcap supported, not bundled
License: Apache-2.0 (see LICENSE); third-party attributions in THIRD-PARTY-NOTICES.md
Data: no production PCAP, private key, or payment credentials are included
EOF

python3 - "$STAGE" "$ZIP" <<'PY'
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
import sys
stage, archive = map(Path, sys.argv[1:])
with ZipFile(archive, "w", ZIP_DEFLATED) as z:
    for path in sorted(stage.rglob("*")):
        if path.is_file():
            z.write(path, Path("ProtocolForge") / path.relative_to(stage))
PY

(cd "$OUT" && sha256sum "$(basename "$ZIP")" > SHA256SUMS)

echo "Windows multi-file package:"
echo "  $ZIP"
echo "  $OUT/SHA256SUMS"
