#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="${VERSION:-0.1.0}"
ARCH="amd64"
RID="linux-x64"
OUT="${OUT:-$ROOT/artifacts/linux-x64}"
PUBLISH_DIR="$OUT/publish"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/protocolforge-linux.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT
APPIMAGE_TOOL="${APPIMAGETOOL:-$(command -v appimagetool || true)}"
ICON_CONVERTER="${ICON_CONVERTER:-$(command -v convert || command -v magick || true)}"

rm -rf "$OUT"
mkdir -p "$PUBLISH_DIR"

DOTNET="${DOTNET:-dotnet}"
export PATH="/usr/share/dotnet:$HOME/.dotnet/tools:$PATH"

"$DOTNET" restore ProtocolForge/ProtocolForge.csproj
"$DOTNET" publish ProtocolForge/ProtocolForge.csproj \
  -c Release \
  -r "$RID" \
  --self-contained true \
  -p:PublishSingleFile=false \
  -p:IncludeNativeLibrariesForSelfExtract=false \
  -p:DebugType=None \
  -p:DebugSymbols=false \
  -o "$PUBLISH_DIR" \
  --nologo \
  -warnaserror

test -x "$PUBLISH_DIR/ProtocolForge"

# 混淆回填: OBFUSCATED_DLL 指向一个混淆后的 ProtocolForge.dll 则随包发布; 未设置则产出未混淆包。
PKG_DLL="$PUBLISH_DIR/ProtocolForge.dll"
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

if [ -z "$ICON_CONVERTER" ]; then
  echo "error: ImageMagick convert/magick is required to create the Linux icon" >&2
  exit 1
fi

"$ICON_CONVERTER" ProtocolForge/Assets/protocol-forge-1024.jpg \
  -resize 512x512 \
  "$TMP_ROOT/protocolforge.png"

# ── AppImage ────────────────────────────────────────────────────────────────
APPDIR="$TMP_ROOT/ProtocolForge.AppDir"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/512x512/apps" "$APPDIR/usr/share/metainfo"
cp -a "$PUBLISH_DIR"/. "$APPDIR/usr/bin/"
cp packaging/linux/protocolforge-appimage.desktop "$APPDIR/protocolforge.desktop"
cp packaging/linux/protocolforge-appimage.desktop "$APPDIR/usr/share/applications/protocolforge.desktop"
cp "$TMP_ROOT/protocolforge.png" "$APPDIR/protocolforge.png"
cp "$TMP_ROOT/protocolforge.png" "$APPDIR/usr/share/icons/hicolor/512x512/apps/protocolforge.png"
cp packaging/linux/protocolforge.appdata.xml "$APPDIR/usr/share/metainfo/protocolforge.appdata.xml"
# Apache-2.0 §4(a) requires the license text to accompany every distributed copy,
# and the bundled MIT components require their license texts in all copies or
# substantial portions. Both must therefore land INSIDE the artifact.
cp "$ROOT/LICENSE" "$APPDIR/LICENSE"
cp "$ROOT/THIRD-PARTY-NOTICES.md" "$APPDIR/THIRD-PARTY-NOTICES.md"
cat > "$APPDIR/AppRun" <<'EOF'
#!/usr/bin/env bash
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$HERE/usr/bin/ProtocolForge" "$@"
EOF
chmod +x "$APPDIR/AppRun"

if [ -n "$APPIMAGE_TOOL" ] && [ -x "$APPIMAGE_TOOL" ]; then
  ARCH=x86_64 "$APPIMAGE_TOOL" --no-appstream "$APPDIR" "$OUT/ProtocolForge-${VERSION}-linux-x86_64.AppImage"
else
  if [ "${SKIP_APPIMAGE:-0}" = "1" ]; then
    echo "warning: appimagetool not found; skipping AppImage" >&2
  else
    echo "error: appimagetool not found. Set APPIMAGETOOL=/path/to/appimagetool or set SKIP_APPIMAGE=1 for deb-only builds." >&2
    exit 1
  fi
fi

# ── deb ─────────────────────────────────────────────────────────────────────
DEB_ROOT="$TMP_ROOT/deb-root"
DEB_PATH="$OUT/protocolforge_${VERSION}_${ARCH}.deb"
mkdir -p "$DEB_ROOT/DEBIAN" \
         "$DEB_ROOT/opt/ProtocolForge" \
         "$DEB_ROOT/usr/bin" \
         "$DEB_ROOT/usr/share/applications" \
         "$DEB_ROOT/usr/share/icons/hicolor/512x512/apps" \
         "$DEB_ROOT/usr/share/metainfo"
cp -a "$PUBLISH_DIR"/. "$DEB_ROOT/opt/ProtocolForge/"
ln -s /opt/ProtocolForge/ProtocolForge "$DEB_ROOT/usr/bin/protocolforge"
cp packaging/linux/protocolforge.desktop "$DEB_ROOT/usr/share/applications/protocolforge.desktop"
cp "$TMP_ROOT/protocolforge.png" "$DEB_ROOT/usr/share/icons/hicolor/512x512/apps/protocolforge.png"
cp packaging/linux/protocolforge.appdata.xml "$DEB_ROOT/usr/share/metainfo/protocolforge.appdata.xml"
cp "$ROOT/LICENSE" "$DEB_ROOT/opt/ProtocolForge/LICENSE"
cp "$ROOT/THIRD-PARTY-NOTICES.md" "$DEB_ROOT/opt/ProtocolForge/THIRD-PARTY-NOTICES.md"

installed_size="$(du -sk "$DEB_ROOT/opt/ProtocolForge" | cut -f1)"
computed_deps=""
if command -v dpkg-shlibdeps >/dev/null 2>&1; then
  computed_deps="$(dpkg-shlibdeps -O "$DEB_ROOT/opt/ProtocolForge/ProtocolForge" 2>/dev/null || true)"
fi
if [ -n "$computed_deps" ]; then
  depends="tshark, $computed_deps"
else
  depends="tshark, libc6, libgcc-s1, libgtk-3-0 | libgtk-3-0t64, libx11-6, libx11-xcb1, libice6, libsm6, libxext6, libxrandr2, libxdamage1, libxfixes3, libxcomposite1, libxkbcommon0, libasound2 | libasound2t64"
fi

cat > "$DEB_ROOT/DEBIAN/control" <<EOF
Package: protocolforge
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Installed-Size: $installed_size
Maintainer: ProtocolForge contributors <https://github.com/yangying-dev/protocol-forge/issues>
Depends: $depends
Description: 3GPP protocol simulation and debugging workbench
 ProtocolForge inspects, edits, and replays 3GPP protocol packets using tshark,
 with a native tree/hex editor and network-interface injection.
EOF

find "$DEB_ROOT" -type d -exec chmod 755 {} +
find "$DEB_ROOT" -type f -exec chmod 644 {} +
chmod 755 "$DEB_ROOT/opt/ProtocolForge/ProtocolForge"
fakeroot dpkg-deb --build "$DEB_ROOT" "$DEB_PATH" >/dev/null

(
  cd "$OUT"
  sha256sum ./*.deb ./*.AppImage 2>/dev/null > SHA256SUMS || true
)

echo "Linux packages:"
find "$OUT" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.AppImage' -o -name 'SHA256SUMS' \) -printf '  %f\n' | sort
