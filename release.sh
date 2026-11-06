#!/bin/bash
# Builds a downloadable, self-contained beta:
#   - universal app (Apple Silicon + Intel) with Node.js bundled, so users don't need to install anything
#   - packed as dist/AI-Access-Auditor-<version>.dmg, plus its SHA-256
# Unsigned (ad-hoc) for now: users approve it once via System Settings → Privacy & Security → Open Anyway.
set -euo pipefail
cd "$(dirname "$0")"
VERSION="${VERSION:-1.0.0-beta}"
NODE_VERSION="v22.12.0"
CACHE="${NODE_CACHE:-$HOME/Library/Caches/ai-access-auditor-build}"
REL="dist/release"
APP="$REL/AI Access Auditor.app"
DMG="dist/AI-Access-Auditor-$VERSION.dmg"

# 1. Official Node.js for both architectures, checksum-verified, combined into one binary (cached)
NODE_UNI="$CACHE/node-$NODE_VERSION-universal"
if [ ! -x "$NODE_UNI" ]; then
  mkdir -p "$CACHE"
  ( cd "$CACHE"
    curl -fsSLO "https://nodejs.org/dist/$NODE_VERSION/SHASUMS256.txt"
    for A in arm64 x64; do curl -fsSLO "https://nodejs.org/dist/$NODE_VERSION/node-$NODE_VERSION-darwin-$A.tar.gz"; done
    grep -E "node-$NODE_VERSION-darwin-(arm64|x64)\.tar\.gz$" SHASUMS256.txt | shasum -a 256 -c -
    for A in arm64 x64; do tar -xzf "node-$NODE_VERSION-darwin-$A.tar.gz" "node-$NODE_VERSION-darwin-$A/bin/node" "node-$NODE_VERSION-darwin-$A/LICENSE"; done
    lipo -create "node-$NODE_VERSION-darwin-arm64/bin/node" "node-$NODE_VERSION-darwin-x64/bin/node" -output "node-$NODE_VERSION-universal"
    cp "node-$NODE_VERSION-darwin-arm64/LICENSE" "node-$NODE_VERSION-LICENSE" )
fi

# 2. Start from the normal build, then make it universal and self-contained
./build-app.sh >/dev/null
rm -rf "$REL" && mkdir -p "$REL"
cp -R "dist/AI Access Auditor.app" "$APP"
T=$(mktemp -d)
for ARCH in arm64 x86_64; do
  swiftc -O -target "$ARCH-apple-macos13.0" -o "$T/app-$ARCH" macos/main.swift macos/prompt.swift macos/i18n.swift -framework Cocoa -framework WebKit
done
lipo -create "$T/app-arm64" "$T/app-x86_64" -output "$APP/Contents/MacOS/AIAccessAuditor"
rm -rf "$T"
mkdir -p "$APP/Contents/Resources/runtime"
cp "$NODE_UNI" "$APP/Contents/Resources/runtime/node"
cp "$CACHE/node-$NODE_VERSION-LICENSE" "$APP/Contents/Resources/runtime/NODE-LICENSE"
plutil -replace CFBundleShortVersionString -string "$VERSION" "$APP/Contents/Info.plist"
plutil -replace LSMinimumSystemVersion -string "13.0" "$APP/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$(date +%Y%m%d%H%M)" "$APP/Contents/Info.plist"
# Sign the app ad-hoc. Not --deep: the bundled node keeps the Node.js project's own signature.
codesign --force -s - "$APP"

# 3. Disk image with the usual "drag to Applications" layout
STAGE=$(mktemp -d)
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG"
hdiutil create -volname "AI Access Auditor" -srcfolder "$STAGE" -ov -format ULFO "$DMG" >/dev/null
rm -rf "$STAGE"
shasum -a 256 "$DMG" | tee "$DMG.sha256"
echo "Built: $DMG ($(du -h "$DMG" | cut -f1))"

# 4. Put the download on the website and keep its link, size, checksum and version on the page up to date.
#    With REPO=owner/name the button points at the GitHub Release (PUBLISH=1 also uploads it there);
#    without it, the DMG is copied into site/downloads for a local preview.
SHA=$(cut -d' ' -f1 "$DMG.sha256")
SIZE_MB=$(( ($(stat -f%z "$DMG") + 524288) / 1048576 ))
NAME="AI-Access-Auditor-$VERSION.dmg"
if [ -n "${REPO:-}" ]; then
  URL="https://github.com/$REPO/releases/download/v$VERSION/$NAME"
else
  URL="downloads/$NAME"
  mkdir -p site/downloads
  cp "$DMG" "$DMG.sha256" site/downloads/
fi
sed -i '' -E \
  -e "s|href=\"[^\"]*AI-Access-Auditor-[0-9A-Za-z.-]+\.dmg\"|href=\"$URL\"|g" \
  -e "s|(<span id=\"sha\">)[0-9a-f]+|\1$SHA|" \
  -e "s|· [0-9]+ MB</span>|· $SIZE_MB MB</span>|" \
  -e "s/Version [0-9]+\.[0-9]+\.[0-9]+ beta/Version ${VERSION/-/ }/g" \
  site/index.html
# The Linux files (built by ./build-linux.sh) are linked from the Install section
sed -i '' -E \
  -e "s#releases/download/v[^/\"]+/AI-Access-Auditor-[0-9]+\.[0-9]+\.[0-9]+(-[a-z]+)?-(amd64\.deb|arm64\.deb|x86_64\.AppImage|windows-x64\.exe|windows-arm64\.exe)#releases/download/v$VERSION/AI-Access-Auditor-$VERSION-\2#g" \
  -e "s#releases/download/v[^/\"]+/SHA256SUMS-(linux|windows)\.txt#releases/download/v$VERSION/SHA256SUMS-\1.txt#g" \
  site/index.html
node i18n/build-site.js   # French and Arabic pages get the same link, size and checksum
if [ "${PUBLISH:-}" = "1" ] && [ -n "${REPO:-}" ]; then
  gh release create "v$VERSION" "$DMG" "$DMG.sha256" --repo "$REPO" --prerelease \
    --title "AI Access Auditor $VERSION" \
    --notes "Unsigned beta for macOS 13 or later (Apple Silicon and Intel), Windows 10 and 11 (installers for x64 and arm64), and Linux (AppImage for x64, .deb for x64 and arm64). Mac SHA-256: $SHA. Linux and Windows checksums: SHA256SUMS-linux.txt, SHA256SUMS-windows.txt. Install steps: https://dirmedmr-alt.github.io/ai-access-auditor/#install"
  LINUX=(desktop/dist/AI-Access-Auditor-$VERSION-x86_64.AppImage desktop/dist/AI-Access-Auditor-$VERSION-amd64.deb desktop/dist/AI-Access-Auditor-$VERSION-arm64.deb desktop/dist/SHA256SUMS-linux.txt)
  if ls "${LINUX[@]}" >/dev/null 2>&1; then gh release upload "v$VERSION" "${LINUX[@]}" --repo "$REPO" --clobber
  else echo "Linux files for $VERSION not found: run VERSION=$VERSION ./build-linux.sh, then upload desktop/dist/* to the release."; fi
  # Windows installers, built and tested by AppVeyor for this commit
  if VERSION="$VERSION" ./fetch-windows.sh; then
    gh release upload "v$VERSION" desktop/dist/windows/AI-Access-Auditor-$VERSION-windows-x64.exe desktop/dist/windows/AI-Access-Auditor-$VERSION-windows-arm64.exe desktop/dist/windows/SHA256SUMS-windows.txt --repo "$REPO" --clobber
  else echo "Windows installers not uploaded (see above)."; fi
fi
echo "Website ready: site/ (download: $URL, $SIZE_MB MB)"
