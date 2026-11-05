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
  swiftc -O -target "$ARCH-apple-macos13.0" -o "$T/app-$ARCH" macos/main.swift macos/prompt.swift -framework Cocoa -framework WebKit
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

# 4. Put the download on the website and keep its size and checksum on the page up to date
SHA=$(cut -d' ' -f1 "$DMG.sha256")
SIZE_MB=$(( ($(stat -f%z "$DMG") + 524288) / 1048576 ))
mkdir -p site/downloads
cp "$DMG" "$DMG.sha256" site/downloads/
sed -i '' -E \
  -e "s|AI-Access-Auditor-[0-9A-Za-z.-]+\.dmg|AI-Access-Auditor-$VERSION.dmg|g" \
  -e "s|(<span id=\"sha\">)[0-9a-f]+|\1$SHA|" \
  -e "s|· [0-9]+ MB</span>|· $SIZE_MB MB</span>|" \
  site/index.html
echo "Website ready: site/ (download: site/downloads/AI-Access-Auditor-$VERSION.dmg, $SIZE_MB MB)"
