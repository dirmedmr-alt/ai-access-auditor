#!/bin/bash
# Builds a downloadable, self-contained release:
#   - universal app (Apple Silicon + Intel) with Node.js bundled, so users don't need to install anything
#   - packed as dist/AI-Access-Auditor-<version>.dmg, plus its SHA-256
# Betas are signed ad-hoc: users approve them once via System Settings → Privacy & Security → Open Anyway.
# Releases (a version without "-beta") are signed with a Developer ID and notarized by Apple, so they open
# without a warning. They need, once:
#   - the "Developer ID Application" certificate in the login keychain (Xcode → Settings → Accounts → Manage Certificates)
#   - xcrun notarytool store-credentials ai-access-auditor --apple-id <id> --team-id <team> --password <app-specific password>
# then: SIGN_ID="Developer ID Application: <Name> (<TEAM>)" VERSION=1.0.8 REPO=... PUBLISH=1 ./release.sh
set -euo pipefail
cd "$(dirname "$0")"
node --test test/ >/dev/null || { echo "Tests failed: run  node --test test/  to see which. Nothing was built."; exit 1; }
VERSION="${VERSION:-1.0.0-beta}"
SIGN_ID="${SIGN_ID:--}"                       # "-" = ad-hoc
NOTARY_PROFILE="${NOTARY_PROFILE:-ai-access-auditor}"
case "$VERSION" in *-*) BETA=1 ;; *) BETA= ;; esac
if [ -z "$BETA" ] && [ "$SIGN_ID" = "-" ] && [ "${PUBLISH:-}" = "1" ]; then
  echo "$VERSION is not a beta, so it must be signed and notarized: set SIGN_ID (see the top of this script)." >&2; exit 1
fi
if [ "$SIGN_ID" != "-" ]; then
  security find-identity -v -p codesigning | grep -qF "$SIGN_ID" || { echo "Signing identity not found in the keychain: $SIGN_ID" >&2; exit 1; }
  xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null || { echo "Notary credentials \"$NOTARY_PROFILE\" not found (see the top of this script)." >&2; exit 1; }
fi
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
if [ "$SIGN_ID" = "-" ]; then
  # Ad-hoc. Not --deep: the bundled node keeps the Node.js project's own signature.
  codesign --force -s - "$APP"
else
  # Inside out, with the hardened runtime and a secure timestamp, as notarization requires
  codesign --force --options runtime --timestamp --entitlements macos/node.entitlements -s "$SIGN_ID" "$APP/Contents/Resources/runtime/node"
  codesign --force --options runtime --timestamp -s "$SIGN_ID" "$APP"
  codesign --verify --strict --verbose=2 "$APP"
fi

# 3. Disk image with the usual "drag to Applications" layout
STAGE=$(mktemp -d)
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG"
hdiutil create -volname "AI Access Auditor" -srcfolder "$STAGE" -ov -format ULFO "$DMG" >/dev/null
rm -rf "$STAGE"
if [ "$SIGN_ID" != "-" ]; then
  # Apple checks the app for malware (usually a few minutes), then the ticket is attached so it opens offline too
  codesign --force --timestamp -s "$SIGN_ID" "$DMG"
  # keep the whole reply (grep -q would stop reading early, and with pipefail that looks like a failure)
  NOTARY_OUT=$(xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait 2>&1) || true
  echo "$NOTARY_OUT"
  grep -q "status: Accepted" <<<"$NOTARY_OUT" \
    || { echo "Notarization failed. Details: xcrun notarytool log <submission id> --keychain-profile $NOTARY_PROFILE" >&2; exit 1; }
  xcrun stapler staple "$DMG"
  spctl -a -t open --context context:primary-signature -v "$DMG"
fi
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
  -e "s/Version [0-9]+\.[0-9]+\.[0-9]+( beta)?/Version ${VERSION/-/ }/g" \
  site/index.html
# The Linux files (built by ./build-linux.sh) are linked from the Install section
sed -i '' -E \
  -e "s#releases/download/v[^/\"]+/AI-Access-Auditor-[0-9]+\.[0-9]+\.[0-9]+(-[a-z]+)?-(amd64\.deb|arm64\.deb|x86_64\.AppImage|windows-x64\.exe|windows-arm64\.exe)#releases/download/v$VERSION/AI-Access-Auditor-$VERSION-\2#g" \
  -e "s#releases/download/v[^/\"]+/SHA256SUMS-(linux|windows)\.txt#releases/download/v$VERSION/SHA256SUMS-\1.txt#g" \
  site/index.html
node i18n/build-site.js   # French and Arabic pages get the same link, size and checksum
if [ "${PUBLISH:-}" = "1" ] && [ -n "${REPO:-}" ]; then
  PLATFORMS="macOS 13 or later (Apple Silicon and Intel), Windows 10 and 11 (installers for x64 and arm64), and Linux (AppImage for x64, .deb for x64 and arm64)"
  if [ -n "$BETA" ]; then NOTES="Unsigned beta for $PLATFORMS."
  else NOTES="For $PLATFORMS. The Mac app is signed and notarized by Apple. The Windows installers aren't signed yet."; fi
  gh release create "v$VERSION" "$DMG" "$DMG.sha256" --repo "$REPO" ${BETA:+--prerelease} \
    --title "AI Access Auditor $VERSION" \
    --notes "$NOTES Mac SHA-256: $SHA. Linux and Windows checksums: SHA256SUMS-linux.txt, SHA256SUMS-windows.txt. Install steps: https://dirmedmr-alt.github.io/ai-access-auditor/#install"
  LINUX=(desktop/dist/AI-Access-Auditor-$VERSION-x86_64.AppImage desktop/dist/AI-Access-Auditor-$VERSION-amd64.deb desktop/dist/AI-Access-Auditor-$VERSION-arm64.deb desktop/dist/SHA256SUMS-linux.txt)
  if ls "${LINUX[@]}" >/dev/null 2>&1; then gh release upload "v$VERSION" "${LINUX[@]}" --repo "$REPO" --clobber
  else echo "Linux files for $VERSION not found: run VERSION=$VERSION ./build-linux.sh, then upload desktop/dist/* to the release."; fi
  # Windows installers, built and tested by AppVeyor for this commit
  if VERSION="$VERSION" ./fetch-windows.sh; then
    gh release upload "v$VERSION" desktop/dist/windows/AI-Access-Auditor-$VERSION-windows-x64.exe desktop/dist/windows/AI-Access-Auditor-$VERSION-windows-arm64.exe desktop/dist/windows/SHA256SUMS-windows.txt --repo "$REPO" --clobber
  else echo "Windows installers not uploaded (see above)."; fi
fi
echo "Website ready: site/ (download: $URL, $SIZE_MB MB)"
