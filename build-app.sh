#!/bin/bash
# Builds "AI Access Auditor.app" in ./dist
set -euo pipefail
cd "$(dirname "$0")"
APP="dist/AI Access Auditor.app"
rm -rf "$APP" && mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -O -o "$APP/Contents/MacOS/AIAccessAuditor" macos/main.swift -framework Cocoa -framework WebKit
cp server.js "$APP/Contents/Resources/" && cp -R public "$APP/Contents/Resources/"
# Icon
T=$(mktemp -d); swift macos/icon.swift "$T/icon.png" 2>/dev/null
mkdir "$T/i.iconset"
for s in 16 32 128 256 512; do
  sips -z $s $s "$T/icon.png" --out "$T/i.iconset/icon_${s}x${s}.png" >/dev/null
  sips -z $((s*2)) $((s*2)) "$T/icon.png" --out "$T/i.iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$T/i.iconset" -o "$APP/Contents/Resources/AppIcon.icns"; rm -rf "$T"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>AI Access Auditor</string>
  <key>CFBundleDisplayName</key><string>AI Access Auditor</string>
  <key>CFBundleIdentifier</key><string>local.ai-access-auditor</string>
  <key>CFBundleExecutable</key><string>AIAccessAuditor</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSAppTransportSecurity</key><dict><key>NSAllowsLocalNetworking</key><true/></dict>
</dict></plist>
PLIST
codesign --force --deep -s - "$APP" 2>/dev/null || true
echo "Built: $APP"

# ./build-app.sh --install  → copy into /Applications and relaunch from there
if [[ "${1:-}" == "--install" ]]; then
  osascript -e 'quit app "AI Access Auditor"' 2>/dev/null || true
  sleep 1
  rm -rf "/Applications/AI Access Auditor.app"
  cp -R "$APP" /Applications/
  echo "Installed: /Applications/AI Access Auditor.app"
  open "/Applications/AI Access Auditor.app"
fi
