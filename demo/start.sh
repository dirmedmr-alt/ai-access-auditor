#!/bin/bash
# Opens the real Mac app on the invented home folder from demo/setup.sh, in demo mode: it reads only that
# folder (no Keychain, running programs or system permissions), so nothing personal can appear.
# Quit your normal AI Access Auditor first (shield in the menu bar → Quit), so only one shield shows.
set -euo pipefail
cd "$(dirname "$0")/.."
D="$PWD/dist/demo-home"
[ -d "$D" ] || { echo "Run ./demo/setup.sh first."; exit 1; }
APP="$PWD/dist/release/AI Access Auditor.app"
[ -d "$APP" ] || APP="/Applications/AI Access Auditor.app"
if pgrep -f "AI Access Auditor.app/Contents/MacOS" >/dev/null; then
  echo "AI Access Auditor is already running. Quit it from the shield in the menu bar, then run this again."; exit 1
fi
echo "Starting the demo app from: $APP"
HOME="$D" AUDIT_DATA_DIR="$D/.ai-access-audit" AUDIT_DEMO=1 nohup "$APP/Contents/MacOS/AIAccessAuditor" >/dev/null 2>&1 &
echo "When you're done: quit it from its shield, then open your normal app again."
