#!/bin/bash
# Makes "Claude Code" ask to run a risky command, as the real hook would. The Allow / Deny popup appears
# right away; this script waits for your answer and prints it.
set -euo pipefail
cd "$(dirname "$0")/.."
D="$PWD/dist/demo-home"
echo '{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"rm -rf build && npm run deploy -- --env production --force","description":"Deploy to production"},"cwd":"/Users/demo/projects/webapp","session_id":"demo"}' \
  | HOME="$D" node gate.js
echo
