// After packaging: put a small launcher in front of the app binary.
// Chromium's sandbox needs unprivileged user namespaces, or else its setuid helper (chrome-sandbox), and
// that helper can't start the app from a folder with spaces in its name ("/opt/AI Access Auditor"). Ubuntu
// 24.04 and later block user namespaces for apps without an AppArmor profile, and an AppImage can't have the
// helper, so the app would often not start at all. The launcher checks, and only when namespaces are blocked
// starts the app without that sandbox. The app only shows its own local pages; links open in your browser.
'use strict';
const fs = require('fs');
const path = require('path');

const LAUNCHER = `#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
BIN="$HERE/ai-access-auditor.bin"
# run as Node.js (the Allow / Deny hooks agents call): no browser, no sandbox question
if [ -n "$ELECTRON_RUN_AS_NODE" ]; then exec "$BIN" "$@"; fi
if unshare -Ur true 2>/dev/null; then exec "$BIN" "$@"; fi
exec "$BIN" --no-sandbox "$@"
`;

exports.default = async function afterPack(ctx) {
  if (ctx.electronPlatformName !== 'linux') return;
  const dir = ctx.appOutDir;
  const exe = path.join(dir, 'ai-access-auditor');
  fs.renameSync(exe, exe + '.bin');
  fs.writeFileSync(exe, LAUNCHER, { mode: 0o755 });
};
