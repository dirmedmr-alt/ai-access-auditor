// After packaging: put a small launcher in front of the app binary.
// Chromium's sandbox needs either unprivileged user namespaces or a setuid-root helper (chrome-sandbox).
// Ubuntu 24.04 and later block the first for apps without an AppArmor profile, and an AppImage can't have
// the second, so on those systems the app would not start at all. The launcher checks, and only then
// starts the app without that sandbox. The app only shows its own local pages; links open in your browser.
'use strict';
const fs = require('fs');
const path = require('path');

const LAUNCHER = `#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
BIN="$HERE/ai-access-auditor.bin"
# run as Node.js (the Allow / Deny hooks agents call): no browser, no sandbox question
if [ -n "$ELECTRON_RUN_AS_NODE" ]; then exec "$BIN" "$@"; fi
if [ -u "$HERE/chrome-sandbox" ] && [ "$(stat -c %u "$HERE/chrome-sandbox" 2>/dev/null)" = 0 ]; then exec "$BIN" "$@"; fi
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
