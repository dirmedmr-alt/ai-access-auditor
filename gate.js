#!/usr/bin/env node
// Claude Code PermissionRequest hook for AI Access Auditor.
// Claude Code runs this whenever it is about to ask you for permission. It forwards the request to the
// AI Access Auditor app, which pops up an Allow / Deny window, and returns your decision to Claude Code.
// If the app isn't running or doesn't answer, it prints nothing, so Claude Code shows its normal prompt.
'use strict';
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const fallback = () => process.exit(0); // no output = Claude Code asks you the usual way

let input = '';
process.stdin.on('data', d => { input += d; }).on('end', main).on('error', fallback);

function main() {
  let req, cfg;
  try { req = JSON.parse(input); } catch { return fallback(); }
  try { cfg = JSON.parse(fs.readFileSync(path.join(os.homedir(), '.ai-access-audit', 'gate.json'), 'utf8')); } catch { return fallback(); }

  const body = JSON.stringify({
    agent: 'Claude Code', tool: req.tool_name, input: req.tool_input, cwd: req.cwd,
    session: req.session_id, suggestions: req.permission_suggestions,
  });
  const r = http.request({
    host: '127.0.0.1', port: cfg.port, path: '/api/gate/ask', method: 'POST', timeout: 295000,
    headers: { 'content-type': 'application/json', 'x-gate-token': cfg.token, 'content-length': Buffer.byteLength(body) },
  }, res => {
    let d = '';
    res.on('data', c => { d += c; }).on('end', () => {
      try {
        const j = JSON.parse(d);
        if (j.behavior === 'allow' || j.behavior === 'deny') {
          const decision = j.behavior === 'allow'
            ? { behavior: 'allow', ...(Array.isArray(j.updatedPermissions) ? { updatedPermissions: j.updatedPermissions } : {}) }
            : { behavior: 'deny', message: j.message || 'Denied in AI Access Auditor.' };
          process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PermissionRequest', decision } }));
        }
      } catch { /* fall through to the normal prompt */ }
      process.exit(0);
    });
  });
  r.on('error', fallback);
  r.on('timeout', () => { r.destroy(); fallback(); });
  r.end(body);
}
