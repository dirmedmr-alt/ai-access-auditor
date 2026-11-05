#!/usr/bin/env node
// Allow / Deny gate for AI Access Auditor. One script, two agents:
//  - Claude Code runs it as a PermissionRequest hook whenever it is about to ask you for permission.
//  - Gemini CLI runs it as a BeforeTool hook before every tool call.
// It forwards the request to the AI Access Auditor app, which pops up an Allow / Deny window, and returns
// your decision. If the app isn't running, the agent carries on exactly as it would without this hook.
'use strict';
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

let input = '';
process.stdin.on('data', d => { input += d; }).on('end', main).on('error', () => process.exit(0));

function main() {
  let req;
  try { req = JSON.parse(input); } catch { return process.exit(0); }
  if (req.hook_event_name === 'BeforeTool') return gemini(req);
  return claude(req);
}

function config() {
  try { return JSON.parse(fs.readFileSync(path.join(os.homedir(), '.ai-access-audit', 'gate.json'), 'utf8')); } catch { return null; }
}

// Ask the app. cb(answer) with answer = { behavior: 'allow' | 'deny' | 'ask', ... }, or null if the app can't be reached.
function ask(cfg, payload, cb) {
  const body = JSON.stringify(payload);
  const r = http.request({
    host: '127.0.0.1', port: cfg.port, path: '/api/gate/ask', method: 'POST', timeout: 295000,
    headers: { 'content-type': 'application/json', 'x-gate-token': cfg.token, 'content-length': Buffer.byteLength(body) },
  }, res => {
    let d = '';
    res.on('data', c => { d += c; }).on('end', () => { try { cb(JSON.parse(d)); } catch { cb(null); } });
  });
  r.on('error', () => cb(null));
  r.on('timeout', () => { r.destroy(); cb(null); });
  r.end(body);
}

// ---------- Claude Code ----------
// No output = Claude Code asks you the usual way.
function claude(req) {
  const cfg = config();
  if (!cfg) return process.exit(0);
  ask(cfg, {
    agent: 'Claude Code', tool: req.tool_name, input: req.tool_input, cwd: req.cwd,
    session: req.session_id, suggestions: req.permission_suggestions,
  }, j => {
    if (j && (j.behavior === 'allow' || j.behavior === 'deny')) {
      const decision = j.behavior === 'allow'
        ? { behavior: 'allow', ...(Array.isArray(j.updatedPermissions) ? { updatedPermissions: j.updatedPermissions } : {}) }
        : { behavior: 'deny', message: j.message || 'Denied in AI Access Auditor.' };
      process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PermissionRequest', decision } }));
    }
    process.exit(0);
  });
}

// ---------- Gemini CLI ----------
// Gemini always prints valid JSON back: "{}" lets Gemini carry on with its own rules (and its own prompt).
const GEMINI_EDIT = /^(write_file|replace)$/;
const GEMINI_RISKY = /^(run_shell_command|write_file|replace|web_fetch)$|^mcp_/;
const reply = obj => { process.stdout.write(JSON.stringify(obj)); process.exit(0); };

// How was this Gemini session started? Its own prompt only appears in "default" mode.
function geminiMode() {
  let mode = null;
  try {
    let pid = process.ppid;
    for (let n = 0; n < 8 && pid > 1; n++) {
      const [ppid, ...cmd] = execFileSync('ps', ['-o', 'ppid=,command=', '-p', String(pid)], { encoding: 'utf8', timeout: 2000 }).trim().split(/\s+/);
      const c = cmd.join(' ');
      if (/(^|\/)gemini(\.js)?(\s|$)|@google\/gemini-cli/.test(c)) {
        if (/(^|\s)(--yolo|-y)(\s|$)|--approval-mode[ =]yolo\b/.test(c)) mode = 'yolo';
        else if (/--approval-mode[ =]auto_edit\b/.test(c)) mode = 'auto_edit';
        else if (/--approval-mode[ =](default|plan)\b/.test(c)) mode = 'default';
        break;
      }
      pid = Number(ppid);
    }
  } catch {}
  if (mode) return mode;
  for (const f of [path.join(process.env.GEMINI_PROJECT_DIR || process.cwd(), '.gemini', 'settings.json'), path.join(os.homedir(), '.gemini', 'settings.json')]) {
    try {
      const j = JSON.parse(fs.readFileSync(f, 'utf8'));
      const m = (j.general && j.general.defaultApprovalMode) || (j.tools && j.tools.approvalMode);
      if (m) return m;
    } catch {}
  }
  return 'default';
}

function gemini(req) {
  const tool = String(req.tool_name || '');
  if (!GEMINI_RISKY.test(tool)) return reply({});
  const mode = geminiMode();
  // Gemini will ask you itself, so don't ask twice
  const geminiAsks = mode === 'default' || mode === 'plan' || (mode === 'auto_edit' && !GEMINI_EDIT.test(tool));
  if (geminiAsks) return reply({});
  const cfg = config();
  if (!cfg) return reply({});
  ask(cfg, { agent: 'Gemini CLI', tool, input: req.tool_input, cwd: req.cwd, session: req.session_id, mode }, j => {
    if (j && j.behavior === 'allow') return reply({ decision: 'allow' });
    if (j && j.behavior === 'deny') return reply({ decision: 'deny', reason: j.message || 'Denied in AI Access Auditor.' });
    // nobody answered in time: Gemini wouldn't ask on its own in this mode, so play safe
    if (j && j.behavior === 'ask') return reply({ decision: 'deny', reason: 'No answer in AI Access Auditor, so this was not run. Ask the user to try again.' });
    return reply({}); // app not reachable: carry on as if this hook weren't installed
  });
}
