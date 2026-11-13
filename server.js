#!/usr/bin/env node
// AI Access Auditor — local-only app that inventories access granted to AI agents
// and lets you revoke it (with automatic backups). Zero dependencies.
'use strict';
const http = require('http');
const fs = require('fs');
const path = process.platform === 'win32' ? require('path').win32 : require('path'); // the same on a real system; lets tests run the Windows code elsewhere
const os = require('os');
const crypto = require('crypto');
const { execFileSync, execFile } = require('child_process');

const HOME = os.homedir();
const MAC = process.platform === 'darwin', LINUX = process.platform === 'linux', WIN = process.platform === 'win32';
const OS_NAME = MAC ? 'mac' : LINUX ? 'linux' : WIN ? 'windows' : process.platform;
// where desktop apps keep their settings: ~/Library/Application Support on a Mac, ~/.config on Linux,
// %APPDATA% (AppData\Roaming) on Windows; LOCAL_APPDATA is where Windows apps install themselves and keep caches
const appData = (...p) => MAC ? path.join(HOME, 'Library', 'Application Support', ...p)
  : WIN ? path.join(process.env.APPDATA || path.join(HOME, 'AppData', 'Roaming'), ...p)
  : path.join(process.env.XDG_CONFIG_HOME || path.join(HOME, '.config'), ...p);
const LOCAL_APPDATA = process.env.LOCALAPPDATA || path.join(HOME, 'AppData', 'Local');
const PORT = process.env.PORT ? Number(process.env.PORT) : 4517;
const DEMO = !!process.env.AUDIT_DEMO; // screenshots: only scan the (fake) home folder, nothing system-wide
const DATA_DIR = process.env.AUDIT_DATA_DIR || path.join(HOME, '.ai-access-audit'); // override for tests
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const REVIEW_FILE = path.join(DATA_DIR, 'reviews.json');
const LOG_FILE = path.join(DATA_DIR, 'actions.log');
const KNOWN_FILE = path.join(DATA_DIR, 'known.json');       // grants you've already seen
const NOTIFIED_FILE = path.join(DATA_DIR, 'notified.json'); // grants we've already sent a notification for
const EXPIRY_FILE = path.join(DATA_DIR, 'expiries.json');   // grants scheduled to be revoked automatically
const AI_NAME_RE = /claude|anthropic|openai|chatgpt|codex|cursor|codeium|windsurf|copilot|gemini|perplexity|ollama|lm ?studio|aider|cline|continue|tabnine|cody|sourcegraph|supermaven|mistral|groq|deepseek|huggingface/i;
const OWN_LAUNCH_AGENT = 'local.ai-access-auditor';
const GATE_TOKEN = crypto.randomBytes(16).toString('hex');   // only lets the Claude Code hook ask questions
const GATE_INFO = path.join(DATA_DIR, 'gate.json');          // where the hook finds us
const GATE_SCRIPT = path.join(DATA_DIR, 'gate.js');          // stable copy of the hook script
const GATE_MARK = 'ai-access-audit/gate.js';
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');   // { scope: 'ai' | 'all' }
const getScope = () => ((readJson(SETTINGS_FILE) || {}).scope === 'all' ? 'all' : 'ai');
const UPLOADS_FILE = path.join(DATA_DIR, 'uploads.json');     // apps caught sending data out, and apps you trust to
const DECISIONS_FILE = path.join(DATA_DIR, 'decisions.json'); // every Allow / Deny you gave in the popup
function sh(cmd, args, timeout = 10000) {
  try { return execFileSync(cmd, args, { encoding: 'utf8', timeout, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true }); }
  catch { return ''; }
}
// Windows: run a PowerShell script and return its output (UTF-8, so non-English names survive)
function psh(script, timeout = 20000) {
  return sh('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', `[Console]::OutputEncoding=[Text.Encoding]::UTF8; ${script}`], timeout);
}
const TOKEN = crypto.randomBytes(16).toString('hex');
fs.mkdirSync(BACKUP_DIR, { recursive: true });

const h = (...p) => path.join(HOME, ...p);
const SECRET_RE = /(key|token|secret|password|passwd|auth|bearer|credential|pat)/i;

// ---------- helpers ----------
function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}
function exists(f) { try { fs.accessSync(f); return true; } catch { return false; } }
function id(...parts) { return crypto.createHash('sha1').update(JSON.stringify(parts)).digest('hex').slice(0, 16); }
function mask(v) {
  if (typeof v !== 'string') return v;
  return v.length <= 6 ? '••••' : v.slice(0, 3) + '••••' + v.slice(-2);
}
function maskEnv(env) {
  const out = {};
  for (const [k, v] of Object.entries(env || {})) out[k] = SECRET_RE.test(k) ? mask(String(v)) : v;
  return out;
}
function maskArgs(args) {
  return (args || []).map(a => (typeof a === 'string' && /^(sk-|ghp_|gho_|xox[bp]-|AIza|ya29\.)/.test(a)) ? mask(a) : a);
}
function getAt(obj, p) { return p.reduce((o, k) => (o == null ? undefined : o[k]), obj); }

// ---------- risk scoring ----------
function ruleRisk(rule) {
  const r = String(rule);
  if (/^(Bash|Shell)(\(\*?\)|\(\s*\*\s*\))?$/.test(r) || r === '*' || /\(\*\)$/.test(r) && /Bash/.test(r)) return 'high';
  if (/Bash\((rm|sudo|curl|wget|ssh|scp|git push|npm publish|docker|kubectl|aws|gcloud)/.test(r)) return 'high';
  if (/^(Write|Edit|WebFetch)(\(\*?\))?$/.test(r) || /^mcp__[^_]+$/.test(r)) return 'medium';
  if (/Bash\(/.test(r)) return 'medium';
  return 'low';
}
const RISKY_TOOL_RE = /filesystem|shell|exec|terminal|computer|browser|puppeteer|playwright|github|gmail|slack|postgres|mysql|aws|stripe|reverse.?engineer|frida|lldb|gdb|debugger|inject|ghidra|hopper|radare|decompil|exploit|keychain|osascript|applescript|desktop-commander|kubectl|docker/;
function mcpRisk(cfg) {
  const pkg = execPackage([cfg.command, ...(cfg.args || [])].filter(Boolean).join(' '));
  const info = pkg ? pkgInfo(pkg.name) : null;
  const s = (JSON.stringify(cfg || {}) + (info ? ' ' + info.text : '')).toLowerCase();
  if (RISKY_TOOL_RE.test(s)) return 'high';
  if (Object.keys(cfg.env || {}).some(k => SECRET_RE.test(k)) || cfg.headers) return 'high';
  return 'medium';
}

// "npx foo", "npm exec foo", "uvx foo", "pipx run foo" → { name: 'foo', rest: [...] }
function execPackage(cmd) {
  const t = String(cmd || '').trim().split(/\s+/);
  let i = t.findIndex(x => /(?:^|\/)(npx|bunx|pnpx|uvx)$/.test(x)), skip = 1;
  if (i < 0) { i = t.findIndex((x, k) => /(?:^|\/)(npm|pnpm|yarn|bun)$/.test(x) && /^(exec|dlx|x)$/.test(t[k + 1] || '')); skip = 2; }
  if (i < 0) { i = t.findIndex((x, k) => /(?:^|\/)pipx$/.test(x) && t[k + 1] === 'run'); skip = 2; }
  // global installs: npm install -g X, pnpm add -g X, bun add -g X, yarn global add X, brew install X, pipx install X, uv tool install X
  if (i < 0) {
    i = t.findIndex((x, k) => (/(?:^|\/)(npm|pnpm|bun)$/.test(x) && /^(install|i|add)$/.test(t[k + 1] || '') && t.slice(k + 2).some(a => a === '-g' || a === '--global'))
      || (/(?:^|\/)brew$/.test(x) && /^(install|reinstall)$/.test(t[k + 1] || ''))
      || (/(?:^|\/)pipx$/.test(x) && t[k + 1] === 'install'));
    skip = 2;
    if (i < 0) { i = t.findIndex((x, k) => (/(?:^|\/)yarn$/.test(x) && t[k + 1] === 'global' && t[k + 2] === 'add') || (/(?:^|\/)uv$/.test(x) && t[k + 1] === 'tool' && t[k + 2] === 'install')); skip = 3; }
    if (i >= 0) { const r = execPackageAfter(t, i + skip); return r && { ...r, rest: ['install', ...r.rest] }; }
  }
  if (i < 0) return null;
  return execPackageAfter(t, i + skip);
}
function execPackageAfter(t, from) {
  for (let k = from; k < t.length; k++) {
    const a = t[k];
    let pkg = null, rest = t.slice(k + 1);
    if (a === '-p' || a === '--package' || a === '--from') { pkg = t[k + 1]; rest = t.slice(k + 2); }
    else if (/^--(package|from)=/.test(a)) pkg = a.split('=')[1];
    else if (a.startsWith('-')) continue;
    else pkg = a;
    if (!pkg) return null;
    return { name: pkg.replace(/(.)@[^/]*$/, '$1'), rest };
  }
  return null;
}
// What an npx-installed package says about itself (from the local npx cache; nothing is downloaded)
const pkgCache = new Map();
function pkgInfo(name) {
  const hit = pkgCache.get(name);
  if (hit && Date.now() - hit.at < 60e3) return hit.info;
  let info = null, newest = 0;
  const root = h('.npm', '_npx');
  let dirs = [];
  try { dirs = fs.readdirSync(root); } catch {}
  for (const d of dirs) {
    const f = path.join(root, d, 'node_modules', ...name.split('/'), 'package.json');
    let st; try { st = fs.statSync(f); } catch { continue; }
    if (st.mtimeMs < newest) continue;
    const j = readJson(f);
    if (!j) continue;
    newest = st.mtimeMs;
    const kw = (j.keywords || []).map(String);
    info = { description: String(j.description || ''), keywords: kw, mcp: !!j.mcpName || kw.some(k => /^(mcp|mcp-server|model-context-protocol)$/i.test(k)),
      text: `${j.description || ''} ${kw.join(' ')}` };
  }
  pkgCache.set(name, { at: Date.now(), info });
  return info;
}

// ---------- scanners ----------
// Each finding: { id, agent, category, title, detail, risk, source, action }
// action kinds: removeArrayItem | deleteKey | setFalse | tccReset | link | none

function claudeSettingsFindings(file, scopeLabel, agent = 'Claude Code') {
  const out = [];
  const j = readJson(file);
  if (!j) return out;
  const perms = j.permissions || {};
  for (const list of ['allow', 'ask', 'deny']) {
    (perms[list] || []).forEach(rule => {
      if (list === 'deny') return; // deny rules restrict access; not a grant
      out.push({
        agent, category: 'Tool permission', title: rule,
        detail: `${list === 'allow' ? 'Auto-allowed' : 'Ask-first'} rule (${scopeLabel})`,
        risk: list === 'allow' ? ruleRisk(rule) : 'low', source: file,
        action: { kind: 'removeArrayItem', file, path: ['permissions', list], value: rule },
      });
    });
  }
  (perms.additionalDirectories || []).forEach(dir => out.push({
    agent, category: 'Folder access', title: dir, detail: `Extra directory the agent may read/write (${scopeLabel})`,
    risk: dir === '/' || dir === HOME || dir === '~' ? 'high' : 'medium', source: file,
    action: { kind: 'removeArrayItem', file, path: ['permissions', 'additionalDirectories'], value: dir },
  }));
  if (perms.defaultMode && perms.defaultMode !== 'default') out.push({
    agent, category: 'Permission mode', title: `defaultMode: ${perms.defaultMode}`,
    detail: `Agent starts in "${perms.defaultMode}" mode (${scopeLabel})`,
    risk: /bypass/i.test(perms.defaultMode) ? 'high' : 'medium', source: file,
    action: { kind: 'deleteKey', file, path: ['permissions'], key: 'defaultMode', value: perms.defaultMode },
  });
  for (const [name, cfg] of Object.entries(j.mcpServers || {})) out.push(mcpFinding(agent, name, cfg, file, ['mcpServers'], scopeLabel));
  if (j.enableAllProjectMcpServers) out.push({
    agent, category: 'MCP server', title: 'enableAllProjectMcpServers', detail: `Auto-approves every MCP server in project .mcp.json files (${scopeLabel})`,
    risk: 'high', source: file, action: { kind: 'setFalse', file, path: [], key: 'enableAllProjectMcpServers' },
  });
  const otherHooks = Object.entries(j.hooks || {}).filter(([, list]) => (list || []).some(e => !isOurHook(e))).map(([k]) => k);
  if (otherHooks.length) out.push({
    agent, category: 'Hooks', title: `Hooks: ${otherHooks.join(', ')}`, detail: `Shell commands run automatically on agent events (${scopeLabel})`,
    risk: 'medium', source: file, action: { kind: 'none', hint: 'Review the "hooks" section in this file manually.' },
  });
  return out;
}

function pkgDesc(cfg) {
  const pkg = cfg.command ? execPackage([cfg.command, ...(cfg.args || [])].join(' ')) : null;
  const info = pkg && pkgInfo(pkg.name);
  return info && info.description ? `"${info.description.slice(0, 140)}" · ` : '';
}
function mcpFinding(agent, name, cfg, file, parentPath, scopeLabel) {
  const cmd = cfg.url ? cfg.url : [cfg.command, ...maskArgs(cfg.args)].filter(Boolean).join(' ');
  const env = maskEnv(cfg.env);
  const envKeys = Object.keys(env);
  return {
    agent, category: 'MCP server', title: name,
    detail: `${pkgDesc(cfg)}${cmd}${envKeys.length ? `  · env: ${envKeys.map(k => `${k}=${env[k]}`).join(', ')}` : ''}${scopeLabel ? `  (${scopeLabel})` : ''}`,
    risk: mcpRisk(cfg), source: file,
    action: { kind: 'deleteKey', file, path: parentPath, key: name, value: cfg },
  };
}

function scanClaudeCode() {
  const out = [];
  out.push(...claudeSettingsFindings(h('.claude', 'settings.json'), 'user'));
  out.push(...claudeSettingsFindings(h('.claude', 'settings.local.json'), 'user local'));
  for (const f of MAC ? ['/Library/Application Support/ClaudeCode/managed-settings.json'] : WIN ? ['C:\\Program Files\\ClaudeCode\\managed-settings.json', 'C:\\ProgramData\\ClaudeCode\\managed-settings.json'] : ['/etc/claude-code/managed-settings.json'])
    claudeSettingsFindings(f, 'managed').forEach(x => { x.action = { kind: 'none', hint: 'Managed by your organization.' }; out.push(x); });

  const cj = h('.claude.json');
  const j = readJson(cj);
  if (!j) return out;
  for (const [name, cfg] of Object.entries(j.mcpServers || {})) out.push(mcpFinding('Claude Code', name, cfg, cj, ['mcpServers'], 'user'));
  for (const [proj, p] of Object.entries(j.projects || {})) {
    const label = proj.replace(HOME, '~');
    if (p.hasTrustDialogAccepted) out.push({
      agent: 'Claude Code', category: 'Trusted folder', title: label,
      detail: 'You accepted the trust dialog: agent may run in this folder', risk: proj === HOME || proj === '/' ? 'high' : 'low', source: cj,
      action: { kind: 'setFalse', file: cj, path: ['projects', proj], key: 'hasTrustDialogAccepted' },
    });
    (p.allowedTools || []).forEach(t => out.push({
      agent: 'Claude Code', category: 'Tool permission', title: t, detail: `Allowed tool (legacy, project ${label})`,
      risk: ruleRisk(t), source: cj, action: { kind: 'removeArrayItem', file: cj, path: ['projects', proj, 'allowedTools'], value: t },
    }));
    (p.enabledMcpjsonServers || []).forEach(s => out.push({
      agent: 'Claude Code', category: 'MCP server', title: s, detail: `Approved .mcp.json server (project ${label})`,
      risk: 'medium', source: cj, action: { kind: 'removeArrayItem', file: cj, path: ['projects', proj, 'enabledMcpjsonServers'], value: s },
    }));
    for (const [name, cfg] of Object.entries(p.mcpServers || {})) out.push(mcpFinding('Claude Code', name, cfg, cj, ['projects', proj, 'mcpServers'], `project ${label}`));
    if (exists(proj)) {
      out.push(...claudeSettingsFindings(path.join(proj, '.claude', 'settings.json'), `project ${label}, shared`));
      out.push(...claudeSettingsFindings(path.join(proj, '.claude', 'settings.local.json'), `project ${label}`));
      const mcpj = path.join(proj, '.mcp.json');
      for (const [name, cfg] of Object.entries((readJson(mcpj) || {}).mcpServers || {}))
        out.push(mcpFinding('Claude Code', name, cfg, mcpj, ['mcpServers'], `project ${label}`));
    }
  }
  return out;
}

function scanClaudeDesktop() {
  const out = [];
  const f = appData('Claude', 'claude_desktop_config.json');
  const j = readJson(f);
  if (!j) return out;
  const A = 'Claude Desktop';
  for (const [name, cfg] of Object.entries(j.mcpServers || {})) out.push(mcpFinding(A, name, cfg, f, ['mcpServers'], ''));
  const p = j.preferences || {};
  (p.localAgentModeTrustedFolders || []).forEach(dir => out.push({
    agent: A, category: 'Folder access', title: dir.replace(HOME, '~'), detail: 'Trusted folder for local agent mode',
    risk: dir === HOME || dir === '/' ? 'high' : 'medium', source: f,
    action: { kind: 'removeArrayItem', file: f, path: ['preferences', 'localAgentModeTrustedFolders'], value: dir },
  }));
  for (const [sess, dirs] of Object.entries(p.remoteSessionFolderGrants || {})) (dirs || []).forEach(dir => out.push({
    agent: A, category: 'Folder access', title: dir.replace(HOME, '~'), detail: `Folder granted to remote session ${sess.slice(0, 20)}…`,
    risk: 'medium', source: f, action: { kind: 'removeArrayItem', file: f, path: ['preferences', 'remoteSessionFolderGrants', sess], value: dir },
  }));
  for (const [acct, on] of Object.entries(p.bypassPermissionsGateByAccount || {})) if (on) out.push({
    agent: A, category: 'Permission mode', title: 'Bypass permissions enabled', detail: `For account ${acct.slice(0, 8)}…: agent can skip approval prompts`,
    risk: 'high', source: f, action: { kind: 'setFalse', file: f, path: ['preferences', 'bypassPermissionsGateByAccount'], key: acct },
  });
  const toggles = {
    coworkBrowserToolsEnabled: ['Browser control', 'high'],
    coworkScheduledTasksEnabled: ['Scheduled tasks (runs without you)', 'medium'],
    ccdScheduledTasksEnabled: ['Claude Code scheduled tasks', 'medium'],
    coworkWebSearchEnabled: ['Web search', 'low'],
  };
  for (const [k, [label, risk]] of Object.entries(toggles)) if (p[k] === true) out.push({
    agent: A, category: 'Capability', title: label, detail: `preferences.${k} = true`, risk, source: f,
    action: { kind: 'setFalse', file: f, path: ['preferences'], key: k },
  });
  return out;
}

function scanOtherMcp() {
  const out = [];
  const targets = [
    ['Cursor', h('.cursor', 'mcp.json'), ['mcpServers']],
    ['Windsurf', h('.codeium', 'windsurf', 'mcp_config.json'), ['mcpServers']],
    ['VS Code', appData('Code', 'User', 'mcp.json'), ['servers']],
    ['VS Code', appData('Code', 'User', 'settings.json'), ['mcp', 'servers']],
    ['Gemini CLI', h('.gemini', 'settings.json'), ['mcpServers']],
    ['Zed', h('.config', 'zed', 'settings.json'), ['context_servers']],
    ['Cline', appData('Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'), ['mcpServers']],
    ['Roo Code', appData('Code', 'User', 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json'), ['mcpServers']],
    ['Cursor', appData('Cursor', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'), ['mcpServers']],
    ['Cline', h('.cline', 'data', 'settings', 'cline_mcp_settings.json'), ['mcpServers']],
  ];
  for (const [agent, f, p] of targets) {
    const servers = getAt(readJson(f), p) || {};
    for (const [name, cfg] of Object.entries(servers)) {
      out.push(mcpFinding(agent, name, cfg || {}, f, p, ''));
      // tools of this server that run without asking
      for (const key of ['alwaysAllow', 'autoApprove']) if (Array.isArray(cfg && cfg[key])) for (const t of cfg[key])
        out.push({ agent, category: 'Tool permission', title: `${name}: ${t}`, detail: `MCP tool that runs without asking (${key})`,
          risk: RISKY_TOOL_RE.test(String(t)) ? 'high' : 'medium', source: f, action: { kind: 'removeArrayItem', file: f, path: [...p, name, key], value: t } });
    }
  }
  // Codex CLI (~/.codex/config.toml). Each item is removed by cutting its exact lines/section out of the file.
  const codex = h('.codex', 'config.toml');
  if (exists(codex)) {
    const t = fs.readFileSync(codex, 'utf8');
    const top = t.split(/^\[/m)[0]; // keys before the first [section] apply to every session
    const cut = text => ({ kind: 'removeTomlBlock', file: codex, block: text });
    const section = header => { const k = t.indexOf(header); if (k < 0) return null; const rest = t.slice(k + header.length); const e = rest.search(/^\[/m); return header + (e < 0 ? rest : rest.slice(0, e)); };
    for (const m of t.matchAll(/^\[mcp_servers\.("?)([^\]"]+)\1\]\s*$/gm)) {
      const sec = section(m[0]);
      const cmd = (sec.match(/^\s*command\s*=\s*"([^"]*)"/m) || [])[1] || (sec.match(/^\s*url\s*=\s*"([^"]*)"/m) || [])[1] || '';
      const args = ((sec.match(/^\s*args\s*=\s*\[(.*)\]/m) || [])[1] || '').replace(/"/g, '');
      out.push({ agent: 'Codex CLI', category: 'MCP server', title: m[2], detail: `${cmd} ${args}`.trim() || 'Defined in config.toml',
        risk: mcpRisk({ command: cmd, args: args.split(',').map(x => x.trim()).filter(Boolean) }), source: codex, action: cut(sec) });
    }
    const line = re => { const m = top.match(re); return m ? { value: m[1], text: m[0] + '\n' } : null; };
    const sb = line(/^sandbox_mode\s*=\s*"([^"]+)"[^\n]*/m);
    if (sb && sb.value === 'danger-full-access') out.push({ agent: 'Codex CLI', category: 'Permission mode', title: 'sandbox_mode = danger-full-access',
      detail: 'No sandbox: full access to your disk and network', risk: 'high', source: codex, action: cut(sb.text) });
    const ap = line(/^approval_policy\s*=\s*"([^"]+)"[^\n]*/m);
    if (ap && (ap.value === 'never' || ap.value === 'on-failure')) out.push({ agent: 'Codex CLI', category: 'Permission mode', title: `approval_policy = ${ap.value}`,
      detail: ap.value === 'never' ? 'Runs commands without ever asking' : 'Only asks after a command fails', risk: ap.value === 'never' ? 'high' : 'medium', source: codex, action: cut(ap.text) });
    for (const m of t.matchAll(/^\[projects\."([^"]+)"\]\s*$/gm)) {
      const sec = section(m[0]);
      if (!/^\s*trust_level\s*=\s*"trusted"/m.test(sec)) continue;
      out.push({ agent: 'Codex CLI', category: 'Trusted folder', title: m[1].replace(HOME, '~'), detail: 'Trusted project: Codex works here with fewer prompts',
        risk: m[1] === HOME || m[1] === '/' ? 'high' : 'low', source: codex, action: cut(sec) });
    }
  }
  const ch = readJson(h('.codex', 'hooks.json')) || {};
  const cHooks = Object.entries(ch.hooks || {}).filter(([, list]) => (list || []).some(e => !isOurHook(e))).map(([k]) => k);
  if (cHooks.length) out.push({ agent: 'Codex CLI', category: 'Hooks', title: `Hooks: ${cHooks.join(', ')}`, detail: 'Shell commands Codex runs automatically on its events',
    risk: 'medium', source: h('.codex', 'hooks.json'), action: { kind: 'none', hint: 'Review ~/.codex/hooks.json, or type /hooks inside Codex.' } });
  // Codex sign-ins: ~/.codex/auth.json (default, plain text) or the Keychain item "Codex Auth" (found by scanKeychain)
  const ca = h('.codex', 'auth.json');
  if (exists(ca)) {
    const j = readJson(ca) || {};
    const how = j.OPENAI_API_KEY ? 'an OpenAI API key' : j.tokens ? 'your ChatGPT login' : 'your OpenAI login';
    out.push({ agent: 'Codex CLI', category: 'Saved login', title: 'OpenAI sign-in (auth.json)',
      detail: `Codex keeps ${how} here as plain text: any program you run can read it and use your OpenAI access. Setting cli_auth_credentials_store = "keyring" in config.toml moves it to ${MAC ? 'the Keychain' : 'the system keyring'}.`,
      risk: 'high', source: ca, action: { kind: 'removeFile', file: ca } });
  }
  // Claude Code on Linux keeps its login in this file (on a Mac it uses the Keychain)
  const cc = h('.claude', '.credentials.json');
  if (exists(cc)) out.push({ agent: 'Claude Code', category: 'Saved login', title: 'Claude sign-in (.credentials.json)',
    detail: 'Claude Code keeps your Claude login here as plain text: any program you run can read it and use your Claude account',
    risk: 'high', source: cc, action: { kind: 'removeFile', file: cc } });
  const cm = h('.codex', '.credentials.json');
  if (exists(cm)) out.push({ agent: 'Codex CLI', category: 'Saved login', title: 'MCP server logins', detail: 'Logins Codex saved for MCP servers, as plain text',
    risk: 'medium', source: cm, action: { kind: 'removeFile', file: cm } });
  return out;
}

const TCC_SERVICES = {
  kTCCServiceAccessibility: ['Accessibility (control your computer)', 'high', 'Privacy_Accessibility'],
  kTCCServiceScreenCapture: ['Screen Recording', 'high', 'Privacy_ScreenCapture'],
  kTCCServiceSystemPolicyAllFiles: ['Full Disk Access', 'high', 'Privacy_AllFiles'],
  kTCCServiceAppleEvents: ['Automation (control other apps)', 'medium', 'Privacy_Automation'],
  kTCCServiceListenEvent: ['Input Monitoring', 'high', 'Privacy_ListenEvent'],
  kTCCServicePostEvent: ['Synthetic input', 'high', 'Privacy_Accessibility'],
  kTCCServiceMicrophone: ['Microphone', 'medium', 'Privacy_Microphone'],
  kTCCServiceCamera: ['Camera', 'medium', 'Privacy_Camera'],
  kTCCServiceSystemPolicyDocumentsFolder: ['Documents folder', 'medium', 'Privacy_FilesAndFolders'],
  kTCCServiceSystemPolicyDesktopFolder: ['Desktop folder', 'medium', 'Privacy_FilesAndFolders'],
  kTCCServiceSystemPolicyDownloadsFolder: ['Downloads folder', 'medium', 'Privacy_FilesAndFolders'],
  kTCCServiceSystemPolicyNetworkVolumes: ['Network drives', 'medium', 'Privacy_FilesAndFolders'],
  kTCCServiceSystemPolicyRemovableVolumes: ['Removable drives', 'medium', 'Privacy_FilesAndFolders'],
  kTCCServiceAddressBook: ['Contacts', 'medium', 'Privacy_Contacts'],
  kTCCServiceCalendar: ['Calendars', 'medium', 'Privacy_Calendars'],
  kTCCServiceReminders: ['Reminders', 'low', 'Privacy_Reminders'],
  kTCCServicePhotos: ['Photos', 'medium', 'Privacy_Photos'],
  kTCCServiceSystemPolicyAppBundles: ['App Management (change other apps)', 'high', 'Privacy_AppBundles'],
  kTCCServiceDeveloperTool: ['Developer Tools', 'medium', 'Privacy_DevTools'],
};
const AI_CLIENT_RE = /claude|anthropic|openai|chatgpt|cursor|codeium|windsurf|copilot|gemini|perplexity|ollama|lmstudio|raycast|vscode|VSCode|zed|warp|iterm|Terminal|ghostty|node$|python/i;

function scanTcc() {
  const out = [];
  const status = { readable: [], unreadable: [], supported: MAC };
  for (const db of DEMO || !MAC ? [] : [appData('com.apple.TCC', 'TCC.db'), '/Library/Application Support/com.apple.TCC/TCC.db']) {
    if (!exists(db)) { status.unreadable.push(db); continue; }
    let rows;
    try {
      rows = execFileSync('sqlite3', ['-separator', '\t', db, 'SELECT service, client, auth_value, last_modified FROM access WHERE auth_value >= 2;'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      status.readable.push(db);
    } catch { status.unreadable.push(db); continue; }
    for (const line of rows.trim().split('\n').filter(Boolean)) {
      const [service, client, , modified] = line.split('\t');
      const meta = TCC_SERVICES[service];
      if (!meta || (getScope() === 'ai' && !AI_CLIENT_RE.test(client))) continue;
      const isAgentHost = /Terminal|iterm|ghostty|warp|vscode|VSCode|node$|python/i.test(client);
      out.push({
        agent: client, category: 'macOS privacy', title: meta[0],
        detail: `${client}${isAgentHost ? ' (agents running inside this app inherit it)' : ''} · granted ${new Date(Number(modified) * 1000).toLocaleDateString()}`,
        risk: meta[1], source: db,
        action: client.includes('.') && !client.startsWith('/')
          ? { kind: 'tccReset', service: service.replace('kTCCService', ''), client, pane: meta[2] }
          : { kind: 'link', url: `x-apple.systempreferences:com.apple.preference.security?${meta[2]}`, hint: 'Remove in System Settings' },
      });
    }
  }
  return { findings: out, status };
}

const MANUAL_CHECKS = [
  { name: 'Claude.ai connectors & integrations', url: 'https://claude.ai/settings/connectors' },
  { name: 'ChatGPT connected apps', url: 'https://chatgpt.com/#settings/Connectors' },
  { name: 'GitHub: authorized OAuth apps', url: 'https://github.com/settings/applications' },
  { name: 'GitHub: installed GitHub Apps', url: 'https://github.com/settings/installations' },
  { name: 'GitHub: personal access tokens', url: 'https://github.com/settings/tokens' },
  { name: 'Google: third-party access', url: 'https://myaccount.google.com/connections' },
  { name: 'Microsoft: app permissions', url: 'https://account.live.com/consent/Manage' },
  { name: 'Slack: installed apps', url: 'https://slack.com/apps/manage' },
  { name: 'Notion: connections', url: 'https://www.notion.so/profile/integrations' },
  { name: 'Anthropic API keys', url: 'https://console.anthropic.com/settings/keys' },
  { name: 'OpenAI API keys', url: 'https://platform.openai.com/api-keys' },
  // whether your conversations are used to train AI models: only changeable on each service's website
  { name: 'Claude: use of your chats for training', url: 'https://claude.ai/settings/data-privacy-controls', privacy: true },
  { name: 'ChatGPT: improve the model for everyone', url: 'https://chatgpt.com/#settings/DataControls', privacy: true },
  { name: 'GitHub Copilot: data use for training', url: 'https://github.com/settings/copilot', privacy: true },
  { name: 'Cursor: Privacy Mode', url: 'https://cursor.com/dashboard?tab=settings', privacy: true },
  { name: 'Google Gemini: Gemini Apps Activity', url: 'https://myactivity.google.com/product/gemini', privacy: true },
];

function scanEnvKeys() {
  const out = [];
  if (WIN && !DEMO) {
    for (const line of sh('reg', ['query', 'HKCU\\Environment'], 5000).split(/\r?\n/)) {
      const m = line.match(/^\s{4}([A-Z0-9_]*(?:API_KEY|TOKEN|SECRET)[A-Z0-9_]*)\s{4}REG_/i);
      if (m) out.push({
        agent: 'Shell', category: 'Exposed secret', title: m[1], detail: 'Saved in your Windows user environment variables: every program you run, including every agent, can read it',
        risk: /ANTHROPIC|OPENAI|GITHUB|AWS|GH_/i.test(m[1]) ? 'medium' : 'low', source: 'HKCU\\Environment',
        action: { kind: 'none', hint: 'Remove it in Settings → System → About → Advanced system settings → Environment Variables, and keep it in a secrets manager instead.' },
      });
    }
  }
  const files = ['.zshrc', '.zprofile', '.bashrc', '.bash_profile', '.profile', '.config/fish/config.fish'].map(f => h(f))
    .concat(WIN ? ['PowerShell', 'WindowsPowerShell'].map(d => h('Documents', d, 'Microsoft.PowerShell_profile.ps1')) : []);
  for (const f of files) {
    if (!exists(f)) continue;
    const lines = fs.readFileSync(f, 'utf8').split('\n');
    lines.forEach((l, i) => {
      const m = l.match(/^\s*(?:export\s+|set\s+-gx\s+|\$env:)?([A-Z0-9_]*(?:API_KEY|TOKEN|SECRET)[A-Z0-9_]*)\s*[= ]/);
      if (m) out.push({
        agent: 'Shell', category: 'Exposed secret', title: m[1], detail: `${f.replace(HOME, '~')}:${i + 1}: every agent you run in a shell can read it`,
        risk: /ANTHROPIC|OPENAI|GITHUB|AWS|GH_/.test(m[1]) ? 'medium' : 'low', source: f,
        action: { kind: 'none', hint: 'Move it to a secrets manager or scope it to a single command.' },
      });
    });
  }
  return out;
}

// ---------- secrets in agents' session history ----------
// Agents keep a full log of every session on disk. Keys and passwords that were pasted, printed or read during a
// session stay there in plain text. Only masked previews are ever stored or shown; the secrets themselves stay put.
const SECRET_PATTERNS = [
  ['Anthropic API key', /sk-ant-[A-Za-z0-9_-]{20,}/g],
  ['OpenAI API key', /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/g],
  ['GitHub token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/g],
  ['AWS access key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{20,}/g],
  ['Stripe secret key', /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/g],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}\b/g],
  ['Hugging Face token', /\bhf_[A-Za-z0-9]{34,}\b/g],
  ['Private key', /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]{20,8000}?-----END (?:[A-Z]+ )?PRIVATE KEY-----/g],
];
const REDACTED = '[removed by AI Access Auditor]';
// Where each kind of key is cancelled. Removing a key from a log only cleans the file: the key keeps working
// until it is cancelled with the service that issued it.
const KEY_REVOKE = {
  'Anthropic API key': ['Anthropic', 'https://console.anthropic.com/settings/keys'],
  'OpenAI API key': ['OpenAI', 'https://platform.openai.com/api-keys'],
  'GitHub token': ['GitHub', 'https://github.com/settings/tokens'],
  'AWS access key': ['AWS', 'https://console.aws.amazon.com/iam/home#/security_credentials'],
  'Google API key': ['Google Cloud', 'https://console.cloud.google.com/apis/credentials'],
  'Slack token': ['Slack', 'https://api.slack.com/apps'],
  'Stripe secret key': ['Stripe', 'https://dashboard.stripe.com/apikeys'],
  'npm token': ['npm', 'https://docs.npmjs.com/revoking-access-tokens'],
  'Hugging Face token': ['Hugging Face', 'https://huggingface.co/settings/tokens'],
  'Private key': ['GitHub SSH keys', 'https://github.com/settings/keys'],
};
// documentation examples and placeholders aren't secrets ("AKIAIOSFODNN7EXAMPLE", "ghp_xxxxxxxx…")
const realSecret = m => !/EXAMPLE|example|xxxxxxxx|XXXXXXXX|your[_-]?(api[_-]?)?key|1234567890abcdef/i.test(m) && new Set(m.replace(/^[a-z]+[_-]/i, '')).size >= 10;
const HISTORY_ROOTS = [
  ['Claude Code', h('.claude', 'projects'), /\.jsonl$/, true],
  ['Codex CLI', h('.codex', 'sessions'), /\.jsonl$/, true],
  ['Codex CLI', h('.codex', 'archived_sessions'), /\.jsonl$/, true],
  ['Gemini CLI', h('.gemini', 'tmp'), /\.json$/, true],
  // OpenCode keeps its sessions in a database: reported, but removed by deleting the session in OpenCode
  ['OpenCode', h('.local', 'share', 'opencode'), /^opencode\.db(-wal)?$/, false],
];
const HISTORY_FILE = path.join(DATA_DIR, 'history-scan.json');
let historyCache = null;
function historyFiles() {
  const out = [];
  const walk = (dir, re, depth, agent, fixable) => {
    let ents = [];
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const f = path.join(dir, e.name);
      if (e.isDirectory() && depth > 0) walk(f, re, depth - 1, agent, fixable);
      else if (e.isFile() && re.test(e.name)) out.push({ file: f, agent, fixable });
    }
  };
  for (const [agent, root, re, fixable] of HISTORY_ROOTS) walk(root, re, re.source.includes('opencode') ? 0 : 4, agent, fixable);
  return out;
}
function scanTextForSecrets(text) {
  const hits = [];
  for (const [kind, re] of SECRET_PATTERNS) for (const m of text.matchAll(re)) if (realSecret(m[0]) && hits.length < 50) hits.push({ kind, preview: mask(m[0]) });
  return hits;
}
function secretsInRange(file, start, end) {
  const buf = Buffer.alloc(Math.min(end - start, 64 << 20));
  let fd;
  try { fd = fs.openSync(file, 'r'); const n = fs.readSync(fd, buf, 0, buf.length, start); return scanTextForSecrets(buf.toString('latin1', 0, n)); }
  catch { return []; } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function secretsInFile(file, size) {
  // big logs are read in pieces, overlapping so a key cut in two is still found
  if (size <= 64 << 20) { try { return scanTextForSecrets(fs.readFileSync(file, 'latin1')); } catch { return []; } }
  const hits = [], CH = 16 << 20, buf = Buffer.alloc(CH + 9000);
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    for (let pos = 0; pos < size && hits.length < 50; pos += CH) {
      const n = fs.readSync(fd, buf, 0, buf.length, pos);
      hits.push(...scanTextForSecrets(buf.toString('latin1', 0, n)));
    }
  } catch {} finally { if (fd !== undefined) fs.closeSync(fd); }
  const seen = new Set();
  return hits.filter(x => !seen.has(x.preview) && seen.add(x.preview));
}
// Checks new and changed logs, for at most budgetMs, and remembers the result, so a scan stays fast even with
// gigabytes of history: the first full pass finishes over the next few scans.
function refreshHistory(budgetMs) {
  if (!historyCache) historyCache = readJson(HISTORY_FILE) || {};
  const t0 = Date.now(), files = historyFiles(), present = new Set(files.map(x => x.file));
  let changed = false;
  for (const k of Object.keys(historyCache)) if (!present.has(k)) { delete historyCache[k]; changed = true; }
  for (const { file } of files) {
    if (Date.now() - t0 > budgetMs) break;
    let st;
    try { st = fs.statSync(file); } catch { continue; }
    const c = historyCache[file];
    if (c && c.mtime === st.mtimeMs && c.size === st.size) continue;
    if (st.size > 2 * 1024 ** 3) continue; // over 2 GB: skipped
    // a session that is still running only grows: read just what was added since last time
    let hits;
    if (c && st.size > c.size && !file.endsWith('.db') && !file.endsWith('.json')) {
      const added = secretsInRange(file, Math.max(0, c.size - 9000), st.size);
      const seen = new Set(c.hits.map(x => x.preview));
      hits = c.hits.concat(added.filter(x => !seen.has(x.preview) && seen.add(x.preview))).slice(0, 50);
    } else hits = secretsInFile(file, st.size);
    historyCache[file] = { mtime: st.mtimeMs, size: st.size, hits };
    changed = true;
  }
  if (changed) try { fs.writeFileSync(HISTORY_FILE, JSON.stringify(historyCache)); } catch {}
  return files;
}
function scanHistory() {
  const out = [];
  if (DEMO) return out;
  const files = refreshHistory(process.argv.includes('--scan') ? 1e9 : 400);
  for (const { file, agent, fixable } of files) {
    const c = historyCache[file];
    if (!c || !c.hits.length) continue;
    const kinds = [...new Set(c.hits.map(x => x.kind))];
    const n = c.hits.length;
    out.push({
      agent, category: 'Secret in history',
      title: `${n}${n >= 50 ? '+' : ''} secret${n === 1 ? '' : 's'} in ${fixable ? `a ${agent} session` : `${agent}'s session history`}`,
      detail: `${kinds.join(', ')}: ${c.hits.slice(0, 3).map(x => x.preview).join(', ')}${n > 3 ? ', …' : ''} · last used ${new Date(c.mtime).toLocaleDateString()} · ${file.replace(HOME, '~')}`,
      risk: 'high', source: file,
      keys: kinds.filter(k => KEY_REVOKE[k]).map(k => ({ kind: k, label: KEY_REVOKE[k][0], url: KEY_REVOKE[k][1] })),
      action: fixable ? { kind: 'redactSecrets', file }
        : { kind: 'none', hint: `Delete the sessions that contain these in ${agent}, and replace the keys with the services they belong to.` },
    });
  }
  return out;
}

// ---------- data sharing: usage data agents send to the company that makes them, and sessions they share ----------
function scanDataSharing() {
  const out = [];
  if (DEMO) return out;
  const add = (agent, title, detail, risk, source, action) => out.push({ agent, category: 'Data sharing', title, detail, risk, source, action });
  const turnOff = (file, at, values, strict = true) => strict ? { kind: 'setValues', file, path: at, values }
    : { kind: 'none', hint: `Edit ${file.replace(HOME, '~')} (it has comments, so it's safer to change by hand): set ${Object.entries(values).map(([k, v]) => `${k} to ${JSON.stringify(v)}`).join(', ')}.` };
  const isOn = v => v === undefined || v === null || v === '' || v === '0' || v === 0 || v === false || v === 'false';
  // Claude Code: usage statistics and error reports are on unless a setting (or the environment) switches them off
  const cs = h('.claude', 'settings.json');
  if (exists(h('.claude'))) {
    const j = exists(cs) ? readJson(cs) : {}, env = (j && j.env) || {};
    const offBy = k => !isOn(env[k]) || !isOn(process.env[k]);
    if (!offBy('DISABLE_TELEMETRY') && !offBy('CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC'))
      add('Claude Code', 'Usage statistics and error reports sent to Anthropic', 'Claude Code reports how you use it and its errors (not your code or conversations). On unless switched off.', 'low', cs,
        j ? turnOff(cs, ['env'], { DISABLE_TELEMETRY: '1', DISABLE_ERROR_REPORTING: '1' }) : { kind: 'none', hint: 'Fix ~/.claude/settings.json (it is not valid JSON), then add "env": {"DISABLE_TELEMETRY": "1"}.' });
  }
  // Gemini CLI: usage statistics (on unless switched off), and OpenTelemetry export if someone turned it on
  const gs = h('.gemini', 'settings.json');
  if (exists(h('.gemini'))) {
    const j = exists(gs) ? readJson(gs) : {};
    if (j && getAt(j, ['privacy', 'usageStatisticsEnabled']) !== false && j.usageStatisticsEnabled !== false)
      add('Gemini CLI', 'Usage statistics sent to Google', 'Gemini CLI reports how you use it to Google. On unless switched off.', 'low', gs, turnOff(gs, ['privacy'], { usageStatisticsEnabled: false }));
    const tel = j && j.telemetry;
    if (tel && tel.enabled === true)
      add('Gemini CLI', 'Telemetry export is on', `Gemini CLI sends detailed telemetry${tel.otlpEndpoint ? ` to ${tel.otlpEndpoint}` : tel.target ? ` (${tel.target})` : ''}${tel.logPrompts !== false ? ', including your prompts' : ''}`,
        tel.logPrompts !== false ? 'high' : 'medium', gs, turnOff(gs, ['telemetry'], { enabled: false }));
  }
  // OpenCode: "share": "auto" puts every session on a public link
  const occ = openCodeConfig();
  if (occ && occ.j.share === 'auto')
    add('OpenCode', 'Every session is shared publicly', 'OpenCode makes a public link for each new session, so anyone with the link can read the conversation and the code in it', 'high', occ.file,
      turnOff(occ.file, [], { share: 'manual' }, occ.strict));
  // Code editors with AI built in: usage data ("telemetry.telemetryLevel" is "all" unless changed)
  for (const [editor, f, to] of [['VS Code', appData('Code', 'User', 'settings.json'), 'Microsoft'], ['Cursor', appData('Cursor', 'User', 'settings.json'), 'Cursor'], ['Windsurf', appData('Windsurf', 'User', 'settings.json'), 'Windsurf']]) {
    if (!exists(path.dirname(f))) continue;
    const r = exists(f) ? readJsonc(f) : { j: {}, strict: true };
    if (!r) continue;
    const level = r.j['telemetry.telemetryLevel'];
    if (level !== 'off') add(editor, `Usage data sent to ${to}`, `telemetry.telemetryLevel is "${level || 'all'}"${level ? '' : ' (the default)'}: ${editor} reports usage and errors`, 'low', f,
      turnOff(f, [], { 'telemetry.telemetryLevel': 'off' }, r.strict));
  }
  return out;
}

// Logins and tokens AI tools keep in the login Keychain (names only; secrets are never read)
function keyringAgent(who) {
  return /claude code/i.test(who) ? 'Claude Code' : /claude/i.test(who) ? 'Claude Desktop' : /chatgpt|openai/i.test(who) ? 'ChatGPT'
    : /github|^gh:/i.test(who) ? 'GitHub CLI' : /gemini-cli/i.test(who) ? 'Gemini CLI' : /codex/i.test(who) ? 'Codex CLI' : ((who.match(AI_NAME_RE) || ['Keychain'])[0].replace(/^./, c => c.toUpperCase()));
}
// Linux: the desktop keyring (GNOME Keyring, KWallet) through the Secret Service D-Bus API.
// Only names and attributes are read, never the secrets, so nothing gets unlocked and no password is asked for.
let keyringCache = { sig: '', at: 0, items: [] };
function busJson(args, timeout = 3000) { try { return JSON.parse(sh('busctl', ['--user', '--json=short', ...args], timeout) || 'null'); } catch { return null; } }
function keyringItems() {
  const dir = h('.local', 'share', 'keyrings');
  let sig = '';
  try { sig = fs.readdirSync(dir).map(n => { try { return n + fs.statSync(path.join(dir, n)).mtimeMs; } catch { return n; } }).join('|'); } catch {}
  if (keyringCache.at && keyringCache.sig === sig && Date.now() - keyringCache.at < 120e3) return keyringCache.items; // the files change when an item is added or removed
  const items = [];
  const owner = busJson(['call', 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'NameHasOwner', 's', 'org.freedesktop.secrets']);
  if (owner && owner.data && owner.data[0]) {
    const found = busJson(['call', 'org.freedesktop.secrets', '/org/freedesktop/secrets', 'org.freedesktop.Secret.Service', 'SearchItems', 'a{ss}', '0']);
    const paths = found && found.data ? [...(found.data[0] || []), ...(found.data[1] || [])] : [];
    for (const p of paths.slice(0, 400)) {
      const r = busJson(['call', 'org.freedesktop.secrets', p, 'org.freedesktop.DBus.Properties', 'GetAll', 's', 'org.freedesktop.Secret.Item'], 2000);
      const d = r && r.data && r.data[0];
      if (!d) continue;
      items.push({ label: (d.Label || {}).data || '', attrs: (d.Attributes || {}).data || {}, modified: Number((d.Modified || {}).data || 0) });
    }
  }
  keyringCache = { sig, at: Date.now(), items };
  return items;
}
function scanSecretService() {
  const out = [];
  for (const { label, attrs, modified } of keyringItems()) {
    const svc = attrs.service || attrs.application || attrs.xdg_schema || '', acct = attrs.account || attrs.username || attrs.user || '';
    const name = svc || label;
    const who = `${svc} ${label} ${attrs.server || ''}`;
    if (!name || !(AI_NAME_RE.test(who) || /^gh:github\.com|^github\.com$/.test(name))) continue;
    const when = modified ? new Date(modified * 1000).toISOString().slice(0, 10) : '';
    const safe = /Safe Storage$/i.test(label);
    out.push({
      agent: keyringAgent(who), category: 'Saved login', title: label || name,
      detail: safe ? `Key the app uses to encrypt its own local data${when ? ` · updated ${when}` : ''}`
        : `Password/token for ${name}${acct ? ` (account ${mask(acct)})` : ''}${when ? ` · updated ${when}` : ''}`,
      risk: safe ? 'low' : /github/i.test(name) ? 'high' : 'medium', source: 'keyring (Secret Service)',
      action: { kind: 'none', hint: `Open "Passwords and Keys" (Seahorse) or KWalletManager, search for "${label || name}" and delete it to sign the tool out.` },
    });
  }
  return out;
}
// Windows: Credential Manager. cmdkey lists the names (never the passwords). Its labels are in the
// system's language, so only the shape of each block is relied on: "label: target=NAME", then type, then user.
function scanCredentialManager(text = sh('cmdkey', ['/list'], 8000)) {
  const out = [];
  for (const block of text.split(/\r?\n\s*\r?\n/)) {
    const lines = block.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const ti = lines.findIndex(l => /target=/i.test(l));
    if (ti < 0) continue;
    const target = lines[ti].replace(/^.*?target=/i, '').trim();
    const user = ((lines[ti + 2] || '').match(/^[^:]+:\s*(.+)$/) || [])[1] || '';
    if (!(AI_NAME_RE.test(target) || /^gh:github\.com|^git:https:\/\/github\.com|^github\.com$/i.test(target))) continue;
    out.push({
      agent: keyringAgent(target), category: 'Saved login', title: target.replace(/:$/, ''),
      detail: `Password/token for ${target}${user ? ` (account ${mask(user)})` : ''}, saved in Windows Credential Manager`,
      risk: /github/i.test(target) ? 'high' : 'medium', source: 'Windows Credential Manager',
      action: { kind: 'none', hint: `Open Credential Manager (Control Panel → Credential Manager → Windows Credentials), find "${target}" and remove it. Or in a terminal: cmdkey /delete:"${target}"` },
    });
  }
  return out;
}
function scanKeychain() {
  const out = [];
  if (DEMO) return out;
  if (LINUX) return scanSecretService();
  if (WIN) return scanCredentialManager();
  if (!MAC) return out;
  const dump = sh('security', ['dump-keychain'], 20000);
  for (const block of dump.split(/^keychain: /m).slice(1)) {
    const attr = k => { const m = block.match(new RegExp(`"${k}"<(?:blob|timedate)>=(?:0x[0-9A-F]+\\s+)?"([^"]*)`)); return m ? m[1].replace(/\\000$/, '') : ''; };
    const cls = (block.match(/^class: "?(\w+)/m) || [])[1] || '';
    const svc = attr('svce'), label = attr('labl'), server = attr('srvr'), acct = attr('acct');
    const name = svc || server || label;
    if (!name || !(AI_NAME_RE.test(`${svc} ${label} ${server}`) || /^gh:github\.com|^github\.com$/.test(name))) continue;
    const mdat = attr('mdat');
    const when = /^\d{14}/.test(mdat) ? `${mdat.slice(0, 4)}-${mdat.slice(4, 6)}-${mdat.slice(6, 8)}` : '';
    const who = `${svc} ${label} ${server}`;
    const agent = keyringAgent(who);
    out.push({
      agent, category: 'Saved login', title: label || name,
      detail: /Safe Storage$/.test(name)
        ? `Key the app uses to encrypt its own local data${when ? ` · updated ${when}` : ''}`
        : `${cls === 'inet' ? 'Internet password' : 'App password/token'} for ${name}${acct ? ` (account ${mask(acct)})` : ''}${when ? ` · updated ${when}` : ''}`,
      risk: /Safe Storage$/.test(name) ? 'low' : /github/i.test(name) ? 'high' : 'medium', source: '~/Library/Keychains/login.keychain-db',
      action: { kind: 'openApp', bundle: 'com.apple.keychainaccess', fallback: 'Passwords', label: 'Open Keychain Access', hint: `Search for "${name}" and delete it to sign the tool out.` },
    });
  }
  return out;
}

// A readable owner for a background job: the app it belongs to, or the vendor in its label
function vendorName(label, prog) {
  const parts = String(label).split('.');
  const v = ['com', 'org', 'net', 'io', 'sh', 'de', 'co'].includes(parts[0]) ? parts[1] : parts[0];
  const known = { brew: 'Homebrew', microsoft: 'Microsoft', google: 'Google', apple: 'Apple', vmware: 'VMware', docker: 'Docker', tenablesecurity: 'Tenable', fortinet: 'Fortinet' };
  if (v && v.length > 1) return known[v] || v.replace(/^./, c => c.toUpperCase());
  const app = (prog.match(/\/Applications\/([^/]+)\.app\//) || [])[1];
  return app || (prog.match(/\/Library\/Application Support\/([^/]+)\//) || [])[1] || 'Background';
}

// Background jobs that start AI tools without you: LaunchAgents/Daemons and crontab
// Linux: systemd services and timers, and programs the desktop starts at login (XDG autostart)
const OWN_AUTOSTART = 'ai-access-auditor.desktop';
function iniFields(file) {
  const out = {};
  let text = '';
  try { text = fs.readFileSync(file, 'utf8'); } catch { return null; }
  let section = '';
  for (const line of text.split('\n')) {
    const sm = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (sm) { section = sm[1]; continue; }
    const m = line.match(/^\s*([A-Za-z][\w-]*)\s*=\s*(.*?)\s*$/);
    if (m && !(`${section}.${m[1]}` in out)) out[`${section}.${m[1]}`] = m[2];
  }
  return out;
}
function scanLinuxJobs() {
  const out = [];
  const add = (owner, title, when, prog, userOwned, file, action, systemWide) => {
    const aiMatch = (`${title} ${prog}`.match(AI_NAME_RE) || [])[0];
    if (getScope() === 'ai' && !aiMatch) return;
    out.push({
      agent: aiMatch ? (AGENT_NAMES[aiMatch.toLowerCase()] || aiMatch.replace(/^./, c => c.toUpperCase())) : owner,
      category: 'Background agent', title,
      detail: `Runs ${when}: ${prog.replace(HOME, '~').slice(0, 160)}${systemWide ? ' (system-wide)' : ''}`,
      risk: aiMatch ? (systemWide || when === 'always running' ? 'high' : 'medium') : 'low', source: file,
      action: userOwned ? action : { kind: 'none', hint: systemWide === 'unit' ? `Needs an admin: sudo systemctl disable --now ${path.basename(file)}` : `Needs an admin: remove ${file}` },
    });
  };
  const unitDirs = [[h('.config', 'systemd', 'user'), true], ...(DEMO ? [] : [['/etc/systemd/user', false], ['/etc/systemd/system', false]])];
  for (const [dir, userOwned] of unitDirs) {
    let names = [];
    try { names = fs.readdirSync(dir).filter(n => /\.(service|timer)$/.test(n)); } catch { continue; }
    for (const n of names) {
      const file = path.join(dir, n), u = iniFields(file);
      if (!u) continue;
      const isTimer = n.endsWith('.timer');
      const svc = isTimer ? iniFields(path.join(dir, u['Timer.Unit'] || n.replace(/\.timer$/, '.service'))) || {} : u;
      if (isTimer && names.includes(u['Timer.Unit'] || n.replace(/\.timer$/, '.service'))) {
        // the service is listed on its own; mark it as scheduled there instead of listing it twice
        continue;
      }
      const prog = svc['Service.ExecStart'] || '';
      const scheduled = !isTimer && names.includes(n.replace(/\.service$/, '.timer'));
      const when = isTimer || scheduled ? 'on a schedule' : /always|on-failure/.test(svc['Service.Restart'] || '') ? 'always running'
        : /default\.target|graphical-session\.target|multi-user\.target/.test(svc['Install.WantedBy'] || '') ? (userOwned ? 'at login' : 'at startup') : 'on demand';
      add('systemd', svc['Unit.Description'] ? `${n} (${svc['Unit.Description']})` : n, when, prog, userOwned, file,
        { kind: 'disableSystemdUnit', files: [file, ...(scheduled ? [path.join(dir, n.replace(/\.service$/, '.timer'))] : [])] }, !userOwned && 'unit');
    }
  }
  const autoDirs = [[path.join(process.env.XDG_CONFIG_HOME || h('.config'), 'autostart'), true], ...(DEMO ? [] : [['/etc/xdg/autostart', false]])];
  for (const [dir, userOwned] of autoDirs) {
    let names = [];
    try { names = fs.readdirSync(dir).filter(n => n.endsWith('.desktop') && n !== OWN_AUTOSTART); } catch { continue; }
    for (const n of names) {
      const file = path.join(dir, n), d = iniFields(file);
      if (!d || d['Desktop Entry.Hidden'] === 'true' || d['Desktop Entry.X-GNOME-Autostart-enabled'] === 'false') continue;
      add(d['Desktop Entry.Name'] || n.replace(/\.desktop$/, ''), d['Desktop Entry.Name'] || n, 'at login', (d['Desktop Entry.Exec'] || '').replace(/\s+%[a-zA-Z]/g, ''), userOwned, file,
        { kind: 'removeAutostart', file }, !userOwned && 'file');
    }
  }
  return out;
}

// Windows: Run entries in the registry, the Startup folders, and Task Scheduler (tasks outside \Microsoft\)
const RUN_KEYS = [['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', true], ['HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', false]];
let tasksCache = { at: 0, list: [] };
const PS_TASKS = "Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled' } | ForEach-Object { "
  + "$a = ($_.Actions | ForEach-Object { \"$($_.Execute) $($_.Arguments)\" }) -join ' ; '; $t = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ','; "
  + "\"{0}`t{1}`t{2}`t{3}`t{4}\" -f $_.TaskPath, $_.TaskName, $_.Principal.UserId, $t, ($a -replace \"[`r`n`t]\", ' ') }";
function parseWinTasks(out) {
  const list = [];
  for (const line of out.split(/\r?\n/)) {
    const [tpath, name, user, triggers, action] = line.split('\t');
    if (name) list.push({ tpath, name, user: user || '', triggers: triggers || '', action: (action || '').trim() });
  }
  return list;
}
function windowsTasks() {
  if (Date.now() - tasksCache.at < (winHelper ? 120e3 : 60e3)) return tasksCache.list;
  tasksCache = { at: Date.now(), list: parseWinTasks(psh(PS_TASKS, 30000)) };
  return tasksCache.list;
}
function scanWindowsJobs() {
  const out = [];
  const add = (owner, title, when, prog, file, action, systemWide) => {
    if (OWN_APP_RE.test(prog) || /^AI Access Auditor$/i.test(title)) return;
    const aiMatch = (`${title} ${prog}`.match(AI_NAME_RE) || [])[0];
    if (getScope() === 'ai' && !aiMatch) return;
    out.push({
      agent: aiMatch ? (AGENT_NAMES[aiMatch.toLowerCase()] || aiMatch.replace(/^./, c => c.toUpperCase())) : owner,
      category: 'Background agent', title,
      detail: `Runs ${when}: ${prog.replace(HOME, '~').slice(0, 160)}${systemWide ? ' (system-wide)' : ''}`,
      risk: aiMatch ? (systemWide || when === 'at startup' ? 'high' : 'medium') : 'low', source: file, action,
    });
  };
  for (const [key, userOwned] of RUN_KEYS) {
    for (const line of sh('reg', ['query', key], 5000).split(/\r?\n/)) {
      const m = line.match(/^\s{4}(.+?)\s{4}(REG_(?:SZ|EXPAND_SZ))\s{4}(.*)$/);
      if (!m) continue;
      const [, name, type, value] = m;
      add(name, name, 'at login', value, `${key}\\${name}`, userOwned ? { kind: 'removeRunValue', key, name, type, value }
        : { kind: 'none', hint: `Needs an administrator: remove "${name}" in Task Manager → Startup apps, or with reg delete "${key}" /v "${name}" /f in an administrator terminal.` }, !userOwned);
    }
  }
  for (const [dir, userOwned] of [[appData('Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'), true], ['C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp', false]]) {
    let names = [];
    try { names = fs.readdirSync(dir).filter(n => !/^desktop\.ini$/i.test(n)); } catch { continue; }
    for (const n of names) {
      const file = path.join(dir, n), title = n.replace(/\.(lnk|url|bat|cmd|exe)$/i, '');
      add(title, title, 'at login', file, file, userOwned ? { kind: 'removeAutostart', file } : { kind: 'none', hint: `Needs an administrator: delete ${file}` }, !userOwned);
    }
  }
  for (const t of windowsTasks()) {
    const full = `${t.tpath}${t.name}`;
    const when = /Boot/.test(t.triggers) ? 'at startup' : /Logon/.test(t.triggers) ? 'at login' : /Time|Daily|Weekly|Monthly/.test(t.triggers) ? 'on a schedule' : 'on demand';
    const mine = !t.user || t.user.toLowerCase().split('\\').pop() === os.userInfo().username.toLowerCase();
    add(t.tpath.replace(/^\\|\\$/g, '') || 'Task Scheduler', full, when, t.action, `task ${full}`,
      mine ? { kind: 'disableTask', task: full } : { kind: 'none', hint: `Needs an administrator: disable "${full}" in Task Scheduler.` }, !mine);
  }
  return out;
}

function scanBackgroundAgents() {
  const out = LINUX ? scanLinuxJobs() : WIN && !DEMO ? scanWindowsJobs() : [];
  const dirs = !MAC ? [] : [[h('Library', 'LaunchAgents'), true], ...(DEMO ? [] : [['/Library/LaunchAgents', false], ['/Library/LaunchDaemons', false]])];
  for (const [dir, userOwned] of dirs) {
    let files = [];
    try { files = fs.readdirSync(dir).filter(f => f.endsWith('.plist')); } catch { continue; }
    for (const f of files) {
      const file = path.join(dir, f);
      let j;
      try { j = JSON.parse(sh('plutil', ['-convert', 'json', '-o', '-', file], 3000) || 'null'); } catch { continue; }
      if (!j || j.Label === OWN_LAUNCH_AGENT) continue;
      const prog = [j.Program, ...(j.ProgramArguments || [])].filter(Boolean).join(' ');
      if (getScope() === 'ai' && !AI_NAME_RE.test(`${j.Label} ${prog}`)) continue;
      const when = j.StartInterval ? `every ${Math.round(j.StartInterval / 60)} min` : j.StartCalendarInterval ? 'on a schedule' : j.KeepAlive ? 'always running' : j.RunAtLoad ? 'at login' : 'on demand';
      const aiMatch = (`${j.Label} ${prog}`.match(AI_NAME_RE) || [])[0];
      out.push({
        agent: aiMatch ? (AGENT_NAMES[aiMatch.toLowerCase()] || aiMatch.replace(/^./, c => c.toUpperCase())) : vendorName(j.Label || f, prog),
        category: 'Background agent', title: j.Label || f,
        detail: `Runs ${when}: ${prog.replace(HOME, '~').slice(0, 160)}${userOwned ? '' : ' (system-wide)'}`,
        // AI jobs that are always on are the real concern; other apps' services are shown for completeness (all-apps mode)
        risk: aiMatch ? (dir.includes('Daemons') || j.KeepAlive ? 'high' : 'medium') : 'low', source: file,
        action: userOwned ? { kind: 'disableLaunchAgent', file } : { kind: 'none', hint: `Needs an admin: sudo launchctl bootout system ${file}` },
      });
    }
  }
  (DEMO ? '' : sh('crontab', ['-l'], 3000)).split('\n').forEach((line, i) => {
    if (!line.trim() || line.trim().startsWith('#') || !AI_NAME_RE.test(line)) return;
    out.push({
      agent: (line.match(AI_NAME_RE) || ['Cron'])[0].replace(/^./, c => c.toUpperCase()), category: 'Background agent',
      title: line.trim().split(/\s+/).slice(5).join(' ').slice(0, 80), detail: `crontab line ${i + 1}: ${line.trim()}`,
      risk: 'medium', source: 'crontab', action: { kind: 'none', hint: 'Run "crontab -e" and delete this line.' },
    });
  });
  return out;
}

// AI extensions inside code editors (they can read your code and often run commands)
// a command in the usual program folders (the app's own PATH can be short when it starts at login)
function findCommand(cmd, extra = []) {
  const dirs = [...extra, ...(process.env.PATH || '').split(':').filter(Boolean), '/usr/local/bin', '/usr/bin', '/bin', '/snap/bin', h('.local', 'bin')];
  for (const d of dirs) { const f = path.join(d, cmd); try { fs.accessSync(f, fs.constants.X_OK); return f; } catch {} }
  return '';
}
const EDITORS = WIN ? [
  ['VS Code', h('.vscode', 'extensions'), path.join(LOCAL_APPDATA, 'Programs', 'Microsoft VS Code', 'bin', 'code.cmd')],
  ['Cursor', h('.cursor', 'extensions'), path.join(LOCAL_APPDATA, 'Programs', 'cursor', 'resources', 'app', 'bin', 'cursor.cmd')],
  ['Windsurf', h('.windsurf', 'extensions'), path.join(LOCAL_APPDATA, 'Programs', 'Windsurf', 'bin', 'windsurf.cmd')],
] : MAC ? [
  ['VS Code', h('.vscode', 'extensions'), '/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code'],
  ['Cursor', h('.cursor', 'extensions'), '/Applications/Cursor.app/Contents/Resources/app/bin/cursor'],
  ['Windsurf', h('.windsurf', 'extensions'), '/Applications/Windsurf.app/Contents/Resources/app/bin/windsurf'],
] : [
  ['VS Code', h('.vscode', 'extensions'), () => findCommand('code', ['/usr/share/code/bin'])],
  ['Cursor', h('.cursor', 'extensions'), () => findCommand('cursor', ['/opt/Cursor/resources/app/bin', '/usr/share/cursor/bin'])],
  ['Windsurf', h('.windsurf', 'extensions'), () => findCommand('windsurf', ['/usr/share/windsurf/bin'])],
];
const AI_EXT_RE = /copilot|claude|anthropic|openai|chatgpt|codeium|continue\.continue|saoudrizwan|rooveterinaryinc|cline|kilocode|tabnine|amazon-?q|codegpt|gemini|sourcegraph\.cody|supermaven|codewhisperer|blackbox/i;
function scanEditorExtensions() {
  const out = [];
  for (const [editor, dir, cliPath] of EDITORS) {
    let names = [];
    try { names = fs.readdirSync(dir); } catch { continue; }
    const cli = typeof cliPath === 'function' ? cliPath() : cliPath;
    const latest = {};
    for (const n of names) {
      const m = n.match(/^(.+?)-(\d+\.\d+\.\d+.*)$/);
      if (m && AI_EXT_RE.test(m[1]) && (!latest[m[1]] || m[2] > latest[m[1]].v)) latest[m[1]] = { v: m[2], dir: path.join(dir, n) };
    }
    for (const [extId, { v, dir: extDir }] of Object.entries(latest)) {
      const pkg = readJson(path.join(extDir, 'package.json')) || {};
      const agentic = /saoudrizwan|rooveterinaryinc|cline|kilocode|claude-code|anthropic|continue|codex/i.test(extId);
      out.push({
        agent: editor, category: 'Editor extension', title: pkg.displayName && !pkg.displayName.startsWith('%') ? pkg.displayName : extId,
        detail: `${extId} v${v}: can read your open code${agentic ? ', edit files and run terminal commands' : ' and send it to an AI service'}`,
        risk: agentic ? 'high' : 'medium', source: extDir,
        action: cli && exists(cli) ? { kind: 'uninstallExt', cli, extId, editor } : { kind: 'none', hint: `Uninstall it from the Extensions panel in ${editor}.` },
      });
    }
  }
  return out;
}

// AI extensions in Chromium browsers (Chrome, Brave, Edge, Arc; on Linux also Chromium, including the Snap and Flatpak versions)
const BROWSERS = WIN ? [
  ['Chrome', path.join(LOCAL_APPDATA, 'Google', 'Chrome', 'User Data')],
  ['Edge', path.join(LOCAL_APPDATA, 'Microsoft', 'Edge', 'User Data')],
  ['Brave', path.join(LOCAL_APPDATA, 'BraveSoftware', 'Brave-Browser', 'User Data')],
  ['Vivaldi', path.join(LOCAL_APPDATA, 'Vivaldi', 'User Data')],
] : MAC ? [
  ['Chrome', appData('Google', 'Chrome')],
  ['Brave', appData('BraveSoftware', 'Brave-Browser')],
  ['Edge', appData('Microsoft Edge')],
  ['Arc', appData('Arc', 'User Data')],
] : [
  ['Chrome', appData('google-chrome')],
  ['Chromium', appData('chromium')],
  ['Chromium', h('snap', 'chromium', 'common', 'chromium')],
  ['Brave', appData('BraveSoftware', 'Brave-Browser')],
  ['Brave', h('.var', 'app', 'com.brave.Browser', 'config', 'BraveSoftware', 'Brave-Browser')],
  ['Chrome', h('.var', 'app', 'com.google.Chrome', 'config', 'google-chrome')],
  ['Edge', appData('microsoft-edge')],
  ['Vivaldi', appData('vivaldi')],
];
function scanBrowserExtensions() {
  const out = [];
  const browsers = BROWSERS;
  const msg = (extDir, manifest, s) => {
    const m = String(s || '').match(/^__MSG_(.+)__$/);
    if (!m) return s;
    for (const loc of [manifest.default_locale, 'en', 'en_US'].filter(Boolean)) {
      const j = readJson(path.join(extDir, '_locales', loc, 'messages.json'));
      const hit = j && Object.entries(j).find(([k]) => k.toLowerCase() === m[1].toLowerCase());
      if (hit) return hit[1].message;
    }
    return s;
  };
  for (const [browser, root] of browsers) {
    let profiles = [];
    try { profiles = fs.readdirSync(root).filter(p => p === 'Default' || /^Profile \d+$/.test(p)); } catch { continue; }
    for (const prof of profiles) {
      const extRoot = path.join(root, prof, 'Extensions');
      let ids = [];
      try { ids = fs.readdirSync(extRoot); } catch { continue; }
      for (const extId of ids) {
        let vers = [];
        try { vers = fs.readdirSync(path.join(extRoot, extId)).sort(); } catch { continue; }
        const extDir = path.join(extRoot, extId, vers[vers.length - 1] || '');
        const mf = readJson(path.join(extDir, 'manifest.json'));
        if (!mf) continue;
        const name = msg(extDir, mf, mf.name) || extId;
        if (!(AI_NAME_RE.test(name) || /\bAI\b|GPT|Monica|Sider|Merlin|MaxAI|HARPA/.test(name))) continue;
        const perms = [...(mf.permissions || []), ...(mf.host_permissions || []), ...((mf.content_scripts || []).flatMap(c => c.matches || []))];
        const allSites = perms.some(p => p === '<all_urls>' || /^\*:\/\/\*\/|^https?:\/\/\*\//.test(p));
        const notable = [...new Set(perms.filter(p => /tabs|history|cookies|clipboard|debugger|scripting|downloads|webRequest|nativeMessaging/.test(p)))];
        out.push({
          agent: browser, category: 'Browser extension', title: name,
          detail: `${allSites ? 'Can read and change every website you visit' : 'Runs on some websites'}${notable.length ? ` · also: ${notable.join(', ')}` : ''} · profile ${prof}`,
          risk: allSites || notable.includes('debugger') ? 'high' : 'medium', source: extDir,
          action: { kind: 'none', hint: `Remove it in ${browser} → Extensions (profile "${prof}").` },
        });
      }
    }
  }
  return out;
}

// Sockets waiting for connections: [{ proc, pid, addr }]. On Linux, ss only names your own processes
// (system services show no name), which is why the known ports below matter.
// Windows: netstat -ano ("TCP  local  remote  state  pid"). The state word is in the system's language,
// so listening sockets are recognised by their remote address (0.0.0.0:0 or [::]:0) instead.
function netstat(text = sh('netstat', ['-ano', '-p', 'TCP'], 8000) + '\n' + sh('netstat', ['-ano', '-p', 'TCPv6'], 8000), procs = processList(3000)) {
  const names = new Map(procs.map(p => [p.pid, exeBase(p.cmd)]));
  return text.split(/\r?\n/)
    .map(l => l.trim().split(/\s+/)).filter(c => c.length >= 5 && /^TCP/i.test(c[0]) && /^\d+$/.test(c[c.length - 1]))
    .map(c => ({ local: c[1], remote: c[2], pid: c[c.length - 1], proc: names.get(c[c.length - 1]) || '', listening: /^(0\.0\.0\.0|\[::\]):0$/.test(c[2]) }));
}
function listeningSockets() {
  if (WIN) return netstat().filter(x => x.listening).map(x => ({ proc: x.proc, pid: x.pid, addr: x.local }));
  if (LINUX) return sh('ss', ['-tlnpH'], 5000).split('\n').map(l => {
    const c = l.trim().split(/\s+/), u = l.match(/users:\(\("([^"]+)",pid=(\d+)/) || [];
    return c.length >= 4 ? { proc: u[1] || '', pid: u[2] || '', addr: c[3] } : null;
  }).filter(Boolean);
  return sh('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN'], 5000).split('\n').slice(1).map(l => {
    const c = l.trim().split(/\s+/);
    return c.length >= 9 ? { proc: c[0], pid: c[1], addr: c[8] } : null;
  }).filter(Boolean);
}
// Local AI model servers listening on the network (others on your Wi-Fi could use them)
function scanLocalServers() {
  const out = [];
  if (DEMO) return out;
  const known = { 11434: 'Ollama', 1234: 'LM Studio', 8080: null, 5000: null };
  for (const { proc, pid, addr } of listeningSockets()) {
    const port = Number(addr.split(':').pop());
    const name = known[port] || (AI_NAME_RE.test(proc) ? proc : null);
    if (!name || /^(127\.[\d.]+(%\w+)?|\[::1\]|localhost|\[::ffff:127\.[\d.]+\]):/.test(addr)) continue;
    out.push({
      agent: name, category: 'Network exposure', title: `${name} open on port ${port}`,
      detail: `${proc || name} listens on ${addr}, so other devices on your network can use it without a password`,
      risk: 'high', source: `process ${proc || name} (pid ${pid || '?'})`,
      action: { kind: 'none', hint: name === 'Ollama' ? 'Set OLLAMA_HOST=127.0.0.1 and restart Ollama.' : 'Change the server setting to listen on 127.0.0.1 (localhost) only.' },
    });
  }
  return out;
}

function openCodeConfig() {
  for (const n of ['opencode.jsonc', 'opencode.json', 'config.json']) {
    const file = h('.config', 'opencode', n), r = readJsonc(file);
    if (r) return { file, ...r };
  }
  return null;
}
// Lenient reader for editors' JSON-with-comments settings files
function readJsonc(file) {
  let t;
  try { t = fs.readFileSync(file, 'utf8'); } catch { return null; }
  try { return { j: JSON.parse(t), strict: true }; } catch {}
  try {
    const stripped = t.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:"'\\])\/\/.*$/gm, '$1').replace(/,(\s*[}\]])/g, '$1');
    return { j: JSON.parse(stripped), strict: false };
  } catch { return null; }
}

// Permissions, trusted folders and "never ask" modes of other AI agents
function scanMoreAgents() {
  const out = [];
  const add = (agent, category, title, detail, risk, source, action) => out.push({ agent, category, title, detail, risk, source, action });
  const none = hint => ({ kind: 'none', hint });

  for (const [agent, f, p] of [
    ['Copilot CLI', h('.copilot', 'mcp-config.json'), ['mcpServers']],
    ['Amazon Q', h('.aws', 'amazonq', 'mcp.json'), ['mcpServers']],
    ['Kiro', h('.kiro', 'settings', 'mcp.json'), ['mcpServers']],
  ]) for (const [name, cfg] of Object.entries(getAt(readJson(f), p) || {})) out.push(mcpFinding(agent, name, cfg || {}, f, p, ''));
  const cont = h('.continue', 'config.json');
  ((readJson(cont) || {}).mcpServers || []).forEach(m => add('Continue', 'MCP server', m.name || m.command || 'server',
    [m.command, ...maskArgs(m.args)].filter(Boolean).join(' '), mcpRisk(m), cont, none('Remove it from ~/.continue/config.json.')));

  // Gemini CLI
  const gs = h('.gemini', 'settings.json'), g = readJson(gs) || {};
  for (const p of [['autoAccept'], ['tools', 'autoAccept']]) if (getAt(g, p) === true)
    add('Gemini CLI', 'Permission mode', `${p.join('.')} = true`, 'Runs tools it considers safe without asking', 'medium', gs, { kind: 'setFalse', file: gs, path: p.slice(0, -1), key: p[p.length - 1] });
  (getAt(g, ['tools', 'allowed']) || []).forEach(r => add('Gemini CLI', 'Tool permission', r, 'Runs without asking (tools.allowed)',
    ruleRisk(String(r).replace(/^run_shell_command/, 'Bash')), gs, { kind: 'removeArrayItem', file: gs, path: ['tools', 'allowed'], value: r }));
  for (const p of [['general', 'defaultApprovalMode'], ['tools', 'approvalMode']]) {
    const m = getAt(g, p);
    if (m === 'yolo' || m === 'auto_edit') add('Gemini CLI', 'Permission mode', `${p.join('.')}: ${m}`,
      m === 'yolo' ? 'Every Gemini session starts in YOLO mode: it acts without asking' : 'Every Gemini session changes files without asking',
      m === 'yolo' ? 'high' : 'medium', gs, { kind: 'deleteKey', file: gs, path: p.slice(0, -1), key: p[p.length - 1], value: m });
  }
  const gHooks = Object.entries(g.hooks || {}).filter(([, list]) => (list || []).some(e => !isOurHook(e))).map(([k]) => k);
  if (gHooks.length) add('Gemini CLI', 'Hooks', `Hooks: ${gHooks.join(', ')}`, 'Shell commands Gemini runs automatically on its events', 'medium', gs,
    none('Review the "hooks" section in ~/.gemini/settings.json, or use /hooks inside Gemini.'));
  // Gemini "Allow always" rules: [[rule]] blocks in policies/*.toml (user-wide, and per project)
  for (const [file, scopeLabel] of geminiPolicyFiles()) {
    for (const r of geminiRules(file)) {
      if (r.fields.decision !== 'allow') continue;
      const tool = r.fields.toolName || '*', mcp = r.fields.mcpName;
      const what = r.fields.commandPrefix ? `${tool}: ${[].concat(r.fields.commandPrefix).join(' | ')}` : r.fields.argsPattern ? `${tool} matching ${r.fields.argsPattern}` : mcp ? `MCP ${mcp}: ${tool}` : tool;
      const risk = tool === 'run_shell_command'
        ? (r.fields.commandPrefix ? [].concat(r.fields.commandPrefix).map(c => ruleRisk(`Bash(${c})`)).sort()[0] : 'high')
        : tool === '*' ? 'high' : /^(write_file|replace)$/.test(tool) || mcp ? 'medium' : 'low';
      add('Gemini CLI', 'Tool permission', what,
        `Runs without asking (${scopeLabel}${r.fields.modes ? `, in ${[].concat(r.fields.modes).join('/')} mode` : ''})`, risk, file,
        { kind: 'removeTomlBlock', file, block: r.text });
    }
  }
  // Gemini sign-ins: the Keychain item "gemini-cli-oauth" (found by scanKeychain), or these files
  const gAcct = (readJson(h('.gemini', 'google_accounts.json')) || {}).active;
  const who = gAcct ? ` (${mask(String(gAcct))})` : '';
  for (const [file, title, detail, risk] of [
    ['oauth_creds.json', 'Google sign-in token', `Gemini's Google login${who}, saved as plain text: any program you run can read it and use your Google AI access`, 'high'],
    ['gemini-credentials.json', 'Google sign-in token (encrypted file)', `Gemini's Google login${who}. It is encrypted, but with a key built from your Mac's name and your username, so any program on this Mac could unlock it`, 'medium'],
    ['mcp-oauth-tokens.json', 'MCP server logins', 'Logins Gemini saved for MCP servers it connects to', 'medium'],
  ]) {
    const f = h('.gemini', file);
    if (exists(f)) add('Gemini CLI', 'Saved login', title, detail, risk, f, { kind: 'removeFile', file: f });
  }
  const tf = h('.gemini', 'trustedFolders.json');
  for (const [dir, lvl] of Object.entries(readJson(tf) || {})) if (lvl !== 'DO_NOT_TRUST')
    { // macOS paths aren't case-sensitive, and Gemini may store them lowercased
      const d = dir.toLowerCase().replace(/\/+$/, ''), home = HOME.toLowerCase();
      const wide = d === '' || d === home || (lvl === 'TRUST_PARENT' && (home.startsWith(d + '/') || path.dirname(d) === '/' || d === home));
      add('Gemini CLI', 'Trusted folder', dir.replace(new RegExp('^' + HOME.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'), '~'),
        lvl === 'TRUST_PARENT' ? `Trusted, together with its parent folder (${path.dirname(dir)})` : 'Trusted folder',
        wide ? 'high' : 'low', tf, { kind: 'deleteKey', file: tf, path: [], key: dir, value: lvl });
    }

  // Cursor CLI
  const cc = h('.cursor', 'cli-config.json');
  (getAt(readJson(cc), ['permissions', 'allow']) || []).forEach(r => add('Cursor CLI', 'Tool permission', r, 'Runs without asking',
    ruleRisk(String(r).replace(/^Shell/, 'Bash')), cc, { kind: 'removeArrayItem', file: cc, path: ['permissions', 'allow'], value: r }));

  // Copilot CLI
  const cp = h('.copilot', 'config.json');
  (getAt(readJson(cp), ['trusted_folders']) || []).forEach(d => add('Copilot CLI', 'Trusted folder', String(d).replace(HOME, '~'), 'Trusted folder: Copilot can read and change files here',
    d === HOME || d === '/' ? 'high' : 'low', cp, { kind: 'removeArrayItem', file: cp, path: ['trusted_folders'], value: d }));

  // OpenCode: settings in ~/.config/opencode/opencode.json or opencode.jsonc (JSON with comments, which are
  // safer to change by hand), MCP servers in its own format, and permissions for all agents or for one agent
  const occ = openCodeConfig();
  if (occ) {
    const { file: oc, j, strict } = occ;
    const manual = none(`Edit ${oc.replace(HOME, '~')} (it has comments, so it's safer to change by hand).`);
    const act = a => (strict ? a : manual);
    for (const [name, cfg] of Object.entries(j.mcp || {})) {
      if (!cfg || typeof cfg !== 'object' || cfg.enabled === false) continue;
      const cmd = Array.isArray(cfg.command) ? cfg.command : [cfg.command].filter(Boolean);
      const f = mcpFinding('OpenCode', name, { command: cmd[0], args: cmd.slice(1), env: cfg.environment, url: cfg.url, headers: cfg.headers }, oc, ['mcp'], '');
      f.action = act({ ...f.action, value: cfg });
      out.push(f);
    }
    const perms = (perm, at, who) => {
      if (perm === 'allow') return add('OpenCode', 'Permission mode', `${who}permission: allow`, 'Uses every tool without asking, including running commands and changing files', 'high', oc,
        act({ kind: 'deleteKey', file: oc, path: at.slice(0, -1), key: at[at.length - 1], value: perm }));
      for (const [tool, v] of Object.entries(perm && typeof perm === 'object' ? perm : {})) {
        if (v === 'allow') add('OpenCode', 'Tool permission', `${who}${tool}: allow`, `Uses ${tool} without asking`, /^(bash|\*)$/.test(tool) ? 'high' : 'medium', oc, act({ kind: 'deleteKey', file: oc, path: at, key: tool, value: v }));
        else if (v && typeof v === 'object') for (const [c, vv] of Object.entries(v)) if (vv === 'allow')
          add('OpenCode', 'Tool permission', `${who}${tool}(${c})`, 'Runs without asking', ruleRisk(`Bash(${c})`), oc, act({ kind: 'deleteKey', file: oc, path: [...at, tool], key: c, value: vv }));
      }
    };
    perms(j.permission, ['permission'], '');
    for (const [aname, a] of Object.entries(j.agent || {})) if (a && a.permission) perms(a.permission, ['agent', aname, 'permission'], `agent ${aname}: `);
  }
  // OpenCode keeps the API keys and logins for its AI providers in a plain-text file
  const oa = h('.local', 'share', 'opencode', 'auth.json');
  if (exists(oa)) add('OpenCode', 'Saved login', 'AI provider logins (auth.json)',
    `OpenCode keeps ${Object.keys(readJson(oa) || {}).length || 'its'} provider login${Object.keys(readJson(oa) || {}).length === 1 ? '' : 's'} here as plain text: any program you run can read them and use your AI accounts`,
    'high', oa, { kind: 'removeFile', file: oa });
  // OpenCode plugins: code OpenCode loads and runs by itself whenever something happens in a session
  for (const dir of [h('.config', 'opencode', 'plugin'), h('.config', 'opencode', 'plugins')]) {
    let names = [];
    try { names = fs.readdirSync(dir).filter(n => /\.(js|mjs|ts)$/.test(n)); } catch {}
    for (const n of names) add('OpenCode', 'Hooks', `Plugin: ${n.replace(/\.(js|mjs|ts)$/, '')}`, 'Code OpenCode loads and runs by itself on its events (it can run commands and read files)',
      'medium', path.join(dir, n), { kind: 'removeFile', file: path.join(dir, n) });
  }

  // VS Code / Cursor / Windsurf: Copilot agent auto-approve settings
  for (const [editor, f] of [
    ['VS Code', appData('Code', 'User', 'settings.json')],
    ['Cursor', appData('Cursor', 'User', 'settings.json')],
    ['Windsurf', appData('Windsurf', 'User', 'settings.json')],
  ]) {
    const r = readJsonc(f);
    if (!r) continue;
    const manual = none(`Edit ${f.replace(HOME, '~')} (it has comments, so it's safer to change by hand).`);
    for (const k of ['chat.tools.autoApprove', 'chat.tools.global.autoApprove']) if (r.j[k] === true)
      add(editor, 'Permission mode', `${k} = true`, 'Copilot agent mode runs every tool without asking', 'high', f, r.strict ? { kind: 'setFalse', file: f, path: [], key: k } : manual);
    for (const [cmd, v] of Object.entries(r.j['chat.tools.terminal.autoApprove'] || {})) if (v === true || (v && v.approve === true))
      add(editor, 'Tool permission', `terminal: ${cmd}`, 'Copilot runs this terminal command without asking', ruleRisk(`Bash(${cmd.replace(/^\/|\/$/g, '')})`), f,
        r.strict ? { kind: 'deleteKey', file: f, path: ['chat.tools.terminal.autoApprove'], key: cmd, value: v } : manual);
  }

  // YAML configs: detect only
  const aider = h('.aider.conf.yml');
  if (exists(aider) && /^\s*yes-always\s*:\s*true/m.test(fs.readFileSync(aider, 'utf8')))
    add('Aider', 'Permission mode', 'yes-always: true', 'Says yes to every question, including running commands', 'high', aider, none('Set yes-always: false in ~/.aider.conf.yml.'));
  const goose = h('.config', 'goose', 'config.yaml');
  if (exists(goose) && /^\s*GOOSE_MODE\s*:\s*['"]?auto/m.test(fs.readFileSync(goose, 'utf8')))
    add('Goose', 'Permission mode', 'GOOSE_MODE: auto', 'Acts without asking for approval', 'high', goose, none('Change GOOSE_MODE in ~/.config/goose/config.yaml.'));

  // Windsurf (Cascade) and Kiro 0.x: command lists in the editor's own settings.json. Matching is by prefix,
  // so "*" or a bare shell or interpreter means any command runs without asking.
  const anyCmd = c => /^\s*(\*|bash|sh|zsh|fish|pwsh|powershell|cmd|python3?|node|ruby|perl|deno|bun|npx|eval)(\s+\*)?\s*$/i.test(c);
  for (const [agent, f, key, what] of [
    ['Windsurf', appData('Windsurf', 'User', 'settings.json'), 'windsurf.cascadeCommandsAllowList', 'Cascade runs commands starting with this without asking'],
    ['Kiro', appData('Kiro', 'User', 'settings.json'), 'kiroAgent.trustedCommands', 'Kiro runs this command without asking'],
  ]) {
    const r = readJsonc(f);
    if (!r || !Array.isArray(r.j[key])) continue;
    const manual = none(`Edit ${f.replace(HOME, '~')} (it has comments, so it's safer to change by hand).`);
    for (const c of r.j[key]) add(agent, 'Tool permission', `terminal: ${c}`, anyCmd(String(c)) ? `${what}: this covers any command` : what,
      anyCmd(String(c)) ? 'high' : ruleRisk(`Bash(${String(c).replace(/\s*\*$/, '')})`), f,
      r.strict ? { kind: 'removeArrayItem', file: f, path: [key], value: c } : manual);
  }

  // Kiro 1.0: permissions.yaml rules (user-wide; per-project copies live in ~/.kiro/workspace-roots/<id>/)
  const kiroFiles = [[h('.kiro', 'settings', 'permissions.yaml'), 'all projects']];
  try { for (const d of fs.readdirSync(h('.kiro', 'workspace-roots'))) kiroFiles.push([h('.kiro', 'workspace-roots', d, 'permissions.yaml'), 'one project']); } catch {}
  for (const [file, scopeLabel] of kiroFiles) for (const r of yamlListItems(file, 'rules')) {
    if (r.fields.effect !== 'allow') continue;
    const cap = String(r.fields.capability || ''), match = [].concat(r.fields.match || []);
    const all = !match.length || match.some(m => String(m).trim() === '*');
    const risk = cap === 'all' || cap === 'builtin' ? 'high'
      : cap === 'shell' ? (all || match.some(m => anyCmd(String(m))) ? 'high' : match.map(m => ruleRisk(`Bash(${String(m).replace(/\s*\*$/, '')})`)).sort()[0])
      : /^(fs_write|filesystem|mcp|power|subagent)$/.test(cap) ? (all ? 'high' : 'medium') : 'low';
    add('Kiro', cap === 'all' ? 'Permission mode' : 'Tool permission', `${cap}: allow${match.length ? ` (${match.join(', ')})` : ''}`,
      cap === 'all' ? `Kiro acts without asking for anything (${scopeLabel})` : `Kiro does this without asking (${scopeLabel})`, risk, file,
      { kind: 'removeTomlBlock', file, block: r.text });
  }

  // Zed's own agent: tool_permissions (Zed 0.224+) or the older always_allow_tool_actions switch
  const zf = h('.config', 'zed', 'settings.json'), zr = readJsonc(zf);
  if (zr) {
    const act = a => (zr.strict ? a : none(`Edit ${zf.replace(HOME, '~')} (it has comments, so it's safer to change by hand).`));
    const ag = zr.j.agent || {};
    if (ag.always_allow_tool_actions === true) add('Zed', 'Permission mode', 'agent.always_allow_tool_actions = true', 'Zed\'s agent uses every tool without asking, including the terminal',
      'high', zf, act({ kind: 'setFalse', file: zf, path: ['agent'], key: 'always_allow_tool_actions' }));
    const tp = ag.tool_permissions || {};
    if (tp.default === 'allow') add('Zed', 'Permission mode', 'tool_permissions.default: allow', 'Zed\'s agent uses tools without asking, unless a rule says otherwise',
      'high', zf, act({ kind: 'deleteKey', file: zf, path: ['agent', 'tool_permissions'], key: 'default', value: 'allow' }));
    for (const [tool, cfg] of Object.entries(tp.tools || {})) {
      if (!cfg || typeof cfg !== 'object') continue;
      const big = /terminal|^mcp:/.test(tool) ? 'high' : /edit|write|delete|move|create/.test(tool) ? 'medium' : 'low';
      if (cfg.default === 'allow') add('Zed', 'Tool permission', `${tool}: allow`, 'Zed\'s agent uses this tool without asking', big, zf,
        act({ kind: 'deleteKey', file: zf, path: ['agent', 'tool_permissions', 'tools', tool], key: 'default', value: 'allow' }));
      for (const pat of Array.isArray(cfg.always_allow) ? cfg.always_allow : []) {
        const shown = typeof pat === 'string' ? pat : (pat && pat.pattern) || JSON.stringify(pat);
        const broad = /^\^?\.\*\$?$|^\*$/.test(shown);
        add('Zed', 'Tool permission', `${tool}: ${shown}`, 'Allowed without asking when the input matches this pattern', broad ? big : big === 'high' ? 'medium' : 'low', zf,
          act({ kind: 'removeArrayItem', file: zf, path: ['agent', 'tool_permissions', 'tools', tool, 'always_allow'], value: pat }));
      }
    }
  }

  // Continue: config.yaml MCP servers (detect only) and the CLI's saved "don't ask again" answers
  for (const m of yamlListItems(h('.continue', 'config.yaml'), 'mcpServers')) {
    const cfg = { command: m.fields.command, args: [].concat(m.fields.args || []), url: m.fields.url };
    add('Continue', 'MCP server', String(m.fields.name || m.fields.command || 'server'), [cfg.url || cfg.command, ...maskArgs(cfg.args)].filter(Boolean).join(' '),
      /\benv\s*:/.test(m.text) ? 'high' : mcpRisk(cfg), h('.continue', 'config.yaml'), none('Remove it from ~/.continue/config.yaml.'));
  }
  const cperm = h('.continue', 'permissions.yaml');
  for (const it of yamlScalarList(cperm, 'allow')) add('Continue', 'Tool permission', it.value, 'Continue\'s CLI (cn) uses this without asking',
    it.value === '*' ? 'high' : ruleRisk(it.value), cperm, { kind: 'removeTomlBlock', file: cperm, block: it.text });

  // Copilot CLI: newer versions keep trusted folders as trustedFolders, settings in settings.json,
  // and the "always allow" answers per project in permissions-config.json
  const cpj = readJson(h('.copilot', 'config.json')) || {};
  (Array.isArray(cpj.trustedFolders) ? cpj.trustedFolders : []).forEach(d => add('Copilot CLI', 'Trusted folder', String(d).replace(HOME, '~'), 'Trusted folder: Copilot can read and change files here',
    d === HOME || d === '/' ? 'high' : 'low', h('.copilot', 'config.json'), { kind: 'removeArrayItem', file: h('.copilot', 'config.json'), path: ['trustedFolders'], value: d }));
  const csf = h('.copilot', 'settings.json'), csr = readJsonc(csf);
  if (csr) {
    const mode = csr.j.defaultPermissionMode;
    if (mode === 'allow-all') add('Copilot CLI', 'Permission mode', 'defaultPermissionMode: allow-all', 'Every Copilot session starts allowed to use all tools, paths and URLs without asking',
      'high', csf, csr.strict ? { kind: 'deleteKey', file: csf, path: [], key: 'defaultPermissionMode', value: mode } : none('Edit ~/.copilot/settings.json.'));
    (Array.isArray(csr.j.allowedUrls) ? csr.j.allowedUrls : []).forEach(u => add('Copilot CLI', 'Network access', String(u), 'Copilot fetches from here without asking',
      String(u).trim() === '*' ? 'medium' : 'low', csf, csr.strict ? { kind: 'removeArrayItem', file: csf, path: ['allowedUrls'], value: u } : none('Edit ~/.copilot/settings.json.')));
  }
  const cpc = h('.copilot', 'permissions-config.json');
  for (const [loc, v] of Object.entries((readJson(cpc) || {}).locations || {})) {
    const where = String(loc).replace(HOME, '~');
    (Array.isArray(v && v.allowed_directories) ? v.allowed_directories : []).forEach(d => add('Copilot CLI', 'Folder access', String(d).replace(HOME, '~'),
      `Copilot can use this folder without asking (when working in ${where})`, d === HOME || d === '/' ? 'high' : 'low', cpc,
      { kind: 'removeArrayItem', file: cpc, path: ['locations', loc, 'allowed_directories'], value: d }));
    const appr = v && v.tool_approvals;
    for (const a of Array.isArray(appr) ? appr : []) {
      const ids = [].concat(a && (a.commandIdentifiers || a.tools || a.toolName || a.name || a.server) || []);
      const kind = String(a && a.kind || 'tool');
      const shown = ids.length ? `${kind}: ${ids.join(', ')}` : kind;
      const risk = kind === 'commands' ? (ids.some(i => /^\*|^(bash|sh|zsh|node|python3?)(:|$)/.test(String(i))) || !ids.length ? 'high'
        : ids.map(i => ruleRisk(`Bash(${String(i).replace(/:\*?$/, '').replace(/:/g, ' ')})`)).sort()[0]) : kind === 'write' || kind === 'mcp' ? 'medium' : 'low';
      add('Copilot CLI', 'Tool permission', shown, `Copilot does this without asking (when working in ${where})`, risk, cpc,
        { kind: 'removeArrayItem', file: cpc, path: ['locations', loc, 'tool_approvals'], value: a });
    }
  }

  // Cline CLI: auto-approve settings (the VS Code extension keeps them in VS Code's own database, which isn't read)
  const clg = h('.cline', 'data', 'globalState.json'), aas = (readJson(clg) || {}).autoApprovalSettings;
  if (aas && aas.enabled !== false && aas.actions) {
    const on = Object.entries(aas.actions).filter(([, v]) => v === true).map(([k]) => k);
    if (on.length) add('Cline', 'Permission mode', `Auto-approve: ${on.join(', ')}`, 'Cline does these without asking',
      on.some(k => /executeAllCommands|useBrowser|useMcp/.test(k)) ? 'high' : on.some(k => /edit|execute/i.test(k)) ? 'medium' : 'low', clg,
      none('Turn these off in Cline\'s auto-approve menu.'));
  }

  // Claude Desktop extensions (each one is an MCP server with its own access)
  const extDir = appData('Claude', 'Claude Extensions');
  let exts = [];
  try { exts = fs.readdirSync(extDir); } catch {}
  for (const e of exts) {
    const mf = readJson(path.join(extDir, e, 'manifest.json'));
    if (mf) add('Claude Desktop', 'MCP server', mf.display_name || mf.name || e, `Desktop extension${mf.description ? ': ' + String(mf.description).slice(0, 120) : ''}`,
      mcpRisk({ command: mf.name, args: [JSON.stringify(mf.server || {})] }), path.join(extDir, e), none('Remove it in Claude Desktop → Settings → Extensions.'));
  }
  return out;
}

// Small YAML readers, for the simple files agents write (not general YAML). yamlListItems returns the items of a
// top-level list ("key:" followed by "- a: b" blocks) with their exact text; yamlScalarList the "- value" lines.
function yamlSection(file, key) {
  let text = '';
  try { text = fs.readFileSync(file, 'utf8'); } catch { return ''; }
  const m = text.match(new RegExp(`^${key}:[ \\t]*\\n((?:[ \\t]+.*\\n?|[ \\t]*\\n)*)`, 'm'));
  return m ? m[1] : '';
}
function yamlScalar(v) {
  v = String(v).trim();
  if (/^\[.*\]$/.test(v)) return v.slice(1, -1).split(',').map(x => yamlScalar(x)).filter(x => x !== '');
  return v.replace(/^(["'])(.*)\1$/, '$2');
}
function yamlListItems(file, key) {
  const sec = yamlSection(file, key);
  const ind = (sec.match(/^([ \t]*)- /m) || [])[1];
  if (ind === undefined) return [];
  // split only at this list's own indent, so nested lists (match:, args:) stay inside their item
  const parts = sec.split(new RegExp(`^(?=${ind}- )`, 'm')).filter(p => p.startsWith(ind + '- '));
  return parts.map(text => {
    const fields = {}; let listKey = null;
    for (const line of text.replace(/^([ \t]*)- /, '$1  ').split('\n')) {
      const kv = line.match(/^\s*([A-Za-z_][\w-]*)\s*:\s*(.*?)\s*$/), li = line.match(/^\s*-\s+(.*?)\s*$/);
      if (kv) { listKey = kv[2] === '' ? kv[1] : null; fields[kv[1]] = kv[2] === '' ? [] : yamlScalar(kv[2]); }
      else if (li && listKey) fields[listKey].push(yamlScalar(li[1]));
    }
    return { text, fields };
  });
}
function yamlScalarList(file, key) {
  const sec = yamlSection(file, key), ind = (sec.match(/^([ \t]*)- /m) || [])[1];
  if (ind === undefined) return [];
  return [...sec.matchAll(new RegExp(`^${ind}-[ \\t]+(.+?)[ \\t]*$\\n?`, 'gm'))].map(m => ({ value: yamlScalar(m[1]), text: m[0] }));
}

// Gemini CLI policy files and a small reader for the [[rule]] blocks Gemini writes (flat key = value lines)
function geminiPolicyFiles() {
  const out = [];
  const dirs = [[h('.gemini', 'policies'), 'all projects']];
  for (const proj of Object.keys((readJson(h('.gemini', 'projects.json')) || {}).projects || {}))
    if (proj !== HOME) dirs.push([path.join(proj, '.gemini', 'policies'), `project ${path.basename(proj)}`]);
  for (const [dir, label] of dirs) {
    let names = [];
    try { names = fs.readdirSync(dir).filter(n => n.endsWith('.toml')); } catch {}
    names.forEach(n => out.push([path.join(dir, n), label]));
  }
  return out;
}
function tomlValue(v) {
  v = v.trim();
  if (/^".*"$/.test(v)) { try { return JSON.parse(v); } catch { return v.slice(1, -1); } }
  if (/^'.*'$/.test(v)) return v.slice(1, -1);
  if (v === 'true' || v === 'false') return v === 'true';
  if (/^\[.*\]$/.test(v)) return [...v.slice(1, -1).matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)].map(m => (m[1] !== undefined ? JSON.parse(`"${m[1]}"`) : m[2]));
  return Number.isNaN(Number(v)) ? v : Number(v);
}
function geminiRules(file) {
  let text = '';
  try { text = fs.readFileSync(file, 'utf8'); } catch { return []; }
  const parts = text.split(/^(?=\[\[rule\]\]\s*$)/m).filter(p => /^\[\[rule\]\]/.test(p));
  return parts.map(p => {
    const fields = {};
    for (const line of p.split('\n').slice(1)) {
      const m = line.match(/^\s*([A-Za-z_]+)\s*=\s*(.+?)\s*$/);
      if (m) fields[m[1]] = tomlValue(m[2]);
    }
    return { text: p, fields };
  });
}

// AI agents installed on this Mac: command-line agents in the usual bin folders, and AI apps
const NVM_BINS = (() => { try { return fs.readdirSync(h('.nvm', 'versions', 'node')).sort().reverse().map(v => h('.nvm', 'versions', 'node', v, 'bin')); } catch { return []; } })();
const BIN_DIRS = [...(MAC ? ['/opt/homebrew/bin'] : []), '/usr/local/bin', h('.local', 'bin'), h('.opencode', 'bin'), h('.npm-global', 'bin'), h('.bun', 'bin'), h('.cargo', 'bin'), h('.volta', 'bin'),
  ...(LINUX ? ['/usr/bin', '/snap/bin', '/home/linuxbrew/.linuxbrew/bin'] : []), ...NVM_BINS,
  ...(WIN ? [appData('npm'), path.join(LOCAL_APPDATA, 'Programs'), h('scoop', 'shims'), path.join(LOCAL_APPDATA, 'Microsoft', 'WinGet', 'Links'), 'C:\\Program Files\\nodejs'] : [])];
// on Windows a command is a file with an extension (claude.cmd from npm, claude.exe from an installer)
const binFile = (dir, cmd) => (WIN ? [`${cmd}.exe`, `${cmd}.cmd`, `${cmd}.ps1`] : [cmd]).map(n => path.join(dir, n)).find(exists);
const CLI_AGENTS = { claude: ['Claude Code', 'npm uninstall -g @anthropic-ai/claude-code'], codex: ['Codex CLI', 'npm uninstall -g @openai/codex'],
  gemini: ['Gemini CLI', 'npm uninstall -g @google/gemini-cli'], 'cursor-agent': ['Cursor CLI', 'rm "$(command -v cursor-agent)"'], aider: ['Aider', 'pipx uninstall aider-chat'],
  goose: ['Goose', MAC ? 'brew uninstall block-goose-cli' : ''], opencode: ['OpenCode', 'npm uninstall -g opencode-ai'], copilot: ['Copilot CLI', 'npm uninstall -g @github/copilot'],
  qwen: ['Qwen Code', 'npm uninstall -g @qwen-code/qwen-code'], amp: ['Amp', 'npm uninstall -g @sourcegraph/amp'], crush: ['Crush', MAC ? 'brew uninstall crush' : ''], 'kiro-cli': ['Kiro', ''] };
const AI_APP_NAMES = 'Claude|ChatGPT|Codex|Cursor|Windsurf|OpenCode|Perplexity|Ollama|LM Studio|Kiro|Zed|Warp|Msty|Jan|Copilot|Gemini|Comet|Dia|Atlas|ChatGPT Atlas|Raycast|GPT4All|AnythingLLM|Void';
const AI_APPS = new RegExp(`^(${AI_APP_NAMES})\\.app$`);
// Linux: apps show up as desktop entries (menu items), wherever they came from
const DESKTOP_DIRS = ['/usr/share/applications', '/usr/local/share/applications', h('.local', 'share', 'applications'), '/var/lib/flatpak/exports/share/applications',
  h('.local', 'share', 'flatpak', 'exports', 'share', 'applications'), '/var/lib/snapd/desktop/applications'];
// Windows: apps show up as Start menu shortcuts
function windowsApps() {
  const out = [], seen = new Set(), re = new RegExp(`^(${AI_APP_NAMES})( (Desktop|Editor|AI))?$`, 'i');
  const walk = (dir, depth) => {
    let ents = [];
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const f = path.join(dir, e.name);
      if (e.isDirectory() && depth > 0) { walk(f, depth - 1); continue; }
      const name = e.name.replace(/\.lnk$/i, '');
      if (!/\.lnk$/i.test(e.name) || !re.test(name) || seen.has(name.toLowerCase())) continue;
      seen.add(name.toLowerCase());
      out.push({ name: name.replace(/ (Desktop|Editor|AI)$/i, ''), file: f });
    }
  };
  walk(appData('Microsoft', 'Windows', 'Start Menu', 'Programs'), 2);
  walk('C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs', 2);
  return out;
}
function linuxApps() {
  const out = [], seen = new Set(), re = new RegExp(`^(${AI_APP_NAMES})( (Desktop|Editor|AI))?$`, 'i');
  for (const dir of DESKTOP_DIRS) {
    let names = [];
    try { names = fs.readdirSync(dir).filter(n => n.endsWith('.desktop') && !/ai-access-auditor/.test(n)); } catch { continue; }
    for (const n of names) {
      const d = iniFields(path.join(dir, n));
      const name = d && d['Desktop Entry.Name'];
      if (!name || !re.test(name) || d['Desktop Entry.NoDisplay'] === 'true' || seen.has(name.toLowerCase())) continue;
      seen.add(name.toLowerCase());
      const file = path.join(dir, n), exec = (d['Desktop Entry.Exec'] || '').replace(/\s+%[a-zA-Z]/g, '');
      const how = dir.includes('snapd') ? `sudo snap remove ${n.split('_')[0]}` : dir.includes('flatpak') ? `flatpak uninstall ${n.replace(/\.desktop$/, '')}`
        : /\.AppImage\b/i.test(exec) ? `delete the AppImage (${exec.split(/\s+/)[0].replace(HOME, '~')})` : '';
      out.push({ name: name.replace(/ (Desktop|Editor|AI)$/i, ''), file, exec, how });
    }
  }
  return out;
}
function scanInstalledAgents() {
  const out = [];
  if (DEMO) return out;
  const seen = new Set();
  for (const dir of BIN_DIRS) for (const [cmd, [name, how]] of Object.entries(CLI_AGENTS)) {
    const f = binFile(dir, cmd);
    if (seen.has(cmd) || !f) continue;
    seen.add(cmd);
    let target = f; try { target = fs.realpathSync(f); } catch {}
    out.push({ agent: name, category: 'AI agent installed', title: `${name} (${cmd} command)`, detail: `${f.replace(HOME, '~')}${target !== f ? ` → ${target.replace(HOME, '~')}` : ''}`,
      risk: 'low', source: f, action: { kind: 'none', hint: how ? `To uninstall: ${how}` : 'Uninstall it the way you installed it.' } });
  }
  for (const a of WIN ? windowsApps() : []) out.push({ agent: a.name, category: 'AI agent installed', title: `${a.name} app`,
    detail: `Start menu: ${a.file.replace(HOME, '~')}`, risk: 'low', source: a.file,
    action: { kind: 'none', hint: 'To uninstall: Settings → Apps → Installed apps, then the ⋯ menu next to it → Uninstall.' } });
  for (const a of LINUX ? linuxApps() : []) out.push({ agent: a.name, category: 'AI agent installed', title: `${a.name} app`,
    detail: `${a.exec.replace(HOME, '~').slice(0, 120)} (${a.file.replace(HOME, '~')})`, risk: 'low', source: a.file,
    action: { kind: 'none', hint: a.how ? `To uninstall: ${a.how}` : 'Uninstall it with your package manager (for example apt remove or dnf remove).' } });
  // Desktop apps that run from anywhere (for example straight from Downloads): found by their data folder
  for (const [name, dir] of [['OpenCode', appData('ai.opencode.desktop')]]) {
    if (!exists(dir) || out.some(f => f.agent === name && f.title === `${name} app`)) continue;
    const appIn = MAC && ['/Applications', h('Applications')].some(d => exists(path.join(d, `${name}.app`)));
    if (!appIn) out.push({ agent: name, category: 'AI agent installed', title: `${name} app`, detail: `Desktop app (its data folder: ${dir.replace(HOME, '~')})`,
      risk: 'low', source: dir, action: { kind: 'none', hint: 'To uninstall, quit it and delete the app, then its data folder if you like.' } });
  }
  for (const dir of MAC ? ['/Applications', h('Applications')] : []) {
    let names = [];
    try { names = fs.readdirSync(dir).filter(n => AI_APPS.test(n)); } catch {}
    for (const n of names) out.push({ agent: n.replace(/\.app$/, ''), category: 'AI agent installed', title: `${n.replace(/\.app$/, '')} app`,
      detail: path.join(dir, n).replace(HOME, '~'), risk: 'low', source: path.join(dir, n), action: { kind: 'none', hint: 'To uninstall, quit it and move it to the Trash.' } });
  }
  return out;
}

// Agents that were uninstalled but left their settings, logins and history behind. Uninstalling a tool
// rarely removes its folder in your home, so the logins and "always allow" rules in it stay usable.
// Nothing is deleted from here: the logins and permissions inside are listed (and revocable) on their own.
const LEFTOVERS = [
  // name, data folder, commands, Mac app names, editor extension id prefixes
  ['Claude Code', h('.claude'), ['claude'], ['Claude'], ['anthropic.claude-code']],
  ['Codex CLI', h('.codex'), ['codex'], ['Codex', 'ChatGPT'], ['openai.chatgpt']],
  ['Gemini CLI', h('.gemini'), ['gemini'], ['Gemini'], ['google.geminicodeassist']],
  ['OpenCode', h('.local', 'share', 'opencode'), ['opencode'], ['OpenCode'], ['sst-dev.opencode']],
  ['Copilot CLI', h('.copilot'), ['copilot'], [], []],
  ['Cursor', h('.cursor'), ['cursor-agent', 'cursor'], ['Cursor'], []],
  ['Windsurf', h('.codeium', 'windsurf'), ['windsurf'], ['Windsurf'], ['codeium.']],
  ['Kiro', h('.kiro'), ['kiro-cli', 'kiro'], ['Kiro'], []],
  ['Goose', h('.config', 'goose'), ['goose'], ['Goose'], []],
  ['Cline', h('.cline'), ['cline'], [], ['saoudrizwan.claude-dev']],
];
function scanLeftovers() {
  const out = [];
  if (DEMO) return out;
  const pathDirs = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const dirs = [...new Set([...BIN_DIRS, ...pathDirs])];
  const appNames = new Set((WIN ? windowsApps() : LINUX ? linuxApps() : []).map(a => a.name.toLowerCase()));
  const extDirs = ['.vscode', '.cursor', '.windsurf', '.vscode-insiders', '.kiro'].map(d => h(d, 'extensions'));
  const exts = extDirs.flatMap(d => { try { return fs.readdirSync(d).map(n => n.toLowerCase()); } catch { return []; } });
  for (const [name, dir, cmds, apps, extIds] of LEFTOVERS) {
    if (!exists(dir)) continue;
    const installed = cmds.some(c => dirs.some(d => binFile(d, c)))
      || (name === 'Claude Code' && exists(h('.claude', 'local', 'claude')))
      || apps.some(a => MAC ? ['/Applications', h('Applications')].some(d => exists(path.join(d, a + '.app'))) : appNames.has(a.toLowerCase()))
      || extIds.some(id => exts.some(e => e.startsWith(id)));
    if (installed) continue;
    // what is still in there, in plain words
    const has = [];
    if (['auth.json', '.credentials.json', 'oauth_creds.json', 'gemini-credentials.json', 'hosts.yml', path.join('data', 'settings', 'providers.json')].some(n => exists(path.join(dir, n)))) has.push('a saved login');
    if (['settings.json', 'config.toml', 'config.json', 'config.yaml', 'mcp.json', 'cli-config.json'].some(n => exists(path.join(dir, n))) || exists(path.join(dir, 'settings'))) has.push('settings and permissions');
    if (['projects', 'sessions', 'tmp', 'storage', 'history', 'session-state'].some(n => exists(path.join(dir, n))) || exists(path.join(dir, 'opencode.db'))) has.push('conversation history');
    if (!has.length) continue;
    const where = dir.replace(HOME, '~');
    out.push({ agent: name, category: 'Left behind', title: `${name} isn't installed, but its data is still here`,
      detail: `${where}: ${has.join(', ')}`, risk: has.includes('a saved login') ? 'medium' : 'low', source: dir,
      action: { kind: 'none', hint: `If you removed ${name} for good, delete ${where}${MAC ? ' (move it to the Trash)' : ''}. Its logins and permissions are also listed one by one, so you can remove just those.` } });
  }
  return out;
}

// Agent skills: folders of instructions (and often scripts) an agent loads and follows on its own
const SKILL_ROOTS = [
  ['Claude Code', h('.claude', 'skills')], ['Codex CLI', h('.codex', 'skills')], ['Gemini CLI', h('.gemini', 'skills')],
  ['Cursor', h('.cursor', 'skills')], ['Copilot CLI', h('.copilot', 'skills')], ['OpenCode', h('.config', 'opencode', 'skill')],
  ['OpenCode', h('.config', 'opencode', 'skills')], ['Any agent', h('.agents', 'skills')],
];
function skillRoots() {
  const roots = [...SKILL_ROOTS];
  for (const proj of Object.keys((readJson(h('.claude.json')) || {}).projects || {}))
    if (proj !== HOME) roots.push(['Claude Code', path.join(proj, '.claude', 'skills')]);
  return roots;
}
const CODE_RE = /\.(sh|bash|zsh|py|js|mjs|cjs|ts|rb|pl|swift|applescript|scpt)$/i;
function filesIn(dir, depth = 3, out = []) {
  if (depth < 0 || out.length > 400) return out;
  let ents = [];
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of ents) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const f = path.join(dir, e.name);
    if (e.isDirectory()) filesIn(f, depth - 1, out); else out.push(f);
  }
  return out;
}
function scanSkills() {
  const out = [];
  if (DEMO) return out;
  for (const [agent, root] of skillRoots()) {
    let ents = [];
    try { ents = fs.readdirSync(root, { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      if (!e.isDirectory() && !e.isSymbolicLink()) continue;
      if (e.name === 'synced') continue; // managed by claude.ai, not installed on this Mac
      const dir = path.join(root, e.name);
      let md = '';
      try { md = fs.readFileSync(path.join(dir, 'SKILL.md'), 'utf8'); } catch { continue; }
      const fm = (md.match(/^---\n([\s\S]*?)\n---/) || [])[1] || '';
      const name = ((fm.match(/^name:\s*(.+)$/m) || [])[1] || e.name).trim().replace(/^["']|["']$/g, '');
      const desc = ((fm.match(/^description:\s*(.+)$/m) || [])[1] || '').trim().replace(/^["']|["']$/g, '');
      const scripts = filesIn(dir).filter(f => CODE_RE.test(f));
      const risky = RISKY_TOOL_RE.test((desc + ' ' + md.slice(0, 4000)).toLowerCase());
      out.push({
        agent, category: 'Agent skill', title: name,
        detail: `${desc ? desc.slice(0, 160) + ' · ' : ''}${scripts.length ? `includes ${scripts.length} script${scripts.length > 1 ? 's' : ''} the agent can run` : 'instructions only'} (${dir.replace(HOME, '~')})`,
        risk: risky && scripts.length ? 'high' : scripts.length || risky ? 'medium' : 'low', source: dir,
        action: { kind: 'removeFolder', dir },
      });
    }
  }
  return out;
}

// AI agents running right now with approvals switched off, or as administrator
const AGENT_PROC_RE = /(?:^|\/)(claude|codex|gemini|aider|cursor-agent|goose|opencode|opencode-cli|copilot|qwen|amp|crush|kiro-cli)(?=\s|$)|@anthropic-ai\/claude-code|@openai\/codex|@google\/gemini-cli|@github\/copilot|@sourcegraph\/amp|opencode-ai/;
const AGENT_NAMES = { claude: 'Claude Code', codex: 'Codex CLI', gemini: 'Gemini CLI', aider: 'Aider', 'cursor-agent': 'Cursor CLI', goose: 'Goose', opencode: 'OpenCode', 'opencode-cli': 'OpenCode', copilot: 'Copilot CLI', qwen: 'Qwen Code', amp: 'Amp', crush: 'Crush', 'kiro-cli': 'Kiro' };
function dangerReason(agentKey, cmd) {
  const rules = [
    [/--dangerously-skip-permissions\b|--permission-mode[ =]bypassPermissions/, 'skips every permission prompt'],
    [/--dangerously-bypass-approvals-and-sandbox\b/, 'runs anything with no approvals and no sandbox'],
    [/--yolo\b|--approval-mode[ =]yolo\b/, 'approves every action automatically (YOLO mode)'],
    [/(?:--sandbox|\s-s)[ =]danger-full-access/, 'runs with no sandbox (full disk and network access)'],
    [/--full-auto\b/, 'runs commands without asking'],
    [/--yes-always\b/, 'says yes to everything'],
    [/--allow-all-tools\b|--allow-all\b/, 'may use every tool without asking'],
  ];
  if (agentKey === 'gemini') rules.push([/(?:^|\s)-y(?=\s|$)/, 'approves every action automatically (YOLO mode)']);
  if (agentKey === 'cursor-agent') rules.push([/(?:^|\s)(?:--force|-f)(?=\s|$)/, 'runs commands without asking (--force)']);
  const hit = rules.find(([re]) => re.test(cmd));
  return hit && hit[1];
}
// every process: pid, parent, user id, running time, full command (BSD ps on a Mac, procps on Linux,
// PowerShell on Windows, where it is slow enough that a list less than a few seconds old is reused)
const PS_ALL = MAC ? ['-axo', 'pid=,ppid=,uid=,etime=,command='] : ['-eo', 'pid=,ppid=,uid=,etime=,args='];
let procCache = { at: 0, list: [] };
// Windows: only the four properties needed, which is much faster than asking for whole process objects
const PS_PROCS = '$n = Get-Date; Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,CreationDate,CommandLine | ForEach-Object { '
  + '$s = if ($_.CreationDate) { [int]($n - $_.CreationDate).TotalSeconds } else { 0 }; '
  + '"{0}`t{1}`t{2}`t{3}" -f $_.ProcessId, $_.ParentProcessId, $s, ($_.CommandLine -replace "[`r`n`t]", " ") }';
function parseWinProcs(out) {
  const list = [];
  for (const line of out.split(/\r?\n/)) {
    const [pid, ppid, secs, ...cmd] = line.split('\t');
    if (!/^\d+$/.test(pid || '')) continue;
    const t = Number(secs) || 0, d = Math.floor(t / 86400), hh = String(Math.floor(t % 86400 / 3600)).padStart(2, '0'), mm = String(Math.floor(t % 3600 / 60)).padStart(2, '0'), ss = String(t % 60).padStart(2, '0');
    list.push({ pid, ppid, uid: '', etime: `${d ? d + '-' : ''}${hh}:${mm}:${ss}`, cmd: cmd.join(' ').trim() });
  }
  return list;
}
function processList(maxAge = 0) {
  // on Windows the helper below keeps the list fresh (every few seconds), so scans never wait for PowerShell
  if (maxAge && Date.now() - procCache.at < (WIN && winHelper ? 30000 : maxAge)) return procCache.list;
  let list = [];
  if (WIN) list = parseWinProcs(psh(PS_PROCS));
  else {
    for (const line of sh('ps', PS_ALL, 5000).split('\n')) {
      const m = line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/);
      if (m) list.push({ pid: m[1], ppid: m[2], uid: m[3], etime: m[4], cmd: m[5] });
    }
  }
  procCache = { at: Date.now(), list };
  return list;
}
// Windows: one PowerShell stays open and reports the process list every few seconds and the scheduled tasks
// every minute. Starting PowerShell each time would cost close to a second; it quits when this program does.
let winHelper = null;
function startWindowsHelper() {
  if (!WIN || DEMO || winHelper) return;
  const script = `[Console]::OutputEncoding=[Text.Encoding]::UTF8; $i = 0; while ($true) { `
    + `if (-not (Get-Process -Id ${process.pid} -ErrorAction SilentlyContinue)) { exit }; `
    + `${PS_PROCS}; '@@PROCS'; if ($i % 8 -eq 0) { ${PS_TASKS}; '@@TASKS' }; $i++; Start-Sleep -Seconds 6 }`;
  winHelper = require('child_process').spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
  let buf = '';
  winHelper.stdout.setEncoding('utf8');
  winHelper.stdout.on('data', d => {
    buf += d;
    for (let m; (m = buf.match(/^@@(PROCS|TASKS)\r?$/m));) {
      const chunk = buf.slice(0, m.index);
      buf = buf.slice(m.index + m[0].length).replace(/^\n/, '');
      if (m[1] === 'PROCS') procCache = { at: Date.now(), list: parseWinProcs(chunk) };
      else tasksCache = { at: Date.now(), list: parseWinTasks(chunk) };
    }
  });
  winHelper.on('exit', () => { winHelper = null; });
  process.on('exit', () => { try { if (winHelper) winHelper.kill(); } catch {} });
}
// A command line as [program, ...arguments]. Windows programs can be quoted or have spaces in their path.
function cmdTokens(cmd) {
  const s = String(cmd || '').trim();
  const q = s.match(/^"([^"]*)"\s*(.*)$/s) || (WIN && s.match(/^([A-Za-z]:\\.*?\.(?:exe|cmd|bat|com))(?=\s|$)\s*(.*)$/is));
  let [first, rest] = q ? [q[1], q[2]] : (i => i < 0 ? [s, ''] : [s.slice(0, i), s.slice(i).trim()])(s.search(/\s/));
  // macOS and Linux list commands without quotes, so a program in a folder with a space ("Application Support")
  // looks like two words: take more words until the path is a real file
  if (!q && first.startsWith('/') && rest && !isFile(first)) {
    const words = rest.split(/(\s+)/);
    for (let k = 0, cand = first; k < words.length && k < 20; k += 2) {
      cand += (words[k - 1] || ' ') + words[k];
      if (isFile(cand)) { first = cand; rest = words.slice(k + 2).join('').trim(); break; }
    }
  }
  return [first, ...(rest ? rest.split(/\s+/).map(t => t.replace(/^"(.*)"$/, '$1')) : [])];
}
function isFile(f) { try { return fs.statSync(f).isFile(); } catch { return false; } }
// the program's short name: "node", "claude" (no folder, no .exe)
const exeBase = cmd => path.basename(cmdTokens(cmd)[0] || '').replace(/\.(exe|cmd|bat|com)$/i, '');
// for matching patterns written for macOS and Linux: forward slashes, no .exe, no quotes
const normCmd = cmd => WIN ? String(cmd).replace(/\\/g, '/').replace(/\.(exe|cmd|bat)(?=["\s]|$)/gi, '').replace(/"/g, '') : String(cmd);
function procCwd(pid) {
  if (LINUX) { try { return fs.readlinkSync(`/proc/${pid}/cwd`); } catch { return ''; } }
  if (WIN) return ''; // another process's folder isn't available on Windows without extra tools
  return (sh('lsof', ['-a', '-p', pid, '-d', 'cwd', '-Fn'], 2000).match(/^n(.*)$/m) || [])[1] || '';
}
// Which agent (if any) a process is. Only the program actually running counts, not text in its arguments.
function agentKey(cmd) {
  const tokens = cmdTokens(cmd);
  const exe = exeBase(cmd).toLowerCase();
  if (AGENT_NAMES[exe]) return exe;
  if (!/^(node|bun|deno|python3?(\.\d+)?|pythonw?)$/.test(exe)) return null;
  const script = normCmd(tokens.slice(1).find(t => !t.startsWith('-')) || '');
  const pm = script.match(AGENT_PROC_RE);
  return pm ? pm[1] || (pm[0].match(/claude|codex|gemini|copilot|amp|opencode/) || ['agent'])[0] : null;
}
function scanProcesses() {
  const out = [];
  if (DEMO) return out;
  const procs = processList(3000);
  out.push(...scanInstalls(procs));
  const byPid = new Map(procs.map(p => [p.pid, p]));
  for (const { pid, ppid, uid, etime, cmd } of procs) {
    if (Number(pid) === process.pid) continue;
    // Some agents (Gemini CLI) relaunch themselves as a child process: report the session once, at the top
    const key = agentKey(cmd);
    if (key && byPid.has(ppid) && agentKey(byPid.get(ppid).cmd) === key) continue;
    if (!key) continue;
    const agent = AGENT_NAMES[key] || key;
    const reason = dangerReason(key, cmd);
    const root = uid === '0';
    if (!reason && !root) continue;
    const cwd = procCwd(pid);
    const shortCmd = cmd.replace(HOME, '~').slice(0, 220);
    out.push({
      agent, category: 'Running agent', title: root ? `${agent} is running as administrator (root)` : `${agent} ${reason}`,
      detail: `Process ${pid}, running for ${etime}${cwd ? ` in ${cwd.replace(HOME, '~')}` : ''}: ${shortCmd}`,
      risk: 'high', source: `process ${pid}`,
      action: root ? { kind: 'none', hint: `Stop it with: sudo kill ${pid}` } : { kind: 'killProcess', pid: Number(pid), cmdStart: cmd.slice(0, 200), tree: true },
    });
  }
  return out;
}

// Someone (you, or an agent) is installing or setting up an AI tool right now: an MCP server, agent skills, an agent plugin
const SHELL_RE = /^-?(zsh|bash|sh|fish|dash|login|tmux|screen|cmd|powershell|pwsh|windowsterminal|wt)$/;
const SETUP_RE = /^(setup|install|init|add|configure|register|enable|login|onboard)$/i;
const AGENT_PKG_RE = /mcp|agent|claude|codex|gemini|copilot|cursor|skill|anthropic|openai|aider|goose|opencode|qwen|crush|kiro|llm|gpt/i;
function descendants(procs, pid) {
  const kids = new Map();
  for (const p of procs) { if (!kids.has(p.ppid)) kids.set(p.ppid, []); kids.get(p.ppid).push(p); }
  const out = [], todo = [pid];
  while (todo.length && out.length < 200) for (const k of kids.get(todo.pop()) || []) { out.push(k); todo.push(k.pid); }
  return out;
}
function connections(pids) {
  if (!pids.length) return [];
  if (WIN) {
    const want = new Set(pids.map(String));
    return [...new Set(netstat().filter(x => !x.listening && want.has(x.pid) && !/^(127\.|\[::1\]|\[::ffff:127\.)/.test(x.remote) && !/:0$/.test(x.remote))
      .map(x => `${x.remote} (${x.proc})`))];
  }
  if (LINUX) {
    const want = new Set(pids.map(String)), seen = new Set();
    for (const l of sh('ss', ['-tnpH', 'state', 'established'], 4000).split('\n')) {
      const c = l.trim().split(/\s+/), u = [...l.matchAll(/\("([^"]+)",pid=(\d+)/g)].find(m => want.has(m[2]));
      if (u && c[3] && !/^(127\.|\[::1\]|\[::ffff:127\.)/.test(c[3])) seen.add(`${c[3]} (${u[1]})`);
    }
    return [...seen];
  }
  const lines = sh('lsof', ['-nP', '-iTCP', '-sTCP:ESTABLISHED', '-a', '-p', pids.join(',')], 4000).split('\n').slice(1);
  const seen = new Set();
  for (const l of lines) {
    const c = l.trim().split(/\s+/);
    const remote = (c[8] || '').split('->')[1];
    if (remote && !/^(127\.|\[::1\]|localhost)/.test(remote)) seen.add(`${remote} (${c[0]})`);
  }
  return [...seen];
}
function scanInstalls(procs) {
  const out = [];
  const byPid = new Map(procs.map(p => [p.pid, p]));
  const hits = [];
  for (const p of procs) {
    const pkg = execPackage(normCmd(p.cmd));
    const mcpAdd = /(?:^|\/)(claude|codex|gemini|cursor-agent|opencode|goose|amp|copilot)\s+(mcp|plugins?|extensions?)\s+(add|install)\b/.exec(normCmd(p.cmd));
    if (!pkg && !mcpAdd) continue;
    const parent = byPid.get(p.ppid);
    const parentExe = parent ? exeBase(parent.cmd).toLowerCase() : '';
    let info = null, name, isTool, isSetup;
    if (mcpAdd) { name = `${mcpAdd[1]} ${mcpAdd[2]} ${mcpAdd[3]}`; isTool = true; isSetup = true; }
    else {
      name = pkg.name; info = pkgInfo(pkg.name);
      isTool = AGENT_PKG_RE.test(name) || !!(info && (info.mcp || /\b(mcp|agent|claude|codex|cursor|copilot|skills?)\b/i.test(info.text)));
      // An MCP client starting its own server isn't an install; a shell (you, or an agent's Bash tool) running setup is
      isSetup = SHELL_RE.test(parentExe) || pkg.rest.some(a => SETUP_RE.test(a));
    }
    if (isTool && isSetup) hits.push({ p, name, info });
  }
  const hitPids = new Set(hits.map(x => x.p.pid));
  for (const { p, name, info } of hits) {
    // report each install once, at its top-most process
    let up = byPid.get(p.ppid), nested = false;
    for (let n = 0; up && n < 30; n++, up = byPid.get(up.ppid)) if (hitPids.has(up.pid)) { nested = true; break; }
    if (nested) continue;
    // who started it: an AI agent somewhere above it, or you
    let by = 'You';
    for (let n = 0, a = byPid.get(p.ppid); a && n < 30; n++, a = byPid.get(a.ppid)) {
      const exe = exeBase(a.cmd).toLowerCase();
      const k = AGENT_NAMES[exe] ? exe : (normCmd(a.cmd).match(AGENT_PROC_RE) || [])[1];
      if (k && AGENT_NAMES[k]) { by = AGENT_NAMES[k]; break; }
      if (/Claude\.app|Cursor\.app|Windsurf\.app/.test(a.cmd)) { by = (a.cmd.match(/(Claude|Cursor|Windsurf)\.app/) || [])[1]; break; }
      if (WIN && /[\\/](AnthropicClaude|cursor|Windsurf)[\\/]/i.test(a.cmd)) { by = /cursor/i.test(a.cmd) ? 'Cursor' : /windsurf/i.test(a.cmd) ? 'Windsurf' : 'Claude Desktop'; break; }
    }
    const kids = descendants(procs, p.pid);
    const net = connections([p.pid, ...kids.map(k => k.pid)]);
    const helpers = [...new Set(kids.map(k => exeBase(k.cmd)))].filter(x => !/^(sh|bash|zsh|node|cmd|conhost|powershell|pwsh)$/i.test(x)).slice(0, 6);
    const text = `${name} ${info ? info.text : ''}`.toLowerCase();
    out.push({
      agent: by, category: 'AI tool install', title: `Installing an AI tool: ${name}`,
      detail: `${info && info.description ? `"${info.description.slice(0, 160)}" · ` : ''}Process ${p.pid}, running for ${p.etime}${helpers.length ? `, using ${helpers.join(', ')}` : ''}`
        + `${net.length ? ` · Connected to the internet: ${net.slice(0, 4).join(', ')}` : ''} · ${p.cmd.replace(HOME, '~').slice(0, 160)}`,
      risk: RISKY_TOOL_RE.test(text) || by !== 'You' ? 'high' : 'medium', source: `process ${p.pid}`,
      action: p.uid === '0' ? { kind: 'none', hint: `Stop it with: sudo kill ${p.pid}` } : { kind: 'killProcess', pid: Number(p.pid), cmdStart: p.cmd.slice(0, 200), tree: true },
    });
  }
  return out;
}

// ---------- uploads: apps sending data from this Mac to another computer ----------
// nettop reports how many bytes each process has sent on each connection (no admin rights needed).
// Sampled every 2 seconds, so a connection that opens and closes in between can slip through.
const UPLOAD_WINDOW = 10 * 60e3;
const AI_LIMIT = 64 * 1024, ANY_LIMIT = 20 * 1024 * 1024;
const SYSTEM_EXE_RE = MAC ? /^\/(System|usr\/libexec|usr\/sbin|sbin|usr\/bin\/(nsurlsessiond|trustd))\//
  : /^\/(usr\/lib\/(systemd|apt|snapd|packagekit|fwupd)|lib\/systemd|usr\/libexec|usr\/sbin|sbin)\//;
const OWN_APP_RE = /AI Access Auditor\.app|AI Access Auditor\.exe|\/ai-access-auditor(\.bin)?(\s|$)|\/AI Access Auditor\/|\.mount_AI-Acc/;
const SENSITIVE_RE = /\/\.ssh\/|\/\.aws\/|\/\.config\/(gh|gcloud)\/|\/\.kube\/|\/\.gnupg\/|\/\.docker\/config|\/Keychains\/|\/\.env(\.|$)|\/Cookies$|\/Login Data$|\/\.npmrc$|\/\.netrc$|\/\.git-credentials$|credentials/i;
const INTERP_RE = /^(node|python3?(\.\d+)?|Python|ruby|perl|bun|deno|php|java)$/;
const uploads = { conns: new Map(), sent: new Map(), primed: false, timer: null, ps: null };
function uploadStore() { const j = readJson(UPLOADS_FILE) || {}; return { events: j.events || [], trusted: j.trusted || [] }; }
function saveUploads(st) { saveFile(UPLOADS_FILE, JSON.stringify(st, null, 2)); }
function fmtBytes(n) { return n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} bytes`; }
// "the app" for trust purposes: the program, plus the script when the program is an interpreter
// the program's path; Mac apps have spaces in their paths, so use the .app bundle when there is one
function exeOf(cmd) { const m = cmd.match(/^(.+?\.app)\//); return m ? m[1] : (cmdTokens(cmd)[0] || ''); }
function appName(cmd) { const e = exeOf(cmd); return path.basename(e).replace(/\.app$/, ''); }
function appKey(cmd) {
  const t = cmd.split(/\s+/);
  const exe = exeOf(cmd);
  // where the program's own name ends (inside a bundle, or the first word)
  let k = t.findIndex(x => /\/Contents\/MacOS\/[^/]+$/.test(x));
  if (k < 0) k = 0;
  const bin = path.basename(t[k] || '');
  if (!INTERP_RE.test(bin)) return exe;
  // node, python…: trust is per script, never the interpreter as a whole
  let script = '(inline code)';
  for (let i = k + 1; i < t.length; i++) {
    if (/^(-c|-e|--eval|-p|--print)$/.test(t[i])) break;      // code given on the command line
    if (t[i] === '-m') { script = `-m ${t[i + 1] || ''}`; break; } // python -m module
    if (!t[i].startsWith('-')) { script = t[i]; break; }
  }
  return `${exe} ${script}`;
}
function startUploadMonitor() {
  // Windows only shows how much each connection sent to administrators, so uploads aren't watched there
  if (DEMO || uploads.timer || WIN) return;
  // tests (preview mode only) can replay recorded nettop output instead of watching the real network
  const replay = process.env.AUDIT_PREVIEW && process.env.AUDIT_NETTOP_REPLAY;
  if (replay) {
    setTimeout(() => {
      const samples = fs.readFileSync(replay, 'utf8').split(/^,.*\n/m).map(x => x.split('\n').filter(Boolean)).filter(x => x.length);
      samples.forEach(handleSample);
    }, 4000).unref();
    uploads.timer = true;
    return;
  }
  // one snapshot every 2 seconds: nettop's streaming mode is far heavier than a quick snapshot
  let busy = false;
  if (LINUX) {
    // ss reports how much each of your processes has sent on each TCP connection (bytes_sent), no admin rights needed
    uploads.timer = setInterval(() => {
      if (busy) return;
      busy = true;
      execFile('ss', ['-tinpH'], { timeout: 5000, maxBuffer: 8 << 20 }, (err, out) => {
        busy = false;
        if (!err && out) ingestSample(ssRecords(out));
      });
    }, 2000);
    uploads.timer.unref();
    return;
  }
  uploads.timer = setInterval(() => {
    if (busy) return;
    busy = true;
    execFile('nettop', ['-L', '1', '-n', '-x', '-J', 'bytes_out'], { timeout: 5000, maxBuffer: 8 << 20 }, (err, out) => {
      busy = false;
      if (err || !out) return;
      handleSample(out.split('\n').filter(l => l && !l.startsWith(',')));
    });
  }, 2000);
  uploads.timer.unref();
}
function parseRemote(conn) {
  const m = conn.match(/^(tcp|udp)[46]\s+(\S+)<->(\S+)$/);
  if (!m || m[3].startsWith('*')) return null;
  const r = m[3];
  const v4 = r.match(/^(\d+\.\d+\.\d+\.\d+):(\d+)$/);
  const ip = v4 ? v4[1] : r.replace(/\.\d+$/, ''), port = v4 ? v4[2] : (r.match(/\.(\d+)$/) || [])[1];
  if (/^(127\.|0\.|169\.254\.|::1$|fe80:|::ffff:127\.)/i.test(ip)) return null;
  return { ip, port, key: `${m[1]} ${m[2]}<->${r}` };
}
// nettop -x -J bytes_out: a "name.pid,bytes" line for each process, then a line per connection
function handleSample(lines) {
  const recs = [];
  let pid = null;
  for (const line of lines) {
    const pm = line.match(/^(.*)\.(\d+),(\d*),?$/);
    if (pm && !/^(tcp|udp)[46]\s/.test(line)) { pid = pm[2]; continue; }
    const cm = line.match(/^([^,]*),(\d*),?$/);
    if (!cm || !pid) continue;
    const rem = parseRemote(cm[1]);
    if (rem) recs.push({ pid, rem, out: Number(cm[2] || 0) });
  }
  ingestSample(recs);
}
// ss -tinpH: a line per connection ("ESTAB 0 0 local peer users:((name,pid=…))"), then an indented line with bytes_sent:N
function ssRecords(text) {
  const recs = [];
  let cur = null;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    if (!/^\s/.test(line)) {
      const c = line.trim().split(/\s+/), u = line.match(/users:\(\("[^"]*",pid=(\d+)/);
      cur = c.length >= 5 && u ? { pid: u[1], local: c[3], peer: c[4] } : null;
      continue;
    }
    if (!cur) continue;
    const b = line.match(/\bbytes_sent:(\d+)/) || line.match(/\bbytes_acked:(\d+)/);
    const m = cur.peer.match(/^\[?(.+?)\]?:(\d+)$/);
    const ip = m && m[1].replace(/^::ffff:/, '').replace(/%\w+$/, '');
    if (b && ip && !/^(127\.|0\.|169\.254\.|::1$|fe80:)/i.test(ip)) recs.push({ pid: cur.pid, rem: { ip, port: m[2], key: `tcp ${cur.local}<->${cur.peer}` }, out: Number(b[1]) });
    cur = null;
  }
  return recs;
}
function ingestSample(recs) {
  const now = Date.now();
  const live = new Set();
  for (const { pid, rem, out } of recs) {
    const ck = `${pid}|${rem.key}`;
    live.add(ck);
    const prev = uploads.conns.get(ck);
    // connections already open when we start only count from now on
    const delta = prev == null ? (uploads.primed ? out : 0) : Math.max(0, out - prev);
    uploads.conns.set(ck, out);
    if (!delta) continue;
    const sk = `${pid}|${rem.ip}`;
    const e = uploads.sent.get(sk) || { pid, ip: rem.ip, port: rem.port, chunks: [] };
    e.chunks.push([now, delta]); e.port = rem.port;
    uploads.sent.set(sk, e);
  }
  for (const k of uploads.conns.keys()) if (!live.has(k)) uploads.conns.delete(k);
  uploads.primed = true;
  checkUploads(now);
}
function checkUploads(now) {
  let procs = null, st = null, changed = false;
  for (const [sk, e] of uploads.sent) {
    e.chunks = e.chunks.filter(([t]) => now - t < UPLOAD_WINDOW);
    if (!e.chunks.length) { uploads.sent.delete(sk); continue; }
    const total = e.chunks.reduce((a, [, b]) => a + b, 0);
    if (total < AI_LIMIT) continue;
    if (!procs) {
      // the process list is reused for a few seconds; busy apps cross the small limit all the time
      if (!uploads.ps || now - uploads.ps.at > 5000) {
        uploads.ps = { at: now, list: processList() };
      }
      procs = uploads.ps.list;
      st = uploadStore();
    }
    const byPid = new Map(procs.map(p => [p.pid, p]));
    let p = byPid.get(e.pid);
    if (!p && now - uploads.ps.at > 1000) { uploads.ps.at = 0; continue; } // refresh on the next sample
    if (!p || Number(p.pid) === process.pid || p.ppid === String(process.pid)) continue;
    const exe = exeOf(p.cmd);
    if (SYSTEM_EXE_RE.test(exe) || OWN_APP_RE.test(p.cmd)) continue;
    const key = appKey(p.cmd);
    if (st.trusted.includes(key)) continue;
    // started by an AI agent? (the agent itself talking to its model service is expected, so only its helpers count)
    const agentOf = q => { const x = exeBase(q.cmd).toLowerCase(); const k = AGENT_NAMES[x] ? x : (normCmd(q.cmd).match(AGENT_PROC_RE) || [])[1]; return k && AGENT_NAMES[k]; };
    if (agentOf(p)) continue;
    let by = null;
    for (let n = 0, a = byPid.get(p.ppid); a && n < 30; n++, a = byPid.get(a.ppid)) if ((by = agentOf(a))) break;
    if (!by && total < ANY_LIMIT) continue;
    let ev = st.events.find(x => x.key === key && x.ip === e.ip && now - Date.parse(x.firstAt) < 24 * 3600e3);
    if (!ev) {
      // the files it has open that could matter: secrets, and your own files
      const files = openFiles(p.pid).filter(f => SENSITIVE_RE.test(f)
        || (f.startsWith(HOME) && !/\/(Library|\.cache)\//.test(f) && !/\.(dylib|so|node|pyc)$|\.so\.\d/.test(f)));
      ev = { key, ip: e.ip, port: e.port, pid: Number(p.pid), cmd: p.cmd.slice(0, 300), name: (() => { const n = appName(p.cmd); const sc = appKey(p.cmd).slice(exeOf(p.cmd).length).trim(); return INTERP_RE.test(n) && sc ? `${n} (${path.basename(sc)})` : n; })(), by, bytes: 0, firstAt: new Date(now).toISOString(),
        files: [...new Set(files)].sort((a, b) => SENSITIVE_RE.test(b) - SENSITIVE_RE.test(a)).slice(0, 6) };
      st.events.push(ev);
      log(`UPLOAD ${ev.name} (process ${ev.pid}${by ? `, started by ${by}` : ''}) sending to ${e.ip}:${e.port}`);
      changed = true;
    }
    if (total > ev.bytes) { ev.bytes = total; ev.lastAt = new Date(now).toISOString(); st.dirty = true; }
  }
  if (st && (changed || st.dirty)) {
    delete st.dirty;
    st.events = st.events.filter(x => now - Date.parse(x.firstAt) < 24 * 3600e3).slice(-200);
    saveUploads(st);
  }
  if (changed) { changedFlag = true; flushEvents(); }
}
// regular files a process has open
function openFiles(pid) {
  const files = [];
  if (LINUX) {
    let fds = [];
    try { fds = fs.readdirSync(`/proc/${pid}/fd`).slice(0, 4000); } catch { return files; }
    for (const fd of fds) {
      try { const f = fs.readlinkSync(`/proc/${pid}/fd/${fd}`); if (f.startsWith('/') && fs.statSync(f).isFile()) files.push(f); } catch {}
    }
    return files;
  }
  let reg = false; // lsof -Ftn: a "tREG" line, then the "n<path>" line
  for (const l of sh('lsof', ['-p', pid, '-Ftn'], 3000).split('\n')) {
    if (l[0] === 't') reg = l === 'tREG';
    else if (l[0] === 'n' && reg) files.push(l.slice(1));
  }
  return files;
}
function scanUploads() {
  const out = [];
  if (DEMO) return out;
  const { events } = uploadStore();
  for (const ev of events) {
    if (Date.now() - Date.parse(ev.firstAt) > 24 * 3600e3) continue;
    const sensitive = ev.files.filter(f => SENSITIVE_RE.test(f));
    const port = ev.port === '443' ? '443, secure web' : ev.port === '80' ? '80, plain web' : ev.port === '22' ? '22, SSH' : ev.port;
    out.push({
      agent: ev.by || ev.name, category: 'Data upload', title: `${ev.name} is sending data to ${ev.ip}`,
      detail: `${fmtBytes(ev.bytes)} sent to ${ev.ip} (port ${port}) since ${new Date(ev.firstAt).toLocaleTimeString()}`
        + `${ev.by ? ` · Started by ${ev.by}` : ''}`
        + `${ev.files.length ? ` · Files it has open: ${ev.files.map(f => f.replace(HOME, '~')).join(', ')}` : ''}`
        + ` · Process ${ev.pid}: ${ev.cmd.replace(HOME, '~').slice(0, 160)}`,
      risk: ev.by || sensitive.length ? 'high' : 'medium', source: `upload ${ev.key} -> ${ev.ip}`,
      action: { kind: 'killProcess', pid: ev.pid, cmdStart: ev.cmd.slice(0, 200), tree: true },
    });
  }
  return out;
}
function trustUploader(findingId) {
  const f = scanAll().findings.find(x => x.id === findingId && x.category === 'Data upload');
  if (!f) throw new Error('Upload not found. Rescan.');
  const st = uploadStore();
  const ev = st.events.find(x => `upload ${x.key} -> ${x.ip}` === f.source.replace('~', HOME) || `upload ${x.key} -> ${x.ip}`.replace(HOME, '~') === f.source);
  if (!ev) throw new Error('Upload not found. Rescan.');
  if (!st.trusted.includes(ev.key)) st.trusted.push(ev.key);
  st.events = st.events.filter(x => x.key !== ev.key);
  saveUploads(st);
  log(`UPLOAD trusted from now on: ${ev.key.replace(HOME, '~')}`);
  return { message: `${ev.name} can send data without asking from now on. Undo it under Decisions.` };
}
function untrustUploader(key) {
  const st = uploadStore();
  st.trusted = st.trusted.filter(k => k !== key);
  saveUploads(st);
  log(`UPLOAD no longer trusted: ${key.replace(HOME, '~')}`);
  return { message: 'It will be watched again.' };
}

// Privileges every agent inherits from your account: admin rights, SSH keys, and hosting and developer logins
let sudoCache = { at: 0, ok: false }, winAdminCache = { at: 0, groups: '', uac: '' };
function demoInherited() {
  return [{ agent: 'Your account', category: 'Inherited credential', title: 'SSH key: ~/.ssh/id_ed25519', detail: 'Loaded in ssh-agent: any agent can use it to log in to servers or push code', risk: 'medium', source: 'ssh-agent', action: { kind: 'none', hint: 'ssh-add -D' } }];
}
function scanInherited() {
  const out = [];
  const add = (agent, category, title, detail, risk, source, hint) => out.push({ agent, category, title, detail, risk, source, action: { kind: 'none', hint } });
  if (DEMO) return out.concat(demoInherited());
  if (!WIN && Date.now() - sudoCache.at > 10 * 60e3) {
    let ok = false;
    try { execFileSync('sudo', ['-n', 'true'], { stdio: 'ignore', timeout: 3000 }); ok = true; } catch {}
    sudoCache = { at: Date.now(), ok };
  }
  // Windows: an administrator account that gets admin rights without being asked (UAC off, or set to never prompt)
  if (WIN) {
    if (Date.now() - winAdminCache.at > 10 * 60e3) winAdminCache = { at: Date.now(), groups: sh('whoami', ['/groups'], 5000), uac: sh('reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'], 5000) };
    const isAdmin = /S-1-5-32-544/.test(winAdminCache.groups), uac = winAdminCache.uac;
    const val = k => { const m = uac.match(new RegExp(`\\s${k}\\s+REG_DWORD\\s+0x([0-9a-f]+)`, 'i')); return m ? parseInt(m[1], 16) : null; };
    if (isAdmin && (val('EnableLUA') === 0 || val('ConsentPromptBehaviorAdmin') === 0)) add('Your account', 'Admin rights',
      val('EnableLUA') === 0 ? 'User Account Control is off' : 'Admin rights without asking',
      'Your account is an administrator and Windows never asks before a program uses those rights, so any agent you run can change the whole system',
      'high', 'User Account Control', 'Turn User Account Control back on: Start → "Change User Account Control settings", and choose one of the top two levels.');
  }
  if (sudoCache.ok) add('Your account', 'Admin rights', 'sudo works without a password',
    'Any agent you run can become administrator without asking you', 'high', '/etc/sudoers', 'Remove NOPASSWD from your sudoers entry (sudo visudo), or run "sudo -k" to end a cached sudo session.');

  // Linux: the docker group can start a container that mounts the whole disk as root, without a password
  if (LINUX && /(^|\s)docker(\s|$)/.test(sh('id', ['-Gn'], 3000).trim())) add('Your account', 'Admin rights', 'Member of the docker group',
    'Any agent you run can use Docker to get full administrator (root) access to this computer without a password', 'high', '/etc/group',
    `Remove yourself from the group (sudo gpasswd -d ${os.userInfo().username} docker), or use rootless Docker.`);
  for (const l of sh('ssh-add', ['-l'], 3000).split('\n').filter(x => /SHA256:/.test(x))) {
    const parts = l.split(' ');
    add('Your account', 'Inherited credential', `SSH key: ${parts.slice(2, -1).join(' ').replace(HOME, '~') || parts[1]}`,
      'Loaded in ssh-agent: any agent can use it to log in to servers or push code', 'medium', 'ssh-agent', 'Unload it with "ssh-add -d <key file>", or all keys with "ssh-add -D".');
  }
  const ghHosts = h('.config', 'gh', 'hosts.yml');
  if (exists(ghHosts)) {
    const t = fs.readFileSync(ghHosts, 'utf8');
    for (const m of t.matchAll(/^([\w.-]+):\s*\n(?:\s+.*\n)*?\s+user:\s*(\S+)/gm))
      add('GitHub CLI', 'Inherited credential', `Logged in to ${m[1]} as ${m[2]}`, 'Any agent can use gh to read, change or delete your repositories', 'high', ghHosts, 'Run "gh auth logout", or "gh auth refresh -s <scopes>" to narrow what the token can do.');
  }
  const awsCred = h('.aws', 'credentials'), awsCfg = h('.aws', 'config');
  const awsProfiles = [...new Set([
    ...(exists(awsCred) ? [...fs.readFileSync(awsCred, 'utf8').matchAll(/^\[([^\]]+)\]/gm)].map(m => m[1]) : []),
    ...(exists(awsCfg) ? [...fs.readFileSync(awsCfg, 'utf8').matchAll(/^\[(?:profile )?([^\]]+)\][^[]*sso_/gm)].map(m => m[1]) : []),
  ])];
  if (awsProfiles.length) add('AWS CLI', 'Inherited credential', `AWS profiles: ${awsProfiles.join(', ')}`, 'Any agent can use these to act on your AWS account', 'high', '~/.aws', 'Remove unused profiles from ~/.aws/credentials, prefer short-lived SSO logins, and log out with "aws sso logout".');
  const gcfg = h('.config', 'gcloud', 'configurations', 'config_default');
  if (exists(gcfg)) { const a = (fs.readFileSync(gcfg, 'utf8').match(/^account\s*=\s*(\S+)/m) || [])[1]; if (a) add('gcloud CLI', 'Inherited credential', `Logged in as ${a}`, 'Any agent can use gcloud to act on your Google projects', 'high', gcfg, 'Run "gcloud auth revoke" when you don\'t need it.'); }
  const kube = h('.kube', 'config');
  if (exists(kube)) { const t = fs.readFileSync(kube, 'utf8'); const n = (t.match(/^- context:/gm) || []).length; const cur = (t.match(/^current-context:\s*(\S+)/m) || [])[1];
    if (n) add('Kubernetes', 'Inherited credential', `${n} cluster context${n > 1 ? 's' : ''}${cur ? `, current: ${cur}` : ''}`, 'Any agent can run kubectl against these clusters', 'high', kube, 'Remove contexts you don\'t use (kubectl config delete-context <name>).'); }
  const dock = readJson(h('.docker', 'config.json'));
  if (dock && Object.keys(dock.auths || {}).length) add('Docker', 'Inherited credential', `Registry logins: ${Object.keys(dock.auths).join(', ')}`, 'Any agent can push or pull images as you', 'medium', '~/.docker/config.json', 'Run "docker logout <registry>".');
  const npmrc = h('.npmrc');
  if (exists(npmrc) && /_authToken\s*=/.test(fs.readFileSync(npmrc, 'utf8'))) add('npm', 'Inherited credential', 'npm login token', 'Any agent can publish packages as you', 'high', '~/.npmrc', 'Run "npm logout", or use a read-only/granular token.');
  const az = readJson(h('.azure', 'azureProfile.json'));
  if (az && (az.subscriptions || []).length) add('Azure CLI', 'Inherited credential', `${az.subscriptions.length} Azure subscription${az.subscriptions.length > 1 ? 's' : ''}`, 'Any agent can use az to act on these subscriptions', 'high', '~/.azure', 'Run "az logout".');
  return out;
}

function scanAll() {
  const tcc = scanTcc();
  const timing = process.env.AUDIT_TIMING ? {} : null; // how long each check takes (tests)
  const findings = [scanClaudeCode, scanClaudeDesktop, scanOtherMcp, () => tcc.findings, scanEnvKeys, scanKeychain, scanBackgroundAgents,
    scanEditorExtensions, scanBrowserExtensions, scanLocalServers, scanMoreAgents, scanInstalledAgents, scanLeftovers, scanSkills, scanProcesses, scanUploads, scanInherited,
    scanHistory, scanDataSharing]
    .flatMap(fn => { const t0 = Date.now(), r = fn(); if (timing) timing[fn.name || 'tcc'] = Date.now() - t0; return r; });
  if (timing) console.log('timing (ms):', JSON.stringify(timing));
  const reviews = readJson(REVIEW_FILE) || {};
  const expiries = readJson(EXPIRY_FILE) || {};
  const seen = new Set();
  const list = [];
  for (const f of findings) {
    f.legacyId = id(f.source, f.action, f.title, f.agent);
    f.id = id(f.source, f.action, f.title); // display names can change; what the grant *is* doesn't
    if (seen.has(f.id)) continue;
    seen.add(f.id);
    f.reviewedAt = reviews[f.id] || null;
    f.expiresAt = expiries[f.id] ? expiries[f.id].at : null;
    f.source = f.source.replace(HOME, '~');
    list.push(f);
  }
  if (migrateIds(list)) { // re-read what the migration just carried over
    const rv = readJson(REVIEW_FILE) || {}, ex = readJson(EXPIRY_FILE) || {};
    list.forEach(f => { f.reviewedAt = rv[f.id] || null; f.expiresAt = ex[f.id] ? ex[f.id].at : null; });
  }
  // First run: everything that exists today becomes the baseline, so you aren't flooded with alerts
  let known = readJson(KNOWN_FILE);
  if (!Array.isArray(known)) { known = list.map(f => f.id); writeIds(KNOWN_FILE, known); }
  const st0 = readJson(SETTINGS_FILE) || {};
  if (!st0.agentsBaselined) {
    const add = list.filter(f => f.category === 'AI agent installed').map(f => f.id);
    known = [...known, ...add]; writeIds(KNOWN_FILE, known);
    saveFile(SETTINGS_FILE, JSON.stringify({ ...st0, agentsBaselined: true }, null, 2));
  }
  const knownSet = new Set(known);
  list.forEach(f => { f.isNew = !knownSet.has(f.id) && !f.reviewedAt; });
  return { scannedAt: new Date().toISOString(), findings: list, tcc: tcc.status, manual: MANUAL_CHECKS };
}

// One-time move from v1 ids (which included the agent's display name) to v2 ids.
// Carries over reviews, expiries, seen and notified state; anything only renamed is treated as already seen.
function migrateIds(list) {
  const st = readJson(SETTINGS_FILE) || {};
  if (st.idVersion === 2) return false;
  const map = new Map(list.map(f => [f.legacyId, f.id]));
  const remapObj = file => { const o = readJson(file); if (!o) return; const n = {}; for (const [k, v] of Object.entries(o)) n[map.get(k) || k] = v; fs.writeFileSync(file, JSON.stringify(n, null, 2)); };
  remapObj(REVIEW_FILE);
  remapObj(EXPIRY_FILE);
  const notified = readJson(NOTIFIED_FILE);
  if (Array.isArray(notified)) writeIds(NOTIFIED_FILE, [...notified.map(i => map.get(i) || i), ...list.map(f => f.id)]);
  const known = readJson(KNOWN_FILE);
  if (Array.isArray(known)) writeIds(KNOWN_FILE, [...known.map(i => map.get(i) || i), ...list.map(f => f.id)]);
  saveFile(SETTINGS_FILE, JSON.stringify({ ...st, idVersion: 2 }, null, 2));
  log(`MIGRATED grant ids to v2 (${map.size} grants)`);
  return true;
}

// What the page and the menu bar receive: no raw config values (those can hold unmasked tokens)
function publicScan() {
  const r = scanAll();
  r.os = OS_NAME;
  r.findings = r.findings.map(({ legacyId, ...f }) => ({ ...f, action: { kind: f.action.kind, hint: f.action.hint, url: f.action.url, label: f.action.label } }));
  return r;
}

// ---------- update check ----------
// Once a day the app asks GitHub which version is the newest. Nothing about this computer is sent: it is one
// plain request for the public release list. It can be switched off in Setup ("Check for updates").
const UPDATE_FILE = path.join(DATA_DIR, 'update.json');
const RELEASES_API = 'https://api.github.com/repos/dirmedmr-alt/ai-access-auditor/releases?per_page=10';
const APP_VERSION = process.env.AUDIT_APP_VERSION || ''; // given by the Mac, Windows and Linux apps
const updatesOn = () => (readJson(SETTINGS_FILE) || {}).updates !== 'off';
// "1.0.6-beta" → [1, 0, 6]; versions differ only in their numbers
const verParts = v => (String(v).match(/(\d+)\.(\d+)\.(\d+)/) || [0, 0, 0, 0]).slice(1).map(Number);
function newerThan(a, b) { const x = verParts(a), y = verParts(b); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i]; return false; }
function updateInfo() {
  const u = readJson(UPDATE_FILE) || {};
  return { enabled: updatesOn(), current: APP_VERSION || null, latest: u.latest || null, url: u.url || null, checkedAt: u.checkedAt || null,
    available: !!(APP_VERSION && u.latest && newerThan(u.latest, APP_VERSION)), dismissed: u.dismissed || null };
}
function checkForUpdate(force = false) {
  return new Promise(resolve => {
    const u = readJson(UPDATE_FILE) || {};
    if (DEMO || !APP_VERSION || (!force && (!updatesOn() || (u.checkedAt && Date.now() - Date.parse(u.checkedAt) < 23 * 3600e3)))) return resolve(updateInfo());
    const req = require('https').get(RELEASES_API, { headers: { 'User-Agent': 'AI-Access-Auditor', Accept: 'application/vnd.github+json' }, timeout: 15000 }, res => {
      let d = '';
      res.on('data', c => { if (d.length < 2e6) d += c; }).on('end', () => {
        try {
          const rel = JSON.parse(d).find(r => !r.draft && /^v\d+\.\d+\.\d+/.test(r.tag_name || ''));
          if (rel) Object.assign(u, { latest: rel.tag_name.replace(/^v/, ''), url: rel.html_url });
          u.checkedAt = new Date().toISOString();
          saveFile(UPDATE_FILE, JSON.stringify(u, null, 2));
          if (rel && newerThan(u.latest, APP_VERSION)) { changedFlag = true; flushEvents(); }
        } catch {}
        resolve(updateInfo());
      });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(updateInfo()));
  });
}
// the apps show one notification per new version
function updateToNotify() {
  const info = updateInfo();
  if (!info.enabled || !info.available) return null;
  const u = readJson(UPDATE_FILE) || {};
  if (u.notified === info.latest) return null;
  u.notified = info.latest;
  saveFile(UPDATE_FILE, JSON.stringify(u, null, 2));
  return { version: info.latest, url: info.url };
}

// ---------- change tracking ----------
function writeIds(file, ids) { saveFile(file, JSON.stringify([...new Set(ids)].slice(-5000))); }
function changes() {
  const expired = sweepExpired();
  const r = publicScan();
  for (const [t, until] of expectedRules) if (until < Date.now()) expectedRules.delete(t);
  if (expectedRules.size) {
    const auto = r.findings.filter(f => f.isNew && f.agent === 'Claude Code' && f.category === 'Tool permission' && expectedRules.has(f.title));
    if (auto.length) { ack(auto.map(f => f.id)); auto.forEach(f => { f.isNew = false; }); }
  }
  const fresh = r.findings.filter(f => f.isNew);
  const notified = new Set(readJson(NOTIFIED_FILE) || []);
  const toNotify = fresh.filter(f => !notified.has(f.id));
  if (toNotify.length) writeIds(NOTIFIED_FILE, [...notified, ...toNotify.map(f => f.id)]);
  const openHigh = r.findings.filter(f => f.risk === 'high' && !f.reviewedAt).length;
  const slim = f => ({ id: f.id, agent: f.agent, title: f.title, category: f.category, risk: f.risk, detail: f.detail, revocable: REVOCABLE.includes(f.action.kind) });
  return { scannedAt: r.scannedAt, total: r.findings.length, openHigh, new: fresh.map(slim), toNotify: toNotify.map(slim), expired, update: updateToNotify() };
}
function ack(ids) {
  const known = readJson(KNOWN_FILE) || [];
  const add = ids && ids.length ? ids : scanAll().findings.map(f => f.id);
  writeIds(KNOWN_FILE, [...known, ...add]);
  return { ok: true };
}

// ---------- actions ----------
function log(msg) { fs.appendFileSync(LOG_FILE, `${new Date().toISOString()}  ${msg}\n`); }

function backup(file) {
  const name = `${Date.now()}__${file.replace(/[\/\\:]/g, '_')}`;
  const dest = path.join(BACKUP_DIR, name);
  fs.copyFileSync(file, dest);
  fs.writeFileSync(dest + '.meta.json', JSON.stringify({ original: file, at: new Date().toISOString() }));
  return name;
}
// Some changes aren't files (a registry value, a scheduled task): the backup records the command that undoes it
const RESTORE_CMDS = ['reg', 'schtasks'];
function backupCommand(label, cmd, args) {
  const name = `${Date.now()}__${label.replace(/[\/\\:*?"<>| ]/g, '_').slice(0, 120)}`;
  fs.writeFileSync(path.join(BACKUP_DIR, name), `${label}\n${cmd} ${args.join(' ')}\n`);
  fs.writeFileSync(path.join(BACKUP_DIR, name + '.meta.json'), JSON.stringify({ original: label, at: new Date().toISOString(), restore: { cmd, args } }));
  return name;
}
// The app's own state files: written to a temporary file first, so a full disk never leaves them empty
function saveFile(file, text) {
  const tmp = file + '.ai-audit-tmp';
  try { fs.writeFileSync(tmp, text); fs.renameSync(tmp, file); }
  catch (e) { try { fs.unlinkSync(tmp); } catch {} throw e; }
}
function writeJsonAtomic(file, obj) {
  const tmp = file + '.ai-audit-tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n', { mode: fs.statSync(file).mode });
  fs.renameSync(tmp, file);
}

function clearExpiry(findingId) {
  const ex = readJson(EXPIRY_FILE) || {};
  if (ex[findingId]) { delete ex[findingId]; saveFile(EXPIRY_FILE, JSON.stringify(ex, null, 2)); }
}

function revoke(findingId, reason = '', snapshot = null) {
  const f = (snapshot || scanAll()).findings.find(x => x.id === findingId);
  if (!f) throw new Error('Finding not found (it may already be gone). Rescan.');
  const res = doRevoke(f, reason);
  clearExpiry(findingId);
  return res;
}

function doRevoke(f, reason) {
  const a = f.action;
  const why = reason ? ` (${reason})` : '';
  if (a.kind === 'disableLaunchAgent') {
    const bk = backup(a.file);
    sh('launchctl', ['bootout', `gui/${process.getuid()}`, a.file], 5000);
    fs.unlinkSync(a.file);
    log(`DISABLE launch agent ${f.title}  file=${a.file}  backup=${bk}${why}`);
    return { message: `Stopped and removed "${f.title}". Backup saved.`, backup: bk };
  }
  if (a.kind === 'disableSystemdUnit') {
    const bks = [];
    for (const file of a.files.slice().reverse()) { // the timer first, so it can't start the service again
      if (!exists(file)) continue;
      bks.push(backup(file));
      sh('systemctl', ['--user', 'disable', '--now', path.basename(file)], 15000);
      fs.unlinkSync(file);
    }
    sh('systemctl', ['--user', 'daemon-reload'], 15000);
    log(`DISABLE systemd unit ${f.title}  files=${a.files.join(',')}  backup=${bks.join(',')}${why}`);
    return { message: `Stopped and removed "${f.title}". Backup saved.`, backup: bks[0] };
  }
  if (a.kind === 'setValues') {
    if (!exists(a.file)) { fs.mkdirSync(path.dirname(a.file), { recursive: true }); fs.writeFileSync(a.file, '{}\n'); }
    const j = readJson(a.file);
    if (!j) throw new Error(`Could not read ${a.file.replace(HOME, '~')} (it may contain comments). Change it by hand.`);
    const bk = backup(a.file);
    let o = j;
    for (const k of a.path) { if (!o[k] || typeof o[k] !== 'object') o[k] = {}; o = o[k]; }
    Object.assign(o, a.values);
    writeJsonAtomic(a.file, j);
    log(`SET ${Object.keys(a.values).join(', ')} [${f.agent}] ${f.title}  file=${a.file}  backup=${bk}${why}`);
    return { message: `Turned off: ${f.title}. Restart running ${f.agent} sessions to pick it up. Backup saved.`, backup: bk };
  }
  if (a.kind === 'redactSecrets') {
    // no backup on purpose: a copy would keep the very secrets being removed
    const st = fs.statSync(a.file);
    if (Date.now() - st.mtimeMs < 120e3) throw new Error('This session is still being written to. Try again a couple of minutes after it ends.');
    let text = fs.readFileSync(a.file, 'utf8'), n = 0;
    for (const [, re] of SECRET_PATTERNS) text = text.replace(re, m => (realSecret(m) ? (n++, REDACTED) : m));
    const tmp = a.file + '.ai-audit-tmp';
    fs.writeFileSync(tmp, text, { mode: st.mode });
    fs.renameSync(tmp, a.file);
    if (historyCache) delete historyCache[a.file];
    log(`REDACT ${n} secret${n === 1 ? '' : 's'} [${f.agent}] in ${a.file}${why}`);
    return { message: `Removed ${n} secret${n === 1 ? '' : 's'} from the session log. The rest of the conversation is unchanged. Replace ${n === 1 ? 'that key' : 'those keys'} with the service too, since the agent may have sent ${n === 1 ? 'it' : 'them'} to its AI provider.` };
  }
  if (a.kind === 'removeRunValue') {
    const bk = backupCommand(`${a.key}\\${a.name}`, 'reg', ['add', a.key, '/v', a.name, '/t', a.type, '/d', a.value, '/f']);
    execFileSync('reg', ['delete', a.key, '/v', a.name, '/f'], { stdio: 'pipe', windowsHide: true });
    log(`REMOVE startup entry ${a.key}\\${a.name}  backup=${bk}${why}`);
    return { message: `"${f.title}" won't start at login anymore. If it is running now, it keeps running until you quit it. You can undo this under History.`, backup: bk };
  }
  if (a.kind === 'disableTask') {
    try { execFileSync('schtasks', ['/change', '/tn', a.task, '/disable'], { stdio: 'pipe', windowsHide: true }); }
    catch (e) { throw new Error(`Windows didn't allow it (${String(e.stderr || e.message).trim().slice(0, 160)}). Disable it in Task Scheduler as an administrator.`); }
    const bk = backupCommand(`task ${a.task}`, 'schtasks', ['/change', '/tn', a.task, '/enable']);
    tasksCache = { at: 0, list: [] };
    log(`DISABLE scheduled task ${a.task}  backup=${bk}${why}`);
    return { message: `Turned off the scheduled task "${f.title}". You can turn it back on under History.`, backup: bk };
  }
  if (a.kind === 'removeAutostart') {
    if (!exists(a.file)) throw new Error('That file is already gone. Rescan.');
    const bk = backup(a.file);
    fs.unlinkSync(a.file);
    log(`REMOVE autostart ${f.title}  file=${a.file}  backup=${bk}${why}`);
    return { message: `"${f.title}" won't start at login anymore. If it is running now, it keeps running until you quit it. Backup saved.`, backup: bk };
  }
  if (a.kind === 'killProcess') {
    const procs = processList();
    const now = (procs.find(p => p.pid === String(a.pid)) || {}).cmd || '';
    if (!now || !now.startsWith(a.cmdStart.slice(0, 100))) return { message: `It had already stopped (process ${a.pid}).` };
    const tree = a.tree ? descendants(procs, String(a.pid)) : [];
    process.kill(a.pid, 'SIGTERM');
    for (const k of tree) try { process.kill(Number(k.pid), 'SIGTERM'); } catch {}
    log(`STOP process ${a.pid}${tree.length ? ` and ${tree.length} helpers` : ''} [${f.agent}] ${f.title}${why}`);
    return { message: `Stopped ${f.category === 'Data upload' ? f.title.split(' is sending')[0] : f.agent} (process ${a.pid}).` };
  }
  if (a.kind === 'removeTomlBlock') {
    const text = exists(a.file) ? fs.readFileSync(a.file, 'utf8') : '';
    if (!text.includes(a.block)) throw new Error('That rule is no longer in the file. Rescan.');
    const bk = backup(a.file);
    let after = text.replace(a.block, '');
    // YAML: a list left with no items becomes [] rather than an empty value
    if (/\.ya?ml$/i.test(a.file)) after = after.replace(/^([A-Za-z_][\w-]*):[ \t]*$(?=\n(?![ \t]+\S)|(?![\s\S]))/gm, '$1: []');
    fs.writeFileSync(a.file, after);
    log(`REVOKE [${f.agent}] ${f.category}: ${f.title}  file=${a.file}  backup=${bk}${why}`);
    return { message: `Revoked "${f.title}". ${f.agent} will ask again (restart any running ${f.agent} sessions). Backup saved.`, backup: bk };
  }
  if (a.kind === 'removeFile') {
    const file = a.file;
    if (!exists(file)) throw new Error('That file is already gone. Rescan.');
    const bk = backup(file);
    fs.unlinkSync(file);
    log(`REMOVE [${f.agent}] ${f.category}: ${f.title}  file=${file}  backup=${bk}${why}`);
    return { message: `Removed "${f.title}". ${f.agent} will ask you to sign in again. A backup is saved under History.`, backup: bk };
  }
  if (a.kind === 'removeFolder') {
    if (!exists(a.dir)) throw new Error('That folder is already gone. Rescan.');
    const name = `${Date.now()}__${a.dir.replace(/[\/\\:]/g, '_')}`;
    fs.cpSync(a.dir, path.join(BACKUP_DIR, name), { recursive: true, verbatimSymlinks: true });
    fs.writeFileSync(path.join(BACKUP_DIR, name + '.meta.json'), JSON.stringify({ original: a.dir, at: new Date().toISOString(), folder: true }));
    fs.rmSync(a.dir, { recursive: true, force: true });
    log(`REMOVE [${f.agent}] ${f.category}: ${f.title}  folder=${a.dir}  backup=${name}${why}`);
    return { message: `Removed "${f.title}". A copy is saved, so you can restore it from History.`, backup: name };
  }
  if (a.kind === 'uninstallExt') {
    if (!/^[\w.-]+$/.test(a.extId)) throw new Error('Unexpected extension name.');
    // Windows editors ship a .cmd launcher, which only runs through cmd.exe
    if (WIN) execFileSync('cmd.exe', ['/d', '/s', '/c', `""${a.cli}" --uninstall-extension ${a.extId}"`], { stdio: 'pipe', timeout: 60000, windowsHide: true, windowsVerbatimArguments: true });
    else execFileSync(a.cli, ['--uninstall-extension', a.extId], { stdio: 'pipe', timeout: 60000 });
    log(`UNINSTALL ${a.editor} extension ${a.extId}${why}`);
    return { message: `Uninstalled ${f.title} from ${a.editor}. Reinstall it from the marketplace if you need it again.` };
  }
  if (a.kind === 'tccReset') {
    execFileSync('tccutil', ['reset', a.service, a.client], { stdio: 'pipe' });
    log(`TCC reset ${a.service} ${a.client}${why}`);
    return { message: `Reset ${f.title} for ${a.client}. The app will ask again next time.` };
  }
  if (!['removeArrayItem', 'deleteKey', 'setFalse'].includes(a.kind)) throw new Error('This item has no automatic action.');
  const j = readJson(a.file);
  if (!j) throw new Error('Could not read ' + a.file);
  const parent = a.path.length ? getAt(j, a.path) : j;
  if (parent == null) throw new Error('Path no longer exists. Rescan.');
  const bk = backup(a.file);
  if (a.kind === 'removeArrayItem') {
    const idx = parent.findIndex(v => JSON.stringify(v) === JSON.stringify(a.value));
    if (idx < 0) throw new Error('Item no longer present. Rescan.');
    parent.splice(idx, 1);
  } else if (a.kind === 'deleteKey') {
    if (!(a.key in parent)) throw new Error('Key no longer present. Rescan.');
    delete parent[a.key];
  } else parent[a.key] = false;
  writeJsonAtomic(a.file, j);
  log(`REVOKE [${f.agent}] ${f.category}: ${f.title}  file=${a.file}  backup=${bk}${why}`);
  const restartHint = /Claude\/claude_desktop_config|\.claude\.json/.test(a.file) ? ' Restart the app so it picks up the change (a running app may overwrite it).' : '';
  return { message: `Revoked "${f.title}". Backup saved.${restartHint}`, backup: bk };
}

const REVOCABLE = ['removeArrayItem', 'deleteKey', 'setFalse', 'tccReset', 'disableLaunchAgent', 'disableSystemdUnit', 'removeAutostart', 'removeRunValue', 'disableTask', 'redactSecrets', 'setValues', 'uninstallExt', 'killProcess', 'removeFolder', 'removeFile', 'removeTomlBlock'];

// Revoke several grants in one go. One scan up front; each revoke re-reads its file, so they don't clash.
function revokeMany(ids) {
  if (!Array.isArray(ids) || !ids.length) throw new Error('Nothing selected.');
  const snap = scanAll();
  const results = ids.map(i => {
    const f = snap.findings.find(x => x.id === i);
    try { revoke(i, 'bulk', snap); return { id: i, ok: true, title: f && f.title }; }
    catch (e) { return { id: i, ok: false, title: f && f.title, error: e.message }; }
  });
  const ok = results.filter(r => r.ok).length;
  return { message: `Revoked ${ok} of ${ids.length}.${ok < ids.length ? ' Some failed: ' + results.filter(r => !r.ok).map(r => `${r.title}: ${r.error}`).join('; ') : ''}`, results };
}

// Time-limited access: revoke automatically once the time is up
function setExpiry(findingId, hours) {
  const ex = readJson(EXPIRY_FILE) || {};
  if (!hours) { delete ex[findingId]; saveFile(EXPIRY_FILE, JSON.stringify(ex, null, 2)); return { message: 'Auto-revoke turned off' }; }
  const f = scanAll().findings.find(x => x.id === findingId);
  if (!f) throw new Error('Finding not found. Rescan.');
  if (!REVOCABLE.includes(f.action.kind)) throw new Error('This grant can\'t be revoked automatically.');
  const at = new Date(Date.now() + Number(hours) * 3600e3).toISOString();
  ex[findingId] = { at, title: f.title, agent: f.agent, category: f.category, risk: f.risk };
  saveFile(EXPIRY_FILE, JSON.stringify(ex, null, 2));
  ack([findingId]);
  log(`EXPIRY set for [${f.agent}] ${f.title} at ${at}`);
  return { message: `"${f.title}" will be revoked ${new Date(at).toLocaleString()}` };
}
function sweepExpired() {
  const ex = readJson(EXPIRY_FILE) || {};
  const due = Object.entries(ex).filter(([, e]) => Date.parse(e.at) <= Date.now());
  if (!due.length) return [];
  const snap = scanAll();
  const done = [];
  for (const [fid, e] of due) {
    try { revoke(fid, 'expired', snap); done.push({ id: fid, agent: e.agent, title: e.title, category: e.category, risk: e.risk, detail: 'Time limit reached' }); }
    catch (err) { log(`EXPIRY could not revoke [${e.agent}] ${e.title}: ${err.message}`); clearExpiry(fid); }
  }
  return done;
}

function openApp(findingId) {
  const f = scanAll().findings.find(x => x.id === findingId);
  if (!f || f.action.kind !== 'openApp') throw new Error('Nothing to open.');
  try { execFileSync('open', ['-b', f.action.bundle], { stdio: 'pipe' }); }
  catch { execFileSync('open', ['-a', f.action.fallback], { stdio: 'pipe' }); }
  return { message: f.action.hint };
}

// ---------- report ----------
// A self-contained HTML page with every grant, saved in Downloads and opened in the browser (Print → Save as
// PDF makes a PDF). Secrets are already masked in the findings; home folder paths are shown as ~.
function exportReport() {
  const r = publicScan(), f = r.findings, now = new Date();
  const e = x => String(x == null ? '' : x).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const home = x => String(x || '').split(HOME).join('~');
  const open = f.filter(x => !x.reviewedAt);
  const score = Math.round(100 * Math.exp(-open.reduce((s, x) => s + ({ high: 12, medium: 4, low: 1 }[x.risk] || 0), 0) / 80));
  const n = k => f.filter(x => x.risk === k).length, order = { high: 0, medium: 1, low: 2 };
  const agents = [...new Set(f.map(x => x.agent))].sort((a, b) => f.filter(x => x.agent === b).length - f.filter(x => x.agent === a).length);
  const rows = a => f.filter(x => x.agent === a).sort((x, y) => order[x.risk] - order[y.risk] || x.category.localeCompare(y.category)).map(x => `
    <tr><td><span class="r ${e(x.risk)}">${e(x.risk)}</span></td><td>${e(x.category)}</td><td><b>${e(home(x.title))}</b><div class="d">${e(home(x.detail))}</div></td>
    <td class="src">${e(home(x.source))}</td><td>${x.reviewedAt ? 'Reviewed' : x.isNew ? 'New' : 'To review'}</td></tr>`).join('');
  const stamp = now.toISOString().slice(0, 16).replace('T', ' ');
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Access Auditor report, ${e(stamp)}</title><style>
body{font:14px/1.45 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1b1b1a;background:#fff;margin:0;padding:32px}
main{max-width:1100px;margin:0 auto}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px}.m{color:#62625e}
.sum{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}.k{border:1px solid #e3e3df;border-radius:10px;padding:10px 16px;min-width:110px}.k b{display:block;font-size:24px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;vertical-align:top;padding:8px;border-bottom:1px solid #ececea}th{font-size:12px;color:#62625e;text-transform:uppercase;letter-spacing:.04em}
.d{color:#62625e;font-size:13px;word-break:break-word}.src{font-size:12px;color:#62625e;word-break:break-all;max-width:260px}
.r{font-size:12px;font-weight:600;padding:2px 8px;border-radius:99px;text-transform:capitalize}.high{background:#fde8e5;color:#b42d1f}.medium{background:#fbf0dc;color:#8f5a08}.low{background:#e3f3e8;color:#1f6b39}
@media print{body{padding:0}h2{break-after:avoid}tr{break-inside:avoid}}
</style></head><body><main>
<h1>AI Access Auditor report</h1>
<p class="m">${e(stamp)} · ${e(({ mac: 'macOS', win: 'Windows', windows: 'Windows', linux: 'Linux' })[r.os || OS_NAME] || r.os || OS_NAME)}${APP_VERSION ? ` · app ${e(APP_VERSION)}` : ''} · secrets are masked</p>
<div class="sum"><div class="k"><b>${score}</b>safety score</div><div class="k"><b>${f.length}</b>grants</div><div class="k"><b>${n('high')}</b>high risk</div>
<div class="k"><b>${n('medium')}</b>medium</div><div class="k"><b>${n('low')}</b>low</div><div class="k"><b>${f.length - open.length}</b>reviewed</div><div class="k"><b>${agents.length}</b>agents</div></div>
${agents.map(a => `<h2>${e(a)} <span class="m">(${f.filter(x => x.agent === a).length})</span></h2>
<table><thead><tr><th>Risk</th><th>Type</th><th>Grant</th><th>Stored in</th><th>Status</th></tr></thead><tbody>${rows(a)}</tbody></table>`).join('')}
<p class="m" style="margin-top:32px">Made by AI Access Auditor, https://dirmedmr-alt.github.io/ai-access-auditor/</p>
</main></body></html>`;
  const dir = exists(h('Downloads')) ? h('Downloads') : DATA_DIR;
  const file = path.join(dir, `AI-Access-Auditor-report-${now.toISOString().slice(0, 16).replace(/[T:]/g, '-')}.html`);
  saveFile(file, html);
  log(`EXPORT report  file=${file}`);
  if (!DEMO) try {
    const [cmd, args] = MAC ? ['open', [file]] : WIN ? ['explorer.exe', [file]] : ['xdg-open', [file]];
    require('child_process').spawn(cmd, args, { detached: true, stdio: 'ignore' }).unref();
  } catch {}
  return { message: dir === DATA_DIR ? 'Report saved in the app\'s data folder and opened in your browser.' : 'Report saved in Downloads and opened in your browser.', file };
}

function listBackups() {
  return fs.readdirSync(BACKUP_DIR).filter(n => !n.endsWith('.meta.json')).sort().reverse().slice(0, 100).map(n => {
    const meta = readJson(path.join(BACKUP_DIR, n + '.meta.json')) || {};
    return { name: n, original: (meta.original || '?').replace(HOME, '~'), at: meta.at };
  });
}
function restore(name) {
  if (name.includes('/') || name.includes('..')) throw new Error('bad name');
  const meta = readJson(path.join(BACKUP_DIR, name + '.meta.json'));
  if (!meta) throw new Error('Backup not found');
  if (meta.restore) {
    if (!RESTORE_CMDS.includes(meta.restore.cmd) || !Array.isArray(meta.restore.args)) throw new Error('This backup can\'t be restored automatically.');
    execFileSync(meta.restore.cmd, meta.restore.args.map(String), { stdio: 'pipe', windowsHide: true });
    tasksCache = { at: 0, list: [] };
    log(`RESTORE ${meta.original} from ${name}`);
    return { message: `Restored ${meta.original}` };
  }
  if (meta.folder) {
    if (exists(meta.original)) throw new Error(`${meta.original.replace(HOME, '~')} exists again. Remove or rename it first.`);
    fs.cpSync(path.join(BACKUP_DIR, name), meta.original, { recursive: true, verbatimSymlinks: true });
    log(`RESTORE folder ${meta.original} from ${name}`);
    return { message: `Restored ${meta.original.replace(HOME, '~')}` };
  }
  if (exists(meta.original)) backup(meta.original);
  fs.copyFileSync(path.join(BACKUP_DIR, name), meta.original);
  if (MAC && meta.original.startsWith(h('Library', 'LaunchAgents'))) sh('launchctl', ['bootstrap', `gui/${process.getuid()}`, meta.original], 5000);
  if (LINUX && meta.original.startsWith(h('.config', 'systemd', 'user') + '/')) {
    sh('systemctl', ['--user', 'daemon-reload'], 15000);
    sh('systemctl', ['--user', 'enable', '--now', path.basename(meta.original)], 15000);
  }
  log(`RESTORE ${meta.original} from ${name}`);
  return { message: `Restored ${meta.original.replace(HOME, '~')}` };
}
function markReviewed(findingId, on) {
  if (on) ack([findingId]);
  const r = readJson(REVIEW_FILE) || {};
  if (on) r[findingId] = new Date().toISOString(); else delete r[findingId];
  saveFile(REVIEW_FILE, JSON.stringify(r, null, 2));
  return { ok: true };
}

// ---------- live events: file watching + Allow/Deny gate ----------
const waiters = new Set();      // long-poll responses from the Mac app waiting for something to happen
const gatePending = new Map();  // id -> { info, respond, delivered }
let changedFlag = false, closedIds = [], watchTimer = null;
const expectedRules = new Map(); // rule title -> expiry time: rules you just approved with "Always"

function flushEvents() {
  const gate = [...gatePending.values()].filter(g => !g.delivered);
  if (!waiters.size || (!gate.length && !changedFlag && !closedIds.length)) return;
  gate.forEach(g => { g.delivered = true; });
  const payload = { gate: gate.map(g => g.info), changed: changedFlag, closed: closedIds };
  changedFlag = false; closedIds = [];
  for (const res of waiters) send(res, 200, payload);
  waiters.clear();
}
function waitEvents(res) {
  waiters.add(res);
  const t = setTimeout(() => { if (waiters.delete(res)) send(res, 200, { gate: [], changed: false, closed: [] }); }, 50000);
  res.on('close', () => { clearTimeout(t); waiters.delete(res); });
  // re-deliver gate requests that are still open (e.g. after the app reloaded)
  for (const g of gatePending.values()) g.delivered = false;
  flushEvents();
}

// Watch the places agents store their access, and tell the app within a couple of seconds
// Things files can't tell us about (running agents, ssh keys, sudo, network ports): check every few seconds
let liveSig = '';
function pollLive() {
  const policySig = geminiPolicyFiles().map(([f]) => { try { return f + fs.statSync(f).mtimeMs; } catch { return f; } }).join('|');
  const sig = [...scanProcesses(), ...scanLocalServers()].map(f => f.title + f.source).sort().join('|') + policySig;
  if (liveSig && sig !== liveSig) { changedFlag = true; flushEvents(); }
  liveSig = sig;
}
setInterval(pollLive, 8000).unref();

function startWatching() {
  const targets = [
    [HOME, /^\.claude\.json$|^\.mcp\.json$|^\.(zshrc|zprofile|bashrc|bash_profile|profile|npmrc|aider\.conf\.yml)$/],
    [h('.gemini'), /\.json$/], [h('.copilot'), /\.json$/], [h('.aws'), /^(credentials|config)$/], [h('.aws', 'amazonq'), /\.json$/],
    [h('.kiro', 'settings'), /\.json$/], [h('.config', 'opencode'), /\.jsonc?$/], [h('.local', 'share', 'opencode'), /^auth\.json$/], [h('.config', 'opencode', 'plugin'), /./], [h('.config', 'opencode', 'plugins'), /./], [appData('ai.opencode.desktop'), /^(cli|opencode\.settings)$/], [h('.continue'), /\.json$/], [h('.config', 'goose'), /\.yaml$/],
    [h('.config', 'gh'), /hosts\.yml$/], [h('.kube'), /^config$/], [h('.docker'), /config\.json$/], [h('.azure'), /\.json$/],
    [appData('Cursor', 'User'), /^settings\.json$/], [appData('Windsurf', 'User'), /^settings\.json$/],
    [appData('Claude', 'Claude Extensions'), /./],
    ...BROWSERS.map(([, root]) => [path.join(root, 'Default', 'Extensions'), /./]),
    ...(MAC ? [[h('Library', 'Keychains'), /^login\.keychain-db$/], [appData('com.apple.TCC'), /^TCC\.db/], [h('Library', 'LaunchAgents'), /\.plist$/]]
      : WIN ? [[appData('Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'), /./], [appData('Microsoft', 'Windows', 'Start Menu', 'Programs'), /\.lnk$/i]]
      : [[h('.local', 'share', 'keyrings'), /./], [h('.config', 'systemd', 'user'), /\.(service|timer)$/], [h('.config', 'autostart'), /\.desktop$/],
        ...DESKTOP_DIRS.map(d => [d, /\.desktop$/])]),
    [h('.claude'), /^settings(\.local)?\.json$/],
    [appData('Claude'), /^claude_desktop_config\.json$/],
    [h('.cursor'), /^(mcp|cli-config)\.json$/], [h('.codeium', 'windsurf'), /mcp_config\.json$/], [h('.gemini'), /settings\.json$/], [h('.codex'), /config\.toml$/],
    [appData('Code', 'User'), /^(settings|mcp)\.json$/],
    [h('.vscode', 'extensions'), /./], [h('.cursor', 'extensions'), /./], [h('.windsurf', 'extensions'), /./],
  ];
  for (const proj of Object.keys((readJson(h('.claude.json')) || {}).projects || {}))
    targets.push([path.join(proj, '.claude'), /^settings(\.local)?\.json$/], [proj, /^\.mcp\.json$/]);
  for (const [, dir] of skillRoots()) targets.push([dir, /./]);
  for (const dir of BIN_DIRS) targets.push([dir, new RegExp(`^(${Object.keys(CLI_AGENTS).join('|')})$`)]);
  if (MAC) targets.push(['/Applications', AI_APPS], [h('Applications'), AI_APPS]);
  targets.push([h('.claude'), /^\.credentials\.json$/], [h('.codex'), /^(config\.toml|auth\.json|\.credentials\.json|hooks\.json)$/]);
  for (const [dir, re] of targets) {
    try {
      fs.watch(dir, { persistent: false }, (_e, name) => {
        if (name && !re.test(String(name))) return;
        clearTimeout(watchTimer);
        watchTimer = setTimeout(() => { changedFlag = true; flushEvents(); }, 1500);
      }).on('error', () => {});
    } catch { /* folder doesn't exist yet */ }
  }
}

function summarize(tool, input) {
  input = input || {};
  if (tool === 'Bash') return { kind: 'run a command', text: String(input.command || ''), risk: /\b(rm|sudo|curl|wget|ssh|scp|chmod|chown|dd|mkfs|git push|npm publish|kill)\b/.test(input.command || '') ? 'high' : 'medium' };
  if (/^(Write|Edit|MultiEdit|NotebookEdit)$/.test(tool)) return { kind: 'change a file', text: String(input.file_path || input.notebook_path || ''), risk: 'medium' };
  if (tool === 'Read') return { kind: 'read a file', text: String(input.file_path || ''), risk: 'low' };
  if (tool === 'WebFetch') return { kind: 'open a web page', text: String(input.url || ''), risk: 'low' };
  if (tool === 'WebSearch') return { kind: 'search the web', text: String(input.query || ''), risk: 'low' };
  // Codex CLI: file edits arrive as a patch
  if (tool === 'apply_patch') {
    const patch = String(input.command || input.input || '');
    const files = [...patch.matchAll(/^\*\*\* (Add|Update|Delete) File: (.+)$/gm)].map(m => `${m[1] === 'Add' ? 'create' : m[1] === 'Delete' ? 'delete' : 'change'} ${m[2]}`);
    return { kind: 'change files', text: files.length ? files.join('\n') : patch.slice(0, 600), risk: /Delete File/.test(patch) ? 'high' : 'medium' };
  }
  // Gemini CLI tool names
  if (tool === 'run_shell_command') return { kind: 'run a command', text: String(input.command || '') + (input.dir_path ? `\n(in ${input.dir_path})` : ''), risk: /\b(rm|sudo|curl|wget|ssh|scp|chmod|chown|dd|mkfs|git push|npm publish|kill)\b/.test(input.command || '') ? 'high' : 'medium' };
  if (tool === 'write_file' || tool === 'replace') return { kind: tool === 'write_file' ? 'write a file' : 'change a file', text: String(input.file_path || ''), risk: 'medium' };
  if (tool === 'web_fetch') return { kind: 'open a web page', text: String(input.url || input.prompt || ''), risk: 'low' };
  if (/^mcp_/.test(tool) && !tool.startsWith('mcp__')) return { kind: `use MCP tool ${tool.slice(4)}`, text: JSON.stringify(input, null, 1).slice(0, 600), risk: 'medium' };
  if (tool.startsWith('mcp__')) { const [, server, name] = tool.split('__'); return { kind: `use ${server}: ${name}`, text: JSON.stringify(input, null, 1).slice(0, 600), risk: 'medium' }; }
  return { kind: `use ${tool}`, text: JSON.stringify(input, null, 1).slice(0, 600), risk: 'medium' };
}

// Called by the Claude Code hook. Holds the request open until you click Allow or Deny in the app.
function gateAsk(body, res) {
  const gid = crypto.randomBytes(8).toString('hex');
  const sum = summarize(String(body.tool || ''), body.input);
  const info = {
    id: gid, agent: body.agent || 'Claude Code', tool: String(body.tool || ''), action: sum.kind, text: sum.text, risk: sum.risk,
    cwd: String(body.cwd || '').replace(HOME, '~'), canAlways: Array.isArray(body.suggestions) && body.suggestions.length > 0,
  };
  const timer = setTimeout(() => finish({ behavior: 'ask' }), 280000); // give up → Claude Code asks you normally
  function finish(answer) {
    if (!gatePending.has(gid)) return;
    clearTimeout(timer);
    gatePending.delete(gid);
    closedIds.push(gid);
    send(res, 200, answer);
    flushEvents();
  }
  res.on('close', () => { if (gatePending.has(gid)) { clearTimeout(timer); gatePending.delete(gid); closedIds.push(gid); flushEvents(); } });
  gatePending.set(gid, { info, finish, suggestions: body.suggestions, input: body.input, cwd: body.cwd, delivered: false });
  flushEvents();
}
function gateDecide({ id: gid, decision, remember }) {
  const g = gatePending.get(gid);
  if (!g) throw new Error('That request is no longer waiting (Claude Code may have moved on).');
  const allow = decision === 'allow';
  const always = allow && remember === 'always' && g.suggestions;
  if (always) for (const sug of g.suggestions) for (const r of sug.rules || []) // the rule Claude Code is about to save isn't "new" to you
    expectedRules.set(r.ruleContent ? `${r.toolName}(${r.ruleContent})` : r.toolName, Date.now() + 60000);
  log(`GATE ${allow ? 'ALLOW' : 'DENY'}${always ? ' (always)' : ''} [${g.info.agent}] ${g.info.tool}: ${g.info.text.slice(0, 200).replace(/\n/g, ' ')}`);
  recordDecision(g, allow, !!always);
  g.finish(allow ? { behavior: 'allow', updatedPermissions: always ? g.suggestions : undefined } : { behavior: 'deny', message: 'You denied this in AI Access Auditor.' });
  return { ok: true };
}

// ---------- decision history: change your mind later ----------
const ruleTitle = r => (r.ruleContent ? `${r.toolName}(${r.ruleContent})` : r.toolName);

// The narrowest Claude Code rule that matches exactly what was asked
function exactRule(tool, input, cwd) {
  input = input || {};
  const abs = p => (path.isAbsolute(p) ? p : path.join(cwd || HOME, p));
  if (tool === 'Bash' && input.command) return `Bash(${input.command})`;
  if (/^(Write|Edit|MultiEdit|NotebookEdit)$/.test(tool) && (input.file_path || input.notebook_path)) return `Edit(/${abs(input.file_path || input.notebook_path)})`;
  if (tool === 'Read' && input.file_path) return `Read(/${abs(input.file_path)})`;
  if (tool === 'WebFetch' && input.url) { try { return `WebFetch(domain:${new URL(input.url).hostname})`; } catch {} }
  return tool; // MCP tools and others: the tool name is already specific
}

function recordDecision(g, allow, always) {
  const list = readJson(DECISIONS_FILE) || [];
  list.unshift({
    id: crypto.randomBytes(6).toString('hex'), at: new Date().toISOString(), agent: g.info.agent, tool: g.info.tool,
    action: g.info.action, text: g.info.text.slice(0, 2000), cwd: g.info.cwd, risk: g.info.risk,
    decision: allow ? 'allow' : 'deny', always,
    savedRules: always ? (g.suggestions || []).flatMap(sug => (sug.rules || []).map(ruleTitle)) : [],
    blockRule: g.info.agent === 'Claude Code' ? exactRule(g.info.tool, g.input, g.cwd) : '', // "Block from now on" writes a Claude Code rule
  });
  saveFile(DECISIONS_FILE, JSON.stringify(list.slice(0, 500), null, 2));
}

function userDenyRules() { return (((readJson(h('.claude', 'settings.json')) || {}).permissions || {}).deny) || []; }

function listDecisions() {
  const findings = scanAll().findings.filter(f => f.agent === 'Claude Code' && f.category === 'Tool permission');
  const deny = new Set(userDenyRules());
  return (readJson(DECISIONS_FILE) || []).map(d => {
    if (d.agent !== 'Claude Code') return { ...d, ruleIds: [], ruleActive: false, blocked: false };
    const live = findings.filter(f => d.savedRules.includes(f.title));
    return { ...d, ruleIds: live.map(f => f.id), ruleActive: live.length > 0, blocked: deny.has(d.blockRule) };
  });
}

function editUserDeny(rule, add) {
  const file = h('.claude', 'settings.json');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (!exists(file)) fs.writeFileSync(file, '{}\n');
  const j = readJson(file);
  if (!j) throw new Error('Could not read ~/.claude/settings.json (is it valid JSON?)');
  const bk = backup(file);
  j.permissions = j.permissions || {};
  const deny = (j.permissions.deny || []).filter(r => r !== rule);
  if (add) deny.push(rule);
  if (deny.length) j.permissions.deny = deny; else delete j.permissions.deny;
  writeJsonAtomic(file, j);
  return bk;
}

// Take back an earlier decision: remove any "always" rule it saved, and/or block it from now on
function changeDecision({ id: did, action }) {
  const d = listDecisions().find(x => x.id === did);
  if (!d) throw new Error('Decision not found.');
  if (d.agent !== 'Claude Code') throw new Error(`Saved rules only exist for Claude Code. ${d.agent} will ask through this app again next time.`);
  const snap = scanAll();
  const revokeSaved = () => d.ruleIds.forEach(rid => { try { revoke(rid, 'decision changed', snap); } catch {} });
  if (action === 'revoke') {
    if (!d.ruleActive) throw new Error('The rule from this decision is already gone.');
    revokeSaved();
    log(`DECISION revoked "always" rule for [${d.agent}] ${d.tool}: ${d.savedRules.join(', ')}`);
    return { message: `Removed: ${d.savedRules.join(', ')}. Claude Code will ask again next time.` };
  }
  if (action === 'block') {
    revokeSaved();
    const bk = editUserDeny(d.blockRule, true);
    log(`DECISION blocked [${d.agent}] ${d.blockRule}  backup=${bk}`);
    return { message: `Blocked from now on: ${d.blockRule}` };
  }
  if (action === 'unblock') {
    const bk = editUserDeny(d.blockRule, false);
    log(`DECISION unblocked [${d.agent}] ${d.blockRule}  backup=${bk}`);
    return { message: `Unblocked: ${d.blockRule}. Claude Code will ask again next time.` };
  }
  throw new Error('Unknown action.');
}

// Turn the Claude Code gate on/off by adding/removing our PermissionRequest hook in ~/.claude/settings.json
// The Node.js the hook should use: the one running us (e.g. bundled in the app), except Homebrew's
// versioned Cellar path, which changes on every upgrade, so use its stable symlink instead.
function nodeBin() {
  if (!process.execPath.includes('/Cellar/')) return process.execPath;
  return ['/opt/homebrew/bin/node', '/usr/local/bin/node'].find(exists) || process.execPath;
}
// The Linux app runs us with its own built-in runtime and passes the command that starts it as Node.js
// (ELECTRON_RUN_AS_NODE=1 "<the app>"), so the hook works without Node.js installed.
const nodeCmd = () => process.env.AUDIT_NODE_CMD || `"${nodeBin()}"`;
const GEMINI_SETTINGS = h('.gemini', 'settings.json');
// our hook entry, whatever data folder it was installed from
// (paths compared with forward slashes: on Windows the file may hold either kind)
const slashes = s => s.replace(/\\+/g, '/');
function isOurHook(e) { const t = slashes(JSON.stringify(e)); return t.includes(GATE_MARK) || t.includes(slashes(GATE_SCRIPT)) || t.includes('"ai-access-auditor"') || t.includes('AI Access Auditor'); }
// the hook script as written in hook commands: forward slashes on Windows too, since Claude Code may run hooks through Git Bash
const gateArg = () => WIN ? slashes(GATE_SCRIPT) : GATE_SCRIPT;
function gateStatus() {
  const j = readJson(h('.claude', 'settings.json')) || {};
  const g = readJson(GEMINI_SETTINGS) || {};
  const c = readJson(CODEX_HOOKS) || {};
  const has = cmd => BIN_DIRS.some(d => exists(path.join(d, cmd)));
  return { installed: Object.values(j.hooks || {}).some(list => (list || []).some(isOurHook)), gemini: Object.values(g.hooks || {}).some(list => (list || []).some(isOurHook)),
    geminiInstalled: exists(h('.gemini')) || has('gemini'),
    codex: Object.values(c.hooks || {}).some(list => (list || []).some(isOurHook)), codexInstalled: exists(h('.codex')) || has('codex') };
}
function gateInstall(on, agent = 'Claude Code') {
  if (agent === 'Gemini CLI') return geminiGateInstall(on);
  if (agent === 'Codex CLI') return codexGateInstall(on);
  const file = h('.claude', 'settings.json');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (!exists(file)) fs.writeFileSync(file, '{}\n');
  const j = readJson(file);
  if (!j) throw new Error('Could not read ~/.claude/settings.json (is it valid JSON?)');
  const bk = backup(file);
  j.hooks = j.hooks || {};
  const list = (j.hooks.PermissionRequest || []).filter(e => !isOurHook(e));
  if (on) list.push({ matcher: '*', hooks: [{ type: 'command', command: `${nodeCmd()} "${gateArg()}"`, timeout: 300 }] });
  if (list.length) j.hooks.PermissionRequest = list; else delete j.hooks.PermissionRequest;
  if (!Object.keys(j.hooks).length) delete j.hooks;
  writeJsonAtomic(file, j);
  log(`GATE ${on ? 'turned on' : 'turned off'} for Claude Code  backup=${bk}`);
  return { message: on ? 'Claude Code will now ask you here before it does anything new. New sessions pick this up right away.' : 'Claude Code gate turned off.' };
}
// Codex CLI: PermissionRequest + PreToolUse hooks in ~/.codex/hooks.json. Codex asks you to approve
// new hooks once (type /hooks inside Codex) before it runs them.
const CODEX_HOOKS = h('.codex', 'hooks.json');
function codexGateInstall(on) {
  const file = CODEX_HOOKS;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (!exists(file)) fs.writeFileSync(file, '{}\n');
  const j = readJson(file);
  if (!j) throw new Error('Could not read ~/.codex/hooks.json (is it valid JSON?)');
  const bk = backup(file);
  j.hooks = j.hooks || {};
  const hook = (statusMessage) => ({ type: 'command', command: `${nodeCmd()} "${gateArg()}" --agent=codex`, timeout: 300, statusMessage });
  for (const [ev, matcher, msg] of [['PermissionRequest', '*', 'Asking you in AI Access Auditor'], ['PreToolUse', '^(Bash|apply_patch|mcp__.*)$', 'Checking with AI Access Auditor']]) {
    const list = (j.hooks[ev] || []).filter(e => !isOurHook(e));
    if (on) list.push({ matcher, hooks: [hook(msg)] });
    if (list.length) j.hooks[ev] = list; else delete j.hooks[ev];
  }
  if (!Object.keys(j.hooks).length) delete j.hooks;
  writeJsonAtomic(file, j);
  log(`GATE ${on ? 'turned on' : 'turned off'} for Codex CLI  backup=${bk}`);
  return { message: on ? 'Codex CLI will now ask you here. One-time step: start Codex, type /hooks and trust the "AI Access Auditor" hooks (Codex asks this for any new hook).' : 'Codex CLI gate turned off.' };
}

// Gemini CLI: a BeforeTool hook in ~/.gemini/settings.json. It only pops up when Gemini wouldn't ask you itself
// (YOLO mode, or file edits in auto-edit mode), so you're never asked twice.
function geminiGateInstall(on) {
  const file = GEMINI_SETTINGS;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (!exists(file)) fs.writeFileSync(file, '{}\n');
  const j = readJson(file);
  if (!j) throw new Error('Could not read ~/.gemini/settings.json. It may contain comments; remove them or add the hook by hand.');
  const bk = backup(file);
  j.hooks = j.hooks || {};
  const list = (j.hooks.BeforeTool || []).filter(e => !isOurHook(e));
  if (on) list.push({ matcher: 'run_shell_command|write_file|replace|web_fetch|mcp_.*', hooks: [{
    name: 'ai-access-auditor', type: 'command', command: `${nodeCmd()} "${gateArg()}"`, timeout: 300000,
    description: 'Asks you in AI Access Auditor before Gemini acts on its own (YOLO / auto-edit)' }] });
  if (list.length) j.hooks.BeforeTool = list; else delete j.hooks.BeforeTool;
  if (!Object.keys(j.hooks).length) delete j.hooks;
  writeJsonAtomic(file, j);
  log(`GATE ${on ? 'turned on' : 'turned off'} for Gemini CLI  backup=${bk}`);
  return { message: on ? 'Gemini CLI will now ask you here whenever it would otherwise act without asking (YOLO or auto-edit mode). Restart running Gemini sessions to pick this up.' : 'Gemini CLI gate turned off.' };
}

// ---------- HTTP ----------
function send(res, code, body, type = 'application/json') {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}
function readBody(req) {
  return new Promise((ok, bad) => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > 1e5) req.destroy(); });
    req.on('end', () => { try { ok(d ? JSON.parse(d) : {}); } catch (e) { bad(e); } });
  });
}

const server = http.createServer(async (req, res) => {
  // Guard against DNS rebinding and other sites calling the API
  const host = (req.headers.host || '').split(':')[0];
  if (!['127.0.0.1', 'localhost'].includes(host)) return send(res, 403, { error: 'forbidden host' });
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/' || url.pathname === '/index.html') {
    const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8').replace('__TOKEN__', TOKEN).replace('<html lang="en">', `<html lang="en" data-os="${OS_NAME}">`);
    return send(res, 200, html, 'text/html; charset=utf-8');
  }
  if (url.pathname === '/i18n.js') return send(res, 200, fs.readFileSync(path.join(__dirname, 'public', 'i18n.js'), 'utf8'), 'text/javascript; charset=utf-8');
  if (!url.pathname.startsWith('/api/')) return send(res, 404, { error: 'not found' });
  if (url.pathname === '/api/gate/ask' && req.method === 'POST') {
    if (req.headers['x-gate-token'] !== GATE_TOKEN) return send(res, 401, { error: 'bad gate token' });
    try { return gateAsk(await readBody(req), res); } catch { return send(res, 400, { error: 'bad request' }); }
  }
  if (req.headers['x-token'] !== TOKEN) return send(res, 401, { error: 'bad token, reload the page' });
  try {
    if (req.method === 'GET' && url.pathname === '/api/scan') { sweepExpired(); return send(res, 200, publicScan()); }
    if (req.method === 'GET' && url.pathname === '/api/events') return waitEvents(res);
    if (req.method === 'GET' && url.pathname === '/api/update') return send(res, 200, updateInfo());
    if (req.method === 'GET' && url.pathname === '/api/settings') return send(res, 200, { scope: getScope(), onboarded: !!(readJson(SETTINGS_FILE) || {}).onboarded, theme: (readJson(SETTINGS_FILE) || {}).theme || 'system', lang: (readJson(SETTINGS_FILE) || {}).lang || 'auto', updates: updatesOn() ? 'on' : 'off' });
    if (req.method === 'GET' && url.pathname === '/api/decisions') return send(res, 200, listDecisions());
    if (req.method === 'GET' && url.pathname === '/api/gate/status') return send(res, 200, gateStatus());
    if (req.method === 'GET' && url.pathname === '/api/changes') return send(res, 200, changes());
    if (req.method === 'GET' && url.pathname === '/api/backups') return send(res, 200, listBackups());
    if (req.method === 'GET' && url.pathname === '/api/uploads/trusted') return send(res, 200, { trusted: uploadStore().trusted.map(k => ({ key: k, label: k.replace(HOME, '~') })) });
    if (req.method === 'GET' && url.pathname === '/api/log') return send(res, 200, { log: exists(LOG_FILE) ? fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(Boolean).reverse().slice(0, 200) : [] });
    const body = req.method === 'POST' ? await readBody(req) : {};
    if (url.pathname === '/api/revoke') return send(res, 200, revoke(body.id));
    if (url.pathname === '/api/gate/decide') return send(res, 200, gateDecide(body));
    if (url.pathname === '/api/settings') {
      const cur = readJson(SETTINGS_FILE) || {};
      const next = { ...cur };
      if (body.scope !== undefined) next.scope = body.scope === 'all' ? 'all' : 'ai';
      if (body.onboarded !== undefined) next.onboarded = !!body.onboarded;
      if (body.theme !== undefined) next.theme = ['light', 'dark'].includes(body.theme) ? body.theme : 'system';
      if (body.lang !== undefined) next.lang = ['en', 'fr', 'ar'].includes(body.lang) ? body.lang : 'auto';
      if (body.updates !== undefined) next.updates = body.updates === 'off' ? 'off' : 'on';
      saveFile(SETTINGS_FILE, JSON.stringify(next, null, 2));
      if (body.scope === 'all' && cur.scope !== 'all') { const known = readJson(KNOWN_FILE) || []; writeIds(KNOWN_FILE, [...known, ...scanAll().findings.map(f => f.id)]); } // widening the view isn't "new access"
      if (body.updates === 'on' && cur.updates === 'off') checkForUpdate(true);
      return send(res, 200, { scope: getScope(), onboarded: !!next.onboarded, theme: next.theme || 'system', lang: next.lang || 'auto', updates: next.updates === 'off' ? 'off' : 'on' });
    }
    if (url.pathname === '/api/update/check') return send(res, 200, await checkForUpdate(true));
    if (url.pathname === '/api/update/dismiss') { const u = readJson(UPDATE_FILE) || {}; u.dismissed = String(body.version || ''); saveFile(UPDATE_FILE, JSON.stringify(u, null, 2)); return send(res, 200, updateInfo()); }
    if (url.pathname === '/api/decisions/change') return send(res, 200, changeDecision(body));
    if (url.pathname === '/api/gate/install') return send(res, 200, gateInstall(!!body.on, ['Gemini CLI', 'Codex CLI'].includes(body.agent) ? body.agent : 'Claude Code'));
    if (url.pathname === '/api/revoke-many') return send(res, 200, revokeMany(body.ids));
    if (url.pathname === '/api/expiry') return send(res, 200, setExpiry(body.id, body.hours));
    if (url.pathname === '/api/open-app') return send(res, 200, openApp(body.id));
    if (url.pathname === '/api/ack') return send(res, 200, ack(body.ids));
    if (url.pathname === '/api/review') return send(res, 200, markReviewed(body.id, body.on));
    if (url.pathname === '/api/uploads/trust') return send(res, 200, trustUploader(body.id));
    if (url.pathname === '/api/uploads/untrust') return send(res, 200, untrustUploader(String(body.key || '')));
    if (url.pathname === '/api/export') return send(res, 200, exportReport());
    if (url.pathname === '/api/restore') return send(res, 200, restore(body.name));
    send(res, 404, { error: 'unknown endpoint' });
  } catch (e) { send(res, 400, { error: e.message }); }
});

if (require.main === module) {
  // A full disk shouldn't stop the watcher: a background save that fails is skipped and done again next round
  let diskFullSince = 0;
  process.on('uncaughtException', err => {
    if (err && ['ENOSPC', 'EDQUOT'].includes(err.code)) {
      if (Date.now() - diskFullSince > 600000) { diskFullSince = Date.now(); console.error(`Disk full, couldn't save ${err.path || 'a file'}; still running.`); }
      return;
    }
    console.error(err); process.exit(1);
  });
  if (process.argv.includes('--scan')) {
    const r = scanAll();
    for (const f of r.findings) console.log(`[${f.risk.toUpperCase().padEnd(6)}] ${f.agent} · ${f.category} · ${f.title}\n          ${f.detail}`);
    console.log(`\n${r.findings.length} grants found. TCC readable: ${r.tcc.readable.length ? 'yes' : 'no'}`);
  } else server.listen(process.env.PORT === '0' ? 0 : PORT, '127.0.0.1', () => {
    if (!process.env.AUDIT_PREVIEW) try { // preview copies (screenshots/tests) must not take over the gate
      fs.copyFileSync(path.join(__dirname, 'gate.js'), GATE_SCRIPT);
      fs.writeFileSync(GATE_INFO, JSON.stringify({ port: server.address().port, token: GATE_TOKEN, pid: process.pid }), { mode: 0o600 });
      fs.chmodSync(GATE_INFO, 0o600);
      const cleanup = () => { try { if ((readJson(GATE_INFO) || {}).pid === process.pid) fs.unlinkSync(GATE_INFO); } catch {} };
      process.on('exit', cleanup);
      ['SIGTERM', 'SIGINT', 'SIGHUP'].forEach(sig => process.on(sig, () => process.exit(0)));
    } catch (e) { console.error('gate setup failed:', e.message); }
    startWatching();
    startUploadMonitor();
    startWindowsHelper();
    if (!DEMO) setInterval(() => refreshHistory(3000), 45e3).unref(); // keeps checking new session logs in the background
    setTimeout(() => checkForUpdate(), 20e3).unref();
    setInterval(() => checkForUpdate(), 3600e3).unref(); // checks at most once a day (see checkForUpdate)
    if (process.env.PORT === '0') {
      console.log(`TOKEN ${TOKEN}`); // only for the Mac app that launched us
      // Exit when the Mac app goes away, even if it was force-quit
      const parent = process.ppid;
      setInterval(() => { if (process.ppid !== parent) process.exit(0); }, 3000).unref();
    }
    console.log(`LISTENING ${server.address().port}`);
    console.log(`AI Access Auditor running at http://localhost:${server.address().port}`);
  });
}
module.exports = { scanAll, _test: { saveFile, scanLeftovers, gateInstall, gateStatus, historyFiles, refreshHistory, scanHistory, startWindowsHelper, revoke, restore, listBackups, ssRecords, iniFields, listeningSockets, cmdTokens, exeBase, normCmd, agentKey, scanCredentialManager, netstat, dangerReason } };
