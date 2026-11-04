#!/usr/bin/env node
// AI Access Auditor — local-only app that inventories access granted to AI agents
// and lets you revoke it (with automatic backups). Zero dependencies.
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const HOME = os.homedir();
const PORT = process.env.PORT ? Number(process.env.PORT) : 4517;
const DATA_DIR = path.join(HOME, '.ai-access-audit');
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
function sh(cmd, args, timeout = 10000) {
  try { return execFileSync(cmd, args, { encoding: 'utf8', timeout, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] }); }
  catch { return ''; }
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
function mcpRisk(cfg) {
  const s = JSON.stringify(cfg || {}).toLowerCase();
  if (/filesystem|shell|exec|terminal|computer|browser|puppeteer|playwright|github|gmail|slack|postgres|mysql|aws|stripe/.test(s)) return 'high';
  if (Object.keys(cfg.env || {}).some(k => SECRET_RE.test(k)) || cfg.headers) return 'high';
  return 'medium';
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
  const otherHooks = Object.entries(j.hooks || {}).filter(([, list]) => !JSON.stringify(list).includes(GATE_MARK) || (list || []).length > 1).map(([k]) => k);
  if (otherHooks.length) out.push({
    agent, category: 'Hooks', title: `Hooks: ${otherHooks.join(', ')}`, detail: `Shell commands run automatically on agent events (${scopeLabel})`,
    risk: 'medium', source: file, action: { kind: 'none', hint: 'Review the "hooks" section in this file manually.' },
  });
  return out;
}

function mcpFinding(agent, name, cfg, file, parentPath, scopeLabel) {
  const cmd = cfg.url ? cfg.url : [cfg.command, ...maskArgs(cfg.args)].filter(Boolean).join(' ');
  const env = maskEnv(cfg.env);
  const envKeys = Object.keys(env);
  return {
    agent, category: 'MCP server', title: name,
    detail: `${cmd}${envKeys.length ? `  · env: ${envKeys.map(k => `${k}=${env[k]}`).join(', ')}` : ''}${scopeLabel ? `  (${scopeLabel})` : ''}`,
    risk: mcpRisk(cfg), source: file,
    action: { kind: 'deleteKey', file, path: parentPath, key: name, value: cfg },
  };
}

function scanClaudeCode() {
  const out = [];
  out.push(...claudeSettingsFindings(h('.claude', 'settings.json'), 'user'));
  out.push(...claudeSettingsFindings(h('.claude', 'settings.local.json'), 'user local'));
  for (const f of ['/Library/Application Support/ClaudeCode/managed-settings.json'])
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
  const f = h('Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
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
    ['VS Code', h('Library', 'Application Support', 'Code', 'User', 'mcp.json'), ['servers']],
    ['VS Code', h('Library', 'Application Support', 'Code', 'User', 'settings.json'), ['mcp', 'servers']],
    ['Gemini CLI', h('.gemini', 'settings.json'), ['mcpServers']],
    ['Zed', h('.config', 'zed', 'settings.json'), ['context_servers']],
    ['Cline', h('Library', 'Application Support', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'), ['mcpServers']],
    ['Roo Code', h('Library', 'Application Support', 'Code', 'User', 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json'), ['mcpServers']],
    ['Cursor', h('Library', 'Application Support', 'Cursor', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'), ['mcpServers']],
  ];
  for (const [agent, f, p] of targets) {
    const servers = getAt(readJson(f), p) || {};
    for (const [name, cfg] of Object.entries(servers)) out.push(mcpFinding(agent, name, cfg || {}, f, p, ''));
  }
  // Codex CLI (TOML) — detect only
  const codex = h('.codex', 'config.toml');
  if (exists(codex)) {
    const t = fs.readFileSync(codex, 'utf8');
    for (const m of t.matchAll(/^\[mcp_servers\.([^\]]+)\]/gm)) out.push({
      agent: 'Codex CLI', category: 'MCP server', title: m[1], detail: 'Defined in config.toml', risk: 'medium', source: codex,
      action: { kind: 'none', hint: 'Edit ~/.codex/config.toml to remove.' },
    });
    const ap = t.match(/^approval_policy\s*=\s*"([^"]+)"/m);
    if (ap && ap[1] === 'never') out.push({ agent: 'Codex CLI', category: 'Permission mode', title: 'approval_policy = never', detail: 'Runs commands without asking', risk: 'high', source: codex, action: { kind: 'none', hint: 'Edit config.toml.' } });
  }
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
};
const AI_CLIENT_RE = /claude|anthropic|openai|chatgpt|cursor|codeium|windsurf|copilot|gemini|perplexity|ollama|lmstudio|raycast|vscode|VSCode|zed|warp|iterm|Terminal|ghostty|node$|python/i;

function scanTcc() {
  const out = [];
  const status = { readable: [], unreadable: [] };
  for (const db of [h('Library', 'Application Support', 'com.apple.TCC', 'TCC.db'), '/Library/Application Support/com.apple.TCC/TCC.db']) {
    if (!exists(db)) { status.unreadable.push(db); continue; }
    let rows;
    try {
      rows = execFileSync('sqlite3', ['-separator', '\t', db, 'SELECT service, client, auth_value, last_modified FROM access WHERE auth_value >= 2;'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      status.readable.push(db);
    } catch { status.unreadable.push(db); continue; }
    for (const line of rows.trim().split('\n').filter(Boolean)) {
      const [service, client, , modified] = line.split('\t');
      const meta = TCC_SERVICES[service];
      if (!meta || !AI_CLIENT_RE.test(client)) continue;
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
];

function scanEnvKeys() {
  const out = [];
  const files = ['.zshrc', '.zprofile', '.bashrc', '.bash_profile', '.profile', '.config/fish/config.fish'].map(f => h(f));
  for (const f of files) {
    if (!exists(f)) continue;
    const lines = fs.readFileSync(f, 'utf8').split('\n');
    lines.forEach((l, i) => {
      const m = l.match(/^\s*(?:export\s+|set\s+-gx\s+)?([A-Z0-9_]*(?:API_KEY|TOKEN|SECRET)[A-Z0-9_]*)\s*[= ]/);
      if (m) out.push({
        agent: 'Shell', category: 'Exposed secret', title: m[1], detail: `${f.replace(HOME, '~')}:${i + 1}: every agent you run in a shell can read it`,
        risk: /ANTHROPIC|OPENAI|GITHUB|AWS|GH_/.test(m[1]) ? 'medium' : 'low', source: f,
        action: { kind: 'none', hint: 'Move it to a secrets manager or scope it to a single command.' },
      });
    });
  }
  return out;
}

// Logins and tokens AI tools keep in the login Keychain (names only; secrets are never read)
function scanKeychain() {
  const out = [];
  const dump = sh('security', ['dump-keychain'], 20000);
  for (const block of dump.split(/^keychain: /m).slice(1)) {
    const attr = k => { const m = block.match(new RegExp(`"${k}"<(?:blob|timedate)>=(?:0x[0-9A-F]+\\s+)?"([^"]*)`)); return m ? m[1].replace(/\\000$/, '') : ''; };
    const cls = (block.match(/^class: "?(\w+)/m) || [])[1] || '';
    const svc = attr('svce'), label = attr('labl'), server = attr('srvr'), acct = attr('acct');
    const name = svc || server || label;
    if (!name || !(AI_NAME_RE.test(`${svc} ${label} ${server}`) || /^gh:github\.com|^github\.com$/.test(name))) continue;
    const mdat = attr('mdat');
    const when = /^\d{14}/.test(mdat) ? `${mdat.slice(0, 4)}-${mdat.slice(4, 6)}-${mdat.slice(6, 8)}` : '';
    const agent = (name.match(AI_NAME_RE) || [/github/i.test(name) ? 'GitHub' : 'Keychain'])[0];
    out.push({
      agent: agent.charAt(0).toUpperCase() + agent.slice(1), category: 'Saved login', title: label || name,
      detail: /Safe Storage$/.test(name)
        ? `Key the app uses to encrypt its own local data${when ? ` · updated ${when}` : ''}`
        : `${cls === 'inet' ? 'Internet password' : 'App password/token'} for ${name}${acct ? ` (account ${mask(acct)})` : ''}${when ? ` · updated ${when}` : ''}`,
      risk: /Safe Storage$/.test(name) ? 'low' : /github/i.test(name) ? 'high' : 'medium', source: '~/Library/Keychains/login.keychain-db',
      action: { kind: 'openApp', bundle: 'com.apple.keychainaccess', fallback: 'Passwords', label: 'Open Keychain Access', hint: `Search for "${name}" and delete it to sign the tool out.` },
    });
  }
  return out;
}

// Background jobs that start AI tools without you: LaunchAgents/Daemons and crontab
function scanBackgroundAgents() {
  const out = [];
  const dirs = [[h('Library', 'LaunchAgents'), true], ['/Library/LaunchAgents', false], ['/Library/LaunchDaemons', false]];
  for (const [dir, userOwned] of dirs) {
    let files = [];
    try { files = fs.readdirSync(dir).filter(f => f.endsWith('.plist')); } catch { continue; }
    for (const f of files) {
      const file = path.join(dir, f);
      let j;
      try { j = JSON.parse(sh('plutil', ['-convert', 'json', '-o', '-', file], 3000) || 'null'); } catch { continue; }
      if (!j || j.Label === OWN_LAUNCH_AGENT) continue;
      const prog = [j.Program, ...(j.ProgramArguments || [])].filter(Boolean).join(' ');
      if (!AI_NAME_RE.test(`${j.Label} ${prog}`)) continue;
      const when = j.StartInterval ? `every ${Math.round(j.StartInterval / 60)} min` : j.StartCalendarInterval ? 'on a schedule' : j.KeepAlive ? 'always running' : j.RunAtLoad ? 'at login' : 'on demand';
      out.push({
        agent: (`${j.Label} ${prog}`.match(AI_NAME_RE) || ['Background'])[0].replace(/^./, c => c.toUpperCase()),
        category: 'Background agent', title: j.Label || f,
        detail: `Runs ${when}: ${prog.replace(HOME, '~').slice(0, 160)}${userOwned ? '' : ' (system-wide)'}`,
        risk: dir.includes('Daemons') || j.KeepAlive ? 'high' : 'medium', source: file,
        action: userOwned ? { kind: 'disableLaunchAgent', file } : { kind: 'none', hint: `Needs an admin: sudo launchctl bootout system ${file}` },
      });
    }
  }
  sh('crontab', ['-l'], 3000).split('\n').forEach((line, i) => {
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
const EDITORS = [
  ['VS Code', h('.vscode', 'extensions'), '/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code'],
  ['Cursor', h('.cursor', 'extensions'), '/Applications/Cursor.app/Contents/Resources/app/bin/cursor'],
  ['Windsurf', h('.windsurf', 'extensions'), '/Applications/Windsurf.app/Contents/Resources/app/bin/windsurf'],
];
const AI_EXT_RE = /copilot|claude|anthropic|openai|chatgpt|codeium|continue\.continue|saoudrizwan|rooveterinaryinc|cline|kilocode|tabnine|amazon-?q|codegpt|gemini|sourcegraph\.cody|supermaven|codewhisperer|blackbox/i;
function scanEditorExtensions() {
  const out = [];
  for (const [editor, dir, cli] of EDITORS) {
    let names = [];
    try { names = fs.readdirSync(dir); } catch { continue; }
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
        action: exists(cli) ? { kind: 'uninstallExt', cli, extId, editor } : { kind: 'none', hint: `Uninstall it from the Extensions panel in ${editor}.` },
      });
    }
  }
  return out;
}

// AI extensions in Chromium browsers (Chrome, Brave, Edge, Arc)
function scanBrowserExtensions() {
  const out = [];
  const browsers = [
    ['Chrome', h('Library', 'Application Support', 'Google', 'Chrome')],
    ['Brave', h('Library', 'Application Support', 'BraveSoftware', 'Brave-Browser')],
    ['Edge', h('Library', 'Application Support', 'Microsoft Edge')],
    ['Arc', h('Library', 'Application Support', 'Arc', 'User Data')],
  ];
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

// Local AI model servers listening on the network (others on your Wi-Fi could use them)
function scanLocalServers() {
  const out = [];
  const known = { 11434: 'Ollama', 1234: 'LM Studio', 8080: null, 5000: null };
  for (const line of sh('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN'], 5000).split('\n').slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 9) continue;
    const proc = cols[0], addr = cols[8];
    const port = Number(addr.split(':').pop());
    const name = known[port] || (AI_NAME_RE.test(proc) ? proc : null);
    if (!name || /^(127\.0\.0\.1|\[::1\]|localhost):/.test(addr)) continue;
    out.push({
      agent: name, category: 'Network exposure', title: `${name} open on port ${port}`,
      detail: `${proc} listens on ${addr}, so other devices on your network can use it without a password`,
      risk: 'high', source: `process ${proc} (pid ${cols[1]})`,
      action: { kind: 'none', hint: name === 'Ollama' ? 'Set OLLAMA_HOST=127.0.0.1 and restart Ollama.' : 'Change the server setting to listen on 127.0.0.1 (localhost) only.' },
    });
  }
  return out;
}

function scanAll() {
  const tcc = scanTcc();
  const findings = [...scanClaudeCode(), ...scanClaudeDesktop(), ...scanOtherMcp(), ...tcc.findings, ...scanEnvKeys(),
    ...scanKeychain(), ...scanBackgroundAgents(), ...scanEditorExtensions(), ...scanBrowserExtensions(), ...scanLocalServers()];
  const reviews = readJson(REVIEW_FILE) || {};
  const expiries = readJson(EXPIRY_FILE) || {};
  const seen = new Set();
  const list = [];
  for (const f of findings) {
    f.id = id(f.source, f.action, f.title, f.agent);
    if (seen.has(f.id)) continue;
    seen.add(f.id);
    f.reviewedAt = reviews[f.id] || null;
    f.expiresAt = expiries[f.id] ? expiries[f.id].at : null;
    f.source = f.source.replace(HOME, '~');
    list.push(f);
  }
  // First run: everything that exists today becomes the baseline, so you aren't flooded with alerts
  let known = readJson(KNOWN_FILE);
  if (!Array.isArray(known)) { known = list.map(f => f.id); writeIds(KNOWN_FILE, known); }
  const knownSet = new Set(known);
  list.forEach(f => { f.isNew = !knownSet.has(f.id) && !f.reviewedAt; });
  return { scannedAt: new Date().toISOString(), findings: list, tcc: tcc.status, manual: MANUAL_CHECKS };
}

// What the page and the menu bar receive: no raw config values (those can hold unmasked tokens)
function publicScan() {
  const r = scanAll();
  r.findings = r.findings.map(f => ({ ...f, action: { kind: f.action.kind, hint: f.action.hint, url: f.action.url, label: f.action.label } }));
  return r;
}

// ---------- change tracking ----------
function writeIds(file, ids) { fs.writeFileSync(file, JSON.stringify([...new Set(ids)].slice(-5000))); }
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
  return { scannedAt: r.scannedAt, total: r.findings.length, openHigh, new: fresh.map(slim), toNotify: toNotify.map(slim), expired };
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
function writeJsonAtomic(file, obj) {
  const tmp = file + '.ai-audit-tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n', { mode: fs.statSync(file).mode });
  fs.renameSync(tmp, file);
}

function clearExpiry(findingId) {
  const ex = readJson(EXPIRY_FILE) || {};
  if (ex[findingId]) { delete ex[findingId]; fs.writeFileSync(EXPIRY_FILE, JSON.stringify(ex, null, 2)); }
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
  if (a.kind === 'uninstallExt') {
    execFileSync(a.cli, ['--uninstall-extension', a.extId], { stdio: 'pipe', timeout: 60000 });
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

const REVOCABLE = ['removeArrayItem', 'deleteKey', 'setFalse', 'tccReset', 'disableLaunchAgent', 'uninstallExt'];

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
  if (!hours) { delete ex[findingId]; fs.writeFileSync(EXPIRY_FILE, JSON.stringify(ex, null, 2)); return { message: 'Auto-revoke turned off' }; }
  const f = scanAll().findings.find(x => x.id === findingId);
  if (!f) throw new Error('Finding not found. Rescan.');
  if (!REVOCABLE.includes(f.action.kind)) throw new Error('This grant can\'t be revoked automatically.');
  const at = new Date(Date.now() + Number(hours) * 3600e3).toISOString();
  ex[findingId] = { at, title: f.title, agent: f.agent, category: f.category, risk: f.risk };
  fs.writeFileSync(EXPIRY_FILE, JSON.stringify(ex, null, 2));
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
  if (exists(meta.original)) backup(meta.original);
  fs.copyFileSync(path.join(BACKUP_DIR, name), meta.original);
  if (meta.original.startsWith(h('Library', 'LaunchAgents'))) sh('launchctl', ['bootstrap', `gui/${process.getuid()}`, meta.original], 5000);
  log(`RESTORE ${meta.original} from ${name}`);
  return { message: `Restored ${meta.original.replace(HOME, '~')}` };
}
function markReviewed(findingId, on) {
  if (on) ack([findingId]);
  const r = readJson(REVIEW_FILE) || {};
  if (on) r[findingId] = new Date().toISOString(); else delete r[findingId];
  fs.writeFileSync(REVIEW_FILE, JSON.stringify(r, null, 2));
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
function startWatching() {
  const targets = [
    [HOME, /^\.claude\.json$|^\.mcp\.json$|^\.(zshrc|zprofile|bashrc|bash_profile|profile)$/],
    [h('.claude'), /^settings(\.local)?\.json$/],
    [h('Library', 'Application Support', 'Claude'), /^claude_desktop_config\.json$/],
    [h('.cursor'), /^mcp\.json$/], [h('.codeium', 'windsurf'), /mcp_config\.json$/], [h('.gemini'), /settings\.json$/], [h('.codex'), /config\.toml$/],
    [h('Library', 'Application Support', 'Code', 'User'), /^(settings|mcp)\.json$/],
    [h('Library', 'LaunchAgents'), /\.plist$/],
    [h('.vscode', 'extensions'), /./], [h('.cursor', 'extensions'), /./], [h('.windsurf', 'extensions'), /./],
  ];
  for (const proj of Object.keys((readJson(h('.claude.json')) || {}).projects || {}))
    targets.push([path.join(proj, '.claude'), /^settings(\.local)?\.json$/], [proj, /^\.mcp\.json$/]);
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
  gatePending.set(gid, { info, finish, suggestions: body.suggestions, delivered: false });
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
  g.finish(allow ? { behavior: 'allow', updatedPermissions: always ? g.suggestions : undefined } : { behavior: 'deny', message: 'You denied this in AI Access Auditor.' });
  return { ok: true };
}

// Turn the Claude Code gate on/off by adding/removing our PermissionRequest hook in ~/.claude/settings.json
function nodeBin() { return ['/opt/homebrew/bin/node', '/usr/local/bin/node'].find(exists) || process.execPath; }
function gateStatus() {
  const j = readJson(h('.claude', 'settings.json')) || {};
  return { installed: JSON.stringify(j.hooks || {}).includes(GATE_MARK) };
}
function gateInstall(on) {
  const file = h('.claude', 'settings.json');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (!exists(file)) fs.writeFileSync(file, '{}\n');
  const j = readJson(file);
  if (!j) throw new Error('Could not read ~/.claude/settings.json (is it valid JSON?)');
  const bk = backup(file);
  j.hooks = j.hooks || {};
  const list = (j.hooks.PermissionRequest || []).filter(e => !JSON.stringify(e).includes(GATE_MARK));
  if (on) list.push({ matcher: '*', hooks: [{ type: 'command', command: `"${nodeBin()}" "${GATE_SCRIPT}"`, timeout: 300 }] });
  if (list.length) j.hooks.PermissionRequest = list; else delete j.hooks.PermissionRequest;
  if (!Object.keys(j.hooks).length) delete j.hooks;
  writeJsonAtomic(file, j);
  log(`GATE ${on ? 'turned on' : 'turned off'} for Claude Code  backup=${bk}`);
  return { message: on ? 'Claude Code will now ask you here before it does anything new. New sessions pick this up right away.' : 'Claude Code gate turned off.' };
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
    const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8').replace('__TOKEN__', TOKEN);
    return send(res, 200, html, 'text/html; charset=utf-8');
  }
  if (!url.pathname.startsWith('/api/')) return send(res, 404, { error: 'not found' });
  if (url.pathname === '/api/gate/ask' && req.method === 'POST') {
    if (req.headers['x-gate-token'] !== GATE_TOKEN) return send(res, 401, { error: 'bad gate token' });
    try { return gateAsk(await readBody(req), res); } catch { return send(res, 400, { error: 'bad request' }); }
  }
  if (req.headers['x-token'] !== TOKEN) return send(res, 401, { error: 'bad token, reload the page' });
  try {
    if (req.method === 'GET' && url.pathname === '/api/scan') { sweepExpired(); return send(res, 200, publicScan()); }
    if (req.method === 'GET' && url.pathname === '/api/events') return waitEvents(res);
    if (req.method === 'GET' && url.pathname === '/api/gate/status') return send(res, 200, gateStatus());
    if (req.method === 'GET' && url.pathname === '/api/changes') return send(res, 200, changes());
    if (req.method === 'GET' && url.pathname === '/api/backups') return send(res, 200, listBackups());
    if (req.method === 'GET' && url.pathname === '/api/log') return send(res, 200, { log: exists(LOG_FILE) ? fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(Boolean).reverse().slice(0, 200) : [] });
    const body = req.method === 'POST' ? await readBody(req) : {};
    if (url.pathname === '/api/revoke') return send(res, 200, revoke(body.id));
    if (url.pathname === '/api/gate/decide') return send(res, 200, gateDecide(body));
    if (url.pathname === '/api/gate/install') return send(res, 200, gateInstall(!!body.on));
    if (url.pathname === '/api/revoke-many') return send(res, 200, revokeMany(body.ids));
    if (url.pathname === '/api/expiry') return send(res, 200, setExpiry(body.id, body.hours));
    if (url.pathname === '/api/open-app') return send(res, 200, openApp(body.id));
    if (url.pathname === '/api/ack') return send(res, 200, ack(body.ids));
    if (url.pathname === '/api/review') return send(res, 200, markReviewed(body.id, body.on));
    if (url.pathname === '/api/restore') return send(res, 200, restore(body.name));
    send(res, 404, { error: 'unknown endpoint' });
  } catch (e) { send(res, 400, { error: e.message }); }
});

if (require.main === module) {
  if (process.argv.includes('--scan')) {
    const r = scanAll();
    for (const f of r.findings) console.log(`[${f.risk.toUpperCase().padEnd(6)}] ${f.agent} · ${f.category} · ${f.title}\n          ${f.detail}`);
    console.log(`\n${r.findings.length} grants found. TCC readable: ${r.tcc.readable.length ? 'yes' : 'no'}`);
  } else server.listen(process.env.PORT === '0' ? 0 : PORT, '127.0.0.1', () => {
    try {
      fs.copyFileSync(path.join(__dirname, 'gate.js'), GATE_SCRIPT);
      fs.writeFileSync(GATE_INFO, JSON.stringify({ port: server.address().port, token: GATE_TOKEN, pid: process.pid }), { mode: 0o600 });
      fs.chmodSync(GATE_INFO, 0o600);
      const cleanup = () => { try { if ((readJson(GATE_INFO) || {}).pid === process.pid) fs.unlinkSync(GATE_INFO); } catch {} };
      process.on('exit', cleanup);
      ['SIGTERM', 'SIGINT', 'SIGHUP'].forEach(sig => process.on(sig, () => process.exit(0)));
    } catch (e) { console.error('gate setup failed:', e.message); }
    startWatching();
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
module.exports = { scanAll };
