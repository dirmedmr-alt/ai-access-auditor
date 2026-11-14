// Tests for the scanner, revoke/restore, secrets, the local server and translations.
// Run: npm test     (no dependencies; each case runs in its own process with an invented home folder)
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawn } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const WIN = process.platform === 'win32', MAC = process.platform === 'darwin';
// where desktop apps keep settings, relative to the home folder
const appRel = (...p) => MAC ? path.join('Library', 'Application Support', ...p) : WIN ? path.join('AppData', 'Roaming', ...p) : path.join('.config', ...p);

// A fresh invented home folder with the given files ({ relative path: content }).
function makeHome(files = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'aaa-test-'));
  for (const [rel, content] of Object.entries(files)) {
    if (path.isAbsolute(rel) || rel.split(/[\\/]/).includes('..')) throw new Error('test files must stay inside the test home: ' + rel);
    const f = path.join(home, rel);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, typeof content === 'string' ? content : JSON.stringify(content));
  }
  return home;
}
// Runs code against server.js inside a child process whose home folder is `home`; returns what the code returns.
function inHome(home, code, extraEnv = {}) {
  const env = { ...process.env, HOME: home, USERPROFILE: home, APPDATA: path.join(home, 'AppData', 'Roaming'),
    LOCALAPPDATA: path.join(home, 'AppData', 'Local'), XDG_CONFIG_HOME: path.join(home, '.config'), AUDIT_DEMO: '1', AUDIT_DATA_DIR: path.join(home, '.ai-access-audit'), ...extraEnv };
  for (const [k, v] of Object.entries(env)) if (v === null) delete env[k];
  const script = `const m = require(${JSON.stringify(path.join(ROOT, 'server.js'))}); const out = (() => { ${code} })(); process.stdout.write(JSON.stringify(out === undefined ? null : out));`;
  return JSON.parse(execFileSync(process.execPath, ['-e', script], { env, encoding: 'utf8', timeout: 60000 }));
}
const findings = home => inHome(home, 'return m.scanAll().findings.map(f => ({ id: f.id, agent: f.agent, category: f.category, title: f.title, risk: f.risk, kind: f.action.kind, keys: f.keys }))');
const find = (list, agent, title) => list.find(f => f.agent === agent && f.title === title);

// ---------- detection ----------
test('Claude Code: permissions, folders, MCP servers', () => {
  const home = makeHome({
    '.claude/settings.json': { permissions: { allow: ['Bash(*)', 'Read', 'Bash(npm test:*)'], additionalDirectories: ['~/Documents'] } },
    '.claude.json': { mcpServers: { github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'], env: { GITHUB_TOKEN: 'ghp_' + 'a1B2c3D4'.repeat(4) + 'zz11' } } } },
  });
  const f = findings(home);
  assert.equal(find(f, 'Claude Code', 'Bash(*)').risk, 'high');
  assert.equal(find(f, 'Claude Code', 'Read').risk, 'low');
  assert.ok(find(f, 'Claude Code', '~/Documents'));
  assert.equal(find(f, 'Claude Code', 'github').risk, 'high');
});

test('other agents: Cursor, Gemini, Codex, Windsurf, Zed, Copilot CLI, Kiro, Continue, Cline', () => {
  const home = makeHome({
    '.cursor/mcp.json': { mcpServers: { postgres: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres'] } } },
    '.gemini/settings.json': { tools: { autoAccept: true, allowed: ['run_shell_command(git)'] } },
    '.codex/config.toml': 'sandbox_mode = "danger-full-access"\napproval_policy = "never"\n',
    [appRel('Windsurf', 'User', 'settings.json')]: { 'windsurf.cascadeCommandsAllowList': ['git', 'python'] },
    '.config/zed/settings.json': { agent: { tool_permissions: { default: 'allow' } } },
    '.copilot/settings.json': { defaultPermissionMode: 'allow-all' },
    '.kiro/settings/permissions.yaml': 'rules:\n  - capability: shell\n    match: ["git *"]\n    effect: allow\n  - capability: all\n    effect: allow\n',
    '.continue/permissions.yaml': 'allow:\n  - Bash\n  - Write\n',
    '.cline/data/settings/cline_mcp_settings.json': { mcpServers: { fs: { command: 'npx', args: ['x'], alwaysAllow: ['write_file'] } } },
  });
  const f = findings(home);
  const has = (agent, title, risk) => { const x = find(f, agent, title); assert.ok(x, `${agent}: ${title} not found`); if (risk) assert.equal(x.risk, risk, `${agent}: ${title}`); };
  has('Cursor', 'postgres', 'high');
  has('Gemini CLI', 'tools.autoAccept = true');
  has('Codex CLI', 'sandbox_mode = danger-full-access', 'high');
  has('Codex CLI', 'approval_policy = never', 'high');
  has('Windsurf', 'terminal: python', 'high');
  has('Zed', 'tool_permissions.default: allow', 'high');
  has('Copilot CLI', 'defaultPermissionMode: allow-all', 'high');
  has('Kiro', 'shell: allow (git *)');
  has('Kiro', 'all: allow', 'high');
  has('Continue', 'Bash', 'high');
  has('Cline', 'fs: write_file');
});

// ---------- revoke and restore ----------
test('revoke then restore: JSON, TOML and YAML files stay valid and come back exactly', () => {
  const kiro = 'rules:\n  - capability: shell\n    match: ["git *"]\n    effect: allow\n';
  const home = makeHome({
    '.claude/settings.json': { permissions: { allow: ['Bash(*)', 'Read'] } },
    '.codex/config.toml': 'model = "x"\nsandbox_mode = "danger-full-access"\n',
    '.kiro/settings/permissions.yaml': kiro,
  });
  const before = ['.claude/settings.json', '.codex/config.toml', '.kiro/settings/permissions.yaml'].map(r => fs.readFileSync(path.join(home, r), 'utf8'));
  inHome(home, `const f = m.scanAll().findings;
    for (const t of ['Bash(*)', 'sandbox_mode = danger-full-access', 'shell: allow (git *)']) m._test.revoke(f.find(x => x.title === t).id);`);
  const claude = JSON.parse(fs.readFileSync(path.join(home, '.claude/settings.json'), 'utf8'));
  assert.deepEqual(claude.permissions.allow, ['Read']);
  assert.ok(!fs.readFileSync(path.join(home, '.codex/config.toml'), 'utf8').includes('danger-full-access'));
  assert.equal(fs.readFileSync(path.join(home, '.kiro/settings/permissions.yaml'), 'utf8'), 'rules: []\n');
  inHome(home, 'for (const b of m._test.listBackups()) m._test.restore(b.name);');
  const after = ['.claude/settings.json', '.codex/config.toml', '.kiro/settings/permissions.yaml'].map(r => fs.readFileSync(path.join(home, r), 'utf8'));
  assert.deepEqual(after, before);
});

test('revoke edits the real file behind a symlink (dotfiles) and keeps the link', { skip: WIN }, () => {
  const home = makeHome({ 'dotfiles/claude-settings.json': { permissions: { allow: ['Bash(*)', 'Read'] } } });
  fs.mkdirSync(path.join(home, '.claude'));
  fs.symlinkSync(path.join(home, 'dotfiles/claude-settings.json'), path.join(home, '.claude/settings.json'));
  fs.chmodSync(path.join(home, 'dotfiles/claude-settings.json'), 0o640);
  inHome(home, `m._test.revoke(m.scanAll().findings.find(x => x.title === 'Bash(*)').id);`);
  assert.ok(fs.lstatSync(path.join(home, '.claude/settings.json')).isSymbolicLink(), 'link replaced by a copy');
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(home, 'dotfiles/claude-settings.json'), 'utf8')).permissions.allow, ['Read']);
  assert.equal(fs.statSync(path.join(home, 'dotfiles/claude-settings.json')).mode & 0o777, 0o640);
});

test('the data folder is private to the user', { skip: WIN }, () => {
  const home = makeHome();
  inHome(home, 'return 1');
  for (const d of ['.ai-access-audit', '.ai-access-audit/backups']) assert.equal(fs.statSync(path.join(home, d)).mode & 0o777, 0o700, d);
});

test('restore refuses names that leave the backup folder', () => {
  const home = makeHome();
  for (const name of ['../../.ssh/id_rsa', 'a/b', '..']) assert.throws(() => inHome(home, `m._test.restore(${JSON.stringify(name)})`));
});

// ---------- secrets ----------
test('leaked keys: found, masked everywhere, linked to where they are cancelled, removable', () => {
  const key = 'sk-ant-api03-' + 'Q7w2E9r4T1y6U3i8O5p0'.repeat(2);
  const home = makeHome({ '.claude/projects/p/s.jsonl': JSON.stringify({ message: 'my key is ' + key }) + '\n' });
  const old = new Date(Date.now() - 3600e3); fs.utimesSync(path.join(home, '.claude/projects/p/s.jsonl'), old, old);
  const out = inHome(home, `m._test.refreshHistory(1e9); const pub = JSON.stringify(m.publicScan()); const rep = m.exportReport();
    return { pub, report: require('fs').readFileSync(rep.file, 'utf8'), f: m.scanAll().findings.find(x => x.category === 'Secret in history') }`);
  assert.ok(out.f, 'secret not found');
  assert.ok(!out.pub.includes(key), 'raw key in the scan sent to the page');
  assert.ok(!out.report.includes(key), 'raw key in the exported report');
  assert.ok(!out.report.includes(home), 'home folder path in the exported report');
  assert.equal(out.f.keys[0].url, 'https://console.anthropic.com/settings/keys');
  inHome(home, `m._test.refreshHistory(1e9); m._test.revoke(m.scanAll().findings.find(x => x.category === 'Secret in history').id);`);
  assert.ok(!fs.readFileSync(path.join(home, '.claude/projects/p/s.jsonl'), 'utf8').includes(key));
});

test('agents left behind after uninstalling are reported', () => {
  // Kiro, rarely installed on test machines; this check needs demo mode off (it looks for installed commands)
  const home = makeHome({ '.kiro/settings/permissions.yaml': 'rules: []\n', '.kiro/cli.json': '{}' });
  const out = inHome(home, `return m._test.scanLeftovers().map(f => ({ agent: f.agent, detail: f.detail }))`, { AUDIT_DEMO: null, PATH: '' });
  const kiro = out.find(f => f.agent === 'Kiro');
  if (kiro) assert.match(kiro.detail, /settings and permissions/);
  else assert.fail('Kiro leftovers not reported (unless Kiro is installed on this machine)');
});

test('last used: each Claude Code permission is matched to its latest use in the session logs', () => {
  const line = (ts, name, input) => JSON.stringify({ type: 'assistant', timestamp: ts, message: { content: [{ type: 'tool_use', id: 'x', name, input }] } });
  const home = makeHome({
    '.claude/settings.json': { permissions: { allow: ['Bash(*)', 'Bash(npm test:*)', 'Bash(git push:*)', 'WebFetch', 'Edit', 'mcp__github'], additionalDirectories: ['~/Documents'] } },
    '.claude/projects/p/a.jsonl': [
      JSON.stringify({ type: 'user', timestamp: '2026-11-01T08:00:00Z', message: { content: 'hello' } }),
      line('2026-11-03T10:00:00Z', 'Bash', { command: 'npm test -- --watch' }),
      line('2026-11-05T10:00:00Z', 'Bash', { command: 'ls -la' }),
      line('2026-11-04T10:00:00Z', 'mcp__github__create_issue', { title: 'x' }),
    ].join('\n') + '\n',
    '.claude/projects/p/b.jsonl': line('2026-11-06T09:00:00Z', 'Read', { file_path: '/tmp/x' }) + '\n',
  });
  fs.appendFileSync(path.join(home, '.claude/projects/p/b.jsonl'), line('2026-11-07T09:00:00Z', 'Edit', { file_path: path.join(home, 'Documents', 'notes', 'a.md') }) + '\n');
  const out = inHome(home, `m._test.refreshHistory(1e9); return m.scanAll().findings.filter(f => f.agent === 'Claude Code').map(f => [f.title, f.lastUsed, f.usageSince])`);
  const last = Object.fromEntries(out.map(([t, l]) => [t, l]));
  assert.equal(last['Bash(*)'], '2026-11-05T10:00:00Z');
  assert.equal(last['Bash(npm test:*)'], '2026-11-03T10:00:00Z');
  assert.equal(last['Bash(git push:*)'], null, 'never used');
  assert.equal(last['WebFetch'], null);
  assert.equal(last['Edit'], '2026-11-07T09:00:00Z');
  assert.equal(last['mcp__github'], '2026-11-04T10:00:00Z');
  assert.equal(last['~/Documents'], '2026-11-07T09:00:00Z');
  assert.equal(out[0][2], '2026-11-01T08:00:00Z', 'oldest date in the logs');
});

test('last used: Codex and Gemini, shown only where their logs can tell', () => {
  const home = makeHome();
  const W = rel => path.join(home, rel);
  const write = (rel, content) => { fs.mkdirSync(path.dirname(W(rel)), { recursive: true }); fs.writeFileSync(W(rel), content); };
  write('.codex/config.toml', `[mcp_servers.github]\ncommand = "npx"\n\n[mcp_servers.linear]\ncommand = "npx"\n\n[projects."${W('work/app')}"]\ntrust_level = "trusted"\n\n[projects."${W('old')}"]\ntrust_level = "trusted"\n`);
  const cx = (ts, type, payload) => JSON.stringify({ timestamp: ts, type, payload });
  write('.codex/sessions/2026/11/02/rollout-a.jsonl', [
    cx('2026-11-02T08:00:00Z', 'session_meta', { id: 'a', cwd: W('work/app/src') }),
    cx('2026-11-02T08:05:00Z', 'response_item', { type: 'function_call', name: 'mcp__github__create_issue', arguments: '{}' }),
    cx('2026-11-02T08:06:00Z', 'response_item', { type: 'function_call_output', output: 'mcp__linear__x' }),
  ].join('\n') + '\n');
  write('.gemini/settings.json', JSON.stringify({ tools: { allowed: ['run_shell_command(git status)', 'run_shell_command(npm publish)'] }, mcpServers: { notes: { command: 'notes-mcp' } } }));
  write('.gemini/trustedFolders.json', JSON.stringify({ [W('work/app')]: 'TRUST_FOLDER', [W('elsewhere')]: 'TRUST_FOLDER' }));
  write('.gemini/tmp/app/.project_root', W('work/app'));
  write('.gemini/tmp/app/chats/session-1.jsonl', [
    JSON.stringify({ sessionId: 's', projectHash: 'h', startTime: '2026-11-03T09:00:00Z' }),
    JSON.stringify({ id: '1', timestamp: '2026-11-03T09:01:00Z', type: 'gemini', content: '', toolCalls: [{ id: 't', name: 'run_shell_command', args: { command: 'git status --short' } }, { id: 'u', name: 'notes__search', args: {} }] }),
  ].join('\n') + '\n');
  const out = inHome(home, `m._test.refreshHistory(1e9); return m.scanAll().findings.filter(f => f.agent === 'Codex CLI' || f.agent === 'Gemini CLI').map(f => [f.agent + ' ' + f.title.replace(${JSON.stringify(home)}, '~'), f.lastUsed === undefined ? 'unknown' : f.lastUsed])`);
  const last = Object.fromEntries(out.map(([t, l]) => [t, l === 'unknown' ? undefined : l]));
  assert.equal(last['Codex CLI github'], '2026-11-02T08:05:00Z');
  assert.equal(last['Codex CLI linear'], undefined, "Codex MCP names vary: no use found isn't proof of never");
  assert.equal(last['Codex CLI ~/work/app'], '2026-11-02T08:00:00Z', 'a session ran in a subfolder');
  assert.equal(last['Codex CLI ~/old'], null, 'every Codex session records its folder, so this one was never used');
  assert.equal(last['Gemini CLI run_shell_command(git status)'], '2026-11-03T09:01:00Z');
  assert.equal(last['Gemini CLI run_shell_command(npm publish)'], undefined);
  assert.equal(last['Gemini CLI notes'], '2026-11-03T09:01:00Z');
  assert.equal(last['Gemini CLI ~/work/app'], '2026-11-03T09:01:00Z');
  assert.equal(last['Gemini CLI ~/elsewhere'], undefined);
});

test('command line: text, JSON, unused only, and an exit code for CI', () => {
  const home = makeHome({ '.claude/settings.json': { permissions: { allow: ['Bash(*)', 'Read'] } } });
  const env = { ...process.env, HOME: home, USERPROFILE: home, AUDIT_DEMO: '1', AUDIT_DATA_DIR: path.join(home, '.ai-access-audit'), NO_COLOR: '1' };
  const run = args => { try { return { code: 0, out: execFileSync(process.execPath, [path.join(ROOT, 'server.js'), ...args], { env, encoding: 'utf8', timeout: 60000 }) }; }
    catch (e) { return { code: e.status, out: String(e.stdout) + String(e.stderr) }; } };
  const text = run(['--scan']);
  assert.equal(text.code, 0);
  assert.match(text.out, /HIGH\s+Bash\(\*\)/);
  const json = run(['--json', '--fail-on', 'high']);
  assert.equal(json.code, 1, 'a high-risk grant that is not reviewed fails the run');
  const j = JSON.parse(json.out);
  assert.ok(j.findings.some(f => f.title === 'Bash(*)' && f.risk === 'high'));
  assert.equal(j.failing, j.findings.filter(f => f.risk === 'high').length);
  assert.ok(!json.out.includes(home), 'no home folder path in the output');
  assert.equal(run(['--json', '--fail-on=low']).code, 1);
  assert.equal(run(['--nope']).code, 2, 'unknown options are refused');
  assert.equal(run(['--fail-on', 'extreme']).code, 2);
  assert.match(run(['--help']).out, /--fail-on/);
});

// ---------- local server ----------
test('local server: refuses other sites, needs its token, sends a strict page policy', async () => {
  const home = makeHome();
  const env = { ...process.env, HOME: home, USERPROFILE: home, AUDIT_DEMO: '1', AUDIT_DATA_DIR: path.join(home, '.ai-access-audit'), PORT: '0' };
  const srv = spawn(process.execPath, [path.join(ROOT, 'server.js')], { env });
  try {
    const port = await new Promise((ok, bad) => {
      let buf = ''; const t = setTimeout(() => bad(new Error('server did not start')), 20000);
      srv.stdout.on('data', d => { buf += d; const m = buf.match(/LISTENING (\d+)/); if (m) { clearTimeout(t); ok(Number(m[1])); } });
    });
    const http = require('node:http');
    const get = (p, headers = {}, method = 'GET') => new Promise(ok => {
      const r = http.request({ host: '127.0.0.1', port, path: p, method, headers }, res => { let b = ''; res.on('data', d => b += d).on('end', () => ok({ code: res.statusCode, headers: res.headers, body: b })); });
      r.end();
    });
    assert.equal((await get('/api/scan', { Host: 'evil.example' })).code, 403);
    assert.equal((await get('/', { Host: 'evil.example' })).code, 403);
    assert.equal((await get('/api/scan')).code, 401);
    assert.equal((await get('/api/revoke', { Origin: 'https://evil.example' }, 'POST')).code, 401);
    assert.equal((await get('/api/gate/ask', {}, 'POST')).code, 401);
    const page = await get('/');
    assert.equal(page.code, 200);
    assert.match(page.headers['content-security-policy'], /script-src 'self' 'nonce-[^']+'/);
    assert.equal(page.headers['x-frame-options'], 'DENY');
    assert.ok(!page.headers['access-control-allow-origin']);
  } finally { srv.kill(); }
});

// ---------- translations ----------
test('every website text has French, Arabic and Chinese', () => {
  execFileSync(process.execPath, [path.join(ROOT, 'i18n', 'build-site.js')], { stdio: 'pipe' });
  const zh = new Map(require(path.join(ROOT, 'i18n', 'site-zh.js')));
  for (const row of require(path.join(ROOT, 'i18n', 'site.js'))) {
    assert.equal(row.length, 3, row[0]);
    assert.ok(zh.has(row[0]), 'no Chinese: ' + row[0].slice(0, 60));
  }
});

test('every app text and pattern has Chinese, and native strings are up to date', () => {
  const warns = [];
  const ctx = { document: { documentElement: { dataset: {}, lang: '', dir: '' }, body: null, addEventListener() {} }, location: { search: '' },
    navigator: { languages: ['en'] }, URLSearchParams, NodeFilter: {}, MutationObserver: class { observe() {} }, console: { warn: (...a) => warns.push(a.join(' ')) } };
  ctx.window = ctx; ctx.confirm = () => true;
  require('node:vm').runInNewContext(fs.readFileSync(path.join(ROOT, 'public', 'i18n.js'), 'utf8'), ctx);
  assert.deepEqual(warns, []);
  execFileSync(process.execPath, [path.join(ROOT, 'desktop', 'gen-strings.js'), '--check'], { stdio: 'pipe' });
});
