// Checks the scanner's Windows parts on a real Windows machine (run by .github/workflows/windows.yml).
// It adds sample grants, scans, turns one off, restores it, and removes the samples again.
'use strict';
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const run = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return String(e.stdout || '') + String(e.stderr || ''); } };
const RUN = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
const startup = path.join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'Claude Helper.cmd');
let failed = 0;
const check = (ok, what) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${what}`); if (!ok) failed++; };

// sample grants
run('reg', ['add', RUN, '/v', 'Claude Background', '/t', 'REG_SZ', '/d', 'C:\\Tools\\claude.exe --background', '/f']);
run('cmdkey', ['/generic:gh:github.com', '/user:octocat', '/pass:not-a-real-token']);
run('schtasks', ['/create', '/tn', 'Claude nightly', '/tr', 'C:\\Tools\\claude.exe -p tidy', '/sc', 'daily', '/st', '03:00', '/f']);
run('reg', ['add', 'HKCU\\Environment', '/v', 'ANTHROPIC_API_KEY', '/t', 'REG_SZ', '/d', 'sk-not-real', '/f']);
fs.mkdirSync(path.dirname(startup), { recursive: true });
fs.writeFileSync(startup, '@echo off\r\n');

process.env.AUDIT_TIMING = '1';
process.env.AUDIT_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-'));
const srv = require('../../server.js');
const t0 = Date.now();
const r = srv.scanAll();
console.log(`scan took ${Date.now() - t0} ms, ${r.findings.length} findings`);
const t1 = Date.now(); srv.scanAll(); console.log(`second scan took ${Date.now() - t1} ms`);

for (const [name, args] of [['powershell (start only)', ['powershell.exe', ['-NoProfile', '-Command', '1']]], ['cmdkey', ['cmdkey', ['/list']]],
  ['netstat', ['netstat', ['-ano', '-p', 'TCP']]], ['whoami', ['whoami', ['/groups']]], ['reg query', ['reg', ['query', RUN]]]]) {
  const t = Date.now(); run(...args); console.log(`  ${name}: ${Date.now() - t} ms`);
}
for (const f of r.findings) console.log(`  [${f.risk}] ${f.agent} · ${f.category} · ${f.title} · ${f.detail.slice(0, 120)}`);
const find = (cat, re) => r.findings.find(f => f.category === cat && re.test(f.title));
check(find('Background agent', /^Claude Background$/), 'startup entry in the registry (Run key)');
check(find('Background agent', /Claude nightly/), 'scheduled task');
check(find('Background agent', /^Claude Helper$/), 'Startup folder');
check(find('Saved login', /gh:github\.com/), 'GitHub login in Credential Manager');
check(find('Exposed secret', /ANTHROPIC_API_KEY/), 'API key in the user environment');
const t = srv._test;
check(t.netstat().length > 0, 'netstat lists connections');
check(t.cmdTokens(`"${process.execPath}" x.js`)[0] === process.execPath, 'command lines with quoted paths');

// turn off and restore
const runFinding = find('Background agent', /^Claude Background$/);
if (runFinding) {
  t.revoke(runFinding.id);
  check(!/Claude Background/.test(run('reg', ['query', RUN])), 'turning off a startup entry removes it');
  const bk = t.listBackups().find(b => /Claude Background/.test(b.original));
  t.restore(bk.name);
  check(/Claude Background\s+REG_SZ\s+C:\\Tools\\claude\.exe --background/.test(run('reg', ['query', RUN])), 'restoring brings it back exactly');
}
const task = find('Background agent', /Claude nightly/);
if (task) {
  t.revoke(task.id);
  check(/Disabled|Désactivé/i.test(run('powershell', ['-NoProfile', '-Command', "(Get-ScheduledTask -TaskName 'Claude nightly').State"])), 'turning off a scheduled task disables it');
}

// clean up
run('reg', ['delete', RUN, '/v', 'Claude Background', '/f']);
run('cmdkey', ['/delete:gh:github.com']);
run('schtasks', ['/delete', '/tn', 'Claude nightly', '/f']);
run('reg', ['delete', 'HKCU\\Environment', '/v', 'ANTHROPIC_API_KEY', '/f']);
try { fs.unlinkSync(startup); } catch {}
// what the app does: the PowerShell helper keeps the lists fresh, so a scan only reads them
srv._test.startWindowsHelper();
setTimeout(() => {
  for (const n of [1, 2]) { const t2 = Date.now(); srv.scanAll(); console.log(`scan with the helper running (${n}): ${Date.now() - t2} ms`); }
  if (failed) { console.log(`${failed} check(s) failed`); process.exit(1); }
  console.log('All Windows checks passed');
  process.exit(0);
}, 25000);
