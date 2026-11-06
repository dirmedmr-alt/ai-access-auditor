// AI Access Auditor for Linux (Electron). It does what the Mac app (macos/main.swift) does:
// - Main window: the auditor UI, served by the bundled scanner (server.js) privately on 127.0.0.1.
// - Tray icon: the app keeps running after the window closes and watches agents' config files live.
// - Popups: Allow / Deny before Claude Code, Gemini CLI or Codex CLI act (see gate.js), and Keep / Remove
//   when an agent gains new access.
'use strict';
const { app, BrowserWindow, Tray, Menu, Notification, dialog, ipcMain, shell, nativeTheme, nativeImage, screen } = require('electron');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const CHECK_INTERVAL = 60e3; // fallback; most changes arrive instantly through the event stream
const DATA_DIR = process.env.AUDIT_DATA_DIR || path.join(os.homedir(), '.ai-access-audit');
const CORE = app.isPackaged ? path.join(process.resourcesPath, 'core') : path.join(__dirname, '..'); // server.js, gate.js, public/
const ICONS = path.join(__dirname, 'build');
const AUTOSTART = path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'autostart', 'ai-access-auditor.desktop');
const startHidden = process.argv.includes('--background');
// the path that starts this app again later (an AppImage runs from a temporary folder that changes every time)
const stableExe = () => process.env.APPIMAGE || process.execPath;
// How the Allow / Deny hooks start Node.js. An AppImage has to mount itself every time it runs, so when
// Node.js is installed anyway, use it; otherwise the app itself runs as Node.js.
function hookNodeCmd() {
  const q = s => `"${s.replace(/(["\\$`])/g, '\\$1')}"`;
  if (process.env.APPIMAGE) {
    const nvm = path.join(os.homedir(), '.nvm', 'versions', 'node');
    let nvmBins = [];
    try { nvmBins = fs.readdirSync(nvm).sort().reverse().map(v => path.join(nvm, v, 'bin', 'node')); } catch {}
    const node = ['/usr/bin/node', '/usr/local/bin/node', ...nvmBins].find(f => { try { fs.accessSync(f, fs.constants.X_OK); return true; } catch { return false; } });
    if (node) return q(node);
  }
  return `ELECTRON_RUN_AS_NODE=1 ${q(stableExe())}`;
}

// ---------- language: the same French and Arabic as the Mac app (desktop/strings.json comes from macos/i18n.swift) ----------
const STRINGS = require('./strings.json');
const EXTRA = { // texts only this app needs
  'AI Access Auditor is still running': ['AI Access Auditor fonctionne toujours', 'لا يزال AI Access Auditor يعمل'],
  'It keeps watching in the background. Open it again from the tray icon or the app menu.':
    ['Il continue de surveiller en arrière-plan. Rouvrez-le depuis l’icône de la zone de notification ou le menu des applications.',
     'يواصل المراقبة في الخلفية. افتحه مجددًا من أيقونة منطقة الإشعارات أو من قائمة التطبيقات.'],
  'The scanner stopped (exit code %d).': ['Le scanner s’est arrêté (code %d).', 'توقف الفاحص (رمز الخروج %d).'],
  'Starting…': ['Démarrage…', 'جارٍ البدء…'],
};
let lang = 'en';
function setLang(pref) {
  const sys = (app.getLocale() || 'en').slice(0, 2).toLowerCase();
  lang = ['en', 'fr', 'ar'].includes(pref) ? pref : ['fr', 'ar'].includes(sys) ? sys : 'en';
}
// "this Mac" → "this computer" (the Mac app's texts are shared)
const OS_WORDS = { en: [[/\bthis Mac\b/g, 'this computer'], [/\byour Mac\b/g, 'your computer']], fr: [[/\bce Mac\b/g, 'cet ordinateur'], [/\bvotre Mac\b/g, 'votre ordinateur']], ar: [] };
function L(en, ...args) {
  const row = STRINGS[en] || EXTRA[en];
  let s = lang === 'en' || !row ? en : row[lang === 'fr' ? 0 : 1];
  let i = 0;
  // in Arabic, isolate names and paths so they keep their own direction inside the sentence
  s = s.replace(/%[@d]/g, () => { const a = args[i++]; return lang === 'ar' && typeof a === 'string' ? `\u2068${a}\u2069` : String(a); });
  for (const [re, to] of OS_WORDS[lang]) s = s.replace(re, to);
  return s;
}
// what the agent wants to do ("run a command"), as it fits after "wants to"
function action(en) {
  if (lang === 'en') return en;
  const row = STRINGS[en];
  if (row) return row[lang === 'fr' ? 0 : 1];
  if (en.startsWith('use ')) return (lang === 'fr' ? 'utiliser ' : 'استخدام ') + en.slice(4);
  return en;
}
function settings() { try { return JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'settings.json'), 'utf8')); } catch { return {}; } }

// ---------- state ----------
let win = null, tray = null, server = null, port = null, token = null, buffer = '';
let pageLoaded = false, pendingJS = [], lastChanges = null, gateInstalled = false, quitting = false, toldStillRunning = false;
const panels = new Map(); // open popups by request id

// ---------- single instance: starting it again shows the window ----------
if (!app.requestSingleInstanceLock()) { app.quit(); }
else {
  app.on('second-instance', (_e, argv) => { if (!argv.includes('--background')) showWindow(); });
  app.whenReady().then(launch);
}
app.setName('AI Access Auditor');

function launch() {
  const s = settings();
  setLang(s.lang);
  nativeTheme.themeSource = ['light', 'dark'].includes(s.theme) ? s.theme : 'system';
  Menu.setApplicationMenu(null); // copy, paste and the other editing keys still work in the page
  buildWindow();
  buildTray();
  if (!startHidden) showWindow();
  startServer();
}

// ---------- main window ----------
function windowState() { try { return JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'window.json'), 'utf8')); } catch { return null; } }
function buildWindow() {
  const st = windowState();
  const visible = st && screen.getAllDisplays().some(d => { const a = d.workArea; return st.x < a.x + a.width && st.x + st.width > a.x && st.y < a.y + a.height && st.y + st.height > a.y; });
  win = new BrowserWindow({
    width: st ? st.width : 1180, height: st ? st.height : 780, ...(visible ? { x: st.x, y: st.y } : {}),
    minWidth: 760, minHeight: 480, show: false, title: 'AI Access Auditor', icon: path.join(ICONS, 'icon.png'),
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#1c1c1e' : '#f2f2f5',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true, spellcheck: false },
  });
  win.loadURL(statusPage(L('Starting…')));
  win.on('close', e => {
    // closing the window keeps the app watching in the background
    if (quitting) return;
    e.preventDefault();
    saveWindowState();
    win.hide();
    if (!toldStillRunning) {
      toldStillRunning = true;
      if (Notification.isSupported()) new Notification({ title: L('AI Access Auditor is still running'), body: L('It keeps watching in the background. Open it again from the tray icon or the app menu.'), icon: appIcon() }).show();
    }
  });
  const wc = win.webContents;
  wc.on('did-finish-load', () => {
    if (!wc.getURL().startsWith('http://127.0.0.1')) return;
    pageLoaded = true;
    pendingJS.splice(0).forEach(js => wc.executeJavaScript(js).catch(() => {}));
  });
  // links to account pages and documentation open in the browser, never inside the app
  wc.setWindowOpenHandler(({ url }) => { openExternal(url); return { action: 'deny' }; });
  wc.on('will-navigate', (e, url) => { if (!isOurs(url)) { e.preventDefault(); openExternal(url); } });
}
function isOurs(url) { try { const u = new URL(url); return u.protocol === 'http:' && u.hostname === '127.0.0.1' && Number(u.port) === port; } catch { return false; } }
function openExternal(url) { if (/^(https?|mailto):/i.test(url)) shell.openExternal(url).catch(() => {}); }
function saveWindowState() { try { if (win && !win.isMinimized()) fs.writeFileSync(path.join(DATA_DIR, 'window.json'), JSON.stringify(win.getBounds())); } catch {} }
function showWindow() {
  if (!win) return;
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
  runJS('window.rescan && window.rescan()');
}
function statusPage(msg) {
  const html = `<html><body style="font:15px system-ui,sans-serif;display:flex;height:90vh;align-items:center;justify-content:center;color:#666;text-align:center;padding:24px">
    <style>@media(prefers-color-scheme:dark){body{color:#aaa;background:#1c1c1e}}</style><div>${msg}</div></body></html>`;
  return 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
}
function runJS(js) {
  if (pageLoaded) win.webContents.executeJavaScript(js).catch(() => {}); else pendingJS.push(js);
}

// ---------- scanner process ----------
function startServer() {
  const env = {
    ...process.env, ELECTRON_RUN_AS_NODE: '1', PORT: '0',
    // the hooks agents run must start Node.js the same way, so they work without Node.js installed
    AUDIT_NODE_CMD: hookNodeCmd(),
  };
  server = spawn(process.execPath, [path.join(CORE, 'server.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  const onData = d => {
    buffer = (buffer + d.toString()).slice(-20000);
    if (!token) { const m = buffer.match(/TOKEN ([a-f0-9]+)/); if (m) token = m[1]; }
    if (!port) {
      const m = buffer.match(/LISTENING (\d+)/);
      if (m) {
        port = Number(m[1]);
        win.loadURL(`http://127.0.0.1:${port}/?syslang=${encodeURIComponent((app.getLocale() || 'en').slice(0, 2))}&os=linux`);
        checkForChanges();
        setInterval(checkForChanges, CHECK_INTERVAL).unref();
        eventLoop();
      }
    }
  };
  server.stdout.on('data', onData);
  server.stderr.on('data', onData);
  server.on('exit', code => {
    if (quitting || !server) return;
    const esc = s => s.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
    pageLoaded = false;
    win.loadURL(statusPage(`${esc(L('The scanner stopped (exit code %d).', code))}<pre style="text-align:start;white-space:pre-wrap;font-size:12px">${esc(buffer.slice(-3000))}</pre>`));
    setTrayIcon(true, 0);
  });
}
function api(p, method = 'GET', body = null) {
  return new Promise(resolve => {
    if (!port || !token) return resolve(null);
    const data = body ? JSON.stringify(body) : null;
    const req = http.request({ host: '127.0.0.1', port, path: `/api/${p}`, method, timeout: p === 'events' ? 80000 : 60000,
      headers: { 'x-token': token, 'content-type': 'application/json', ...(data ? { 'content-length': Buffer.byteLength(data) } : {}) } }, res => {
      let d = '';
      res.on('data', c => { d += c; }).on('end', () => { if (res.statusCode !== 200) return resolve(null); try { resolve(JSON.parse(d)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end(data || undefined);
  });
}

async function checkForChanges() {
  const c = await api('changes');
  if (!c) return;
  lastChanges = c;
  refreshGateStatus();
  setTrayIcon(c.new.length > 0, c.new.length);
  promptNewGrants(c.toNotify || []);
  notifyExpired(c.expired || []);
  if (win.isVisible()) runJS('window.rescan && window.rescan()');
}
// Long-poll the scanner: it answers as soon as an agent asks something or an agent's config changes
async function eventLoop() {
  for (;;) {
    const e = await api('events');
    if (!e) { await new Promise(r => setTimeout(r, 3000)); continue; }
    (e.closed || []).forEach(id => { const p = panels.get(id); if (p) { panels.delete(id); p.dismiss(); } });
    (e.gate || []).forEach(showGatePrompt);
    if (e.changed) checkForChanges();
  }
}
async function refreshGateStatus() { const s = await api('gate/status'); if (s) { gateInstalled = !!s.installed; buildTrayMenu(); } }

// ---------- popups ----------
const rank = r => ({ high: 0, medium: 1, low: 2 }[r] ?? 3);
let openCount = 0;
function prompt(content, onDecision) {
  const w = new BrowserWindow({
    width: 460, height: 260, show: false, frame: false, resizable: false, maximizable: false, minimizable: false, fullscreenable: false,
    alwaysOnTop: true, skipTaskbar: false, title: content.title, icon: path.join(ICONS, 'icon.png'),
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#2a2a2c' : '#fbfbfd',
    webPreferences: { preload: path.join(__dirname, 'popup-preload.js'), contextIsolation: true, sandbox: true, spellcheck: false },
  });
  w.setAlwaysOnTop(true, 'floating');
  w.setVisibleOnAllWorkspaces(true);
  let decided = false;
  const slot = openCount++;
  const finish = (allowed, option) => {
    if (decided) return;
    decided = true;
    openCount = Math.max(0, openCount - 1);
    onDecision(allowed, option);
    if (!w.isDestroyed()) w.destroy();
  };
  w.payload = { ...content, lang, rtl: lang === 'ar', risk: content.risk || 'medium', pills: { high: L(' HIGH RISK ').trim(), medium: L(' MEDIUM RISK ').trim(), low: L(' LOW RISK ').trim() } };
  w.finish = finish;
  w.on('closed', () => finish(null, 0)); // closed without deciding
  w.loadFile(path.join(__dirname, 'popup.html'));
  w.sized = height => {
    const a = screen.getPrimaryDisplay().workArea;
    const off = (slot % 5) * 26;
    w.setBounds({ width: 460, height: Math.min(Math.ceil(height), a.height - 40), x: Math.round(a.x + a.width / 2 - 230 + off), y: a.y + 60 + off });
    if (!w.isVisible()) { w.show(); w.focus(); }
  };
  return { dismiss() { decided = true; openCount = Math.max(0, openCount - 1); if (!w.isDestroyed()) w.destroy(); } };
}
ipcMain.on('popup-ready', (e, height) => { const w = BrowserWindow.fromWebContents(e.sender); if (w && w.sized) w.sized(height); });
ipcMain.on('popup-decide', (e, allowed, option) => { const w = BrowserWindow.fromWebContents(e.sender); if (w && w.finish) w.finish(allowed, Number(option) || 0); });
ipcMain.handle('popup-content', e => { const w = BrowserWindow.fromWebContents(e.sender); return w ? w.payload : null; });

function showGatePrompt(g) {
  if (panels.has(g.id)) return;
  const symbol = ['Bash', 'run_shell_command'].includes(g.tool) ? 'terminal' : g.tool.startsWith('mcp_') ? 'server'
    : ['Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'write_file', 'replace', 'apply_patch'].includes(g.tool) ? 'pencil'
    : g.tool.startsWith('Web') || g.tool === 'web_fetch' ? 'globe' : 'hand';
  panels.set(g.id, prompt({
    symbol, risk: g.risk,
    title: L('%@ wants to %@', g.agent, action(g.action)),
    subtitle: g.cwd ? L('Tool: %@ · in %@', g.tool, g.cwd) : L('Tool: %@', g.tool),
    detail: g.text,
    footnote: L('%@ is paused until you decide. You can take back this decision later under Decisions.', g.agent),
    options: g.canAlways ? [L('Just this once'), L("Always (don't ask again)")] : [L('Just this once')],
    allowTitle: L('Allow'), denyTitle: L('Deny'), safeDefault: g.risk === 'high',
  }, (allowed, option) => {
    panels.delete(g.id);
    if (allowed == null) return; // closed without deciding: after the timeout the agent asks the usual way
    api('gate/decide', 'POST', { id: g.id, decision: allowed ? 'allow' : 'deny', remember: option === 1 ? 'always' : 'once' });
  }));
}

// Something gained access outside the gate (new MCP server, folder, extension…): keep it or remove it
function promptNewGrants(grants) {
  const ordered = grants.slice().sort((a, b) => rank(a.risk) - rank(b.risk));
  for (const g of ordered.slice(0, 3)) {
    const key = `grant-${g.id}`;
    if (panels.has(key)) continue;
    if (g.category === 'AI agent installed' && ['Claude Code', 'Gemini CLI', 'Codex CLI'].includes(g.agent)) { offerGate(g); continue; }
    const canRemove = !!g.revocable;
    const isUpload = g.category === 'Data upload';
    const isProcess = g.category === 'Running agent' || g.category === 'AI tool install' || isUpload;
    panels.set(key, prompt({
      symbol: isUpload ? 'upload' : isProcess ? 'bolt' : 'shield', risk: g.risk,
      title: isProcess ? g.title : g.category === 'AI agent installed' ? L('New AI agent on this Mac: %@', g.agent) : L('%@ got new access', g.agent),
      subtitle: L(g.category),
      detail: `${g.title}\n${g.detail}`,
      footnote: isUpload ? L('"Stop it" ends the program now. "Always" lets this app send data without asking again (undo it under Decisions).')
        : isProcess ? L('"Stop it" ends the process now. "Let it run" can also be limited to 1 hour, 1 day or 7 days.')
        : canRemove ? L('Remove takes the access away now (a backup is saved, so you can undo it).') : L('This one has to be removed by hand. Choose "Review" to see how.'),
      options: (isUpload ? ['Allow this time', 'Always for this app'] : isProcess ? ['Until it ends', 'For 1 hour', 'For 1 day', 'For 7 days'] : ['Keep it', 'Keep for 1 hour', 'Keep for 1 day', 'Keep for 7 days']).map(x => L(x)),
      allowTitle: L(isUpload ? 'Allow' : isProcess ? 'Let it run' : 'Keep'), denyTitle: L(canRemove ? (isProcess ? 'Stop it' : 'Remove') : 'Review'),
      destructive: canRemove,
    }, async (allowed, option) => {
      panels.delete(key);
      if (allowed == null) return;
      if (!allowed) {
        if (!canRemove) return openFinding(g.id);
        const r = await api('revoke', 'POST', { id: g.id });
        if (!r) dialog.showMessageBox({ type: 'warning', message: L("Couldn't remove %@", g.title), detail: L('Open AI Access Auditor to try again.') });
      } else if (isUpload && option === 1) await api('uploads/trust', 'POST', { id: g.id });
      else if (option === 0 || !canRemove) await api('review', 'POST', { id: g.id, on: true });
      else await api('expiry', 'POST', { id: g.id, hours: [0, 1, 24, 168][option] });
      checkForChanges();
    }));
  }
  if (ordered.length > 3) notify(ordered.slice(3));
}

// A new agent that can be put behind Allow / Deny: offer to turn that on right away
function offerGate(g) {
  const key = `grant-${g.id}`;
  panels.set(key, prompt({
    symbol: 'hand', risk: 'medium',
    title: L('New AI agent on this Mac: %@', g.agent), subtitle: L('AI agent installed'), detail: `${g.title}\n${g.detail}`,
    footnote: L('"Ask before it acts" adds a small hook (a backup is saved) so %@ asks you here before it runs commands or changes files. You can turn it off any time on the Overview.', g.agent),
    options: [], allowTitle: L('Ask before it acts'), denyTitle: L('Not now'),
  }, async allowed => {
    panels.delete(key);
    await api('review', 'POST', { id: g.id, on: true });
    checkForChanges();
    if (allowed !== true) return;
    const r = await api('gate/install', 'POST', { on: true, agent: g.agent });
    dialog.showMessageBox({ type: 'info', message: r ? L('%@ will ask you here', g.agent) : L("Couldn't turn it on"), detail: r ? r.message : L('Open AI Access Auditor and use the switch on the Overview.') });
  }));
}

async function toggleGate() {
  const on = !gateInstalled;
  if (on) {
    const { response } = await dialog.showMessageBox({ type: 'question', message: L('Ask before Claude Code acts?'),
      detail: L("Whenever Claude Code is about to ask for permission, this app pops up instead so you can Allow or Deny. This adds a hook to ~/.claude/settings.json (a backup is saved). If this app isn't running, Claude Code just asks the usual way."),
      buttons: [L('Turn On'), L('Cancel')], defaultId: 0, cancelId: 1 });
    if (response !== 0) return;
  }
  if (!await api('gate/install', 'POST', { on })) dialog.showMessageBox({ type: 'warning', message: L("Couldn't change the Claude Code gate") });
  refreshGateStatus();
  runJS('window.rescan && window.rescan()');
}

// ---------- notifications ----------
const appIcon = () => nativeImage.createFromPath(path.join(ICONS, 'icon.png'));
function notify(grants) {
  if (!grants.length || !Notification.isSupported()) return;
  const ordered = grants.slice().sort((a, b) => rank(a.risk) - rank(b.risk));
  for (const g of ordered.slice(0, 3)) {
    const n = new Notification({ title: L('%@ gained access', g.agent), body: `${L(g.category)} · ${L(g.risk === 'high' ? 'High risk' : g.risk[0].toUpperCase() + g.risk.slice(1))}\n${g.title}`,
      urgency: g.risk === 'high' ? 'critical' : 'normal', icon: appIcon() });
    n.on('click', () => openFinding(g.id));
    n.show();
  }
  if (ordered.length > 3) {
    const n = new Notification({ title: L('%d more new AI grants', ordered.length - 3), body: L('Open AI Access Auditor to review them.'), icon: appIcon() });
    n.on('click', () => openView('new'));
    n.show();
  }
}
function notifyExpired(grants) {
  if (!grants.length || !Notification.isSupported()) return;
  const n = new Notification({ title: grants.length === 1 ? L('Access expired and was removed') : L('%d grants expired and were removed', grants.length),
    body: grants.slice(0, 4).map(g => `${g.agent}: ${g.title}`).join('\n'), icon: appIcon() });
  n.on('click', () => openView('history'));
  n.show();
}
function openFinding(id) { showWindow(); runJS(`window.selectFinding && window.selectFinding('${String(id).replace(/[^0-9a-f]/gi, '')}')`); }
function openView(v) { showWindow(); runJS(`window.showView && window.showView('${String(v).replace(/[^a-z]/gi, '')}')`); }

// ---------- tray ----------
function trayImage(alert) {
  const img = nativeImage.createFromPath(path.join(ICONS, alert ? 'tray-alert.png' : 'tray.png'));
  const hi = nativeImage.createFromPath(path.join(ICONS, alert ? 'tray-alert@2x.png' : 'tray@2x.png'));
  if (!hi.isEmpty()) img.addRepresentation({ scaleFactor: 2, buffer: hi.toPNG() });
  return img;
}
function buildTray() {
  tray = new Tray(trayImage(false));
  tray.on('click', showWindow); // not every desktop sends this; the menu always has "Open"
  setTrayIcon(false, 0);
}
function setTrayIcon(alert, count) {
  if (!tray) return;
  tray.setImage(trayImage(alert));
  tray.setToolTip(alert ? (count === 1 ? L('1 new AI access grant') : L('%d new AI access grants', count)) : L('No new AI access'));
  buildTrayMenu();
}
// Linux trays can't rebuild a menu as it opens, so it is rebuilt whenever something changes
function buildTrayMenu() {
  if (!tray) return;
  const c = lastChanges;
  const items = [{ label: !c ? L('Checking…') : !c.new.length ? L('No new AI access') : c.new.length === 1 ? L('1 new grant since you last looked') : L('%d new grants since you last looked', c.new.length), enabled: false }];
  if (c) {
    for (const g of c.new.slice().sort((a, b) => rank(a.risk) - rank(b.risk)).slice(0, 8)) {
      const dot = g.risk === 'high' ? '🔴' : g.risk === 'medium' ? '🟠' : '🟢';
      const t = `${g.agent}: ${g.title}`;
      items.push({ label: `${dot}  ${t.length > 56 ? t.slice(0, 55) + '…' : t}`, click: () => openFinding(g.id) });
    }
    if (c.new.length > 8) items.push({ label: L('…and %d more', c.new.length - 8), click: () => openView('new') });
    if (c.new.length) items.push({ label: L('Mark All as Seen'), click: async () => { await api('ack', 'POST', {}); checkForChanges(); } });
    items.push({ type: 'separator' }, { label: L('%d grants · %d high-risk not reviewed', c.total, c.openHigh), enabled: false });
  }
  items.push({ type: 'separator' },
    { label: L('Open AI Access Auditor'), click: showWindow },
    { label: L('Check Now'), click: checkForChanges },
    { label: L('Decisions…'), click: () => openView('decisions') },
    { label: L('Setup…'), click: () => { showWindow(); runJS('window.openSetup && window.openSetup()'); } },
    { type: 'separator' },
    { label: L('Ask Before Claude Code Acts'), type: 'checkbox', checked: gateInstalled, click: toggleGate },
    { label: L('Open at Login'), type: 'checkbox', checked: loginEnabled(), click: () => { setLogin(!loginEnabled()); buildTrayMenu(); } },
    { label: L('Quit'), click: quit });
  tray.setContextMenu(Menu.buildFromTemplate(items));
}

// ---------- open at login: an XDG autostart entry that starts the app in the background ----------
function loginEnabled() { return fs.existsSync(AUTOSTART); }
function setLogin(on) {
  try {
    if (!on) { if (loginEnabled()) fs.unlinkSync(AUTOSTART); return; }
    fs.mkdirSync(path.dirname(AUTOSTART), { recursive: true });
    const exe = stableExe().replace(/(["`$\\])/g, '\\$1');
    fs.writeFileSync(AUTOSTART, `[Desktop Entry]\nType=Application\nName=AI Access Auditor\nComment=Watches the access AI agents have\nExec="${exe}" --background\nIcon=ai-access-auditor\nTerminal=false\nX-GNOME-Autostart-enabled=true\n`);
  } catch (e) { dialog.showMessageBox({ type: 'warning', message: "Couldn't turn on Open at Login", detail: e.message }); }
}

// ---------- bridge for the page (same commands as the Mac app) ----------
function sendNativeState() { runJS(`window.nativeState && window.nativeState(${JSON.stringify({ native: true, login: loginEnabled(), inApplications: true })})`); }
ipcMain.on('native', (e, msg) => {
  if (!win || e.sender !== win.webContents || !isOurs(e.senderFrame.url) || !msg || typeof msg.cmd !== 'string') return;
  switch (msg.cmd) {
    case 'setLogin': if (!!msg.on !== loginEnabled()) setLogin(!!msg.on); buildTrayMenu(); break;
    case 'setLang': setLang(msg.lang); buildTrayMenu(); return;
    case 'setTheme': nativeTheme.themeSource = ['light', 'dark'].includes(msg.theme) ? msg.theme : 'system'; return;
    case 'relaunch': app.relaunch(); quit(); return;
    default: break;
  }
  sendNativeState();
});
// confirm() in the page: a real dialog with the buttons in the app's language
ipcMain.on('confirm', (e, message) => {
  if (!win || e.sender !== win.webContents) { e.returnValue = false; return; }
  const [first, ...rest] = String(message).split('\n\n');
  e.returnValue = dialog.showMessageBoxSync(win, { type: 'warning', message: first, detail: rest.join('\n\n'), buttons: [L('Confirm'), L('Cancel')], defaultId: 0, cancelId: 1, noLink: true }) === 0;
});

// Automated check (the release build runs it on Linux): AUDIT_SMOKE=<folder> saves screenshots of the
// window and of a sample popup in each language, then quits.
if (process.env.AUDIT_SMOKE) app.whenReady().then(async () => {
  const dir = process.env.AUDIT_SMOKE, wait = ms => new Promise(r => setTimeout(r, ms));
  fs.mkdirSync(dir, { recursive: true });
  for (let i = 0; i < 60 && !pageLoaded; i++) await wait(500);
  await wait(4000);
  fs.writeFileSync(path.join(dir, 'window.png'), (await win.webContents.capturePage()).toPNG());
  fs.writeFileSync(path.join(dir, 'page.txt'), await win.webContents.executeJavaScript('document.documentElement.dataset.os + "\\n" + document.body.innerText').catch(e => String(e)));
  for (const l of ['en', 'fr', 'ar']) {
    setLang(l);
    prompt({ symbol: 'terminal', risk: 'high', title: L('%@ wants to %@', 'Claude Code', action('run a command')), subtitle: L('Tool: %@ · in %@', 'Bash', '~/projects/site'),
      detail: 'rm -rf build && curl -fsSL https://example.com/install.sh | sh', footnote: L('%@ is paused until you decide. You can take back this decision later under Decisions.', 'Claude Code'),
      options: [L('Just this once'), L("Always (don't ask again)")], allowTitle: L('Allow'), denyTitle: L('Deny'), safeDefault: true }, () => {});
    await wait(2500);
    const pw = BrowserWindow.getAllWindows().find(w => w !== win && w.isVisible());
    if (pw) { fs.writeFileSync(path.join(dir, `popup-${l}.png`), (await pw.webContents.capturePage()).toPNG()); pw.destroy(); }
  }
  fs.writeFileSync(path.join(dir, 'done.txt'), `port ${port}\nlogin ${loginEnabled()}\n`);
  quit();
});

function quit() {
  quitting = true;
  saveWindowState();
  const s = server; server = null;
  if (s) s.kill();
  app.quit();
}
app.on('before-quit', () => { quitting = true; const s = server; server = null; if (s) s.kill(); });
app.on('window-all-closed', () => {}); // keep running in the tray
