#!/usr/bin/env node
// Copies the French, Arabic and Chinese of the popups, menus and notifications from the Mac app (macos/i18n.swift)
// into desktop/strings.json, so both apps say exactly the same thing. Run it after changing i18n.swift.
'use strict';
const fs = require('fs');
const path = require('path');
const swift = fs.readFileSync(path.join(__dirname, '..', 'macos', 'i18n.swift'), 'utf8');
const body = swift.slice(swift.indexOf('static let table'), swift.indexOf('static let zh'));
const zhBody = swift.slice(swift.indexOf('static let zh'));
const str = '"((?:[^"\\\\]|\\\\.)*)"';
const re = new RegExp(`${str}\\s*:\\s*\\[\\s*${str}\\s*,\\s*${str}\\s*\\]`, 'g');
const unescape = s => s.replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
  .replace(/\\(["\\'])/g, '$1').replace(/\\n/g, '\n').replace(/\\t/g, '\t');
const table = {};
for (const m of body.matchAll(re)) table[unescape(m[1])] = [unescape(m[2]), unescape(m[3])];
// Chinese: "English": "中文" pairs; every text needs one
const zh = {};
for (const m of zhBody.matchAll(new RegExp(`${str}\\s*:\\s*${str}\\s*,`, 'g'))) zh[unescape(m[1])] = unescape(m[2]);
const noZh = Object.keys(table).filter(k => zh[k] === undefined);
if (noZh.length) { console.error('No Chinese in macos/i18n.swift for:\n' + noZh.map(k => '  - ' + k).join('\n')); process.exit(1); }
for (const k of Object.keys(table)) table[k].push(zh[k]);
const n = Object.keys(table).length;
if (n < 80) { console.error(`Only ${n} strings found in macos/i18n.swift; the format may have changed.`); process.exit(1); }
const out = JSON.stringify(table, null, 1) + '\n';
const file = path.join(__dirname, 'strings.json');
if (process.argv.includes('--check')) {
  if (!fs.existsSync(file) || fs.readFileSync(file, 'utf8') !== out) { console.error('desktop/strings.json is out of date: run node desktop/gen-strings.js'); process.exit(1); }
} else fs.writeFileSync(file, out);
console.log(`desktop/strings.json: ${n} strings`);
