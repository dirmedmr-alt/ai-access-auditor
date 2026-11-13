# Security review: AI Access Auditor

**Date:** November 13, 2026
**Version reviewed:** the code after release 1.0.11. The fixes below ship in **1.0.12**.
**Reviewed by:** the project's maintainer. This is an internal review, not an independent audit.

## Summary

AI Access Auditor reads the settings of the AI agents on your computer, can change them when you click a button, and runs a small web server that only your own computer can reach. A tool like this must not become a new risk, so this review asked one question: could the app be misused to harm the computer it protects?

The review found **4 issues, all fixed in 1.0.12**. The most important one affected people who keep their agent settings in a "dotfiles" folder: removing a permission there could fail without the app noticing. No issue allowed a website or another user to take control of the app.

| # | Issue | Severity | Status |
|---|---|---|---|
| 1 | Revoking a permission didn't work when the settings file was a symbolic link | High | Fixed |
| 2 | The app's data folder, including backups, was readable by other accounts on the same computer | Medium | Fixed |
| 3 | The app window had no second line of defense against injected code | Low (hardening) | Fixed |
| 4 | Links opened from the app weren't limited to web pages, and the update link wasn't checked | Low (hardening) | Fixed |

## What was reviewed

1. **The local server**: can a website you visit, or another program, make the app revoke, restore or change settings?
2. **Showing untrusted text**: names of MCP servers, folders, commands and files come from settings files that other programs can write. Can they inject code into the app's window or its popups?
3. **The bridge between the page and the native app** on macOS, Windows and Linux.
4. **File changes**: revoke, restore, backups, temporary files, file paths received in requests.
5. **Running commands**: is any user-controlled text ever passed to a shell?
6. **Secrets**: do keys and tokens ever appear unmasked on screen, in logs, in reports or in backups?

Each area was checked by reading the code and by testing against the running app, using invented settings files.

## Findings

### 1. Revoking failed for symlinked settings files (High, fixed)

Many developers keep settings such as `~/.claude/settings.json` in a dotfiles folder and link to them. When asked to revoke a permission, the app wrote the new settings to a temporary file and moved it over the link. That replaced the link with a separate copy. The app reported "Revoked", but the real file, the one the agent reads, still held the permission.

**Fix:** every change (revoke, removing secrets from session logs, restore) now resolves the link and edits the real file. The link stays in place, and the file keeps its original permissions. Tested with a full revoke-and-restore cycle on a linked settings file.

### 2. Data folder readable by other accounts (Medium, fixed)

`~/.ai-access-audit` holds backups made before each change. A backup of a settings file can contain an API token. The backup files themselves were private, but the folder was readable by other accounts on the same computer. On a shared computer, another user could list it.

**Fix:** on macOS and Linux the folder and its backup folder are now private to your account (`700`). New files the app creates are private by default.

### 3. No second line of defense in the app window (Low, fixed)

All text from settings files is escaped before it is shown, and no way around that was found. As a second layer, the app's page now has a strict **Content Security Policy**: only the app's own script, marked with a new random value on each load, may run. Injected scripts, outside content, forms and framing are all blocked. Every screen was clicked through afterwards to confirm nothing broke.

### 4. Links opened outside the app (Low, fixed)

The Mac window opened any kind of link outside the app, including `file:` links and other apps' link types. It now opens only web pages and System Settings panes. The Windows and Linux app already allowed only web and email links.

The daily update check takes its download link from GitHub's reply. That link is now accepted only if it is one of this project's own release pages.

## What held up

- **Websites can't control the app.** Requests using another site's address (DNS rebinding), requests without the app's secret token, and attempts to embed the app in another page were all refused. No cross-site access headers are sent.
- **The server only listens on your own computer** (`127.0.0.1`), never on the network.
- **The hook that asks before an agent acts** needs its own separate token, stored in a file only you can read.
- **Text from settings files is always escaped**, both in the main window and in the Windows and Linux popups. Popups run with Electron's isolation and sandbox turned on.
- **No user-controlled text reaches a shell.** Commands are run with fixed arguments. The one command line that is built from data (uninstalling an editor extension on Windows) only accepts plain extension names.
- **Restore rejects path tricks** such as `../../.ssh`, and only runs undo commands from a short fixed list.
- **Secrets stay masked** on screen, in the activity log, in exported reports and in notifications. Removing secrets from a session log keeps no backup, on purpose, because a backup would keep the secret.

## Limits of this review

- It was done by the maintainer. An independent review would add confidence.
- It covers the app's own code. It doesn't cover Electron, Node.js or macOS themselves.
- The Windows installers aren't code-signed yet, so Windows can't confirm who published them. The Mac app is signed and notarized by Apple.

## Reporting a security problem

If you find a security issue, please report it privately through GitHub: on the repository page, open **Security → Report a vulnerability**. Please don't open a public issue for it.
