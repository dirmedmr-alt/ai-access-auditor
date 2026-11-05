# AI Access Auditor

A local app that lists the access you've given to AI agents and lets you revoke it.

**Mac app:** `./build-app.sh`, then open `dist/AI Access Auditor.app`. You can drag it into
/Applications. It needs Node.js (`brew install node`) and doesn't use a browser.

    npm start        # browser version: http://localhost:4517
    npm run scan     # print the findings in the terminal

**What it scans:**
- **Claude Code:** tool permissions, permission modes, trusted folders, MCP servers and hooks
- **Claude Desktop:** folder grants, browser control, scheduled tasks and permission bypass
- **MCP servers** in Cursor, VS Code, Windsurf, Gemini CLI, Zed, Codex, Cline and Roo Code
- **macOS privacy grants** for AI apps and terminals (this needs Full Disk Access)
- **Saved logins** for AI tools and GitHub in your Keychain (names only, never the secrets)
- **Background agents:** LaunchAgents and LaunchDaemons, plus crontab lines that start AI tools
- **AI extensions** in VS Code, Cursor and Windsurf, and in Chrome, Brave, Edge and Arc
- **Local AI servers** (Ollama, LM Studio) that other devices on your network can reach
- **Other agents' permissions:**
  - Codex: approval policy, sandbox and trusted projects
  - Gemini CLI: auto-accept, allowed tools and trusted folders
  - Cursor CLI: allow rules
  - Copilot CLI: trusted folders
  - VS Code, Cursor and Windsurf: Copilot auto-approve settings
  - OpenCode: permissions
  - Aider and Goose: auto modes
  - MCP servers in Copilot CLI, Amazon Q, Kiro, OpenCode, Continue and Claude Desktop extensions
- **Agents running right now** with approvals off (`--dangerously-skip-permissions`, `--yolo`, `--full-auto`, `-y`, and so on) or as root. These can be stopped from the popup
- **Privileges every agent inherits from you:** passwordless sudo, loaded SSH keys, and GitHub, AWS, Google Cloud, Azure, Kubernetes, Docker and npm logins
- **API keys** exported in your shell startup files
- **Optional "watch all apps":** macOS privacy permissions and background jobs for every app, not just AI apps

**Menu bar & alerts:** the Mac app stays in the menu bar after you close its window. Every 5 minutes
it checks for new access. When an agent gains something new, the shield turns red, a notification shows
what was added, and the grant is labeled "New" in the app. "Open at Login" in the shield menu starts it
quietly when you log in. Grants that exist on the first run become your starting list, so you're only
alerted about changes after that.

**Live protection (LuLu-style):**
- **New access pops up right away.** The app watches the agents' config files. When anything gains access, a floating window asks whether to **Keep** it (forever, or for 1 hour, 1 day or 7 days) or **Remove** it.
- **Ask before Claude Code acts:** turn this on from the menu bar shield or the Overview. Whenever Claude Code is about to ask for permission, the app pops up **Allow / Deny** instead. Allow can be "just this once" or "always". This works through a `PermissionRequest` hook (`gate.js`) added to `~/.claude/settings.json`. If the app isn't running, or you don't answer within about 4½ minutes, Claude Code asks you in its own window.
- macOS privacy prompts (Screen Recording, Accessibility and so on) come from the system itself, so the app can only report them afterwards.

**Actions:**
- **Revoke:** backs up the file first. You can also tick several grants and revoke them together.
- **Revoke automatically:** after 1 hour, 1 day, 7 days or 30 days.
- **Mark as reviewed:** for grants you want to keep.
- **Restore:** on the History tab.

Install the app with `./build-app.sh --install`. Every action is logged in `~/.ai-access-audit/`.

The server listens only on 127.0.0.1, checks a per-session token, and masks secrets in its output.

## Releasing a download and the website

    ./release.sh                     # or: VERSION=1.0.1-beta ./release.sh

This builds `dist/AI-Access-Auditor-<version>.dmg`:
- It runs on Apple Silicon and Intel, on macOS 13 or later.
- It includes the official Node.js, checksum-verified, so users don't need to install anything.

It also copies the `.dmg` into `site/downloads/` and updates the version, size and SHA-256 shown in
`site/index.html`. To publish, upload the whole `site/` folder to any static host, such as Netlify,
Cloudflare Pages, GitHub Pages or your own server.

The beta is unsigned, so users approve it once in System Settings → Privacy & Security → Open Anyway.
The website explains this step. To remove the warning, join the Apple Developer Program, then sign the
app with a Developer ID and notarize it.

Website screenshots come from invented demo data (`AUDIT_DEMO=1`), never from a real Mac.
