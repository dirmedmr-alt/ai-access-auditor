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
- **API keys** exported in your shell startup files

**Menu bar & alerts:** the Mac app stays in the menu bar after you close its window. Every 5 minutes
it checks for new access. When an agent gains something new, the shield turns red, a notification shows
what was added, and the grant is labeled "New" in the app. "Open at Login" in the shield menu starts it
quietly when you log in. Grants that exist on the first run become your starting list, so you're only
alerted about changes after that.

**Actions:**
- **Revoke:** backs up the file first. You can also tick several grants and revoke them together.
- **Revoke automatically:** after 1 hour, 1 day, 7 days or 30 days.
- **Mark as reviewed:** for grants you want to keep.
- **Restore:** on the History tab.

Install the app with `./build-app.sh --install`. Every action is logged in `~/.ai-access-audit/`.

The server listens only on 127.0.0.1, checks a per-session token, and masks secrets in its output.
