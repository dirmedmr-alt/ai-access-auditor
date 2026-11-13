#!/bin/bash
# Creates an invented home folder for demo videos and screenshots: realistic agents, permissions, MCP
# servers and a session log with fake keys. Nothing in it comes from this Mac. Run it again to reset.
#   ./demo/setup.sh            then   ./demo/start.sh
set -euo pipefail
cd "$(dirname "$0")/.."
D="$PWD/dist/demo-home"
rand() { node -e "const c='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';console.log([...require('crypto').randomBytes($1)].map(b=>c[b%62]).join(''))"; }
case "$D" in */dist/demo-home) ;; *) echo "unexpected path"; exit 1;; esac
rm -rf "$D"
mkdir -p "$D/.claude/projects/-Users-demo-projects-webapp" "$D/projects/webapp/.claude" "$D/.cursor" "$D/.gemini" "$D/.codex" \
  "$D/Library/Application Support/Claude" "$D/Library/LaunchAgents" "$D/.vscode/extensions/anthropic.claude-code-2.1.0" \
  "$D/.vscode/extensions/github.copilot-chat-0.30.0" "$D/.kube" "$D/.config/gh" "$D/.ai-access-audit" "$D/Downloads"

# Claude Code: a wide-open shell rule, web access, an extra folder, a GitHub MCP server with a token
cat > "$D/.claude/settings.json" <<'J'
{"permissions":{"allow":["Bash(*)","WebFetch","Read","Bash(npm test:*)"],"additionalDirectories":["~/Documents"]}}
J
cat > "$D/.claude.json" <<J
{"projects":{"$D/projects/webapp":{"hasTrustDialogAccepted":true,"allowedTools":[]}},"mcpServers":{"github":{"command":"npx","args":["-y","@modelcontextprotocol/server-github"],"env":{"GITHUB_TOKEN":"ghp_$(rand 36)"}}}}
J
echo '{"permissions":{"allow":["Bash(git push:*)","Edit"]}}' > "$D/projects/webapp/.claude/settings.local.json"

# a past session in which a key ended up in the log (random, not a real key)
KEY="sk-ant-api03-$(rand 40)"
GHK="ghp_$(rand 36)"
cat > "$D/.claude/projects/-Users-demo-projects-webapp/session.jsonl" <<J
{"type":"user","message":"deploy the app, my key is $KEY"}
{"type":"tool","output":"git remote set-url origin https://$GHK@github.com/demo/webapp.git"}
J
touch -t 202611080930 "$D/.claude/projects/-Users-demo-projects-webapp/session.jsonl"

# Cursor, Gemini CLI, Codex CLI, Claude Desktop
cat > "$D/.cursor/mcp.json" <<'J'
{"mcpServers":{"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/Users/demo"]},"postgres":{"command":"npx","args":["-y","@modelcontextprotocol/server-postgres","postgresql://localhost/app"]}}}
J
echo '{"/Users/demo/projects":"TRUST_FOLDER"}' > "$D/.gemini/trustedFolders.json"
echo '{"tools":{"autoAccept":true,"allowed":["run_shell_command(git)"]}}' > "$D/.gemini/settings.json"
printf 'approval_policy = "on-request"\nsandbox_mode = "danger-full-access"\n' > "$D/.codex/config.toml"
cat > "$D/Library/Application Support/Claude/claude_desktop_config.json" <<J
{"preferences":{"localAgentModeTrustedFolders":["$D/Documents/Notes"],"coworkBrowserToolsEnabled":true,"coworkWebSearchEnabled":true}}
J
echo '{"displayName":"Claude Code for VS Code"}' > "$D/.vscode/extensions/anthropic.claude-code-2.1.0/package.json"
echo '{"displayName":"GitHub Copilot Chat"}' > "$D/.vscode/extensions/github.copilot-chat-0.30.0/package.json"
printf 'apiVersion: v1\ncurrent-context: prod-cluster\ncontexts:\n- context:\n    cluster: prod\n  name: prod-cluster\n' > "$D/.kube/config"
printf 'github.com:\n    user: demo-dev\n    git_protocol: https\n' > "$D/.config/gh/hosts.yml"
plutil -convert xml1 -o "$D/Library/LaunchAgents/com.example.claude-nightly.plist" - <<'J'
{"Label":"com.example.claude-nightly","ProgramArguments":["/usr/local/bin/claude","-p","Triage new issues"],"StartCalendarInterval":{"Hour":2}}
J

# the app itself: welcome screen already done, English (change "en" to fr, ar or zh for another language)
echo '{"onboarded":true,"lang":"en"}' > "$D/.ai-access-audit/settings.json"
echo "Demo home ready: $D"
