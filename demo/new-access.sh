#!/bin/bash
# Gives Cursor a new MCP server (Slack, with a token) in the demo home. The "new access" popup appears within seconds.
set -euo pipefail
cd "$(dirname "$0")/.."
F="$PWD/dist/demo-home/.cursor/mcp.json"
node -e '
const fs = require("fs"), f = process.argv[1], j = JSON.parse(fs.readFileSync(f, "utf8"));
j.mcpServers.slack = { command: "npx", args: ["-y", "@modelcontextprotocol/server-slack"], env: { SLACK_BOT_TOKEN: "xoxb-" + require("crypto").randomBytes(18).toString("hex") } };
fs.writeFileSync(f, JSON.stringify(j, null, 2));' "$F"
echo "Added a Slack MCP server to Cursor (demo home)."
