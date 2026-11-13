# Demo kit

For videos and screenshots without personal data: the real app runs on an invented home folder.

1. Quit your normal AI Access Auditor (shield in the menu bar → Quit).
2. `./demo/setup.sh` creates `dist/demo-home` (run it again any time to reset everything).
3. `./demo/start.sh` opens the app on it, in demo mode (it doesn't read your Keychain, running programs or system permissions).
4. While recording:
   - `./demo/new-access.sh` gives Cursor a new Slack MCP server → the "new access" popup.
   - `./demo/ask.sh` makes Claude Code ask to run a deploy command → the Allow / Deny popup.
5. Quit the demo app from its shield, then open your normal app again.

For another language, change `"lang":"en"` at the end of `setup.sh` to `fr`, `ar` or `zh`.
Don't turn on "Open at Login" in the demo app: that one setting uses your real login items.
