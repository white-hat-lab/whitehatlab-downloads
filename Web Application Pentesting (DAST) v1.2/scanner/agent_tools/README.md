# Agent Tools

This folder contains helper scripts the scan agent can run through Bash.

The agent should read `TOOLS.json` first. Each entry explains:

- what the script does
- when to use it
- example commands
- what evidence is required before reporting a finding

Current tools:

- `tool_router.py` - generic endpoint classifier. Run after baseline to choose relevant test modules such as injection, API auth logic, IDOR/BOLA, SSRF/open redirect, XXE, upload, LFI/path traversal, JWT, and headers/clickjacking.
- `jwt_tool.py` - JWT decode, variant generation, and replay comparison.
- `clickjacking_tool.py` - frame-protection checks and optional iframe PoC generation.

Use these as optional helpers. They do not replace proof. Verify exploitable behavior with `dast_tool.py` or `curl`, then include a copy-paste replay command when reporting.
