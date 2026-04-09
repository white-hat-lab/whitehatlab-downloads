# White-Hat-Labs

# Web Application Pentesting Tool

**AI Agent-Based Pentesting — No Noise. No Guesswork. No False Positives.**

## What This Is

This is **not a traditional DAST scanner**.

This is an **AI-powered web application pentesting tool** where you **chat with an agent** that performs real security testing.

- No rule-based scanning
- No payload spraying
- No fake findings

It's a Claude agent with MCP tools — **thinks, tests, and validates vulnerabilities like a human pentester.**

## How It Works

1. **Smart Discovery**
   - Headless browser finds real endpoints, forms, and parameters

2. **Input Validation (Canary + Baseline)**
   - Identifies which inputs actually work
   - Ignores dead/unused parameters

3. **AI Pentesting Agent (Claude)**
   - Decides attack strategy
   - Executes real tests
   - Validates exploitability

4. **MCP Tools (Execution Layer)**
   - Agent uses MCP (Model Context Protocol) to:
     - Send requests
     - Authenticate
     - Navigate browser
     - Extract responses
     - Report findings

MCP comes from the **Claude Code ecosystem (Anthropic)** and connects the agent to real tools.

## Why This Is Different

- Chat-driven pentesting
- Agent decides what to test (not hardcoded rules)
- Tests only real inputs
- Every finding is validated
- No false positives

## Installation

### Mac
- Download WhiteHatLabs.app
- Unzip
- Run: `xattr -cr WhiteHatLabs.app`
- Double-click to open

### Windows
- Download WhiteHatLabs.exe
- Run the app

Python is bundled — no setup needed.
App opens at: **http://localhost:5050**

## Prerequisite (Required)

Install and login to Claude (AI agent):

```bash
npm install -g @anthropic-ai/claude-code
claude
```

## How to Use

1. Open **http://localhost:5050**
2. Paste target URL(s)
3. (Optional) Add login credentials
4. Confirm authorization
5. Click **Start Assessment**

## Monitor

- Live logs show what the agent is doing
- Proxy tab shows all HTTP requests
- Findings appear in real-time

## Results + Chat

- View report in **Report tab**
- Download:
  - CSV
  - DOCX (pentest report)
- Use chat to:
  - Validate findings
  - Retest endpoints
  - Run targeted checks

## Resume or Stop

- **Resume Assessment** → continue previous scan
- **Clean (Stop All & Save)** → stop and save results

## Supported URL Formats

```
http://target.com/api/users
http://target.com/search?q=test
POST http://target.com/login
PUT http://target.com/api/users/1
DELETE http://target.com/api/users/1
```

## Tech Stack

- Python (Flask)
- Playwright
- Claude Code CLI
- MCP (Model Context Protocol)
- SQLite

## Contact

support@aisecurityscanners.dev

## Disclaimer

Only test systems you are authorized to assess.
