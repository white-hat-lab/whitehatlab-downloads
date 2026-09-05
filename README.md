<p align="center">
  <img src="https://raw.githubusercontent.com/white-hat-lab/whitehatlab-downloads/main/logo.png" width="120" alt="White-Hat-Labs">
</p>

<h1 align="center">White-Hat-Labs</h1>
<p align="center">AI-Powered Security Testing Suite</p>
<p align="center"><a href="ABOUT.md">About</a> · <a href="GALLERY.md">Screenshots</a></p>

<p align="center">
  <img src="https://raw.githubusercontent.com/white-hat-lab/whitehatlab-downloads/main/screenshot.png" width="900" alt="White-Hat-Labs Scanner — 46 findings at 24% scan progress">
</p>
<p align="center"><em>AI agent scanning a web application — 46 vulnerabilities found at 24% progress</em></p>

---

## Scanners

### Web Application Pentesting (DAST)
Agentic penetration testing using Claude AI. Paste URLs, the AI agent discovers attack surfaces, tests for OWASP Top 10 vulnerabilities, and reports confirmed findings with evidence.

**[Download Mac](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.2-dast/WhiteHatLabs-DAST-v1.2-Mac.zip)** | **[Download Windows](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.2-dast/WhiteHatLabs-DAST-v1.2.exe)** | **[Release Notes](https://github.com/white-hat-lab/whitehatlab-downloads/releases/tag/v1.2-dast)**

---

### SAST + SCA Scanner
Static Application Security Testing + Software Composition Analysis. Paste a GitHub URL or upload a ZIP, pass the setup check, and pattern rules, taint tracking, CodeQL, Semgrep, dependency scanning and an AI review run end to end. Includes checks for AI and agent applications.

**[Run with Docker](SAST_DOCKER.md)** | **[Docker image](https://github.com/white-hat-lab/whitehat-all/pkgs/container/whitehat-all-sast-sca)** | **[Release Notes](https://github.com/white-hat-lab/whitehatlab-downloads/releases/tag/v1.0-sast)**

---

### Network Security Scanner
Network security assessment — port scanning, service detection, vulnerability checks powered by Claude AI.

**[Download Mac](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.0-network/WhiteHatLabs-Network-v1.0-Mac.zip)** | **[Download Windows](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.0-network/WhiteHatLabs-Network-v1.0.exe)** | **[Release Notes](https://github.com/white-hat-lab/whitehatlab-downloads/releases/tag/v1.0-network)**

---

## Tools

### The Read-Out v1.1 — Report Generator
Transform raw scans into boardroom-ready reports. Upload multiple scan reports and a customer template — The Read-Out merges findings by vulnerability type, deduplicates instances, and generates a polished unified report in seconds.

**[Download (Mac / Windows / Linux)](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.1-readout/TheReadOut.zip)** | **[Release Notes](https://github.com/white-hat-lab/whitehatlab-downloads/releases/tag/v1.1-readout)**

```bash
# Quick Start:
unzip TheReadOut.zip && cd Report_App
pip install -r requirements.txt
python3 app.py
# Open http://localhost:5055
```

Docs: [Installation](READOUT_INSTALLATION.md) · [How The Read-Out Works](HOW_READOUT_WORKS.md)

---

## Prerequisites

- Docker users (SAST/SCA): Docker Desktop or Docker Engine, plus a Claude subscription or an Anthropic API key. Claude Code is inside the image; sign in with `docker exec -it whitehat-sast claude auth login`.
- Native packages (DAST, Network, legacy SAST): install [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) with `npm install -g @anthropic-ai/claude-code` and run `claude` once in a terminal to sign in.

## Current scanner release status

The scanner source is private. The SAST/SCA scanner is delivered as a Docker image built from that source; the image contains compiled bytecode and the bundled analysis tools, not the Python source files. See [CURRENT_SCANNER_RELEASE_STATUS.md](CURRENT_SCANNER_RELEASE_STATUS.md).

## Quick Start (macOS, native DAST / Network packages)
```bash
# After downloading and unzipping:
xattr -cr WhiteHatLabs.app    # Required once — removes macOS quarantine
open WhiteHatLabs.app          # Opens the scanner
```

## Quick Start (Windows, native DAST / Network packages)
1. Download the .exe
2. If SmartScreen blocks: Click **"More info"** > **"Run anyway"**
3. Open `http://localhost:5050` in your browser

---

## Support
- Email: support@aisecurityscanners.dev
- Website: [white-hat-lab.com](https://white-hat-lab.com)

Built by [White-Hat-Labs](https://white-hat-lab.com)
