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

### Web Application Pentesting (DAST) — legacy v1.2 package
Agentic penetration testing using Claude AI. Paste URLs, the AI agent discovers attack surfaces, tests for OWASP Top 10 vulnerabilities, and reports confirmed findings with evidence.

> The v1.2 downloads are retained for historical access and do not contain the current private-source fixes. No replacement binary has passed the current release build process yet.

**[Download Mac](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.2-dast/WhiteHatLabs-DAST-v1.2-Mac.zip)** | **[Download Windows](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.2-dast/WhiteHatLabs-DAST-v1.2.exe)** | **[Release Notes](https://github.com/white-hat-lab/whitehatlab-downloads/releases/tag/v1.2-dast)**

---

### SAST + SCA Scanner — legacy v1.0 package
Static Application Security Testing + Software Composition Analysis. Upload source code or provide a GitHub repo URL for 11-step analysis with AI verification.

> The v1.0 downloads are retained for historical access and do not contain the current SAST/SCA fixes. No replacement binary has passed the current release build process yet.

**[Download Mac](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.0-sast/WhiteHatLabs-SAST-v1.0-Mac.zip)** | **[Download Windows](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.0-sast/WhiteHatLabs-SAST-v1.0.exe)** | **[Release Notes](https://github.com/white-hat-lab/whitehatlab-downloads/releases/tag/v1.0-sast)**

---

### Network Security Scanner — legacy v1.0 package
Network security assessment — port scanning, service detection, vulnerability checks powered by Claude AI.

> The v1.0 downloads are retained for historical access and do not contain the current private-source fixes. No replacement binary has passed the current release build process yet.

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

1. Install [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code): `npm install -g @anthropic-ai/claude-code`
2. Run `claude` once in terminal to sign in

## Current scanner release status

The fixed scanner source is consolidated in a private source-of-truth repository. Current private Docker build definitions exist for DAST, SAST/SCA, and network delivery, but no public container image is published because Python source can be extracted from image layers. See [CURRENT_SCANNER_RELEASE_STATUS.md](CURRENT_SCANNER_RELEASE_STATUS.md) for the validation and artifact policy.

## Quick Start (macOS)
```bash
# After downloading and unzipping:
xattr -cr WhiteHatLabs.app    # Required once — removes macOS quarantine
open WhiteHatLabs.app          # Opens the scanner
```

## Quick Start (Windows)
1. Download the .exe
2. If SmartScreen blocks: Click **"More info"** > **"Run anyway"**
3. Open `http://localhost:5050` in your browser

---

## Support
- Email: support@aisecurityscanners.dev
- Website: [white-hat-lab.com](https://white-hat-lab.com)

Built by [White-Hat-Labs](https://white-hat-lab.com)
