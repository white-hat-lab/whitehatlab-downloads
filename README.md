<p align="center">
  <img src="https://raw.githubusercontent.com/white-hat-lab/whitehatlab-downloads/main/logo.png" width="120" alt="White-Hat-Labs">
</p>

<h1 align="center">White-Hat-Labs</h1>
<p align="center">AI-Powered Security Testing Suite</p>
<p align="center"><a href="ABOUT.md">About the Scanners</a></p>

---

## Scanners

### Web Application Pentesting (DAST) v1.2
Agentic penetration testing using Claude AI. Paste URLs, the AI agent discovers attack surfaces, tests for OWASP Top 10 vulnerabilities, and reports confirmed findings with evidence.

**[Download Mac](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.2-dast/WhiteHatLabs-DAST-v1.2-Mac.zip)** | **[Download Windows](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.2-dast/WhiteHatLabs-DAST-v1.2.exe)** | **[Release Notes](https://github.com/white-hat-lab/whitehatlab-downloads/releases/tag/v1.2-dast)**

---

### SAST + SCA Scanner v1.0
Static Application Security Testing + Software Composition Analysis. Upload source code or provide a GitHub repo URL for 11-step analysis with AI verification.

**[Download Mac](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.0-sast/WhiteHatLabs-SAST-v1.0-Mac.zip)** | **[Download Windows](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.0-sast/WhiteHatLabs-SAST-v1.0.exe)** | **[Release Notes](https://github.com/white-hat-lab/whitehatlab-downloads/releases/tag/v1.0-sast)**

---

### Network Security Scanner v1.0
Network security assessment — port scanning, service detection, vulnerability checks powered by Claude AI.

**[Download Mac](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.0-network/WhiteHatLabs-Network-v1.0-Mac.zip)** | **[Download Windows](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.0-network/WhiteHatLabs-Network-v1.0.exe)** | **[Release Notes](https://github.com/white-hat-lab/whitehatlab-downloads/releases/tag/v1.0-network)**

---

## Tools

### The Read-Out v1.0 — Report Generator
Transform raw scans into boardroom-ready reports. Upload multiple scan reports and a customer template — The Read-Out merges findings by vulnerability type, deduplicates instances, and generates a polished unified report in seconds.

**[Download (Mac / Windows / Linux)](https://github.com/white-hat-lab/whitehatlab-downloads/releases/download/v1.0-readout/TheReadOut.zip)** | **[Release Notes](https://github.com/white-hat-lab/whitehatlab-downloads/releases/tag/v1.0-readout)**

```bash
# Quick Start:
unzip TheReadOut.zip && cd Report_App
pip install flask python-docx
python3 app.py
# Open http://localhost:5055
```

---

## Prerequisites

1. Install [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code): `npm install -g @anthropic-ai/claude-code`
2. Run `claude` once in terminal to sign in

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
