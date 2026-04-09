# About White-Hat-Labs Security Scanners

## Web Application Pentesting (DAST)

AI-driven Dynamic Application Security Testing. Give it a URL — the AI agent does the rest.

### How It Works
1. Paste target URLs
2. AI agent crawls and discovers all endpoints, forms, parameters
3. Tests every endpoint for vulnerabilities autonomously
4. Reports confirmed findings with evidence, payloads, and reproduction steps

### What It Tests
- SQL Injection (error, blind, time-based)
- Cross-Site Scripting (reflected, stored, DOM)
- Command Injection
- Path Traversal / LFI / RFI
- Server-Side Request Forgery (SSRF) with OOB callback confirmation
- XML External Entity (XXE)
- Broken Access Control / IDOR
- JWT Vulnerabilities
- File Upload Attacks
- Open Redirects / CSRF
- LLM Prompt Injection
- Authorization bypass testing

### Features
- Real-time scan logs
- Chat with the AI agent mid-scan
- Proxy tab showing all HTTP traffic
- Professional DOCX and CSV reports with evidence, request, response, and reproduce (curl)
- Resume scans — old findings preserved
- Authentication support (login-protected apps)
- OOB callback server for blind SSRF/XXE confirmation

---

## SAST + SCA Scanner

Static Application Security Testing + Software Composition Analysis.

### How It Works
1. Upload source code (ZIP) or provide a GitHub repo URL
2. 11-step analysis pipeline runs automatically
3. AI agent verifies findings and eliminates false positives

### Analysis Pipeline
1. Pattern scanning (regex-based vulnerability detection)
2. Secrets detection (API keys, passwords, tokens)
3. Infrastructure as Code (IaC) scanning
4. WebQL analysis
5. CodeQL analysis (deep semantic code analysis)
6. API Security (OWASP API Top 10)
7. LLM Security (OWASP LLM Top 10)
8. AI Bundle Scan
9. Deduplication
10. AI Verification (eliminates false positives)
11. False Negative Detection (finds missed vulnerabilities)

### Features
- Supports multiple languages (Python, Java, JavaScript, Go, C#, Ruby, PHP)
- SCA dependency scanning with CVE mapping
- Incremental scanning (only changed files)
- Professional reports

---

## Network Security Scanner

Network security assessment powered by Claude AI.

### Features
- Port scanning and service detection
- 19 MCP tools for comprehensive testing
- 11 pentest tools from scripts
- Vulnerability assessment against discovered services
- Professional reports

---

## The Read-Out — Report Generator

Transform raw scans into boardroom-ready reports.

### Features
- Upload multiple scan reports
- Upload customer template
- Merges findings by vulnerability type
- Deduplicates instances across scans
- Generates polished unified report in seconds

---

## Prerequisites

All scanners require:
1. **Claude Code CLI** — `npm install -g @anthropic-ai/claude-code`
2. Run `claude` once to sign in with your Anthropic account

## Support
- Email: support@aisecurityscanners.dev
- Website: [white-hat-lab.com](https://white-hat-lab.com)
