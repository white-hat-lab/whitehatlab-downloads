# Web Application Pentesting (DAST) v1.2

White Hat Labs pentest workbench for web application security testing.

## Features

- Scanner workflow with Codex-backed agent testing
- Crawler and Burp-assisted endpoint import
- Per-engagement storage for proxy rows, logs, findings, coverage, and reports
- Report export with evidence, retest steps, PoC, curl commands, and clickable URLs
- Burp Suite integration helper and request normalization
- Template-based pentest report generation

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

Open:

```text
http://localhost:5051/
```

## Notes

Runtime data is stored outside the repo under the local user data directories. Do not commit generated databases, scan state, exports, or screenshots unless they are intended release assets.
