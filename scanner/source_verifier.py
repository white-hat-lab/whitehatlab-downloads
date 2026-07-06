#!/usr/bin/env python3
"""
source_verifier.py — Source-aware remediation verification for DAST findings.

This is NOT a SAST scanner. It does not run semgrep/codeql/bandit and it does
not hunt for new bugs. It takes findings that DAST *already* produced at
runtime and, *if* the target's source code is available, traces each finding's
input back to its sink and reports whether that input is already sanitized /
remediated on the path the finding exploits.

Two modes, decided purely by whether a repo path is supplied:
  - repo_path given   → source-aware: annotate each finding with where it lives
                        in source and whether it's already fixed there.
  - repo_path absent  → pure blackbox: findings pass through untouched.

Hard rule (see prompt): a finding whose confidence is "confirmed" was PROVEN
exploitable at runtime. Source can never downgrade it to "fixed" — if the
source *looks* fixed, that means the sanitizer doesn't actually cover the
exploited path, and we say so (conflict_note) instead of hiding a real bug.

Reuses the Claude Code CLI already in the loop (no extra dependencies). Every
failure mode is non-fatal: if the CLI is missing or errors, findings are
returned unchanged with remediation_status="not_checked".

CLI:
  python3 source_verifier.py --repo-path ./Archive/sample-targets/pygoat-src --scan-id <id>
  python3 source_verifier.py --repo-path ./Archive/sample-targets/pygoat-src --findings findings.json --out out.json
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime

# Fields the verifier attaches to each finding (kept stable for report_generator).
VERIFY_FIELDS = (
    'source_location',      # "introduction/views.py:142" or ""
    'source_sink',          # the relevant code snippet at the sink
    'remediation_status',   # fixed | vulnerable | partial | not_found | not_checked
    'remediation_evidence', # why — cites file:line
    'source_remediation',   # concrete, source-specific fix steps
    'source_conflict',      # set only when runtime-confirmed but source looks fixed
    'source_checked_at',    # ISO timestamp
)

# Chunk findings so each Claude call reasons over a bounded set.
_CHUNK = 6
_TIMEOUT = 300


def _eprint(*a):
    print(*a, file=sys.stderr)


def _find_claude_cli():
    """Locate the Claude Code CLI. Mirrors agent.py without importing it
    (agent.py has heavy import-time side effects)."""
    env_cli = os.environ.get('WHITELABS_CLAUDE_CLI')
    if env_cli and os.path.isfile(env_cli):
        return env_cli
    which = shutil.which('claude')
    if which:
        return which
    candidates = [
        os.path.expanduser("~/.vscode/extensions/anthropic.claude-code-*/resources/native-binary/claude"),
        "/opt/homebrew/bin/claude",
        "/usr/local/bin/claude",
        "/usr/bin/claude",
        os.path.expanduser("~/.npm-global/bin/claude"),
        os.path.expanduser("~/.local/bin/claude"),
    ]
    for pat in candidates:
        for hit in sorted(glob.glob(pat), reverse=True):
            if os.path.isfile(hit):
                return hit
    return None


def _claude_env():
    env = os.environ.copy()
    # Stale IDE-injected key breaks subscription auth — drop it unless opted in.
    if not os.environ.get('WHITELABS_PASS_ANTHROPIC_API_KEY', '').strip():
        env.pop('ANTHROPIC_API_KEY', None)
        env.pop('ANTHROPIC_API_KEY_FILE', None)
    return env


def _slim(f):
    """Send the model only what it needs to locate the sink."""
    return {
        'id': f.get('id') or f.get('finding_id') or '',
        'vuln_type': f.get('vuln_type', ''),
        'url': f.get('url', ''),
        'method': f.get('method', ''),
        'parameter': f.get('parameter', ''),
        'payload': str(f.get('payload', ''))[:300],
        'confidence': f.get('confidence', 'possible'),
        'evidence': str(f.get('evidence', ''))[:300],
    }


_PROMPT = """You are a source-code verification assistant for a DAST (dynamic) security tool.
The target application's COMPLETE SOURCE CODE is in your current working directory.

A dynamic scan already produced the findings below. Your ONLY job: for each
finding, investigate the source and decide whether the input it abuses is
ALREADY sanitized / remediated ON THE PATH THIS FINDING EXPLOITS.

You are NOT hunting for new bugs. You are NOT running static-analysis tools.
Just read the source with Read / Grep / Glob (and `grep`/`cat` via Bash).
Do NOT modify any file.

METHOD (do this per finding):
1. Find where `parameter` enters the code for the route in `url` (the view /
   handler / controller). Use Grep on the parameter name and the URL path.
2. Trace that value to the sink that matters for `vuln_type`:
     XSS  -> where it's rendered into HTML / a template / a response
     SQLi -> where it reaches a SQL query
     SSRF -> where it becomes an outbound request URL
     IDOR/authz -> the object lookup + the access check
     command injection -> where it reaches a shell / os call
     path traversal -> where it builds a filesystem path
3. Decide whether a sanitizer/defense actually covers THIS parameter on THIS
   path and context — escape()/autoescape for XSS, parameterized query/ORM for
   SQLi, allowlist for SSRF, an ownership check for IDOR, etc.
   A sanitizer that exists elsewhere in the file but is NOT applied to this
   parameter on this path does NOT count as fixed.

CRITICAL RULE — runtime truth wins:
  If a finding's `confidence` is "confirmed", it was PROVEN exploitable at
  runtime. You must NEVER mark it "fixed". If the source appears sanitized, the
  sanitizer does not actually cover the exploited path — set
  remediation_status="vulnerable" and explain the contradiction in
  `conflict_note` (e.g. "escape() applied to `comment` but not `username`",
  or "HTML-escaped but reflected into a JS context").

For EACH finding output one object with EXACTLY these keys:
{
  "id": "<the finding id>",
  "source_location": "<relative/file.py:LINE of the sink, or \\"\\" if not found>",
  "sink_snippet": "<the relevant source lines, <=400 chars>",
  "remediation_status": "fixed | vulnerable | partial | not_found",
  "remediation_evidence": "<one or two sentences citing file:line for your verdict>",
  "source_remediation": "<concrete fix tied to the real code: which file/line, what to change>",
  "conflict_note": "<only if confidence=confirmed but source looks fixed; else \\"\\">"
}

status meaning:
  fixed      = input is properly sanitized for this sink on this path
  vulnerable = no effective sanitizer on this path (or runtime-confirmed)
  partial    = some defense exists but is incomplete / context-mismatched
  not_found  = could not locate the relevant source for this finding

FINDINGS (JSON):
%s

Output ONLY a JSON array of result objects — no prose, no markdown fences."""


def _extract_json_array(text):
    """Pull the first balanced top-level JSON array out of model text."""
    if not text:
        return None
    start = text.find('[')
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == '\\':
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
            if depth == 0:
                blob = text[start:i + 1]
                try:
                    return json.loads(blob)
                except Exception:
                    return None
    return None


def _verify_chunk(claude_cli, repo_path, chunk, log):
    """Run one Claude pass over a chunk of findings. Returns {id: result}."""
    prompt = _PROMPT % json.dumps([_slim(f) for f in chunk], indent=2)
    cmd = [
        claude_cli, '-p', prompt,
        '--output-format', 'json',
        '--dangerously-skip-permissions',
        # Read-only investigation only — never let it edit the target source.
        '--allowedTools', 'Read', 'Grep', 'Glob', 'Bash',
    ]
    try:
        proc = subprocess.run(
            cmd, cwd=repo_path, env=_claude_env(),
            capture_output=True, text=True, timeout=_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        log(f"[source-verify] timed out after {_TIMEOUT}s on chunk of {len(chunk)}")
        return {}
    except Exception as e:
        log(f"[source-verify] claude invocation failed: {e}")
        return {}

    if proc.returncode != 0:
        log(f"[source-verify] claude exited {proc.returncode}: {(proc.stderr or '')[:200]}")
        return {}

    # --output-format json wraps the model's text in {"result": "..."}.
    result_text = proc.stdout
    try:
        envelope = json.loads(proc.stdout)
        result_text = envelope.get('result', proc.stdout)
    except Exception:
        pass

    arr = _extract_json_array(result_text)
    if not isinstance(arr, list):
        log("[source-verify] could not parse a JSON array from model output")
        return {}
    out = {}
    for r in arr:
        if isinstance(r, dict) and r.get('id'):
            out[str(r['id'])] = r
    return out


def verify_findings(findings, repo_path, log=None):
    """Annotate each finding with source-code remediation status.

    findings : list[dict]  — DAST findings (mutated in place and returned)
    repo_path: str | None  — path to target source. If falsy -> blackbox, no-op.
    log      : callable    — optional logger (defaults to stderr).

    Always returns the findings list. Never raises.
    """
    if log is None:
        log = _eprint
    if not findings:
        return findings
    if not repo_path:
        return findings  # blackbox mode — nothing to do
    repo_path = os.path.abspath(os.path.expanduser(repo_path))
    if not os.path.isdir(repo_path):
        log(f"[source-verify] repo path not found: {repo_path} — skipping (blackbox)")
        return findings

    claude_cli = _find_claude_cli()
    now = datetime.now().isoformat()
    if not claude_cli:
        log("[source-verify] Claude CLI not found — marking findings not_checked")
        for f in findings:
            f.setdefault('remediation_status', 'not_checked')
            f['source_checked_at'] = now
        return findings

    log(f"[source-verify] verifying {len(findings)} finding(s) against {repo_path}")
    by_id = {}
    for i in range(0, len(findings), _CHUNK):
        chunk = findings[i:i + _CHUNK]
        by_id.update(_verify_chunk(claude_cli, repo_path, chunk, log))

    fixed = vuln = conflict = 0
    for f in findings:
        fid = str(f.get('id') or f.get('finding_id') or '')
        r = by_id.get(fid)
        f['source_checked_at'] = now
        if not r:
            f.setdefault('remediation_status', 'not_checked')
            continue
        status = (r.get('remediation_status') or 'not_checked').lower()
        confidence = (f.get('confidence') or 'possible').lower()
        conflict_note = (r.get('conflict_note') or '').strip()

        # Enforce the hard rule on our side too, in case the model slips:
        # a runtime-confirmed finding can never be reported as fixed.
        if confidence == 'confirmed' and status in ('fixed', 'partial'):
            if not conflict_note:
                conflict_note = ("Runtime-confirmed exploit, but source appears "
                                 "sanitized — sanitizer does not cover the exploited path.")
            status = 'vulnerable'

        f['remediation_status'] = status
        f['source_location'] = r.get('source_location', '') or ''
        f['source_sink'] = (r.get('sink_snippet', '') or '')[:600]
        f['remediation_evidence'] = r.get('remediation_evidence', '') or ''
        f['source_remediation'] = r.get('source_remediation', '') or ''
        f['source_conflict'] = conflict_note

        if status == 'fixed':
            fixed += 1
        elif status == 'vulnerable':
            vuln += 1
        if conflict_note:
            conflict += 1

    log(f"[source-verify] done: {fixed} fixed-in-source, {vuln} still vulnerable, "
        f"{conflict} runtime/source conflict(s)")
    return findings


# ---------------------------------------------------------------------------
# CLI / standalone use
# ---------------------------------------------------------------------------
def _load_scan_findings(scan_id, data_dir):
    state_path = os.path.join(data_dir, 'scans', scan_id, 'state.json')
    if not os.path.isfile(state_path):
        raise SystemExit(f"state file not found: {state_path}")
    with open(state_path) as f:
        state = json.load(f)
    return state, state_path


def main():
    ap = argparse.ArgumentParser(description='Source-aware remediation verification for DAST findings')
    ap.add_argument('--repo-path', required=True, help='Path to the target application source code')
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--scan-id', help='Verify findings in this scan\'s state.json (writes back in place)')
    src.add_argument('--findings', help='Path to a JSON file: a list of findings, or {"findings": [...]}')
    ap.add_argument('--data-dir', default=os.environ.get('WHITELABS_DATA_DIR') or os.path.expanduser('~/.whitehatlabs-cli'))
    ap.add_argument('--out', help='Where to write annotated findings (default: overwrite source)')
    args = ap.parse_args()

    if args.scan_id:
        state, state_path = _load_scan_findings(args.scan_id, args.data_dir)
        findings = state.get('findings', [])
        verify_findings(findings, args.repo_path, log=print)
        state['findings'] = findings
        out = args.out or state_path
        tmp = out + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(state, f, indent=2, default=str)
        os.replace(tmp, out)
        print(f"[source-verify] wrote {out}")
    else:
        with open(args.findings) as f:
            data = json.load(f)
        findings = data.get('findings', data) if isinstance(data, dict) else data
        verify_findings(findings, args.repo_path, log=print)
        out = args.out or args.findings
        with open(out, 'w') as f:
            json.dump(findings, f, indent=2, default=str)
        print(f"[source-verify] wrote {out}")


if __name__ == '__main__':
    main()
