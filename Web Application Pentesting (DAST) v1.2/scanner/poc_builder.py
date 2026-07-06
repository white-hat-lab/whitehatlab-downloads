#!/usr/bin/env python3
"""
poc_builder.py — On-demand proof-of-concept generation for a single finding.

The "Generate PoC" button (Proxy/Findings tab) calls this. It spawns the Claude
agent to ACTUALLY execute an exploit against the live target for one finding,
captures the real request/response proof, and decides severity from the
*demonstrated impact* (PoC-driven severity), not from a guess.

Reuses the Claude Code CLI already on the host. Synchronous; never raises —
returns a structured dict the API/UI can render.
"""
import glob
import json
import os
import shutil
import subprocess
import sys

_TIMEOUT = None


def _find_claude_cli():
    env_cli = os.environ.get('WHITELABS_CLAUDE_CLI')
    if env_cli and os.path.isfile(env_cli):
        return env_cli
    which = shutil.which('claude')
    if which:
        return which
    for pat in (
        os.path.expanduser("~/.vscode/extensions/anthropic.claude-code-*/resources/native-binary/claude"),
        "/opt/homebrew/bin/claude", "/usr/local/bin/claude", "/usr/bin/claude",
        os.path.expanduser("~/.npm-global/bin/claude"),
        os.path.expanduser("~/.local/bin/claude"),
    ):
        for hit in sorted(glob.glob(pat), reverse=True):
            if os.path.isfile(hit):
                return hit
    return None


def _claude_env():
    env = os.environ.copy()
    if not os.environ.get('WHITELABS_PASS_ANTHROPIC_API_KEY', '').strip():
        env.pop('ANTHROPIC_API_KEY', None)
        env.pop('ANTHROPIC_API_KEY_FILE', None)
    return env


_PROMPT = """You are building a working PROOF-OF-CONCEPT for ONE already-reported web
vulnerability, on a target the operator is authorized to test. Use the **Bash**
tool (curl, and the DAST CLI below) to ACTUALLY execute the exploit against the
live target and capture real evidence. Do NOT fabricate — every value in your
output must come from a real request you made.

DAST CLI (auth cookies for this scan are already stored; send_request reuses them):
  python3 {dast_tool} send_request --url "URL" --method M --param P --payload "PL"
  python3 {dast_tool} get_baseline --url "URL"
  python3 {dast_tool} authenticate --login-url "URL" --username U --password P
  python3 {dast_tool} register --register-url "URL" --login-url "URL"

THE FINDING TO PROVE:
{finding}

STEPS:
1. Reproduce the vulnerability against the target with concrete request(s).
2. Capture the exact request you sent and the response proof (the reflected
   payload, SQL error, command output, file contents, OOB hit, etc.).
3. Decide severity from the IMPACT YOU DEMONSTRATED:
   - critical: RCE, auth bypass, full data exfiltration, SSRF to cloud metadata
   - high: stored XSS, SQLi data read, sensitive file/secret disclosure
   - medium: reflected XSS, CSRF, limited info disclosure
   - low: missing headers, verbose errors
   - info: could NOT reproduce / no real impact shown
4. Never run `find /` or any command that waits for interactive input. There is no fixed time limit; take the time needed to prove or disprove the finding.

Output ONLY this JSON (no prose, no markdown fence):
{{
  "reproduced": true | false,
  "severity": "critical|high|medium|low|info",
  "title": "<one line>",
  "poc_steps": ["step 1", "step 2", ...],
  "poc_request": "<the exact HTTP request / curl you sent>",
  "poc_response": "<the response snippet that proves it, <=1200 chars>",
  "proof": "<what in the response proves exploitation>",
  "impact": "<what an attacker gains>"
}}"""


def _extract_json_obj(text):
    if not text:
        return None
    start = text.find('{')
    if start == -1:
        return None
    depth, in_str, esc = 0, False, False
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
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except Exception:
                    return None
    return None


def build_poc(finding, target_url, repo_path=None, scan_id=None):
    """Generate + run a PoC for one finding. Returns a result dict (never raises).

    Sets DAST_SCAN_ID so the agent's send_request reuses this scan's auth cookies.
    """
    claude_cli = _find_claude_cli()
    if not claude_cli:
        return {'reproduced': False, 'severity': 'info', 'error': 'Claude CLI not found',
                'title': 'PoC unavailable'}

    dast_tool = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dast_tool.py')
    slim = {k: finding.get(k) for k in
            ('vuln_type', 'severity', 'url', 'method', 'parameter', 'payload',
             'evidence', 'confidence') if finding.get(k)}
    slim.setdefault('target', target_url)
    prompt = _PROMPT.format(dast_tool=dast_tool,
                            finding=json.dumps(slim, indent=2, default=str))

    env = _claude_env()
    if scan_id:
        env['DAST_SCAN_ID'] = scan_id
    cmd = [claude_cli, '-p', prompt, '--output-format', 'json',
           '--dangerously-skip-permissions', '--strict-mcp-config']
    try:
        proc = subprocess.run(cmd, cwd=(repo_path if repo_path and os.path.isdir(repo_path) else None),
                              env=env, capture_output=True, text=True, timeout=_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {'reproduced': False, 'severity': 'info', 'error': 'PoC timed out',
                'title': 'PoC timed out'}
    except Exception as e:
        return {'reproduced': False, 'severity': 'info', 'error': str(e),
                'title': 'PoC failed'}

    result_text = proc.stdout
    try:
        result_text = json.loads(proc.stdout).get('result', proc.stdout)
    except Exception:
        pass
    obj = _extract_json_obj(result_text)
    if not isinstance(obj, dict):
        return {'reproduced': False, 'severity': 'info',
                'error': 'could not parse PoC output', 'title': 'PoC inconclusive',
                'raw': (result_text or '')[:500]}
    obj.setdefault('reproduced', False)
    obj.setdefault('severity', 'info' if not obj.get('reproduced') else 'medium')
    return obj


if __name__ == '__main__':
    f = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    print(json.dumps(build_poc(f, f.get('target') or f.get('url', '')), indent=2))
