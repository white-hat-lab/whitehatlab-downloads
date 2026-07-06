#!/usr/bin/env python3
"""
dast_tool.py — Bash-callable Python CLI that replaces the MCP server.

Why: claude CLI `-p` mode has a bug where MCP tools are not exposed to the
model even when the MCP handshake succeeds. This tool gives the agent the
same functionality through a regular command-line interface. The agent calls
us via Bash, parses our JSON output, and feeds results back into its reasoning.

Commands (all print JSON to stdout):
  get_baseline        --url URL [--method GET] [--headers JSON]
  send_request        --url URL [--method GET] [--data STR] [--headers JSON] [--param KEY] [--payload VAL]
  get_crawl_results   [--scan-id ID]
  authenticate        --login-url URL --username U --password P
  report_finding      --vuln-type T --severity S --url URL --method M --parameter P --payload PL --evidence E [--response-preview ...] [--risk-reasoning ...] [--attack-narrative ...] [--confidence C] [--request ...] [--curl-command ...]
  coverage            --url URL [--method GET] --json '[{"category":"OWASP Web A03 Injection","subcategory":"SQLi","status":"tested","reason":"..."}]'
  generate_callback
  check_callback      --session SESSION_ID  (or --token TOKEN for legacy)
  browser_get         --url URL       (uses Playwright headless)
  browser_js          --url URL --script JS

State is read/written through a shared JSON file under ~/.whitehatlabs-cli/scans/<scan_id>/state.json
The scan_id is taken from DAST_SCAN_ID env var set by the agent spawn.
"""
import argparse
import json
import os
import sys
import time
import uuid
import hashlib
import fcntl
from datetime import datetime
from urllib.parse import urlparse, urlencode

# Avoid stdout pollution from urllib3 warnings
import warnings
warnings.filterwarnings("ignore")

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# State handling
# ---------------------------------------------------------------------------
_DATA_DIR = os.environ.get('WHITELABS_DATA_DIR') or os.path.expanduser('~/.whitehatlabs-cli')
_SCAN_ID = os.environ.get('DAST_SCAN_ID', '').strip()


def _state_path():
    if not _SCAN_ID:
        # fallback: global state for standalone use (no active scan)
        return os.path.join(_DATA_DIR, 'global_state.json')
    return os.path.join(_DATA_DIR, 'scans', _SCAN_ID, 'state.json')


def _load_state():
    p = _state_path()
    if not p or not os.path.isfile(p):
        return {}
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return {}


def _merge_list(existing, incoming, key_fields=None):
    out = list(existing or [])
    seen = set()

    def item_key(item):
        if key_fields and isinstance(item, dict):
            return tuple(item.get(k) for k in key_fields)
        if isinstance(item, dict) and item.get('id'):
            return ('id', item.get('id'))
        try:
            return json.dumps(item, sort_keys=True, default=str)
        except Exception:
            return str(item)

    for item in out:
        seen.add(item_key(item))
    for item in incoming or []:
        k = item_key(item)
        if k in seen:
            continue
        out.append(item)
        seen.add(k)
    return out


def _merge_state(existing, incoming):
    """Merge stale process state into current disk state without dropping keys.

    Agent commands run as separate processes and can write findings/coverage in
    parallel. A plain atomic replace can still lose data when process B loaded
    state before process A saved findings. This merge keeps append-only scan
    artifacts intact while allowing scalar fields like auth to be refreshed.
    """
    merged = dict(existing or {})
    for key, value in (incoming or {}).items():
        current = merged.get(key)
        if key == 'findings':
            merged[key] = _merge_list(current, value, ('vuln_type', 'url', 'parameter'))
        elif key == 'checklist_coverage':
            merged[key] = _merge_list(current, value, ('method', 'url', 'area'))
        elif key == 'logs':
            merged[key] = _merge_list(current, value)[-2000:]
        elif isinstance(current, dict) and isinstance(value, dict):
            nested = dict(current)
            nested.update(value)
            merged[key] = nested
        elif isinstance(current, list) and isinstance(value, list):
            merged[key] = _merge_list(current, value)
        else:
            merged[key] = value
    return merged


def _save_state_atomic(state):
    p = _state_path()
    if not p:
        return False
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = f"{p}.{os.getpid()}.tmp"
    lock_path = p + '.lock'
    try:
        with open(lock_path, 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            current = {}
            if os.path.isfile(p):
                try:
                    with open(p) as f:
                        current = json.load(f)
                except Exception:
                    current = {}
            state = _merge_state(current, state)
            with open(tmp, 'w') as f:
                json.dump(state, f, indent=2, default=str)
            os.replace(tmp, p)
            fcntl.flock(lock, fcntl.LOCK_UN)
        return True
    except Exception as e:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        print(f"[dast_tool] WARN: state save failed: {e}", file=sys.stderr)
        return False


def _append_finding(finding):
    state = _load_state()
    findings = state.get('findings', [])
    # Dedup by (vuln_type, url, parameter)
    key = (finding.get('vuln_type'), finding.get('url'), finding.get('parameter'))
    if any((f.get('vuln_type'), f.get('url'), f.get('parameter')) == key for f in findings):
        return False
    findings.append(finding)
    state['findings'] = findings
    state.setdefault('logs', []).append({
        'time': datetime.now().strftime('%H:%M:%S'),
        'message': f"FOUND [{finding.get('severity','?').upper()}] {finding.get('vuln_type')} on {finding.get('url')} — {finding.get('parameter','')}",
    })
    _save_state_atomic(state)
    return True


def _append_coverage(method, url, records):
    state = _load_state()
    cov = state.get('checklist_coverage', [])
    method = (method or 'GET').upper()
    valid_statuses = {'tested', 'partial', 'skipped', 'not_applicable', 'na', 'confirmed'}
    normalized = []
    for rec in records:
        surface = str(rec.get('surface') or '').strip()
        category = str(rec.get('category') or '').strip()
        subcategory = str(rec.get('subcategory') or '').strip()
        area = str(rec.get('area') or '').strip()
        if not area:
            area = " / ".join([p for p in (category, subcategory) if p])
        status = str(rec.get('status') or '').strip().lower()
        if status == 'na':
            status = 'not_applicable'
        if not area or status not in valid_statuses:
            continue
        normalized.append({
            'method': method,
            'url': url,
            'surface': surface[:200],
            'category': category[:200],
            'subcategory': subcategory[:300],
            'area': area,
            'status': status,
            'reason': str(rec.get('reason') or '')[:1000],
            'evidence': str(rec.get('evidence') or '')[:2000],
            'ts': datetime.now().isoformat(),
        })
    if not normalized:
        return 0

    # Upsert in state by method/url/area so repeated agent calls refine status.
    by_key = {
        (r.get('method', 'GET'), r.get('url', ''), r.get('area', '')): r
        for r in cov
    }
    for rec in normalized:
        by_key[(rec['method'], rec['url'], rec['area'])] = rec
    state['checklist_coverage'] = list(by_key.values())
    state.setdefault('logs', []).append({
        'time': datetime.now().strftime('%H:%M:%S'),
        'message': f"Coverage recorded for {method} {url}: {len(normalized)} dynamic check(s)",
    })
    _save_state_atomic(state)

    if _SCAN_ID:
        try:
            _here = os.path.dirname(os.path.abspath(__file__))
            if _here not in sys.path:
                sys.path.insert(0, _here)
            import db as _db
            _db.upsert_checklist_coverage(_SCAN_ID, method, url, normalized)
        except Exception:
            pass
    return len(normalized)


# ---------------------------------------------------------------------------
# Proxy-tab integration — mark URLs as tested in real time
# ---------------------------------------------------------------------------
def _mark_tested(method, url):
    """Mark a URL as tested in the Proxy tab. Best-effort — silent on failure."""
    if not _SCAN_ID or not url:
        return
    try:
        # Ensure DAST-CLI is on sys.path so we can import db.py
        _here = os.path.dirname(os.path.abspath(__file__))
        if _here not in sys.path:
            sys.path.insert(0, _here)
        import db as _db
        _db.mark_proxy_tested(_SCAN_ID, (method or 'GET').upper(), url)
    except Exception:
        # Don't let a DB hiccup break the agent's test flow
        pass


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------
def _session():
    s = requests.Session()
    s.verify = False
    s.headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 DAST-CLI'
    if os.environ.get('DAST_USE_BURP_PROXY'):
        burp_proxy = 'http://127.0.0.1:8080'
        s.proxies = {'http': burp_proxy, 'https': burp_proxy}
    # Load auth cookies from state if present
    state = _load_state()
    cookies = (state.get('auth') or {}).get('cookies') or {}
    if cookies:
        # Set both ways: jar (domain-scoped) and raw header (always sent regardless of domain)
        cookie_header = '; '.join(f'{k}={v}' for k, v in cookies.items())
        s.headers['Cookie'] = cookie_header
        for k, v in cookies.items():
            s.cookies.set(k, v)
        print(f"[dast_tool] SESSION COOKIES ({len(cookies)}): {', '.join(cookies.keys())}", flush=True)
    else:
        print("[dast_tool] WARNING: no cookies loaded — requests will be unauthenticated", flush=True)
    return s


def _redirect_chain(response):
    chain = []
    for hop in list(response.history or []):
        chain.append({
            'status': hop.status_code,
            'url': hop.url,
            'location': hop.headers.get('Location', ''),
        })
    return chain


def _response_out(response, original_url, method, elapsed_ms):
    chain = _redirect_chain(response)
    first = response.history[0] if response.history else response
    return {
        'url': response.url,
        'original_url': original_url,
        'final_url': response.url,
        'method': method,
        'status': response.status_code,
        'initial_status': first.status_code,
        'redirected': bool(chain),
        'redirect_chain': chain,
        'length': len(response.content),
        'headers': dict(response.headers),
        'body_snippet': response.text[:3000],
        'body_hash': hashlib.sha256(response.content).hexdigest()[:16],
        'elapsed_ms': elapsed_ms,
    }


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_get_baseline(args):
    s = _session()
    headers = json.loads(args.headers) if args.headers else {}
    try:
        start = time.time()
        r = s.request(args.method, args.url, headers=headers, timeout=30, allow_redirects=True)
        elapsed_ms = int((time.time() - start) * 1000)
        out = _response_out(r, args.url, args.method, elapsed_ms)
        out['body_snippet'] = out['body_snippet'][:2000]
        # Save to state for later comparison
        state = _load_state()
        state.setdefault('baselines', {})[f"{args.method}:{args.url}"] = out
        _save_state_atomic(state)
        # Mark URL as tested in Proxy tab
        _mark_tested(args.method, args.url)
        print(json.dumps(out, indent=2))
    except Exception as e:
        print(json.dumps({'error': str(e), 'url': args.url}))
        sys.exit(1)


def cmd_send_request(args):
    s = _session()
    headers = json.loads(args.headers) if args.headers else {}
    url = args.url
    data = args.data
    # Inject payload into a URL param if both --param and --payload given
    if args.param and args.payload is not None:
        parsed = urlparse(url)
        qs = {}
        if parsed.query:
            from urllib.parse import parse_qs
            qs = {k: v[0] if v else '' for k, v in parse_qs(parsed.query).items()}
        qs[args.param] = args.payload
        url = parsed._replace(query=urlencode(qs)).geturl()
    try:
        start = time.time()
        r = s.request(args.method, url, headers=headers, data=data, timeout=30, allow_redirects=True)
        elapsed_ms = int((time.time() - start) * 1000)
        out = _response_out(r, url, args.method, elapsed_ms)
        # Diff against baseline if we have one
        state = _load_state()
        baseline = (state.get('baselines') or {}).get(f"{args.method}:{args.url}")
        if baseline:
            baseline_initial = baseline.get('initial_status', baseline.get('status', 0))
            out['baseline_diff'] = {
                'status_diff': r.status_code - baseline.get('status', 0),
                'initial_status_diff': out.get('initial_status', r.status_code) - baseline_initial,
                'length_diff': len(r.content) - baseline.get('length', 0),
                'hash_match': out['body_hash'] == baseline.get('body_hash'),
                'timing_diff_ms': elapsed_ms - baseline.get('elapsed_ms', 0),
                'final_url_changed': out.get('final_url') != baseline.get('final_url', baseline.get('url')),
            }
        # Mark URL as tested in Proxy tab (use original URL without payload injection)
        _mark_tested(args.method, args.url)
        print(json.dumps(out, indent=2))
    except Exception as e:
        print(json.dumps({'error': str(e), 'url': url}))
        sys.exit(1)


def cmd_get_crawl_results(args):
    state = _load_state()
    crawl = state.get('crawl_results') or {}
    # If crawl_results is a file path, load it
    if isinstance(crawl, str) and os.path.isfile(crawl):
        with open(crawl) as f:
            crawl = json.load(f)
    print(json.dumps(crawl, indent=2, default=str))


# Cookie names that indicate a real authenticated session (vs. just a CSRF cookie)
_SESSION_COOKIE_NAMES = {
    'sessionid', 'session', 'sessionId', 'PHPSESSID', 'connect.sid',
    'JSESSIONID', 'laravel_session', '_session_id', 'sid', 'auth_token',
    'access_token', 'jwt', 'remember_token',
}


def cmd_authenticate(args):
    """Login and store session cookies in state.

    Handles framework CSRF correctly (Django `csrfmiddlewaretoken`, Rails
    `authenticity_token`, Laravel `_token`, .NET `__RequestVerificationToken`)
    by extracting EVERY hidden token field and sending a matching Referer/Origin.
    Verifies a real session cookie came back — does not call a 403 a success.
    """
    import re
    s = requests.Session()
    s.verify = False
    s.headers['User-Agent'] = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                               'AppleWebKit/537.36 DAST-CLI')
    try:
        # 1. GET the login page → collect CSRF cookie + every hidden token field.
        r1 = s.get(args.login_url, timeout=30)
        token_fields = {}
        # name-before-value and value-before-name orderings
        for pat in (
            r'<input[^>]+name=["\']([^"\']*(?:csrf|token|_token|verification)[^"\']*)["\'][^>]*value=["\']([^"\']*)["\']',
            r'<input[^>]+value=["\']([^"\']*)["\'][^>]*name=["\']([^"\']*(?:csrf|token|_token|verification)[^"\']*)["\']',
        ):
            for m in re.finditer(pat, r1.text, re.I):
                a, b = m.group(1), m.group(2)
                # figure out which group is the field name (the one matching the keyword)
                if re.search(r'csrf|token|verification', a, re.I):
                    token_fields.setdefault(a, b)
                else:
                    token_fields.setdefault(b, a)
        # Django: the csrftoken cookie value can be reused as csrfmiddlewaretoken
        csrf_cookie = (s.cookies.get('csrftoken') or s.cookies.get('csrf')
                       or s.cookies.get('XSRF-TOKEN'))
        if csrf_cookie:
            token_fields.setdefault('csrfmiddlewaretoken', csrf_cookie)

        # 2. POST credentials under the common field names, with token + Referer.
        data = {
            'username': args.username, 'email': args.username, 'login': args.username,
            'password': args.password,
        }
        data.update(token_fields)
        pu = urlparse(args.login_url)
        headers = {
            'Referer': args.login_url,
            'Origin': f'{pu.scheme}://{pu.netloc}',
            'X-CSRFToken': csrf_cookie or '',
        }
        r2 = s.post(args.login_url, data=data, headers=headers, timeout=30, allow_redirects=True)

        # 3. Verify a REAL session was established (not just a CSRF cookie / 403).
        cookies = {c.name: c.value for c in s.cookies}
        has_session = any(n in cookies for n in _SESSION_COOKIE_NAMES)
        # The generic cookie-name allow-list misses app-specific forms-auth cookies
        # (e.g. ASP.NET sets HG886_BET_TWC, not "sessionid"). The most reliable signal
        # that login actually succeeded is that we LEFT the login page: the response no
        # longer renders a password field / login URL, and we weren't rejected.
        _bl = (r2.text or '').lower()
        _still_on_login = (
            'type="password"' in _bl or "type='password'" in _bl
            or 'no match found' in _bl
            or '/login' in (r2.url or '').lower()
        )
        _non_csrf_cookie = any(
            not re.search(r'csrf|xsrf|verification|requestverification', n, re.I)
            for n in cookies
        )
        # Success: not rejected, at least one (non-CSRF) cookie set, and we are no
        # longer sitting on the login page.
        ok = (r2.status_code not in (401, 403)) and _non_csrf_cookie and not _still_on_login
        has_session = has_session or (ok and _non_csrf_cookie)

        state = _load_state()
        state['auth'] = {
            'cookies': cookies,
            'login_status': r2.status_code,
            'authenticated': ok,
            'login_url': args.login_url,
        }
        _save_state_atomic(state)

        if ok:
            status = 'authenticated'
        elif r2.status_code in (401, 403):
            status = f'login rejected (HTTP {r2.status_code}) — check creds / CSRF / login URL'
        elif not has_session:
            status = 'no session cookie set — login likely failed (wrong field names or creds)'
        else:
            status = f'uncertain (HTTP {r2.status_code})'
        print(json.dumps({
            'status': status,
            'authenticated': ok,
            'login_status_code': r2.status_code,
            'session_cookie_present': has_session,
            'token_fields_sent': list(token_fields.keys()),
            'cookies': list(cookies.keys()),
            'final_url': r2.url,
        }, indent=2))
    except Exception as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(1)


def _extract_form_fields(html):
    """Return {name: (type, value)} for every <input> in the page."""
    import re
    fields = {}
    for tag in re.findall(r'<input\b[^>]*>', html, re.I):
        name = re.search(r'\bname=["\']([^"\']+)["\']', tag, re.I)
        if not name:
            continue
        ftype = re.search(r'\btype=["\']([^"\']+)["\']', tag, re.I)
        value = re.search(r'\bvalue=["\']([^"\']*)["\']', tag, re.I)
        fields[name.group(1)] = (
            (ftype.group(1).lower() if ftype else 'text'),
            (value.group(1) if value else ''),
        )
    return fields


def cmd_register(args):
    """Self-register an account so the scanner can reach authenticated-only
    endpoints when no creds are given or login fails. Discovers the signup
    form fields generically, submits, then verifies a session.
    """
    import re
    s = requests.Session()
    s.verify = False
    s.headers['User-Agent'] = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                               'AppleWebKit/537.36 DAST-CLI')
    username = args.username or ('dastuser_' + uuid.uuid4().hex[:8])
    password = args.password or ('Dast!' + uuid.uuid4().hex[:10] + 'A9')
    email = args.email or (username + '@example.com')
    try:
        r1 = s.get(args.register_url, timeout=30)
        fields = _extract_form_fields(r1.text)
        csrf_cookie = (s.cookies.get('csrftoken') or s.cookies.get('csrf')
                       or s.cookies.get('XSRF-TOKEN'))

        data = {}
        for name, (ftype, value) in fields.items():
            low = name.lower()
            if re.search(r'csrf|token|verification', low):
                data[name] = value or csrf_cookie or ''
            elif ftype == 'password' or 'pass' in low:
                data[name] = password                       # incl. confirm fields
            elif 'email' in low:
                data[name] = email
            elif re.search(r'user|login|name', low):
                data[name] = username
            elif ftype in ('hidden', 'submit'):
                data[name] = value
            elif ftype in ('checkbox', 'radio'):
                data[name] = value or 'on'                  # accept ToS, etc.
            else:
                data[name] = value or username
        # Fallbacks if the form was JS-rendered / not parsed.
        data.setdefault('username', username)
        data.setdefault('email', email)
        data.setdefault('password', password)
        data.setdefault('password1', password)
        data.setdefault('password2', password)
        if csrf_cookie:
            data.setdefault('csrfmiddlewaretoken', csrf_cookie)

        pu = urlparse(args.register_url)
        headers = {'Referer': args.register_url,
                   'Origin': f'{pu.scheme}://{pu.netloc}',
                   'X-CSRFToken': csrf_cookie or ''}
        r2 = s.post(args.register_url, data=data, headers=headers, timeout=30, allow_redirects=True)

        cookies = {c.name: c.value for c in s.cookies}
        has_session = any(n in cookies for n in _SESSION_COOKIE_NAMES)

        # If registration didn't auto-login, log in with the new creds.
        if not has_session and args.login_url:
            lr = s.get(args.login_url, timeout=30)
            cc = s.cookies.get('csrftoken') or csrf_cookie
            ld = {'username': username, 'email': email, 'login': username, 'password': password}
            if cc:
                ld['csrfmiddlewaretoken'] = cc
            s.post(args.login_url, data=ld, timeout=30,
                   headers={'Referer': args.login_url, 'Origin': f'{pu.scheme}://{pu.netloc}'},
                   allow_redirects=True)
            cookies = {c.name: c.value for c in s.cookies}
            has_session = any(n in cookies for n in _SESSION_COOKIE_NAMES)

        state = _load_state()
        state['auth'] = {
            'cookies': cookies,
            'authenticated': has_session,
            'registered_username': username,
            'registered_password': password,
            'login_url': args.login_url or args.register_url,
        }
        _save_state_atomic(state)
        print(json.dumps({
            'status': 'registered + session established' if has_session
                      else f'registered (HTTP {r2.status_code}) but no session — try authenticate manually',
            'authenticated': has_session,
            'username': username,
            'password': password,
            'register_status_code': r2.status_code,
            'session_cookie_present': has_session,
            'fields_submitted': list(data.keys()),
            'cookies': list(cookies.keys()),
        }, indent=2))
    except Exception as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(1)


def cmd_report_finding(args):
    finding = {
        'id': f"agent-{int(time.time()*1000)%1000000}-{uuid.uuid4().hex[:6]}",
        'vuln_type': args.vuln_type,
        'severity': args.severity,
        'url': args.url,
        'method': args.method,
        'parameter': args.parameter,
        'payload': args.payload,
        'evidence': args.evidence,
        'response_preview': args.response_preview or '',
        'response': args.response_preview or '',
        'curl_command': args.curl_command or '',
        'request': args.request or '',
        'risk_reasoning': args.risk_reasoning or '',
        'attack_narrative': args.attack_narrative or '',
        'confidence': args.confidence or 'possible',
        'false_positive_risk': args.false_positive_risk or 'medium',
        'reported_at': datetime.now().isoformat(),
    }
    if len(finding['evidence']) < 10:
        print(json.dumps({'error': 'evidence too short (min 10 chars)'}))
        sys.exit(1)
    # Auto-classify confidence if not explicitly set
    if not args.confidence:
        has_preview = bool(finding['response_preview'])
        has_req = bool(finding['request'])
        finding['confidence'] = 'confirmed' if (has_preview and has_req) else ('likely' if (has_preview or has_req) else 'possible')
    added = _append_finding(finding)
    print(json.dumps({
        'status': 'reported' if added else 'duplicate (not reported)',
        'finding_id': finding['id'],
        'confidence': finding['confidence'],
    }, indent=2))


def cmd_coverage(args):
    try:
        records = json.loads(args.json)
        if not isinstance(records, list):
            raise ValueError('coverage JSON must be a list')
    except Exception as e:
        print(json.dumps({'error': f'bad --json: {e}'}))
        sys.exit(1)
    count = _append_coverage(args.method, args.url, records)
    not_full = [
        r for r in records
        if str(r.get('status') or '').lower() in ('partial', 'skipped', 'na', 'not_applicable')
    ]
    print(json.dumps({
        'recorded': count,
        'not_fully_tested': len(not_full),
        'url': args.url,
        'method': args.method,
    }, indent=2))


def _interactsh_bin():
    import shutil
    for candidate in [
        shutil.which('interactsh-client'),
        os.path.expanduser('~/go/bin/interactsh-client'),
        '/usr/local/bin/interactsh-client',
    ]:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def _try_interactsh(custom_server=None):
    """Try to start interactsh-client. Returns (session_id, oob_url, proc) or None."""
    import subprocess, threading

    bin_path = _interactsh_bin()
    if not bin_path:
        return None

    cmd = [bin_path, '-json']
    if custom_server:
        cmd += ['-server', custom_server]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception:
        return None

    oob_url = None
    session_id = None
    deadline = time.time() + 12
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.1)
            continue
        try:
            data = json.loads(line.strip())
            if 'url' in data or 'interactsh-url' in data:
                oob_url = data.get('url') or data.get('interactsh-url')
                session_id = data.get('id') or uuid.uuid4().hex[:16]
                break
        except json.JSONDecodeError:
            stripped = line.strip()
            if stripped and ('oast.' in stripped or stripped.count('.') >= 2):
                oob_url = stripped
                session_id = uuid.uuid4().hex[:16]
                break

    if not oob_url:
        proc.kill()
        return None

    return session_id, oob_url, proc


def _webhook_site_session():
    """Create a webhook.site token; returns (session_id, oob_url) or None."""
    try:
        r = requests.post('https://webhook.site/token', timeout=10, verify=False)
        if r.status_code == 201:
            data = r.json()
            token = data['uuid']
            url = f"webhook.site/{token}"
            return token, url
    except Exception:
        pass
    return None


def _build_payloads(oob_url):
    return {
        'ssrf':      f'http://{oob_url}',
        'log4j':     f'${{jndi:ldap://{oob_url}/x}}',
        'xxe':       f'<!DOCTYPE x [<!ENTITY oob SYSTEM "http://{oob_url}">]>',
        'blind_xss': f'<script src="//{oob_url}/x"></script>',
        'dns':       oob_url,
    }


def cmd_generate_callback(args):
    """Start OOB listener — tries interactsh first, falls back to webhook.site."""
    import threading

    custom_server = getattr(args, 'server', None)
    backend = 'interactsh'

    result = _try_interactsh(custom_server)

    if result:
        session_id, oob_url, proc = result
        state = _load_state()
        state.setdefault('interactsh', {})[session_id] = {
            'created': datetime.now().isoformat(),
            'url': oob_url,
            'pid': proc.pid,
            'backend': 'interactsh',
            'hits': [],
        }
        _save_state_atomic(state)

        def _drain(proc, session_id):
            for line in proc.stdout:
                try:
                    ev = json.loads(line.strip())
                except Exception:
                    ev = {'raw': line.strip()}
                s = _load_state()
                entry = s.get('interactsh', {}).get(session_id)
                if entry is not None:
                    entry['hits'].append(ev)
                    _save_state_atomic(s)

        threading.Thread(target=_drain, args=(proc, session_id), daemon=True).start()

    else:
        # fallback: webhook.site
        backend = 'webhook.site'
        wh = _webhook_site_session()
        if not wh:
            print(json.dumps({'error': 'interactsh unreachable and webhook.site fallback failed'}))
            sys.exit(1)
        session_id, oob_url = wh
        state = _load_state()
        state.setdefault('interactsh', {})[session_id] = {
            'created': datetime.now().isoformat(),
            'url': oob_url,
            'backend': 'webhook.site',
            'webhook_token': session_id,
            'hits': [],
        }
        _save_state_atomic(state)

    print(json.dumps({
        'session_id': session_id,
        'oob_url': oob_url,
        'backend': backend,
        'payloads': _build_payloads(oob_url),
        'note': f'python3 dast_tool.py check_callback --session {session_id}',
    }, indent=2))


def cmd_check_callback(args):
    """Poll for OOB hits — checks local state (interactsh) or webhook.site API."""
    state = _load_state()
    sessions = state.get('interactsh', {})

    if args.session:
        entry = sessions.get(args.session, {})
        backend = entry.get('backend', 'interactsh')

        if backend == 'webhook.site':
            token = entry.get('webhook_token', args.session)
            try:
                r = requests.get(
                    f'https://webhook.site/token/{token}/requests?sorting=newest&per_page=25',
                    timeout=10, verify=False
                )
                if r.status_code == 200:
                    data = r.json()
                    remote_hits = data.get('data', [])
                    hit_count = len(remote_hits)
                    hits = [{'method': h.get('method'), 'ip': h.get('ip'), 'created_at': h.get('created_at'), 'headers': h.get('headers', {})} for h in remote_hits]
                else:
                    hit_count = 0
                    hits = []
            except Exception as e:
                hit_count = 0
                hits = [{'error': str(e)}]
        else:
            hits = entry.get('hits', [])
            hit_count = len(hits)

        print(json.dumps({
            'session_id': args.session,
            'oob_url': entry.get('url'),
            'backend': backend,
            'hit': hit_count > 0,
            'hit_count': hit_count,
            'hits': hits,
        }, indent=2))
    else:
        # legacy token-based lookup
        cb = (state.get('callbacks') or {}).get(args.token or '', {})
        print(json.dumps({'token': args.token, 'found': cb.get('hit', False), 'hits': cb.get('hits', [])}))


def cmd_browser_get(args):
    if os.environ.get('DAST_DISABLE_PLAYWRIGHT') == '1':
        print(json.dumps({'error': 'Playwright browser tools are disabled for this DAST-CLI scan'}))
        sys.exit(1)
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print(json.dumps({'error': f'playwright not available: {e}'}))
        sys.exit(1)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(args.url, timeout=30000, wait_until='networkidle')
            content = page.content()[:5000]
            title = page.title()
            url = page.url
            browser.close()
            print(json.dumps({'url': url, 'title': title, 'content_snippet': content}, indent=2))
    except Exception as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(1)


def cmd_browser_js(args):
    if os.environ.get('DAST_DISABLE_PLAYWRIGHT') == '1':
        print(json.dumps({'error': 'Playwright browser tools are disabled for this DAST-CLI scan'}))
        sys.exit(1)
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print(json.dumps({'error': f'playwright not available: {e}'}))
        sys.exit(1)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(args.url, timeout=30000, wait_until='networkidle')
            result = page.evaluate(args.script)
            browser.close()
            print(json.dumps({'result': result}, default=str, indent=2))
    except Exception as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(prog='dast_tool', description='DAST agent tools (Bash-callable)')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('get_baseline')
    p.add_argument('--url', required=True)
    p.add_argument('--method', default='GET')
    p.add_argument('--headers', help='JSON object')
    p.set_defaults(func=cmd_get_baseline)

    p = sub.add_parser('send_request')
    p.add_argument('--url', required=True)
    p.add_argument('--method', default='GET')
    p.add_argument('--data')
    p.add_argument('--headers')
    p.add_argument('--param', help='inject payload into this query param')
    p.add_argument('--payload')
    p.set_defaults(func=cmd_send_request)

    p = sub.add_parser('get_crawl_results')
    p.add_argument('--scan-id')
    p.set_defaults(func=cmd_get_crawl_results)

    p = sub.add_parser('authenticate')
    p.add_argument('--login-url', required=True)
    p.add_argument('--username', required=True)
    p.add_argument('--password', required=True)
    p.set_defaults(func=cmd_authenticate)

    p = sub.add_parser('register')
    p.add_argument('--register-url', required=True, help='signup/register page URL')
    p.add_argument('--login-url', help='login URL to use if registration does not auto-login')
    p.add_argument('--username', help='optional; auto-generated if omitted')
    p.add_argument('--password', help='optional; auto-generated if omitted')
    p.add_argument('--email', help='optional; auto-generated if omitted')
    p.set_defaults(func=cmd_register)

    p = sub.add_parser('report_finding')
    p.add_argument('--vuln-type', required=True)
    p.add_argument('--severity', required=True, choices=['critical', 'high', 'medium', 'low', 'info'])
    p.add_argument('--url', required=True)
    p.add_argument('--method', required=True)
    p.add_argument('--parameter', required=True)
    p.add_argument('--payload', required=True)
    p.add_argument('--evidence', required=True)
    p.add_argument('--response-preview')
    p.add_argument('--curl-command', help='Copy-paste curl command that reproduces the finding')
    p.add_argument('--request')
    p.add_argument('--risk-reasoning')
    p.add_argument('--attack-narrative')
    p.add_argument('--confidence', choices=['confirmed', 'likely', 'possible'])
    p.add_argument('--false-positive-risk', choices=['low', 'medium', 'high'])
    p.set_defaults(func=cmd_report_finding)

    p = sub.add_parser('coverage')
    p.add_argument('--url', required=True)
    p.add_argument('--method', default='GET')
    p.add_argument('--json', required=True, help='JSON list of {surface,category,subcategory,status,reason,evidence}; area is optional')
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser('generate_callback')
    p.add_argument('--server', default=None, help='custom interactsh server URL (e.g. https://your.server.com)')
    p.set_defaults(func=cmd_generate_callback)

    p = sub.add_parser('check_callback')
    p.add_argument('--session', default=None, help='interactsh session_id from generate_callback')
    p.add_argument('--token', default=None, help='legacy webhook token (backwards compat)')
    p.set_defaults(func=cmd_check_callback)

    p = sub.add_parser('browser_get')
    p.add_argument('--url', required=True)
    p.set_defaults(func=cmd_browser_get)

    p = sub.add_parser('browser_js')
    p.add_argument('--url', required=True)
    p.add_argument('--script', required=True)
    p.set_defaults(func=cmd_browser_js)

    args = ap.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
