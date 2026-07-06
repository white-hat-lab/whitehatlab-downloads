"""Pentest — FastAPI web application for penetration testing."""
import os, sys, asyncio, threading, uuid, subprocess, signal, re
import hashlib
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests as _requests
import uvicorn
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import db

_app_dir = os.path.dirname(os.path.abspath(__file__))
_report_template_dir = os.path.join(_app_dir, 'report_templates')
_default_report_template = os.path.join(_report_template_dir, 'default_pentest_template.docx')
_source_report_dir = os.path.join(_report_template_dir, 'source_reports')
_evidence_screenshot_dir = os.path.join(_report_template_dir, 'evidence_screenshots')
_default_report_import_dir = '/Users/jyothi/Downloads'
_IMAGE_EXTS = {'.png', '.jpg', '.jpeg'}

# ── Burp config ───────────────────────────────────────────────────────────────
BURP_BASE    = 'http://127.0.0.1:8090'
BURP_PROXY   = 'http://127.0.0.1:8080'
BURP_TIMEOUT = 4

# ── In-memory scan state (keyed by engagement_id) ────────────────────────────
_scans: dict = {}   # eid -> {status, phase, progress, findings, logs, proxy, ...}
_scan_threads: dict = {}
_abort_flags: dict = {}   # eid -> threading.Event

def _utc():
    return datetime.now(timezone.utc).isoformat()

def _safe_report_filename(name):
    base = os.path.basename(name or 'source-report.docx')
    base = re.sub(r'[^A-Za-z0-9._-]+', '_', base).strip('._') or 'source-report.docx'
    if not base.lower().endswith('.docx'):
        base += '.docx'
    return base[:140]

def _validate_docx_bytes(data):
    if len(data or b'') < 100:
        return 'Template upload was empty.'
    try:
        import zipfile
        import io as _io
        with zipfile.ZipFile(_io.BytesIO(data)) as zf:
            if 'word/document.xml' not in zf.namelist():
                return 'That file is not a valid DOCX.'
    except Exception as exc:
        return f'That file is not a valid DOCX: {exc}'
    return ''

def _bytes_sha256(data):
    return hashlib.sha256(data).hexdigest()

def _file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def _existing_source_report_hashes():
    hashes = set()
    for report in _list_source_reports():
        try:
            hashes.add(_file_sha256(report['path']))
        except OSError:
            pass
    return hashes

def _save_source_report_bytes(data, filename):
    os.makedirs(_source_report_dir, exist_ok=True)
    digest = _bytes_sha256(data)
    if digest in _existing_source_report_hashes():
        return {'ok': True, 'duplicate': True, 'sha256': digest}
    safe = _safe_report_filename(filename)
    final_name = f'{datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")}-{uuid.uuid4().hex[:8]}-{safe}'
    path = os.path.join(_source_report_dir, final_name)
    with open(path, 'wb') as f:
        f.write(data)
    return {'ok': True, 'duplicate': False, 'sha256': digest,
            'report': next((r for r in _list_source_reports() if r['name'] == final_name), None)}

def _list_source_reports():
    os.makedirs(_source_report_dir, exist_ok=True)
    reports = []
    for name in sorted(os.listdir(_source_report_dir)):
        if not name.lower().endswith('.docx'):
            continue
        path = os.path.join(_source_report_dir, name)
        try:
            stat = os.stat(path)
        except OSError:
            continue
        reports.append({
            'name': name,
            'path': path,
            'size': stat.st_size,
            'updated_at': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        })
    return reports

def _list_evidence_screenshots(eid=None):
    os.makedirs(_evidence_screenshot_dir, exist_ok=True)
    images = []
    scan_dir = os.path.join(_evidence_screenshot_dir, str(eid)) if eid else ''
    roots = [scan_dir] if scan_dir and os.path.isdir(scan_dir) else [_evidence_screenshot_dir]
    for root in roots:
        for name in sorted(os.listdir(root)):
            if eid and root == _evidence_screenshot_dir and not name.startswith(f'{eid}-'):
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext not in _IMAGE_EXTS:
                continue
            path = os.path.join(root, name)
            try:
                stat = os.stat(path)
            except OSError:
                continue
            images.append({
                'name': name,
                'path': path,
                'size': stat.st_size,
                'updated_at': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            })
    return images

# ── Burp helpers ──────────────────────────────────────────────────────────────

def burp_get(path, params=None):
    try:
        r = _requests.get(f'{BURP_BASE}{path}', params=params, timeout=BURP_TIMEOUT)
        return r.json(), r.status_code
    except Exception as e:
        return {'error': str(e), 'items': [], 'total_in_history': 0}, 503

def burp_post(path, json=None):
    try:
        r = _requests.post(f'{BURP_BASE}{path}', json=json or {}, timeout=BURP_TIMEOUT)
        return r.json(), r.status_code
    except Exception as e:
        return {'error': str(e)}, 503

def burp_history(eid: str, limit=5000, ignore_watermark=False):
    """Fetch Burp history filtered by this engagement's watermark."""
    eng = db.get_engagement(eid) if eid else None
    watermark = 0 if (ignore_watermark or not eng) else (eng.get('burp_watermark') or 0)
    params = {'limit': str(limit)}
    if watermark > 0:
        params['after_index'] = str(watermark)
    data, code = burp_get('/proxy/history', params=params)
    return data, code

def burp_set_watermark(eid: str):
    """Set this engagement's watermark to current Burp total (hides existing history)."""
    data, code = burp_get('/proxy/history', params={'limit': '1'})
    if code == 200:
        total = data.get('total_in_history', 0)
        db.update_engagement(eid, burp_watermark=total)
        return total
    return 0

_IMPORT_SKIP_EXTS = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.map', '.pdf', '.zip', '.webp'}
_IMPORT_SKIP_HOSTS = ('fonts.googleapis.com', 'fonts.gstatic.com', 'safebrowsing', 'google.com', 'googleapis.com', 'gstatic.com', 'passwordsleakcheck')

def _proxy_status(item):
    try:
        return int(item.get('status_code') or item.get('status') or 0)
    except Exception:
        return 0

def _proxy_body_preview(item):
    body = item.get('request_body') or item.get('body') or item.get('body_preview') or ''
    return str(body)[:500]

def _normalize_attack_vector(raw_url):
    try:
        parsed = urlparse(raw_url or '')
        path = re.sub(r'WHL_CANARY_[A-Za-z0-9_-]+', '{attack_vector}', parsed.path or '/')
        path = re.sub(r'(?<=/)\d+(?=/|$)', '{id}', path)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        normalized_pairs = []
        for key, value in pairs:
            if re.search(r'WHL_CANARY_|<|>|%3c|%3e|script|sleep\(|union|select|or\s+1=1', value or '', re.I):
                normalized_pairs.append((key, '{attack_vector}'))
            else:
                normalized_pairs.append((key, value))
        query = urlencode(normalized_pairs, doseq=True)
        return urlunparse(('', '', path, '', query, '')) or '/'
    except Exception:
        return raw_url or ''

def _target_matches(item_url, target_url):
    if not target_url:
        return True
    try:
        item = urlparse(item_url or '')
        target = urlparse(target_url or '')
        return item.hostname == target.hostname and (item.port or (443 if item.scheme == 'https' else 80)) == (target.port or (443 if target.scheme == 'https' else 80))
    except Exception:
        return False

def _is_auth_gate(item):
    try:
        parsed = urlparse(item.get('url') or '')
        path = (parsed.path or '').lower()
        status = _proxy_status(item)
        length = int(item.get('response_length') or item.get('length') or 0)
        if status in (301, 302, 303, 307, 308):
            return True
        if path.endswith('/login.php') or path.endswith('/login') or '/login.php/' in path or '/login/' in path:
            return True
        if length in (383, 384, 4399) and ('login' in path or status == 200):
            return True
        return False
    except Exception:
        return False

def _burp_item_to_proxy_entry(item):
    return {
        'method': (item.get('method') or 'GET').upper(),
        'url': item.get('url') or '',
        'status': _proxy_status(item),
        'length': int(item.get('response_length') or item.get('length') or 0),
        'body_preview': _proxy_body_preview(item),
        'request_headers': item.get('request_headers') or [],
        'request_body': item.get('request_body') or item.get('body') or '',
        'response_headers': item.get('response_headers') or [],
        'response_body': item.get('response_body') or '',
        'tested': 0,
    }

def _normalize_burp_items_for_proxy(items, target_url=''):
    seen = {}
    for item in items or []:
        try:
            url = item.get('url') or ''
            if not url or not _target_matches(url, target_url):
                continue
            parsed = urlparse(url)
            if any(h in (parsed.hostname or '') for h in _IMPORT_SKIP_HOSTS):
                continue
            _, ext = os.path.splitext(parsed.path.lower())
            if ext in _IMPORT_SKIP_EXTS:
                continue
            if _proxy_status(item) != 200 or _is_auth_gate(item):
                continue
            entry = _burp_item_to_proxy_entry(item)
            key = (entry['method'], _normalize_attack_vector(url), _proxy_body_preview(item))
            current = seen.get(key)
            if not current or (not current.get('body_preview') and entry.get('body_preview')):
                seen[key] = entry
        except Exception:
            continue
    return list(seen.values())

# ── Scan helpers ──────────────────────────────────────────────────────────────

def _get_scan(eid):
    return _scans.get(eid)

def _init_scan(eid):
    _scans[eid] = {
        'status': 'idle', 'phase': '', 'progress': 0,
        'findings': [], 'logs': [], 'proxy': [],
        'session_id': None, 'agent_backend': 'codex',
        'pending_question': None, 'pending_config': None,
        'started_at': _utc(), 'ended_at': None, 'error': None,
    }
    return _scans[eid]

def _running_agent_scan(except_eid=None):
    for sid, scan in _scans.items():
        if except_eid and sid == except_eid:
            continue
        if scan.get('status') == 'running' and scan.get('phase') in {'agent', 'capture', 'running'}:
            return sid
    return None

def _urls_need_credentials(urls):
    auth_words = (
        'login', 'signin', 'sign-in', 'sign_in', 'auth', 'session',
        'password', 'account', 'profile', 'admin', 'dashboard', 'portal',
        'user', 'member', 'secure',
    )
    for _, url in urls or []:
        parsed = urlparse(url)
        hay = f"{parsed.path} {parsed.query}".lower()
        if any(word in hay for word in auth_words):
            return True
    return False

def _parse_operator_answer(answer):
    data = {'raw_answer': answer}
    pairs = dict(re.findall(r'(?i)\b(username|user|login|password|pass|pwd|login_url)\s*[:=]\s*([^\s]+)', answer or ''))
    if pairs:
        data['username'] = pairs.get('username') or pairs.get('user') or pairs.get('login')
        data['password'] = pairs.get('password') or pairs.get('pass') or pairs.get('pwd')
        data['login_url'] = pairs.get('login_url')
        return data
    parts = (answer or '').split()
    if len(parts) >= 2:
        data['username'] = parts[0]
        data['password'] = parts[1]
    return data

def _findings_for_scan(eid, findings):
    """Keep only findings created by this engagement.

    Older agent code used a shared temp file, and concurrent scans can still
    share process-level state. The report/database boundary must be strict:
    a finding tagged for a different scan is not allowed into this engagement.
    Untagged findings are kept for backwards compatibility with old completed
    scans, but new findings are tagged by scanner/agent.py.
    """
    out = []
    for finding in findings or []:
        sid = (finding or {}).get('_scan_id') or (finding or {}).get('scan_id')
        if sid and str(sid) != str(eid):
            continue
        out.append(finding)
    return out

def _log(eid, phase, msg):
    t = datetime.now().strftime('%H:%M:%S')
    entry = {'time': t, 'phase': phase, 'message': msg}
    if eid in _scans:
        _scans[eid]['logs'].append(entry)
    db.add_log(eid, phase, msg)

def _flush(eid):
    scan = _scans.get(eid)
    if not scan:
        return
    db.update_engagement(eid,
        status=scan['status'], phase=scan['phase'],
        progress=scan['progress'], ended_at=scan.get('ended_at'),
        error=scan.get('error'))
    db.bulk_add_findings(eid, _findings_for_scan(eid, scan.get('findings', [])))
    db.replace_logs(eid, scan.get('logs', []))
    db.replace_proxy_entries(eid, scan.get('proxy', []))

def _merge_logs(*groups):
    merged = []
    seen = set()
    for group in groups:
        for item in group or []:
            entry = {
                'time': item.get('time', ''),
                'phase': item.get('phase', ''),
                'message': item.get('message', ''),
            }
            key = (entry['time'], entry['phase'], entry['message'])
            if key in seen:
                continue
            seen.add(key)
            merged.append(entry)
    return merged

def _line_key(method, url):
    method = (method or 'GET').upper()
    return url if method == 'GET' else f'{method} {url}'

def _normalize_request_contexts(raw_contexts, urls):
    allowed = {_line_key(m, u) for m, u in urls}
    contexts = []
    seen = set()
    for item in raw_contexts or []:
        if not isinstance(item, dict):
            continue
        method = (item.get('method') or 'GET').upper()
        url = (item.get('url') or '').strip()
        if not url:
            continue
        key = _line_key(method, url)
        if key not in allowed or key in seen:
            continue
        seen.add(key)
        contexts.append({
            'method': method,
            'url': url,
            'status_code': int(item.get('status_code') or item.get('status') or 0),
            'response_length': int(item.get('response_length') or item.get('length') or 0),
            'request_headers': item.get('request_headers') or [],
            'request_body': item.get('request_body') or item.get('body') or '',
            'response_headers': item.get('response_headers') or [],
            'response_body': item.get('response_body') or '',
        })
    return contexts

def _headers_list_to_dict(headers):
    out = {}
    for line in headers or []:
        if not isinstance(line, str) or ':' not in line:
            continue
        name, value = line.split(':', 1)
        name = name.strip()
        if not name or name.lower() in ('host', 'content-length', 'connection'):
            continue
        out[name] = value.strip()
    return out

def _request_context_baselines(request_contexts):
    baselines = {}
    for ctx in request_contexts or []:
        parsed = urlparse(ctx.get('url') or '')
        method = (ctx.get('method') or 'GET').upper()
        body = ctx.get('response_body') or ''
        baseline = {
            'url': ctx.get('url') or '',
            'status': ctx.get('status_code') or 0,
            'body': body[:8000],
            'headers': _headers_list_to_dict(ctx.get('response_headers') or []),
            'length': ctx.get('response_length') or len(body),
            'request_headers': ctx.get('request_headers') or [],
            'request_body': ctx.get('request_body') or '',
        }
        baselines[f'{method}:{parsed.path}'] = baseline
        baselines[f'{method}:{ctx.get("url")}'] = baseline
    return baselines

def _finding_dedupe_key(f):
    explicit = f.get('finding_id')
    if explicit:
        return f'id:{explicit}'
    agent_id = f.get('id')
    if agent_id:
        return f'agent:{agent_id}'
    parts = [
        f.get('vuln_type', ''),
        f.get('severity', ''),
        f.get('url', ''),
        f.get('method', 'GET'),
        f.get('parameter', ''),
        f.get('payload', ''),
    ]
    raw = '\x1f'.join(str(p) for p in parts)
    return 'derived:' + hashlib.sha256(raw.encode('utf-8', 'ignore')).hexdigest()[:16]

def _normalize_finding_for_app(f):
    f = dict(f or {})
    if not f.get('finding_id') and f.get('id'):
        f['finding_id'] = f.get('id')
    if not f.get('response') and f.get('response_preview'):
        f['response'] = f.get('response_preview')
    allowed = {
        'finding_id', 'severity', 'vuln_type', 'url', 'method', 'parameter',
        'payload', 'evidence', 'curl_command', 'request', 'response', 'source',
        'risk_reasoning', 'attack_narrative', 'confidence',
        'false_positive_risk', 'remediation_status', 'source_location',
        'source_sink', 'remediation_evidence', 'poc',
    }
    return {k: v for k, v in f.items() if k in allowed}

def _run_scan(eid, config):
    """Background thread: run the agent against the supplied Scanner URLs."""
    scan = _scans[eid]
    abort = _abort_flags.get(eid, threading.Event())
    scanner_dir = os.path.join(_app_dir, 'scanner')
    if scanner_dir not in sys.path:
        sys.path.insert(0, scanner_dir)

    try:
        import asyncio
        from agent import run_agent, _scan_state, load_findings_from_file, _findings_file

        scan['status'] = 'running'
        db.update_engagement(eid, status='running', phase='agent', started_at=_utc())

        target_url = config['target_url']
        urls = config['urls']  # list of (method, url)
        creds = None
        if config.get('username') and config.get('password'):
            creds = {'username': config['username'], 'password': config['password'],
                     'login_url': config.get('login_url', '')}

        # Clear agent state
        _scan_state['findings'] = []
        _scan_state['logs'] = []
        _scan_state['urls_hit'] = set()
        _scan_state['session'] = None
        _scan_state['use_burp_proxy'] = config.get('use_burp_proxy', False)
        _scan_state['agent_backend'] = config.get('agent_backend', 'codex')
        _scan_state['cookie_string'] = config.get('cookie') or None
        scan['agent_backend'] = config.get('agent_backend', 'codex')

        if config.get('use_burp_proxy'):
            os.environ['DAST_USE_BURP_PROXY'] = '1'
        else:
            os.environ.pop('DAST_USE_BURP_PROXY', None)

        os.environ['DAST_SCAN_ID'] = eid

        try:
            os.remove(_findings_file(eid))
        except FileNotFoundError:
            pass

        request_contexts = config.get('request_contexts') or []
        context_by_key = {_line_key(c.get('method'), c.get('url')): c for c in request_contexts}
        crawl_endpoints = []
        for m, u in urls:
            ep = {'url': u, 'method': m}
            ctx = context_by_key.get(_line_key(m, u))
            if ctx:
                ep['request_headers'] = ctx.get('request_headers') or []
                ep['request_body'] = ctx.get('request_body') or ''
                ep['response_headers'] = ctx.get('response_headers') or []
                ep['response_body'] = ctx.get('response_body') or ''
                ep['status'] = ctx.get('status_code') or 0
                ep['length'] = ctx.get('response_length') or 0
            crawl_endpoints.append(ep)
        request_baselines = _request_context_baselines(request_contexts)
        crawl_results = {
            'endpoints': crawl_endpoints,
            'forms': [],
            'params': [],
            'baselines': request_baselines,
            'request_contexts': request_contexts,
        }
        _log(eid, 'agent', f'Using {len(urls)} supplied URL(s). Scanner will not expand the target list.')
        if request_contexts:
            _log(eid, 'agent', f'Loaded {len(request_contexts)} full request context(s) from Proxy/Burp.')
        if (config.get('app_notes') or '').strip():
            _log(eid, 'agent', 'Operator notes loaded into agent prompt.')
        if (config.get('repo_path') or '').strip():
            _log(eid, 'agent', 'Source repo path loaded into agent prompt.')
        if config.get('focused_capture'):
            _log(eid, 'capture', f'Focused capture mode — testing only {target_url}')

        scan['proxy'] = [
            {
                'method': m,
                'url': u,
                'status': (context_by_key.get(_line_key(m, u)) or {}).get('status_code', 0),
                'length': (context_by_key.get(_line_key(m, u)) or {}).get('response_length', 0),
                'tested': 0,
                'request_headers': (context_by_key.get(_line_key(m, u)) or {}).get('request_headers', []),
                'request_body': (context_by_key.get(_line_key(m, u)) or {}).get('request_body', ''),
                'response_headers': (context_by_key.get(_line_key(m, u)) or {}).get('response_headers', []),
                'response_body': (context_by_key.get(_line_key(m, u)) or {}).get('response_body', ''),
            }
            for m, u in urls
        ]
        db.bulk_add_proxy(eid, scan['proxy'])

        # ── Agent ──
        scan['phase'] = 'agent'
        _log(eid, 'agent', f'Starting agent on {len(urls)} URLs…')

        asyncio.run(run_agent(
            target_url,
            crawl_results=crawl_results,
            baselines=request_baselines,
            credentials=creds,
            scan_id=eid,
            app_notes=config.get('app_notes', ''),
            repo_path=config.get('repo_path', ''),
        ))
        scan['session_id'] = _scan_state.get('session_id')

        # Collect findings
        new_findings = load_findings_from_file(eid) or []
        agent_findings = _findings_for_scan(eid, _scan_state.get('findings', []))
        merged = {}
        for f in (new_findings + agent_findings):
            normalized = _normalize_finding_for_app(f)
            merged[_finding_dedupe_key(normalized)] = normalized
        scan['findings'] = _findings_for_scan(eid, list(merged.values()))
        scan['logs'] = _merge_logs(scan.get('logs', []), _scan_state.get('logs', []))

        scan['status'] = 'interrupted' if abort.is_set() else 'completed'
        scan['phase'] = 'done'
        scan['progress'] = 100
        scan['ended_at'] = _utc()
        _log(eid, 'done', f"Scan complete — {len(scan['findings'])} finding(s).")

    except Exception as e:
        import traceback
        scan['status'] = 'error'
        scan['error'] = str(e)
        scan['ended_at'] = _utc()
        _log(eid, 'error', f'Scan error: {e}')
        _log(eid, 'error', traceback.format_exc())

    finally:
        _flush(eid)

# ── App lifespan ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    for eng in db.list_engagements():
        if eng.get('status') == 'running':
            db.update_engagement(
                eng['id'],
                status='interrupted',
                phase='done',
                progress=100,
                ended_at=_utc(),
                error='Interrupted by app restart before scan finished.',
            )
    yield

app = FastAPI(title='Pentest', lifespan=lifespan)
app.mount('/static', StaticFiles(directory=os.path.join(_app_dir, 'static')), name='static')
templates = Jinja2Templates(directory=os.path.join(_app_dir, 'templates'))

# ─────────────────────────────────────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────────────────────────────────────

@app.get('/', response_class=HTMLResponse)
async def index(request: Request):
    from starlette.templating import _TemplateResponse
    return templates.TemplateResponse(request=request, name='index.html')

# ─────────────────────────────────────────────────────────────────────────────
# Engagements
# ─────────────────────────────────────────────────────────────────────────────

@app.get('/api/engagements')
async def list_engagements():
    return {'engagements': db.list_engagements()}

@app.post('/api/engagements')
async def create_engagement(request: Request):
    body = await request.json()
    target_url = (body.get('target_url') or '').strip()
    name = (body.get('name') or '').strip() or None
    if target_url and not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    eid = db.create_engagement(target_url=target_url, name=name)
    return {'ok': True, 'engagement': db.get_engagement(eid)}

@app.delete('/api/engagements')
async def delete_all_engagements():
    for eid in list(_scans.keys()):
        flag = _abort_flags.get(eid)
        if flag:
            flag.set()
    _scans.clear()
    _abort_flags.clear()
    db.delete_all_engagements()
    return {'ok': True}

@app.delete('/api/engagements/{eid}')
async def delete_engagement(eid: str):
    flag = _abort_flags.get(eid)
    if flag:
        flag.set()
    _scans.pop(eid, None)
    _abort_flags.pop(eid, None)
    db.delete_engagement(eid)
    return {'ok': True}

# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────

@app.post('/api/scan')
async def start_scan(request: Request, background_tasks: BackgroundTasks):
    body = await request.json()
    running = _running_agent_scan()
    if running:
        return JSONResponse({'error': f'Scan {running} is already running. Stop it before starting another scan.'}, 409)
    urls_raw = body.get('urls', '')
    if not urls_raw.strip():
        return JSONResponse({'error': 'No URLs provided'}, 400)

    urls = []
    for line in urls_raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if line.upper().startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ')):
            method, url = line.split(None, 1)
            urls.append((method.upper(), url.strip()))
        else:
            urls.append(('GET', line))

    request_contexts = _normalize_request_contexts(body.get('request_contexts') or [], urls)

    target_url = urls[0][1] if urls else ''
    eid = db.create_engagement(
        target_url=target_url,
        auth_username=body.get('username', ''),
        auth_password=body.get('password', ''),
        auth_login_url=body.get('login_url', ''),
        app_notes=body.get('app_notes', ''),
        repo_path=body.get('repo_path', ''),
        agent_backend=body.get('agent_backend', 'codex'),
        use_burp_proxy=1 if body.get('use_burp_proxy') else 0,
        disable_fuzzers=1 if body.get('disable_fuzzers') else 0,
        enable_browser=1 if body.get('enable_browser') else 0,
    )

    # Set Burp watermark so only new traffic shows for this engagement
    if body.get('use_burp_proxy'):
        burp_set_watermark(eid)

    scan = _init_scan(eid)
    context_by_key = {_line_key(c.get('method'), c.get('url')): c for c in request_contexts}
    scan['proxy'] = [
        {
            'method': m,
            'url': u,
            'status': (context_by_key.get(_line_key(m, u)) or {}).get('status_code', 0),
            'length': (context_by_key.get(_line_key(m, u)) or {}).get('response_length', 0),
            'tested': 0,
            'request_headers': (context_by_key.get(_line_key(m, u)) or {}).get('request_headers', []),
            'request_body': (context_by_key.get(_line_key(m, u)) or {}).get('request_body', ''),
            'response_headers': (context_by_key.get(_line_key(m, u)) or {}).get('response_headers', []),
            'response_body': (context_by_key.get(_line_key(m, u)) or {}).get('response_body', ''),
        }
        for m, u in urls
    ]
    db.bulk_add_proxy(eid, scan['proxy'])

    config = {
        'target_url': target_url,
        'urls': urls,
        'username': body.get('username', ''),
        'password': body.get('password', ''),
        'login_url': body.get('login_url', ''),
        'app_notes': body.get('app_notes', ''),
        'repo_path': body.get('repo_path', ''),
        'agent_backend': body.get('agent_backend', 'codex'),
        'use_burp_proxy': bool(body.get('use_burp_proxy')),
        'disable_fuzzers': bool(body.get('disable_fuzzers')),
        'enable_browser': bool(body.get('enable_browser')),
        'request_contexts': request_contexts,
    }

    if _urls_need_credentials(urls) and not (config.get('username') and config.get('password')):
        question = 'This target looks like it may need authentication. Send username and password, for example: bee bug'
        scan['status'] = 'needs_input'
        scan['phase'] = 'waiting'
        scan['pending_question'] = question
        scan['pending_config'] = config
        _log(eid, 'question', question)
        db.update_engagement(eid, status='needs_input', phase='waiting', progress=0)
        return {'engagement_id': eid, 'status': 'needs_input', 'question': question, 'url_count': len(urls)}

    abort = threading.Event()
    _abort_flags[eid] = abort

    t = threading.Thread(target=_run_scan, args=(eid, config), daemon=True)
    _scan_threads[eid] = t
    t.start()

    return {'engagement_id': eid, 'status': 'started', 'url_count': len(urls)}

@app.get('/api/scan/{eid}/status')
async def scan_status(eid: str):
    scan = _get_scan(eid)
    if not scan:
        eng = db.get_engagement(eid)
        if not eng:
            return JSONResponse({'error': 'Not found'}, 404)
        return {k: eng[k] for k in ('status','phase','progress','started_at','ended_at','error') if k in eng}
    return {
        'status': scan['status'], 'phase': scan['phase'],
        'progress': scan['progress'], 'started_at': scan.get('started_at'),
        'ended_at': scan.get('ended_at'), 'error': scan.get('error'),
        'findings_count': len(scan.get('findings', [])),
    }

@app.get('/api/scan/{eid}/results')
async def scan_results(eid: str):
    scan = _get_scan(eid)
    if scan:
        findings = scan.get('findings', [])
        logs = scan.get('logs', [])[-200:]
        proxy = scan.get('proxy', [])
        session_id = scan.get('session_id')
        if scan.get('status') == 'running':
            try:
                scanner_dir = os.path.join(_app_dir, 'scanner')
                if scanner_dir not in sys.path:
                    sys.path.insert(0, scanner_dir)
                from agent import _scan_state
                session_id = session_id or _scan_state.get('session_id')
                if str(_scan_state.get('scan_id') or '') == str(eid):
                    logs = _merge_logs(scan.get('logs', []), _scan_state.get('logs', []))[-300:]
                if session_id and session_id != 'running':
                    scan['session_id'] = session_id
            except Exception:
                pass
    else:
        findings = db.get_findings(eid)
        logs = db.get_logs(eid)
        proxy = db.get_proxy_entries(eid)
        session_id = None
    eng = db.get_engagement(eid) or {}
    return {
        'engagement_id': eid,
        'status': (scan or eng).get('status', 'unknown'),
        'phase': (scan or eng).get('phase', ''),
        'progress': (scan or eng).get('progress', 0),
        'target_url': eng.get('target_url', ''),
        'pending_question': (scan or {}).get('pending_question'),
        'chat_available': bool(
            scan and (
                scan.get('status') == 'needs_input'
                or (scan.get('status') == 'running' and session_id and session_id != 'running')
            )
        ),
        'findings': findings,
        'logs': logs,
        'proxy': proxy,
        'coverage': db.get_coverage(eid),
    }

@app.post('/api/scan/{eid}/stop')
async def stop_scan(eid: str):
    flag = _abort_flags.get(eid)
    if flag:
        flag.set()
    scan = _get_scan(eid)
    if scan:
        scan['status'] = 'interrupted'
        scan['ended_at'] = _utc()
        _flush(eid)
    return {'ok': True}

@app.post('/api/scan/{eid}/chat')
async def scan_chat(eid: str, request: Request):
    body = await request.json()
    message = (body.get('message') or '').strip()
    if not message:
        return JSONResponse({'error': 'Message is empty'}, 400)

    scan = _get_scan(eid)
    if not scan:
        return JSONResponse({'error': 'Engagement is not loaded.'}, 404)

    if scan.get('status') == 'needs_input':
        config = dict(scan.get('pending_config') or {})
        parsed = _parse_operator_answer(message)
        if parsed.get('username'):
            config['username'] = parsed['username']
            db.update_engagement(eid, auth_username=parsed['username'])
        if parsed.get('password'):
            config['password'] = parsed['password']
            db.update_engagement(eid, auth_password=parsed['password'])
        if parsed.get('login_url'):
            config['login_url'] = parsed['login_url']
            db.update_engagement(eid, auth_login_url=parsed['login_url'])

        if not (config.get('username') and config.get('password')):
            return JSONResponse({'error': 'Send username and password, for example: bee bug'}, 400)

        running = _running_agent_scan(except_eid=eid)
        if running:
            return JSONResponse({'error': f'Scan {running} is already running. Stop it before resuming this scan.'}, 409)

        scan['pending_config'] = None
        scan['pending_question'] = None
        scan['status'] = 'running'
        scan['phase'] = 'agent'
        _log(eid, 'chat', f'> {message}')
        _log(eid, 'agent', 'Input received. Resuming scan.')
        abort = threading.Event()
        _abort_flags[eid] = abort
        t = threading.Thread(target=_run_scan, args=(eid, config), daemon=True)
        _scan_threads[eid] = t
        t.start()
        return {'ok': True, 'resumed': True, 'response': 'Input received. Resuming scan.'}

    if scan.get('status') != 'running':
        return JSONResponse({'error': 'Agent is not active. Start or resume a scan first.'}, 409)

    session_id = scan.get('session_id')
    try:
        scanner_dir = os.path.join(_app_dir, 'scanner')
        if scanner_dir not in sys.path:
            sys.path.insert(0, scanner_dir)
        from agent import _scan_state
        session_id = session_id or _scan_state.get('session_id')
        if session_id and session_id != 'running':
            scan['session_id'] = session_id
    except Exception:
        pass
    if not session_id or session_id == 'running':
        return JSONResponse({'error': 'Agent session is not ready yet.'}, 409)

    try:
        from agent import send_chat_message, _scan_state
        _scan_state['agent_backend'] = scan.get('agent_backend') or 'codex'
        _log(eid, 'chat', f'> {message}')
        response = await send_chat_message(session_id, message)
        _log(eid, 'agent', response)
        return {'ok': True, 'response': response}
    except Exception as e:
        _log(eid, 'chat', f'Chat error: {e}')
        return JSONResponse({'error': f'Chat error: {e}'}, 500)

@app.post('/api/scan/{eid}/resume')
async def resume_scan(eid: str, request: Request, background_tasks: BackgroundTasks):
    body = await request.json()
    running = _running_agent_scan(except_eid=eid)
    if running:
        return JSONResponse({'error': f'Scan {running} is already running. Stop it before resuming this scan.'}, 409)
    eng = db.get_engagement(eid)
    if not eng:
        return JSONResponse({'error': 'Engagement not found'}, 404)

    old_findings = db.get_findings(eid)
    scan = _init_scan(eid)
    scan['findings'] = old_findings

    urls_raw = body.get('urls', '')
    urls = []
    for line in urls_raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if line.upper().startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ')):
            method, url = line.split(None, 1)
            urls.append((method.upper(), url.strip()))
        else:
            urls.append(('GET', line))

    abort = threading.Event()
    _abort_flags[eid] = abort

    config = {
        'target_url': eng.get('target_url', ''),
        'urls': urls,
        'username': eng.get('auth_username', ''),
        'password': eng.get('auth_password', ''),
        'login_url': eng.get('auth_login_url', ''),
        'app_notes': eng.get('app_notes', ''),
        'repo_path': eng.get('repo_path', ''),
        'agent_backend': body.get('agent_backend', eng.get('agent_backend', 'codex')),
        'use_burp_proxy': bool(eng.get('use_burp_proxy')),
        'disable_fuzzers': bool(eng.get('disable_fuzzers')),
        'enable_browser': bool(eng.get('enable_browser')),
        'previous_findings': old_findings,
    }

    t = threading.Thread(target=_run_scan, args=(eid, config), daemon=True)
    _scan_threads[eid] = t
    t.start()

    return {'engagement_id': eid, 'status': 'resumed', 'previous_findings': len(old_findings)}

@app.post('/api/scan/{eid}/poc')
async def generate_poc(eid: str, request: Request):
    body = await request.json()
    finding_id = body.get('finding_id')
    findings = db.get_findings(eid)
    finding = next((f for f in findings if str(f.get('finding_id')) == str(finding_id)), None)
    if not finding:
        return JSONResponse({'error': 'Finding not found'}, 404)
    try:
        sys.path.insert(0, os.path.join(_app_dir, 'scanner'))
        from poc_builder import build_poc
        poc = build_poc(finding)
        db.update_finding(finding_id, poc=str(poc),
                          confidence='confirmed' if poc.get('reproduced') else finding.get('confidence'))
        return {'ok': True, 'poc': poc}
    except Exception as e:
        return JSONResponse({'error': str(e)}, 500)

@app.get('/api/scan/{eid}/report')
async def scan_report(eid: str, request: Request):
    fmt = request.query_params.get('format', 'docx')
    findings = db.get_findings(eid)
    eng = db.get_engagement(eid) or {}
    proxy = db.get_proxy_entries(eid)

    if fmt == 'csv':
        import csv, io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(['Severity','Confidence','Type','URL','Method','Parameter','Payload',
                    'Evidence','Risk Reasoning','Curl Command','Request','Response'])
        for f in findings:
            w.writerow([f.get('severity',''), f.get('confidence',''), f.get('vuln_type',''),
                        f.get('url',''), f.get('method',''), f.get('parameter',''),
                        f.get('payload',''), f.get('evidence',''), f.get('risk_reasoning',''),
                        f.get('curl_command',''), f.get('request',''), f.get('response','')])
        buf.seek(0)
        return StreamingResponse(iter([buf.read()]), media_type='text/csv',
                                 headers={'Content-Disposition': f'attachment; filename=pentest-{eid}.csv'})

    # DOCX
    try:
        sys.path.insert(0, os.path.join(_app_dir, 'scanner'))
        from report_generator import generate_docx_report
        scan_data = {'id': eid, 'engagement_id': eid, 'target_url': eng.get('target_url',''),
                     'started_at': eng.get('started_at',''), 'ended_at': eng.get('ended_at',''),
                     'status': eng.get('status','')}
        # A scan report must contain only data found in this engagement.
        # Uploaded/source reports belong to the separate template/final-report
        # workflow and must not be mixed into per-scan evidence.
        buf = generate_docx_report(scan_data, findings, proxy,
                                   source_reports=[],
                                   evidence_images=_list_evidence_screenshots(eid))
        return StreamingResponse(iter([buf.read()]),
                                 media_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                                 headers={'Content-Disposition': f'attachment; filename=pentest-{eid}.docx'})
    except Exception as e:
        return JSONResponse({'error': str(e)}, 500)

@app.get('/api/report/template')
async def report_template_status():
    exists = os.path.exists(_default_report_template)
    stat = os.stat(_default_report_template) if exists else None
    return {
        'ok': True,
        'exists': exists,
        'name': os.path.basename(_default_report_template),
        'path': _default_report_template,
        'size': stat.st_size if stat else 0,
        'updated_at': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat() if stat else None,
    }

@app.post('/api/report/template')
async def upload_report_template(request: Request):
    data = await request.body()
    filename = request.headers.get('x-filename', 'default_pentest_template.docx')
    if not filename.lower().endswith('.docx'):
        return JSONResponse({'error': 'Upload a .docx Word template.'}, 400)
    err = _validate_docx_bytes(data)
    if err:
        return JSONResponse({'error': err.replace('DOCX', 'DOCX template')}, 400)

    os.makedirs(_report_template_dir, exist_ok=True)
    tmp_path = _default_report_template + '.tmp'
    with open(tmp_path, 'wb') as f:
        f.write(data)
    os.replace(tmp_path, _default_report_template)
    return await report_template_status()

@app.get('/api/report/source-reports')
async def report_source_reports():
    reports = _list_source_reports()
    return {'ok': True, 'reports': reports, 'count': len(reports)}

@app.post('/api/report/source-reports')
async def upload_source_report(request: Request):
    data = await request.body()
    filename = _safe_report_filename(request.headers.get('x-filename', 'source-report.docx'))
    if not filename.lower().endswith('.docx'):
        return JSONResponse({'error': 'Upload .docx report files.'}, 400)
    err = _validate_docx_bytes(data)
    if err:
        return JSONResponse({'error': err}, 400)

    saved = _save_source_report_bytes(data, filename)
    saved['reports'] = _list_source_reports()
    return saved

@app.post('/api/report/source-reports/import-folder')
async def import_source_reports_from_folder(request: Request):
    body = await request.json() if request.headers.get('content-type', '').startswith('application/json') else {}
    folder = body.get('folder') or _default_report_import_dir
    folder = os.path.abspath(os.path.expanduser(folder))
    if not os.path.isdir(folder):
        return JSONResponse({'error': f'Folder not found: {folder}'}, 400)
    imported = 0
    duplicates = 0
    skipped = 0
    errors = []
    for name in sorted(os.listdir(folder)):
        if name.startswith('~$') or not name.lower().endswith('.docx'):
            skipped += 1
            continue
        path = os.path.join(folder, name)
        try:
            data = open(path, 'rb').read()
            err = _validate_docx_bytes(data)
            if err:
                skipped += 1
                errors.append({'name': name, 'error': err})
                continue
            saved = _save_source_report_bytes(data, name)
            if saved.get('duplicate'):
                duplicates += 1
            else:
                imported += 1
        except Exception as exc:
            skipped += 1
            errors.append({'name': name, 'error': str(exc)})
    return {'ok': True, 'folder': folder, 'imported': imported, 'duplicates': duplicates,
            'skipped': skipped, 'errors': errors[:20], 'reports': _list_source_reports()}

@app.delete('/api/report/source-reports')
async def clear_source_reports():
    os.makedirs(_source_report_dir, exist_ok=True)
    removed = 0
    for name in os.listdir(_source_report_dir):
        if not name.lower().endswith('.docx'):
            continue
        try:
            os.remove(os.path.join(_source_report_dir, name))
            removed += 1
        except OSError:
            pass
    return {'ok': True, 'removed': removed, 'reports': []}

@app.get('/api/report/evidence-screenshots')
async def report_evidence_screenshots():
    images = _list_evidence_screenshots()
    return {'ok': True, 'folder': _evidence_screenshot_dir, 'images': images, 'count': len(images)}

# ─────────────────────────────────────────────────────────────────────────────
# Proxy tab  (per-engagement Burp history view)
# ─────────────────────────────────────────────────────────────────────────────

@app.get('/api/proxy/{eid}/history')
async def proxy_history(eid: str, request: Request):
    limit = int(request.query_params.get('limit', 5000))
    rows = db.get_proxy_entries(eid)[:limit]
    items = []
    for row in rows:
        items.append({
            'index': row.get('id'),
            'method': row.get('method') or 'GET',
            'url': row.get('url') or '',
            'status_code': row.get('status') or 0,
            'response_length': row.get('length') or 0,
            'body_preview': row.get('body_preview') or '',
            'request_headers': row.get('request_headers') or [],
            'request_body': row.get('request_body') or '',
            'response_headers': row.get('response_headers') or [],
            'response_body': row.get('response_body') or '',
            'tested': row.get('tested') or 0,
        })
    resp = JSONResponse({'items': items, 'count': len(items), 'total_in_history': len(items)}, status_code=200)
    resp.headers['Cache-Control'] = 'no-store'
    return resp

@app.post('/api/proxy/{eid}/import-burp')
async def proxy_import_burp(eid: str, request: Request):
    eng = db.get_engagement(eid)
    if not eng:
        return JSONResponse({'error': 'Engagement not found'}, 404)
    payload = await request.json() if request.headers.get('content-type', '').startswith('application/json') else {}
    limit = int(payload.get('limit') or 5000)
    after_index = payload.get('after_index')
    params = {'limit': str(limit)}
    if after_index:
        params['after_index'] = str(after_index)
    data, code = burp_get('/proxy/history', params=params)
    if code != 200:
        return JSONResponse({'error': data.get('error', 'Burp not reachable')}, code)
    rows = _normalize_burp_items_for_proxy(data.get('items', []), eng.get('target_url') or '')
    db.replace_proxy_entries(eid, rows)
    scan = _get_scan(eid)
    if scan is not None:
        scan['proxy'] = rows
    return {
        'ok': True,
        'imported': len(rows),
        'burp_total': data.get('total_in_history', 0),
        'target_url': eng.get('target_url') or '',
    }

@app.post('/api/proxy/{eid}/clear')
async def proxy_clear(eid: str):
    """Set watermark to current Burp total — hides all existing history for this engagement."""
    db.clear_proxy_entries(eid)
    scan = _get_scan(eid)
    if scan:
        scan['proxy'] = []
    return {'ok': True}

# ─────────────────────────────────────────────────────────────────────────────
# Burp tab  (global Burp history, not per-engagement)
# ─────────────────────────────────────────────────────────────────────────────

@app.get('/api/burp/status')
async def burp_status():
    data, code = burp_get('/proxy/history', {'limit': '1'})
    if code == 200:
        return {'connected': True, 'total': data.get('total_in_history', 0)}
    return {'connected': False, 'error': data.get('error', 'Burp not reachable')}

@app.get('/api/burp/history')
async def burp_history_global(request: Request):
    limit = int(request.query_params.get('limit', 2000))
    search = request.query_params.get('search', '')
    after_index = request.query_params.get('after_index', '')
    params = {'limit': str(limit)}
    if search:
        params['search'] = search
    if after_index:
        params['after_index'] = after_index
    data, code = burp_get('/proxy/history', params=params)
    resp = JSONResponse(data, status_code=code)
    resp.headers['Cache-Control'] = 'no-store'
    return resp

@app.post('/api/burp/history/clear')
async def burp_history_clear():
    """Clear Burp history display (watermark-only, not actual Burp data)."""
    data, code = burp_get('/proxy/history', {'limit': '1'})
    if code == 200:
        return {'ok': True, 'total': data.get('total_in_history', 0)}
    return JSONResponse({'ok': False, 'error': data.get('error')}, code)

@app.get('/api/burp/request-context')
async def burp_request_context(request: Request):
    url = request.query_params.get('url', '')
    method = request.query_params.get('method', 'GET')
    data, code = burp_get('/proxy/history', {'limit': '5000'})
    if code != 200:
        return JSONResponse({'error': 'Burp not reachable'}, 503)
    items = data.get('items', [])
    match = next((i for i in reversed(items)
                  if i.get('url', '') == url and i.get('method', '').upper() == method.upper()), None)
    if not match:
        return JSONResponse({'error': 'Not found in Burp history'}, 404)
    return match

@app.get('/api/burp/issues')
async def burp_issues():
    data, code = burp_get('/scanner/issues')
    return JSONResponse(data, status_code=code)

@app.get('/api/burp/sitemap')
async def burp_sitemap():
    data, code = burp_get('/target/sitemap')
    return JSONResponse(data, status_code=code)

@app.post('/api/burp/send')
async def burp_send(request: Request):
    body = await request.json()
    data, code = burp_post('/proxy/request', json=body)
    return JSONResponse(data, status_code=code)

# ─────────────────────────────────────────────────────────────────────────────
# Capture tab
# ─────────────────────────────────────────────────────────────────────────────

@app.post('/api/capture/scan')
async def capture_scan(request: Request, background_tasks: BackgroundTasks):
    body = await request.json()
    running = _running_agent_scan()
    if running:
        return JSONResponse({'error': f'Scan {running} is already running. Stop it before starting capture scan.'}, 409)
    url = body.get('url', '').strip()
    if not url:
        return JSONResponse({'error': 'No URL provided'}, 400)

    eid = db.create_engagement(target_url=url,
                               auth_username=body.get('username', ''),
                               auth_password=body.get('password', ''),
                               auth_login_url=body.get('login_url', ''),
                               app_notes=body.get('notes', ''),
                               agent_backend=body.get('agent_backend', 'codex'))
    scan = _init_scan(eid)
    abort = threading.Event()
    _abort_flags[eid] = abort

    config = {
        'target_url': url,
        'urls': [('GET', url)],
        'username': body.get('username', ''),
        'password': body.get('password', ''),
        'login_url': body.get('login_url', ''),
        'app_notes': body.get('notes', ''),
        'agent_backend': body.get('agent_backend', 'codex'),
        'cookie': body.get('cookie', ''),
        'use_burp_proxy': False,
        'focused_capture': True,
        'disable_fuzzers': True,
        'enable_browser': False,
    }

    t = threading.Thread(target=_run_scan, args=(eid, config), daemon=True)
    _scan_threads[eid] = t
    t.start()

    return {'engagement_id': eid, 'status': 'started'}

# ─────────────────────────────────────────────────────────────────────────────
# Crawler tab
# ─────────────────────────────────────────────────────────────────────────────

_crawler_jobs: dict = {}
_crawler_abort: dict = {}

def _crawler_log(job_id, phase, msg):
    t = datetime.now().strftime('%H:%M:%S')
    job = _crawler_jobs.get(job_id)
    if job is not None:
        job.setdefault('logs', []).append({'time': t, 'phase': phase, 'message': msg})

def _run_crawler(job_id, config):
    job = _crawler_jobs[job_id]
    abort = _crawler_abort.get(job_id, threading.Event())
    try:
        sys.path.insert(0, os.path.join(_app_dir, 'scanner'))
        from crawler import crawl

        job.update({'status': 'running', 'phase': 'crawl', 'progress': 5, 'error': None})
        proxy = BURP_PROXY if config.get('use_burp_proxy') else None
        if proxy:
            _crawler_log(job_id, 'burp', f'Routing discovery traffic through {proxy}')
            burp_set_watermark(job_id)

        def progress(phase, msg):
            if abort.is_set():
                raise RuntimeError('Crawl stopped')
            job['phase'] = phase
            if phase == 'crawl':
                job['progress'] = min(max(job.get('progress', 10), 10), 45)
            elif phase == 'dirbuster':
                job['progress'] = max(job.get('progress', 45), 55)
            elif phase == 'baseline':
                job['progress'] = max(job.get('progress', 70), 75)
            elif phase == 'canary':
                job['progress'] = max(job.get('progress', 85), 88)
            _crawler_log(job_id, phase, msg)

        result = crawl(
            config['target_url'],
            max_pages=int(config.get('max_pages') or 500),
            depth=int(config.get('depth') or 6),
            timeout=int(config.get('timeout') or 420),
            username=config.get('username') or None,
            password=config.get('password') or None,
            login_url=config.get('login_url') or None,
            enable_fuzzers=bool(config.get('enable_dirbuster', True)),
            enable_browser=bool(config.get('enable_browser', False)),
            show_browser=False,
            burp_proxy=proxy,
            enable_canaries=False,
        )

        endpoints = []
        seen = set()
        for ep in result.get('endpoints', []):
            method = (ep.get('method') if isinstance(ep, dict) else 'GET') or 'GET'
            url = (ep.get('url') if isinstance(ep, dict) else ep) or ''
            key = f'{method.upper()} {url}'
            if url and key not in seen:
                seen.add(key)
                endpoints.append({'method': method.upper(), 'url': url})

        job.update({
            'status': 'completed' if not abort.is_set() else 'interrupted',
            'phase': 'done',
            'progress': 100,
            'ended_at': _utc(),
            'endpoints': endpoints,
            'forms': result.get('forms', []),
            'params': result.get('params', []),
            'links': result.get('links', []),
            'xhr_urls': result.get('xhr_urls', []),
            'js_urls': result.get('js_urls', []),
            'canary_results': result.get('canary_results', []),
        })
        _crawler_log(job_id, 'done', f"Discovery complete — {len(endpoints)} endpoints, {len(job['forms'])} forms, {len(job['params'])} params")
    except Exception as e:
        job.update({
            'status': 'interrupted' if abort.is_set() else 'error',
            'phase': 'error' if not abort.is_set() else 'done',
            'progress': job.get('progress', 0),
            'ended_at': _utc(),
            'error': str(e),
        })
        _crawler_log(job_id, 'error' if not abort.is_set() else 'done', str(e))

@app.post('/api/crawler/start')
async def crawler_start(request: Request):
    body = await request.json()
    target_url = (body.get('target_url') or '').strip()
    if not target_url:
        return JSONResponse({'error': 'No target URL provided'}, 400)
    if not target_url.startswith(('http://', 'https://')):
        return JSONResponse({'error': 'Target URL must start with http:// or https://'}, 400)

    job_id = db.new_id()
    _crawler_jobs[job_id] = {
        'id': job_id,
        'status': 'queued',
        'phase': '',
        'progress': 0,
        'target_url': target_url,
        'started_at': _utc(),
        'ended_at': None,
        'logs': [],
        'endpoints': [],
        'forms': [],
        'params': [],
        'links': [],
        'xhr_urls': [],
        'js_urls': [],
        'canary_results': [],
        'error': None,
    }
    _crawler_abort[job_id] = threading.Event()

    config = {
        'target_url': target_url,
        'login_url': body.get('login_url', ''),
        'username': body.get('username', ''),
        'password': body.get('password', ''),
        'use_burp_proxy': bool(body.get('use_burp_proxy', True)),
        'enable_dirbuster': bool(body.get('enable_dirbuster', True)),
        'enable_browser': bool(body.get('enable_browser', False)),
        'max_pages': body.get('max_pages', 500),
        'depth': body.get('depth', 6),
        'timeout': body.get('timeout', 420),
    }
    t = threading.Thread(target=_run_crawler, args=(job_id, config), daemon=True)
    t.start()
    return {'job_id': job_id, 'status': 'started'}

@app.get('/api/crawler/{job_id}')
async def crawler_status(job_id: str):
    job = _crawler_jobs.get(job_id)
    if not job:
        return JSONResponse({'error': 'Crawler job not found'}, 404)
    return {**job, 'logs': job.get('logs', [])[-300:]}

@app.post('/api/crawler/{job_id}/stop')
async def crawler_stop(job_id: str):
    flag = _crawler_abort.get(job_id)
    if flag:
        flag.set()
    job = _crawler_jobs.get(job_id)
    if job and job.get('status') == 'running':
        job['status'] = 'interrupted'
        job['ended_at'] = _utc()
        _crawler_log(job_id, 'done', 'Stop requested')
    return {'ok': True}

# ─────────────────────────────────────────────────────────────────────────────
# Network tab
# ─────────────────────────────────────────────────────────────────────────────

_net_scans: dict = {}
_net_abort: dict = {}

def _run_net_scan(eid, config):
    try:
        sys.path.insert(0, os.path.join(_app_dir, 'scanner'))
        from network_agent import run_network_scan
        _net_scans[eid] = {'status': 'running', 'logs': [], 'findings': []}
        run_network_scan(eid, config, _net_scans[eid], _net_abort.get(eid, threading.Event()))
        _net_scans[eid]['status'] = 'completed'
    except Exception as e:
        if eid in _net_scans:
            _net_scans[eid]['status'] = 'error'
            _net_scans[eid]['error'] = str(e)

@app.post('/api/network/scan')
async def network_scan(request: Request):
    body = await request.json()
    targets = body.get('targets', '')
    if not targets.strip():
        return JSONResponse({'error': 'No targets provided'}, 400)
    eid = db.new_id()
    abort = threading.Event()
    _net_abort[eid] = abort
    config = {'targets': targets, 'ports': body.get('ports', '1-65535'),
              'rate': body.get('rate', '1000'), 'sudo_password': body.get('sudo_password', '')}
    t = threading.Thread(target=_run_net_scan, args=(eid, config), daemon=True)
    t.start()
    return {'scan_id': eid, 'status': 'started'}

@app.get('/api/network/scan/{eid}/status')
async def network_scan_status(eid: str):
    return _net_scans.get(eid, {'status': 'not_found'})

@app.post('/api/network/scan/{eid}/stop')
async def network_scan_stop(eid: str):
    flag = _net_abort.get(eid)
    if flag:
        flag.set()
    return {'ok': True}

# ─────────────────────────────────────────────────────────────────────────────
# Global stop all
# ─────────────────────────────────────────────────────────────────────────────

@app.post('/api/stop/all')
async def stop_all():
    for flag in _abort_flags.values():
        flag.set()
    for flag in _net_abort.values():
        flag.set()
    for eid in list(_scans.keys()):
        scan = _scans[eid]
        if scan.get('status') == 'running':
            scan['status'] = 'interrupted'
            scan['ended_at'] = _utc()
            _flush(eid)
    return {'ok': True}

# ─────────────────────────────────────────────────────────────────────────────
# Setup / health
# ─────────────────────────────────────────────────────────────────────────────

@app.get('/api/health')
async def health():
    return {'ok': True, 'app': 'Pentest'}

@app.get('/api/setup/status')
async def setup_status():
    checks = {}
    # Claude CLI
    try:
        r = subprocess.run(['claude', '--version'], capture_output=True, timeout=5)
        checks['claude_cli'] = r.returncode == 0
    except Exception:
        checks['claude_cli'] = False
    # Burp
    bdata, bcode = burp_get('/proxy/history', {'limit': '1'})
    checks['burp'] = bcode == 200
    checks['burp_total'] = bdata.get('total_in_history', 0)
    return checks

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PENTEST_PORT', 5051))
    print(f'\n  Pentest running → http://localhost:{port}\n')
    uvicorn.run('main:app', host='127.0.0.1', port=port, reload=False, log_level='warning')
