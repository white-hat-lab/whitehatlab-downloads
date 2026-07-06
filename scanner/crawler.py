"""
Multi-tool crawler that discovers endpoints, forms, params, and baselines.
HeadlessCrawler is imported lazily and only when browser crawling is enabled.

Discovery pipeline (each stage merges into a shared URL pool):
  1. katana      — fast Go spider (JS-crawling, depth 3, ~30 s)
  2. ffuf         — directory + API endpoint fuzzing with SecLists wordlists
  3. feroxbuster  — recursive content discovery
  4. Optional Playwright — form detection + JS-rendered route extraction
"""
import os
import shutil
import subprocess
import tempfile
import threading
import json as _json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── SecLists / tool paths ─────────────────────────────────────────────────────
_SECLISTS = os.path.expanduser('~/seclists')
_WORDLISTS = {
    'raft_medium':  os.path.join(_SECLISTS, 'Discovery/Web-Content/raft-medium-directories.txt'),
    'common':       os.path.join(_SECLISTS, 'Discovery/Web-Content/common.txt'),
    'api':          os.path.join(_SECLISTS, 'Discovery/Web-Content/api/api-endpoints.txt'),
    'api_wild':     os.path.join(_SECLISTS, 'Discovery/Web-Content/api/api-seen-in-wild.txt'),
    'big':          os.path.join(_SECLISTS, 'Discovery/Web-Content/big.txt'),
}

_DEFAULT_DIR_WORDS = [
    'admin', 'api', 'app', 'assets', 'auth', 'backup', 'config', 'dashboard',
    'debug', 'docs', 'download', 'health', 'help', 'home', 'images', 'img',
    'js', 'private', 'profile', 'register', 'reports', 'static', 'status',
    'support', 'test', 'upload', 'uploads', 'user', 'users', 'v1', 'v2',
]


def _proxy_dict(proxy_url):
    if not proxy_url:
        return None
    return {'http': proxy_url, 'https': proxy_url}


def _cookie_header_to_dict(cookie_header):
    cookies = {}
    for part in (cookie_header or '').split(';'):
        if '=' not in part:
            continue
        name, value = part.split('=', 1)
        name = name.strip()
        if name:
            cookies[name] = value.strip()
    return cookies


def _vulnerableapp_metadata_urls(target_url):
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        return []
    origin = f"{parsed.scheme}://{parsed.netloc}"
    candidates = [
        f"{origin}/VulnerableApp/scanner",
        f"{origin}/VulnerableApp/scanner/",
    ]
    path = parsed.path or '/'
    if path.rstrip('/').endswith('/VulnerableApp'):
        candidates.insert(0, f"{origin}{path.rstrip('/')}/scanner")
    if path.rstrip('/').endswith('/VulnerableApp/scanner'):
        candidates.insert(0, target_url)
    seen = set()
    out = []
    for url in candidates:
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _import_vulnerableapp_scanner_metadata(target_url, progress_cb=None, proxy=None, timeout=20):
    """Import SasanLabs VulnerableApp's built-in scanner inventory.

    The facade exposes the real challenge list at /VulnerableApp/scanner, but the
    JSON contains Docker-internal hostnames such as VulnerableApp-base:9090.
    Rewrite those to the externally reachable target origin before normalizing.
    """
    target = urlparse(target_url)
    if not target.scheme or not target.netloc:
        return []
    target_origin = f"{target.scheme}://{target.netloc}"
    imported = []
    proxies = _proxy_dict(proxy)

    for metadata_url in _vulnerableapp_metadata_urls(target_url):
        try:
            resp = requests.get(metadata_url, timeout=timeout, verify=False, proxies=proxies)
        except Exception:
            continue
        content_type = (resp.headers.get('content-type') or '').lower()
        if resp.status_code != 200 or ('json' not in content_type and not resp.text.lstrip().startswith('[')):
            continue
        try:
            data = resp.json()
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict):
                continue
            raw = item.get('url') or ''
            parsed = urlparse(raw)
            if not parsed.path:
                continue
            rewritten = urlunparse((
                target.scheme,
                target.netloc,
                parsed.path or '/',
                '',
                parsed.query,
                '',
            ))
            imported.append({
                'url': rewritten,
                'method': (item.get('method') or 'GET').upper(),
                'source': 'vulnerableapp-scanner',
                'variant': item.get('variant', ''),
                'vulnerabilityTypes': item.get('vulnerabilityTypes') or [],
            })
        if imported:
            if progress_cb:
                progress_cb('crawl', f'[vulnerableapp] Imported {len(imported)} endpoints from {metadata_url}')
            break

    return imported


def _looks_like_login_response(resp):
    final_url = getattr(resp, 'url', '') or ''
    body = (getattr(resp, 'text', '') or '')[:5000].lower()
    final_path = urlparse(final_url).path.lower()
    if any(seg in final_path for seg in ('/login', '/signin', '/sign-in', '/auth')):
        return True
    return (
        '<form' in body
        and ('name="login"' in body or 'name="username"' in body or 'name="password"' in body)
        and ('type="password"' in body or 'password:' in body)
    )


def _json_text_hint(resp):
    """Return compact response text used for generic input-hint extraction."""
    content_type = (resp.headers.get('content-type') or '').lower()
    if 'json' in content_type:
        try:
            data = resp.json()
            if isinstance(data, dict):
                parts = []
                for key in ('content', 'message', 'error', 'detail', 'description'):
                    value = data.get(key)
                    if isinstance(value, str):
                        parts.append(value)
                if parts:
                    return ' '.join(parts)
            return _json.dumps(data)[:2000]
        except Exception:
            pass
    return (resp.text or '')[:2000]


def _infer_params_from_response(resp):
    """Infer likely input names from API/help text without app-specific rules."""
    hint = _json_text_hint(resp)
    lower = hint.lower()
    params = []

    phrase_map = [
        (('username and password', 'user name and password'), ['username', 'password']),
        (('login or token', 'username or token'), ['login', 'token']),
        (('login and password',), ['login', 'password']),
        (('email and password',), ['email', 'password']),
    ]
    for phrases, names in phrase_map:
        if any(p in lower for p in phrases):
            params.extend(names)

    keyword_map = [
        ('username', 'username'),
        ('user name', 'username'),
        ('password', 'password'),
        ('login', 'login'),
        ('email', 'email'),
        ('token', 'token'),
        ('jwt', 'token'),
        ('url', 'url'),
        ('uri', 'url'),
        ('domain', 'domain'),
        ('host', 'host'),
        ('file', 'file'),
        ('path', 'path'),
        ('xml', 'xml'),
        ('xpath', 'xpath'),
        ('query', 'query'),
        ('id', 'id'),
    ]
    provide_context = any(w in lower for w in ('provide', 'enter', 'missing', 'required'))
    for needle, name in keyword_map:
        if needle in lower and (provide_context or name in ('token', 'jwt')):
            params.append(name)

    # Keep order stable while removing duplicates.
    seen = set()
    deduped = []
    for name in params:
        if name not in seen:
            seen.add(name)
            deduped.append(name)
    return deduped


def _extract_html_forms(html, base_url, max_options_per_select=200):
    """Extract forms and bounded select/radio choices from a rendered HTML page."""
    try:
        from bs4 import BeautifulSoup
    except Exception:
        return []

    soup = BeautifulSoup(html or '', 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        action = urljoin(base_url, form.get('action') or base_url)
        method = (form.get('method') or 'GET').upper()
        fields = []
        defaults = {}
        choice_fields = []

        for inp in form.find_all(['input', 'textarea', 'button']):
            name = inp.get('name')
            if not name:
                continue
            ftype = (inp.get('type') or inp.name or 'text').lower()
            value = inp.get('value') or ''
            fields.append({'name': name, 'type': ftype, 'value': value})
            if ftype in ('checkbox', 'radio'):
                choice_fields.append({'name': name, 'type': ftype, 'values': [value] if value else []})
            elif ftype not in ('submit', 'button', 'image', 'file'):
                defaults[name] = value
            elif name not in defaults:
                defaults[name] = value or 'submit'

        for sel in form.find_all('select'):
            name = sel.get('name')
            if not name:
                continue
            options = []
            for opt in sel.find_all('option')[:max_options_per_select]:
                value = opt.get('value')
                if value is None:
                    value = opt.get_text(strip=True)
                options.append(value or '')
            fields.append({'name': name, 'type': 'select', 'value': options[0] if options else ''})
            if options:
                defaults[name] = options[0]
                choice_fields.append({'name': name, 'type': 'select', 'values': options})

        forms.append({
            'action': action,
            'method': method,
            'fields': fields,
            'defaults': defaults,
            'choice_fields': choice_fields,
        })
    return forms


def _find_tool(name, *extra_paths):
    """Return absolute path to a CLI tool, checking PATH and known extra locations."""
    p = shutil.which(name)
    if p:
        return p
    for ep in extra_paths:
        if os.path.isfile(ep):
            return ep
    return None


def _katana_bin():
    return _find_tool('katana', os.path.expanduser('~/go/bin/katana'))

def _ffuf_bin():
    return _find_tool('ffuf', os.path.expanduser('~/go/bin/ffuf'), '/usr/local/bin/ffuf')

def _ferox_bin():
    return _find_tool('feroxbuster', os.path.expanduser('~/.cargo/bin/feroxbuster'))


_BROWSER_SEED_SKIP_EXTS = {
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
    '.woff', '.woff2', '.ttf', '.eot', '.otf', '.map', '.pdf', '.zip', '.gz',
    '.tgz', '.bz2', '.7z', '.rar', '.mp3', '.mp4', '.webm', '.avi', '.mov',
    '.mkv', '.xml', '.txt', '.rss',
}

_BROWSER_SEED_SKIP_PATH_PARTS = (
    '/static/', '/assets/', '/images/', '/img/', '/fonts/', '/media/',
    '/cdn-cgi/', '/wp-content/', '/wp-includes/',
)


def _normalize_browser_seed_url(url, target_url):
    """Return a normalized browser seed URL and a dedupe key.

    This is intentionally for Playwright seeding only. We preserve the original
    raw URLs for endpoint reporting later, but the browser should not visit the
    same page hundreds of times just because query values differ.
    """
    if not url or not str(url).startswith(('http://', 'https://')):
        return None, None
    try:
        parsed = urlparse(url)
        target = urlparse(target_url)
    except Exception:
        return None, None
    if not parsed.scheme or not parsed.netloc:
        return None, None
    if parsed.netloc.lower() != target.netloc.lower():
        return None, None

    path = parsed.path or '/'
    path_lower = path.lower()
    if any(part in path_lower for part in _BROWSER_SEED_SKIP_PATH_PARTS):
        return None, None
    ext = os.path.splitext(path_lower)[1]
    if ext in _BROWSER_SEED_SKIP_EXTS:
        return None, None

    path = path.rstrip('/') or '/'
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    # Collapse query value explosions but preserve which parameters make this a
    # distinct route shape.
    query_names = sorted({k for k, _v in pairs if k})
    normalized_query = urlencode([(name, '1') for name in query_names])
    normalized = urlunparse((parsed.scheme, parsed.netloc, path, '', normalized_query, ''))
    key = (parsed.scheme.lower(), parsed.netloc.lower(), path.lower(), tuple(query_names))
    return normalized, key


def _clean_browser_seed_urls(urls, target_url):
    """Clean fast-tool output before using it as Playwright seed input."""
    cleaned = []
    seen = set()
    dropped = 0
    for raw in urls or []:
        normalized, key = _normalize_browser_seed_url(raw, target_url)
        if not normalized or not key:
            dropped += 1
            continue
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        cleaned.append(normalized)
    return cleaned, dropped


# ── Auth helper — get session cookie before fuzzing ───────────────────────────

def _get_auth_cookie(login_url, username, password, progress_cb=None, proxy=None):
    """Log in to the target and return a cookie header string for use with CLI tools.

    Handles CSRF tokens automatically (Django, Flask-WTF, Rails, etc.).
    Returns a string like "sessionid=abc123; csrftoken=xyz" or None on failure.
    """
    if not login_url or not username or not password:
        return None
    try:
        import re as _re
        s = requests.Session()
        s.verify = False
        if proxy:
            s.proxies.update(_proxy_dict(proxy))
        s.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

        # GET the login page to collect CSRF token and any hidden fields.
        # Retry with a generous timeout — some targets (slow .gov hosts) take
        # >10s to respond and a single short timeout spuriously fails auth.
        resp = None
        for _attempt in range(3):
            try:
                resp = s.get(login_url, timeout=30, allow_redirects=True)
                break
            except requests.exceptions.RequestException:
                if _attempt == 2:
                    raise
        body = resp.text

        # Extract all hidden input fields (CSRF tokens etc.)
        hidden = {}
        for m in _re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]*>', body, _re.IGNORECASE):
            tag = m.group(0)
            nm = _re.search(r'name=["\']([^"\']+)["\']', tag)
            vl = _re.search(r'value=["\']([^"\']*)["\']', tag)
            if nm:
                hidden[nm.group(1)] = vl.group(1) if vl else ''

        # Detect form action
        fm = _re.search(r'<form[^>]+action=["\']([^"\']*)["\']', body, _re.IGNORECASE)
        action = fm.group(1) if fm else login_url
        if action and not action.startswith('http'):
            from urllib.parse import urljoin
            action = urljoin(login_url, action)

        # Build POST data
        data = dict(hidden)
        # Fill username/password fields by sniffing field names
        for m in _re.finditer(r'<input([^>]*)>', body, _re.IGNORECASE):
            attrs = m.group(1)
            itype = (_re.search(r'type=["\'](\w+)["\']', attrs) or type('', (), {'group': lambda s, n: 'text'})()).group(1).lower()
            iname = _re.search(r'name=["\']([^"\']+)["\']', attrs)
            if not iname:
                continue
            name = iname.group(1)
            if itype == 'password':
                data[name] = password
            elif itype in ('text', 'email') and any(k in name.lower() for k in ('user', 'email', 'login', 'name')):
                data[name] = username
            elif itype in ('submit', 'button') and name not in data:
                vl = _re.search(r'value=["\']([^"\']*)["\']', attrs)
                data[name] = vl.group(1) if vl else 'submit'

        for m in _re.finditer(r'<select[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</select>', body, _re.IGNORECASE | _re.DOTALL):
            name = m.group(1)
            if name in data:
                continue
            options = _re.findall(r'<option[^>]+value=["\']([^"\']*)["\'][^>]*>', m.group(2), _re.IGNORECASE)
            data[name] = options[0] if options else ''

        for m in _re.finditer(r'<button([^>]*)>', body, _re.IGNORECASE):
            attrs = m.group(1)
            iname = _re.search(r'name=["\']([^"\']+)["\']', attrs)
            if not iname:
                continue
            name = iname.group(1)
            if name in data:
                continue
            vl = _re.search(r'value=["\']([^"\']*)["\']', attrs)
            data[name] = vl.group(1) if vl else 'submit'

        # Fallback: common field names
        if not any(v == username for v in data.values()):
            for k in ('username', 'email', 'user', 'login'):
                if k not in data:
                    data[k] = username
                    break
        if not any(v == password for v in data.values()):
            for k in ('password', 'pass', 'passwd', 'pwd'):
                if k not in data:
                    data[k] = password
                    break

        post_resp = None
        for _attempt in range(3):
            try:
                post_resp = s.post(action or login_url, data=data, timeout=30, allow_redirects=True)
                break
            except requests.exceptions.RequestException:
                if _attempt == 2:
                    raise

        # Check login succeeded: we should NOT still be on the login page
        if 'login' in post_resp.url.lower() and post_resp.status_code == 200:
            if progress_cb:
                progress_cb('crawl', f'[auth] Login may have failed (still on login page)')
            return None

        # Build cookie header string from session cookies
        cookies = '; '.join(f'{c.name}={c.value}' for c in s.cookies)
        if cookies and progress_cb:
            progress_cb('crawl', f'[auth] Authenticated as {username} — cookie obtained')
        return cookies or None
    except Exception as exc:
        if progress_cb:
            progress_cb('crawl', f'[auth] Could not authenticate: {exc}')
        return None


# ── Stage 1: katana ───────────────────────────────────────────────────────────

def _run_katana(target_url, timeout=60, cookie=None, progress_cb=None, proxy=None):
    """Fast Go-based spider — finds JS routes, API endpoints, XHR calls."""
    bin_ = _katana_bin()
    if not bin_:
        return []
    if progress_cb:
        progress_cb('crawl', '[katana] Starting fast JS spider...')

    out = tempfile.mktemp(suffix='_katana.txt')
    cmd = [
        bin_,
        '-u', target_url,
        '-depth', '3',
        '-jc',              # JS crawling
        '-kf', 'all',       # known files (robots, sitemap, etc.)
        '-ef', 'png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,css',
        '-o', out,
        '-silent',
        '-timeout', '8',
        '-rate-limit', '80',
        '-concurrency', '10',
    ]
    if cookie:
        cmd += ['-H', f'Cookie: {cookie}']
    if proxy:
        cmd += ['-proxy', proxy]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        urls = []
        if os.path.exists(out):
            with open(out) as f:
                for line in f:
                    u = line.strip()
                    if u and u.startswith('http'):
                        urls.append(u)
            os.unlink(out)
        if progress_cb:
            progress_cb('crawl', f'[katana] Found {len(urls)} URLs')
        return urls
    except Exception as exc:
        if progress_cb:
            progress_cb('crawl', f'[katana] Skipped: {exc}')
        return []


# ── Stage 2: ffuf ─────────────────────────────────────────────────────────────

def _run_ffuf(target_url, timeout=90, cookie=None, progress_cb=None, proxy=None):
    """Fuzz directories AND API endpoints with SecLists wordlists."""
    bin_ = _ffuf_bin()
    if not bin_:
        return []

    # Pick best available wordlist — use common.txt (4k entries, ~30s) for speed;
    # raft-medium (30k) is too slow for interactive scans.
    wordlist = next(
        (p for k in ('common', 'raft_medium') if os.path.isfile(p := _WORDLISTS[k])),
        None
    )
    # API wordlist: prefer the smaller targeted list (288 entries) for speed
    api_wordlist = next(
        (p for k in ('api', 'api_wild') if os.path.isfile(p := _WORDLISTS[k])),
        None
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    results = []

    def _fuzz(wl, label):
        if not wl or not os.path.isfile(wl):
            return
        if progress_cb:
            progress_cb('crawl', f'[ffuf] Fuzzing with {label} ({_line_count(wl)} words)...')
        out = tempfile.mktemp(suffix='_ffuf.json')
        cmd = [
            bin_,
            '-u', f'{base}/FUZZ',
            '-w', wl,
            '-mc', '200,201,204,301,302,307,401,403,405,500',
            '-fc', '404',
            '-o', out, '-of', 'json',
            '-t', '30',
            '-rate', '80',
            '-timeout', '6',
            '-maxtime', '45',    # graceful stop with partial results after 45s
            '-s',                # silent
        ]
        if cookie:
            cmd += ['-H', f'Cookie: {cookie}']
        if proxy:
            cmd += ['-x', proxy]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if os.path.exists(out):
                try:
                    data = _json.loads(open(out).read())
                    for r in data.get('results', []):
                        u = r.get('url', '')
                        if u:
                            results.append(u)
                except Exception:
                    pass
                os.unlink(out)
        except Exception as exc:
            if progress_cb:
                progress_cb('crawl', f'[ffuf/{label}] Skipped: {exc}')

    t1 = threading.Thread(target=_fuzz, args=(wordlist, 'raft-medium'), daemon=True)
    t2 = threading.Thread(target=_fuzz, args=(api_wordlist, 'api-wild'), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()

    if progress_cb:
        progress_cb('crawl', f'[ffuf] Found {len(results)} endpoints')
    return results


def _line_count(path):
    try:
        return sum(1 for _ in open(path))
    except Exception:
        return 0


# ── Stage 3: feroxbuster ──────────────────────────────────────────────────────

def _run_feroxbuster(target_url, timeout=90, cookie=None, progress_cb=None, proxy=None):
    """Recursive content discovery — finds paths ffuf misses due to depth."""
    bin_ = _ferox_bin()
    if not bin_:
        return []

    wordlist = next(
        (p for k in ('common', 'raft_medium') if os.path.isfile(p := _WORDLISTS[k])),
        None
    )
    if not wordlist:
        return []

    if progress_cb:
        progress_cb('crawl', '[feroxbuster] Recursive directory scan...')

    out = tempfile.mktemp(suffix='_ferox.txt')
    cmd = [
        bin_,
        '--url', target_url,
        '--wordlist', wordlist,
        '--status-codes', '200,201,301,302,307,401,403',
        '--output', out,
        '--json',           # JSONL output — each discovered URL as a JSON line
        '--quiet',
        '--no-state',
        '--threads', '30',
        '--depth', '2',
        '--rate-limit', '100',
        '--timeout', '8',
        '--time-limit', '80s',   # graceful stop after 80s with partial results
    ]
    if cookie:
        cmd += ['--cookies', cookie]
    if proxy:
        cmd += ['--proxy', proxy]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
        urls = []
        if os.path.exists(out):
            with open(out) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = _json.loads(line)
                        # feroxbuster JSONL: {"type":"response","url":"..."}
                        u = obj.get('url', '')
                        if u and u.startswith('http'):
                            urls.append(u)
                    except Exception:
                        # Fallback: scan for http:// in plain text
                        for part in line.split():
                            if part.startswith('http'):
                                urls.append(part)
                                break
            os.unlink(out)
        if progress_cb:
            progress_cb('crawl', f'[feroxbuster] Found {len(urls)} paths')
        return urls
    except Exception as exc:
        if progress_cb:
            progress_cb('crawl', f'[feroxbuster] Skipped: {exc}')
        return []


# ── Stage 4: JS endpoint extraction (LinkFinder-style) ───────────────────────

def _run_linkfinder(js_urls, base_url, cookie=None, progress_cb=None, proxy=None):
    """Download JS files and extract endpoint paths using regex.

    No external tool needed — runs inline with requests + re.
    Finds routes hardcoded in JS bundles that crawlers never follow.
    """
    import re

    if not js_urls:
        return []

    base = urlparse(base_url)
    base_root = f"{base.scheme}://{base.netloc}"

    # Matches relative paths and API-style routes inside JS strings/templates
    _PATH_RE = re.compile(
        r'''(?:"|'|`)(/[a-zA-Z0-9_\-/\.]{2,100})(?:[?#"'`]|$)'''
    )
    # Skip clearly non-route matches
    _SKIP_PREFIXES = ('//', '/*', '* ', './', '../', '/cdn-', '/static/', '/assets/')
    _SKIP_EXTS = ('.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.woff2',
                  '.ttf', '.eot', '.css', '.map')

    sess = requests.Session()
    sess.verify = False
    if proxy:
        sess.proxies.update(_proxy_dict(proxy))
    headers = {'Cookie': cookie} if cookie else {}

    found = set()
    processed = 0

    for js_url in js_urls:
        # Only process JS files from the same host
        parsed = urlparse(js_url)
        if parsed.netloc and parsed.netloc != base.netloc:
            continue
        if not (parsed.path.endswith('.js') or 'bundle' in parsed.path or 'chunk' in parsed.path):
            continue
        try:
            r = sess.get(js_url, headers=headers, timeout=15)
            if r.status_code != 200:
                continue
            content = r.text
            processed += 1
            for m in _PATH_RE.finditer(content):
                path = m.group(1)
                if any(path.startswith(p) for p in _SKIP_PREFIXES):
                    continue
                if any(path.endswith(e) for e in _SKIP_EXTS):
                    continue
                if len(path) < 3 or len(path) > 120:
                    continue
                # Must look like a real route — at least one slash segment with letters
                if not re.search(r'/[a-zA-Z]{2,}', path):
                    continue
                full = base_root + path
                found.add(full)
        except Exception:
            continue

    results = list(found)
    if progress_cb:
        progress_cb('crawl', f'[linkfinder] Scanned {processed} JS files, found {len(results)} endpoint paths')
    return results


def _run_dirbuster_py(target_url, timeout=90, cookie=None, progress_cb=None, proxy=None, max_words=2500):
    """Small built-in DirBuster-style path discovery fallback.

    This keeps endpoint discovery useful even when ffuf/feroxbuster or
    SecLists are not installed. It is intentionally bounded for interactive UI
    runs.
    """
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        return []

    wordlist = next(
        (p for k in ('common', 'raft_medium', 'big') if os.path.isfile(p := _WORDLISTS[k])),
        None
    )
    words = list(_DEFAULT_DIR_WORDS)
    if wordlist:
        try:
            with open(wordlist) as fh:
                for line in fh:
                    word = line.strip()
                    if word and not word.startswith('#') and not word.startswith('.'):
                        word = word.lstrip('/')
                        if word not in words:
                            words.append(word)
                    if len(words) >= max_words:
                        break
        except Exception:
            pass

    base = f'{parsed.scheme}://{parsed.netloc}'
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; PentestCrawler/1.0)',
    }
    if cookie:
        headers['Cookie'] = cookie
    proxies = _proxy_dict(proxy)
    found = []
    interesting = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405}

    if progress_cb:
        via = ' through Burp' if proxy else ''
        progress_cb('dirbuster', f'[dirbuster] Brute forcing {len(words)} paths{via}...')

    probe_paths = []
    seen_probe_paths = set()
    auth_control_probe_paths = {
        'login', 'login.php', 'signin', 'signin.php', 'logout', 'logout.php',
        'logoff', 'logoff.php', 'session', 'session.php',
    }
    for word in words:
        candidates = [word]
        if not os.path.splitext(word)[1] and '.' not in word:
            candidates.append(f'{word}.php')
        for candidate in candidates:
            candidate = candidate.lstrip('/')
            if candidate.lower() in auth_control_probe_paths:
                continue
            if candidate and candidate not in seen_probe_paths:
                seen_probe_paths.add(candidate)
                probe_paths.append(candidate)

    def _probe(word):
        url = f'{base}/{word}'
        try:
            r = requests.get(
                url,
                headers=headers,
                proxies=proxies,
                verify=False,
                timeout=5,
                allow_redirects=False,
            )
            location = r.headers.get('Location', '')
            if location and ('login' in location.lower() or 'logout' in location.lower()):
                return None
            if r.status_code in interesting:
                return url
        except Exception:
            return None
        return None

    deadline = timeout
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(_probe, w) for w in probe_paths]
        try:
            for fut in as_completed(futures, timeout=deadline):
                url = fut.result()
                if url:
                    found.append(url)
        except Exception:
            for fut in futures:
                fut.cancel()

    if progress_cb:
        progress_cb('dirbuster', f'[dirbuster] Found {len(found)} paths')
    return found


# ── HeadlessCrawler loader ────────────────────────────────────────────────────

def _get_headless_crawler():
    """Lazy import HeadlessCrawler only when actually needed."""
    from headless_crawler import HeadlessCrawler
    return HeadlessCrawler


# ── Main crawl() ─────────────────────────────────────────────────────────────

def crawl(target_url, max_pages=2000, depth=10, timeout=1200, cookies=None,
          progress_cb=None, username=None, password=None, login_url=None,
          enable_fuzzers=True, show_browser=False, enable_browser=False,
          burp_proxy=None, enable_canaries=True):
    """Crawl target and return endpoints, forms, params, baselines.

    Discovery pipeline:
      1. katana      — JS spider (fast, ~30 s)
      2. ffuf        — directory + API endpoint fuzzing (parallel wordlists)
      3. feroxbuster — recursive path discovery
      4. linkfinder  — extract routes from JS bundle files
      5. Optional Playwright — form detection + XHR capture on discovered pages

    Returns:
        {
            'endpoints': [{'url': ..., 'method': ...}, ...],
            'forms': [...],
            'params': [...],
            'baselines': {...},
            'links': [...],
            'js_urls': [...],
            'xhr_urls': [...],
            'canary_results': [...],
        }
    """
    if progress_cb:
        progress_cb('crawl', f'Starting multi-tool discovery on {target_url}...')

    # ── Pre-auth: get session cookie so fast tools can reach authenticated pages ──
    auth_cookie = None
    if username and password:
        _login_url = login_url or f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}/login/"
        if progress_cb:
            progress_cb('crawl', f'[auth] Logging in as {username} to get session cookie...')
        auth_cookie = _get_auth_cookie(_login_url, username, password, progress_cb=progress_cb, proxy=burp_proxy)

    # ── Stages 1-3: fast parallel pre-crawl ──────────────────────────────────
    _extra_urls = []   # shared list — appended to from all threads

    # Discovery-tool budgets scale with the crawl timeout (deep crawls get more).
    _kt = min(max(timeout // 4, 120), 600)     # katana
    _ft = min(max(timeout // 2, 300), 1200)    # ffuf / feroxbuster
    def _s1():
        _extra_urls.extend(_run_katana(target_url, timeout=_kt, cookie=auth_cookie, progress_cb=progress_cb, proxy=burp_proxy))

    def _s2():
        _extra_urls.extend(_run_ffuf(target_url, timeout=_ft, cookie=auth_cookie, progress_cb=progress_cb, proxy=burp_proxy))

    def _s3():
        _extra_urls.extend(_run_feroxbuster(target_url, timeout=_ft, cookie=auth_cookie, progress_cb=progress_cb, proxy=burp_proxy))

    def _s4():
        _extra_urls.extend(_run_dirbuster_py(target_url, timeout=min(_ft, 180), cookie=auth_cookie, progress_cb=progress_cb, proxy=burp_proxy))

    if not enable_fuzzers and progress_cb:
        browser_note = ' + Playwright' if enable_browser else ''
        progress_cb('crawl', f'[config] Fuzzers disabled — running katana{browser_note} only (low-noise mode)')

    fns = [_s1] + ([_s2, _s3, _s4] if enable_fuzzers else [])
    threads = [threading.Thread(target=fn, daemon=True) for fn in fns]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=_ft + 60)   # outer cap scales with the tool budget

    if progress_cb:
        progress_cb('crawl', f'Pre-crawl tools discovered {len(_extra_urls)} raw URLs total')

    vulnerableapp_endpoints = _import_vulnerableapp_scanner_metadata(
        target_url,
        progress_cb=progress_cb,
        proxy=burp_proxy,
        timeout=min(max(timeout // 6, 10), 60),
    )
    if vulnerableapp_endpoints:
        _extra_urls.extend(ep['url'] for ep in vulnerableapp_endpoints)
        if burp_proxy and progress_cb:
            progress_cb('burp', f'[vulnerableapp] Replaying {len(vulnerableapp_endpoints)} metadata endpoints through Burp during baseline capture')

    # ── Stage 4: LinkFinder — extract routes from JS bundles ─────────────────
    js_urls = [u for u in _extra_urls if
               u.endswith('.js') or 'bundle' in urlparse(u).path or 'chunk' in urlparse(u).path]
    if js_urls:
        _extra_urls.extend(_run_linkfinder(js_urls, target_url, cookie=auth_cookie, progress_cb=progress_cb, proxy=burp_proxy))

    _browser_seed_file = None
    if enable_browser and _extra_urls:
        cleaned_seed_urls, dropped_seed_urls = _clean_browser_seed_urls(_extra_urls, target_url)
        if progress_cb:
            progress_cb(
                'crawl',
                f'Cleaned Playwright seed URLs: {len(_extra_urls)} raw -> '
                f'{len(cleaned_seed_urls)} normalized ({dropped_seed_urls} dropped as duplicate/junk)'
            )
        if cleaned_seed_urls:
            seed = tempfile.NamedTemporaryFile('w', suffix='_playwright_seeds.txt', delete=False)
            try:
                seed.write('\n'.join(cleaned_seed_urls))
                seed.write('\n')
                _browser_seed_file = seed.name
            finally:
                seed.close()

    results = {
        'endpoints': [{'url': target_url, 'method': 'GET'}] + vulnerableapp_endpoints,
        'forms': [],
        'input_points': [],
        'detected_parameters': [],
        'api_endpoints': [],
        'xhr_captured_urls': [],
        'js_discovered_urls': [],
        'links': [],
        'canary_results': [],
    }

    # ── Stage 4: Optional Playwright headless crawl ───────────────────────────
    # Renders pages to detect form fields, JS routes, and XHR endpoints.
    # Bounds come from the crawl() params (max_pages / depth / timeout).
    if enable_browser:
        if progress_cb:
            progress_cb('crawl', f'Starting Playwright browser for form/JS analysis (max {max_pages} pages, depth {depth})...')

        HeadlessCrawler = _get_headless_crawler()
        crawler = HeadlessCrawler(
            target_url=target_url,
            max_depth=depth,
            max_pages=max_pages,
            timeout=max(timeout, 300) * 1000,   # crawl() timeout is in seconds
            show_browser=show_browser,
            login_url=login_url,
            username=username,
            password=password,
            passive_only=True,
            enable_scanning=False,
            enable_gobuster=False,   # skip built-in gobuster — ffuf covers it
            seed_urls_file=_browser_seed_file,
        )

        try:
            results = crawler.run()
        finally:
            if _browser_seed_file:
                try:
                    os.unlink(_browser_seed_file)
                except OSError:
                    pass
    elif progress_cb:
        progress_cb('crawl', '[config] Browser crawling disabled — skipping Playwright stage')

    # ── Merge extra URLs into results ─────────────────────────────────────────
    existing_ep_urls = {
        (ep if isinstance(ep, str) else ep.get('url', ''))
        for ep in results.get('endpoints', [])
    }
    for u in _extra_urls:
        if u and u not in existing_ep_urls:
            results.setdefault('endpoints', []).append({'url': u, 'method': 'GET'})
            existing_ep_urls.add(u)

    # ── Normalize / filter rules ──────────────────────────────────────────────
    SKIP_EXT = (
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.map', '.pdf', '.zip', '.gz',
        '.tgz', '.bz2', '.7z', '.rar', '.mp3', '.mp4', '.webm', '.avi',
        '.mov', '.mkv', '.xml', '.txt'
    )
    SKIP_PATTERNS = (
        '${', '%7b', '%7d', '__webpack', 'chunk', 'precache', 'service-worker',
        'manifest.json', 'favicon', 'robots.txt', 'sitemap', 'hot-update',
        'sockjs', '__vite', '_next/static', 'analytics', 'telemetry', 'beacon',
        'doubleclick', 'googletagmanager', 'google-analytics', 'segment',
    )
    SKIP_PREFIXES = ('blob:', 'data:', 'javascript:', 'mailto:', 'tel:', 'about:')
    SKIP_PATH_PARTS = (
        '/static/', '/assets/', '/dist/', '/build/', '/public/', '/vendor/',
        '/_next/', '/__vite/', '/sockjs/', '/webpack/', '/hot-update/',
        '/service-worker', '/sw.js', '/manifest', '/favicon', '/robots.txt',
        '/sitemap', '/analytics', '/telemetry', '/metrics', '/beacon',
    )
    API_HINTS = ('/api/', '/graphql', '/rest/', '/v1/', '/v2/', '/v3/', '/auth/')

    # Scanner's own API paths — must never appear in crawl results
    SCANNER_PATHS = (
        '/api/license/', '/api/license/status', '/api/license/refresh',
        '/api/contact', '/api/subscribe', '/api/checkout', '/api/check',
        '/api/scan', '/api/chat', '/api/projects', '/api/clean',
        '/api/activate', '/api/verify', '/api/check-ai',
    )
    AUTH_CONTROL_PATHS = (
        '/login', '/login.php', '/signin', '/signin.php',
        '/logout', '/logout.php', '/logoff', '/session/destroy',
    )

    # Scope controls
    _target_parsed = urlparse(target_url)
    _target_scheme = _target_parsed.scheme or 'http'
    _target_host = (_target_parsed.hostname or '').lower()
    _target_port = _target_parsed.port or (443 if _target_scheme == 'https' else 80)
    _target_netloc = f"{_target_host}:{_target_port}"

    _target_path = _target_parsed.path or '/'
    _target_first_segment = ''
    _target_segments = [s for s in _target_path.split('/') if s]
    if _target_segments:
        _target_first_segment = '/' + _target_segments[0]

    # A single-segment target that is a landing file (e.g. /index.html, /home.php)
    # means "scan this site", not "scope to /index.html/" — otherwise every other
    # page on the host is dropped as out-of-scope. Treat it as whole-host scope.
    if len(_target_segments) == 1 and '.' in _target_segments[0]:
        _target_first_segment = ''

    _AUTH_SEGMENTS = {
        'login', 'signin', 'sign-in', 'sign_in', 'auth', 'authenticate',
        'register', 'signup', 'sign-up', 'sign_up', 'logout', 'logoff',
        'session', 'sso', 'oauth', 'callback', 'account',
    }
    if _target_first_segment.lstrip('/') in _AUTH_SEGMENTS:
        _target_first_segment = ''

    _self_ports = {'5050'}

    def _normalize_url(url):
        if not url:
            return ''
        url = str(url).strip()
        if not url:
            return ''
        if url.lower().startswith(SKIP_PREFIXES):
            return ''
        parsed = urlparse(url)
        scheme = parsed.scheme or _target_scheme
        host = (parsed.hostname or '').lower()
        if not host:
            return ''
        port = parsed.port or (443 if scheme == 'https' else 80)
        path = parsed.path or '/'
        while '//' in path:
            path = path.replace('//', '/')
        normalized = urlunparse((scheme, f'{host}:{port}', path, '', parsed.query, ''))
        return normalized.rstrip('?')

    def _in_target_scope(url):
        parsed = urlparse(url)
        scheme = parsed.scheme or _target_scheme
        host = (parsed.hostname or '').lower()
        port = parsed.port or (443 if scheme == 'https' else 80)
        if host != _target_host or port != _target_port:
            return False
        path = parsed.path or '/'
        if not _target_first_segment or _target_path in ('', '/'):
            return True
        if any(h in path.lower() for h in API_HINTS):
            return True
        return path == _target_first_segment or path.startswith(_target_first_segment + '/')

    def _is_junk_url(url):
        if not url:
            return True
        lower_url = url.lower()
        if lower_url.startswith(SKIP_PREFIXES):
            return True
        parsed = urlparse(url)
        path = (parsed.path or '/').lower()
        if not _in_target_scope(url):
            return True
        if any(path.endswith(ext) for ext in SKIP_EXT):
            return True
        if any(p in lower_url for p in SKIP_PATTERNS):
            return True
        if any(p in path for p in SKIP_PATH_PARTS):
            return True
        if str(parsed.port or _target_port) in _self_ports and str(parsed.port or _target_port) != str(_target_port):
            return True
        if any(path == sp or path == sp + '/' or path.startswith(sp + '/') for sp in SCANNER_PATHS):
            return True
        if path in AUTH_CONTROL_PATHS:
            return True
        return False

    def _looks_interesting(url, method='GET'):
        # Comprehensive mode: promote every in-scope, non-static URL as a
        # testable endpoint. _is_junk_url already filters static assets
        # (.js/.css/images/fonts/...), out-of-scope hosts, and the scanner's
        # own API paths — so anything that survives that is a real page worth
        # testing (HTML documents, dynamic routes, API paths, query-bearing URLs).
        return not _is_junk_url(url)

    def _endpoint_key(url, method='GET'):
        parsed = urlparse(url)
        path = parsed.path or '/'
        method = (method or 'GET').upper()
        return f"{method}:{parsed.hostname}:{parsed.port or _target_port}{path}"

    def _strip_query(url):
        """Return URL with query string removed — keep only base path."""
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, '', '', ''))

    # Normalize endpoints
    raw_endpoints = results.get('endpoints', [])
    endpoints = []
    seen_paths = set()
    seen_links = set()

    def _add_link(url):
        normalized = _normalize_url(url)
        if not normalized or _is_junk_url(normalized):
            return
        parsed = urlparse(normalized)
        link_key = f"{parsed.scheme}://{parsed.hostname}:{parsed.port or _target_port}{parsed.path}"
        if link_key in seen_links:
            return
        seen_links.add(link_key)

    def _add_endpoint(url, method='GET', promote=True):
        normalized = _normalize_url(url)
        method = (method or 'GET').upper()
        if not normalized:
            return
        _add_link(normalized)
        if not promote:
            return
        if not _looks_interesting(normalized, method):
            return
        dedup_key = _endpoint_key(normalized, method)
        if dedup_key in seen_paths:
            return
        seen_paths.add(dedup_key)
        endpoints.append({'url': _strip_query(normalized), 'method': method})

    for ep in raw_endpoints:
        url = ep if isinstance(ep, str) else ep.get('url', '')
        method = ep.get('method', 'GET') if isinstance(ep, dict) else 'GET'
        _add_endpoint(url, method, promote=True)

    # Normalize forms
    raw_forms = results.get('forms', [])
    forms = []
    seen_forms = set()
    for form in raw_forms:
        action = form.get('action', form.get('url', ''))
        action = _normalize_url(action)
        if not action or _is_junk_url(action):
            continue
        method = form.get('method', 'GET').upper()
        fields = form.get('fields', form.get('inputs', []))
        if not isinstance(fields, list):
            fields = []
        normalized_fields = []
        for f in fields:
            if isinstance(f, dict):
                name = f.get('name', '')
                if not name:
                    continue
                normalized_fields.append({
                    'name': name,
                    'type': f.get('type', 'text'),
                    'value': f.get('value', ''),
                })
            elif isinstance(f, str) and f.strip():
                normalized_fields.append({'name': f.strip(), 'type': 'text', 'value': ''})
        if not normalized_fields:
            continue
        form_key = f"{method}:{action}:{','.join(sorted(f['name'] for f in normalized_fields))}"
        if form_key in seen_forms:
            continue
        seen_forms.add(form_key)
        forms.append({'action': action, 'method': method, 'fields': normalized_fields})
        _add_endpoint(action, method, promote=True)

    # Collect params
    params = []
    seen_params = set()

    def _add_param(name, url, ptype='text', source='detected'):
        name = (name or '').strip()
        url = _normalize_url(url)
        if not name or not url or _is_junk_url(url):
            return
        key = (name, url)
        if key in seen_params:
            return
        seen_params.add(key)
        params.append({'name': name, 'url': url, 'type': ptype or 'text', 'source': source})

    def _attach_endpoint_param(method, url, name, ptype='text', source='detected'):
        normalized = _strip_query(_normalize_url(url))
        method = (method or 'GET').upper()
        if not normalized or not name:
            return
        for ep in endpoints:
            if (ep.get('method') or 'GET').upper() != method:
                continue
            if ep.get('url') != normalized:
                continue
            ep.setdefault('params', [])
            if not any(p.get('name') == name for p in ep['params']):
                ep['params'].append({'name': name, 'type': ptype or 'text', 'source': source})
            break

    for ip in results.get('input_points', []):
        _add_param(ip.get('name', ''), ip.get('url', ip.get('form_action', '')),
                   ip.get('type', 'text'), ip.get('source', 'form'))

    for dp in results.get('detected_parameters', []):
        _add_param(dp.get('name', ''), dp.get('url', ''),
                   dp.get('type', 'text'), dp.get('source', 'detected'))

    js_urls = []
    xhr_urls = []

    for api_ep in results.get('api_endpoints', []):
        u = api_ep if isinstance(api_ep, str) else api_ep.get('url', '')
        m = api_ep.get('method', 'GET').upper() if isinstance(api_ep, dict) else 'GET'
        _add_endpoint(u, m, promote=True)

    for xhr_url in results.get('xhr_captured_urls', []):
        u = xhr_url if isinstance(xhr_url, str) else xhr_url.get('url', '')
        normalized = _normalize_url(u)
        if normalized and not _is_junk_url(normalized):
            if normalized not in xhr_urls:
                xhr_urls.append(normalized)
            _add_endpoint(normalized, 'GET', promote=True)

    for js_url in results.get('js_discovered_urls', []):
        u = js_url if isinstance(js_url, str) else js_url.get('url', '')
        normalized = _normalize_url(u)
        if normalized and not _is_junk_url(normalized):
            if normalized not in js_urls:
                js_urls.append(normalized)
            _add_link(normalized)

    links = sorted(seen_links)

    if progress_cb:
        progress_cb(
            'crawl',
            f'Discovery complete: {len(endpoints)} endpoints, {len(forms)} forms, '
            f'{len(params)} params, {len(xhr_urls)} XHR, {len(js_urls)} JS URLs'
        )

    # ── Capture baselines ─────────────────────────────────────────────────────
    if progress_cb:
        progress_cb('baseline', f'Capturing baselines for {len(endpoints)} endpoints...')

    baselines = {}
    session = requests.Session()
    session.verify = False
    if burp_proxy:
        session.proxies.update(_proxy_dict(burp_proxy))
    session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    if auth_cookie:
        session.cookies.update(_cookie_header_to_dict(auth_cookie))
    if cookies:
        for k, v in cookies.items():
            session.cookies.set(k, v)

    for c in results.get('cookies', []):
        if isinstance(c, dict) and c.get('name') and c.get('value'):
            session.cookies.set(c['name'], c['value'])

    choice_nav_submits = 0
    choice_nav_limit = min(max_pages, 300)

    def _record_html_form(form_info, source_url):
        action = _normalize_url(form_info.get('action') or source_url)
        if not action or _is_junk_url(action):
            return
        method = (form_info.get('method') or 'GET').upper()
        fields = form_info.get('fields') or []
        normalized_fields = [
            {'name': f.get('name', ''), 'type': f.get('type', 'text'), 'value': f.get('value', '')}
            for f in fields
            if f.get('name')
        ]
        if not normalized_fields:
            return
        form_key = f"{method}:{action}:{','.join(sorted(f['name'] for f in normalized_fields))}"
        if form_key not in seen_forms:
            seen_forms.add(form_key)
            forms.append({'action': action, 'method': method, 'fields': normalized_fields})
            _add_endpoint(action, method, promote=True)
            for f in normalized_fields:
                _add_param(f.get('name', ''), action, f.get('type', 'text'), 'form')

    def _submit_choice_navigation_forms(html, page_url):
        nonlocal choice_nav_submits
        discovered = []
        if choice_nav_submits >= choice_nav_limit:
            return discovered
        for form_info in _extract_html_forms(html, page_url):
            _record_html_form(form_info, page_url)
            method = (form_info.get('method') or 'GET').upper()
            if method not in ('GET', 'POST'):
                continue
            action = _normalize_url(form_info.get('action') or page_url)
            if not action or _is_junk_url(action):
                continue
            field_types = {f.get('type', '').lower() for f in form_info.get('fields', [])}
            if 'password' in field_types or 'file' in field_types:
                continue
            choices = [
                c for c in form_info.get('choice_fields', [])
                if c.get('values') and len(c.get('values') or []) > 1
            ]
            if not choices:
                continue

            # Generic menu/wizard discovery: vary one choice field at a time
            # while keeping other form fields at their default values.
            for choice in choices[:3]:
                for value in (choice.get('values') or [])[:200]:
                    if choice_nav_submits >= choice_nav_limit:
                        return discovered
                    if value is None or str(value) == '':
                        continue
                    data = dict(form_info.get('defaults') or {})
                    data[choice['name']] = value
                    try:
                        if method == 'GET':
                            resp = session.get(action, params=data, timeout=10, allow_redirects=True)
                        else:
                            resp = session.post(action, data=data, timeout=10, allow_redirects=True)
                        choice_nav_submits += 1
                        if resp.status_code == 404 or _looks_like_login_response(resp):
                            continue
                        final_url = _normalize_url(resp.url)
                        if final_url and not _is_junk_url(final_url):
                            discovered.append(final_url)
                    except Exception:
                        choice_nav_submits += 1
                        continue
        return discovered

    dead_urls = set()
    choice_discovered_urls = []
    seen_choice_discovered = set()
    for i, ep in enumerate(endpoints):
        url = ep.get('url', '') if isinstance(ep, dict) else ep
        if not url:
            continue
        method = ep.get('method', 'GET') if isinstance(ep, dict) else 'GET'
        method = method.upper()
        if method not in ('GET', 'HEAD', 'POST'):
            # Baselines are for endpoint liveness only. Keep uncommon methods
            # out of discovery replay, but include POST because benchmark apps
            # such as VulnerableApp publish POST challenge endpoints in their
            # scanner metadata and the operator expects them to appear in Burp.
            continue
        parsed = urlparse(url)
        key = f"{method}:{parsed.path}"
        if key in baselines:
            continue
        try:
            request_kwargs = {'timeout': 10, 'allow_redirects': True}
            if method == 'POST':
                request_kwargs['data'] = {}
            resp = session.request(method, url, **request_kwargs)
            if resp.status_code == 404:
                dead_urls.add(url)
                continue
            if _looks_like_login_response(resp):
                dead_urls.add(url)
                continue
            content_type = resp.headers.get('content-type', '')
            if 'html' in content_type.lower() or '<form' in resp.text.lower():
                for discovered_url in _submit_choice_navigation_forms(resp.text, resp.url):
                    if discovered_url not in seen_choice_discovered:
                        seen_choice_discovered.add(discovered_url)
                        choice_discovered_urls.append(discovered_url)
            inferred_params = _infer_params_from_response(resp)
            for pname in inferred_params:
                _add_param(pname, url, 'text', 'response-hint')
                _attach_endpoint_param(method, url, pname, 'text', 'response-hint')
            baselines[key] = {
                'url': url,
                'status': resp.status_code,
                'body': resp.text[:8000],
                'headers': dict(resp.headers),
                'length': len(resp.text),
                'params': inferred_params,
            }
        except Exception:
            pass
        if progress_cb and (i + 1) % 10 == 0:
            progress_cb('baseline', f'Baselines: {len(baselines)}/{len(endpoints)}')

    if dead_urls:
        before = len(endpoints)
        endpoints = [ep for ep in endpoints
                     if (ep.get('url', '') if isinstance(ep, dict) else ep) not in dead_urls]
        if progress_cb:
            progress_cb('baseline', f'Filtered {before - len(endpoints)} dead (404) URLs')

    added_choice_nav = 0
    for discovered_url in choice_discovered_urls:
        before = len(endpoints)
        _add_endpoint(discovered_url, 'GET', promote=True)
        if len(endpoints) > before:
            added_choice_nav += 1
    if progress_cb and added_choice_nav:
        progress_cb('baseline', f'Discovered {added_choice_nav} form-driven navigation endpoints')

    if progress_cb:
        progress_cb('baseline', f'Baselines captured: {len(baselines)}, live endpoints: {len(endpoints)}')

    # ── Canary probes ─────────────────────────────────────────────────────────
    if not enable_canaries:
        if progress_cb:
            progress_cb('canary', 'Canary probes disabled for endpoint discovery')
        return {
            'endpoints': endpoints,
            'forms': forms,
            'params': params,
            'baselines': baselines,
            'links': links,
            'js_urls': js_urls,
            'xhr_urls': xhr_urls,
            'canary_results': [],
            'proxy_logs': results.get('proxy_logs', []) if enable_browser else [],
        }

    if progress_cb:
        progress_cb('canary', f'Running canary probes on {len(forms)} forms + {len(params)} params...')

    import random
    import string
    from urllib.parse import urlparse as _urlparse

    def _gen_canary():
        rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"WHL_CANARY_{rand}"

    def _is_safe_endpoint(url):
        dangerous = ['logout', 'delete', 'remove', 'payment', 'checkout', 'transfer', 'admin/delete']
        return not any(k in url.lower() for k in dangerous)

    canary_results = []

    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'POST').upper()
        fields = form.get('fields', [])
        if not action or not fields or not _is_safe_endpoint(action):
            continue
        canary = _gen_canary()
        canary_data = {f.get('name', ''): canary for f in fields if f.get('name')}
        bl_key = f"{method}:{_urlparse(action).path}"
        baseline_len = baselines.get(bl_key, {}).get('length', 0)
        try:
            if method == 'POST':
                resp = session.post(action, data=canary_data, timeout=10, allow_redirects=True)
            else:
                resp = session.get(action, params=canary_data, timeout=10, allow_redirects=True)
            reflected = canary in resp.text
            length_diff = abs(len(resp.text) - baseline_len) if baseline_len else 0
            processed = resp.status_code != 404 and length_diff > 20
            for field in fields:
                fname = field.get('name', '')
                if not fname:
                    continue
                canary_results.append({
                    'url': action, 'method': method, 'param': fname,
                    'canary': canary, 'reflected': reflected, 'processed': processed,
                    'status_code': resp.status_code, 'length_diff': length_diff,
                    'type': ('reflection_candidate' if reflected
                             else ('backend_processed' if processed else 'no_effect')),
                })
        except Exception:
            pass

    for param_info in params:
        pname = param_info.get('name', '')
        purl = param_info.get('url', '')
        if not pname or not purl or not _is_safe_endpoint(purl):
            continue
        canary = _gen_canary()
        bl_key = f"GET:{_urlparse(purl).path}"
        baseline_len = baselines.get(bl_key, {}).get('length', 0)
        try:
            resp = session.get(purl, params={pname: canary}, timeout=10, allow_redirects=True)
            reflected = canary in resp.text
            length_diff = abs(len(resp.text) - baseline_len) if baseline_len else 0
            processed = resp.status_code != 404 and length_diff > 20
            canary_results.append({
                'url': purl, 'method': 'GET', 'param': pname,
                'canary': canary, 'reflected': reflected, 'processed': processed,
                'status_code': resp.status_code, 'length_diff': length_diff,
                'type': ('reflection_candidate' if reflected
                         else ('backend_processed' if processed else 'no_effect')),
            })
        except Exception:
            pass

    reflected_count = sum(1 for c in canary_results if c['reflected'])
    processed_count = sum(1 for c in canary_results if c['processed'] and not c['reflected'])
    dead_count = sum(1 for c in canary_results if c['type'] == 'no_effect')

    if progress_cb:
        progress_cb('canary',
                    f'Canary probes done: {reflected_count} reflected, '
                    f'{processed_count} processed, {dead_count} dead params')

    return {
        'endpoints': endpoints,
        'forms': forms,
        'params': params,
        'baselines': baselines,
        'links': links,
        'js_urls': js_urls,
        'xhr_urls': xhr_urls,
        'canary_results': canary_results,
        'proxy_logs': results.get('proxy_logs', []) if enable_browser else [],
    }
