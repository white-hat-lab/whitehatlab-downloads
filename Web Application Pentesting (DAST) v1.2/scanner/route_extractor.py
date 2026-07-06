#!/usr/bin/env python3
"""
route_extractor.py — When the target's source is available, enumerate EVERY
route from the framework's routing files and seed them into the scan.

This closes the biggest coverage gap: link-crawling + wordlist dirbusting can't
discover custom route names (e.g. pygoat's `/xssL`, `/ssrf_lab`, `/a9_lab`) or
form-only POST endpoints. The route table lists them all, deterministically.

Pure regex over source files — no framework import, no code execution. Supports
Django (urls.py), Flask/Quart, FastAPI/Starlette, and Express/Koa.

API:
    extract_routes(repo_path, base_url) -> list[{'method','url','source'}]
"""
import os
import re
import json
from urllib.parse import urljoin
from urllib.parse import urlparse

_SKIP_DIRS = {'.git', 'node_modules', 'venv', '.venv', 'env', '__pycache__',
              'site-packages', 'dist', 'build', 'migrations', '.tox', 'static',
              'staticfiles', 'media', 'tests', 'test'}

_MAX_FILES = 4000


def _walk(repo_path, name_filters=None, suffixes=None):
    """Yield file paths under repo_path, skipping noise dirs."""
    count = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if suffixes and not fn.endswith(tuple(suffixes)):
                continue
            if name_filters and not any(nf in fn for nf in name_filters):
                continue
            count += 1
            if count > _MAX_FILES:
                return
            yield os.path.join(root, fn)


def _read(path):
    try:
        with open(path, encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return ''


def _clean_route(route):
    """Turn a framework route pattern into a concrete, fuzzable path."""
    if route is None:
        return None
    r = route.strip()
    # strip Django regex anchors
    r = r.lstrip('^').rstrip('$')
    # Django re_path escapes
    r = r.replace('\\/', '/').replace('\\.', '.')
    # Replace param placeholders with a probe value so the URL is requestable:
    #   Django <int:id> / <slug:x>, Flask <id> / <int:id>, FastAPI/Express {id} / :id
    r = re.sub(r'<[^:>]+:([^>]+)>', r'1', r)        # <int:id> -> 1
    r = re.sub(r'<([^>]+)>', r'1', r)               # <id> -> 1
    r = re.sub(r'\{[^}]+\}', r'1', r)               # {id} -> 1
    r = re.sub(r':([A-Za-z_][A-Za-z0-9_]*)', r'1', r)  # :id -> 1
    # drop trailing Django regex bits like (?P<...>) leftovers
    r = re.sub(r'\(\?P<[^>]+>[^)]*\)', '1', r)
    r = re.sub(r'\([^)]*\)', '1', r)
    if not r.startswith('/'):
        r = '/' + r
    return r


# ---------------------------------------------------------------------------
# Django
# ---------------------------------------------------------------------------
_DJANGO_ROUTE = re.compile(
    r"""\b(?:path|re_path|url)\s*\(\s*["']([^"']*)["']""", re.X)
# include('some.module' or "some.module") with its mount prefix
_DJANGO_INCLUDE = re.compile(
    r"""\b(?:path|re_path|url)\s*\(\s*["']([^"']*)["']\s*,\s*include\(\s*["']([^"']+)["']""", re.X)


def _module_candidates(fp, repo_path):
    """Module dotted-paths a urls.py file could be imported as.
    e.g. introduction/urls.py -> {'introduction.urls', 'introduction'}."""
    rel = os.path.relpath(fp, repo_path)
    noext = rel[:-3] if rel.endswith('.py') else rel
    parts = noext.replace(os.sep, '/').split('/')
    cands = set()
    for i in range(len(parts)):
        cands.add('.'.join(parts[i:]))            # introduction.urls, urls
        if parts[-1] == 'urls':
            cands.add('.'.join(parts[i:-1]))      # introduction
    cands.discard('')
    return cands


def _extract_django(repo_path):
    """Parse all urls.py and resolve each route to its real mount prefix by
    matching include('module', prefix) declarations to the module's file."""
    files = [f for f in _walk(repo_path, name_filters=['urls'], suffixes=['.py'])
             if os.path.basename(f).startswith('urls')]
    if not files:
        return []

    # Pass 1: collect include(module -> prefix) across the project.
    module_prefix = {}
    for fp in files:
        text = _read(fp)
        for m in _DJANGO_INCLUDE.finditer(text):
            prefix, module = m.group(1), m.group(2)
            module_prefix[module] = prefix
            module_prefix[module.rsplit('.', 1)[0]] = prefix  # app pkg too

    # Pass 2: extract leaf routes, prefix by this file's resolved mount.
    seen, out = set(), []
    for fp in files:
        text = _read(fp)
        if 'urlpatterns' not in text and 'path(' not in text and 'url(' not in text:
            continue
        # mount prefix for THIS file (default '' = mounted at root)
        prefix = ''
        for cand in _module_candidates(fp, repo_path):
            if cand in module_prefix:
                prefix = module_prefix[cand]
                break
        for m in _DJANGO_ROUTE.finditer(text):
            seg = text[m.start():m.start() + 220]
            if 'include(' in seg:      # skip include() lines (no leaf view)
                continue
            full = _clean_route('/' + (prefix + m.group(1)).lstrip('/'))
            if full and full not in seen:
                seen.add(full)
                out.append((full, fp))
    return out


# ---------------------------------------------------------------------------
# Flask / Quart  &  FastAPI / Starlette
# ---------------------------------------------------------------------------
_FLASK_ROUTE = re.compile(
    r"""@\w+\.route\(\s*["']([^"']+)["'](?:[^)]*methods\s*=\s*\[([^\]]*)\])?""", re.S)
_FASTAPI_ROUTE = re.compile(
    r"""@\w+\.(get|post|put|patch|delete|head|options)\(\s*["']([^"']+)["']""", re.I)


def _extract_python_web(repo_path):
    out, seen = [], set()
    for fp in _walk(repo_path, suffixes=['.py']):
        text = _read(fp)
        if '@' not in text:
            continue
        for m in _FLASK_ROUTE.finditer(text):
            path = _clean_route(m.group(1))
            methods = m.group(2)
            mlist = ([x.strip().strip('"\'').upper() for x in methods.split(',')]
                     if methods else ['GET'])
            for meth in mlist or ['GET']:
                k = (meth, path)
                if path and k not in seen:
                    seen.add(k); out.append((meth, path, fp))
        for m in _FASTAPI_ROUTE.finditer(text):
            meth = m.group(1).upper()
            path = _clean_route(m.group(2))
            k = (meth, path)
            if path and k not in seen:
                seen.add(k); out.append((meth, path, fp))
    return out


# ---------------------------------------------------------------------------
# Express / Koa (JS/TS)
# ---------------------------------------------------------------------------
_EXPRESS_ROUTE = re.compile(
    r"""\b(?:app|router|api)\.(get|post|put|patch|delete|all)\(\s*["'`]([^"'`]+)["'`]""", re.I)


def _extract_express(repo_path):
    out, seen = [], set()
    for fp in _walk(repo_path, suffixes=['.js', '.ts', '.mjs']):
        text = _read(fp)
        for m in _EXPRESS_ROUTE.finditer(text):
            meth = m.group(1).upper()
            if meth == 'ALL':
                meth = 'GET'
            path = _clean_route(m.group(2))
            k = (meth, path)
            if path and k not in seen:
                seen.add(k); out.append((meth, path, fp))
    return out


# ---------------------------------------------------------------------------
# OpenAPI / Swagger
# ---------------------------------------------------------------------------
def _load_openapi(path):
    text = _read(path)
    if not text:
        return None
    try:
        if path.endswith('.json'):
            return json.loads(text)
        import yaml
        return yaml.safe_load(text)
    except Exception:
        return None


def _openapi_server_prefix(spec):
    servers = spec.get('servers') or []
    if not servers:
        return ''
    first = servers[0] or {}
    parsed = urlparse(first.get('url') or '')
    return (parsed.path or '').rstrip('/')


def _openapi_form_params(operation, template, test_name):
    params = []
    content = ((operation.get('requestBody') or {}).get('content') or {})
    form = content.get('application/x-www-form-urlencoded') or {}
    props = (((form.get('schema') or {}).get('properties')) or {})
    for name, meta in props.items():
        meta = meta or {}
        entry = {'name': name, 'in': 'form'}
        default = meta.get('default')
        if default is not None:
            entry['default'] = str(default)
        params.append(entry)

    # Benchmark-style tests sometimes taint the parameter/header name, not
    # only the value. Preserve that input location so active checks can build
    # the actual request shape.
    marker = test_name
    for p in operation.get('parameters') or []:
        if not isinstance(p, dict):
            continue
        default = ((p.get('schema') or {}).get('default'))
        if default:
            marker = str(default)
            break
    for p in props.values():
        if isinstance(p, dict) and p.get('default'):
            marker = str(p.get('default'))
            break
    if 'getParameterNames' in template:
        params.append({'name': 'parameter-name', 'in': 'form_name', 'marker': marker})
    if 'getHeaderNames' in template:
        params.append({'name': 'header-name', 'in': 'header_name', 'marker': marker})
    return params


def _extract_openapi(repo_path, base_url):
    out, seen = [], set()
    candidates = []
    for fp in _walk(repo_path, suffixes=['.yaml', '.yml', '.json']):
        base = os.path.basename(fp).lower()
        if base in ('openapi.yaml', 'openapi.yml', 'swagger.yaml', 'swagger.yml', 'openapi.json', 'swagger.json'):
            candidates.append(fp)
    for fp in candidates:
        spec = _load_openapi(fp)
        if not isinstance(spec, dict) or 'paths' not in spec:
            continue
        prefix = _openapi_server_prefix(spec)
        for path, path_item in (spec.get('paths') or {}).items():
            if not isinstance(path_item, dict):
                continue
            template = path_item.get('x-uiTemplate') or ''
            test_match = re.search(r'(BenchmarkTest\d+)', path)
            test_name = test_match.group(1) if test_match else ''
            for meth, operation in path_item.items():
                if meth.lower() not in ('get', 'post', 'put', 'patch', 'delete', 'head', 'options'):
                    continue
                if not isinstance(operation, dict):
                    continue
                route_path = _clean_route('/'.join([prefix.strip('/'), str(path).lstrip('/')]))
                url = urljoin(base_url.rstrip('/') + '/', route_path.lstrip('/'))
                params = []
                for p in operation.get('parameters') or []:
                    if isinstance(p, dict) and p.get('name') and p.get('in'):
                        params.append({'name': str(p['name']), 'in': str(p['in'])})
                params.extend(_openapi_form_params(operation, template, test_name))
                key = (meth.upper(), url)
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    'method': meth.upper(),
                    'url': url,
                    'source': os.path.relpath(fp, repo_path),
                    'params': params,
                    'template': template,
                })
    return out


def extract_routes(repo_path, base_url):
    """Return [{'method','url','source'}] for every route found in source.

    Never raises — returns [] on any problem so the scan proceeds regardless.
    """
    try:
        repo_path = os.path.abspath(os.path.expanduser(repo_path))
        if not os.path.isdir(repo_path):
            return []
        base = base_url.rstrip('/') + '/'
        results, seen = [], set()

        for r in _extract_openapi(repo_path, base_url):
            key = (r['method'], r['url'])
            if key not in seen:
                seen.add(key)
                results.append(r)

        # Django first (route + method unknown → default GET)
        for full, fp in _extract_django(repo_path):
            url = urljoin(base, full.lstrip('/'))
            if ('GET', url) not in seen:
                seen.add(('GET', url))
                results.append({'method': 'GET', 'url': url,
                                'source': os.path.relpath(fp, repo_path)})

        # Flask / FastAPI (method known)
        for meth, path, fp in _extract_python_web(repo_path):
            url = urljoin(base, path.lstrip('/'))
            if (meth, url) not in seen:
                seen.add((meth, url))
                results.append({'method': meth, 'url': url,
                                'source': os.path.relpath(fp, repo_path)})

        # Express / Koa
        for meth, path, fp in _extract_express(repo_path):
            url = urljoin(base, path.lstrip('/'))
            if (meth, url) not in seen:
                seen.add((meth, url))
                results.append({'method': meth, 'url': url,
                                'source': os.path.relpath(fp, repo_path)})

        return results
    except Exception:
        return []


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print('usage: route_extractor.py <repo_path> <base_url>')
        sys.exit(1)
    rs = extract_routes(sys.argv[1], sys.argv[2])
    print(f'{len(rs)} routes:')
    for r in rs:
        print(f"  {r['method']:6} {r['url']}   <- {r['source']}")
