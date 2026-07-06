#!/usr/bin/env python3
"""Clickjacking helper for the DAST agent.

Implements the OWASP WSTG-CLNT-09 baseline check:
- request the target page
- inspect X-Frame-Options and CSP frame-ancestors
- optionally write a simple iframe PoC page

Outputs JSON only.
"""
import argparse
import html
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _header(headers, name):
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return ''


def _parse_frame_ancestors(csp):
    if not csp:
        return ''
    for part in csp.split(';'):
        part = part.strip()
        if part.lower().startswith('frame-ancestors'):
            return part
    return ''


def _xfo_result(value):
    if not value:
        return {'present': False, 'protective': False, 'reason': 'X-Frame-Options header missing'}
    normalized = value.strip().upper()
    if normalized in ('DENY', 'SAMEORIGIN') or normalized.startswith('ALLOW-FROM '):
        return {'present': True, 'protective': True, 'reason': f'X-Frame-Options is {value}'}
    return {'present': True, 'protective': False, 'reason': f'Unrecognized X-Frame-Options value: {value}'}


def _csp_result(value):
    fa = _parse_frame_ancestors(value)
    if not fa:
        return {'present': bool(value), 'protective': False, 'frame_ancestors': '', 'reason': 'CSP frame-ancestors directive missing'}
    low = fa.lower()
    if "'none'" in low or "'self'" in low or re.search(r'\shttps?://', low):
        return {'present': True, 'protective': True, 'frame_ancestors': fa, 'reason': f'CSP {fa}'}
    return {'present': True, 'protective': False, 'frame_ancestors': fa, 'reason': f'CSP frame-ancestors may be weak: {fa}'}


def _same_origin(url, final_url):
    try:
        a = urlparse(url)
        b = urlparse(final_url)
        return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)
    except Exception:
        return False


def _make_poc(url, out_path):
    body = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Clickjacking test page</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    iframe {{ width: 900px; height: 650px; border: 2px solid #333; opacity: 0.85; }}
  </style>
</head>
<body>
  <h1>Clickjacking iframe test</h1>
  <p>If the target page loads below, it may be frameable by an attacker-controlled page.</p>
  <iframe src="{html.escape(url, quote=True)}"></iframe>
</body>
</html>
"""
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(body)
    return out_path


def cmd_check(args):
    headers = {}
    if args.headers:
        headers.update(json.loads(args.headers))
    resp = requests.request(
        args.method.upper(),
        args.url,
        headers=headers,
        data=args.data,
        timeout=args.timeout,
        verify=False,
        allow_redirects=True,
    )

    xfo = _header(resp.headers, 'x-frame-options')
    csp = _header(resp.headers, 'content-security-policy')
    xfo_eval = _xfo_result(xfo)
    csp_eval = _csp_result(csp)
    protected = bool(xfo_eval['protective'] or csp_eval['protective'])
    indicator = not protected and resp.status_code < 400

    poc_path = ''
    if args.poc_out:
        poc_path = os.path.abspath(os.path.expanduser(args.poc_out))
        os.makedirs(os.path.dirname(poc_path), exist_ok=True)
        _make_poc(resp.url, poc_path)
    elif args.make_poc:
        fd, poc_path = tempfile.mkstemp(prefix='clickjacking-poc-', suffix='.html')
        os.close(fd)
        _make_poc(resp.url, poc_path)

    return {
        'ok': True,
        'tested_at': datetime.now(timezone.utc).isoformat(),
        'url': args.url,
        'method': args.method.upper(),
        'status': resp.status_code,
        'final_url': resp.url,
        'same_origin_after_redirect': _same_origin(args.url, resp.url),
        'headers': {
            'x_frame_options': xfo,
            'content_security_policy': csp,
        },
        'evaluation': {
            'x_frame_options': xfo_eval,
            'csp_frame_ancestors': csp_eval,
            'frame_protection_present': protected,
            'clickjacking_indicator': indicator,
            'reporting_note': 'Report only if the frameable page contains authenticated or sensitive user actions/data.'
        },
        'poc_html': poc_path,
        'request': f'{args.method.upper()} {urlparse(args.url).path or "/"} HTTP/1.1',
        'response_preview': resp.text[:600],
    }


def main():
    ap = argparse.ArgumentParser(description='OWASP WSTG clickjacking header and iframe PoC helper')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('check')
    p.add_argument('--url', required=True)
    p.add_argument('--method', default='GET')
    p.add_argument('--data')
    p.add_argument('--headers', help='JSON object of request headers')
    p.add_argument('--timeout', type=int, default=15)
    p.add_argument('--make-poc', action='store_true')
    p.add_argument('--poc-out', help='Write iframe PoC HTML to this path')
    p.set_defaults(func=cmd_check)

    args = ap.parse_args()
    try:
        print(json.dumps(args.func(args), indent=2, default=str))
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}))
        sys.exit(1)


if __name__ == '__main__':
    main()
