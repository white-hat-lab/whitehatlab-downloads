#!/usr/bin/env python3
"""JWT helper for the DAST agent.

Outputs JSON only. Designed to be called by the scan agent through Bash.
"""
import argparse
import base64
import copy
import json
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _b64url_decode(segment):
    segment = segment.encode() if isinstance(segment, str) else segment
    segment += b'=' * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment)


def _b64url_encode(data):
    if not isinstance(data, bytes):
        data = json.dumps(data, separators=(',', ':'), sort_keys=True).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _decode_json(segment):
    return json.loads(_b64url_decode(segment).decode('utf-8', 'replace'))


def _split_token(token):
    parts = (token or '').strip().split('.')
    if len(parts) != 3:
        raise ValueError('JWT must have three dot-separated segments')
    return parts


def _decode_token(token):
    h, p, s = _split_token(token)
    header = _decode_json(h)
    payload = _decode_json(p)
    return header, payload, s


def _looks_sensitive(payload):
    keys = {str(k).lower() for k in payload.keys()}
    hits = []
    for key in keys:
        if any(x in key for x in ('password', 'secret', 'token', 'ssn', 'credit', 'card', 'private')):
            hits.append(key)
    return sorted(hits)


def cmd_analyze(args):
    header, payload, sig = _decode_token(args.token)
    now = int(time.time())
    exp = payload.get('exp')
    iat = payload.get('iat')
    nbf = payload.get('nbf')
    findings = []
    alg = str(header.get('alg', '')).lower()
    if alg in ('none', ''):
        findings.append('token header uses alg none or missing alg')
    if not payload.get('iss'):
        findings.append('missing iss claim')
    if not payload.get('aud'):
        findings.append('missing aud claim')
    if isinstance(exp, int):
        if exp < now:
            findings.append('token is expired')
        elif exp - now > 60 * 60 * 24 * 30:
            findings.append('token lifetime exceeds 30 days')
    else:
        findings.append('missing or non-integer exp claim')
    sensitive = _looks_sensitive(payload)
    if sensitive:
        findings.append('payload contains sensitive-looking claim names: ' + ', '.join(sensitive))
    return {
        'ok': True,
        'header': header,
        'payload': payload,
        'signature_present': bool(sig),
        'claims': {'exp': exp, 'iat': iat, 'nbf': nbf, 'now': now},
        'passive_findings': findings,
    }


def _make_none_token(header, payload):
    h = copy.deepcopy(header)
    h['alg'] = 'none'
    h.pop('typ', None)
    return _b64url_encode(h) + '.' + _b64url_encode(payload) + '.'


def _make_bad_signature(token):
    h, p, _ = _split_token(token)
    return h + '.' + p + '.invalidsignature'


def _make_expired(header, payload, original_sig):
    p = copy.deepcopy(payload)
    p['exp'] = 1
    return _b64url_encode(header) + '.' + _b64url_encode(p) + '.' + original_sig


def _make_claim_tamper(header, payload, original_sig):
    p = copy.deepcopy(payload)
    changed = []
    for key in ('role', 'roles', 'admin', 'is_admin', 'isAdmin', 'user_id', 'uid', 'sub'):
        if key not in p:
            continue
        if isinstance(p[key], bool):
            p[key] = True
        elif isinstance(p[key], list):
            p[key] = list(dict.fromkeys(p[key] + ['admin']))
        elif key in ('user_id', 'uid', 'sub'):
            p[key] = '1'
        else:
            p[key] = 'admin'
        changed.append(key)
        break
    if not changed:
        p['role'] = 'admin'
        changed.append('role')
    return _b64url_encode(header) + '.' + _b64url_encode(p) + '.' + original_sig, changed


def build_variants(token):
    header, payload, sig = _decode_token(token)
    tampered, changed = _make_claim_tamper(header, payload, sig)
    return {
        'valid': token,
        'alg_none': _make_none_token(header, payload),
        'bad_signature': _make_bad_signature(token),
        'expired': _make_expired(header, payload, sig),
        'claim_tamper': tampered,
        'claim_tamper_changed': changed,
    }


def cmd_variants(args):
    variants = build_variants(args.token)
    redacted = {} if args.show_tokens else {k: ('<token omitted>' if k != 'claim_tamper_changed' else v) for k, v in variants.items()}
    return {'ok': True, 'variants': variants if args.show_tokens else redacted}


def _headers_for(args, token):
    headers = {}
    if args.extra_headers:
        try:
            headers.update(json.loads(args.extra_headers))
        except Exception as exc:
            raise ValueError(f'--extra-headers must be JSON: {exc}')
    if args.header.lower() == 'cookie':
        cookie_name = args.cookie_name or 'token'
        existing = headers.get('Cookie', '')
        sep = '; ' if existing else ''
        headers['Cookie'] = existing + sep + f'{cookie_name}={token}'
    else:
        value = f'{args.scheme} {token}'.strip() if args.scheme else token
        headers[args.header] = value
    return headers


def _request(args, token):
    method = args.method.upper()
    headers = _headers_for(args, token)
    started = time.time()
    resp = requests.request(
        method,
        args.url,
        headers=headers,
        data=args.data,
        timeout=args.timeout,
        verify=False,
        allow_redirects=True,
    )
    elapsed_ms = int((time.time() - started) * 1000)
    text = resp.text or ''
    return {
        'status': resp.status_code,
        'final_url': resp.url,
        'elapsed_ms': elapsed_ms,
        'length': len(resp.content or b''),
        'content_type': resp.headers.get('content-type', ''),
        'body_preview': text[:args.preview_chars],
    }


def cmd_replay(args):
    variants = build_variants(args.token)
    selected = ['valid', 'alg_none', 'bad_signature', 'expired', 'claim_tamper']
    results = {}
    for name in selected:
        results[name] = _request(args, variants[name])
    valid = results.get('valid', {})
    accepted_bad = []
    for name, result in results.items():
        if name == 'valid':
            continue
        if result.get('status') == valid.get('status') and result.get('status') and int(result['status']) < 400:
            accepted_bad.append(name)
    return {
        'ok': True,
        'url': args.url,
        'method': args.method.upper(),
        'header': args.header,
        'tested_at': datetime.now(timezone.utc).isoformat(),
        'results': results,
        'accepted_bad_variants': accepted_bad,
        'reportable_indicator': bool(accepted_bad),
        'reporting_rule': 'Report only if accepted_bad_variants still returns privileged data or action success.',
    }


def main():
    ap = argparse.ArgumentParser(description='JWT analysis and replay helper for authorized DAST scans')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('analyze')
    p.add_argument('--token', required=True)
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser('variants')
    p.add_argument('--token', required=True)
    p.add_argument('--show-tokens', action='store_true')
    p.set_defaults(func=cmd_variants)

    p = sub.add_parser('replay')
    p.add_argument('--url', required=True)
    p.add_argument('--token', required=True)
    p.add_argument('--method', default='GET')
    p.add_argument('--data')
    p.add_argument('--header', default='Authorization', help='Authorization or Cookie')
    p.add_argument('--scheme', default='Bearer')
    p.add_argument('--cookie-name')
    p.add_argument('--extra-headers', help='JSON object of extra headers')
    p.add_argument('--timeout', type=int, default=15)
    p.add_argument('--preview-chars', type=int, default=600)
    p.set_defaults(func=cmd_replay)

    args = ap.parse_args()
    try:
        print(json.dumps(args.func(args), indent=2, default=str))
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}))
        sys.exit(1)


if __name__ == '__main__':
    main()
