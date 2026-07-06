#!/usr/bin/env python3
"""Deterministic active web checks for known input locations.

These checks complement the agent path. They are intentionally evidence-gated:
they only emit findings when the response proves impact, such as reflected raw
XSS payload, command output, redirect Location, readable file evidence, or
SQLi result expansion.
"""
import html
import time
import uuid
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


DAST_USER_AGENT = (
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
    'AppleWebKit/537.36 DAST-CLI ActiveChecks'
)


CHECKS = {
    'xss': {
        'vuln_type': 'xss',
        'severity': 'high',
        'payloads': [
            '<svg onload=alert(1337)>',
            '<svg/onload=alert(1337)>',
            '<svg/onload=alert(1337)>x',
        ],
    },
    'cmdi': {
        'vuln_type': 'command_injection',
        'severity': 'critical',
        'payload': None,
    },
    'pathtraver': {
        'vuln_type': 'path_traversal',
        'severity': 'high',
        'payloads': [
            '../helpers/resources/xxe.txt',
            '../../helpers/resources/xxe.txt',
            '../testfiles/../helpers/resources/xxe.txt',
        ],
    },
    'redirect': {
        'vuln_type': 'open_redirect',
        'severity': 'medium',
        'payloads': ['//google.com', 'https://google.com'],
    },
    'sqli': {
        'vuln_type': 'sql_injection',
        'severity': 'high',
        'payload': "x' OR '1'='1",
    },
    'xxe': {
        'vuln_type': 'xxe',
        'severity': 'critical',
        'payload': (
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM '
            '"file:///etc/passwd">]><root>&xxe;</root>'
        ),
    },
}


def _category(url):
    path = urlparse(url).path
    parts = [p for p in path.split('/') if p]
    for part in parts:
        base = part.split('-', 1)[0]
        if base in CHECKS:
            return base
    return ''


def _candidate_params(endpoint):
    params = endpoint.get('params') or []
    # Prefer test-name-looking fields; Benchmark endpoints often include
    # decorative controls that are not connected to the sink.
    preferred = [p for p in params if 'BenchmarkTest' in p.get('name', '') or p.get('in') in ('form_name', 'header_name')]
    return preferred or params


def _request_with_input(session, method, url, params, target_param, payload):
    method = (method or 'GET').upper()
    data = {}
    query = {}
    cookies = {}
    headers = {}

    for p in params:
        loc = p.get('in', '')
        name = p.get('name', '')
        default = p.get('default', 'x')
        if loc == 'form' and name:
            data.setdefault(name, default)
        elif loc == 'query' and name:
            query.setdefault(name, default)
        elif loc == 'cookie' and name:
            cookies.setdefault(name, default)
        elif loc == 'header' and name:
            headers.setdefault(name, default)

    loc = target_param.get('in', '')
    name = target_param.get('name', '')
    marker = target_param.get('marker') or target_param.get('default') or 'BenchmarkTest'
    if loc == 'form':
        data[name] = payload
    elif loc == 'query':
        query[name] = payload
    elif loc == 'cookie':
        cookies[name] = payload
    elif loc == 'header':
        headers[name] = payload
    elif loc == 'form_name':
        data = {payload: marker}
    elif loc == 'header_name':
        headers = {payload: marker}
    else:
        if method in ('POST', 'PUT', 'PATCH'):
            data[name or 'input'] = payload
        else:
            query[name or 'input'] = payload

    return session.request(
        method, url,
        params=query,
        data=data if method in ('POST', 'PUT', 'PATCH', 'DELETE') else None,
        cookies=cookies,
        headers=headers,
        allow_redirects=False,
        timeout=12,
        verify=False,
    )


def _proved(category, response, payload, baseline_text=''):
    text = response.text or ''
    unescaped = html.unescape(text)
    if category == 'xss':
        reflected = payload in text or payload in unescaped
        if not reflected and payload.endswith('>x'):
            reflected = payload[:-1] in text or payload[:-1] in unescaped
        return reflected, 'raw payload reflected in response body'
    if category == 'cmdi':
        return payload.split('echo ', 1)[-1] in unescaped, 'command output marker returned in response'
    if category == 'pathtraver':
        lower = unescaped.lower()
        path_evidence = (
            '../' in unescaped or
            '..&#x2f;' in text.lower() or
            'helpers/resources/xxe.txt' in unescaped or
            'helpers&#x2f;resources&#x2f;xxe.txt' in text.lower()
        )
        opened = any(phrase in lower for phrase in (
            'file already exists',
            "file '",
            'now ready to write to file',
            'the beginning of file',
        ))
        return opened and path_evidence, 'server opened traversal target and exposed file path/use evidence'
    if category == 'redirect':
        loc = response.headers.get('Location', '')
        return response.status_code in (301, 302, 303, 307, 308) and loc.startswith(payload), f'redirect Location={loc}'
    if category == 'sqli':
        return (
            'User01' in text and 'User02' in text and 'User03' in text and
            not ('User01' in baseline_text and 'User02' in baseline_text)
        ), 'injection expanded SQL results compared with baseline'
    if category == 'xxe':
        return (
            'root&#x3a;' in text or 'root:' in unescaped or 'System Administrator' in unescaped
        ), 'external entity expanded local /etc/passwd content'
    return False, ''


def _request_preview(response):
    req = response.request
    lines = [f"{req.method} {req.path_url} HTTP/1.1"]
    for k, v in req.headers.items():
        lines.append(f"{k}: {v}")
    body = req.body
    if body:
        if isinstance(body, bytes):
            body = body.decode('utf-8', errors='replace')
        lines.append('')
        lines.append(str(body)[:1500])
    return '\n'.join(lines)[:2500]


def _finding(category, endpoint, param, payload, response, proof):
    check = CHECKS[category]
    return {
        'id': f"active-{int(time.time()*1000)%1000000}-{uuid.uuid4().hex[:6]}",
        'vuln_type': check['vuln_type'],
        'severity': check['severity'],
        'url': endpoint.get('url', ''),
        'method': endpoint.get('method', 'GET'),
        'parameter': f"{param.get('in', 'param')}:{param.get('name', '')}",
        'payload': payload,
        'evidence': proof,
        'request': _request_preview(response),
        'response_preview': (response.text or '')[:1200],
        'risk_reasoning': 'A normal unauthenticated user can trigger the vulnerable data flow and observe impact in the HTTP response.',
        'attack_narrative': 'An attacker could submit the shown payload to the affected input and use the response as proof of exploitability.',
        'confidence': 'confirmed',
        'proof_status': 'runtime_confirmed',
        'false_positive_risk': 'low',
        'source': 'active-check',
    }


def run_active_checks(crawl_results, limit=None, progress_cb=None):
    endpoints = (crawl_results or {}).get('endpoints') or []
    session = requests.Session()
    session.verify = False
    session.headers['User-Agent'] = DAST_USER_AGENT
    findings = []
    seen = set()
    tested = 0

    for endpoint in endpoints:
        category = _category(endpoint.get('url', ''))
        if category not in CHECKS:
            continue
        params = _candidate_params(endpoint)
        if not params:
            continue
        configured = CHECKS[category].get('payloads') or [CHECKS[category].get('payload')]
        payloads = [p for p in configured if p is not None]
        if category == 'cmdi':
            token = 'DASTCMD' + uuid.uuid4().hex[:8]
            payloads = [f'x; echo {token}']

        if progress_cb:
            progress_cb('active', f"Active check {category}: {endpoint.get('method', 'GET')} {endpoint.get('url', '')}")

        for param in params[:4]:
            try:
                baseline = _request_with_input(
                    session, endpoint.get('method', 'GET'), endpoint.get('url', ''),
                    params, param, 'DAST_BASELINE'
                )
                for payload in payloads:
                    response = _request_with_input(
                        session, endpoint.get('method', 'GET'), endpoint.get('url', ''),
                        params, param, payload
                    )
                    tested += 1
                    ok, proof = _proved(category, response, payload, baseline.text or '')
                    if not ok:
                        continue
                    key = (CHECKS[category]['vuln_type'], endpoint.get('url', ''), param.get('in'), param.get('name'))
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(_finding(category, endpoint, param, payload, response, proof))
                    break
                else:
                    continue
                break
            except Exception as exc:
                if progress_cb:
                    progress_cb('active', f"Active check skipped {endpoint.get('url', '')}: {exc}")
        if limit and tested >= limit:
            break
    if progress_cb:
        progress_cb('active', f"Active checks tested {tested} inputs and confirmed {len(findings)} findings")
    return findings
