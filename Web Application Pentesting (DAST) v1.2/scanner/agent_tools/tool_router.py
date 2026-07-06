#!/usr/bin/env python3
"""Generic security test router for the DAST agent.

The router does not prove vulnerabilities by itself. It fingerprints the
supplied request/response and returns the relevant test modules so the agent
does not behave like a one-size-fits-all curl bot.
"""
import argparse
import json
import re
from urllib.parse import parse_qs, urlparse


def _load_json(value, fallback):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _headers_to_dict(value):
    parsed = _load_json(value, {})
    if isinstance(parsed, dict):
        return {str(k).lower(): str(v) for k, v in parsed.items()}
    if isinstance(parsed, list):
        out = {}
        for line in parsed:
            if isinstance(line, str) and ':' in line:
                k, v = line.split(':', 1)
                out[k.strip().lower()] = v.strip()
        return out
    return {}


def _tokens_from_text(text):
    return re.findall(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', text or '')


def _has_any(text, needles):
    text = (text or '').lower()
    return any(n in text for n in needles)


def _query_params(url):
    return sorted(parse_qs(urlparse(url).query, keep_blank_values=True).keys())


def _request_body_params(body, content_type):
    body = body or ''
    ct = (content_type or '').lower()
    if not body:
        return []
    if 'json' in ct:
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                return sorted(str(k) for k in data.keys())
        except Exception:
            return []
    if 'xml' in ct or body.lstrip().startswith('<'):
        return sorted(set(re.findall(r'<([A-Za-z_][A-Za-z0-9_.:-]*)[\\s>]', body)) - {'xml'})
    if '=' in body:
        return sorted(parse_qs(body, keep_blank_values=True).keys())
    return []


def _add_module(modules, name, reason, priority, commands=None, evidence=None):
    if name in modules:
        modules[name]['reasons'].append(reason)
        modules[name]['priority'] = min(modules[name]['priority'], priority)
        return
    modules[name] = {
        'name': name,
        'priority': priority,
        'reasons': [reason],
        'suggested_commands': commands or [],
        'evidence_required': evidence or [],
    }


def classify(args):
    method = (args.method or 'GET').upper()
    url = args.url or ''
    parsed = urlparse(url)
    path = (parsed.path or '').lower()
    query_names = _query_params(url)
    req_headers = _headers_to_dict(args.request_headers)
    resp_headers = _headers_to_dict(args.response_headers)
    content_type = (args.content_type or resp_headers.get('content-type') or req_headers.get('content-type') or '').lower()
    request_body = args.request_body or ''
    response_body = args.response_body or ''
    combined = ' '.join([url, request_body, response_body, json.dumps(req_headers), json.dumps(resp_headers)])
    body_params = _request_body_params(request_body, content_type)
    all_params = sorted(set(query_names + body_params))
    modules = {}

    jwt_tokens = _tokens_from_text(combined)
    if jwt_tokens or _has_any(combined, ['jwt', 'bearer ']):
        _add_module(
            modules,
            'jwt',
            'JWT token/header/cookie signal observed',
            1,
            [
                "python3 scanner/agent_tools/jwt_tool.py analyze --token '<JWT>'",
                "python3 scanner/agent_tools/jwt_tool.py replay --url '<URL>' --token '<JWT>' --header Cookie --cookie-name JWT",
            ],
            [
                'decoded baseline claims and algorithm',
                'valid token vs tampered token response comparison',
                'negative control showing bad signature is rejected or accepted',
                'copy-paste curl for accepted tampered token',
            ],
        )

    if all_params:
        _add_module(
            modules,
            'input_injection',
            f'Input parameters found: {", ".join(all_params[:12])}',
            2,
            [
                "python3 scanner/dast_tool.py send_request --url '<URL>' --method '<METHOD>' --param '<PARAM>' --payload \"'\"",
                "dalfox url '<URL>' --only-poc r --skip-bav --silence",
                "sqlmap -u '<URL>' --batch --level=1 --risk=1",
            ],
            [
                'baseline response hash/length',
                'payload response hash/length/status',
                'clear SQL error, timing delta, reflection, or command/file output',
                'negative control with benign value',
            ],
        )

    if _has_any(combined, ['<html', '<form', 'text/html']) or 'html' in content_type:
        _add_module(
            modules,
            'xss_clickjacking_headers',
            'HTML/page response observed',
            3,
            [
                "python3 scanner/agent_tools/clickjacking_tool.py check --url '<URL>' --make-poc",
                "nuclei -u '<URL>' -tags xss,csp,headers -severity low,medium,high -silent",
            ],
            [
                'reflected payload shown unescaped in response or browser sink',
                'frameable sensitive page PoC for clickjacking',
                'response headers proving missing/weak policy',
            ],
        )

    if 'json' in content_type or path.startswith('/api') or '/api/' in path or response_body.lstrip().startswith(('{', '[')):
        _add_module(
            modules,
            'api_auth_logic',
            'JSON/API-like endpoint observed',
            2,
            [
                "python3 scanner/dast_tool.py send_request --url '<URL>' --method '<METHOD>'",
                "nuclei -u '<URL>' -tags exposure,token,misconfig -silent",
            ],
            [
                'unauthenticated replay result',
                'role/object-id comparison where applicable',
                'schema/content-type/error behavior',
            ],
        )

    id_like = [p for p in all_params if p.lower() in ('id', 'user', 'userid', 'user_id', 'account', 'accountid', 'tenant', 'tenantid', 'order', 'orderid')]
    if id_like or re.search(r'/(users?|accounts?|orders?|tenants?)/\\d+', path):
        _add_module(
            modules,
            'idor_bola',
            'Object identifier or tenant/user/account signal observed',
            1,
            [],
            [
                'two-user or no-auth comparison',
                'object ID changed and unauthorized data/action observed',
                'proof this is not same-role expected access',
            ],
        )

    if _has_any(' '.join(all_params) + ' ' + path + ' ' + request_body, ['url', 'uri', 'redirect', 'next', 'callback', 'image', 'src', 'dest', 'feed', 'proxy']):
        _add_module(
            modules,
            'ssrf_open_redirect',
            'URL-like parameter or redirect/fetch signal observed',
            1,
            [
                "python3 scanner/dast_tool.py generate_callback",
                "python3 scanner/dast_tool.py send_request --url '<URL>' --method '<METHOD>' --param '<PARAM>' --payload '<CALLBACK_URL>'",
            ],
            [
                'callback hit, internal metadata response, or redirect Location to attacker host',
                'negative control with normal URL',
            ],
        )

    if 'xml' in content_type or request_body.lstrip().startswith('<?xml') or '<!doctype' in request_body.lower() or 'xxe' in path:
        _add_module(
            modules,
            'xxe',
            'XML parser or XXE route signal observed',
            1,
            [
                "python3 scanner/dast_tool.py generate_callback",
                "python3 scanner/dast_tool.py send_request --url '<URL>' --method POST --data '<XML_PAYLOAD>' --headers '{\"Content-Type\":\"application/xml\"}'",
            ],
            [
                'file content disclosure or OOB callback',
                'safe XML baseline accepted first',
                'DOCTYPE/entity payload rejected/accepted comparison',
            ],
        )

    if _has_any(combined, ['multipart/form-data', 'type="file"', 'upload', 'filename=']):
        _add_module(
            modules,
            'file_upload',
            'File upload signal observed',
            2,
            [
                "nuclei -u '<URL>' -tags upload,file -silent",
            ],
            [
                'dangerous extension accepted',
                'uploaded file retrievable/executable',
                'content-type and path validation bypass proof',
            ],
        )

    if _has_any(' '.join(all_params) + ' ' + path, ['file', 'path', 'template', 'page', 'include', 'download']):
        _add_module(
            modules,
            'lfi_path_traversal',
            'File/path/include/download parameter signal observed',
            2,
            [],
            [
                'known local file content visible',
                'encoded traversal variant comparison',
                'negative control showing normal file behavior',
            ],
        )

    _add_module(
        modules,
        'baseline_headers_cookies',
        'Always applicable passive baseline checks',
        5,
        [
            "python3 scanner/dast_tool.py get_baseline --url '<URL>' --method '<METHOD>'",
        ],
        [
            'cookie flags, cache headers, CSP/XFO/HSTS where relevant',
            'only report missing headers with correct severity and context',
        ],
    )

    ordered = sorted(modules.values(), key=lambda m: (m['priority'], m['name']))
    return {
        'ok': True,
        'url': url,
        'method': method,
        'fingerprint': {
            'path': parsed.path,
            'content_type': content_type,
            'query_params': query_names,
            'body_params': body_params,
            'jwt_token_count': len(jwt_tokens),
            'request_body_shape': 'xml' if request_body.lstrip().startswith('<') else ('json' if request_body.lstrip().startswith(('{', '[')) else ('form' if '=' in request_body else 'empty')),
        },
        'modules': ordered,
        'rule': 'Use the highest-priority relevant modules first. Do not report until module evidence_required is satisfied.',
    }


def main():
    parser = argparse.ArgumentParser(description='Route an endpoint to relevant DAST test modules')
    parser.add_argument('classify', nargs='?', default='classify')
    parser.add_argument('--url', required=True)
    parser.add_argument('--method', default='GET')
    parser.add_argument('--request-headers', default='')
    parser.add_argument('--request-body', default='')
    parser.add_argument('--response-headers', default='')
    parser.add_argument('--response-body', default='')
    parser.add_argument('--content-type', default='')
    args = parser.parse_args()
    if args.classify != 'classify':
        raise SystemExit('only classify is supported')
    print(json.dumps(classify(args), indent=2))


if __name__ == '__main__':
    main()
