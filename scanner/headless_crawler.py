#!/usr/bin/env python3
"""
Headless crawler using Playwright to discover JS-rendered routes/forms.
Implements comprehensive URL discovery: JS parsing, XHR interception, DOM monitoring,
event triggering, and SPA router extraction.
For authorized security testing only.
"""

import os
import re
import sys
import time
import json
import base64
import warnings
import urllib3
import threading
import socket
import shutil
import subprocess
import tempfile
from typing import Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

# Suppress SSL/TLS warnings for testing environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# In-memory scan log bounds (tail retained; aligned with app post-scan trim).
_SCAN_LOG_MAX_ENTRIES = 6000
_SCAN_LOG_DATA_STR_CAP = 4096


def _cap_scan_log_data(data):
    """Shrink huge string values in log payloads so one entry cannot dominate RAM."""
    if not isinstance(data, dict):
        return {}
    out = {}
    for k, v in data.items():
        if isinstance(v, str) and len(v) > _SCAN_LOG_DATA_STR_CAP:
            out[k] = v[:_SCAN_LOG_DATA_STR_CAP] + f"... ({len(v)} chars)"
        else:
            out[k] = v
    return out


# =============================================================================
# MITMPROXY SUBPROCESS — Network-level HTTP/HTTPS proxy for full traffic capture
# Runs mitmdump as an external process to avoid corrupting Flask's logging.
# Addon script writes JSONL to a temp file; a reader thread tails that file
# and appends entries to the crawler's _proxy_logs list.
# =============================================================================

# Addon script template — written to a temp .py file and passed to mitmdump -s
_MITM_ADDON_SCRIPT = r'''
import json, time, os, sys
from mitmproxy import http

LOG_FILE = "__LOGFILE__"

def _guess_type(flow):
    ct = (flow.response.headers.get("content-type", "") if flow.response else "").lower()
    if "html" in ct: return "document"
    if "javascript" in ct or "ecmascript" in ct: return "script"
    if "json" in ct: return "xhr"
    if "xml" in ct: return "xhr"
    if "css" in ct: return "stylesheet"
    if ct.startswith("image/"): return "image"
    if ct.startswith("font/") or "woff" in ct: return "font"
    rh = flow.request.headers
    if rh.get("x-requested-with", "").lower() == "xmlhttprequest": return "xhr"
    if rh.get("accept", "").startswith("application/json"): return "xhr"
    return "other"

def _raw_request(req):
    hdr = "\n".join(f"{k}: {v}" for k, v in req.headers.items())
    body = ""
    try:
        body = req.get_text(strict=False) or ""
    except Exception:
        pass
    raw = f"{req.method} {req.path} HTTP/1.1\n{hdr}"
    if body:
        raw += f"\n\n{body}"
    return raw

def response(flow: http.HTTPFlow):
    try:
        url = flow.request.pretty_url
        req_body = ""
        try:
            req_body = flow.request.get_text(strict=False) or ""
        except Exception:
            try:
                req_body = flow.request.content.decode("utf-8", errors="replace") if flow.request.content else ""
            except Exception:
                pass
        resp_body = ""
        try:
            resp_body = flow.response.get_text(strict=False) or ""
        except Exception:
            try:
                resp_body = flow.response.content.decode("utf-8", errors="replace") if flow.response.content else ""
            except Exception:
                pass
        entry = {
            "url": url,
            "method": flow.request.method,
            "type": _guess_type(flow),
            "request_headers": dict(flow.request.headers),
            "request_body": req_body[:8000],
            "raw_request": _raw_request(flow.request),
            "status": flow.response.status_code if flow.response else 0,
            "response_headers": dict(flow.response.headers) if flow.response else {},
            "response_body": resp_body[:12000],
            "timestamp": time.time()
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
'''


def _find_free_port(start=8081, end=8099):
    """Find a free port in range for mitmproxy."""
    for port in range(start, end):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                return port
        except OSError:
            continue
    return start  # fallback


def _mitm_log_reader(log_file, proxy_logs, stop_event, allowed_url_fn=None, scan_logger=None):
    """Background thread that tails the JSONL file produced by the mitmdump addon.
    Only appends entries for URLs that pass allowed_url_fn — stay in target domain/subdomain, never leave.
    If scan_logger is provided (HeadlessCrawler instance), also logs HTTP requests to scan_logs."""
    pos = 0
    while not stop_event.is_set():
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    f.seek(pos)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            # Stay in domain: only log requests to target host (and subdomains if allowed)
                            if allowed_url_fn and not allowed_url_fn(entry.get('url', '')):
                                continue
                            # Add unique id
                            entry['id'] = f"{int(time.time() * 1000)}_{len(proxy_logs)}"
                            proxy_logs.append(entry)
                            
                            # Also log to scan_logs in Flask/Werkzeug format for UI visibility
                            if scan_logger and hasattr(scan_logger, '_log_scan'):
                                from urllib.parse import urlparse
                                parsed = urlparse(entry.get('url', ''))
                                method = entry.get('method', 'GET')
                                path = parsed.path or '/'
                                if parsed.query:
                                    path += '?' + parsed.query
                                status = entry.get('status', 0)
                                # Format like Flask/Werkzeug logs: "127.0.0.1 - - [timestamp] "METHOD /path HTTP/1.1" STATUS -"
                                timestamp = time.strftime('%d/%b/%Y %H:%M:%S', time.localtime(entry.get('timestamp', time.time())))
                                log_msg = f'127.0.0.1 - - [{timestamp}] "{method} {path} HTTP/1.1" {status} -'
                                scan_logger._log_scan('response', log_msg, {
                                    'method': method,
                                    'url': entry.get('url', ''),
                                    'status': status,
                                    'proxy_id': entry['id']
                                })
                        except json.JSONDecodeError:
                            pass
                    pos = f.tell()
        except Exception:
            pass
        stop_event.wait(0.5)  # Poll every 500ms

# =============================================================================
# Crawler LLM hooks — disabled (DAST scanning uses Claude Code CLI only)
# =============================================================================

class AIConfig:
    """Singleton placeholder; no HTTP LLM API keys are used in this product."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.api_key = None
        self.provider = None
        self.model = None
        self.available = False
        self._model_cache = {}

    def call(self, prompt, max_tokens=4000):
        """Disabled — scanning LLM runs via Claude Code CLI, not HTTP APIs."""
        return None

# Global AI instance - initialized once at module load
AI = AIConfig()

# Legacy compatibility functions
def get_working_ai_config():
    """Legacy function - returns (api_key, provider, message)"""
    return None, None, "Use Claude Code CLI for AI (no crawler HTTP API keys)"

# Cache for available models per provider
_model_cache = {}

def fetch_available_models(api_key, provider):
    """
    Fetch available models from API provider.
    Returns list of model IDs or None on failure.
    """
    try:
        import requests

        if provider.lower() == 'anthropic':
            resp = requests.get(
                'https://api.anthropic.com/v1/models',
                headers={
                    'x-api-key': api_key,
                    'anthropic-version': '2023-06-01'
                },
                timeout=10
            )
            if resp.status_code == 200:
                models = [m.get('id') for m in resp.json().get('data', [])]
                return models

        elif provider.lower() == 'openai':
            resp = requests.get(
                'https://api.openai.com/v1/models',
                headers={'Authorization': f'Bearer {api_key}'},
                timeout=10
            )
            if resp.status_code == 200:
                models = [m.get('id') for m in resp.json().get('data', [])]
                return models

        elif provider.lower() == 'deepseek':
            # DeepSeek doesn't have a models endpoint, use known models
            return ['deepseek-chat', 'deepseek-coder']

    except Exception as e:
        print(f"[AI] Failed to fetch models for {provider}: {e}")

    return None

def get_best_model(api_key, provider):
    """
    Get the best available model for a provider by fetching from API.
    Caches results to avoid repeated API calls.
    """
    global _model_cache

    cache_key = f"{provider}:{api_key[:10] if api_key else 'none'}"

    # Check cache first
    if cache_key in _model_cache:
        return _model_cache[cache_key]

    # Fetch available models
    models = fetch_available_models(api_key, provider) if api_key else None

    if models:
        # Prefer certain models based on provider
        if provider.lower() == 'anthropic':
            # Prefer sonnet models (good balance of speed/quality)
            for preferred in ['claude-sonnet-4-20250514', 'claude-sonnet-4-5-20250929', 'claude-3-5-sonnet']:
                for m in models:
                    if preferred in m:
                        _model_cache[cache_key] = m
                        print(f"[AI] Selected model for {provider}: {m}")
                        return m
            # Fall back to first available
            if models:
                _model_cache[cache_key] = models[0]
                print(f"[AI] Using first available model for {provider}: {models[0]}")
                return models[0]

        elif provider.lower() == 'openai':
            for preferred in ['gpt-4o', 'gpt-4-turbo', 'gpt-4', 'gpt-3.5-turbo']:
                if preferred in models:
                    _model_cache[cache_key] = preferred
                    return preferred
            if models:
                _model_cache[cache_key] = models[0]
                return models[0]

    # Fallback to defaults if API fetch failed
    fallback = get_default_model(provider)
    _model_cache[cache_key] = fallback
    return fallback

def get_default_model(provider):
    """Get fallback default model name for a provider (used when API fetch fails)"""
    defaults = {
        'anthropic': 'claude-sonnet-4-20250514',
        'deepseek': 'deepseek-chat',
        'openai': 'gpt-4o',
        'gemini': 'gemini-1.5-pro',
        'groq': 'llama-3.1-70b-versatile'
    }
    return defaults.get(provider, 'deepseek-chat')

def validate_ai_api_key(api_key, provider='deepseek'):
    """HTTP LLM API keys are not used; scanning relies on Claude Code CLI."""
    return False, "Not applicable — use Claude Code CLI (no ANTHROPIC/OPENAI keys in app)"


# =============================================================================
# DAST SCANNER - PAYLOAD DATABASE
# =============================================================================
# QUICK_SCAN_PAYLOADS: 2-3 payloads per type for fast scanning
# SCAN_PAYLOADS: 10 payloads per type for thorough scanning

QUICK_SCAN_PAYLOADS = {
    'sqli': [
        {"payload": "'", "type": "error_based", "desc": "Single quote"},
        {"payload": "' OR '1'='1'--", "type": "boolean_based", "desc": "OR true with comment"},
    ],
    'xss': [
        {"payload": "<script>alert('XSS')</script>", "type": "reflection", "desc": "Basic script tag"},
        {"payload": "<img src=x onerror=alert('XSS')>", "type": "reflection", "desc": "IMG onerror"},
    ],
    'cmdi': [
        {"payload": "; id", "type": "output_based", "desc": "Semicolon id"},
        {"payload": "| cat /etc/passwd", "type": "output_based", "desc": "Pipe passwd"},
    ],
    'path_traversal': [
        {"payload": "../../../etc/passwd", "type": "output_based", "desc": "Basic traversal"},
        {"payload": "..%2f..%2f..%2fetc%2fpasswd", "type": "output_based", "desc": "URL encoded"},
    ],
    'ssti': [
        {"payload": "{{7*7}}", "type": "output_based", "expect": "49", "desc": "Jinja2/Twig multiplication"},
        {"payload": "${7*7}", "type": "output_based", "expect": "49", "desc": "Freemarker/Velocity"},
    ],
    'ldap': [
        {"payload": "*", "type": "output_based", "desc": "Wildcard"},
        {"payload": "*)(&", "type": "error_based", "desc": "Filter break"},
    ],
    'xpathi': [
        {"payload": "' or '1'='1", "type": "boolean_based", "desc": "XPath OR true"},
        {"payload": "'] | //* | //*['", "type": "output_based", "desc": "XPath union"},
    ],
}

SCAN_PAYLOADS = {
    'sqli': [
        # Error-based
        {"payload": "'", "type": "error_based", "desc": "Single quote"},
        {"payload": "\"", "type": "error_based", "desc": "Double quote"},
        {"payload": "' OR '1'='1", "type": "boolean_based", "desc": "OR true condition"},
        {"payload": "' OR '1'='1'--", "type": "boolean_based", "desc": "OR true with comment"},
        {"payload": "1' OR '1'='1' #", "type": "boolean_based", "desc": "MySQL comment"},
        {"payload": "1 OR 1=1", "type": "boolean_based", "desc": "Numeric OR"},
        {"payload": "' UNION SELECT NULL--", "type": "union_based", "desc": "Union probe"},
        {"payload": "1' AND SLEEP(5)--", "type": "time_based", "delay": 5, "desc": "MySQL sleep"},
        {"payload": "1'; WAITFOR DELAY '0:0:5'--", "type": "time_based", "delay": 5, "desc": "MSSQL waitfor"},
        {"payload": "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "type": "time_based", "delay": 5, "desc": "MySQL subquery sleep"},
    ],
    'xss': [
        {"payload": "<script>alert('XSS')</script>", "type": "reflection", "desc": "Basic script tag"},
        {"payload": "<img src=x onerror=alert('XSS')>", "type": "reflection", "desc": "IMG onerror"},
        {"payload": "<svg onload=alert('XSS')>", "type": "reflection", "desc": "SVG onload"},
        {"payload": "<body onload=alert('XSS')>", "type": "reflection", "desc": "Body onload"},
        {"payload": "javascript:alert('XSS')", "type": "reflection", "desc": "JavaScript protocol"},
        {"payload": "'\"><script>alert('XSS')</script>", "type": "reflection", "desc": "Quote break"},
        {"payload": "<iframe src=\"javascript:alert('XSS')\">", "type": "reflection", "desc": "Iframe"},
        {"payload": "<input onfocus=alert('XSS') autofocus>", "type": "reflection", "desc": "Input autofocus"},
        {"payload": "'-alert('XSS')-'", "type": "reflection", "desc": "Template literal"},
        {"payload": "${alert('XSS')}", "type": "reflection", "desc": "Template expression"},
    ],
    'cmdi': [
        {"payload": "; id", "type": "output_based", "desc": "Semicolon id"},
        {"payload": "| id", "type": "output_based", "desc": "Pipe id"},
        {"payload": "& id", "type": "output_based", "desc": "Ampersand id"},
        {"payload": "`id`", "type": "output_based", "desc": "Backtick id"},
        {"payload": "$(id)", "type": "output_based", "desc": "Command substitution"},
        {"payload": "; cat /etc/passwd", "type": "output_based", "desc": "Read passwd"},
        {"payload": "| cat /etc/passwd", "type": "output_based", "desc": "Pipe passwd"},
        {"payload": "; sleep 5", "type": "time_based", "delay": 5, "desc": "Sleep command"},
        {"payload": "| sleep 5", "type": "time_based", "delay": 5, "desc": "Pipe sleep"},
        {"payload": "& ping -c 5 127.0.0.1", "type": "time_based", "delay": 5, "desc": "Ping delay"},
    ],
    'path_traversal': [
        {"payload": "../../../etc/passwd", "type": "output_based", "desc": "Basic traversal"},
        {"payload": "....//....//....//etc/passwd", "type": "output_based", "desc": "Double dot bypass"},
        {"payload": "..%2f..%2f..%2fetc%2fpasswd", "type": "output_based", "desc": "URL encoded"},
        {"payload": "..%252f..%252f..%252fetc%252fpasswd", "type": "output_based", "desc": "Double encoded"},
        {"payload": "/etc/passwd", "type": "output_based", "desc": "Absolute path"},
        {"payload": "....\\....\\....\\windows\\win.ini", "type": "output_based", "desc": "Windows backslash"},
        {"payload": "..\\..\\..\\windows\\win.ini", "type": "output_based", "desc": "Windows traversal"},
        {"payload": "../../../etc/passwd%00", "type": "output_based", "desc": "Null byte"},
        {"payload": "..%c0%af..%c0%af..%c0%afetc/passwd", "type": "output_based", "desc": "UTF-8 encoding"},
        {"payload": "....//....//....//etc/shadow", "type": "output_based", "desc": "Shadow file"},
    ],
    'ssti': [
        {"payload": "{{7*7}}", "type": "output_based", "expect": "49", "desc": "Jinja2/Twig multiplication"},
        {"payload": "${7*7}", "type": "output_based", "expect": "49", "desc": "Freemarker/Velocity"},
        {"payload": "<%= 7*7 %>", "type": "output_based", "expect": "49", "desc": "ERB"},
        {"payload": "#{7*7}", "type": "output_based", "expect": "49", "desc": "Ruby interpolation"},
        {"payload": "{{config}}", "type": "output_based", "desc": "Jinja2 config"},
        {"payload": "{{self}}", "type": "output_based", "desc": "Jinja2 self"},
        {"payload": "${class.getClassLoader()}", "type": "output_based", "desc": "Java classloader"},
        {"payload": "{{request.application.__globals__}}", "type": "output_based", "desc": "Flask globals"},
        {"payload": "#set($x=7*7)${x}", "type": "output_based", "expect": "49", "desc": "Velocity set"},
        {"payload": "{{constructor.constructor('return 7*7')()}}", "type": "output_based", "expect": "49", "desc": "Sandbox escape"},
    ],
    'ldap': [
        {"payload": "*", "type": "output_based", "desc": "Wildcard"},
        {"payload": "*)(&", "type": "error_based", "desc": "Filter break"},
        {"payload": "*)(uid=*))(|(uid=*", "type": "output_based", "desc": "OR injection"},
        {"payload": "admin)(&)", "type": "error_based", "desc": "Admin bypass"},
        {"payload": "x])(|(objectclass=*)", "type": "output_based", "desc": "Object class enum"},
        {"payload": "*)(|(password=*))", "type": "output_based", "desc": "Password field"},
        {"payload": "admin)(!(&(1=0", "type": "boolean_based", "desc": "Boolean true"},
        {"payload": "admin)(|(1=0", "type": "boolean_based", "desc": "Boolean false"},
        {"payload": "*)((", "type": "error_based", "desc": "Syntax error"},
        {"payload": "*))%00", "type": "output_based", "desc": "Null byte"},
    ],
    'xpathi': [
        {"payload": "' or '1'='1", "type": "boolean_based", "desc": "XPath OR true"},
        {"payload": "' or ''='", "type": "boolean_based", "desc": "XPath empty string"},
        {"payload": "') or ('1'='1", "type": "boolean_based", "desc": "XPath paren break"},
        {"payload": "1 or 1=1", "type": "boolean_based", "desc": "XPath numeric OR"},
        {"payload": "admin' or '1'='1", "type": "boolean_based", "desc": "XPath admin bypass"},
        {"payload": "'] | //* | //*['", "type": "output_based", "desc": "XPath union"},
        {"payload": "' and count(/*)>0 or '1'='1", "type": "boolean_based", "desc": "XPath count"},
        {"payload": "x]|//*|//*[x", "type": "error_based", "desc": "XPath syntax break"},
        {"payload": "' or substring(name(/*[1]),1,1)='a' or '1'='1", "type": "boolean_based", "desc": "XPath substring"},
        {"payload": "x']|//node()|/foo['x", "type": "output_based", "desc": "XPath node enum"},
    ],
}

DETECTION_PATTERNS = {
    'sqli': {
        'error_patterns': [
            # MySQL
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySqlException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB)",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            # MS SQL Server
            r"Syntax error.*in query expression",
            r"Driver.*SQL[\-\_\ ]*Server",
            r"OLE DB.*SQL Server",
            r"\[SQL Server\]",
            r"SQLServer JDBC Driver",
            r"com\.microsoft\.sqlserver",
            r"MSSQL",
            # DB2
            r"CLI Driver.*DB2",
            r"DB2 SQL error",
            # PostgreSQL
            r"PG::SyntaxError:",
            r"PSQLException",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"PostgreSQL.*ERROR",
            # Oracle
            r"Oracle error",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle.*Driver",
            r"java\.sql\.SQLException.*Oracle",
            # SQLite
            r"SQLiteException",
            r"SQLITE_ERROR",
            r"sqlite3\.OperationalError:",
            r"System\.Data\.SQLite\.SQLiteException",
            # HSQLDB (used by OWASP Benchmark)
            r"HSQLDB",
            r"org\.hsqldb",
            r"unexpected token",
            r"unexpected end of statement",
            r"CallableStatement",
            r"PreparedStatement",
            # Generic SQL
            r"near \".+?\": syntax error",
            r"quoted string not properly terminated",
            r"unclosed quotation mark",
            r"You have an error in your SQL syntax",
            r"java\.sql\.SQLException",
            r"java\.sql\.SQLSyntaxErrorException",
            # r"JDBC.*exception",  # Too generic
            # r"SQL.*exception",   # Too generic
            # r"sql.*error",       # Too generic
            r"SQL command not properly ended",
            r"Unexpected token.*SQL",
            r"unterminated.*string",
            r"missing.*expression",
            # r"database error",   # Too generic
            # r"error in your SQL", # Too generic
            # r"unhandled exception", # Too generic
            r"division by zero",
        ],
    },
    'xss': {
        'reflection_check': True,  # Check if payload appears in response
    },
    'cmdi': {
        'output_patterns': [
            r"uid=\d+.*gid=\d+",
            r"root:.*:0:0:",
            r"/bin/bash",
            r"/bin/sh",
            r"www-data",
            r"daemon:.*:1:1:",
            r"\[fonts\]",  # Windows win.ini
            r"\[extensions\]",  # Windows win.ini
            r"PING.*bytes",  # ping output
            r"TTL=\d+",  # ping TTL
            r"icmp_seq=\d+",  # ping sequence
            r"total\s+\d+",  # ls output
            r"drwx",  # ls directory
            r"-rw-",  # ls file
        ],
        'error_patterns': [
            r"java\.lang\.Runtime",
            r"java\.lang\.ProcessBuilder",
            r"java\.io\.IOException.*Process",
            r"Cannot run program",
            r"CreateProcess error",
            r"No such file or directory",
            r"command not found",
        ],
    },
    'path_traversal': {
        'output_patterns': [
            r"root:.*:0:0:",
            r"daemon:.*:1:1:",
            r"bin:.*:2:2:",
            r"/bin/bash",
            r"/bin/sh",
            r"/usr/sbin/nologin",
            r"\[fonts\]",
            r"\[extensions\]",
            r"\[mci extensions\]",
            r"for 16-bit app support",
            r"Access to file:",
            # File read success indicators
            r"The beginning of file:",
            r"File contents:",
            r"nobody:.*:65534:",
            r"ftp:.*:14:",
            # File write indicators
            r"ready to write",
            r"written to file",
            r"file created",
            r"FileOutputStream",
            r"FileWriter",
            # Path traversal in response (payload reflected in file path)
            r"\.\./\.\./",
            r"\.\.\\\.\.\\",
        ],
        'error_patterns': [
            r"java\.io\.FileNotFoundException",
            r"java\.io\.IOException.*file",
            r"java\.nio\.file",
            r"No such file",
            r"Access denied",
            r"Permission denied",
            r"FileInputStream",
            r"FileReader",
            r"FileOutputStream",
            r"FileWriter",
            r"RandomAccessFile",
            r"java\.io\.File",
            r"getCanonicalPath",
        ],
    },
    'ssti': {
        'output_patterns': [
            r"49",  # 7*7 result
            r"SECRET_KEY",
            r"DEBUG",
            r"<Config",
            r"__globals__",
            r"__class__",
            r"java\.lang\.Class",
        ],
    },
    'ldap': {
        'error_patterns': [
            r"LDAP.*error",
            r"Invalid DN syntax",
            r"Filter Error",
            r"Bad search filter",
            r"ldap_search",
            r"supplied argument is not a valid ldap",
            r"javax\.naming\.NamingException",
            r"javax\.naming\.directory",
            r"InvalidNameException",
            r"javax\.naming\.ldap",
            r"LdapContext",
            r"DirContext",
            r"SearchControls",
            r"invalid.*filter",
            r"LDAP.*filter",
            r"malformed.*filter",
            r"Unbalanced",
        ],
    },
    'xpathi': {
        'error_patterns': [
            r"XPath.*error",
            r"XPath.*syntax",
            r"XPathException",
            r"XPathExpressionException",
            r"XPathSyntaxException",
            r"Invalid XPath",
            r"javax\.xml\.xpath",
            r"net\.sf\.saxon",
            r"org\.jaxen",
            r"TransformerException",
            r"SAXPathException",
            r"XPath evaluation",
            r"XPath expression",
            r"A location path was expected",
            r"Extra illegal tokens",
            r"Unknown nodetype",
        ],
    },
}

SEVERITY_MAP = {
    'sqli': 'Critical',
    'xss': 'High',
    'cmdi': 'Critical',
    'path_traversal': 'High',
    'ssti': 'High',
    'ldap': 'High',
    'xpathi': 'High',
}

CWE_MAP = {
    'sqli': 'CWE-89',
    'xss': 'CWE-79',
    'cmdi': 'CWE-78',
    'path_traversal': 'CWE-22',
    'ssti': 'CWE-1336',
    'ldap': 'CWE-90',
    'xpathi': 'CWE-643',
}

OWASP_MAP = {
    'sqli': 'A03:2021-Injection',
    'xss': 'A03:2021-Injection',
    'cmdi': 'A03:2021-Injection',
    'path_traversal': 'A01:2021-Broken Access Control',
    'ssti': 'A03:2021-Injection',
    'ldap': 'A03:2021-Injection',
    'xpathi': 'A03:2021-Injection',
}


class HeadlessCrawler:
    def __init__(self, target_url, max_depth=3, max_pages=1000, timeout=15000, show_browser=False,
                 manual_mode=False, manual_only=False, login_url=None, username=None, password=None, allow_subdomains=False, passive_only=True,
                 ai_api_key=None, ai_provider='anthropic', ai_model=None, enable_scanning=True, scan_on_the_fly=False, quick_scan=True, page_scan_mode=True, ask_for_help=False,
                 auth_type='form', mfa_secret=None, oauth_client_id=None, oauth_client_secret=None,
                 api_key_header=None, api_key_value=None,
                 enable_gobuster=False, gobuster_wordlist=None,
                 seed_urls_file=None, crawl_delay=0):
        self.target_url = target_url
        self.seed_urls_file = seed_urls_file  # File with seed URLs (e.g. gau output)
        self.crawl_delay = crawl_delay  # Delay in seconds between page visits (rate limiting)
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.show_browser = show_browser
        self.manual_mode = manual_mode
        self.manual_only = manual_only
        # Single-round crawl: visit each URL once and extract attack vectors from that page
        # without additional click-through / auto-submits that cause "second cycles".
        #
        # Default is OFF now because deep interaction is required to observe POST/PUT traffic
        # (form submits, XHR actions) and to build a useful attack surface.
        self.single_round = os.getenv("HEADLESS_SINGLE_ROUND", "0") != "0"
        # Skip non-HTML assets (pdf/images/archives/etc). These often open in the same tab
        # and can appear "stuck" (e.g., Chromium PDF viewer) while yielding no attack vectors.
        self.skip_asset_urls = os.getenv("HEADLESS_SKIP_ASSETS", "1") != "0"
        self._asset_exts = {
            ".pdf",
            ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2",
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
            ".mp4", ".mov", ".avi", ".mkv", ".mp3", ".wav",
            ".woff", ".woff2", ".ttf", ".otf", ".eot",
        }

        self.click_through = os.getenv("HEADLESS_CLICK_THROUGH", "1") != "0"
        self.submit_forms = os.getenv("HEADLESS_SUBMIT_FORMS", "1") != "0"
        if self.single_round:
            self.click_through = False
            self.submit_forms = False

        # Guardrails for "deep interaction" to prevent the crawler from looping forever or
        # getting stuck in non-HTML viewers (PDF) after a click/submit.
        try:
            self._interaction_budget_total = int(os.getenv("HEADLESS_INTERACTION_BUDGET", "60") or "60")
        except Exception:
            self._interaction_budget_total = 60
        try:
            self._interaction_budget_per_page = int(os.getenv("HEADLESS_INTERACTION_PER_PAGE", "10") or "10")
        except Exception:
            self._interaction_budget_per_page = 10
        self._interaction_budget_total = max(0, min(self._interaction_budget_total, 500))
        self._interaction_budget_per_page = max(0, min(self._interaction_budget_per_page, 50))
        self._interaction_total_used = 0
        self._interaction_used_by_page = {}
        # Normalize login_url hostname to match target_url to avoid cookie domain mismatch
        # (e.g. login on 127.0.0.1 but crawl on localhost → cookies won't carry over)
        if login_url and target_url:
            try:
                from urllib.parse import urlunparse as _urlunparse
                t_parsed = urlparse(target_url)
                l_parsed = urlparse(login_url)
                if t_parsed.hostname != l_parsed.hostname:
                    login_url = _urlunparse(l_parsed._replace(netloc=t_parsed.netloc))
                    print(f"[*] Normalized login URL hostname to match target: {login_url}")
            except Exception:
                pass
        self.login_url = login_url
        self.username = username
        self.password = password
        # Advanced auth
        self.auth_type = auth_type or 'form'
        self.mfa_secret = mfa_secret
        self.oauth_client_id = oauth_client_id
        self.oauth_client_secret = oauth_client_secret
        self.api_key_header = api_key_header
        self.api_key_value = api_key_value
        self._custom_auth_headers = {}
        self.allow_subdomains = allow_subdomains
        self.passive_only = passive_only
        
        # Security: If passive_only is True, force disable scanning regardless of other flags
        if self.passive_only:
             enable_scanning = False
        
        self.root_domain = self._get_root_domain(urlparse(self.target_url).netloc)
        self.visited = set()
        self.endpoints = []
        self._seen_endpoint_urls = set()   # dedup guard for endpoints
        self.forms = []
        self._seen_form_keys = set()       # dedup guard for forms
        self.input_points = []
        self._seen_input_keys = set()      # dedup guard for input_points
        self.parameters = {}
        self.hidden_fields = []
        self.file_uploads = []
        self.cookies = []
        self._logged_in = False
        self._login_attempts = 0
        # Fail-fast: repeated login attempts often cause loops/stalls on pages where
        # Playwright's networkidle never settles (analytics/chat/long-polling).
        try:
            self._max_login_attempts = int(os.getenv("HEADLESS_MAX_LOGIN_ATTEMPTS", "1") or "1")
        except Exception:
            self._max_login_attempts = 1
        self._max_login_attempts = max(1, min(self._max_login_attempts, 3))
        self._login_attempted_once = False
        self._login_permanently_failed = False
        # Advanced URL discovery
        self._js_urls = set()  # URLs from JavaScript files
        self._xhr_urls = set()  # URLs from XHR/Fetch requests
        self._api_endpoints = []  # Discovered API endpoints
        self._submitted_forms = set()
        self._submit_count = 0
        self._submitted_action_counts = {}  # per-URL POST cap: {action_url: count}
        # AI integration - only use if explicitly provided (disabled by default for speed)
        self.ai_api_key = ai_api_key  # Don't default to API key - too slow
        self.ai_provider = ai_provider
        self.ai_model = ai_model or self._get_default_model(ai_provider)
        self._ai_app_profile = None
        self._ai_skip_patterns = set()
        self._queued_urls = set()  # Track URLs already in queue to prevent duplicates
        # Stuck detection
        self._stuck_threshold = 30  # seconds without progress
        self._last_progress_time = time.time()
        self._last_visited_count = 0
        self._stuck_recovery_attempts = 0
        self._max_stuck_recoveries = 3
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.paused = False
        self._proxy_logs = []
        self._proxy_log_map = {}
        self._proxy_log_map_cdp = {}
        self._use_cdp_proxy = False
        # mitmproxy subprocess integration
        self._mitm_port = None
        self._mitm_process = None      # subprocess.Popen for mitmdump
        self._mitm_stop_event = None   # threading.Event to stop log reader
        self._mitm_reader_thread = None
        self._mitm_log_file = None     # temp JSONL file path
        self._mitm_script_file = None  # temp addon .py file path
        self.capture_on_resume = False
        self._manual_snapshots = []
        self._manual_seen_inputs = set()
        self._manual_seen_forms = set()
        self._last_manual_extract = 0.0
        # Global click deduplication — tracks fingerprints of clicked elements
        # across ALL pages to prevent re-clicking the same nav buttons on every page.
        # Fingerprint = hash(tag + text + selector + aria-label + role)
        self._clicked_element_fps = set()
        # Track which nav structures have been fully explored (by page host+path prefix)
        self._explored_nav_structures = set()
        # AI Navigator — page content hashes to detect duplicate layouts
        self._page_content_hashes = {}
        self._ai_nav_decisions = {}  # cache: url_pattern -> AI decision
        # DAST Scanner
        self._stop_requested = False
        self._browser = None  # Reference to browser for forced stop
        self.enable_scanning = enable_scanning
        self.scan_on_the_fly = scan_on_the_fly
        self.quick_scan = quick_scan  # Use fewer payloads for faster scanning
        self.page_scan_mode = page_scan_mode  # 2 AI calls per page (fast) vs per-input (slow)
        self.vulnerabilities = []
        self.vulnerabilities_lock = threading.Lock()
        self._scanned_points = set()
        self._scanned_pages = set()  # Track pages already scanned in page_scan_mode
        self._probed_forms = set()  # Track forms interacted with at the browser level
        self._scan_session = None  # Will hold requests session for scanning
        # Scan logging
        self.scan_logs = []  # Detailed scan activity logs
        # Help Request System
        self.ask_for_help = ask_for_help  # Enable/disable help requests
        self.help_request = None  # Current help request (if any)
        self.help_response = None  # User's response to help request
        self._help_event = threading.Event()
        self._help_event.set()  # Not waiting by default
        # Gobuster directory enumeration
        self.enable_gobuster = enable_gobuster
        self.gobuster_wordlist = gobuster_wordlist
        self._gobuster_process = None

    def _is_probably_asset_url(self, url):
        """Heuristic: skip likely non-HTML downloads (pdf/images/archives/fonts/media)."""
        try:
            from urllib.parse import urlparse
            import os as _os
            path = (urlparse(url).path or "").lower()
            ext = _os.path.splitext(path)[1]
            return bool(ext) and ext in self._asset_exts
        except Exception:
            return False

    def _consume_interaction_budget(self, page_url: str, n: int = 1) -> bool:
        """Return True if we can spend n more interaction steps."""
        if n <= 0:
            return True
        if self._interaction_budget_total <= 0:
            return False
        if self._interaction_total_used + n > self._interaction_budget_total:
            return False
        if page_url:
            used = int(self._interaction_used_by_page.get(page_url, 0))
            if self._interaction_budget_per_page > 0 and (used + n) > self._interaction_budget_per_page:
                return False
        self._interaction_total_used += n
        if page_url:
            self._interaction_used_by_page[page_url] = int(self._interaction_used_by_page.get(page_url, 0)) + n
        return True

    def _recover_if_asset_navigation(self, page, base_url: str) -> None:
        """If a click/submit navigates into a PDF/asset viewer, recover to base_url."""
        if not self.skip_asset_urls or page.is_closed():
            return
        try:
            cur = page.url or ""
        except Exception:
            cur = ""
        if not cur:
            return
        if self._is_probably_asset_url(cur):
            try:
                # Try going back first (preserves SPA state better than a fresh goto).
                page.go_back(wait_until="domcontentloaded", timeout=2500)
                try:
                    page.wait_for_load_state("networkidle", timeout=1500)
                except Exception:
                    pass
            except Exception:
                try:
                    page.goto(base_url, wait_until="domcontentloaded", timeout=5000)
                except Exception:
                    pass

    def _is_html_content_type(self, content_type):
        ct = (content_type or "").lower()
        # Treat unknown as navigable; only block on clearly binary download types.
        if not ct:
            return True
        if "application/pdf" in ct:
            return False
        if ct.startswith("image/") or ct.startswith("audio/") or ct.startswith("video/") or ct.startswith("font/"):
            return False
        if any(x in ct for x in ["application/zip", "application/x-7z-compressed", "application/x-rar-compressed",
                                 "application/octet-stream", "application/x-gzip"]):
            return False
        # Allow typical document/API responses (even if not HTML).
        if "text/html" in ct or "application/xhtml" in ct:
            return True
        if ct.startswith("text/"):
            return True
        if any(x in ct for x in ["json", "javascript", "xml"]):
            return True
        return True

    def _log_scan(self, log_type, message, data=None):
        """Add a scan log entry with timestamp."""
        raw = data if isinstance(data, dict) else ({} if data is None else {'_value': data})
        log_entry = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'type': log_type,  # 'info', 'ai_request', 'ai_response', 'payload', 'response', 'vuln', 'error'
            'message': message,
            'data': _cap_scan_log_data(raw),
        }
        self.scan_logs.append(log_entry)
        if len(self.scan_logs) > _SCAN_LOG_MAX_ENTRIES:
            self.scan_logs[:] = self.scan_logs[-_SCAN_LOG_MAX_ENTRIES:]
        # Also print for console visibility
        prefix = {
            'info': '[SCAN]',
            'ai_request': '[AI-REQ]',
            'ai_response': '[AI-RES]',
            'payload': '[PAYLOAD]',
            'response': '[RESPONSE]',
            'vuln': '[VULN]',
            'error': '[ERROR]'
        }.get(log_type, '[SCAN]')
        print(f"{prefix} {message}")

    def get_scan_logs(self, start=0, limit=100, log_type=None, return_all=False):
        """Get scan logs with pagination and optional filtering."""
        logs = self.scan_logs
        if log_type:
            logs = [l for l in logs if l['type'] == log_type]
        total = len(logs)
        if return_all:
            return {
                'total': total,
                'start': 0,
                'end': total,
                'logs': logs
            }
        return {
            'total': total,
            'start': start,
            'end': min(start + limit, total),
            'logs': logs[start:start + limit]
        }

    def toggle_pause(self):
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.paused = True
        else:
            self.pause_event.set()
            self.paused = False
            self.capture_on_resume = True

    def _pause_if_needed(self):
        if not self.pause_event.is_set():
            while not self.pause_event.is_set() and not self._stop_requested:
                time.sleep(0.2)

    def request_help(self, help_type, element_info, page=None, screenshot=None):
        """
        Request help from the user when crawler is stuck.
        Pauses crawl and waits for user response.

        help_type: 'click', 'fill', 'file_upload', 'captcha', 'modal', 'custom_select', 'other'
        element_info: dict with element details (selector, tag, text, etc.)
        """
        if not self.ask_for_help:
            return 'skip'  # If help not enabled, skip

        # Take screenshot if page available
        screenshot_data = None
        if page and not page.is_closed():
            try:
                screenshot_data = page.screenshot(type='png')
                import base64
                screenshot_data = base64.b64encode(screenshot_data).decode('utf-8')
            except Exception:
                pass

        self.help_request = {
            'type': help_type,
            'element': element_info,
            'screenshot': screenshot_data,
            'timestamp': time.time(),
            'url': page.url if page and not page.is_closed() else '',
            'message': self._get_help_message(help_type, element_info)
        }
        self.help_response = None

        # Pause and wait for user response
        self._help_event.clear()
        self.paused = True
        print(f"[HELP] Requesting help: {help_type} - {element_info.get('selector', 'unknown')}")

        # Wait for user response (with timeout of 5 minutes)
        start_wait = time.time()
        while not self._help_event.is_set() and (time.time() - start_wait) < 300:
            time.sleep(0.5)

        response = self.help_response or 'skip'
        self.help_request = None
        self.paused = False

        # If copilot returned structured Playwright instructions, execute them here
        # (must run in this thread — Playwright is not thread-safe)
        if isinstance(response, dict) and page and not page.is_closed():
            self._execute_copilot_instructions(page, response)
            response = 'handled'

        return response

    def _execute_copilot_instructions(self, page, instructions):
        """Execute Playwright actions returned by the CrawlCopilot."""
        for action in instructions.get('actions', []):
            try:
                atype    = action.get('type', '')
                selector = action.get('selector', '')

                if atype == 'select_option':
                    page.select_option(selector, value=action.get('value', ''))

                elif atype in ('fill', 'fill_date'):
                    page.fill(selector, action.get('value', ''))

                elif atype == 'click':
                    page.click(selector, timeout=3000)
                    page.wait_for_timeout(500)

                elif atype == 'click_dropdown':
                    toggle = action.get('toggle', selector)
                    page.click(toggle, timeout=3000)
                    page.wait_for_timeout(300)
                    # Click nth visible option in the now-open menu
                    idx = int(action.get('option_index', 0))
                    items = page.locator(
                        '.dropdown-menu.show a, '
                        '.dropdown-menu[style*="display: block"] a, '
                        '.open > .dropdown-menu a'
                    )
                    if items.count() > idx:
                        items.nth(idx).click()
                        page.wait_for_timeout(200)
                    else:
                        page.keyboard.press('Escape')

                else:
                    print(f"[Copilot] Unknown action type: {atype}")

            except Exception as e:
                print(f"[Copilot] Action '{atype}' on '{selector}' failed: {e}")
                continue

    def respond_to_help(self, response):
        """
        User responds to help request.
        response: 'handled', 'skip', 'stop'
        """
        self.help_response = response
        self._help_event.set()
        if response == 'stop':
            self.pause_event.clear()
            self.paused = True

    def get_help_request(self):
        """Get current help request (for API)"""
        return self.help_request

    def _get_help_message(self, help_type, element_info):
        """Generate human-readable help message"""
        messages = {
            'click': f"Can't click button/link: {element_info.get('text', element_info.get('selector', 'element'))}",
            'fill': f"Can't fill input field: {element_info.get('name', element_info.get('selector', 'field'))}",
            'file_upload': f"File upload detected: {element_info.get('name', 'file input')} - Please upload a file",
            'captcha': "CAPTCHA detected - Please solve it manually",
            'modal': "Modal/popup blocking - Please close or interact with it",
            'custom_select': f"Custom dropdown: {element_info.get('text', element_info.get('selector', 'dropdown'))} - Please select an option",
            'other': f"Need help with: {element_info.get('description', 'unknown element')}"
        }
        return messages.get(help_type, f"Need help with {help_type}")

    def _capture_manual_snapshot(self, page):
        try:
            if page.is_closed():
                return
            html = page.content()
            snapshot = {
                'url': page.url,
                'title': page.title(),
                'timestamp': time.time(),
                'html': html[:8000]
            }
            self._manual_snapshots.append(snapshot)
        except Exception:
            pass

    def _manual_pause_and_sync(self, page, url):
        if not self.manual_mode or page.is_closed():
            return url
        # Don't auto-pause - only pause when user clicks Pause button
        # Just check if already paused and wait if so
        self._pause_if_needed()
        if self.capture_on_resume:
            self._capture_manual_snapshot(page)
            self.capture_on_resume = False
        manual_url = page.url
        if manual_url and manual_url != url and self._is_allowed_url(manual_url):
            return manual_url
        return url

    def _manual_collect_input_points(self, page):
        if page.is_closed():
            return
        try:
            base_url = page.url or self.target_url
        except Exception:
            base_url = self.target_url

        frames = page.frames
        for frame in frames:
            try:
                data = self._extract_from_frame(frame)
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            forms = data.get("forms", [])
            loose_inputs = data.get("looseInputs", [])

            for form in forms:
                action = self._normalize_url(base_url, form.get("action") or base_url)
                if not action:
                    action = base_url
                form_key = (base_url, action, (form.get("method") or "GET").upper())
                if form_key in self._manual_seen_forms:
                    continue
                self._manual_seen_forms.add(form_key)
                form_entry = {
                    "url": base_url,
                    "action": action,
                    "method": form.get("method", "GET"),
                    "inputs": form.get("inputs", []),
                }
                self._add_form(form_entry)
                self._add_params(action)
                for inp in form_entry["inputs"]:
                    if not inp.get("name"):
                        continue
                    ip_key = (action, form_entry["method"], inp.get("name"))
                    if ip_key in self._manual_seen_inputs:
                        continue
                    self._manual_seen_inputs.add(ip_key)
                    input_point = {
                        "page": base_url,
                        "action": action,
                        "method": form_entry["method"],
                        "name": inp.get("name"),
                        "input_type": inp.get("type", "text"),
                    }
                    self._add_input_point(input_point)

                    # DAST: Scan this input point (manual mode)
                    if self.enable_scanning and self.scan_on_the_fly:
                        self._scan_input_point(input_point, None, None)

            for inp in loose_inputs:
                name = inp.get("name") or ""
                if not name:
                    continue
                ip_key = (base_url, "GET", name)
                if ip_key in self._manual_seen_inputs:
                    continue
                self._manual_seen_inputs.add(ip_key)
                input_point = {
                    "page": base_url,
                    "action": base_url,
                    "method": "GET",
                    "name": name,
                    "input_type": inp.get("type", "text"),
                }
                self._add_input_point(input_point)

                # DAST: Scan this input point (manual mode)
                if self.enable_scanning:
                    self._scan_input_point(input_point, None, None)


    def _call_ai(self, prompt, max_tokens=2000):
        """Call AI API for intelligent analysis.
        Supports: anthropic, openai, gemini, deepseek, grok, groq, ollama-*
        Automatically retries with fallback provider if primary fails.
        """
        if not self.ai_api_key:
            return None
        try:
            import requests
            provider = self.ai_provider.lower()
            result = self._call_ai_provider(prompt, max_tokens, provider, self.ai_api_key)
            if result:
                return result

            return None
        except Exception as e:
            print(f"[AI] API error: {e}")
        return None

    def _get_default_model(self, provider):
        """Get default model for a provider"""
        return get_default_model(provider)

    def _call_ai_provider(self, prompt, max_tokens, provider, api_key):
        """Crawler LLM calls disabled — DAST uses Claude Code CLI only."""
        return None

    def _check_stuck(self, current_visited_count):
        """Check if crawl is stuck and return True if so."""
        current_time = time.time()

        # If we've made progress, reset timer
        if current_visited_count > self._last_visited_count:
            self._last_progress_time = current_time
            self._last_visited_count = current_visited_count
            return False

        # Check if we've been stuck too long
        time_since_progress = current_time - self._last_progress_time
        if time_since_progress > self._stuck_threshold:
            return True

        return False

    def _ai_recover_from_stuck(self, page, queue, current_url):
        """Use AI to analyze the current state and suggest recovery actions."""
        if not self.ai_api_key:
            return self._basic_stuck_recovery(page, queue)

        if self._stuck_recovery_attempts >= self._max_stuck_recoveries:
            print(f"[AI] Max stuck recovery attempts ({self._max_stuck_recoveries}) reached, skipping")
            return False

        self._stuck_recovery_attempts += 1
        print(f"[AI] Crawl appears stuck - attempting AI recovery (attempt {self._stuck_recovery_attempts})")

        try:
            # Get current page state
            page_html = page.content()[:8000]  # Truncate for API
            current_queue_size = len(queue)
            visited_count = len(self.visited)

            prompt = f"""The web crawler is stuck. Analyze the situation and suggest recovery actions.

Current URL: {current_url}
Pages visited: {visited_count}
Queue size: {current_queue_size}
Queue preview (first 5): {[url for url, _ in queue[:5]]}

Current page HTML (truncated):
```html
{page_html}
```

Analyze and return ONLY valid JSON with recovery suggestions:
{{
    "diagnosis": "brief explanation of why crawler might be stuck",
    "action": "one of: skip_page, click_element, navigate_to, clear_queue, reduce_scope",
    "target": "CSS selector for click_element, or URL for navigate_to, or null",
    "skip_patterns": ["URL patterns to skip in future"],
    "priority_urls": ["URLs that should be crawled first"]
}}

Common stuck situations:
- Infinite loops on similar pages (add skip patterns)
- Modal dialogs blocking (click close button)
- Login required (navigate to login)
- Too many similar pages (reduce scope)
- JavaScript errors (skip page)
"""

            response = self._call_ai(prompt, max_tokens=1000)
            if not response:
                return self._basic_stuck_recovery(page, queue)

            # Parse AI response
            import json
            try:
                # Clean response
                response = response.strip()
                if response.startswith('```'):
                    response = response.split('```')[1]
                    if response.startswith('json'):
                        response = response[4:]
                recovery = json.loads(response)
            except json.JSONDecodeError:
                print(f"[AI] Could not parse recovery response")
                return self._basic_stuck_recovery(page, queue)

            diagnosis = recovery.get('diagnosis', 'Unknown')
            action = recovery.get('action', 'skip_page')
            target = recovery.get('target')
            skip_patterns = recovery.get('skip_patterns', [])
            priority_urls = recovery.get('priority_urls', [])

            print(f"[AI] Diagnosis: {diagnosis}")
            print(f"[AI] Recovery action: {action}")

            # Add skip patterns
            for pattern in skip_patterns:
                self._ai_skip_patterns.add(pattern)
                print(f"[AI] Added skip pattern: {pattern}")

            # Execute recovery action
            if action == 'click_element' and target:
                try:
                    el = page.locator(target).first
                    if el.is_visible():
                        el.click(timeout=3000)
                        page.wait_for_timeout(1000)
                        print(f"[AI] Clicked element: {target}")
                        return True
                except Exception as e:
                    print(f"[AI] Click failed: {e}")

            elif action == 'navigate_to' and target:
                try:
                    if self._is_allowed_url(target):
                        page.goto(target, wait_until='networkidle', timeout=self.timeout)
                        print(f"[AI] Navigated to: {target}")
                        return True
                except Exception as e:
                    print(f"[AI] Navigation failed: {e}")

            elif action == 'clear_queue':
                # Keep only unique base paths
                seen_paths = set()
                new_queue = []
                for url, depth in queue:
                    path = urlparse(url).path.split('?')[0]
                    if path not in seen_paths:
                        seen_paths.add(path)
                        new_queue.append((url, depth))
                queue.clear()
                queue.extend(new_queue[:500])  # Keep up to 500 unique paths
                print(f"[AI] Cleared queue, reduced to {len(queue)} unique paths")
                return True

            elif action == 'reduce_scope':
                # Remove similar URLs from queue
                if queue:
                    queue[:] = queue[:200]  # Keep first 200
                    print(f"[AI] Reduced scope to {len(queue)} URLs")
                return True

            elif action == 'skip_page':
                print(f"[AI] Skipping current page")
                return True

            # Add priority URLs to front of queue
            for url in priority_urls:
                if url not in self.visited and self._is_allowed_url(url):
                    queue.insert(0, (url, 0))
                    print(f"[AI] Added priority URL: {url}")

            return True

        except Exception as e:
            print(f"[AI] Recovery error: {e}")
            return self._basic_stuck_recovery(page, queue)

    def _basic_stuck_recovery(self, page, queue):
        """Basic recovery without AI - just skip and continue."""
        print(f"[*] Basic stuck recovery - clearing stale queue entries")

        # Remove duplicate base URLs from queue
        if queue:
            seen = set()
            new_queue = []
            for url, depth in queue:
                base = url.split('?')[0]
                if base not in seen:
                    seen.add(base)
                    new_queue.append((url, depth))
            queue.clear()
            queue.extend(new_queue[:500])  # Keep up to 500 unique base URLs

        # Reset progress timer
        self._last_progress_time = time.time()
        return True

    # =========================================================================
    # DAST SCANNER METHODS
    # =========================================================================

    def _get_scan_payloads(self, input_point, vuln_type):
        """
        Get payloads for scanning. Uses AI if available, otherwise built-in payloads.
        Quick scan uses 2 payloads per type, full scan uses 10.
        """
        if self.ai_api_key:
            ai_payloads = self._ai_generate_payloads(input_point, vuln_type)
            if ai_payloads:
                return ai_payloads

        # Use quick or full payload database
        payload_db = QUICK_SCAN_PAYLOADS if self.quick_scan else SCAN_PAYLOADS
        return payload_db.get(vuln_type, [])

    def _ai_generate_payloads(self, input_point, vuln_type):
        """Generate 3 context-aware payloads using AI."""
        try:
            prompt = f"""You are a security testing assistant for authorized penetration testing.
Generate exactly 3 test payloads for detecting {vuln_type.upper()} vulnerability in this input:

Input Details:
- Parameter name: {input_point.get('name', 'unknown')}
- Input type: {input_point.get('input_type', 'text')}
- Form action: {input_point.get('action', 'unknown')}
- HTTP method: {input_point.get('method', 'GET')}

Rules:
1. Generate exactly 3 payloads specific to this context
2. Include detection method (error_based, time_based, reflection, output_based)
3. For time_based, use 5 second delays
4. Output JSON array only, no explanation

Output format:
[
  {{"payload": "...", "type": "error_based|time_based|reflection|output_based", "desc": "short description"}},
  {{"payload": "...", "type": "...", "desc": "..."}},
  {{"payload": "...", "type": "...", "desc": "..."}}
]"""

            response = self._call_ai(prompt, max_tokens=500)
            if not response:
                return None

            # Parse JSON from response
            start = response.find('[')
            end = response.rfind(']')
            if start == -1 or end == -1:
                return None

            payloads = json.loads(response[start:end + 1])
            if isinstance(payloads, list) and len(payloads) > 0:
                # Mark as AI-generated
                for p in payloads:
                    p['ai_generated'] = True
                return payloads[:3]  # Limit to 3

        except Exception as e:
            print(f"[SCAN] AI payload generation failed: {e}")

        return None

    # =========================================================================
    # 2 AI CALLS TOTAL ARCHITECTURE
    # =========================================================================

    def scan_all_2ai(self, cookies_dict=None, cached_payloads=None):
        """
        Scan ALL collected inputs with exactly 2 AI calls total:
        1. Crawl complete - collect ALL inputs from ALL pages
        2. AI Call 1: Generate payloads for ALL inputs at once (or use cached_payloads if provided)
        3. Execute ALL payloads, collect ALL responses
        4. AI Call 2: Validate ALL results for FP at once

        Args:
            cookies_dict: Optional cookies to use for requests
            cached_payloads: Optional pre-generated payloads from AI input profiling.
                           If provided, skips AI payload generation (saves an AI call).

        Returns: List of confirmed vulnerabilities
        """
        if not self.enable_scanning:
            return []

        print(f"[SCAN-2AI] Starting 2-AI-call scan for: {self.target_url}")
        self._log_scan('info', f"Starting 2-AI-call scan for target: {self.target_url}", {
            'target_url': self.target_url,
            'forms_count': len(self.forms),
            'inputs_count': len(self.input_points)
        })

        # Step 1: Collect ALL inputs from all pages
        print(f"[SCAN-2AI] Step 1: Collecting all inputs...")
        all_inputs = self._collect_all_inputs()

        if not all_inputs:
            print("[SCAN-2AI] No inputs found to scan")
            return []

        print(f"[SCAN-2AI] Collected {len(all_inputs)} inputs from {len(set(i['page_url'] for i in all_inputs))} pages")

        # Step 2: Use cached payloads if available, otherwise generate via AI
        if cached_payloads and len(cached_payloads) > 0:
            print(f"[SCAN-2AI] Step 2: Using {len(cached_payloads)} cached AI payloads (skipping AI generation)")
            self._log_scan('info', f"Using {len(cached_payloads)} cached payloads from input profiling")
            payloads = cached_payloads
        else:
            print(f"[SCAN-2AI] Step 2: AI generating payloads for all inputs...")
            print(f"[SCAN-2AI] AI Key: ***...{self.ai_api_key[-4:] if self.ai_api_key and len(self.ai_api_key) > 4 else '****'}")
            print(f"[SCAN-2AI] AI Provider: {self.ai_provider}")
            payloads = self._ai_generate_all_payloads(all_inputs)

            if not payloads:
                print("[SCAN-2AI] AI returned no payloads, using fallback payloads")
                payloads = self._generate_fallback_payloads_all(all_inputs)

        print(f"[SCAN-2AI] Generated {len(payloads)} total payloads")

        # Step 3: Execute ALL payloads
        print(f"[SCAN-2AI] Step 3: Executing all payloads...")
        results = self._execute_payloads_batch(payloads, cookies_dict)
        print(f"[SCAN-2AI] Collected {len(results)} responses")

        # Step 4: AI Call 2 - Validate ALL results
        if self.ai_api_key and results:
            print(f"[SCAN-2AI] Step 4: AI validating all results for FP...")
            validated = self._ai_validate_all_results(results)
            print(f"[SCAN-2AI] Validation complete: {len(validated)} confirmed vulnerabilities")
            self.vulnerabilities.extend(validated)
            return validated

        # No AI - pattern matching fallback
        print(f"[SCAN-2AI] Step 4: Pattern matching (no AI)...")
        matched = self._pattern_match_results(results)
        print(f"[SCAN-2AI] Pattern matching found {len(matched)} potential vulnerabilities")
        self.vulnerabilities.extend(matched)
        return matched

    def _collect_all_inputs(self):
        """Collect all inputs from forms and input_points into a unified list."""
        all_inputs = []

        # Collect from forms
        for form in self.forms:
            page_url = form.get('page_url', form.get('action', self.target_url))
            if page_url and not page_url.startswith('http'):
                page_url = urljoin(self.target_url, page_url)

            action = form.get('action', page_url)
            if action and not action.startswith('http'):
                action = urljoin(self.target_url, action)

            method = form.get('method', 'GET').upper()

            for inp in form.get('inputs', []):
                name = inp.get('name', '')
                if name:
                    all_inputs.append({
                        'page_url': page_url,
                        'action': action,
                        'method': method,
                        'name': name,
                        'type': inp.get('type', 'text'),
                        'source': 'form'
                    })

        # Collect from loose inputs
        for inp in self.input_points:
            page_url = inp.get('page_url', inp.get('action', self.target_url))
            if page_url and not page_url.startswith('http'):
                page_url = urljoin(self.target_url, page_url)

            action = inp.get('action', page_url)
            if action and not action.startswith('http'):
                action = urljoin(self.target_url, action)

            name = inp.get('name', '')
            if name:
                all_inputs.append({
                    'page_url': page_url,
                    'action': action,
                    'method': inp.get('method', 'GET').upper(),
                    'name': name,
                    'type': inp.get('input_type', 'text'),
                    'source': 'input'
                })

        # Deduplicate by (action, method, name)
        seen = set()
        unique_inputs = []
        for inp in all_inputs:
            key = (inp['action'], inp['method'], inp['name'])
            if key not in seen:
                seen.add(key)
                unique_inputs.append(inp)

        # --- Global parameter deduplication ---
        # Params appearing on 10+ different endpoints (cookies, hidden fields
        # like security_level/bug/PHPSESSID) only need one fuzz target.
        param_actions: dict = {}
        for inp in unique_inputs:
            param_actions.setdefault(inp['name'], set()).add(inp['action'])

        _GLOBAL_THRESHOLD = 10
        global_params = {name for name, actions in param_actions.items()
                         if len(actions) >= _GLOBAL_THRESHOLD}

        if global_params:
            deduped = []
            seen_global: set = set()
            for inp in unique_inputs:
                if inp['name'] in global_params:
                    if inp['name'] in seen_global:
                        continue
                    seen_global.add(inp['name'])
                deduped.append(inp)
            skipped = len(unique_inputs) - len(deduped)
            if skipped:
                print(f"[2AI-Scan] Global param dedup: kept 1 target each for "
                      f"{len(global_params)} global params, skipped {skipped} duplicates")
            unique_inputs = deduped

        return unique_inputs

    def _ai_generate_all_payloads(self, all_inputs):
        """
        AI CALL #1 (TOTAL): Generate payloads for ALL inputs across the entire scan.
        Single AI call for the whole scan.
        """
        if not self.ai_api_key:
            self._log_scan('info', "AI not configured, skipping AI payload generation")
            return None

        try:
            # Build inputs summary
            inputs_summary = []
            for inp in all_inputs:
                inputs_summary.append({
                    'page': inp['page_url'],
                    'action': inp['action'],
                    'method': inp['method'],
                    'name': inp['name'],
                    'type': inp['type']
                })

            prompt = f"""You are a security testing assistant for authorized penetration testing.
Generate test payloads for ALL inputs provided below.

Target: {self.target_url}
Total inputs: {len(inputs_summary)}

Inputs to test:
{json.dumps(inputs_summary, indent=2)}

Vulnerability types to test: SQLi, XSS, Command Injection, Path Traversal, SSTI

Rules:
1. Generate 2-3 best payloads per input per vulnerability type
2. Include detection method for each (error_based, time_based, reflection, output_based)
3. For time-based, use 5 second delays
4. Be smart - skip inputs that are unlikely to be vulnerable (e.g., CSRF tokens, page numbers)
5. Output JSON array only, no explanations

Output format:
[
  {{"action": "/login", "method": "POST", "input_name": "username", "vuln_type": "sqli", "payload": "' OR '1'='1", "detection": "boolean_based", "desc": "SQL OR bypass"}},
  {{"action": "/search", "method": "GET", "input_name": "q", "vuln_type": "xss", "payload": "<script>alert(1)</script>", "detection": "reflection", "desc": "Basic XSS"}}
]

Generate payloads now:"""

            self._log_scan('ai_request', "AI Call #1 (TOTAL): Generate ALL payloads", {
                'provider': self.ai_provider,
                'total_inputs': len(inputs_summary),
                'target': self.target_url
            })

            response = self._call_ai(prompt, max_tokens=4000)
            if not response:
                self._log_scan('error', "AI returned empty response")
                return None

            self._log_scan('ai_response', "AI payload generation response received", {
                'response_length': len(response)
            })

            # Parse JSON
            start = response.find('[')
            end = response.rfind(']')
            if start == -1 or end == -1:
                self._log_scan('error', "Could not parse JSON from AI response")
                return None

            payloads = json.loads(response[start:end + 1])
            if isinstance(payloads, list) and len(payloads) > 0:
                self._log_scan('info', f"AI generated {len(payloads)} payloads for entire scan", {
                    'payload_count': len(payloads)
                })
                return payloads

        except Exception as e:
            self._log_scan('error', f"AI payload generation failed: {e}")

        return None

    def _generate_fallback_payloads_all(self, all_inputs):
        """Generate payloads from built-in list for all inputs."""
        payloads = []
        payload_db = QUICK_SCAN_PAYLOADS if self.quick_scan else SCAN_PAYLOADS

        for inp in all_inputs:
            for vuln_type, type_payloads in payload_db.items():
                for p in type_payloads:
                    payloads.append({
                        'action': inp['action'],
                        'method': inp['method'],
                        'input_name': inp['name'],
                        'vuln_type': vuln_type,
                        'payload': p['payload'],
                        'detection': p['type'],
                        'desc': p.get('desc', ''),
                        'delay': p.get('delay', 0),
                        'expect': p.get('expect', '')
                    })

        return payloads

    def _execute_payloads_batch(self, payloads, cookies_dict=None):
        """Execute all payloads via HTTP requests and collect responses."""
        import requests
        results = []
        session = requests.Session()
        session.verify = False

        if cookies_dict:
            for k, v in cookies_dict.items():
                session.cookies.set(k, v)

        for p in payloads:
            action = p.get('action', '')
            if not action:
                continue
            if not action.startswith('http'):
                action = urljoin(self.target_url, action)

            method = p.get('method', 'GET').upper()
            input_name = p.get('input_name', '')
            payload_val = p.get('payload', '')
            detection = p.get('detection', '')
            delay_expected = p.get('delay', 0)

            result = {
                'action': action,
                'method': method,
                'input_name': input_name,
                'vuln_type': p.get('vuln_type', ''),
                'payload': payload_val,
                'detection': detection,
                'delay_expected': delay_expected,
                'desc': p.get('desc', ''),
            }

            try:
                start_time = time.time()
                if method == 'POST':
                    resp = session.post(action, data={input_name: payload_val}, timeout=15, allow_redirects=True)
                else:
                    resp = session.get(action, params={input_name: payload_val}, timeout=15, allow_redirects=True)
                elapsed = time.time() - start_time

                result['status_code'] = resp.status_code
                result['response_time'] = round(elapsed, 3)
                result['response_length'] = len(resp.text)
                result['response_body'] = resp.text[:2000]
            except Exception as e:
                result['error'] = str(e)

            results.append(result)

        return results

    def _pattern_match_results(self, results):
        """Fallback: use pattern matching to detect vulnerabilities without AI."""
        findings = []
        patterns = {
            'sqli': [
                r'SQL syntax.*MySQL', r'Warning.*mysql_', r'Unclosed quotation mark',
                r'PostgreSQL.*ERROR', r'ORA-\d{5}', r'Microsoft.*ODBC.*SQL Server',
                r'sqlite3\.OperationalError', r'You have an error in your SQL syntax',
            ],
            'xss': [
                r'<script>alert\(', r'<img\s+.*onerror=', r'<svg\s+.*onload=',
            ],
            'cmdi': [
                r'uid=\d+\(', r'root:', r'www-data:', r'Volume Serial Number',
            ],
            'path_traversal': [
                r'root:.*:0:0:', r'\[boot loader\]', r'\[extensions\]',
            ],
            'ssti': [
                r'49(?![\d])',  # 7*7 result
            ],
        }
        import re
        for r in results:
            if 'error' in r:
                continue
            body = r.get('response_body', '')
            vuln_type = r.get('vuln_type', '').lower()
            detection = r.get('detection', '')

            matched = False
            # Time-based detection
            if detection == 'time_based' and r.get('delay_expected', 0) > 0:
                if r.get('response_time', 0) >= r['delay_expected'] * 0.8:
                    matched = True

            # Pattern-based detection
            for ptype, pats in patterns.items():
                if vuln_type and ptype not in vuln_type.lower().replace('_', '').replace(' ', ''):
                    continue
                for pat in pats:
                    if re.search(pat, body, re.IGNORECASE):
                        matched = True
                        break
                if matched:
                    break

            if matched:
                sev_map = {'sqli': 'Critical', 'xss': 'High', 'cmdi': 'Critical',
                           'path_traversal': 'High', 'ssti': 'Critical'}
                severity = sev_map.get(vuln_type, 'Medium')
                findings.append({
                    'vuln_type': r.get('vuln_type', 'Unknown'),
                    'severity': severity,
                    'url': r.get('action', ''),
                    'parameter': r.get('input_name', ''),
                    'payload': r.get('payload', ''),
                    'description': r.get('desc', ''),
                    'evidence': body[:500],
                    'exploit_score': 70,
                    'source': 'pattern_match',
                })

        return findings

    def _ai_validate_all_results(self, results):
        """
        AI CALL #2 (TOTAL): Validate ALL results for False Positives in one call.
        Single AI call for the whole scan.
        """
        if not self.ai_api_key or not results:
            return []

        try:
            # Filter to only successful results
            results_summary = []
            for r in results:
                if 'error' not in r:
                    results_summary.append({
                        'url': r.get('action'),
                        'input': r.get('input_name'),
                        'method': r.get('method'),
                        'vuln_type': r.get('vuln_type'),
                        'payload': r.get('payload'),
                        'detection': r.get('detection'),
                        'status_code': r.get('status_code'),
                        'response_time': r.get('response_time'),
                        'response_length': r.get('response_length'),
                        'response_snippet': r.get('response_body', '')[:300],
                        'delay_expected': r.get('delay_expected', 0)
                    })

            if not results_summary:
                return []

            # Split into chunks if too large (max ~50 results per AI call for token limits)
            chunk_size = 50
            all_validated = []

            for i in range(0, len(results_summary), chunk_size):
                chunk = results_summary[i:i+chunk_size]
                validated = self._ai_validate_chunk(chunk, i // chunk_size + 1, (len(results_summary) - 1) // chunk_size + 1)
                all_validated.extend(validated)

            return all_validated

        except Exception as e:
            self._log_scan('error', f"AI validation failed: {e}")
            return []

    def _ai_validate_chunk(self, results_chunk, chunk_num, total_chunks):
        """Validate a chunk of results with AI."""
        prompt = f"""You are a security expert validating vulnerability scan results.
Analyze these test results and determine which are REAL, EXPLOITABLE vulnerabilities.

Test Results (chunk {chunk_num}/{total_chunks}):
{json.dumps(results_chunk, indent=2)}

For each result, determine exploitation confidence (0-100%):

EXPLOITATION SCORING:
- 100%: PROVEN EXPLOITED - Direct evidence of successful exploitation
  * SQLi: Data extracted, auth bypassed, or SQL error with query visible
  * XSS: Payload reflected unencoded AND executable in browser context
  * CMDi: Command output visible (uid=, whoami result, file contents)
  * Path Traversal: Sensitive file contents visible (passwd, config files)
  * SSTI: Template expression evaluated (49 for 7*7, math results)

- 80-99%: HIGHLY LIKELY - Strong indicators but not 100% proof
  * Error messages revealing vulnerability exists
  * Behavior differences suggesting injection worked
  * Time-based delays matching expected delay

- 50-79%: PROBABLE - Some evidence but needs verification
  * Suspicious behavior changes
  * Partial reflection of payload
  * Ambiguous error messages

- Below 50%: NOT CONFIRMED - Insufficient evidence (exclude these)

IMPORTANT: Only include results with exploit_score >= 50

Output JSON array:
[
  {{"url": "...", "input": "username", "vuln_type": "sqli", "payload": "...", "exploit_score": 100, "evidence": "SQL error: You have an error in your SQL syntax", "exploited": true}}
]

If no exploitable vulnerabilities found, return: []

Analyze now:"""

        self._log_scan('ai_request', f"AI Call #2 (TOTAL): Validate chunk {chunk_num}/{total_chunks}", {
            'provider': self.ai_provider,
            'results_count': len(results_chunk),
            'chunk': chunk_num
        })

        response = self._call_ai(prompt, max_tokens=2000)
        if not response:
            return []

        self._log_scan('ai_response', f"AI validation chunk {chunk_num} response received", {
            'response_length': len(response)
        })

        try:
            start = response.find('[')
            end = response.rfind(']')
            if start == -1 or end == -1:
                return []

            validated = json.loads(response[start:end + 1])
            findings = []

            if isinstance(validated, list):
                for v in validated:
                    # Get exploit score (new) or fall back to confidence (old format)
                    exploit_score = v.get('exploit_score', 0)
                    if not exploit_score and v.get('confidence') == 'high':
                        exploit_score = 90
                    elif not exploit_score and v.get('confidence') == 'medium':
                        exploit_score = 70

                    # Only include if score >= 50
                    if exploit_score >= 50:
                        # Determine confidence label from score
                        if exploit_score == 100:
                            confidence = 'exploited'
                        elif exploit_score >= 80:
                            confidence = 'high'
                        else:
                            confidence = 'medium'

                        finding = {
                            'vuln_type': v.get('vuln_type', '').upper(),
                            'severity': SEVERITY_MAP.get(v.get('vuln_type', ''), 'Medium'),
                            'confidence': confidence,
                            'exploit_score': exploit_score,
                            'exploited': v.get('exploited', exploit_score == 100),
                            'cwe': CWE_MAP.get(v.get('vuln_type', ''), ''),
                            'owasp': OWASP_MAP.get(v.get('vuln_type', ''), ''),
                            'found_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
                            'ai_validated': True,
                            'evidence': v.get('evidence', ''),
                            'url': v.get('url', ''),
                            'parameter': v.get('input', ''),
                            'payload_used': v.get('payload', ''),
                        }
                        findings.append(finding)

                        status = "EXPLOITED" if exploit_score == 100 else "CONFIRMED"
                        print(f"[VULN] {status} ({exploit_score}%): {finding['vuln_type']} in {finding['parameter']} at {finding['url']}")
                        self._log_scan('vuln', f"{status}: {finding['vuln_type']} in {finding['parameter']} ({exploit_score}%)", finding)

            return findings

        except Exception as e:
            self._log_scan('error', f"Failed to parse AI validation response: {e}")
            return []

    def _scan_input_point(self, input_point, context, cookies_dict=None):
        """
        Scan a single input point for vulnerabilities.
        Tests with payloads and analyzes responses.
        (Legacy per-input method - use scan_page or scan_all_collected instead)
        """
        point_key = (input_point.get('action'), input_point.get('method'), input_point.get('name'))
        if point_key in self._scanned_points:
            return
        self._scanned_points.add(point_key)

        param_name = input_point.get('name', '')
        action_url = input_point.get('action', '')
        method = input_point.get('method', 'GET').upper()

        if not param_name or not action_url:
            return

        print(f"[SCAN] Testing {method} {action_url} [{param_name}]")

        # Get baseline response for comparison
        baseline = self._get_baseline_response(action_url, method, param_name, context, cookies_dict)

        # Test each vulnerability type (use quick payloads if quick_scan enabled)
        payload_db = QUICK_SCAN_PAYLOADS if self.quick_scan else SCAN_PAYLOADS
        for vuln_type in payload_db.keys():
            payloads = self._get_scan_payloads(input_point, vuln_type)

            for payload_info in payloads:
                if isinstance(payload_info, dict):
                    payload = payload_info.get('payload', '')
                    detection_type = payload_info.get('type', 'error_based')
                    delay = payload_info.get('delay', 0)
                    expected = payload_info.get('expect', '')
                    desc = payload_info.get('desc', '')
                    ai_generated = payload_info.get('ai_generated', False)
                else:
                    payload = str(payload_info)
                    detection_type = 'error_based'
                    delay = 0
                    expected = ''
                    desc = ''
                    ai_generated = False

                # Send payload and get response
                response_data = self._send_scan_payload(
                    action_url, method, param_name, payload, context, cookies_dict
                )

                if not response_data:
                    continue

                # Check for vulnerability
                is_vuln, evidence = self._detect_vulnerability(
                    vuln_type, detection_type, payload, response_data, baseline, expected
                )

                if is_vuln:
                    finding = self._build_finding(
                        vuln_type=vuln_type,
                        input_point=input_point,
                        payload=payload,
                        payload_desc=desc,
                        detection_type=detection_type,
                        response_data=response_data,
                        evidence=evidence,
                        ai_generated=ai_generated,
                        cookies_dict=cookies_dict
                    )
                    with self.vulnerabilities_lock:
                        self.vulnerabilities.append(finding)
                    print(f"[VULN] {vuln_type.upper()} found in {param_name} at {action_url}")
                    # Found vuln for this type, move to next type
                    break

    def _build_finding(self, vuln_type, input_point, payload, payload_desc, detection_type,
                       response_data, evidence, ai_generated, cookies_dict):
        """Build detailed vulnerability finding with reproduction steps."""
        from datetime import datetime

        action_url = input_point.get('action', '')
        method = input_point.get('method', 'GET').upper()
        param_name = input_point.get('name', '')

        # Build request details for reproduction
        if method == 'GET':
            full_url = f"{action_url}?{param_name}={payload}"
            request_body = None
        else:
            full_url = action_url
            request_body = f"{param_name}={payload}"

        finding = {
            'vuln_type': vuln_type.upper(),
            'severity': SEVERITY_MAP.get(vuln_type, 'Medium'),
            'confidence': 'High' if detection_type in ['error_based', 'output_based'] else 'Medium',
            'cwe': CWE_MAP.get(vuln_type, ''),
            'owasp': OWASP_MAP.get(vuln_type, ''),
            'found_at': datetime.now().isoformat(),
            'ai_generated': ai_generated,

            # Location
            'url': action_url,
            'parameter': param_name,
            'method': method,

            # Evidence for reproduction
            'evidence': {
                'request': {
                    'method': method,
                    'url': full_url if method == 'GET' else action_url,
                    'headers': {
                        'Content-Type': 'application/x-www-form-urlencoded' if method == 'POST' else None,
                        'Cookie': '; '.join([f"{k}={v}" for k, v in (cookies_dict or {}).items()]) if cookies_dict else None,
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    },
                    'body': request_body
                },
                'response': {
                    'status_code': response_data.get('status_code'),
                    'response_time_ms': response_data.get('response_time_ms'),
                    'body_length': response_data.get('body_length'),
                    'body_snippet': response_data.get('body', '')[:500] if response_data.get('body') else ''
                },
                'detection': {
                    'type': detection_type,
                    'payload_used': payload,
                    'payload_description': payload_desc,
                    'detection_evidence': evidence
                },
                'reproduction_steps': [
                    f"1. Send {method} request to: {action_url}",
                    f"2. Set parameter '{param_name}' to: {payload}",
                    f"3. Include headers: Content-Type: application/x-www-form-urlencoded" if method == 'POST' else f"3. Append to URL: ?{param_name}={payload}",
                    f"4. Observe: {evidence[:200]}",
                    f"5. Expected after fix: No error/output should be visible, response should handle input safely"
                ]
            }
        }

        # Clean up None values in headers
        finding['evidence']['request']['headers'] = {
            k: v for k, v in finding['evidence']['request']['headers'].items() if v
        }

        return finding

    @staticmethod
    def _canonicalize_url(url):
        """Normalize a URL for deduplication: lowercase scheme/host, resolve path,
        strip default ports, remove trailing slash on paths, sort query params."""
        try:
            p = urlparse(url)
            scheme = p.scheme.lower()
            netloc = p.netloc.lower()
            # Strip default ports
            if netloc.endswith(':80') and scheme == 'http':
                netloc = netloc[:-3]
            elif netloc.endswith(':443') and scheme == 'https':
                netloc = netloc[:-4]
            # Resolve .. and . in path via posixpath
            import posixpath
            path = posixpath.normpath(p.path or '/')
            # normpath turns '' and '/' into '/', keep root as /
            if path == '.':
                path = '/'
            # Remove trailing slash except for root
            if path != '/' and path.endswith('/'):
                path = path.rstrip('/')
            # Sort query parameters for consistent ordering
            query = p.query
            if query:
                parts = sorted(query.split('&'))
                query = '&'.join(parts)
            canon = f"{scheme}://{netloc}{path}"
            if query:
                canon += f"?{query}"
            return canon
        except Exception:
            return url

    def _enqueue_url(self, queue, url, depth, priority=False):
        """Add URL to crawl queue with deduplication. Returns True if added."""
        canon = self._canonicalize_url(url)
        if canon in self.visited or canon in self._queued_urls:
            return False
        # Also check un-canonicalized form in case visited was populated before
        if url in self.visited or url in self._queued_urls:
            return False
        if depth > self.max_depth:
            return False
        if self.skip_asset_urls and self._is_probably_asset_url(url):
            return False
        if not self._is_allowed_url(url):
            return False
        self._queued_urls.add(canon)
        self._queued_urls.add(url)  # Also add original to catch exact matches
        if priority:
            queue.insert(0, (url, depth))
        else:
            queue.append((url, depth))
        return True

    def _should_skip_url(self, url):
        """Check if URL matches any AI-suggested skip patterns.
        Only matches against the URL path (not the full URL) to avoid
        false positives from domain/query string matches."""
        try:
            url_path = urlparse(url).path.lower()
        except Exception:
            url_path = url.lower()
        for pattern in self._ai_skip_patterns:
            # Match against path segments only, not arbitrary substrings
            if pattern.startswith('/'):
                # Exact path prefix match
                if url_path.startswith(pattern):
                    return True
            else:
                # Match as a path segment (bounded by / or end)
                if f'/{pattern}' in url_path or url_path.endswith(pattern):
                    return True
        return False

    def _ai_analyze_login_page(self, page_html):
        """Use AI to analyze login page and return form field mappings."""
        if not self.ai_api_key:
            return None

        # Truncate HTML for API
        html_sample = page_html[:10000] if len(page_html) > 10000 else page_html

        prompt = f"""Analyze this login page HTML and extract the form field information.

HTML:
```html
{html_sample}
```

Username to use: {self.username}
Password to use: {self.password}

Return ONLY valid JSON (no markdown, no explanation):
{{
    "form_action": "the form action URL or empty string",
    "form_method": "POST or GET",
    "fields": {{
        "actual_field_name": "value_to_submit"
    }},
    "submit_selector": "CSS selector for submit button"
}}

IMPORTANT:
- Include ALL form fields (hidden fields like CSRF tokens with their values, username field, password field)
- Use actual field names from the HTML (e.g., "csrfmiddlewaretoken", "username", "password")
- For username field, use value: "{self.username}"
- For password field, use value: "{self.password}"
- Include hidden fields with their actual values from the HTML"""

        response = self._call_ai(prompt)
        if response:
            try:
                import json
                # Clean response
                clean = response.strip()
                if clean.startswith('```'):
                    clean = '\n'.join(clean.split('\n')[1:-1])
                return json.loads(clean)
            except:
                pass
        return None

    def _ai_profile_app(self, page_html, page_url):
        """Use AI to profile the application and understand its structure."""
        if not self.ai_api_key:
            return None

        html_sample = page_html[:8000] if len(page_html) > 8000 else page_html

        prompt = f"""Analyze this web application page and provide profiling information.

URL: {page_url}
HTML (truncated):
```html
{html_sample}
```

Return ONLY valid JSON:
{{
    "app_type": "framework name (Django, Flask, Rails, PHP, Node, React, Vue, etc.)",
    "is_spa": true/false,
    "auth_type": "session/jwt/oauth/none",
    "skip_url_patterns": ["patterns", "to", "skip", "like", "logout", "signout", "delete"],
    "priority_url_patterns": ["patterns", "to", "prioritize", "like", "admin", "api", "dashboard"],
    "session_indicators": ["text that indicates logged in state like 'Logout', 'Sign out'"],
    "main_navigation_selector": "CSS selector for main navigation menu"
}}"""

        response = self._call_ai(prompt)
        if response:
            try:
                import json
                clean = response.strip()
                if clean.startswith('```'):
                    clean = '\n'.join(clean.split('\n')[1:-1])
                profile = json.loads(clean)
                self._ai_app_profile = profile
                # Store skip patterns
                _skip_pats = []
                for pattern in profile.get('skip_url_patterns', []):
                    if pattern:
                        self._ai_skip_patterns.add(pattern.lower())
                        _skip_pats.append(pattern.lower())
                print(f"[AI] App profiled: {profile.get('app_type', 'Unknown')} (SPA: {profile.get('is_spa', False)})")
                if _skip_pats:
                    print(f"[AI] Skip patterns set: {', '.join(_skip_pats)}")
                    self._log_scan('info', f'AI skip patterns: {", ".join(_skip_pats)}',
                                   {'patterns': _skip_pats})
                return profile
            except Exception as e:
                print(f"[AI] Profile parse error: {e}")
        return None

    def _ai_should_skip_url(self, url):
        """Check if URL should be skipped based on AI profile.
        Uses path-only matching to avoid false positives from domain/query."""
        if not self._ai_skip_patterns:
            return False
        try:
            url_path = urlparse(url).path.lower()
        except Exception:
            url_path = url.lower()
        for pattern in self._ai_skip_patterns:
            # Match against path segments, not arbitrary substrings
            pattern_lower = pattern.lower()
            path_parts = [p for p in url_path.split('/') if p]
            pat_parts = [p for p in pattern_lower.split('/') if p]
            if pat_parts and all(pp in path_parts for pp in pat_parts):
                return True
        return False

    # =========================================================================
    # AI NAVIGATOR — Smart crawl decision-making powered by LLM
    # Instead of brute-force clicking everything on every page, the AI
    # analyzes the page DOM once and returns:
    #   1. Which elements are security-relevant (prioritize)
    #   2. Which elements are duplicate nav (skip)
    #   3. Whether the page has unique content vs duplicate layout
    #   4. Suggested interaction strategy (click, fill form, expand, skip)
    # =========================================================================

    def _ai_navigate_page(self, page, url, queue, depth):
        """Use AI to intelligently decide what to interact with on this page.
        Returns a dict with: priority_elements, skip_elements, is_duplicate, strategy."""
        if not self.ai_api_key:
            return None
        if page.is_closed():
            return None

        # Check if we already have a cached decision for this URL pattern
        url_pattern = self._get_url_pattern(url)
        if url_pattern in self._ai_nav_decisions:
            cached = self._ai_nav_decisions[url_pattern]
            print(f"[AI-NAV] Using cached decision for pattern: {url_pattern}")
            return cached

        try:
            # Extract a compact DOM summary for the AI (not full HTML — too big)
            dom_summary = page.evaluate(r"""
                () => {
                    const result = {links: [], buttons: [], forms: [], inputs: [], selects: [], iframes: []};

                    // Links (deduplicated by href)
                    const seenHrefs = new Set();
                    document.querySelectorAll('a[href]').forEach(a => {
                        const href = a.getAttribute('href') || '';
                        if (seenHrefs.has(href) || href.startsWith('#') || href.startsWith('javascript:')) return;
                        seenHrefs.add(href);
                        const text = (a.textContent || '').trim().substring(0, 60);
                        const vis = a.offsetParent !== null;
                        result.links.push({href, text, visible: vis});
                    });

                    // Buttons
                    document.querySelectorAll('button, [role="button"], input[type="button"], input[type="submit"]').forEach(b => {
                        const text = (b.textContent || b.value || '').trim().substring(0, 60);
                        const aria = b.getAttribute('aria-label') || '';
                        const onclick = (b.getAttribute('onclick') || '').substring(0, 80);
                        const cls = (b.className || '').substring(0, 60);
                        const vis = b.offsetParent !== null;
                        result.buttons.push({text, aria, onclick, cls, visible: vis});
                    });

                    // Forms
                    document.querySelectorAll('form').forEach(f => {
                        const action = f.getAttribute('action') || '';
                        const method = f.getAttribute('method') || 'GET';
                        const inputs = [];
                        f.querySelectorAll('input, textarea, select').forEach(i => {
                            inputs.push({
                                type: i.type || i.tagName.toLowerCase(),
                                name: i.name || '',
                                id: i.id || '',
                                placeholder: i.placeholder || ''
                            });
                        });
                        result.forms.push({action, method, inputs});
                    });

                    // File upload inputs
                    document.querySelectorAll('input[type="file"]').forEach(f => {
                        result.inputs.push({type: 'file', name: f.name, accept: f.accept || '*'});
                    });

                    // Iframes (potential admin panels, embedded apps)
                    document.querySelectorAll('iframe').forEach(f => {
                        result.iframes.push({src: f.src || '', id: f.id || ''});
                    });

                    // Page metadata
                    result.title = document.title || '';
                    result.meta_desc = (document.querySelector('meta[name="description"]') || {}).content || '';
                    result.bodyClasses = (document.body.className || '').substring(0, 100);

                    // Truncate for API
                    result.links = result.links.slice(0, 50);
                    result.buttons = result.buttons.slice(0, 30);
                    return result;
                }
            """)

            # Build a compact prompt
            links_summary = '\n'.join([
                f"  [{i}] {l['href'][:80]} — \"{l['text'][:40]}\" {'(hidden)' if not l.get('visible') else ''}"
                for i, l in enumerate(dom_summary.get('links', [])[:40])
            ])
            buttons_summary = '\n'.join([
                f"  [{i}] \"{b['text'][:40]}\" aria=\"{b['aria'][:30]}\" class=\"{b['cls'][:30]}\" {'onclick' if b.get('onclick') else ''} {'(hidden)' if not b.get('visible') else ''}"
                for i, b in enumerate(dom_summary.get('buttons', [])[:20])
            ])
            forms_summary = '\n'.join([
                f"  [{i}] action={f['action'][:60]} method={f['method']} fields=[{', '.join(inp['name'] or inp['type'] for inp in f.get('inputs', [])[:8])}]"
                for i, f in enumerate(dom_summary.get('forms', []))
            ])
            iframes_summary = '\n'.join([
                f"  [{i}] src={iframe['src'][:80]}"
                for i, iframe in enumerate(dom_summary.get('iframes', []))
            ])

            visited_count = len(self.visited)
            queued_count = len(queue)

            prompt = f"""You are a web security crawler AI navigator. Analyze this page and make crawling decisions.

URL: {url}
Title: {dom_summary.get('title', '')}
Pages visited: {visited_count}, Queued: {queued_count}

LINKS ({len(dom_summary.get('links', []))} total):
{links_summary}

BUTTONS ({len(dom_summary.get('buttons', []))} total):
{buttons_summary}

FORMS ({len(dom_summary.get('forms', []))} total):
{forms_summary}

IFRAMES: {iframes_summary or 'none'}
FILE UPLOADS: {len(dom_summary.get('inputs', []))} found

Return ONLY valid JSON (no markdown, no explanation):
{{
    "priority_links": [0, 3, 7],
    "skip_links": [1, 2, 5],
    "priority_buttons": [0],
    "skip_buttons": [2, 3],
    "has_forms": true/false,
    "has_file_upload": true/false,
    "is_admin_panel": true/false,
    "is_login_page": true/false,
    "is_duplicate_layout": true/false,
    "security_notes": "brief note about what's interesting on this page for pentesting",
    "suggested_actions": ["expand_menu", "fill_forms", "check_iframes", "test_file_upload"]
}}

RULES:
- priority_links: indices of links most likely to lead to NEW unique content or security-relevant pages (admin, API, settings, file upload, user data)
- skip_links: indices of links that are clearly static/marketing content, social media, or external sites
- priority_buttons: buttons worth clicking (expand menus, toggle admin features, reveal hidden content)
- skip_buttons: navigation buttons already covered by links, decorative buttons, logout/delete buttons
- is_duplicate_layout: true if this looks like a template page with same nav as other pages (e.g. school sub-sites with identical headers)
- Focus on finding: forms, file uploads, admin panels, API endpoints, authentication bypasses, hidden parameters"""

            response = self._call_ai(prompt, max_tokens=1500)
            if not response:
                return None

            # Parse AI response
            clean = response.strip()
            if clean.startswith('```'):
                clean = '\n'.join(clean.split('\n')[1:-1])

            import json
            decision = json.loads(clean)

            # Cache the decision for this URL pattern
            self._ai_nav_decisions[url_pattern] = decision

            # Log AI decision
            priority_count = len(decision.get('priority_links', []))
            skip_count = len(decision.get('skip_links', []))
            notes = decision.get('security_notes', '')[:100]
            is_dup = decision.get('is_duplicate_layout', False)
            print(f"[AI-NAV] Page analysis: {priority_count} priority, {skip_count} skip, dup={is_dup}")
            if notes:
                print(f"[AI-NAV] Security: {notes}")

            # Apply priority decisions — enqueue priority links first
            links = dom_summary.get('links', [])
            for idx in decision.get('priority_links', []):
                if isinstance(idx, int) and 0 <= idx < len(links):
                    href = links[idx].get('href', '')
                    normalized = self._normalize_url(url, href)
                    if normalized and normalized not in self.visited:
                        if self._is_allowed_url(normalized):
                            self._enqueue_url(queue, normalized, depth + 1, priority=True)

            # Mark skip links so they get deprioritized
            skip_indices = set(decision.get('skip_links', []))
            for idx, link in enumerate(links):
                if idx not in skip_indices:
                    href = link.get('href', '')
                    normalized = self._normalize_url(url, href)
                    if normalized and normalized not in self.visited:
                        if self._is_allowed_url(normalized):
                            self._enqueue_url(queue, normalized, depth + 1, priority=False)

            # Log if admin panel or interesting page detected
            if decision.get('is_admin_panel'):
                print(f"[AI-NAV] *** ADMIN PANEL DETECTED: {url}")
                self._log_scan('info', f'AI detected admin panel: {url}', {'url': url, 'type': 'admin'})
            if decision.get('has_file_upload'):
                print(f"[AI-NAV] *** FILE UPLOAD DETECTED: {url}")
                self._log_scan('info', f'AI detected file upload: {url}', {'url': url, 'type': 'file_upload'})

            return decision

        except json.JSONDecodeError as e:
            print(f"[AI-NAV] JSON parse error: {e}")
            return None
        except Exception as e:
            print(f"[AI-NAV] Error: {e}")
            return None

    def _get_url_pattern(self, url):
        """Convert a URL to a pattern for caching AI decisions.
        e.g. /o/kes/page/staff-directory -> /o/*/page/*"""
        try:
            parsed = urlparse(url)
            parts = parsed.path.strip('/').split('/')
            # Keep first 2 segments, wildcard the rest
            if len(parts) <= 2:
                return parsed.netloc + parsed.path
            pattern_parts = parts[:2] + ['*'] * (len(parts) - 2)
            return parsed.netloc + '/' + '/'.join(pattern_parts)
        except Exception:
            return url

    def _ai_should_deep_explore(self, page, url):
        """Ask AI whether this page needs deep URL discovery (event triggering, JS parsing)
        or if it's a standard content page that only needs link extraction.
        This prevents wasting time on brute-force event triggering for simple pages."""
        if not self.ai_api_key:
            return True  # Default to exploring if no AI

        # Check page content hash — if we've seen nearly identical content, skip deep explore
        content_hash = self._get_page_content_hash(page)
        if content_hash and content_hash in self._page_content_hashes:
            prev_url = self._page_content_hashes[content_hash]
            print(f"[AI-NAV] Duplicate content detected (same as {prev_url[:60]}), skipping deep explore")
            return False
        if content_hash:
            self._page_content_hashes[content_hash] = url

        # Use cached nav decision if available
        url_pattern = self._get_url_pattern(url)
        if url_pattern in self._ai_nav_decisions:
            decision = self._ai_nav_decisions[url_pattern]
            if decision.get('is_duplicate_layout'):
                return False  # AI already said this is a duplicate layout
            return True

        return True  # Default to exploring

    def _build_form_payload(self, inputs):
        payload = {}
        select_fields = []
        for inp in inputs or []:
            name = (inp.get("name") or "").strip()
            if not name:
                continue
            itype = (inp.get("type") or "").lower()
            value = inp.get("value")

            if value is None or value == "":
                if itype in ("checkbox", "radio"):
                    value = "on"
                elif itype == "file":
                    continue
                elif itype == "select" and isinstance(inp.get("options"), list):
                    select_fields.append({
                        "name": name,
                        "options": inp.get("options") or []
                    })
                    opt = inp.get("options")[0] if inp.get("options") else {}
                    value = opt.get("value") or opt.get("label") or ""
                else:
                    # DAST: send empty string so form has all keys; servers expect username/password etc. to be present
                    value = ""

            payload[name] = value
        return payload, select_fields

    def _explore_dropdown_navigation(self, page, base_url, queue, depth):
        """Explore pages accessible via dropdown/select navigation (like bWAPP's bug selector)."""
        if not self.submit_forms:
            return

        try:
            # Find forms with select elements that have many options (likely navigation)
            dropdown_forms = page.evaluate(r"""
                () => {
                    const results = [];
                    document.querySelectorAll('form').forEach(form => {
                        const selects = form.querySelectorAll('select');
                        selects.forEach(select => {
                            const options = select.querySelectorAll('option');
                            // Navigation dropdowns typically have many options
                            if (options.length > 5) {
                                const optionData = [];
                                options.forEach(opt => {
                                    const val = opt.value || '';
                                    const text = opt.textContent.trim();
                                    // Skip category headers (typically have values like 0, 1, or special markers)
                                    if (val && val !== '0' && !text.startsWith('/') && !text.startsWith('---')) {
                                        optionData.push({value: val, text: text.substring(0, 50)});
                                    }
                                });
                                if (optionData.length > 0) {
                                    results.push({
                                        action: form.action || '',
                                        method: form.method || 'GET',
                                        selectName: select.name || '',
                                        options: optionData
                                    });
                                }
                            }
                        });
                    });
                    return results;
                }
            """)

            if not dropdown_forms:
                return

            # Limit how many dropdown options to explore
            try:
                max_options = int(os.getenv("HEADLESS_DROPDOWN_LIMIT", "200"))
            except ValueError:
                max_options = 200

            # Remember the page that contains the dropdown so we can reliably
            # navigate back after each form submission instead of using the
            # fragile go_back() which often fails after POST navigations.
            dropdown_page_url = page.url

            explored = 0
            consecutive_failures = 0
            for form_info in dropdown_forms:
                select_name = form_info.get('selectName', '')
                options = form_info.get('options', [])
                action = form_info.get('action', '')
                method = (form_info.get('method', 'GET') or 'GET').upper()

                if not select_name or not options:
                    continue

                print(f"[+] Found navigation dropdown '{select_name}' with {len(options)} options")

                for opt in options:
                    if explored >= max_options:
                        break
                    if consecutive_failures >= 5:
                        print(f"[!] Too many consecutive failures in dropdown exploration, stopping")
                        break

                    opt_value = opt.get('value', '')
                    opt_text = opt.get('text', '')

                    if not opt_value:
                        continue

                    try:
                        # Navigate fresh to the dropdown page each iteration.
                        # This is more reliable than go_back() which breaks
                        # after POST form submissions on many web apps.
                        page.goto(dropdown_page_url, wait_until='networkidle', timeout=self.timeout)

                        # Select the option
                        page.select_option(f'select[name="{select_name}"]', value=opt_value)

                        # Find and click submit button
                        submit_clicked = False
                        for submit_sel in ['button[type="submit"]', 'input[type="submit"]', 'button[name="form"]', 'input[name="form"]']:
                            try:
                                btn = page.locator(submit_sel).first
                                if btn.is_visible():
                                    btn.click()
                                    submit_clicked = True
                                    break
                            except:
                                continue

                        if not submit_clicked:
                            consecutive_failures += 1
                            continue

                        # Wait for navigation
                        try:
                            page.wait_for_load_state('networkidle', timeout=5000)
                        except:
                            page.wait_for_timeout(1000)

                        # Get the resulting URL and add to queue
                        result_url = page.url
                        if result_url and result_url != dropdown_page_url and result_url not in self.visited:
                            # Skip logout pages during exploration — they destroy the session
                            _rp = urlparse(result_url).path.lower()
                            if any(kw in _rp for kw in ('logout', 'signout', 'sign_out', 'log_out')):
                                print(f"[*] Dropdown skipping logout URL: {result_url}")
                                self._add_endpoint_entry(result_url, source="dropdown")
                                continue
                            if self._enqueue_url(queue, result_url, depth + 1):
                                explored += 1
                                print(f"[+] Dropdown [{explored}] {opt_text}: {result_url}")

                                # Extract forms and input points while page is authenticated
                                try:
                                    for frame in page.frames:
                                        try:
                                            data = self._extract_from_frame(frame)
                                        except Exception:
                                            continue
                                        if not isinstance(data, dict):
                                            continue
                                        for form in data.get("forms", []):
                                            action = self._normalize_url(result_url, form.get("action") or result_url)
                                            if not action:
                                                action = result_url
                                            form_entry = {
                                                "url": result_url,
                                                "action": action,
                                                "method": form.get("method", "GET"),
                                                "inputs": form.get("inputs", []),
                                            }
                                            self._add_form(form_entry)
                                            field_names = [i.get('name','') for i in form_entry['inputs'] if i.get('name')]
                                            if field_names:
                                                self._log_scan('info', f'Form found: {form_entry["method"].upper()} {action[:80]} ({len(field_names)} fields: {", ".join(field_names[:5])})', {
                                                    'url': result_url, 'action': action, 'method': form_entry['method'], 'fields': field_names
                                                })
                                            for inp in form_entry["inputs"]:
                                                if not inp.get("name"):
                                                    continue
                                                self._add_input_point({
                                                    "page": result_url,
                                                    "action": action,
                                                    "method": form_entry["method"],
                                                    "name": inp.get("name"),
                                                    "input_type": inp.get("type", "text"),
                                                    "value": inp.get("value", ""),
                                                })
                                        for inp in data.get("looseInputs", []):
                                            if inp.get("name"):
                                                self._add_input_point({
                                                    "page": result_url,
                                                    "action": result_url,
                                                    "method": "GET",
                                                    "name": inp.get("name"),
                                                    "input_type": inp.get("type", "text"),
                                                    "value": inp.get("value", ""),
                                                })
                                except Exception as _extr_err:
                                    pass  # Don't let extraction errors stop dropdown exploration

                                # Submit forms via POST to generate real proxy traffic
                                try:
                                    page.evaluate("""() => {
                                        const forms = document.querySelectorAll('form');
                                        const submitted = [];
                                        forms.forEach(form => {
                                            const method = (form.getAttribute('method') || 'GET').toUpperCase();
                                            const action = form.getAttribute('action') ? new URL(form.getAttribute('action'), window.location.href).href : window.location.href;
                                            // Skip nav forms (security_level/bug selectors) and GET forms
                                            const fieldNames = Array.from(form.querySelectorAll('input[name],textarea[name],select[name]'))
                                                .map(el => el.name).filter(Boolean);
                                            const isNavForm = fieldNames.length === 1 &&
                                                (fieldNames[0] === 'security_level' || fieldNames[0] === 'bug');
                                            if (isNavForm) return;
                                            // Skip login/registration forms to preserve session
                                            const hasPassword = fieldNames.some(n => n === 'password' || n === 'pass' || n === 'passwd');
                                            const hasUser = fieldNames.some(n => ['login','username','user','email','uname'].includes(n));
                                            if (hasPassword && hasUser) return;
                                            // Skip password change/reset forms — submitting them destroys credentials
                                            const hasPwdChange = fieldNames.some(n => ['password_new','new_password','newpassword','password1','password_conf','confirm_password','password2'].includes(n));
                                            if (hasPwdChange) return;
                                            // Build form data with "." as test value
                                            const params = new URLSearchParams();
                                            form.querySelectorAll('input[name],textarea[name],select[name]').forEach(el => {
                                                if (el.type === 'file') return;
                                                if (el.type === 'hidden' || el.type === 'submit') {
                                                    params.append(el.name, el.value || '.');
                                                } else if (el.tagName === 'SELECT') {
                                                    params.append(el.name, el.value || '.');
                                                } else {
                                                    params.append(el.name, '.');
                                                }
                                            });
                                            if (params.toString()) {
                                                if (method === 'POST') {
                                                    fetch(action, {
                                                        method: 'POST',
                                                        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                                                        body: params.toString(),
                                                        credentials: 'include'
                                                    }).catch(() => {});
                                                } else {
                                                    fetch(action + '?' + params.toString(), {
                                                        method: 'GET',
                                                        credentials: 'include'
                                                    }).catch(() => {});
                                                }
                                                submitted.push(method + ' ' + action);
                                            }
                                        });
                                        return submitted;
                                    }""")
                                    page.wait_for_timeout(300)  # Brief wait for fetch to complete
                                except Exception:
                                    pass  # Don't let submission errors stop exploration

                                # Send heartbeat so watchdog doesn't kill us
                                if hasattr(self, '_progress_callback') and self._progress_callback:
                                    try:
                                        self._progress_callback({
                                            'status': 'crawling',
                                            'current_url': result_url,
                                            'message': f'Exploring dropdown navigation ({explored} pages)...',
                                        })
                                    except Exception:
                                        pass

                        consecutive_failures = 0

                    except Exception as e:
                        consecutive_failures += 1
                        continue

                if consecutive_failures >= 5:
                    break

            if explored > 0:
                print(f"[+] Explored {explored} dropdown navigation options")
                # Extract cookies from authenticated browser context
                try:
                    self._extract_cookies(page.context)
                except Exception:
                    pass

        except Exception as e:
            print(f"[!] Error exploring dropdowns: {e}")

    def _submit_forms(self, context, base_url, forms, queue, depth):
        if not self.submit_forms:
            return
        try:
            limit = int(os.getenv("HEADLESS_FORM_SUBMIT_LIMIT", "50"))
        except ValueError:
            limit = 50
        if limit <= 0:
            return

        try:
            option_limit = int(os.getenv("HEADLESS_FORM_OPTION_LIMIT", "50"))
        except ValueError:
            option_limit = 50

        for form in forms or []:
            if self._submit_count >= limit:
                break
            action = self._normalize_url(base_url, form.get("action") or base_url)
            method = (form.get("method") or "GET").upper()
            if not action or not self._is_allowed_url(action):
                continue
            if method not in ("GET", "POST"):
                continue
            # Skip login/registration forms to preserve authenticated session
            field_names = [i.get("name", "").lower() for i in form.get("inputs", []) if i.get("name")]
            _has_pwd = any(n in ('password', 'pass', 'passwd', 'password_conf') for n in field_names)
            _has_usr = any(n in ('login', 'username', 'user', 'email', 'uname') for n in field_names)
            if _has_pwd and _has_usr:
                continue
            # Skip password change/reset forms — submitting them changes auth credentials
            _has_pwd_new = any(n in ('password_new', 'new_password', 'newpassword', 'password1',
                                     'password_conf', 'confirm_password', 'password2',
                                     'password_new_conf') for n in field_names)
            if _has_pwd_new:
                continue
            form_key = (action, method, tuple(sorted([i.get("name","") for i in form.get("inputs", []) if i.get("name")])))
            if form_key in self._submitted_forms:
                continue

            # Per-URL cap: don't hammer the same endpoint more than N times
            try:
                per_url_cap = int(os.getenv("HEADLESS_FORM_PER_URL_CAP", "5"))
            except ValueError:
                per_url_cap = 5
            if per_url_cap > 0 and self._submitted_action_counts.get(action, 0) >= per_url_cap:
                continue

            payload, select_fields = self._build_form_payload(form.get("inputs", []))
            payloads = [payload]

            if select_fields and option_limit > 0:
                for sel in select_fields:
                    name = sel.get("name")
                    options = sel.get("options") or []
                    for opt in options[:option_limit]:
                        if not name:
                            continue
                        opt_val = opt.get("value") or opt.get("label") or ""
                        if not opt_val:
                            continue
                        p = dict(payload)
                        p[name] = opt_val
                        payloads.append(p)

            for payload_item in payloads:
                if self._submit_count >= limit:
                    break
                if method == "GET":
                    try:
                        if payload_item:
                            from urllib.parse import urlencode
                            action_url = action
                            query = urlencode(payload_item, doseq=True)
                            sep = "&" if "?" in action_url else "?"
                            action_url = f"{action_url}{sep}{query}"
                        else:
                            action_url = action
                        self._enqueue_url(queue, action_url, depth + 1)
                        self._submit_count += 1
                    except Exception:
                        continue
                else:
                    try:
                        resp = context.request.post(action, data=payload_item, timeout=10000)
                        if resp:
                            resp_url = resp.url
                            if resp_url:
                                self._enqueue_url(queue, resp_url, depth + 1)
                            try:
                                location = resp.headers.get("location") or resp.headers.get("Location")
                                if location:
                                    loc_url = self._normalize_url(action, location)
                                    if loc_url:
                                        self._enqueue_url(queue, loc_url, depth + 1)
                            except Exception:
                                pass
                        self._submit_count += 1
                    except Exception:
                        continue

            self._submitted_forms.add(form_key)
            self._submitted_action_counts[action] = self._submitted_action_counts.get(action, 0) + len(payloads)

    def _probe_browser_forms(self, page, current_url, queue, depth):
        """Actively probe forms at the browser level by typing 'Test' and clicking buttons."""
        if not self.submit_forms or page.is_closed():
            return
        if not self._consume_interaction_budget(current_url, n=1):
            return
        # If we're currently on a PDF/asset viewer, recover before probing forms.
        self._recover_if_asset_navigation(page, current_url)

        try:
            # Find all forms on the page
            forms = page.query_selector_all("form")
            if not forms:
                return

            for i, form in enumerate(forms):
                try:
                    if page.is_closed():
                        return
                    if not self._consume_interaction_budget(current_url, n=1):
                        return
                    
                    # Generate a unique key for this form on this page to avoid infinite loops
                    # We use page URL + form index as a simple identifier
                    form_id = f"{current_url}_form_{i}"
                    if form_id in self._probed_forms:
                        continue
                    
                    self._probed_forms.add(form_id)

                    # Skip login/logout forms — probing them destroys the authenticated session
                    form_action_raw = (form.get_attribute("action") or "").lower()
                    form_action_full = urljoin(current_url, form_action_raw) if form_action_raw else current_url
                    _login_url_path = urlparse(self.login_url).path.lower() if self.login_url else ''
                    _form_action_path = urlparse(form_action_full).path.lower()
                    _is_login_form = False
                    if _login_url_path and _login_url_path == _form_action_path:
                        _is_login_form = True
                    if not _is_login_form:
                        # Also detect by field names
                        _field_names = set()
                        try:
                            for _fi in form.query_selector_all("input"):
                                _fn = (_fi.get_attribute("name") or "").lower()
                                if _fn:
                                    _field_names.add(_fn)
                        except:
                            pass
                        if 'password' in _field_names and ('login' in _field_names or 'username' in _field_names or 'user' in _field_names or 'email' in _field_names):
                            _is_login_form = True
                    if _is_login_form:
                        print(f"[*] [Browser Probe] Skipping login form on {current_url} to preserve session")
                        continue

                    # Skip password change/reset forms — submitting them destroys credentials
                    _pwd_change_fields = {'password_new', 'new_password', 'newpassword', 'password1',
                                          'password_conf', 'confirm_password', 'password2'}
                    if _field_names & _pwd_change_fields:
                        print(f"[*] [Browser Probe] Skipping password change form on {current_url}")
                        continue

                    # 1. Fill visible input fields
                    inputs = form.query_selector_all("input:not([type='hidden']), textarea")
                    has_filled = False
                    for inp in inputs:
                        try:
                            if not inp.is_visible():
                                continue

                            itype = (inp.get_attribute("type") or "text").lower()
                            name = inp.get_attribute("name") or inp.get_attribute("id") or ""

                            if itype == "password":
                                current_val = inp.get_attribute("value") or ""
                                if not current_val:
                                    inp.fill("password")
                                    has_filled = True
                            elif itype in ("text", "search", "url", "tel", "email", "textarea") or not itype:
                                current_val = inp.get_attribute("value") or ""
                                if not current_val:
                                    inp.fill("1")
                                    has_filled = True
                        except:
                            continue

                    # 1b. Fill native <select> elements — pick first non-empty option
                    try:
                        selects = form.query_selector_all("select")
                        for sel_el in selects:
                            try:
                                if not sel_el.is_visible():
                                    continue
                                opts = sel_el.query_selector_all("option")
                                for opt in opts:
                                    val = opt.get_attribute("value") or ""
                                    if val:
                                        sel_el.select_option(value=val)
                                        has_filled = True
                                        break
                            except Exception:
                                continue
                    except Exception:
                        pass

                    # 1c. Interact with Bootstrap/custom dropdowns ([data-toggle="dropdown"])
                    # These back hidden inputs rather than native <select> elements.
                    try:
                        toggles = page.query_selector_all(
                            '[data-toggle="dropdown"]:visible, [data-bs-toggle="dropdown"]:visible'
                        )
                        for toggle in toggles:
                            try:
                                if not toggle.is_visible():
                                    continue
                                toggle.click()
                                page.wait_for_timeout(300)
                                # Click first visible menu option
                                first_item = page.locator(
                                    '.dropdown-menu.show a, .dropdown-menu[style*="display: block"] a, '
                                    '.open > .dropdown-menu a'
                                ).first
                                if first_item.count() and first_item.is_visible():
                                    first_item.click()
                                    page.wait_for_timeout(200)
                                    has_filled = True
                                else:
                                    # Close the menu so it doesn't block submit
                                    page.keyboard.press("Escape")
                            except Exception:
                                continue
                    except Exception:
                        pass

                    # 2. Find and click the submit button
                    submit_button = None
                    # Common selectors for submit buttons
                    submit_selectors = [
                        "button[type='submit']", "input[type='submit']", 
                        "button:has-text('Go')", "button:has-text('Submit')",
                        "button:has-text('Login')", "input:has-text('Login')",
                        "button.btn-primary", "button.btn"
                    ]
                    
                    for sel in submit_selectors:
                        try:
                            btn = form.query_selector(sel)
                            if btn and btn.is_visible():
                                submit_button = btn
                                break
                        except:
                            continue
                            
                    if submit_button:
                        # Collect form data before submit for proxy logging
                        form_method = (form.get_attribute("method") or "GET").upper()
                        form_action = form.get_attribute("action") or current_url
                        if form_action and not form_action.startswith("http"):
                            form_action = urljoin(current_url, form_action)
                        filled_data = {}
                        try:
                            all_inputs = form.query_selector_all("input, select, textarea")
                            for fi in all_inputs:
                                try:
                                    fname = fi.get_attribute("name")
                                    if not fname:
                                        continue
                                    try:
                                        fval = fi.input_value()
                                    except Exception:
                                        fval = fi.get_attribute("value") or ""
                                    filled_data[fname] = fval
                                except Exception:
                                    continue
                        except Exception:
                            pass

                        print(f"[*] [Browser Probe] Typing 'Test' and clicking submit on {current_url} (form={form_method} {form_action[:60]}, data={filled_data})")
                        self._log_scan('info', f'Browser probe: {form_method} {form_action[:80]}', {'url': current_url, 'method': form_method, 'data': filled_data})
                        submit_button.click()

                        # Wait for navigation or results
                        try:
                            page.wait_for_load_state('domcontentloaded', timeout=3000)
                            try:
                                page.wait_for_load_state('networkidle', timeout=1000)
                            except Exception:
                                pass
                        except:
                            page.wait_for_timeout(1000)
                        # If submit navigated into a PDF/asset viewer, recover.
                        self._recover_if_asset_navigation(page, current_url)

                        # Log form submission to proxy for visibility
                        try:
                            if filled_data:
                                if form_method == "GET":
                                    submit_url = form_action + ("?" if "?" not in form_action else "&") + urlencode(filled_data)
                                    submit_body = ""
                                else:
                                    submit_url = form_action
                                    submit_body = urlencode(filled_data)
                                parsed_su = urlparse(submit_url)
                                su_path = parsed_su.path or "/"
                                if parsed_su.query:
                                    su_path += f"?{parsed_su.query}"
                                proxy_entry = {
                                    'id': f"probe_{int(time.time() * 1000)}_{len(self._proxy_logs)}",
                                    'url': submit_url,
                                    'method': form_method,
                                    'type': 'document',
                                    'request_headers': (
                                        {
                                            'Content-Type': 'application/x-www-form-urlencoded',
                                            # Preserve session context for later scanning (e.g. PHPSESSID, security_level).
                                            'Cookie': self._build_cookie_header(),
                                        }
                                        if form_method == "POST"
                                        else {'Cookie': self._build_cookie_header()}
                                    ),
                                    'request_body': submit_body,
                                    'raw_request': f"{form_method} {su_path} HTTP/1.1\nHost: {parsed_su.netloc}" + (f"\n\n{submit_body}" if submit_body else ""),
                                    'status': 200,
                                    'response_headers': {},
                                    'response_body': '',
                                    'timestamp': time.time()
                                }
                                self._proxy_logs.append(proxy_entry)
                        except Exception as _pe:
                            print(f"[!] Proxy log error: {_pe}")

                        # If we navigated away, add new URL to queue and go back
                        if page.url != current_url:
                            new_url = page.url
                            if self.skip_asset_urls and self._is_probably_asset_url(new_url):
                                pass
                            else:
                                self._enqueue_url(queue, new_url, depth + 1)

                            # Go back to continue probing other forms or the next page
                            try:
                                page.goto(current_url, wait_until="domcontentloaded", timeout=5000)
                            except:
                                pass
                except:
                    continue
        except Exception as e:
            print(f"[!] Browser probe error: {e}")

    def _enumerate_form_select_options(self, page, current_url, queue, depth, max_options=100):
        """Discover navigation targets from <select> dropdowns using in-page fetch().

        Many web apps (e.g. bWAPP, admin portals) use a <select> dropdown whose
        option values are opaque IDs (not URLs) that map server-side to real pages.
        The normal link extractor skips these because they don't look like hrefs.

        This method uses fetch() inside the browser context to POST/GET the form
        for every option value and read the final redirect URL — without actually
        navigating the browser.  This is orders-of-magnitude faster than click+wait+
        go-back for each option and does NOT flood the proxy with discovery requests.

        Safe-guards:
        - Skips well-known non-navigation selects (security_level, language, …).
        - Deduplicates via _probed_forms so each (page, select-name) pair is only
          enumerated once per crawl.
        - Caps at max_options per select.
        """
        if page.is_closed():
            return
        try:
            # Step 1: collect form/select metadata and base input values via JS.
            forms_info = page.evaluate("""
                () => {
                    const SKIP = new Set([
                        'security_level','security','level',
                        'lang','language','locale','theme','timezone','tz',
                        'per_page','page_size','limit','rows','size',
                        'sort','order','orderby','order_by',
                        'view','layout','format','output',
                    ]);
                    return Array.from(document.querySelectorAll('form')).map(form => {
                        // Collect all current non-select field values.
                        const baseInputs = {};
                        Array.from(form.querySelectorAll('input, textarea')).forEach(el => {
                            const n = el.name || el.id;
                            if (n) baseInputs[n] = el.value || '';
                        });
                        // Include submit button name/value (e.g. name="form" value="submit").
                        const btn = form.querySelector(
                            "button[type='submit'], input[type='submit']");
                        if (btn && btn.name) baseInputs[btn.name] = btn.value || '';

                        const selects = Array.from(form.querySelectorAll('select'))
                            .filter(s => !SKIP.has((s.name || '').toLowerCase()))
                            .map(s => ({
                                name: s.name || s.id || '',
                                options: Array.from(s.options)
                                    .map(o => o.value)
                                    .filter(v => v !== '' && v != null),
                            }))
                            .filter(s => s.name && s.options.length > 1);

                        const hasSubmit = !!(form.querySelector(
                            "button[type='submit'], input[type='submit'], " +
                            "button:not([type]), button[type='button']"));

                        if (!selects.length || !hasSubmit) return null;
                        return {
                            action:     form.action || location.href,
                            method:     (form.method || 'get').toUpperCase(),
                            baseInputs: baseInputs,
                            selects:    selects,
                        };
                    }).filter(Boolean);
                }
            """)
            if not forms_info:
                return

            for form_info in forms_info:
                action      = form_info.get('action', current_url)
                method      = form_info.get('method', 'GET')
                base_inputs = form_info.get('baseInputs', {})

                for sel_info in form_info.get('selects', []):
                    sel_name = sel_info.get('name', '')
                    opt_vals = sel_info.get('options', [])[:max_options]
                    if not sel_name or not opt_vals:
                        continue

                    enum_key = f"{current_url}|select_enum|{sel_name}"
                    if enum_key in self._probed_forms:
                        continue
                    self._probed_forms.add(enum_key)

                    # Step 2: fire all fetch() calls from inside the page in one shot.
                    # fetch() with redirect:'follow' + credentials:'include' gives us
                    # the final URL after the server redirect — no DOM rendering needed,
                    # no navigate-back cycle, proxy stays clean.
                    try:
                        urls = page.evaluate("""
                            async ({action, method, baseInputs, selName, optVals}) => {
                                const results = [];
                                for (const val of optVals) {
                                    try {
                                        const params = Object.assign({}, baseInputs,
                                                                      {[selName]: val});
                                        const body = new URLSearchParams(params);
                                        const resp = await fetch(action, {
                                            method:      method === 'GET' ? 'GET' : 'POST',
                                            body:        method !== 'GET' ? body : undefined,
                                            redirect:    'follow',
                                            credentials: 'include',
                                        });
                                        results.push(resp.url || null);
                                    } catch (_) {
                                        results.push(null);
                                    }
                                }
                                return results;
                            }
                        """, {
                            'action':     action,
                            'method':     method,
                            'baseInputs': base_inputs,
                            'selName':    sel_name,
                            'optVals':    opt_vals,
                        })
                    except Exception:
                        continue

                    # Step 3: queue every novel same-origin URL discovered.
                    discovered = 0
                    for new_url in (urls or []):
                        if (new_url and new_url != current_url
                                and new_url != action):
                            if self._enqueue_url(queue, new_url, depth + 1):
                                discovered += 1

                    if discovered:
                        print(f"[*] Select enum '{sel_name}' on {current_url}: "
                              f"{discovered} pages queued (fetch-based, no proxy noise)")
                        self._log_scan("info",
                            f"Select enum: '{sel_name}' -> {discovered} pages discovered",
                            {"url": current_url, "select": sel_name,
                             "discovered": discovered})

        except Exception as e:
            print(f"[!] Select option enumeration error: {e}")

    def _normalize_url(self, base, href):
        if not href:
            return ""
        if href.startswith("javascript:") or href.startswith("mailto:"):
            return ""
        url = urljoin(base, href).split("#", 1)[0]
        # Deduplicate query parameters to prevent accumulation
        # e.g. ?n=1&n=1&n=1 becomes ?n=1
        parsed = urlparse(url)
        if parsed.query:
            seen_params = {}
            for part in parsed.query.split('&'):
                if '=' in part:
                    key, val = part.split('=', 1)
                    if key not in seen_params:
                        seen_params[key] = val
                elif part and part not in seen_params:
                    seen_params[part] = ''
            if seen_params:
                deduped_query = '&'.join(f'{k}={v}' if v else k for k, v in seen_params.items())
                url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{deduped_query}"
            else:
                url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return url

    def _get_root_domain(self, host):
        host = host.split(":")[0]
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        return ".".join(parts[-2:])

    def get_scope_description(self) -> str:
        """Return human-readable scope: domain and whether subdomains are allowed. Stay in our domain."""
        try:
            parsed = urlparse(self.target_url)
            domain = parsed.netloc or "unknown"
            if self.allow_subdomains:
                return f"{domain} and *.{self.root_domain}"
            return f"{domain} only (no other domains or subdomains)"
        except Exception:
            return "unknown"

    # Paths that are clearly off-site junk (Google, Blogger, social share, etc.)
    _JUNK_PATH_PREFIXES = (
        '/_/scs/', '/share-post.g', '/email-blog/', '/b/post-preview',
        '/_/BloggerUi/', '/blogger.g', '/feeds/posts/',
        '/recaptcha/', '/maps/', '/analytics/',
        # GitHub-style repo paths that get routed through same-origin on SPA apps
        '/blob/', '/tree/', '/raw/', '/commit/', '/pull/', '/issues/',
        '/releases/', '/actions/', '/wiki/', '/compare/',
    )
    _JUNK_PATH_SUBSTRINGS = (
        'blogger', 'blogspot', 'googleapis', 'gstatic',
        'facebook.com', 'twitter.com', 'plus.google',
        'google.com', 'owasp.org', 'github.com', 'youtube.com',
        'linkedin.com', 'cloudflare', 'jquery.com', 'jsdelivr',
        'unpkg.com', 'cdnjs.com', 'maxcdn', 'bootstrapcdn',
        'fontawesome', 'googlesyndication', 'doubleclick',
        'googletagmanager', 'google-analytics', 'recaptcha',
    )

    def _is_allowed_url(self, url, base_url=None):
        """Only allow URLs that stay in our domain (and subdomains if allow_subdomains). Never leave target domain."""
        try:
            parsed = urlparse(url)
            base = base_url or self.target_url
            base_parsed = urlparse(base)
            base_host = base_parsed.netloc.split(":")[0]
            url_host = parsed.netloc.split(":")[0]

            # Port must match — localhost:4040 != localhost:7000
            base_port = base_parsed.port or (443 if base_parsed.scheme == 'https' else 80)
            url_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            if base_port != url_port:
                return False

            if not self.allow_subdomains:
                if url_host != base_host:
                    return False
            elif not (url_host == base_host or url_host == self.root_domain or url_host.endswith("." + self.root_domain)):
                return False
            # Skip obvious off-site junk paths served through same host
            path = parsed.path
            for prefix in self._JUNK_PATH_PREFIXES:
                if path.startswith(prefix):
                    return False
            url_lower = url.lower()
            for sub in self._JUNK_PATH_SUBSTRINGS:
                if sub in url_lower:
                    return False
            # Check AI skip patterns
            if self._ai_should_skip_url(url):
                return False
            return True
        except Exception:
            return False

    def _add_form(self, form_entry):
        """Add a form to self.forms with deduplication."""
        action = form_entry.get('action', form_entry.get('url', ''))
        method = form_entry.get('method', 'GET').upper()
        field_names = tuple(sorted(
            i.get('name', '') for i in form_entry.get('inputs', []) if i.get('name')
        ))
        key = (action, method, field_names)
        if key in self._seen_form_keys:
            return False
        self._seen_form_keys.add(key)
        self.forms.append(form_entry)
        return True

    def _add_input_point(self, ip):
        """Add an input_point to self.input_points with deduplication."""
        action = ip.get('action', ip.get('page', ''))
        method = ip.get('method', 'GET').upper()
        name = ip.get('name', '')
        key = (action, method, name)
        if key in self._seen_input_keys:
            return False
        self._seen_input_keys.add(key)
        self.input_points.append(ip)
        return True

    def _add_params(self, url):
        """Extract query string parameters from URL."""
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        if not params:
            return
        # Store parameters with base URL (without query string)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self.parameters.setdefault(base_url, [])
        self.parameters[base_url] = sorted(set(self.parameters[base_url] + params))

    def _add_endpoint_entry(self, url, source="headless", status=None, methods=None):
        """Add a discovered endpoint to the endpoint list with optional methods (deduplicated)."""
        if not url:
            return
        if not self._is_allowed_url(url):
            return
        # Normalize for dedup: strip query string to get base URL
        parsed = urlparse(url)
        canon = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if canon in self._seen_endpoint_urls:
            # Merge methods into existing entry if new methods provided
            if methods:
                for ep in self.endpoints:
                    if ep.get('url', '').split('?')[0] == canon.split('?')[0]:
                        existing = set(ep.get('methods', []))
                        existing.update(methods)
                        ep['methods'] = sorted(existing)
                        break
            return
        self._seen_endpoint_urls.add(canon)
        entry = {
            "url": url,
            "status": status,
            "source": source,
        }
        if methods:
            entry["methods"] = sorted(set(methods))
        self.endpoints.append(entry)
        self._add_params(url)

    def _build_cookie_header(self):
        """Build a Cookie header string from collected cookies."""
        try:
            parts = []
            for c in self.cookies or []:
                name = c.get("name")
                value = c.get("value")
                if name and value is not None:
                    parts.append(f"{name}={value}")
            return "; ".join(parts) if parts else ""
        except Exception:
            return ""

    def _rewrite_url_to_target(self, url):
        """Rewrite a backend URL to use the target host:port.

        Many apps (e.g. VulnerableApp-Facade) proxy to a backend on a
        different host:port.  Their JSON APIs expose the real backend URLs
        (e.g. http://127.0.0.1:9090/...) but the scanner should hit them
        through the facade (e.g. http://localhost:7070/...).
        Also handles Docker internal hostnames (e.g. VulnerableApp-base:9090).
        """
        try:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(url)
            target = urlparse(self.target_url)
            # If same host+port, no rewrite needed
            if parsed.netloc == target.netloc:
                return url
            # Always rewrite if host is non-routable (Docker internal, 127.x, 10.x, 172.x, 192.168.x)
            host = parsed.netloc.split(':')[0]
            is_internal = (
                host in ('127.0.0.1', 'localhost', '0.0.0.0')
                or host.startswith('10.')
                or host.startswith('172.')
                or host.startswith('192.168.')
                or not host.replace('.', '').replace('-', '').replace('_', '').isascii()
                or any(c.isalpha() for c in host)  # Docker hostname like VulnerableApp-base
            )
            if is_internal or parsed.netloc != target.netloc:
                return urlunparse((
                    target.scheme, target.netloc,
                    parsed.path, parsed.params, parsed.query, parsed.fragment
                ))
            return url
        except Exception:
            return url

    def _extract_urls_from_json(self, data, base_url, depth=0, max_depth=5):
        """Recursively extract URL-like strings from JSON data structures.

        Traverses nested arrays/objects looking for values that are URLs or
        URL paths.  Keys like 'url', 'href', 'path', 'endpoint' are checked
        first, then all other values are scanned.

        URLs pointing to a different host:port (common with proxy/facade apps)
        are rewritten to the target's host:port so the crawler can reach them.

        Returns:
            set[str]: Validated, absolute URLs found in *data*.
        """
        urls = set()
        if depth > max_depth:
            return urls

        if isinstance(data, str):
            s = data.strip()
            if s.startswith('http://') or s.startswith('https://'):
                # Try as-is first, then rewrite to target host if different backend
                rewritten = self._rewrite_url_to_target(s)
                if self._is_allowed_url(rewritten):
                    urls.add(rewritten)
                elif self._is_allowed_url(s):
                    urls.add(s)
            elif s.startswith('/') and len(s) > 1 and not s.startswith('//'):
                normalized = self._normalize_url(base_url, s)
                if normalized and self._is_allowed_url(normalized):
                    urls.add(normalized)
        elif isinstance(data, list):
            for item in data[:500]:  # cap to prevent DoS on huge arrays
                urls.update(self._extract_urls_from_json(item, base_url, depth + 1, max_depth))
        elif isinstance(data, dict):
            # Prioritize URL-bearing keys
            url_keys = ('url', 'href', 'path', 'endpoint', 'uri', 'link',
                        'location', 'Url', 'URI', 'Path', 'Endpoint', 'action')
            for key in url_keys:
                if key in data:
                    urls.update(self._extract_urls_from_json(data[key], base_url, depth + 1, max_depth))
            # Then recurse into all values
            for value in data.values():
                if isinstance(value, (dict, list)):
                    urls.update(self._extract_urls_from_json(value, base_url, depth + 1, max_depth))

        return urls

    # ------------------------------------------------------------------
    # Pre-crawl discovery: robots.txt
    # ------------------------------------------------------------------
    def _discover_robots_txt(self, base_url):
        """Fetch and parse robots.txt for Sitemap directives and path hints.

        Returns:
            dict with keys 'sitemap_urls', 'disallowed_paths', 'allowed_paths'.
        """
        result = {'sitemap_urls': [], 'disallowed_paths': [], 'allowed_paths': []}
        try:
            import requests as _req
        except Exception:
            return result

        robots_url = urljoin(base_url, '/robots.txt')
        headers = {}
        cookie_header = self._build_cookie_header()
        if cookie_header:
            headers['Cookie'] = cookie_header

        try:
            resp = _req.get(robots_url, timeout=8, verify=False, headers=headers)
        except Exception:
            return result
        if resp.status_code != 200:
            return result

        for line in resp.text.splitlines():
            line = line.strip()
            lower = line.lower()
            if lower.startswith('sitemap:'):
                sitemap_url = line.split(':', 1)[1].strip()
                if sitemap_url:
                    result['sitemap_urls'].append(sitemap_url)
            elif lower.startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    full_url = urljoin(base_url, path)
                    if self._is_allowed_url(full_url):
                        result['disallowed_paths'].append(full_url)
            elif lower.startswith('allow:'):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    full_url = urljoin(base_url, path)
                    if self._is_allowed_url(full_url):
                        result['allowed_paths'].append(full_url)

        if result['sitemap_urls']:
            print(f"[ROBOTS] Found {len(result['sitemap_urls'])} Sitemap directive(s) in robots.txt")
        return result

    # ------------------------------------------------------------------
    # Pre-crawl discovery: sitemap.xml
    # ------------------------------------------------------------------
    def _discover_sitemap(self, base_url, extra_sitemap_urls=None):
        """Fetch and parse sitemap.xml to discover all listed URLs.

        Supports standard sitemaps, sitemap index files (1 level deep),
        and a regex fallback for non-standard XML.

        Returns:
            list[str]: Discovered URLs from sitemap(s).
        """
        import xml.etree.ElementTree as ET

        self._sitemap_urls = []
        MAX_SITEMAP_URLS = 500
        MAX_SUB_SITEMAPS = 10

        try:
            import requests as _req
        except Exception:
            return []

        headers = {}
        cookie_header = self._build_cookie_header()
        if cookie_header:
            headers['Cookie'] = cookie_header

        # Build candidate sitemap URLs
        candidates = [
            urljoin(base_url, '/sitemap.xml'),
            urljoin(base_url, '/sitemap_index.xml'),
            urljoin(base_url, '/sitemap1.xml'),
        ]
        # Append sitemap path relative to target (e.g., /VulnerableApp/sitemap.xml)
        try:
            from urllib.parse import urlparse as _urlparse
            target_path = _urlparse(self.target_url).path.rstrip('/')
            if target_path and target_path != '/':
                candidates.insert(0, urljoin(base_url, f"{target_path}/sitemap.xml"))
        except Exception:
            pass

        if extra_sitemap_urls:
            for u in extra_sitemap_urls:
                if u not in candidates:
                    candidates.append(u)

        visited_sitemaps = set()
        all_urls = []

        def _parse_sitemap(sitemap_url, recurse=True):
            if sitemap_url in visited_sitemaps:
                return
            visited_sitemaps.add(sitemap_url)
            if len(all_urls) >= MAX_SITEMAP_URLS:
                return
            try:
                resp = _req.get(sitemap_url, timeout=10, verify=False, headers=headers)
            except Exception:
                return
            if resp.status_code != 200:
                return

            content = resp.text.strip()
            if not content:
                return

            # Handle gzip
            if sitemap_url.endswith('.gz'):
                import gzip as _gzip
                try:
                    content = _gzip.decompress(resp.content).decode('utf-8', errors='replace')
                except Exception:
                    return

            ns = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}

            # Try XML parsing first
            try:
                root = ET.fromstring(content)
                tag = root.tag.lower().split('}')[-1] if '}' in root.tag else root.tag.lower()

                # Sitemap index format
                if tag == 'sitemapindex' and recurse:
                    sub_locs = root.findall('.//sm:sitemap/sm:loc', ns)
                    if not sub_locs:  # try without namespace
                        sub_locs = root.findall('.//sitemap/loc')
                    for loc in sub_locs[:MAX_SUB_SITEMAPS]:
                        sub_url = (loc.text or '').strip()
                        if sub_url:
                            _parse_sitemap(sub_url, recurse=False)
                    return

                # Standard urlset format
                url_locs = root.findall('.//sm:url/sm:loc', ns)
                if not url_locs:  # try without namespace
                    url_locs = root.findall('.//url/loc')
                for loc in url_locs:
                    url = (loc.text or '').strip()
                    if url and self._is_allowed_url(url):
                        all_urls.append(url)
                        if len(all_urls) >= MAX_SITEMAP_URLS:
                            return
                if url_locs:
                    return  # XML parsing succeeded
            except ET.ParseError:
                pass  # fall through to regex

            # Regex fallback for non-standard XML or plain text sitemaps
            import re as _re
            # Try <loc> tags first
            loc_matches = _re.findall(r'<loc>\s*(.*?)\s*</loc>', content, _re.IGNORECASE)
            if loc_matches:
                for url in loc_matches:
                    url = url.strip()
                    if url and self._is_allowed_url(url):
                        all_urls.append(url)
                        if len(all_urls) >= MAX_SITEMAP_URLS:
                            return
            else:
                # Plain text: one URL per line
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith('http') and self._is_allowed_url(line):
                        all_urls.append(line)
                        if len(all_urls) >= MAX_SITEMAP_URLS:
                            return

        for candidate in candidates:
            _parse_sitemap(candidate)
            if len(all_urls) >= MAX_SITEMAP_URLS:
                break

        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for u in all_urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)

        self._sitemap_urls = deduped
        if deduped:
            print(f"[SITEMAP] Discovered {len(deduped)} URLs from sitemap")
        return deduped

    # ------------------------------------------------------------------
    # Pre-crawl discovery: JSON endpoint listings
    # ------------------------------------------------------------------
    def _discover_json_endpoint_urls(self, base_url):
        """Probe common JSON endpoints that list application URLs.

        Fetches endpoints like /allEndPointJson and /scanner and recursively
        extracts URL strings from the JSON responses.

        Returns:
            list[str]: Discovered URLs.
        """
        self._json_discovered_urls = []
        try:
            import requests as _req
        except Exception:
            return []

        headers = {'Accept': 'application/json'}
        cookie_header = self._build_cookie_header()
        if cookie_header:
            headers['Cookie'] = cookie_header

        # Build candidates relative to target path
        candidates = []
        try:
            from urllib.parse import urlparse as _urlparse
            target_path = _urlparse(self.target_url).path.rstrip('/')
            if target_path and target_path != '/':
                candidates.append(f"{target_path}/allEndPointJson")
                candidates.append(f"{target_path}/scanner")
        except Exception:
            pass
        candidates.extend([
            '/allEndPointJson',
            '/scanner',
            '/scanner/dast',
            '/VulnerabilityDefinitions',
            '/api/endpoints',
            '/api/routes',
            '/api/v1/endpoints',
            '/api/config',
            '/.well-known/openapi.json',
        ])

        all_urls = set()
        for path in candidates:
            endpoint_url = urljoin(base_url, path)
            try:
                resp = _req.get(endpoint_url, timeout=8, verify=False, headers=headers)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            content_type = (resp.headers.get('content-type', '') or '').lower()
            text = resp.text.strip()
            # Must look like JSON
            if not (text.startswith('[') or text.startswith('{')):
                continue
            try:
                data = resp.json()
            except Exception:
                # Handle malformed JSON (e.g. concatenated arrays from facade merging)
                import re as _re
                try:
                    arrays = _re.findall(r'\[.*?\]', text, _re.DOTALL)
                    data = []
                    for arr_str in arrays:
                        try:
                            data.extend(json.loads(arr_str))
                        except Exception:
                            pass
                    if not data:
                        continue
                except Exception:
                    continue

            urls = self._extract_urls_from_json(data, base_url)
            try:
                self._extract_json_api_hints(data, base_url, source_endpoint=endpoint_url)
            except Exception:
                pass
            if urls:
                all_urls.update(urls)
                print(f"[JSON-DISCOVERY] Found {len(urls)} URLs from {path}")

        merged_urls = set(getattr(self, "_json_discovered_urls", []) or [])
        merged_urls.update(all_urls)
        self._json_discovered_urls = list(merged_urls)
        return self._json_discovered_urls

    def _extract_json_param_names(self, value):
        """Extract likely parameter names from JSON values."""
        names = set()
        if isinstance(value, dict):
            for key, nested in value.items():
                key_s = str(key).strip()
                if key_s:
                    names.add(key_s)
                names.update(self._extract_json_param_names(nested))
        elif isinstance(value, list):
            for item in value[:200]:
                if isinstance(item, str):
                    cleaned = item.strip()
                    if cleaned and re.match(r"^[A-Za-z_][A-Za-z0-9_\\-\\.]*$", cleaned):
                        names.add(cleaned)
                elif isinstance(item, dict):
                    candidate = item.get("name") or item.get("param") or item.get("field") or item.get("key")
                    if candidate:
                        names.add(str(candidate).strip())
                    names.update(self._extract_json_param_names(item))
        return {n for n in names if n}

    def _extract_param_names_from_text(self, text):
        """Extract probable parameter names from descriptive text."""
        if not isinstance(text, str) or not text:
            return set()
        names = set()
        stopwords = {
            "and", "or", "the", "from", "for", "with", "without", "true", "false",
            "null", "none", "value", "values", "query", "param", "parameter", "field",
            "body", "header", "cookie", "http", "https", "www", "div", "union"
        }
        # Quoted names with explicit parameter context.
        for m in re.findall(r"""["']([A-Za-z_][A-Za-z0-9_\-\.]{1,40})["']\s+(?:query\s+param|parameter|field)\b""", text, flags=re.IGNORECASE):
            names.add(m)
        for m in re.findall(r"""\b(?:query\s+param|parameter|field)\b[^"']{0,30}["']([A-Za-z_][A-Za-z0-9_\-\.]{1,40})["']""", text, flags=re.IGNORECASE):
            names.add(m)
        # Query string-like fragments in payloads.
        for m in re.findall(r"[?&]([A-Za-z_][A-Za-z0-9_\-\.]{1,40})=", text):
            names.add(m)
        for m in re.findall(r"\b([A-Za-z_][A-Za-z0-9_\-\.]{1,40})\b\s+(?:query\s+param|parameter|field)\b", text, flags=re.IGNORECASE):
            names.add(m)
        filtered = set()
        for n in names:
            lowered = n.lower()
            if lowered in stopwords:
                continue
            if lowered.startswith("level_"):
                continue
            filtered.add(n)
        return filtered

    def _extract_json_api_hints(self, data, base_url, source_endpoint=None, depth=0, max_depth=6):
        """Extract endpoint methods and parameter hints from JSON endpoint listings."""
        if depth > max_depth:
            return

        # ── VulnerableApp-Facade /VulnerabilityDefinitions format ──
        # {"AppName": [{"name": "VulnName", "levels": [{"levelIdentifier": "LEVEL_1", ...}]}]}
        if isinstance(data, dict) and data and depth == 0:
            first_val = next(iter(data.values()), None)
            if (isinstance(first_val, list) and first_val
                    and isinstance(first_val[0], dict)
                    and "name" in first_val[0]
                    and "levels" in first_val[0]):
                _facade_count = 0
                for app_name, vulns in data.items():
                    if not isinstance(vulns, list):
                        continue
                    for vuln in vulns:
                        if not isinstance(vuln, dict):
                            continue
                        vuln_name = (vuln.get("name") or vuln.get("id") or "").strip()
                        if not vuln_name:
                            continue
                        for level in (vuln.get("levels") or []):
                            if not isinstance(level, dict):
                                continue
                            level_id = (level.get("levelIdentifier") or "").strip()
                            if not level_id:
                                continue

                            # Construct endpoint: /{app_name}/{vuln_name}/{level_id}
                            route_path = f"/{app_name}/{vuln_name}/{level_id}"
                            target_url = self._normalize_url(base_url, route_path)
                            if not target_url or not self._is_allowed_url(target_url):
                                continue

                            # Determine HTTP method from hints or default to GET
                            method = "GET"
                            self._add_endpoint_entry(target_url, source="json-discovery", methods=[method])
                            self._api_endpoints.append({
                                "url": target_url,
                                "method": method,
                                "type": "json-discovery",
                            })
                            _facade_count += 1

                            # Extract parameter names from hint descriptions
                            param_names = set()
                            for hint in (level.get("hints") or []):
                                if not isinstance(hint, dict):
                                    continue
                                desc = hint.get("description") or ""
                                param_names.update(self._extract_param_names_from_text(desc))

                            if param_names:
                                self.parameters.setdefault(target_url, [])
                                self.parameters[target_url] = sorted(set(
                                    self.parameters[target_url] + list(param_names)
                                ))
                                if not hasattr(self, "_detected_params"):
                                    self._detected_params = []
                                for pname in sorted(param_names):
                                    self._detected_params.append({
                                        "name": pname,
                                        "type": "json",
                                        "source": "json-discovery",
                                        "url": target_url,
                                    })
                                    self._add_input_point({
                                        "page": target_url,
                                        "action": target_url,
                                        "method": method,
                                        "name": pname,
                                        "input_type": "text",
                                        "inputs": [{"name": pname, "value": "test"}],
                                        "source": "json-discovery",
                                    })
                                self._add_form({
                                    "url": target_url,
                                    "action": target_url,
                                    "method": method,
                                    "inputs": [{"name": n, "value": "test"} for n in sorted(param_names)],
                                    "source": "json-discovery",
                                })

                            # Extract template URLs from resourceInformation
                            res_info = level.get("resourceInformation") or {}
                            html_res = res_info.get("htmlResource") or {}
                            uri = (html_res.get("uri") or "").strip()
                            if uri:
                                tpl_url = self._normalize_url(base_url, uri)
                                if tpl_url and tpl_url not in self._json_discovered_urls:
                                    self._json_discovered_urls.append(tpl_url)
                            for static_res in (res_info.get("staticResources") or []):
                                s_uri = (static_res.get("uri") or "").strip() if isinstance(static_res, dict) else ""
                                if s_uri:
                                    s_url = self._normalize_url(base_url, s_uri)
                                    if s_url and s_url not in self._json_discovered_urls:
                                        self._json_discovered_urls.append(s_url)

                if _facade_count:
                    print(f"[JSON-DISCOVERY] VulnerabilityDefinitions facade: discovered {_facade_count} vulnerability endpoints")
                return  # Handled — don't fall through

        # Special handling for VulnerableApp-style /allEndPointJson payload.
        if isinstance(data, list) and data and isinstance(data[0], dict) and ("Name" in data[0] and "Detailed Information" in data[0]):
            try:
                parsed_source = urlparse(source_endpoint or "")
                source_path = parsed_source.path if parsed_source else ""
                app_prefix = ""
                if source_path.endswith("/allEndPointJson"):
                    app_prefix = source_path.rsplit("/allEndPointJson", 1)[0]
                if not app_prefix:
                    app_prefix = urlparse(self.target_url).path.rstrip("/")
            except Exception:
                app_prefix = urlparse(self.target_url).path.rstrip("/")

            for item in data[:300]:
                if not isinstance(item, dict):
                    continue
                vuln_name = (item.get("Name") or "").strip()
                details = item.get("Detailed Information") or []
                if not vuln_name or not isinstance(details, list):
                    continue
                for detail in details:
                    if not isinstance(detail, dict):
                        continue
                    level = str(detail.get("Level") or "").strip()
                    if not level:
                        continue
                    method = str(detail.get("HttpMethod") or detail.get("method") or "GET").upper()
                    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
                        method = "GET"
                    route_path = f"{app_prefix}/{vuln_name}/{level}".replace("//", "/")
                    target_url = self._normalize_url(base_url, route_path)
                    if not target_url or not self._is_allowed_url(target_url):
                        continue

                    self._add_endpoint_entry(target_url, source="json-discovery", methods=[method])
                    self._api_endpoints.append({
                        "url": target_url,
                        "method": method,
                        "type": "json-discovery",
                    })

                    html_template = str(detail.get("HtmlTemplate") or "").strip().strip("/")
                    if html_template:
                        template_base = self._normalize_url(base_url, f"{app_prefix}/templates/{vuln_name}/{html_template}")
                        if template_base:
                            if not hasattr(self, "_json_discovered_urls"):
                                self._json_discovered_urls = []
                            for suffix in (".html", ".js"):
                                tpl_url = f"{template_base}{suffix}"
                                if tpl_url not in self._json_discovered_urls:
                                    self._json_discovered_urls.append(tpl_url)

                    param_names = set()
                    if detail.get("Parameter"):
                        param_names.update(self._extract_json_param_names(detail.get("Parameter")))
                    param_names.update(self._extract_param_names_from_text(detail.get("Description") or ""))
                    for vector in (detail.get("AttackVectors") or []):
                        if not isinstance(vector, dict):
                            continue
                        param_names.update(self._extract_param_names_from_text(vector.get("Description") or ""))
                        param_names.update(self._extract_param_names_from_text(vector.get("CurlPayload") or ""))

                    if param_names:
                        self.parameters.setdefault(target_url, [])
                        self.parameters[target_url] = sorted(set(self.parameters[target_url] + list(param_names)))
                        if not hasattr(self, "_detected_params"):
                            self._detected_params = []
                        for pname in sorted(param_names):
                            self._detected_params.append({
                                "name": pname,
                                "type": "json",
                                "source": "json-discovery",
                                "url": target_url,
                            })
                            self._add_input_point({
                                "page": target_url,
                                "action": target_url,
                                "method": method,
                                "name": pname,
                                "input_type": "text",
                                "inputs": [{"name": pname, "value": "test"}],
                                "source": "json-discovery",
                            })
                        self._add_form({
                            "url": target_url,
                            "action": target_url,
                            "method": method,
                            "inputs": [{"name": n, "value": "test"} for n in sorted(param_names)],
                            "source": "json-discovery",
                        })

        if isinstance(data, list):
            for item in data[:500]:
                self._extract_json_api_hints(item, base_url, source_endpoint=source_endpoint, depth=depth + 1, max_depth=max_depth)
            return

        if not isinstance(data, dict):
            return

        url_keys = ("url", "href", "path", "endpoint", "uri", "link", "route", "action")
        method_keys = ("method", "httpMethod", "verb", "type")
        param_keys = ("params", "parameters", "query", "queryParams", "body", "payload", "data", "fields", "inputs")

        target_url = ""
        for key in url_keys:
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                target_url = self._normalize_url(base_url, val.strip())
                if target_url:
                    break

        methods = set()
        for key in method_keys:
            val = data.get(key)
            if isinstance(val, str):
                m = val.strip().upper()
                if m in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
                    methods.add(m)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        m = item.strip().upper()
                        if m in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
                            methods.add(m)

        param_names = set()
        for key in param_keys:
            if key in data:
                param_names.update(self._extract_json_param_names(data.get(key)))

        if target_url and self._is_allowed_url(target_url):
            self._add_endpoint_entry(target_url, source="json-discovery", methods=list(methods) if methods else None)
            if methods:
                for method in sorted(methods):
                    self._api_endpoints.append({
                        "url": target_url,
                        "method": method,
                        "type": "json-discovery",
                    })
            if param_names:
                self.parameters.setdefault(target_url, [])
                self.parameters[target_url] = sorted(set(self.parameters[target_url] + list(param_names)))
                if not hasattr(self, "_detected_params"):
                    self._detected_params = []
                guessed_method = "POST" if "POST" in methods else ("GET" if "GET" in methods else (sorted(methods)[0] if methods else "POST"))
                synthetic_inputs = []
                for pname in sorted(param_names):
                    self._detected_params.append({
                        "name": pname,
                        "type": "json",
                        "source": "json-discovery",
                        "url": target_url,
                    })
                    synthetic_inputs.append({"name": pname, "value": "test"})
                    self._add_input_point({
                        "page": target_url,
                        "action": target_url,
                        "method": guessed_method,
                        "name": pname,
                        "input_type": "text",
                        "inputs": [{"name": pname, "value": "test"}],
                        "source": "json-discovery",
                    })
                if synthetic_inputs:
                    self._add_form({
                        "url": target_url,
                        "action": target_url,
                        "method": guessed_method,
                        "inputs": synthetic_inputs,
                        "source": "json-discovery",
                    })

        for value in data.values():
            if isinstance(value, (dict, list)):
                self._extract_json_api_hints(value, base_url, source_endpoint=source_endpoint, depth=depth + 1, max_depth=max_depth)

    def _extract_html_inputs(self, html):
        """Parse HTML and return form/input structures without browser rendering."""
        forms = []
        try:
            form_pattern = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
            input_pattern = re.compile(r"<(input|textarea|select)\b([^>]*)>", re.IGNORECASE | re.DOTALL)
            attr_pattern = re.compile(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*['\"]([^'\"]*)['\"]")

            def _attrs_to_dict(attrs_text):
                attrs = {}
                for key, value in attr_pattern.findall(attrs_text or ""):
                    attrs[key.lower()] = value
                return attrs

            for attrs_text, body in form_pattern.findall(html or ""):
                attrs = _attrs_to_dict(attrs_text)
                inputs = []
                for tag, input_attrs_text in input_pattern.findall(body or ""):
                    iattrs = _attrs_to_dict(input_attrs_text)
                    name = iattrs.get("name") or iattrs.get("id") or ""
                    if not name:
                        continue
                    inputs.append({
                        "name": name,
                        "type": (iattrs.get("type") or tag or "text").lower(),
                        "value": iattrs.get("value") or "",
                    })
                forms.append({
                    "action": attrs.get("action") or "",
                    "method": (attrs.get("method") or "POST").upper(),
                    "inputs": inputs,
                })
            # If no <form> wrappers exist, collect loose inputs as a synthetic form.
            if not forms:
                loose_inputs = []
                for tag, input_attrs_text in input_pattern.findall(html or ""):
                    iattrs = _attrs_to_dict(input_attrs_text)
                    name = iattrs.get("name") or iattrs.get("id") or ""
                    if not name:
                        continue
                    loose_inputs.append({
                        "name": name,
                        "type": (iattrs.get("type") or tag or "text").lower(),
                        "value": iattrs.get("value") or "",
                    })
                if loose_inputs:
                    forms.append({
                        "action": "",
                        "method": "GET",
                        "inputs": loose_inputs,
                    })
        except Exception:
            return []
        return forms

    def _derive_action_from_template_url(self, template_url):
        """Best-effort mapping from template file URL to route endpoint URL."""
        try:
            parsed = urlparse(template_url)
            segments = [s for s in parsed.path.split("/") if s]
            if "templates" not in segments:
                return ""
            idx = segments.index("templates")
            # Example:
            # /VulnerableApp/templates/CommandInjection/LEVEL_1/CI_Level1.html
            # -> /VulnerableApp/CommandInjection/LEVEL_1
            prefix = segments[:idx]
            tail = segments[idx + 1:]
            if len(tail) < 2:
                return ""
            mapped_segments = prefix + tail[:2]
            mapped_path = "/" + "/".join(mapped_segments)
            return f"{parsed.scheme}://{parsed.netloc}{mapped_path}"
        except Exception:
            return ""

    def _extract_forms_from_template_urls(self, base_url):
        """Fetch discovered template HTML files and extract form parameters."""
        try:
            import requests as _req
        except Exception:
            return 0

        headers = {"Accept": "text/html,application/xhtml+xml"}
        cookie_header = self._build_cookie_header()
        if cookie_header:
            headers["Cookie"] = cookie_header

        candidates = set()
        for u in getattr(self, "_json_discovered_urls", []) or []:
            if isinstance(u, str) and "/templates/" in u and u.lower().split("?", 1)[0].endswith((".html", ".htm")):
                candidates.add(u)
        for ep in self.endpoints:
            u = ep.get("url", "") if isinstance(ep, dict) else ""
            if isinstance(u, str) and "/templates/" in u and u.lower().split("?", 1)[0].endswith((".html", ".htm")):
                candidates.add(u)

        if not candidates:
            return 0

        existing_forms = {
            (f.get("action", ""), (f.get("method", "GET") or "GET").upper())
            for f in (self.forms or [])
        }
        existing_inputs = {
            (ip.get("action", ""), (ip.get("method", "GET") or "GET").upper(), ip.get("name", ""))
            for ip in (self.input_points or [])
        }

        added = 0
        for turl in sorted(candidates):
            try:
                resp = _req.get(turl, timeout=8, verify=False, headers=headers)
            except Exception:
                continue
            if resp.status_code != 200 or not (resp.text or "").strip():
                continue

            parsed_forms = self._extract_html_inputs(resp.text)
            if not parsed_forms:
                continue

            default_action = self._derive_action_from_template_url(turl) or self._normalize_url(base_url, turl)
            for form in parsed_forms:
                method = (form.get("method") or "POST").upper()
                action_raw = form.get("action") or default_action
                action = self._normalize_url(turl, action_raw) if action_raw else default_action
                if "/templates/" in (action or ""):
                    action = default_action
                if not action or not self._is_allowed_url(action):
                    continue

                fkey = (action, method)
                if fkey not in existing_forms:
                    self._add_form({
                        "url": turl,
                        "action": action,
                        "method": method,
                        "inputs": form.get("inputs", []),
                        "source": "template-html",
                    })
                    existing_forms.add(fkey)
                    added += 1

                for inp in form.get("inputs", []):
                    name = inp.get("name", "")
                    if not name:
                        continue
                    self.parameters.setdefault(action, [])
                    self.parameters[action] = sorted(set(self.parameters[action] + [name]))
                    ikey = (action, method, name)
                    if ikey not in existing_inputs:
                        self._add_input_point({
                            "page": turl,
                            "action": action,
                            "method": method,
                            "name": name,
                            "input_type": inp.get("type", "text"),
                            "inputs": [{"name": name, "value": inp.get("value", "test") or "test"}],
                            "source": "template-html",
                        })
                        existing_inputs.add(ikey)
                    if not hasattr(self, "_detected_params"):
                        self._detected_params = []
                    self._detected_params.append({
                        "name": name,
                        "type": "template",
                        "source": "template-html",
                        "url": action,
                    })

        if added:
            print(f"[+] Template HTML extraction added {added} forms")
        return added

    def _discover_openapi_specs(self, base_url):
        """Discover OpenAPI/Swagger specs and add endpoints/params."""
        self._openapi_specs = []
        candidates = [
            "/swagger.json",
            "/openapi.json",
            "/swagger/v1/swagger.json",
            "/v2/api-docs",
            "/v3/api-docs",
            "/api-docs",
            "/api/swagger.json",
            "/api/openapi.json",
            "/swagger.yaml",
            "/openapi.yaml",
        ]

        try:
            import requests
        except Exception:
            return

        headers = {}
        cookie_header = self._build_cookie_header()
        if cookie_header:
            headers["Cookie"] = cookie_header

        for path in candidates:
            spec_url = urljoin(base_url, path)
            try:
                resp = requests.get(spec_url, timeout=8, verify=False, headers=headers)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            text = resp.text.strip()
            if not text:
                continue
            if not (text.startswith("{") and "paths" in text):
                # Try to parse JSON anyway (some specs are minified)
                pass
            try:
                spec = resp.json()
            except Exception:
                # Skip YAML for now to avoid new deps
                continue

            if not isinstance(spec, dict) or "paths" not in spec:
                continue

            self._openapi_specs.append(spec_url)

            servers = spec.get("servers") or []
            server_base = base_url
            if servers and isinstance(servers, list):
                first = servers[0] or {}
                server_url = first.get("url")
                if server_url:
                    if server_url.startswith("http"):
                        server_base = server_url
                    else:
                        server_base = urljoin(base_url, server_url)

            paths = spec.get("paths") or {}
            for path_key, path_obj in paths.items():
                if not path_key:
                    continue
                # Replace path params with 1 for a testable URL
                sample_path = re.sub(r"\{[^/]+\}", "1", path_key)
                full_url = urljoin(server_base.rstrip("/") + "/", sample_path.lstrip("/"))
                self._add_endpoint_entry(full_url, source="openapi")

                # Collect query parameters from spec
                if isinstance(path_obj, dict):
                    for method, op in path_obj.items():
                        if not isinstance(op, dict):
                            continue
                        params = op.get("parameters") or []
                        for p in params:
                            if not isinstance(p, dict):
                                continue
                            if p.get("in") == "query" and p.get("name"):
                                self.parameters.setdefault(full_url, [])
                                self.parameters[full_url] = sorted(set(self.parameters[full_url] + [p.get("name")]))
                            if p.get("in") == "path" and p.get("name"):
                                if not hasattr(self, "_detected_params"):
                                    self._detected_params = []
                                self._detected_params.append({
                                    "name": p.get("name"),
                                    "type": "path",
                                    "source": "openapi",
                                    "url": full_url,
                                })

            print(f"[+] OpenAPI discovery: {len(paths)} paths from {spec_url}")

    def _discover_graphql_endpoints(self, base_url):
        """Discover GraphQL endpoints via introspection."""
        self._graphql_endpoints = []
        candidates = [
            "/graphql",
            "/api/graphql",
            "/graphql/endpoint",
            "/gql",
        ]
        introspection_query = {
            "query": "query IntrospectionQuery { __schema { queryType { name } } }"
        }

        try:
            import requests
        except Exception:
            return

        headers = {"Content-Type": "application/json"}
        cookie_header = self._build_cookie_header()
        if cookie_header:
            headers["Cookie"] = cookie_header

        for path in candidates:
            gql_url = urljoin(base_url, path)
            try:
                resp = requests.post(gql_url, json=introspection_query, timeout=8, verify=False, headers=headers)
            except Exception:
                continue
            if resp.status_code not in (200, 400, 401, 403):
                continue
            body = (resp.text or "").lower()
            if "graphql" in body or "__schema" in body or "errors" in body:
                self._graphql_endpoints.append(gql_url)
                self._add_endpoint_entry(gql_url, source="graphql")
                self._api_endpoints.append({
                    "url": gql_url,
                    "method": "POST",
                    "type": "graphql",
                })
                if not hasattr(self, "_detected_params"):
                    self._detected_params = []
                self._detected_params.append({
                    "name": "query",
                    "type": "graphql",
                    "source": "graphql",
                    "url": gql_url,
                })
                print(f"[+] GraphQL endpoint discovered: {gql_url}")

                # Deep introspection to get full schema for mutation testing
                if not hasattr(self, '_graphql_schemas'):
                    self._graphql_schemas = []
                try:
                    deep_query = {
                        "query": """query IntrospectionQuery {
                            __schema {
                                queryType { name }
                                mutationType { name }
                                subscriptionType { name }
                                types {
                                    kind name description
                                    fields(includeDeprecated: true) {
                                        name description
                                        args { name description type { kind name ofType { kind name ofType { kind name } } } defaultValue }
                                        type { kind name ofType { kind name ofType { kind name } } }
                                    }
                                    inputFields { name description type { kind name ofType { kind name } } defaultValue }
                                    enumValues(includeDeprecated: true) { name description }
                                }
                            }
                        }"""
                    }
                    schema_resp = requests.post(gql_url, json=deep_query, timeout=10,
                                                verify=False, headers=headers)
                    if schema_resp.status_code == 200:
                        schema_data = schema_resp.json()
                        if 'data' in schema_data and '__schema' in schema_data.get('data', {}):
                            self._graphql_schemas.append({
                                'endpoint': gql_url,
                                'schema': schema_data['data']['__schema'],
                            })
                            mutation_type = schema_data['data']['__schema'].get('mutationType')
                            if mutation_type:
                                print(f"[+] GraphQL mutations available at {gql_url}")
                except Exception as e:
                    print(f"[!] GraphQL deep introspection failed for {gql_url}: {e}")

    def _probe_http_methods(self, urls):
        """Probe HTTP methods using OPTIONS for a subset of URLs."""
        self._method_probe_map = {}
        try:
            import requests
        except Exception:
            return

        headers = {}
        cookie_header = self._build_cookie_header()
        if cookie_header:
            headers["Cookie"] = cookie_header

        for url in urls[:100]:
            try:
                resp = requests.options(url, timeout=6, verify=False, headers=headers)
            except Exception:
                continue
            allow = resp.headers.get("Allow") or resp.headers.get("allow") or ""
            methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
            if methods:
                self._method_probe_map[url] = methods
                # Add or update endpoint entry with methods
                self._add_endpoint_entry(url, source="method_probe", status=resp.status_code, methods=methods)

    def _static_js_param_discovery(self, base_url):
        """Extract parameter-like tokens from JS URLs (strict filter)."""
        if not getattr(self, "_js_urls", None):
            return
        try:
            import requests
        except Exception:
            return

        param_pattern = re.compile(
            r'^(id|name|email|password|username|user|token|key|api_key|search|query|q|page|limit|offset|sort|order|'
            r'filter|type|status|role|action|callback|redirect|url|path|file|filename|upload|'
            r'phone|address|city|state|zip|country|comment|message|title|content|description|'
            r'[a-z]+[_-](id|name|code|key|token|type|url|num|number|date|time|email|phone|value)|'
            r'(new|old|current)[_-]?(password|email|phone|name|value)|'
            r'(post|order|video|report|service|product|coupon|vehicle|mechanic)[_-]?(id|code|name)|'
            r'otp|pin|vin|VIN|code|coupon|quantity|amount|price)$'
        )

        discovered = set()
        headers = {}
        cookie_header = self._build_cookie_header()
        if cookie_header:
            headers["Cookie"] = cookie_header

        for js_url in list(self._js_urls)[:15]:
            try:
                resp = requests.get(js_url, timeout=6, verify=False, headers=headers)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            # Find tokens that look like param names
            tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_-]{2,}", resp.text or "")
            for t in tokens:
                if param_pattern.match(t):
                    discovered.add(t)

        if discovered:
            self.parameters.setdefault(base_url, [])
            self.parameters[base_url] = sorted(set(self.parameters[base_url] + list(discovered)))
            print(f"[+] JS static param discovery: {len(discovered)} params")

    def _discover_common_paths(self, base_url):
        """Probe common paths that may not be linked from the crawled pages.

        Discovers hidden pages like file upload forms, admin panels, info pages,
        and other pages that aren't linked from the main navigation.
        """
        import requests
        session = requests.Session()
        session.verify = False

        # Copy cookies from crawl
        for c in self.cookies:
            if isinstance(c, dict) and c.get('name') and c.get('value'):
                session.cookies.set(c['name'], c['value'])

        # Build list of directories we already know about
        known_dirs = set()
        for url in self.visited:
            parsed = urlparse(url)
            path = parsed.path
            if '/' in path:
                parent = path.rsplit('/', 1)[0]
                if parent:
                    known_dirs.add(parent)

        # Common file names to probe in each known directory
        common_files = [
            'info.php', 'phpinfo.php', 'test.php', 'admin.php', 'config.php',
            'upload.php', 'fileupload.php', 'file_upload.php',
            'fileupload1.php', 'fileupload2.php', 'fileupload3.php',
            'index.php', 'login.php', 'setup.php', 'install.php',
        ]

        # Also probe numbered variants of pages we've already found
        # e.g. if we found CommandExec-1.php, probe CommandExec-2,3,4...
        import re
        numbered_patterns = set()
        for url in self.visited:
            parsed = urlparse(url)
            path = parsed.path
            # Match patterns like name-1.php, name_1.php, name1.php
            m = re.search(r'(.+?)[-_]?(\d+)(\.php|\.html|\.asp|\.jsp)', path)
            if m:
                prefix, num, ext = m.groups()
                num = int(num)
                for i in range(1, min(num + 5, 20)):
                    # Try with separator
                    sep = '-' if '-' in path else ('_' if '_' in path else '')
                    variant = f"{prefix}{sep}{i}{ext}"
                    if variant != path:
                        numbered_patterns.add(variant)

        discovered = 0
        visited_set = set(self.visited)

        # Probe numbered variants first (highest value)
        for path in numbered_patterns:
            url = f"{base_url}{path}"
            if url in visited_set:
                continue
            try:
                resp = session.get(url, timeout=5, allow_redirects=True)
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Check it's not a generic error/404 page
                    if '<title>404' not in resp.text.lower() and 'not found' not in resp.text.lower()[:500]:
                        self.visited.add(url)
                        self._add_endpoint_entry(url, source='path_discovery', status=200, methods=['GET'])
                        discovered += 1
                        print(f"[DISCOVERY] Found: {url}")
            except Exception:
                pass

        # Probe common files in known directories
        for dir_path in known_dirs:
            for fname in common_files:
                url = f"{base_url}{dir_path}/{fname}"
                if url in visited_set or url in self._seen_endpoint_urls:
                    continue
                try:
                    resp = session.get(url, timeout=5, allow_redirects=True)
                    if resp.status_code == 200 and len(resp.text) > 100:
                        if '<title>404' not in resp.text.lower() and 'not found' not in resp.text.lower()[:500]:
                            self.visited.add(url)
                            self._add_endpoint_entry(url, source='path_discovery', status=200, methods=['GET'])
                            discovered += 1
                            print(f"[DISCOVERY] Found: {url}")
                except Exception:
                    pass

        if discovered:
            print(f"[DISCOVERY] Found {discovered} additional pages via path probing")

    # ------------------------------------------------------------------
    # Gobuster directory enumeration
    # ------------------------------------------------------------------

    # Built-in compact wordlist for web directory/file enumeration.
    # Focused on common web app paths — no external wordlist files needed.
    _GOBUSTER_BUILTIN_WORDLIST = [
        # Common directories
        "admin", "administrator", "api", "app", "assets", "auth", "backup", "backups",
        "bin", "cache", "cgi-bin", "classes", "cms", "common", "components", "conf",
        "config", "configuration", "console", "content", "control", "controller",
        "core", "css", "dashboard", "data", "database", "db", "debug", "default",
        "demo", "dev", "development", "dist", "doc", "docs", "documentation",
        "download", "downloads", "editor", "email", "engine", "error", "errors",
        "etc", "examples", "export", "extensions", "external", "extra", "feed",
        "file", "files", "fonts", "forms", "forum", "framework", "gallery",
        "global", "graphics", "help", "hidden", "home", "html", "http", "httpd",
        "icons", "images", "img", "import", "inc", "include", "includes",
        "index", "info", "install", "internal", "js", "json", "lang", "language",
        "layout", "lib", "libraries", "library", "license", "local", "log", "login",
        "logout", "logs", "mail", "main", "maintenance", "manage", "management",
        "manager", "media", "members", "messages", "misc", "mobile", "model",
        "models", "module", "modules", "monitor", "monitoring", "new", "news",
        "node", "old", "output", "page", "pages", "panel", "password", "php",
        "phpMyAdmin", "phpmyadmin", "plugin", "plugins", "portal", "post",
        "preview", "private", "process", "production", "profile", "profiles",
        "project", "projects", "protected", "proxy", "public", "query",
        "readme", "register", "release", "remote", "report", "reports",
        "resource", "resources", "rest", "restricted", "root", "rss", "run",
        "runtime", "sample", "samples", "save", "schema", "script", "scripts",
        "search", "secret", "secure", "security", "server", "service", "services",
        "session", "settings", "setup", "share", "shared", "shell", "site",
        "sitemap", "sites", "source", "sql", "src", "ssl", "staging", "start",
        "static", "stats", "status", "storage", "store", "style", "styles",
        "stylesheets", "submit", "support", "swagger", "sys", "system", "tag",
        "tags", "temp", "template", "templates", "test", "testing", "tests",
        "theme", "themes", "tmp", "token", "tool", "tools", "trace", "track",
        "upload", "uploads", "user", "users", "usr", "util", "utilities",
        "utils", "var", "vendor", "version", "view", "views", "web", "webapp",
        "webmail", "webpack", "widget", "widgets", "wiki", "wordpress", "wp",
        "wp-admin", "wp-content", "wp-includes", "wp-login", "xml",
        # Common files
        ".env", ".git/config", ".git/HEAD", ".gitignore", ".htaccess",
        ".htpasswd", ".svn/entries", ".well-known/security.txt",
        "CHANGELOG", "CHANGELOG.md", "CONTRIBUTING.md", "Dockerfile",
        "LICENSE", "Makefile", "README", "README.md", "Rakefile",
        "VERSION", "WEB-INF/web.xml", "Gruntfile.js", "Gulpfile.js",
        "bower.json", "composer.json", "config.json", "config.xml",
        "config.yml", "configuration.php", "crossdomain.xml",
        "database.yml", "docker-compose.yml", "elmah.axd",
        "error_log", "favicon.ico", "humans.txt",
        "info.php", "install.php", "package.json", "phpinfo.php",
        "robots.txt", "server-info", "server-status", "setup.php",
        "sitemap.xml", "test.php", "trace.axd", "web.config",
        # API / framework patterns
        "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger",
        "api/health", "api/status", "api/config", "api/users", "api/admin",
        "graphql", "graphiql", "playground",
        "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
        "swagger-ui", "swagger-ui.html", "api-docs",
        "_debug", "_profiler", "_error", "__debug__",
        "actuator", "actuator/health", "actuator/env", "actuator/info",
        "health", "healthcheck", "health-check", "ping", "version",
        "metrics", "prometheus",
    ]

    def _run_gobuster(self, base_url):
        """Run gobuster directory enumeration to discover hidden paths."""
        if not self.enable_gobuster:
            return
        if self._stop_requested:
            return

        gobuster_bin = shutil.which('gobuster')
        if not gobuster_bin:
            print("[Gobuster] ✗ gobuster binary not found — skipping directory enumeration")
            self._log_scan('warning', 'Gobuster not found on PATH', {})
            return

        print(f"[Gobuster] Starting directory enumeration on {base_url}")
        self._log_scan('info', f'Gobuster starting directory enumeration on {base_url}', {'source': 'gobuster'})

        wordlist_file = None
        try:
            # Write wordlist to temp file
            if self.gobuster_wordlist and os.path.isfile(self.gobuster_wordlist):
                wordlist_path = self.gobuster_wordlist
            else:
                wordlist_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, prefix='gobuster_wl_')
                wordlist_file.write('\n'.join(self._GOBUSTER_BUILTIN_WORDLIST))
                wordlist_file.flush()
                wordlist_file.close()
                wordlist_path = wordlist_file.name

            # Build gobuster command
            cmd = [
                gobuster_bin, 'dir',
                '-u', base_url,
                '-w', wordlist_path,
                '-q',                     # Quiet — no banner
                '--no-progress',          # No progress bar
                '--no-color',             # No ANSI colors
                '-e',                     # Expanded — print full URLs
                '-t', '10',               # 10 threads
                '--timeout', '10s',       # 10s per request
                '-k',                     # Skip TLS verification
                '-s', '200,204,301,302,307,401,403',  # Status codes to match
                '-b', '',                 # No blacklist (we filter ourselves)
                '-x', 'php,html,txt,bak,old,conf,json,xml,yml,yaml,log,env,inc,asp,aspx,jsp',
            ]

            # Pass cookies for authenticated enumeration
            cookie_header = self._build_cookie_header()
            if cookie_header:
                cmd.extend(['-c', cookie_header])

            print(f"[Gobuster] Running: {' '.join(cmd[:8])}... ({len(self._GOBUSTER_BUILTIN_WORDLIST)} words)")

            self._gobuster_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            discovered = 0
            existing_urls = {ep.get('url', '') for ep in self.endpoints}
            existing_urls.update(self.visited)

            # Parse gobuster output line by line
            # Format: http://host/path               (Status: 200) [Size: 1234]
            import re
            line_pattern = re.compile(
                r'^(https?://\S+?)\s+'          # URL
                r'\(Status:\s*(\d+)\)'          # Status code
                r'(?:\s*\[Size:\s*(\d+)\])?'    # Optional size
            )

            for line in self._gobuster_process.stdout:
                if self._stop_requested:
                    self._gobuster_process.terminate()
                    print("[Gobuster] Stopped by user request")
                    break

                line = line.strip()
                if not line:
                    continue

                match = line_pattern.match(line)
                if not match:
                    continue

                found_url = match.group(1)
                status_code = int(match.group(2))
                size = int(match.group(3)) if match.group(3) else 0

                # Skip tiny responses (likely custom 404 pages)
                if size < 50 and status_code == 200:
                    continue

                # Skip if already discovered
                if found_url in existing_urls:
                    continue

                # Add to endpoints
                self._add_endpoint_entry(found_url, source='gobuster', status=status_code)
                existing_urls.add(found_url)
                discovered += 1
                print(f"[Gobuster] Found: {found_url} [{status_code}] ({size} bytes)")

            # Wait for process to finish
            try:
                self._gobuster_process.wait(timeout=300)
            except subprocess.TimeoutExpired:
                self._gobuster_process.kill()

            # Log stderr for diagnostics
            stderr_out = self._gobuster_process.stderr.read()
            if stderr_out and 'error' in stderr_out.lower():
                print(f"[Gobuster] Warnings: {stderr_out.strip()[:200]}")

            self._gobuster_process = None

            print(f"[Gobuster] Complete: {discovered} new endpoints discovered")
            self._log_scan('info', f'Gobuster complete: {discovered} new endpoints discovered', {
                'source': 'gobuster', 'discovered': discovered
            })

        except Exception as e:
            print(f"[Gobuster] Error: {e}")
            self._log_scan('error', f'Gobuster error: {e}', {'source': 'gobuster'})
        finally:
            # Clean up temp wordlist
            if wordlist_file and os.path.exists(wordlist_file.name):
                try:
                    os.unlink(wordlist_file.name)
                except Exception:
                    pass
            self._gobuster_process = None

    def _code_discovery_urls(self, base_url):
        """Discover URLs from local codebase (best-effort, limited)."""
        self._code_discovered_urls = []
        root = os.getcwd()
        max_files = 250
        max_size = 1024 * 1024
        exts = {".py", ".js", ".ts", ".tsx", ".jsx", ".php", ".html", ".htm", ".java", ".go", ".rb"}
        skip_dirs = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".next"}
        url_re = re.compile(r"(https?://[^\s\"'<>]+|/api/[A-Za-z0-9_\\-\\/]+)")

        seen = set()
        count = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for name in filenames:
                if count >= max_files:
                    break
                _, ext = os.path.splitext(name)
                if ext.lower() not in exts:
                    continue
                path = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(path) > max_size:
                        continue
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                matches = url_re.findall(content)
                for raw in matches:
                    raw = raw.strip()
                    if raw.startswith("http"):
                        url = raw
                    else:
                        url = urljoin(base_url, raw)
                    if url and url not in seen and self._is_allowed_url(url):
                        seen.add(url)
                        self._code_discovered_urls.append(url)
                        self._add_endpoint_entry(url, source="code")
                count += 1
            if count >= max_files:
                break

    def _detect_path_parameters(self, url):
        """Detect path parameters like /users/123/orders/456."""
        parsed = urlparse(url)
        path = parsed.path
        path_params = []

        # Split path into segments
        segments = [s for s in path.split('/') if s]

        for i, segment in enumerate(segments):
            param_info = None

            # Numeric ID detection
            if segment.isdigit():
                # Try to infer name from previous segment
                param_name = segments[i-1].rstrip('s') + '_id' if i > 0 else 'id'
                param_info = {
                    'name': param_name,
                    'value': segment,
                    'type': 'integer',
                    'position': i
                }
            # UUID detection
            elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', segment.lower()):
                param_name = segments[i-1].rstrip('s') + '_uuid' if i > 0 else 'uuid'
                param_info = {
                    'name': param_name,
                    'value': segment,
                    'type': 'uuid',
                    'position': i
                }
            # Hash/token detection (32+ hex chars)
            elif re.match(r'^[0-9a-f]{32,}$', segment.lower()):
                param_info = {
                    'name': 'token',
                    'value': segment[:20] + '...',
                    'type': 'hash',
                    'position': i
                }
            # Slug detection (word-word-word)
            elif re.match(r'^[a-z0-9]+(-[a-z0-9]+)+$', segment.lower()) and len(segment) > 5:
                param_name = segments[i-1].rstrip('s') + '_slug' if i > 0 else 'slug'
                param_info = {
                    'name': param_name,
                    'value': segment,
                    'type': 'slug',
                    'position': i
                }
            # Base64 detection
            elif re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', segment):
                param_info = {
                    'name': 'encoded_data',
                    'value': segment[:20] + '...',
                    'type': 'base64',
                    'position': i
                }
            # Date detection (2024-01-15 or 20240115)
            elif re.match(r'^\d{4}-\d{2}-\d{2}$', segment) or re.match(r'^\d{8}$', segment):
                param_info = {
                    'name': 'date',
                    'value': segment,
                    'type': 'date',
                    'position': i
                }
            # Email in path (rare but possible)
            elif '@' in segment and '.' in segment:
                param_info = {
                    'name': 'email',
                    'value': segment,
                    'type': 'email',
                    'position': i
                }

            if param_info:
                path_params.append(param_info)

        return path_params

    def _ai_analyze_parameters(self, page, url):
        """Use AI to analyze page and detect parameters with data types."""
        if not self.ai_api_key:
            return None

        try:
            # Get page content for AI analysis
            page_content = page.evaluate("""
                () => {
                    // Get forms and their inputs
                    const forms = Array.from(document.querySelectorAll('form')).map(f => ({
                        action: f.action,
                        method: f.method,
                        inputs: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                            name: i.name,
                            type: i.type,
                            id: i.id,
                            placeholder: i.placeholder,
                            pattern: i.pattern,
                            required: i.required,
                            value: i.type === 'hidden' ? i.value : ''
                        }))
                    }));

                    // Get URL patterns from links
                    const links = Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(h => h.startsWith('http'))
                        .slice(0, 20);

                    // Get any API calls in scripts
                    const scripts = Array.from(document.querySelectorAll('script'))
                        .map(s => s.textContent)
                        .join('\\n')
                        .substring(0, 3000);

                    return { forms, links, scripts };
                }
            """)

            prompt = f"""Analyze this web page content and identify ALL parameters with their data types.

URL: {url}

Forms found:
{json.dumps(page_content.get('forms', []), indent=2)[:2000]}

Links found:
{json.dumps(page_content.get('links', []), indent=2)[:1000]}

Script snippets:
{page_content.get('scripts', '')[:1500]}

Return a JSON array of parameters with this format:
[
  {{"name": "user_id", "type": "integer", "source": "path", "example": "123"}},
  {{"name": "email", "type": "email", "source": "form", "example": "user@example.com"}},
  {{"name": "api_key", "type": "api_key", "source": "header", "example": "sk-xxx"}},
  {{"name": "search", "type": "string", "source": "query", "example": "keyword"}}
]

Data types to detect: integer, string, email, uuid, date, datetime, boolean, float, phone, url, json, base64, hash, api_key, password, token, file, array

Return ONLY the JSON array, no explanation."""

            response = self._call_ai(prompt, max_tokens=1500)
            if response:
                # Extract JSON from response
                try:
                    # Find JSON array in response
                    json_match = re.search(r'\[[\s\S]*\]', response)
                    if json_match:
                        params = json.loads(json_match.group())
                        return params
                except:
                    pass
        except Exception as e:
            print(f"[AI] Parameter analysis error: {e}")

        return None

    def _infer_input_type(self, inp):
        """Infer the data type of a form input based on its attributes."""
        name = (inp.get('name') or '').lower()
        input_type = (inp.get('type') or 'text').lower()
        placeholder = (inp.get('placeholder') or '').lower()
        pattern = inp.get('pattern') or ''

        # Check HTML5 input types first
        type_map = {
            'email': 'email',
            'password': 'password',
            'number': 'integer',
            'tel': 'phone',
            'url': 'url',
            'date': 'date',
            'datetime-local': 'datetime',
            'time': 'time',
            'file': 'file',
            'hidden': 'hidden',
            'checkbox': 'boolean',
            'radio': 'enum',
        }
        if input_type in type_map:
            return type_map[input_type]

        # Infer from name patterns
        if any(x in name for x in ['email', 'mail']):
            return 'email'
        if any(x in name for x in ['password', 'passwd', 'pwd', 'pass']):
            return 'password'
        if any(x in name for x in ['phone', 'tel', 'mobile', 'cell']):
            return 'phone'
        if any(x in name for x in ['id', 'num', 'count', 'qty', 'quantity', 'amount', 'price', 'age']):
            return 'integer'
        if any(x in name for x in ['date', 'dob', 'birthday']):
            return 'date'
        if any(x in name for x in ['url', 'link', 'website', 'href']):
            return 'url'
        if any(x in name for x in ['token', 'csrf', 'nonce', 'key', 'api']):
            return 'token'
        if any(x in name for x in ['uuid', 'guid']):
            return 'uuid'
        if any(x in name for x in ['json', 'data', 'payload']):
            return 'json'
        if any(x in name for x in ['user', 'name', 'first', 'last', 'title']):
            return 'string'
        if any(x in name for x in ['search', 'query', 'q', 'keyword']):
            return 'search'
        if any(x in name for x in ['comment', 'message', 'description', 'text', 'content', 'body']):
            return 'text'

        # Check placeholder hints
        if 'email' in placeholder:
            return 'email'
        if 'phone' in placeholder:
            return 'phone'

        return 'string'

    def _extract_from_frame(self, frame):
        return frame.evaluate(r"""
            () => {
                const looksLikeUrl = (v) => {
                    if (!v) return false;
                    const val = v.trim();
                    if (!val || val.startsWith('#')) return false;
                    const lower = val.toLowerCase();
                    if (lower.startsWith('javascript:') || lower.startsWith('mailto:') || lower.startsWith('tel:') || lower.startsWith('data:') || lower.startsWith('blob:')) {
                        return false;
                    }
                    if (val.startsWith('/') || val.startsWith('http://') || val.startsWith('https://')) return true;
                    if (/\.(php|asp|aspx|jsp|html?)(\?|#|$)/i.test(val)) return true;
                    if (val.includes('/')) return true;
                    return false;
                };

                // Get all anchor links
                const links = Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.getAttribute('href'));

                // Also get links from buttons that navigate (onclick with location or href)
                const buttonLinks = Array.from(document.querySelectorAll('button[onclick], a.btn, [onclick]'))
                    .map(b => {
                        const onclick = b.getAttribute('onclick') || '';
                        const href = b.getAttribute('href') || '';
                        if (href && !href.startsWith('#') && !href.startsWith('javascript:')) return href;
                        // Match various onclick patterns
                        const patterns = [
                            /location\.href\s*=\s*['"]([^'"]+)['"]/,
                            /location\s*=\s*['"]([^'"]+)['"]/,
                            /window\.location\.href\s*=\s*['"]([^'"]+)['"]/,
                            /window\.location\s*=\s*['"]([^'"]+)['"]/,
                            /navigate\s*\(\s*['"]([^'"]+)['"]/,
                            /href\s*=\s*['"]([^'"]+)['"]/
                        ];
                        for (const pattern of patterns) {
                            const match = onclick.match(pattern);
                            if (match) return match[1];
                        }
                        return null;
                    })
                    .filter(l => l);

                // Combine all links
                const allLinks = [...new Set([...links, ...buttonLinks])];

                const forms = Array.from(document.querySelectorAll('form')).map(f => {
                    // Get associated label for an input
                    const getLabel = (input) => {
                        const id = input.getAttribute('id');
                        if (id) {
                            const label = document.querySelector(`label[for="${id}"]`);
                            if (label) return (label.textContent || '').trim();
                        }
                        const parentLabel = input.closest('label');
                        if (parentLabel) return (parentLabel.textContent || '').trim().replace(input.value || '', '').trim();
                        return '';
                    };

                    return {
                        action: f.getAttribute('action') || '',
                        method: (f.getAttribute('method') || 'GET').toUpperCase(),
                        enctype: f.getAttribute('enctype') || 'application/x-www-form-urlencoded',
                        id: f.getAttribute('id') || '',
                        name: f.getAttribute('name') || '',
                        inputs: Array.from(f.querySelectorAll('input, textarea, select')).map(i => {
                            const tag = (i.tagName || '').toLowerCase();
                            const input = {
                                name: i.getAttribute('name') || i.getAttribute('id') || '',
                                type: (i.getAttribute('type') || tag || 'text').toLowerCase(),
                                value: i.getAttribute('value') || '',
                                // Additional attributes for security testing
                                disabled: i.hasAttribute('disabled'),
                                readonly: i.hasAttribute('readonly'),
                                required: i.hasAttribute('required'),
                                maxlength: i.getAttribute('maxlength') || '',
                                minlength: i.getAttribute('minlength') || '',
                                pattern: i.getAttribute('pattern') || '',
                                placeholder: i.getAttribute('placeholder') || '',
                                autocomplete: i.getAttribute('autocomplete') || '',
                                min: i.getAttribute('min') || '',
                                max: i.getAttribute('max') || '',
                                step: i.getAttribute('step') || '',
                                label: getLabel(i)
                            };
                            if (tag === 'select') {
                                input.options = Array.from(i.querySelectorAll('option')).map(o => ({
                                    value: o.getAttribute('value') || '',
                                    label: (o.textContent || '').trim()
                                }));
                            }
                            return input;
                        })
                    };
                });
                const hiddenFields = Array.from(document.querySelectorAll('input[type="hidden"]')).map(h => ({
                    name: h.getAttribute('name') || h.getAttribute('id') || '',
                    value: h.getAttribute('value') || ''
                }));
                const fileUploads = Array.from(document.querySelectorAll('input[type="file"]')).map(f => ({
                    name: f.getAttribute('name') || f.getAttribute('id') || '',
                    accept: f.getAttribute('accept') || ''
                }));
                const looseInputs = Array.from(document.querySelectorAll('input, textarea, select'))
                    .filter(i => !i.closest('form'))
                    .map(i => ({
                        name: i.getAttribute('name') || i.getAttribute('id') || '',
                        type: (i.getAttribute('type') || i.tagName || 'text').toLowerCase()
                    }));
                const dataLinks = [];
                const dataAttrs = ['data-href', 'data-url', 'data-action', 'data-target', 'data-link', 'data-path'];
                dataAttrs.forEach(attr => {
                    document.querySelectorAll(`[${attr}]`).forEach(el => {
                        const v = el.getAttribute(attr) || '';
                        if (looksLikeUrl(v)) dataLinks.push(v);
                    });
                });

                const optionLinks = [];
                document.querySelectorAll('select option').forEach(opt => {
                    const v = opt.getAttribute('value') || '';
                    if (looksLikeUrl(v)) optionLinks.push(v);
                });

                return { links: allLinks, forms, hiddenFields, fileUploads, looseInputs, dataLinks, optionLinks };
            }
        """)

    # =========================================================================
    # CLICK DEDUPLICATION — prevent re-clicking the same navigation elements
    # across different pages that share the same global nav/header/footer.
    # =========================================================================

    def _fingerprint_element(self, page, el):
        """Generate a unique fingerprint for a DOM element so we never click it twice.
        Combines tag, trimmed text, key attributes, and parent context."""
        try:
            fp_data = page.evaluate(r"""
                (el) => {
                    const tag = el.tagName || '';
                    const text = (el.textContent || '').trim().substring(0, 80);
                    const aria = el.getAttribute('aria-label') || '';
                    const role = el.getAttribute('role') || '';
                    const cls = el.className || '';
                    const href = el.getAttribute('href') || el.getAttribute('data-href') || '';
                    const onclick = (el.getAttribute('onclick') || '').substring(0, 100);
                    // Include parent tag+class for context (same button text in different sections)
                    const parent = el.parentElement;
                    const parentCtx = parent ? (parent.tagName + '|' + (parent.className || '').substring(0, 40)) : '';
                    return tag + '||' + text + '||' + aria + '||' + role + '||'
                           + cls.substring(0, 60) + '||' + href + '||' + onclick + '||' + parentCtx;
                }
            """, el)
            return fp_data
        except Exception:
            return None

    def _is_element_already_clicked(self, page, el):
        """Check if this element (by fingerprint) has already been clicked globally."""
        fp = self._fingerprint_element(page, el)
        if fp is None:
            return False  # Can't fingerprint — allow click
        if fp in self._clicked_element_fps:
            return True
        self._clicked_element_fps.add(fp)
        return False

    def _get_nav_structure_key(self, url):
        """Generate a key for the navigation structure of a page.
        Pages under the same path prefix share the same nav, so we only
        need to explore the nav once per unique prefix."""
        try:
            parsed = urlparse(url)
            # Use host + first 2 path segments as the nav structure key
            parts = parsed.path.strip('/').split('/')
            prefix = '/'.join(parts[:2]) if len(parts) >= 2 else parsed.path
            return f"{parsed.netloc}/{prefix}"
        except Exception:
            return url

    def _has_nav_been_explored(self, url):
        """Check if navigation for this page's section has already been explored."""
        key = self._get_nav_structure_key(url)
        if key in self._explored_nav_structures:
            return True
        return False

    def _mark_nav_explored(self, url):
        """Mark this page section's navigation as explored."""
        key = self._get_nav_structure_key(url)
        self._explored_nav_structures.add(key)

    def _get_page_content_hash(self, page):
        """Generate a hash of the page's main content area to detect duplicate layouts.
        Strips navigation/header/footer to focus on unique content."""
        try:
            content_hash = page.evaluate(r"""
                () => {
                    // Try to get just the main content, excluding nav/header/footer
                    const main = document.querySelector('main, [role="main"], #content, .content, article');
                    let text = '';
                    if (main) {
                        text = main.innerText || '';
                    } else {
                        // Fallback: get body text minus nav elements
                        const body = document.body;
                        if (!body) return '';
                        const clone = body.cloneNode(true);
                        clone.querySelectorAll('nav, header, footer, [role="navigation"], .nav, .header, .footer, .menu').forEach(el => el.remove());
                        text = clone.innerText || '';
                    }
                    // Simple hash: first 200 chars + length
                    const trimmed = text.trim().substring(0, 500);
                    return trimmed.length + '|' + trimmed.substring(0, 200);
                }
            """)
            return content_hash
        except Exception:
            return None

    def _precheck_urls_alive(self, urls, max_workers=20):
        """Fast parallel pre-check: HEAD request each URL, keep only live ones.
        Filters out 404s and dead endpoints BEFORE adding them to the browser queue.
        This saves massive crawl time — no more navigating to hundreds of dead sitemap URLs."""
        import requests as _req
        from concurrent.futures import ThreadPoolExecutor, as_completed

        live = set()
        dead = 0
        checked = 0
        total = len(urls)

        def _check(url):
            try:
                r = _req.head(url, timeout=6, verify=False, allow_redirects=True)
                return url, r.status_code
            except Exception:
                try:
                    r = _req.get(url, timeout=6, verify=False, stream=True)
                    code = r.status_code
                    r.close()
                    return url, code
                except Exception:
                    return url, 0

        print(f"[*] Pre-checking {total} discovered URLs (parallel HEAD requests)...")
        self._log_scan('info', f'Pre-checking {total} URLs for liveness', {'total': total})

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_check, u): u for u in urls}
            for f in as_completed(futures):
                checked += 1
                url, status = f.result()
                if status and 200 <= status < 404:
                    live.add(url)
                elif status == 404:
                    dead += 1
                if checked % 50 == 0 or checked == total:
                    print(f"    → {checked}/{total} — {len(live)} live, {dead} dead")

        print(f"[+] Pre-check: {len(live)} live, {dead} dead (404), {total - len(live) - dead} errors")
        return live

    def _get_404_pattern(self, url):
        """Convert URL to a pattern for 404 tracking.
        e.g. /api/v2/s/448071/live_feeds -> /api/v2/s/*/live_feeds
        Groups similar URLs so 3 failures in a pattern skips all remaining."""
        try:
            parsed = urlparse(url)
            parts = parsed.path.strip('/').split('/')
            if len(parts) < 2:
                return None
            # Replace numeric segments with * to create pattern
            pattern_parts = []
            for part in parts:
                if part.isdigit() or (len(part) > 8 and all(c in '0123456789abcdef-' for c in part)):
                    pattern_parts.append('*')
                else:
                    pattern_parts.append(part)
            return parsed.netloc + '/' + '/'.join(pattern_parts)
        except Exception:
            return None

    def _click_through(self, page, current_url, depth, queue):
        if not self.click_through:
            return
        if page.is_closed():
            return
        if not self._consume_interaction_budget(current_url, n=1):
            return
        self._recover_if_asset_navigation(page, current_url)
        try:
            limit = int(os.getenv("HEADLESS_CLICK_LIMIT", "20"))
        except ValueError:
            limit = 20
        clicked = 0
        discovered_urls = set()

        # Phase 1: Click collapsible elements to expand hidden content
        # Look for buttons that toggle/expand content (no onclick navigation)
        # Uses global fingerprint dedup to avoid re-clicking the same buttons across pages
        collapsible_selectors = [
            "button.coll", "button[data-toggle]", "button[data-bs-toggle]",
            "[class*='collapse']", "[class*='accordion']", "[class*='expand']",
            "button.btn:not([onclick])",
            # React MUI / Material-UI sidebar patterns
            "[class*='MuiListItem']", "[class*='MuiTreeItem']",
            "[class*='MuiAccordion'] [class*='MuiAccordionSummary']",
            "[class*='MuiCollapse']",
            # React Suite (rsuite) sidebar/dropdown patterns
            ".rs-dropdown-toggle", ".rs-sidenav .rs-dropdown",
            "[class*='rs-dropdown-toggle']",
            # Ant Design sidebar patterns
            ".ant-menu-submenu-title", ".ant-collapse-header",
            # Chakra UI / Headless UI patterns
            "[class*='chakra-accordion'] button", "[class*='disclosure'] button",
            # Generic SPA sidebar/nav patterns
            "[class*='sidebar'] li", "[class*='Sidebar'] li",
            "[class*='nav-item']", "[class*='menu-item']",
            "[class*='tree-node']", "[class*='TreeNode']",
            "[role='treeitem']", "[role='menuitem']",
        ]
        _collapsible_clicked = 0
        _collapsible_skipped = 0
        for selector in collapsible_selectors:
            try:
                elements = page.query_selector_all(selector)
                for el in elements:
                    try:
                        if page.is_closed():
                            return
                        if not el.is_visible():
                            continue
                        text = (el.inner_text() or "").lower()
                        # Skip navigation buttons, only click expandable ones
                        if any(skip in text for skip in ['logout', 'sign out', 'login', 'sign in', 'delete', 'remove', 'submit', 'access']):
                            continue
                        # Dedup: skip if this exact element was already clicked on another page
                        if self._is_element_already_clicked(page, el):
                            _collapsible_skipped += 1
                            continue
                        # Click to expand
                        el.click(timeout=1000)
                        _collapsible_clicked += 1
                        try:
                            page.wait_for_timeout(300)  # Brief wait for expansion
                        except Exception:
                            return
                        self._recover_if_asset_navigation(page, current_url)
                    except:
                        continue
            except:
                continue
        if _collapsible_skipped > 0:
            print(f"[DEDUP] Skipped {_collapsible_skipped} already-clicked collapsibles, clicked {_collapsible_clicked} new ones")

        # Brief wait for all content to expand
        try:
            page.wait_for_timeout(500)
        except Exception:
            return

        # Phase 1b: After expanding, extract all newly visible links from
        # expanded menus (React Suite, Ant Design, etc.)
        try:
            expanded_links = page.evaluate("""
                () => {
                    const links = [];
                    // React Suite expanded dropdown items
                    const selectors = [
                        '.rs-dropdown-menu-collapse-in a',
                        '.rs-dropdown-item a',
                        '.rs-dropdown-item-content',
                        // Ant Design
                        '.ant-menu-item a',
                        '.ant-menu-submenu-open a',
                        // Generic expanded menu items
                        '[class*="collapse-in"] a',
                        '[class*="menu-open"] a',
                        '[aria-expanded="true"] + * a',
                    ];
                    for (const sel of selectors) {
                        document.querySelectorAll(sel).forEach(a => {
                            const href = a.getAttribute('href');
                            if (href && href !== '#' && !href.startsWith('javascript:')) {
                                links.push(href);
                            }
                        });
                    }
                    return [...new Set(links)];
                }
            """)
            for link in expanded_links:
                normalized = self._normalize_url(current_url, link)
                if normalized and normalized not in self.visited:
                    if self._is_allowed_url(normalized):
                        discovered_urls.add(normalized)
            if expanded_links:
                print(f"[+] Found {len(expanded_links)} links from expanded menus")
        except Exception as e:
            print(f"[!] Error extracting expanded menu links: {e}")

        # Phase 1c: Click-explore SPA menu items that use React/Vue synthetic events
        # (no href, no onclick attr — must click and observe URL change)
        # Strategy: collect all item texts first, then for each item:
        #   1. Navigate to page, 2. Expand all dropdowns, 3. Find item by text, 4. Click it
        # This avoids stale element handles after navigation.
        try:
            _skip_texts = {
                'logout', 'sign out', 'login', 'sign in', 'delete',
                'github', 'about us', 'home', 'external', 'donate',
                'twitter', 'facebook', 'linkedin', 'discord', 'slack',
                'owasp', 'zap', 'addon', 'projects by', 'scanners',
                'dast', 'sast', 'documentation', 'wiki', 'blog',
            }
            # Step 1: Collect all menu item texts from currently expanded + collapsed menus
            spa_item_texts = page.evaluate("""
                () => {
                    const texts = [];
                    const seen = new Set();
                    // Expand all dropdowns first by clicking toggles
                    document.querySelectorAll('.rs-dropdown-toggle, .rs-btn.rs-dropdown-toggle').forEach(t => {
                        try { t.click(); } catch(e) {}
                    });
                    // Brief wait for expansion
                    const selectors = [
                        '.rs-dropdown-item-content',
                        '.rs-dropdown-item > a:not([href])',
                        '.ant-menu-item a:not([href])',
                    ];
                    for (const sel of selectors) {
                        document.querySelectorAll(sel).forEach(el => {
                            const text = (el.textContent || '').trim();
                            // Get parent dropdown name for context (to disambiguate LEVEL_1 across categories)
                            let parent = el.closest('.rs-dropdown');
                            let parentText = '';
                            if (parent) {
                                const toggle = parent.querySelector('.rs-dropdown-toggle');
                                if (toggle) parentText = (toggle.textContent || '').trim();
                            }
                            const key = parentText + '::' + text;
                            if (text && !seen.has(key)) {
                                seen.add(key);
                                texts.push({text, parentText, selector: sel});
                            }
                        });
                    }
                    return texts;
                }
            """)

            if not spa_item_texts:
                spa_item_texts = []

            # Filter out skip texts
            spa_item_texts = [
                item for item in spa_item_texts
                if item['text'] and not any(skip in item['text'].lower() for skip in _skip_texts)
            ]

            if spa_item_texts:
                print(f"[+] Found {len(spa_item_texts)} SPA menu items to click-explore")
                _spa_explored = 0
                _spa_visited_urls = set()

                for item in spa_item_texts:
                    try:
                        if page.is_closed():
                            return
                        item_text = item['text']
                        parent_text = item['parentText']

                        # Navigate fresh to the page
                        page.goto(current_url, wait_until='domcontentloaded', timeout=8000)
                        try:
                            page.wait_for_load_state('networkidle', timeout=2000)
                        except Exception:
                            page.wait_for_timeout(500)

                        # Expand the specific parent dropdown
                        if parent_text:
                            safe_parent = parent_text.replace("'", "\\'")
                            try:
                                page.evaluate(f"""
                                    () => {{
                                        document.querySelectorAll('.rs-dropdown-toggle, .rs-btn.rs-dropdown-toggle').forEach(t => {{
                                            if ((t.textContent || '').trim() === '{safe_parent}') {{
                                                t.click();
                                            }}
                                        }});
                                    }}
                                """)
                                page.wait_for_timeout(300)
                            except Exception:
                                pass

                        # Find and click the specific menu item by exact text
                        before_url = page.url
                        safe_item = item_text.replace("'", "\\'")
                        clicked = page.evaluate(f"""
                            () => {{
                                const target = '{safe_item}';
                                const els = document.querySelectorAll('.rs-dropdown-item-content, .rs-dropdown-item > a');
                                for (const el of els) {{
                                    if ((el.textContent || '').trim() === target && el.offsetParent !== null) {{
                                        el.click();
                                        return true;
                                    }}
                                }}
                                return false;
                            }}
                        """)

                        if not clicked:
                            continue

                        try:
                            page.wait_for_load_state('networkidle', timeout=3000)
                        except Exception:
                            page.wait_for_timeout(500)

                        after_url = page.url
                        if (after_url and after_url != before_url
                                and after_url not in self.visited
                                and after_url not in _spa_visited_urls):
                            if self._is_allowed_url(after_url):
                                discovered_urls.add(after_url)
                                _spa_visited_urls.add(after_url)
                                _spa_explored += 1
                    except Exception:
                        continue

                if _spa_explored > 0:
                    print(f"[+] Discovered {_spa_explored} URLs from SPA menu clicks")
        except Exception as e:
            print(f"[!] Error in SPA menu exploration: {e}")

        # Phase 2: Extract onclick URLs from ALL buttons (including newly visible ones)
        try:
            onclick_urls = page.evaluate("""
                () => {
                    const urls = [];
                    document.querySelectorAll('button[onclick], a[onclick], [onclick]').forEach(el => {
                        const onclick = el.getAttribute('onclick') || '';
                        const patterns = [
                            /window\\.location\\.href\\s*=\\s*['"]([^'"]+)['"]/,
                            /window\\.location\\s*=\\s*['"]([^'"]+)['"]/,
                            /location\\.href\\s*=\\s*['"]([^'"]+)['"]/,
                            /location\\s*=\\s*['"]([^'"]+)['"]/
                        ];
                        for (const pattern of patterns) {
                            const match = onclick.match(pattern);
                            if (match) {
                                urls.push(match[1]);
                                break;
                            }
                        }
                    });
                    return urls;
                }
            """)
            for url in onclick_urls:
                normalized = self._normalize_url(current_url, url)
                if normalized and normalized not in self.visited:
                    if self._is_allowed_url(normalized):
                        discovered_urls.add(normalized)
                        print(f"[+] Found onclick URL: {normalized}")
        except Exception as e:
            print(f"[!] Error extracting onclick URLs: {e}")

        # Add all discovered onclick URLs to queue - prioritize lab URLs
        for url in discovered_urls:
            priority = 'lab' in url.lower()
            self._enqueue_url(queue, url, depth + 1, priority=priority)

        # Phase 3: Process regular links and navigation buttons
        # Uses global fingerprint dedup to skip already-explored nav buttons
        elements = page.query_selector_all("a[href], a.btn, button.btn[onclick], button[onclick]")
        for el in elements:
            if clicked >= limit:
                break
            try:
                if page.is_closed():
                    return
                if not el.is_visible():
                    continue

                # Skip logout/login buttons
                text = (el.inner_text() or "").lower()
                if any(skip in text for skip in ['logout', 'sign out', 'login', 'sign in', 'delete', 'remove']):
                    continue

                tag = el.evaluate("el => el.tagName.toLowerCase()")
                if tag == "a":
                    href = el.get_attribute("href") or ""
                    normalized = self._normalize_url(current_url, href)
                    if not normalized:
                        continue
                    if not self._is_allowed_url(normalized):
                        continue
                    # For links, just add to queue without clicking
                    self._enqueue_url(queue, normalized, depth + 1)
                    continue

                # Dedup: skip if this button was already clicked on another page
                if self._is_element_already_clicked(page, el):
                    continue

                # For buttons with onclick, click and see where they navigate
                onclick = el.get_attribute("onclick") or ""
                if not onclick:
                    continue  # Skip buttons without onclick (collapsibles already handled)

                el.click(timeout=2000)
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=3000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=1000)
                    except Exception:
                        pass
                except Exception:
                    page.wait_for_timeout(500)

                new_url = page.url
                if new_url and new_url != current_url:
                    # Avoid looping on login pages or repeating the same navigation
                    if self._is_login_page(page):
                        try:
                            goto_timeout = min(int(self.timeout or 15000), 12000)
                            page.goto(current_url, wait_until="domcontentloaded", timeout=goto_timeout)
                            try:
                                page.wait_for_load_state("networkidle", timeout=1000)
                            except Exception:
                                pass
                        except Exception:
                            pass
                        continue
                    if self._enqueue_url(queue, new_url, depth + 1):
                        print(f"[+] Button click navigated to: {new_url}")
                    clicked += 1
                    try:
                        page.go_back(timeout=2000)
                        page.wait_for_load_state("domcontentloaded", timeout=2000)
                        try:
                            page.wait_for_load_state("networkidle", timeout=1000)
                        except Exception:
                            pass
                    except Exception:
                        # If go_back fails, navigate back to current URL
                        try:
                            goto_timeout = min(int(self.timeout or 15000), 12000)
                            page.goto(current_url, wait_until="domcontentloaded", timeout=goto_timeout)
                            try:
                                page.wait_for_load_state("networkidle", timeout=1000)
                            except Exception:
                                pass
                        except:
                            pass
            except Exception:
                continue

    def _is_login_page(self, page):
        """Check if current page is the main application login page (not a lab login form)."""
        try:
            url_lower = page.url.lower()

            # Skip detection for lab pages - they have login forms but aren't THE login page
            if any(skip in url_lower for skip in ['lab', 'challenge', 'vuln', 'test', 'exercise']):
                return False

            # Check if this is specifically the main login URL (compare by path, not full URL)
            # This handles cases where query params are added after failed login
            if self.login_url:
                from urllib.parse import urlparse
                login_path = urlparse(self.login_url.lower()).path
                current_path = urlparse(url_lower).path
                if login_path and current_path == login_path:
                    return True

            # Check URL patterns for main login pages
            # Be more specific - must be a dedicated login endpoint
            login_url_patterns = ['/login', '/signin', '/sign-in', '/authenticate',
                                  '/login.php', '/signin.php', '/login.asp', '/login.aspx',
                                  '/login.jsp', '/login.html']
            current_path = urlparse(url_lower).path if '/' in url_lower else url_lower
            if any(current_path == pattern or current_path.rstrip('/') == pattern
                   for pattern in login_url_patterns):
                return True
            # Also check partial matches (e.g. /accounts/login/)
            if any(url_lower.endswith(pattern) or (pattern + '/') in url_lower or (pattern + '?') in url_lower
                   for pattern in ['/login', '/signin', '/sign-in', '/authenticate']):
                return True

            # Check for login form indicators that suggest we were redirected to login
            content = page.content().lower()
            login_redirect_indicators = [
                'please log in to continue', 'session expired',
                'you must be logged in', 'login required',
                'unauthorized', 'access denied'
            ]
            if any(indicator in content for indicator in login_redirect_indicators):
                return True

            return False
        except:
            return False

    def _verify_login_success(self, page, pre_login_url):
        """Verify if login was successful."""
        try:
            current_url = page.url
            content = page.content().lower()

            print(f"[*] Login verification: pre_login_url={pre_login_url}, current_url={current_url}")

            # FIRST: Check if we're still on the login page — this means login FAILED
            # (must come before cookie check because PHP always sets PHPSESSID)
            if self._is_login_page(page):
                # Check for specific login error messages
                error_indicators = [
                    'invalid username', 'invalid password', 'incorrect password',
                    'wrong password', 'wrong username', 'authentication failed',
                    'login failed', 'please enter a correct', 'invalid credentials',
                    'invalid login', 'error', 'not valid'
                ]
                for err in error_indicators:
                    if err in content:
                        print(f"[!] Login failed - still on login page, error detected: '{err}'")
                        return False
                print(f"[!] Login failed - still on login page (no redirect happened)")
                return False

            # Check for success indicators (most reliable)
            success_indicators = [
                'logout', 'sign out', 'signout', 'log out'
            ]
            if any(indicator in content for indicator in success_indicators):
                print(f"[+] Login successful - found logout button")
                return True

            # Check if URL changed from login page (redirect happened)
            if current_url != pre_login_url:
                print(f"[+] Login successful - redirected to: {current_url}")
                return True

            # Check for session cookie (but NOT phpsessid — PHP always sets it)
            cookies = page.context.cookies()
            session_cookie_names = ['sessionid', 'session', 'sid', 'jsessionid']
            for cookie in cookies:
                if any(name in cookie.get('name', '').lower() for name in session_cookie_names):
                    if cookie.get('value'):
                        print(f"[+] Login successful - session cookie found: {cookie.get('name')}")
                        return True

            print(f"[!] Login verification inconclusive - no success indicators found")
            return False
        except Exception as e:
            print(f"[!] Error verifying login: {e}")
            return False

    def _do_login(self, page):
        """Attempt to login using provided credentials with verification.
        Supports form login, OAuth 2.0, SAML SSO, API key, and HTTP Basic auth.
        Uses AI to analyze login page when available.
        """
        # Dispatch to specialized auth handlers
        if self.auth_type == 'api_key':
            return self._do_api_key_login(page)
        elif self.auth_type == 'http_basic':
            return self._do_http_basic_login(page)

        # OAuth and SAML still need login_url
        if not self.login_url:
            return False

        if self.auth_type == 'oauth':
            return self._do_oauth_login(page)
        elif self.auth_type == 'saml':
            return self._do_saml_login(page)

        # Default: form-based login
        if not self.username:
            return False

        # Fail-fast: do not loop on login again and again.
        if getattr(self, '_login_permanently_failed', False):
            return False
        if getattr(self, '_login_attempted_once', False) and not getattr(self, '_logged_in', False):
            return False

        if self._login_attempts >= self._max_login_attempts:
            print(f"[!] Max login attempts ({self._max_login_attempts}) reached")
            return False

        self._login_attempts += 1
        self._login_attempted_once = True
        print(f"[*] Login attempt {self._login_attempts}/{self._max_login_attempts} to {self.login_url}")

        try:
            # Avoid networkidle: many login pages keep connections open.
            # Allow up to 30s — slow .gov hosts can exceed a 10s page load.
            goto_timeout = min(int(self.timeout or 15000), 30000)
            page.goto(self.login_url, wait_until="domcontentloaded", timeout=goto_timeout)
            pre_login_url = page.url
            page.wait_for_timeout(800)

            # Try AI-powered login first
            if self.ai_api_key:
                print("[AI] Analyzing login page...")
                login_html = page.content()
                ai_login_info = self._ai_analyze_login_page(login_html)

                if ai_login_info and ai_login_info.get('fields'):
                    print(f"[AI] Login form analyzed: {list(ai_login_info.get('fields', {}).keys())}")
                    try:
                        # Fill all fields using AI-detected names
                        for field_name, field_value in ai_login_info.get('fields', {}).items():
                            try:
                                selector = f'[name="{field_name}"]'
                                locator = page.locator(selector)
                                if locator.count() > 0:
                                    # Get the tag name to handle different element types
                                    tag_name = locator.first.evaluate("el => el.tagName.toLowerCase()")
                                    input_type = locator.first.get_attribute('type') or 'text'

                                    if tag_name == 'select':
                                        # Handle <select> elements - use select_option
                                        try:
                                            locator.first.select_option(value=str(field_value))
                                            print(f"[AI] Selected option '{field_value}' for '{field_name}'")
                                        except:
                                            # Try selecting by label if value fails
                                            try:
                                                locator.first.select_option(label=str(field_value))
                                            except:
                                                pass
                                    elif tag_name == 'button':
                                        # Skip button elements - they are for submission, not filling
                                        pass
                                    elif tag_name == 'textarea':
                                        # Handle <textarea> elements
                                        locator.first.fill(str(field_value))
                                        print(f"[AI] Filled textarea '{field_name}'")
                                    elif input_type == 'hidden':
                                        # Hidden fields are already set, but verify value
                                        current_val = locator.first.get_attribute('value')
                                        if current_val != field_value:
                                            page.evaluate(f'document.querySelector("[name=\\"{field_name}\\"]").value = "{field_value}"')
                                    elif input_type in ('checkbox', 'radio'):
                                        # Handle checkbox/radio - check if value matches
                                        if str(field_value).lower() in ('true', '1', 'on', 'checked'):
                                            locator.first.check()
                                        print(f"[AI] Set {input_type} '{field_name}'")
                                    else:
                                        # Standard input elements (text, password, email, etc.)
                                        locator.first.clear()
                                        locator.first.fill(str(field_value))
                                        print(f"[AI] Filled field '{field_name}'")
                            except Exception as e:
                                print(f"[AI] Error filling {field_name}: {e}")

                        # Submit the form
                        submit_selector = ai_login_info.get('submit_selector', 'button[type="submit"]')
                        try:
                            page.locator(submit_selector).first.click()
                            print(f"[AI] Clicked submit: {submit_selector}")
                        except:
                            # Fallback to common submit buttons
                            for sel in ['button[type="submit"]', 'input[type="submit"]', 'button.btn-primary']:
                                try:
                                    if page.locator(sel).count() > 0:
                                        page.locator(sel).first.click()
                                        break
                                except:
                                    continue

                        # Wait for navigation
                        try:
                            page.wait_for_load_state("domcontentloaded", timeout=8000)
                        except:
                            pass
                        page.wait_for_timeout(1200)

                        # Verify login
                        if self._verify_login_success(page, pre_login_url):
                            self._logged_in = True
                            print(f"[AI] Login successful!")
                            # Profile the app after successful login
                            self._ai_profile_app(page.content(), page.url)
                            return True
                        else:
                            print("[AI] Login verification failed, trying standard method...")

                    except Exception as e:
                        print(f"[AI] Login error: {e}, falling back to standard method")

            # Try common username field selectors (ordered by specificity)
            username_selectors = [
                '#id_username', '#username', '#login', '#email',
                'input[name="username"]', 'input[name="login"]', 'input[name="user"]',
                'input[name="email"]', 'input[id*="user"]', 'input[id*="login"]',
                'input[type="text"]:not([name=""])', 'input[type="email"]'
            ]
            password_selectors = [
                '#id_password', '#password', '#pass',
                'input[name="password"]', 'input[name="pass"]', 'input[name="passwd"]',
                'input[type="password"]'
            ]
            submit_selectors = [
                'button[type="submit"]:has-text("Login")',
                'button[type="submit"]:has-text("Sign in")',
                'button[type="submit"]:has-text("Log in")',
                'button[type="submit"]:has-text("Continue")',
                'button[type="submit"]:has-text("Next")',
                'button:has-text("Login")',
                'button:has-text("Sign in")',
                'button:has-text("Log in")',
                'button:has-text("Continue")',
                'button:has-text("Next")',
                'input[type="submit"][value*="Login"]',
                'input[type="submit"][value*="Sign"]',
                'input[type="submit"][value*="Continue"]',
                'input[type="submit"][value*="Next"]',
                'button.btn-success[type="submit"]',
                'button.btn-info[type="submit"]',
                'button.btn-primary[type="submit"]',
                'input[type="submit"]',
                'button[type="submit"]',
                'form button.btn-success',
                'form button.btn-info',
                'form button.btn-primary'
            ]

            # Find and fill username
            username_filled = False
            for sel in username_selectors:
                try:
                    locator = page.locator(sel)
                    if locator.count() > 0 and locator.first.is_visible():
                        # Verify this is actually an input element, not a container
                        tag = locator.first.evaluate("el => el.tagName.toLowerCase()")
                        if tag not in ('input', 'textarea'):
                            print(f"[*] Skipping {sel} — matched <{tag}>, not an input")
                            continue
                        locator.first.clear()
                        locator.first.fill(self.username)
                        # Verify the value was actually set
                        actual_val = locator.first.input_value()
                        print(f"[+] Filled username using: {sel} (tag=<{tag}>, value='{actual_val}')")
                        username_filled = True
                        break
                except:
                    continue

            if not username_filled:
                print("[!] Could not find username field")
                return False

            # Check if password field is visible on the same page
            password_visible = False
            for sel in password_selectors:
                try:
                    locator = page.locator(sel)
                    if locator.count() > 0 and locator.first.is_visible():
                        password_visible = True
                        break
                except:
                    continue

            # If password is visible, fill it (single-page login)
            if password_visible and self.password:
                for sel in password_selectors:
                    try:
                        locator = page.locator(sel)
                        if locator.count() > 0 and locator.first.is_visible():
                            locator.first.clear()
                            locator.first.fill(self.password)
                            actual_val = locator.first.input_value()
                            print(f"[+] Filled password using: {sel} (value length={len(actual_val)})")
                            break
                    except:
                        continue

            # Submit the first form (username or username+password)
            submitted = False
            for sel in submit_selectors:
                try:
                    locator = page.locator(sel)
                    if locator.count() > 0 and locator.first.is_visible():
                        locator.first.click()
                        print(f"[+] Clicked submit using: {sel}")
                        submitted = True
                        break
                except:
                    continue

            if not submitted:
                # Try pressing Enter on the last filled field
                try:
                    if password_visible:
                        page.locator('input[type="password"]').first.press("Enter")
                    else:
                        page.locator('input[name="username"], input[type="text"]').first.press("Enter")
                    print("[+] Submitted form via Enter key")
                    submitted = True
                except:
                    pass

            if not submitted:
                print("[!] Could not find submit button")
                return False

            # Wait for navigation/response
            try:
                page.wait_for_load_state("domcontentloaded", timeout=8000)
            except:
                pass
            page.wait_for_timeout(1500)  # Extra wait for redirects

            post_submit_url = page.url
            print(f"[*] After form submit: URL={post_submit_url} (was {pre_login_url})")
            # Log page title for debugging
            try:
                page_title = page.title()
                print(f"[*] After form submit: page title='{page_title}'")
            except:
                pass

            # Check if this is a TWO-STEP LOGIN (password page appeared after username)
            if not password_visible and self.password:
                print("[*] Checking for two-step login (separate password page)...")

                # Check if we're now on a password page
                password_page_detected = False
                for sel in password_selectors:
                    try:
                        locator = page.locator(sel)
                        if locator.count() > 0 and locator.first.is_visible():
                            password_page_detected = True
                            print(f"[+] Two-step login detected - password page found")
                            break
                    except:
                        continue

                if password_page_detected:
                    # Fill the password on the second page
                    for sel in password_selectors:
                        try:
                            locator = page.locator(sel)
                            if locator.count() > 0 and locator.first.is_visible():
                                locator.first.clear()
                                locator.first.fill(self.password)
                                print(f"[+] Filled password on step 2 using: {sel}")
                                break
                        except:
                            continue

                    # Submit the password form
                    submitted_step2 = False
                    for sel in submit_selectors:
                        try:
                            locator = page.locator(sel)
                            if locator.count() > 0 and locator.first.is_visible():
                                locator.first.click()
                                print(f"[+] Clicked submit on step 2 using: {sel}")
                                submitted_step2 = True
                                break
                        except:
                            continue

                    if not submitted_step2:
                        try:
                            page.locator('input[type="password"]').first.press("Enter")
                            print("[+] Submitted step 2 form via Enter key")
                            submitted_step2 = True
                        except:
                            pass

                    # Wait for navigation after password submission
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=8000)
                    except:
                        pass
                    page.wait_for_timeout(1200)

            # Verify login success
            if self._verify_login_success(page, pre_login_url):
                # Check for MFA prompt after primary login
                if self._detect_mfa_prompt(page):
                    print("[*] MFA/2FA prompt detected after login")
                    if not self._do_mfa_login(page):
                        print("[!] MFA authentication failed")
                        return False
                self._logged_in = True
                print(f"[+] Login verified successfully!")
                return True
            else:
                # Could be MFA page — check before declaring failure
                if self._detect_mfa_prompt(page):
                    print("[*] MFA/2FA prompt detected (login may still be in progress)")
                    if self._do_mfa_login(page):
                        if self._verify_login_success(page, pre_login_url):
                            self._logged_in = True
                            print(f"[+] Login verified after MFA!")
                            return True
                print(f"[!] Login verification failed")
                self._logged_in = False
                # Do not retry login repeatedly; mark as permanently failed and
                # skip the login URL to avoid getting stuck in a loop.
                self._login_permanently_failed = True
                try:
                    login_path = (urlparse(self.login_url).path or '').lower()
                    if login_path:
                        self._ai_skip_patterns.add(login_path)
                    self._ai_skip_patterns.add('/login')
                    self._ai_skip_patterns.add('login.php')
                    print(f"[AI] Added login skip patterns: {login_path}, /login, login.php")
                except Exception:
                    pass
                return False

        except Exception as e:
            print(f"[!] Login error: {e}")
            self._login_permanently_failed = True
            return False

    # ------------------------------------------------------------------
    # Advanced Authentication Methods
    # ------------------------------------------------------------------

    def _do_oauth_login(self, page):
        """Handle OAuth 2.0 authorization code flow via browser."""
        print(f"[*] OAuth 2.0 login flow starting at {self.login_url}")
        try:
            page.goto(self.login_url, wait_until="networkidle", timeout=self.timeout)
            pre_login_url = page.url
            time.sleep(2)

            # On the OAuth provider page, look for username/password fields
            # Common providers: Google, GitHub, Okta, Auth0, Azure AD
            username_selectors = [
                'input[name="login"]', 'input[name="username"]',
                'input[name="email"]', 'input[type="email"]',
                '#identifierId', '#username', '#login_field',
                'input[name="loginfmt"]',  # Microsoft/Azure AD
            ]
            password_selectors = [
                'input[name="password"]', 'input[type="password"]',
                '#password', '#Passwd',
            ]
            submit_selectors = [
                'button[type="submit"]', 'input[type="submit"]',
                '#identifierNext', '#passwordNext',  # Google
                'input[name="commit"]',  # GitHub
                'button[data-testid="submit"]',
            ]

            # Fill username
            username_filled = False
            for sel in username_selectors:
                try:
                    if page.locator(sel).count() > 0 and page.locator(sel).first.is_visible():
                        page.locator(sel).first.fill(self.username or '')
                        username_filled = True
                        print(f"[OAuth] Filled username via {sel}")
                        break
                except Exception:
                    continue

            if not username_filled:
                print("[!] OAuth: Could not find username field on provider page")
                return False

            # Submit username (some providers have multi-step)
            time.sleep(1)
            for sel in submit_selectors:
                try:
                    if page.locator(sel).count() > 0 and page.locator(sel).first.is_visible():
                        page.locator(sel).first.click()
                        break
                except Exception:
                    continue

            time.sleep(2)
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass

            # Fill password
            password_filled = False
            for sel in password_selectors:
                try:
                    if page.locator(sel).count() > 0 and page.locator(sel).first.is_visible():
                        page.locator(sel).first.fill(self.password or '')
                        password_filled = True
                        print(f"[OAuth] Filled password via {sel}")
                        break
                except Exception:
                    continue

            if password_filled:
                time.sleep(1)
                for sel in submit_selectors:
                    try:
                        if page.locator(sel).count() > 0 and page.locator(sel).first.is_visible():
                            page.locator(sel).first.click()
                            break
                    except Exception:
                        continue

            time.sleep(3)
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass

            # Handle consent/authorize screen
            consent_selectors = [
                'button:has-text("Allow")', 'button:has-text("Authorize")',
                'button:has-text("Accept")', 'button:has-text("Approve")',
                'button:has-text("Grant")', 'input[value="Approve"]',
                '#consent_accept', '#authorize',
            ]
            for sel in consent_selectors:
                try:
                    if page.locator(sel).count() > 0 and page.locator(sel).first.is_visible():
                        page.locator(sel).first.click()
                        print(f"[OAuth] Clicked consent button: {sel}")
                        time.sleep(3)
                        try:
                            page.wait_for_load_state("networkidle", timeout=10000)
                        except Exception:
                            pass
                        break
                except Exception:
                    continue

            # Check if we're back on the target application
            if self._verify_login_success(page, pre_login_url):
                self._logged_in = True
                print("[+] OAuth login successful!")
                return True

            print("[!] OAuth login may have failed — checking page state")
            return False

        except Exception as e:
            print(f"[!] OAuth login error: {e}")
            return False

    def _do_saml_login(self, page):
        """Handle SAML SSO login via browser redirect to IdP."""
        print(f"[*] SAML SSO login starting at {self.login_url}")
        try:
            page.goto(self.login_url, wait_until="networkidle", timeout=self.timeout)
            pre_login_url = page.url
            time.sleep(2)

            # SAML flow redirects to IdP — fill credentials there
            # Most IdPs use standard username/password forms
            username_selectors = [
                'input[name="username"]', 'input[name="email"]',
                'input[type="email"]', 'input[name="loginfmt"]',
                'input[name="UserName"]', '#username', '#i0116',
            ]
            password_selectors = [
                'input[name="password"]', 'input[type="password"]',
                'input[name="Password"]', '#password', '#i0118',
                '#passwordInput',
            ]
            submit_selectors = [
                'button[type="submit"]', 'input[type="submit"]',
                '#loginButton', '#submitButton', '#idSIButton9',
                'span:has-text("Sign in")', 'button:has-text("Sign in")',
                'button:has-text("Log in")',
            ]

            # Fill username
            for sel in username_selectors:
                try:
                    if page.locator(sel).count() > 0 and page.locator(sel).first.is_visible():
                        page.locator(sel).first.fill(self.username or '')
                        print(f"[SAML] Filled username via {sel}")
                        break
                except Exception:
                    continue

            time.sleep(1)

            # Click next/submit (multi-step flows)
            for sel in submit_selectors:
                try:
                    if page.locator(sel).count() > 0 and page.locator(sel).first.is_visible():
                        page.locator(sel).first.click()
                        break
                except Exception:
                    continue

            time.sleep(2)
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass

            # Fill password
            for sel in password_selectors:
                try:
                    if page.locator(sel).count() > 0 and page.locator(sel).first.is_visible():
                        page.locator(sel).first.fill(self.password or '')
                        print(f"[SAML] Filled password via {sel}")
                        break
                except Exception:
                    continue

            time.sleep(1)

            # Submit
            for sel in submit_selectors:
                try:
                    if page.locator(sel).count() > 0 and page.locator(sel).first.is_visible():
                        page.locator(sel).first.click()
                        break
                except Exception:
                    continue

            time.sleep(3)
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass

            # After SAML assertion processing, verify login
            if self._verify_login_success(page, pre_login_url):
                self._logged_in = True
                print("[+] SAML SSO login successful!")
                return True

            print("[!] SAML login verification failed")
            return False

        except Exception as e:
            print(f"[!] SAML login error: {e}")
            return False

    def _do_api_key_login(self, page):
        """Set custom auth headers for API key authentication."""
        if not self.api_key_header or not self.api_key_value:
            print("[!] API key auth requires header name and value")
            return False

        print(f"[*] Setting API key auth header: {self.api_key_header}")
        self._custom_auth_headers[self.api_key_header] = self.api_key_value

        # Set route handler to inject custom headers into all requests
        try:
            parsed = urlparse(self.target_url)
            target_pattern = f'**{parsed.netloc}/**'

            def inject_headers(route):
                headers = {**route.request.headers, **self._custom_auth_headers}
                route.continue_(headers=headers)

            page.route(target_pattern, inject_headers)
            print(f"[+] API key header will be injected on all requests to {parsed.netloc}")
            self._logged_in = True
            return True
        except Exception as e:
            print(f"[!] API key auth setup error: {e}")
            return False

    def _do_http_basic_login(self, page):
        """Set HTTP Basic Authorization header via route handler."""
        if not self.username or not self.password:
            print("[!] HTTP Basic auth requires username and password")
            return False

        import base64
        creds = base64.b64encode(f'{self.username}:{self.password}'.encode()).decode()
        self._custom_auth_headers['Authorization'] = f'Basic {creds}'
        print(f"[*] Setting HTTP Basic auth for user: {self.username}")

        try:
            parsed = urlparse(self.target_url)
            target_pattern = f'**{parsed.netloc}/**'

            def inject_basic_auth(route):
                headers = {**route.request.headers, **self._custom_auth_headers}
                route.continue_(headers=headers)

            page.route(target_pattern, inject_basic_auth)
            self._logged_in = True
            print(f"[+] HTTP Basic auth header will be injected on all requests")
            return True
        except Exception as e:
            print(f"[!] HTTP Basic auth setup error: {e}")
            return False

    def _detect_mfa_prompt(self, page):
        """Detect if the current page is showing an MFA/2FA prompt."""
        try:
            content = page.content().lower()
            mfa_indicators = [
                'two-factor', 'two factor', '2fa', 'mfa',
                'verification code', 'authenticator',
                'one-time', 'one time', 'otp', 'totp',
                'security code', 'confirm your identity',
                'enter the code', 'enter code',
            ]
            if any(indicator in content for indicator in mfa_indicators):
                # Also check for an input field that looks like a code input
                code_selectors = [
                    'input[name*="otp"]', 'input[name*="totp"]',
                    'input[name*="code"]', 'input[name*="token"]',
                    'input[name*="2fa"]', 'input[name*="mfa"]',
                    'input[name*="verification"]',
                    'input[autocomplete="one-time-code"]',
                ]
                for sel in code_selectors:
                    try:
                        if page.locator(sel).count() > 0:
                            return True
                    except Exception:
                        continue
                # Even without matching selector, text indicators are strong enough
                return True
        except Exception:
            pass
        return False

    def _do_mfa_login(self, page):
        """Handle MFA/2FA challenge — auto-generate TOTP or ask user."""
        print("[*] Handling MFA/2FA challenge...")

        totp_code = None

        # Auto-generate TOTP code if secret is provided
        if self.mfa_secret:
            try:
                import pyotp
                totp = pyotp.TOTP(self.mfa_secret)
                totp_code = totp.now()
                print(f"[*] Generated TOTP code: {totp_code[:2]}****")
            except ImportError:
                print("[!] pyotp not installed — cannot auto-generate TOTP code")
            except Exception as e:
                print(f"[!] TOTP generation failed: {e}")

        if not totp_code:
            # Use the "ask for help" mechanism if available
            if hasattr(self, '_help_requests'):
                self._help_requests.append({
                    'type': 'mfa_code',
                    'message': 'MFA/2FA code required. Please provide the verification code.',
                    'timestamp': time.time(),
                })
                print("[*] Help request sent for MFA code. Waiting...")
                # Wait up to 60 seconds for user to provide code
                for _ in range(30):
                    time.sleep(2)
                    if hasattr(self, '_help_response') and self._help_response:
                        totp_code = self._help_response.strip()
                        self._help_response = None
                        break
            if not totp_code:
                print("[!] No TOTP secret configured and no user code received")
                return False

        # Find the code input field and fill it
        code_selectors = [
            'input[name*="otp"]', 'input[name*="totp"]',
            'input[name*="code"]', 'input[name*="token"]',
            'input[name*="2fa"]', 'input[name*="mfa"]',
            'input[name*="verification"]',
            'input[autocomplete="one-time-code"]',
            'input[type="text"][maxlength="6"]',
            'input[type="number"][maxlength="6"]',
            'input[type="tel"]',
        ]

        code_filled = False
        for sel in code_selectors:
            try:
                if page.locator(sel).count() > 0 and page.locator(sel).first.is_visible():
                    page.locator(sel).first.fill(totp_code)
                    code_filled = True
                    print(f"[MFA] Filled code via {sel}")
                    break
            except Exception:
                continue

        if not code_filled:
            print("[!] Could not find MFA code input field")
            return False

        # Submit the MFA form
        time.sleep(1)
        submit_selectors = [
            'button[type="submit"]', 'input[type="submit"]',
            'button:has-text("Verify")', 'button:has-text("Submit")',
            'button:has-text("Confirm")', 'button:has-text("Continue")',
        ]
        for sel in submit_selectors:
            try:
                if page.locator(sel).count() > 0 and page.locator(sel).first.is_visible():
                    page.locator(sel).first.click()
                    break
            except Exception:
                continue

        time.sleep(3)
        try:
            page.wait_for_load_state("networkidle", timeout=10000)
        except Exception:
            pass

        print("[+] MFA code submitted")
        return True

    def _check_and_relogin(self, page):
        """Check if we've been logged out and re-authenticate if needed."""
        if not self.login_url or not self.username:
            return

        # Fail-fast mode: never try to re-login automatically (prevents loops).
        if getattr(self, '_login_permanently_failed', False) or getattr(self, '_login_attempted_once', False):
            return

        # If we've used all login attempts, don't keep trying
        if self._login_attempts >= self._max_login_attempts:
            return

        # First check if we still have a session cookie - if yes, we're likely still logged in
        try:
            cookies = page.context.cookies()
            session_cookie_names = ['sessionid', 'session', 'sid', 'phpsessid', 'jsessionid', 'token', 'auth']
            for cookie in cookies:
                cookie_name = cookie.get('name', '').lower()
                if any(name in cookie_name for name in session_cookie_names):
                    if cookie.get('value'):  # Has a session cookie, probably still logged in
                        return
        except:
            pass

        # Check if page has logout button/link - if so, we're logged in
        try:
            logout_exists = page.locator('a:has-text("logout"), a:has-text("sign out"), a:has-text("log out"), button:has-text("logout")').count() > 0
            if logout_exists:
                return  # Still logged in
        except:
            pass

        # Only try to re-login if we're clearly redirected to the login page
        # Must match the login URL exactly or contain common login path indicators
        current_url = page.url.lower()
        login_url_lower = self.login_url.lower() if self.login_url else ''

        is_login_page = False
        if login_url_lower:
            # Check exact match or close match
            if current_url == login_url_lower or current_url == login_url_lower + '/':
                is_login_page = True
            # Check if URL path contains login indicators
            elif '/login' in current_url or '/signin' in current_url or '/auth' in current_url:
                # Also check if the page has a login form
                try:
                    has_login_form = page.locator('input[type="password"]').count() > 0
                    if has_login_form:
                        is_login_page = True
                except:
                    pass

        if is_login_page:
            print(f"[!] Detected logout - attempting re-authentication...")
            self._logged_in = False
            return

    def _extract_cookies(self, context):
        """Extract cookies from browser context."""
        try:
            for cookie in context.cookies():
                self.cookies.append({
                    "name": cookie.get("name", ""),
                    "value": cookie.get("value", ""),
                    "domain": cookie.get("domain", ""),
                    "path": cookie.get("path", "/"),
                    "secure": cookie.get("secure", False),
                    "httponly": cookie.get("httpOnly", False),
                    "expires": cookie.get("expires", -1),
                    "sameSite": cookie.get("sameSite", "None"),
                })
        except:
            pass

    def _extract_html_comments(self, page):
        """Extract useful information from HTML comments including:
        - Credential hints (username:password, test accounts)
        - TODO/FIXME comments with sensitive info
        - Debug information
        - Hidden endpoints
        """
        hints = {
            'credentials': [],
            'todos': [],
            'debug_info': [],
            'endpoints': []
        }
        try:
            comments = page.evaluate(r"""
                () => {
                    const comments = [];
                    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
                    while (walker.nextNode()) {
                        comments.push(walker.currentNode.textContent);
                    }
                    return comments;
                }
            """)

            for comment in comments:
                comment_lower = comment.lower()

                # Look for credential patterns
                # Pattern: username:password, user/pass, test:test, admin:admin
                cred_patterns = [
                    r'(?:user(?:name)?|login|account)\s*[:\s=]+\s*([^\s,;]+)\s*[,;/\s]+\s*(?:pass(?:word)?|pwd)\s*[:\s=]+\s*([^\s,;<>]+)',
                    r'([a-zA-Z0-9_]+)\s*:\s*([a-zA-Z0-9_]+)(?:\s|$|[,;])',  # simple user:pass format
                    r'(?:test|demo|admin|guest)\s*(?:account|user|login)?\s*[:\s=]+\s*\(?([^\s,;)]+)\s*[/,;:\s]+\s*([^\s,;)<>]+)',
                    r'credentials?\s*[:\s=]+\s*([^\s,;]+)\s*[/,;:\s]+\s*([^\s,;<>]+)',
                ]

                for pattern in cred_patterns:
                    matches = re.findall(pattern, comment, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple) and len(match) >= 2:
                            username, password = match[0], match[1]
                            # Filter out common false positives
                            if len(username) >= 2 and len(password) >= 2:
                                if not any(fp in username.lower() for fp in ['http', 'www', 'type', 'input', 'field']):
                                    hints['credentials'].append({
                                        'username': username,
                                        'password': password,
                                        'source': 'html_comment'
                                    })
                                    print(f"[+] Found credential hint in HTML comment: {username}:{password}")

                # Look for TODO/FIXME with sensitive information
                if any(marker in comment_lower for marker in ['todo', 'fixme', 'hack', 'xxx', 'bug', 'delete']):
                    hints['todos'].append(comment.strip())
                    # Check if TODO mentions accounts/credentials
                    if any(word in comment_lower for word in ['account', 'password', 'credential', 'user', 'test', 'admin']):
                        print(f"[+] Found sensitive TODO comment: {comment.strip()[:100]}")

                # Look for debug information
                if any(marker in comment_lower for marker in ['debug', 'api_key', 'secret', 'token', 'key=']):
                    hints['debug_info'].append(comment.strip())
                    print(f"[+] Found debug info in comment: {comment.strip()[:100]}")

                # Look for endpoint hints
                endpoint_match = re.findall(r'(/[a-zA-Z][a-zA-Z0-9_\-/]*)', comment)
                for endpoint in endpoint_match:
                    if len(endpoint) > 2 and not endpoint.startswith('//'):
                        hints['endpoints'].append(endpoint)

        except Exception as e:
            print(f"[!] Error extracting HTML comments: {e}")

        # Store hints for later use
        if not hasattr(self, '_html_hints'):
            self._html_hints = hints
        else:
            self._html_hints['credentials'].extend(hints['credentials'])
            self._html_hints['todos'].extend(hints['todos'])
            self._html_hints['debug_info'].extend(hints['debug_info'])
            self._html_hints['endpoints'].extend(hints['endpoints'])

        return hints

    def _extract_data_attributes(self, page, base_url):
        """Extract data attributes that may contain IDs, URLs, or other input sources.
        Looks for patterns like data-id, data-order-id, data-user-id, data-href, etc.
        """
        data_attrs = []
        try:
            attrs = page.evaluate(r"""
                () => {
                    const results = [];
                    // Get all elements with data-* attributes
                    document.querySelectorAll('*').forEach(el => {
                        for (const attr of el.attributes) {
                            if (attr.name.startsWith('data-')) {
                                const name = attr.name;
                                const value = attr.value;
                                // Focus on ID-like and URL-like attributes
                                if (name.includes('id') || name.includes('url') ||
                                    name.includes('href') || name.includes('action') ||
                                    name.includes('target') || name.includes('order') ||
                                    name.includes('user') || name.includes('item') ||
                                    name.includes('product') || name.includes('page')) {
                                    results.push({
                                        attr: name,
                                        value: value,
                                        tag: el.tagName.toLowerCase(),
                                        text: (el.textContent || '').substring(0, 50).trim()
                                    });
                                }
                            }
                        }
                    });
                    // Deduplicate
                    const seen = new Set();
                    return results.filter(r => {
                        const key = r.attr + ':' + r.value;
                        if (seen.has(key)) return false;
                        seen.add(key);
                        return true;
                    });
                }
            """)

            for attr in attrs:
                attr_name = attr.get('attr', '')
                attr_value = attr.get('value', '')

                # Check if value looks like an ID (numeric or alphanumeric)
                if attr_name.endswith('-id') or 'id' in attr_name.lower():
                    data_attrs.append({
                        'type': 'path_param',
                        'name': attr_name.replace('data-', '').replace('-', '_'),
                        'value': attr_value,
                        'element': attr.get('tag'),
                        'context': attr.get('text')
                    })
                    print(f"[+] Found data attribute: {attr_name}={attr_value}")

                # Check if value looks like a URL
                if attr_value.startswith('/') or attr_value.startswith('http'):
                    normalized = self._normalize_url(base_url, attr_value)
                    if normalized:
                        data_attrs.append({
                            'type': 'url',
                            'name': attr_name,
                            'value': normalized,
                            'element': attr.get('tag')
                        })

        except Exception as e:
            print(f"[!] Error extracting data attributes: {e}")

        # Store for later use
        if not hasattr(self, '_data_attributes'):
            self._data_attributes = []
        self._data_attributes.extend(data_attrs)

        return data_attrs

    def _extract_websocket_endpoints(self, page):
        """Extract WebSocket connection URLs from JavaScript code."""
        ws_endpoints = []
        try:
            endpoints = page.evaluate(r"""
                () => {
                    const wsUrls = [];

                    // Search all scripts for WebSocket patterns
                    const scripts = Array.from(document.querySelectorAll('script'));
                    const inlineContent = scripts.map(s => s.textContent || '').join('\n');

                    // Pattern to find WebSocket URLs
                    const wsPatterns = [
                        /new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]/g,
                        /new\s+WebSocket\s*\(\s*`([^`]+)`/g,
                        /wss?:\/\/[^\s'"`,)}\]]+/g,
                        /['"`](wss?:\/\/[^'"`]+)['"`]/g
                    ];

                    for (const pattern of wsPatterns) {
                        const matches = inlineContent.matchAll(pattern);
                        for (const match of matches) {
                            const url = match[1] || match[0];
                            if (url && (url.startsWith('ws://') || url.startsWith('wss://'))) {
                                wsUrls.push(url.replace(/['"`]/g, ''));
                            }
                        }
                    }

                    // Check for socket.io patterns
                    if (inlineContent.includes('socket.io') || inlineContent.includes('io.connect') || inlineContent.includes('io(')) {
                        wsUrls.push('socket.io detected');
                    }

                    return [...new Set(wsUrls)];
                }
            """)

            for url in endpoints:
                ws_endpoints.append({
                    'url': url,
                    'type': 'websocket'
                })
                print(f"[+] Found WebSocket endpoint: {url}")

        except Exception as e:
            print(f"[!] Error extracting WebSocket endpoints: {e}")

        if not hasattr(self, '_websocket_endpoints'):
            self._websocket_endpoints = []
        self._websocket_endpoints.extend(ws_endpoints)

        return ws_endpoints

    def _detect_grpc_indicators(self, page):
        """Detect gRPC/protobuf indicators in JavaScript and network traffic."""
        grpc_indicators = []
        try:
            indicators = page.evaluate(r"""
                () => {
                    const results = [];
                    const scripts = Array.from(document.querySelectorAll('script'));
                    const inlineContent = scripts.map(s => s.textContent || '').join('\n');

                    // gRPC-related patterns in JavaScript
                    const grpcPatterns = [
                        { pattern: /grpc[_\-]?web/gi, type: 'grpc-web' },
                        { pattern: /@grpc\/grpc-js/g, type: 'grpc-js' },
                        { pattern: /\.proto\b/g, type: 'proto-file' },
                        { pattern: /protobuf/gi, type: 'protobuf' },
                        { pattern: /google-protobuf/g, type: 'google-protobuf' },
                        { pattern: /application\/grpc/g, type: 'grpc-content-type' },
                    ];

                    for (const { pattern, type } of grpcPatterns) {
                        const matches = inlineContent.matchAll(pattern);
                        for (const match of matches) {
                            results.push({ type, match: match[0], index: match.index });
                        }
                    }

                    // Check script src attributes for proto/grpc references
                    for (const script of scripts) {
                        const src = script.src || '';
                        if (/grpc|proto/i.test(src)) {
                            results.push({ type: 'grpc-script', match: src });
                        }
                    }

                    return results;
                }
            """)

            if indicators:
                for ind in indicators:
                    grpc_indicators.append({
                        'type': ind.get('type', 'unknown'),
                        'match': ind.get('match', ''),
                        'host': page.url,
                    })
                    print(f"[+] Found gRPC indicator: {ind.get('type')} - {ind.get('match', '')[:80]}")

        except Exception as e:
            print(f"[!] Error detecting gRPC indicators: {e}")

        if not hasattr(self, '_grpc_indicators'):
            self._grpc_indicators = []
        self._grpc_indicators.extend(grpc_indicators)

        return grpc_indicators

    def _extract_browser_storage(self, page):
        """Extract localStorage and sessionStorage keys and values."""
        storage_data = {'localStorage': [], 'sessionStorage': []}
        try:
            data = page.evaluate(r"""
                () => {
                    const result = {localStorage: [], sessionStorage: []};

                    // Extract localStorage
                    try {
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            const value = localStorage.getItem(key);
                            result.localStorage.push({
                                key: key,
                                value: value ? value.substring(0, 500) : '',  // Truncate long values
                                length: value ? value.length : 0
                            });
                        }
                    } catch (e) {}

                    // Extract sessionStorage
                    try {
                        for (let i = 0; i < sessionStorage.length; i++) {
                            const key = sessionStorage.key(i);
                            const value = sessionStorage.getItem(key);
                            result.sessionStorage.push({
                                key: key,
                                value: value ? value.substring(0, 500) : '',
                                length: value ? value.length : 0
                            });
                        }
                    } catch (e) {}

                    return result;
                }
            """)

            storage_data = data

            for item in data.get('localStorage', []):
                print(f"[+] Found localStorage key: {item['key']}")
            for item in data.get('sessionStorage', []):
                print(f"[+] Found sessionStorage key: {item['key']}")

        except Exception as e:
            print(f"[!] Error extracting browser storage: {e}")

        if not hasattr(self, '_browser_storage'):
            self._browser_storage = {'localStorage': [], 'sessionStorage': []}
        self._browser_storage['localStorage'].extend(storage_data.get('localStorage', []))
        self._browser_storage['sessionStorage'].extend(storage_data.get('sessionStorage', []))

        return storage_data

    def _extract_event_listeners(self, page):
        """Extract JavaScript event listeners that may contain navigation or form logic."""
        event_data = []
        try:
            listeners = page.evaluate(r"""
                () => {
                    const results = [];

                    // Get elements with inline event handlers (not just onclick)
                    const eventAttrs = ['onclick', 'onsubmit', 'onchange', 'oninput', 'onkeyup',
                                       'onkeydown', 'onfocus', 'onblur', 'onload', 'onerror',
                                       'onmouseover', 'onmouseout', 'ondblclick'];

                    eventAttrs.forEach(attr => {
                        document.querySelectorAll(`[${attr}]`).forEach(el => {
                            const handler = el.getAttribute(attr) || '';
                            if (handler) {
                                results.push({
                                    element: el.tagName.toLowerCase(),
                                    id: el.id || '',
                                    name: el.getAttribute('name') || '',
                                    event: attr,
                                    handler: handler.substring(0, 500),
                                    text: (el.textContent || '').trim().substring(0, 100)
                                });
                            }
                        });
                    });

                    // Look for forms with JavaScript validation
                    document.querySelectorAll('form').forEach(form => {
                        const action = form.getAttribute('action') || '';
                        const onsubmit = form.getAttribute('onsubmit') || '';
                        if (onsubmit) {
                            results.push({
                                element: 'form',
                                id: form.id || '',
                                name: form.getAttribute('name') || '',
                                event: 'onsubmit',
                                handler: onsubmit.substring(0, 500),
                                action: action
                            });
                        }
                    });

                    // Look for buttons/links that might use JS for navigation
                    document.querySelectorAll('button, [role="button"], .btn, a[href="javascript:"], a[href="#"]').forEach(el => {
                        eventAttrs.forEach(attr => {
                            const handler = el.getAttribute(attr);
                            if (handler) {
                                results.push({
                                    element: el.tagName.toLowerCase(),
                                    id: el.id || '',
                                    classes: el.className || '',
                                    event: attr,
                                    handler: handler.substring(0, 500),
                                    text: (el.textContent || '').trim().substring(0, 100)
                                });
                            }
                        });
                    });

                    return results;
                }
            """)

            event_data = listeners

            # Extract URLs from event handlers
            for listener in listeners:
                handler = listener.get('handler', '')
                # Look for URLs in handlers
                url_patterns = [
                    r'location\.href\s*=\s*[\'"]([^\'"]+)[\'"]',
                    r'location\s*=\s*[\'"]([^\'"]+)[\'"]',
                    r'window\.location\s*=\s*[\'"]([^\'"]+)[\'"]',
                    r'fetch\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r'ajax\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r'\.get\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r'\.post\s*\(\s*[\'"]([^\'"]+)[\'"]'
                ]
                for pattern in url_patterns:
                    matches = re.findall(pattern, handler)
                    if matches:
                        print(f"[+] Found URL in {listener.get('event')} handler: {matches}")

        except Exception as e:
            print(f"[!] Error extracting event listeners: {e}")

        if not hasattr(self, '_event_listeners'):
            self._event_listeners = []
        self._event_listeners.extend(event_data)

        return event_data

    def _extract_urls_from_js(self, page, base_url):
        """Extract URLs from JavaScript files and inline scripts.
        Also detects dynamic URL patterns with variables like '/order/' + id + '/receipt'.
        """
        urls = set()
        dynamic_patterns = []  # Store patterns with path parameters
        try:
            # Get all script sources
            js_content = page.evaluate(r"""
                () => {
                    const scripts = [];
                    // Get inline script content
                    document.querySelectorAll('script:not([src])').forEach(s => {
                        scripts.push(s.textContent || '');
                    });
                    return scripts.join('\n');
                }
            """)

            # Patterns to find URLs in JavaScript
            url_patterns = [
                # API endpoints
                r'["\'](?:\/api\/[^"\']+)["\']',
                r'["\'](?:\/v\d+\/[^"\']+)["\']',
                # Relative paths
                r'["\'](?:\/[a-zA-Z][a-zA-Z0-9_\-\/]*)["\']',
                # fetch/axios calls
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
                r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
                # Router paths (React, Vue, Angular)
                r'path\s*:\s*["\']([^"\']+)["\']',
                r'route\s*:\s*["\']([^"\']+)["\']',
                r'to\s*:\s*["\']([^"\']+)["\']',
                r'href\s*:\s*["\']([^"\']+)["\']',
                r'url\s*:\s*["\']([^"\']+)["\']',
                r'endpoint\s*:\s*["\']([^"\']+)["\']',
                # Template literals
                r'`([^`]*\$\{[^}]+\}[^`]*)`',
                # Location assignments
                r'location\.href\s*=\s*["\']([^"\']+)["\']',
                r'location\s*=\s*["\']([^"\']+)["\']',
                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                # Navigation functions
                r'navigate\s*\(\s*["\']([^"\']+)["\']',
                r'push\s*\(\s*["\']([^"\']+)["\']',
                r'replace\s*\(\s*["\']([^"\']+)["\']',
                r'go\s*\(\s*["\']([^"\']+)["\']',
            ]

            # Patterns for DYNAMIC URL construction (string concatenation with variables)
            # Matches patterns like: '/order/' + orderId + '/receipt'
            # or: url: '/api/users/' + userId
            dynamic_url_patterns = [
                # String concatenation: '/path/' + var + '/more'
                r"['\"](/[a-zA-Z][a-zA-Z0-9_\-/]*)['\"][\s]*\+[\s]*([a-zA-Z_][a-zA-Z0-9_]*)[\s]*\+[\s]*['\"]([^'\"]*)['\"]",
                # String concatenation: '/path/' + var (no trailing part)
                r"['\"](/[a-zA-Z][a-zA-Z0-9_\-/]*)['\"][\s]*\+[\s]*([a-zA-Z_][a-zA-Z0-9_]*)",
                # jQuery/AJAX style: url: '/api/' + id
                r"url\s*:\s*['\"](/[^'\"]+)['\"][\s]*\+[\s]*([a-zA-Z_][a-zA-Z0-9_]*)",
                # Template literal with variable: `/order/${id}/receipt`
                r"`(/[^`]*\$\{([^}]+)\}[^`]*)`",
            ]

            for pattern in url_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    if match and isinstance(match, str):
                        # Clean up the match
                        url = match.strip()
                        if url.startswith('/') and not url.startswith('//'):
                            normalized = self._normalize_url(base_url, url)
                            if normalized:
                                urls.add(normalized)
                        elif url.startswith('http'):
                            if self._is_allowed_url(url, base_url):
                                urls.add(url)

            # Extract dynamic URL patterns with path parameters
            for pattern in dynamic_url_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        # Reconstruct the URL pattern with placeholder
                        if len(match) >= 2:
                            prefix = match[0]
                            var_name = match[1]
                            suffix = match[2] if len(match) > 2 else ''

                            # Create a pattern representation: /order/{order_id}/receipt
                            param_name = var_name.replace('Id', '_id').replace('ID', '_id')
                            if not param_name.endswith('_id') and param_name.lower() in ['id', 'userid', 'orderid', 'itemid', 'productid']:
                                param_name = param_name.lower().replace('id', '_id') if 'id' in param_name.lower() else f"{param_name}_id"

                            url_pattern = f"{prefix}{{{param_name}}}{suffix}"
                            dynamic_patterns.append({
                                'pattern': url_pattern,
                                'variable': var_name,
                                'prefix': prefix,
                                'suffix': suffix
                            })
                            print(f"[+] Found dynamic URL pattern: {url_pattern} (variable: {var_name})")

                            # Also create a test URL with a sample ID
                            test_url = f"{prefix}1{suffix}"
                            normalized = self._normalize_url(base_url, test_url)
                            if normalized:
                                urls.add(normalized)

            # Also fetch and parse external JS files
            js_files = page.evaluate("""
                () => Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.getAttribute('src'))
                    .filter(src => src && !src.includes('google') && !src.includes('analytics') && !src.includes('cdn'))
            """)

            import requests
            for js_src in js_files[:10]:  # Limit to first 10 JS files
                try:
                    js_url = self._normalize_url(base_url, js_src)
                    if not js_url:
                        continue
                    resp = requests.get(js_url, timeout=5, verify=False)
                    if resp.status_code == 200:
                        for pattern in url_patterns:
                            matches = re.findall(pattern, resp.text, re.IGNORECASE)
                            for match in matches:
                                if match and isinstance(match, str):
                                    url = match.strip()
                                    if url.startswith('/') and not url.startswith('//'):
                                        normalized = self._normalize_url(base_url, url)
                                        if normalized:
                                            urls.add(normalized)

                        # Also check external JS for dynamic patterns
                        for pattern in dynamic_url_patterns:
                            matches = re.findall(pattern, resp.text, re.IGNORECASE)
                            for match in matches:
                                if isinstance(match, tuple) and len(match) >= 2:
                                    prefix = match[0]
                                    suffix = match[2] if len(match) > 2 else ''
                                    test_url = f"{prefix}1{suffix}"
                                    normalized = self._normalize_url(base_url, test_url)
                                    if normalized:
                                        urls.add(normalized)
                except:
                    continue

            if urls:
                print(f"[+] Extracted {len(urls)} URLs from JavaScript")
                for url in urls:
                    self._js_urls.add(url)

            # Store dynamic patterns for later use
            if dynamic_patterns:
                if not hasattr(self, '_dynamic_url_patterns'):
                    self._dynamic_url_patterns = []
                self._dynamic_url_patterns.extend(dynamic_patterns)

        except Exception as e:
            print(f"[!] Error extracting JS URLs: {e}")

        return urls

    def _setup_request_interception(self, page):
        """Setup interception to capture XHR/Fetch requests and responses."""
        captured_urls = []
        response_urls = []

        def handle_request(request):
            url = request.url
            if self._is_allowed_url(url):
                resource_type = request.resource_type
                if resource_type in ['xhr', 'fetch', 'document']:
                    if not self._use_cdp_proxy and not self._mitm_port:
                        req_id = f"{int(time.time() * 1000)}_{len(self._proxy_logs)}"
                        headers = dict(request.headers or {})
                        try:
                            if not any(k.lower() == 'cookie' for k in headers.keys()):
                                cookies = page.context.cookies(url)
                                if cookies:
                                    cookie_header = '; '.join(
                                        f"{c.get('name')}={c.get('value')}" for c in cookies if c.get('name')
                                    )
                                    if cookie_header:
                                        headers['cookie'] = cookie_header
                        except Exception:
                            pass
                        body = request.post_data or ''
                        if not body:
                            try:
                                body_buffer = request.post_data_buffer
                                if body_buffer:
                                    body = body_buffer.decode('utf-8', errors='replace')
                            except Exception:
                                pass
                        try:
                            parsed = urlparse(url)
                            path = parsed.path or '/'
                            if parsed.query:
                                path += f"?{parsed.query}"
                            host = parsed.netloc
                        except Exception:
                            path = url or '/'
                            host = ''
                        header_lines = [f"{k}: {v}" for k, v in headers.items()]
                        if host and not any(k.lower() == 'host' for k in headers.keys()):
                            header_lines.insert(0, f"Host: {host}")
                        raw_request = f"{request.method} {path} HTTP/1.1\n" + "\n".join(header_lines)
                        if body:
                            raw_request = f"{raw_request}\n\n{body}"
                        entry = {
                            'id': req_id,
                            'url': url,
                            'method': request.method,
                            'type': resource_type,
                            'request_headers': headers,
                            'request_body': body,
                            'raw_request': raw_request,
                            'status': None,
                            'response_headers': {},
                            'response_body': '',
                            'timestamp': time.time()
                        }
                        self._proxy_logs.append(entry)
                        self._proxy_log_map[id(request)] = entry
                        # Also key by URL+method for response matching (id() can differ)
                        self._proxy_log_map[f"{request.method}|{url}"] = entry
                    captured_urls.append({
                        'url': url,
                        'method': request.method,
                        'type': resource_type
                    })

        def handle_response(response):
            """Capture response bodies to extract URLs from API responses."""
            try:
                url = response.url
                if not self._is_allowed_url(url):
                    return
                req = response.request
                entry = self._proxy_log_map.get(id(req)) or self._proxy_log_map.get(f"{req.method}|{url}")
                if entry is not None:
                    entry['status'] = response.status
                    entry['response_headers'] = response.headers
                    content_type = response.headers.get('content-type', '')
                    if any(t in content_type for t in ['text', 'json', 'javascript', 'xml', 'html']):
                        try:
                            body = response.text()
                            entry['response_body'] = (body or '')[:50000]
                        except Exception:
                            pass

                content_type = response.headers.get('content-type', '')
                if 'json' in content_type or 'javascript' in content_type:
                    try:
                        body = response.text()
                        # Extract URLs from JSON/JS responses
                        url_patterns = [
                            r'"(/[a-zA-Z][a-zA-Z0-9_\-/]*)"',
                            r"'(/[a-zA-Z][a-zA-Z0-9_\-/]*)'",
                            r'"url"\s*:\s*"([^"]+)"',
                            r'"href"\s*:\s*"([^"]+)"',
                            r'"path"\s*:\s*"([^"]+)"',
                            r'"endpoint"\s*:\s*"([^"]+)"',
                            r'"redirect"\s*:\s*"([^"]+)"',
                        ]
                        for pattern in url_patterns:
                            matches = re.findall(pattern, body)
                            for match in matches:
                                if match and match.startswith('/'):
                                    response_urls.append(match)
                    except:
                        pass
            except:
                pass

        page.on('request', handle_request)
        page.on('response', handle_response)
        return captured_urls, response_urls

    def _start_mitmproxy(self):
        """Start mitmdump as a subprocess for full HTTP/HTTPS traffic capture.

        Uses an external mitmdump process with an addon script that writes JSONL
        to a temp file. A reader thread tails that file and populates _proxy_logs.
        This avoids mitmproxy's logging corruption of Flask's root logger.
        Works on headless servers (no DISPLAY required); prefers venv mitmdump.
        """
        try:
            port = _find_free_port(8081, 8099)

            # Create temp JSONL log file
            log_fd, log_path = tempfile.mkstemp(prefix='mitm_log_', suffix='.jsonl')
            os.close(log_fd)
            self._mitm_log_file = log_path

            # Write addon script with correct log file path
            script_fd, script_path = tempfile.mkstemp(prefix='mitm_addon_', suffix='.py')
            script_content = _MITM_ADDON_SCRIPT.replace('__LOGFILE__', log_path.replace('\\', '\\\\'))
            os.write(script_fd, script_content.encode('utf-8'))
            os.close(script_fd)
            self._mitm_script_file = script_path

            # Find mitmdump: prefer venv so it works in isolated/headless environments
            import shutil
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            venv_mitm = os.path.join(project_root, '.venv', 'bin', 'mitmdump')
            if os.path.isfile(venv_mitm):
                mitmdump_bin = venv_mitm
            else:
                venv_mitm = os.path.join(project_root, 'venv', 'bin', 'mitmdump')
                mitmdump_bin = venv_mitm if os.path.isfile(venv_mitm) else None
            if not mitmdump_bin:
                mitmdump_bin = shutil.which('mitmdump')
            if not mitmdump_bin:
                print("[!] mitmdump binary not found — falling back to CDP proxy")
                return None

            # Launch mitmdump subprocess
            cmd = [
                mitmdump_bin,
                '-s', script_path,
                '--listen-host', '0.0.0.0',
                '--listen-port', str(port),
                '--ssl-insecure',
                '--set', 'flow_detail=0',     # minimal console output
                '--quiet',
            ]
            print(f"[+] Starting mitmdump: {' '.join(cmd)}")
            self._mitm_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None,
            )

            # Start log reader thread
            self._mitm_stop_event = threading.Event()
            self._mitm_reader_thread = threading.Thread(
                target=_mitm_log_reader,
                args=(log_path, self._proxy_logs, self._mitm_stop_event, self._is_allowed_url, self),
                daemon=True,
                name="mitm-log-reader"
            )
            self._mitm_reader_thread.start()

            # Wait for proxy to accept connections
            self._mitm_port = port
            for _ in range(40):
                time.sleep(0.25)
                # Check if process died
                if self._mitm_process.poll() is not None:
                    stderr = self._mitm_process.stderr.read().decode('utf-8', errors='replace') if self._mitm_process.stderr else ''
                    print(f"[!] mitmdump exited early (code {self._mitm_process.returncode}): {stderr[:500]}")
                    self._mitm_port = None
                    return None
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=1):
                        print(f"[+] mitmproxy (subprocess) ready on port {port}")
                        return port
                except (ConnectionRefusedError, OSError):
                    continue
            print(f"[!] mitmproxy may not be ready on port {port} (timeout)")
            return port
        except Exception as e:
            print(f"[!] Failed to start mitmproxy: {e} — falling back to CDP proxy")
            self._mitm_port = None
            return None

    def _stop_mitmproxy(self):
        """Stop the mitmdump subprocess and reader thread."""
        # Signal log reader to stop
        if self._mitm_stop_event:
            self._mitm_stop_event.set()
        # Kill the mitmdump subprocess
        if self._mitm_process:
            try:
                self._mitm_process.terminate()
                try:
                    self._mitm_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._mitm_process.kill()
                    self._mitm_process.wait(timeout=3)
            except Exception as e:
                print(f"[!] Error stopping mitmdump: {e}")
                # Avoid pkill/lsof: just kill the process we spawned (no process-group kill on Windows/headless)
                try:
                    if self._mitm_process.poll() is None:
                        self._mitm_process.kill()
                        self._mitm_process.wait(timeout=2)
                except Exception:
                    pass
                if sys.platform != 'win32' and self._mitm_process.poll() is None:
                    try:
                        import signal
                        pgid = os.getpgid(self._mitm_process.pid)
                        os.killpg(pgid, signal.SIGKILL)
                    except Exception:
                        pass
        # Wait for reader thread
        if self._mitm_reader_thread and self._mitm_reader_thread.is_alive():
            self._mitm_reader_thread.join(timeout=3)
        # Cleanup temp files
        for f in [self._mitm_log_file, self._mitm_script_file]:
            if f:
                try:
                    os.unlink(f)
                except Exception:
                    pass
        self._mitm_port = None
        self._mitm_process = None
        self._mitm_reader_thread = None
        self._mitm_stop_event = None
        self._mitm_log_file = None
        self._mitm_script_file = None
        print("[*] mitmproxy stopped")

    def _setup_cdp_capture(self, context, page):
        """Capture full browser requests via CDP network events."""
        try:
            session = context.new_cdp_session(page)
            session.send("Network.enable")
        except Exception:
            return None

        self._use_cdp_proxy = True
        allowed_types = None

        def build_raw_request(method, url, headers, body):
            try:
                parsed = urlparse(url)
                path = parsed.path or '/'
                if parsed.query:
                    path += f"?{parsed.query}"
                host = parsed.netloc
            except Exception:
                path = url or '/'
                host = ''
            header_lines = [f"{k}: {v}" for k, v in (headers or {}).items()]
            if host and not any(k.lower() == 'host' for k in (headers or {}).keys()):
                header_lines.insert(0, f"Host: {host}")
            raw = f"{method} {path} HTTP/1.1\n" + "\n".join(header_lines)
            if body:
                raw = f"{raw}\n\n{body}"
            return raw

        def ensure_cookie_header(headers, url):
            if any(k.lower() == 'cookie' for k in (headers or {}).keys()):
                return headers
            try:
                cookies = context.cookies(url)
                if cookies:
                    cookie_header = '; '.join(
                        f"{c.get('name')}={c.get('value')}" for c in cookies if c.get('name')
                    )
                    if cookie_header:
                        enriched = dict(headers or {})
                        enriched['cookie'] = cookie_header
                        return enriched
            except Exception:
                pass
            return headers

        def merge_headers(base_headers, extra_headers):
            merged = dict(base_headers or {})
            for key, value in (extra_headers or {}).items():
                merged[key] = value
            return merged

        def on_request_will_be_sent(params):
            request_id = params.get("requestId")
            request = params.get("request", {})
            url = request.get("url", "")
            if not url or not self._is_allowed_url(url):
                return
            resource_type = (params.get("type") or "").lower()
            if allowed_types and resource_type and resource_type not in allowed_types:
                return
            method = request.get("method", "GET")
            headers = ensure_cookie_header(request.get("headers", {}) or {}, url)
            body = request.get("postData", "") or ""
            raw_request = build_raw_request(method, url, headers, body)
            entry = {
                'id': f"{int(time.time() * 1000)}_{len(self._proxy_logs)}",
                'url': url,
                'method': method,
                'type': resource_type or 'document',
                'request_headers': headers,
                'request_body': body,
                'raw_request': raw_request,
                'status': None,
                'response_headers': {},
                'response_body': '',
                'timestamp': time.time()
            }
            if request_id:
                self._proxy_log_map_cdp[request_id] = entry
            self._proxy_logs.append(entry)

        def on_request_will_be_sent_extra_info(params):
            request_id = params.get("requestId")
            entry = self._proxy_log_map_cdp.get(request_id)
            if entry is None:
                return
            extra_headers = params.get("headers", {}) or {}
            associated = params.get("associatedCookies") or []
            if associated and not any(k.lower() == 'cookie' for k in extra_headers.keys()):
                try:
                    cookie_parts = []
                    for item in associated:
                        cookie = item.get("cookie") or {}
                        name = cookie.get("name")
                        value = cookie.get("value")
                        if name:
                            cookie_parts.append(f"{name}={value}")
                    if cookie_parts:
                        extra_headers["cookie"] = "; ".join(cookie_parts)
                except Exception:
                    pass
            merged = merge_headers(entry.get('request_headers'), extra_headers)
            merged = ensure_cookie_header(merged, entry.get('url') or '')
            entry['request_headers'] = merged
            entry['raw_request'] = build_raw_request(
                entry.get('method') or 'GET',
                entry.get('url') or '',
                merged,
                entry.get('request_body') or ''
            )

        def on_response_received(params):
            request_id = params.get("requestId")
            entry = self._proxy_log_map_cdp.get(request_id)
            if entry is None:
                return
            response = params.get("response", {}) or {}
            entry['status'] = response.get('status')
            entry['response_headers'] = response.get('headers', {}) or {}

        def on_response_received_extra_info(params):
            request_id = params.get("requestId")
            entry = self._proxy_log_map_cdp.get(request_id)
            if entry is None:
                return
            extra_headers = params.get("headers", {}) or {}
            merged = merge_headers(entry.get('response_headers'), extra_headers)
            entry['response_headers'] = merged

        def on_loading_finished(params):
            request_id = params.get("requestId")
            entry = self._proxy_log_map_cdp.get(request_id)
            if entry is None:
                return
            try:
                if not entry.get('request_body'):
                    try:
                        post_data = session.send("Network.getRequestPostData", {"requestId": request_id})
                        if post_data and post_data.get("postData"):
                            entry['request_body'] = post_data.get("postData") or ''
                            entry['raw_request'] = build_raw_request(
                                entry.get('method') or 'GET',
                                entry.get('url') or '',
                                entry.get('request_headers') or {},
                                entry.get('request_body') or ''
                            )
                    except Exception:
                        pass
                body_res = session.send("Network.getResponseBody", {"requestId": request_id})
                body_text = body_res.get("body", "") if body_res else ""
                if body_res and body_res.get("base64Encoded"):
                    decoded = base64.b64decode(body_text)
                    body_text = decoded.decode('utf-8', errors='replace')
                entry['response_body'] = (body_text or '')[:12000]
            except Exception:
                pass

        def on_loading_failed(params):
            request_id = params.get("requestId")
            entry = self._proxy_log_map_cdp.get(request_id)
            if entry is None:
                return
            try:
                if not entry.get('request_body'):
                    post_data = session.send("Network.getRequestPostData", {"requestId": request_id})
                    if post_data and post_data.get("postData"):
                        entry['request_body'] = post_data.get("postData") or ''
                        entry['raw_request'] = build_raw_request(
                            entry.get('method') or 'GET',
                            entry.get('url') or '',
                            entry.get('request_headers') or {},
                            entry.get('request_body') or ''
                        )
            except Exception:
                pass

        session.on("Network.requestWillBeSent", on_request_will_be_sent)
        session.on("Network.requestWillBeSentExtraInfo", on_request_will_be_sent_extra_info)
        session.on("Network.responseReceived", on_response_received)
        session.on("Network.responseReceivedExtraInfo", on_response_received_extra_info)
        session.on("Network.loadingFinished", on_loading_finished)
        session.on("Network.loadingFailed", on_loading_failed)
        return session

    def get_mitm_port(self) -> int:
        """Return the mitmproxy port if running, else None."""
        return self._mitm_port

    def get_proxy_logs(self, start: int = 0, limit: int = 200) -> Dict[str, Any]:
        # Deduplicate proxy logs by method + normalized path (strip duplicate query params)
        # Also filter out browser-probe "Test"-appended duplicate URLs
        seen = set()
        deduped = []
        # First pass: collect all normalized URLs so we can detect Test-appended dupes
        all_norm_urls = set()
        for entry in self._proxy_logs:
            url = entry.get('url', '')
            try:
                parsed = urlparse(url)
                all_norm_urls.add(f"{parsed.scheme}://{parsed.netloc}{parsed.path}{'?' + parsed.query if parsed.query else ''}")
            except Exception:
                pass
        for entry in self._proxy_logs:
            url = entry.get('url', '')
            # Method can be missing for some capture paths; recover from raw_request.
            method = str(entry.get('method') or '').upper().strip()
            if not method:
                try:
                    raw = str(entry.get('raw_request') or '')
                    first = raw.splitlines()[0] if raw else ''
                    m = first.split(' ', 1)[0].strip().upper() if first else ''
                    if m in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
                        method = m
                except Exception:
                    pass
            if not method:
                method = 'GET'
            # Normalize: deduplicate query params to collapse accumulated variants
            try:
                parsed = urlparse(url)
                if parsed.query:
                    seen_params = {}
                    for part in parsed.query.split('&'):
                        if '=' in part:
                            key, val = part.split('=', 1)
                            if key not in seen_params:
                                seen_params[key] = val
                        elif part and part not in seen_params:
                            seen_params[part] = ''
                    # Skip browser-probe URLs: if any param value ends with "Test"
                    # and the same URL without "Test" suffix exists, skip it
                    is_probe_dupe = False
                    for k, v in seen_params.items():
                        if v.endswith('Test') and len(v) > 4:
                            clean_params = dict(seen_params)
                            clean_params[k] = v[:-4]  # strip "Test"
                            clean_query = '&'.join(sorted(f'{ck}={cv}' for ck, cv in clean_params.items()))
                            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{clean_query}"
                            if clean_url in all_norm_urls:
                                is_probe_dupe = True
                                break
                    if is_probe_dupe:
                        continue
                    norm_query = '&'.join(sorted(f'{k}={v}' for k, v in seen_params.items()))
                    norm_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{norm_query}"
                else:
                    # Skip path-level probe URLs (e.g. /page.htmTest when /page.htm exists)
                    path = parsed.path
                    if path.endswith('Test'):
                        clean_path = path[:-4]
                        clean_url = f"{parsed.scheme}://{parsed.netloc}{clean_path}"
                        if clean_url in all_norm_urls:
                            continue
                    norm_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            except Exception:
                norm_url = url
            key = (method, norm_url)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(entry)

        total = len(deduped)
        start = max(0, int(start))
        end = min(total, start + int(limit))
        return {
            'total': total,
            'start': start,
            'end': end,
            'logs': deduped[start:end]
        }

    def _explore_hamburger_menus(self, page, current_url, queue, depth):
        """Open hamburger/nav menus, expand all sub-menus, and extract hidden links.

        Many sites (especially school districts, CMS platforms like Thrillshare/Finalsite)
        hide most navigation behind a hamburger menu button. This function:
        1. Finds and clicks the hamburger/menu toggle button
        2. Recursively expands all sub-menu toggles
        3. Extracts all revealed links
        4. Closes the menu and restores the page state
        """
        if page.is_closed():
            return set()
        discovered = set()
        try:
            # Track links BEFORE opening the menu
            pre_links = set(page.evaluate(r"""
                () => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.getAttribute('href'))
                        .filter(h => h && !h.startsWith('#') && !h.startsWith('javascript:'));
                }
            """))

            # Step 1: Find and click the hamburger/menu button
            menu_opened = False
            menu_selectors = [
                'button:has-text("Menu")', 'button:has-text("MENU")',
                '[aria-label*="menu" i]', '[aria-label*="Menu" i]',
                '[aria-label*="navigation" i]', '[aria-label*="Navigation" i]',
                'button.hamburger', 'button.menu-toggle', 'button.nav-toggle',
                '.hamburger', '.menu-btn', '.menu-button', '.nav-toggle',
                'button[class*="menu"]', 'button[class*="hamburger"]',
                'button[class*="nav-toggle"]', '[data-toggle="menu"]',
                '#menu-toggle', '#nav-toggle', '#hamburger',
            ]
            for selector in menu_selectors:
                if menu_opened:
                    break
                try:
                    elements = page.query_selector_all(selector)
                    for el in elements:
                        try:
                            if not el.is_visible():
                                continue
                            text = (el.inner_text() or "").strip().lower()
                            # Skip if it's a logout/login button
                            if any(skip in text for skip in ['logout', 'sign out', 'login', 'sign in']):
                                continue
                            el.click(timeout=2000)
                            page.wait_for_timeout(800)
                            menu_opened = True
                            print(f"[NAV] Opened hamburger menu via: {selector}")
                            break
                        except Exception:
                            continue
                except Exception:
                    continue

            if not menu_opened:
                return discovered

            # Step 2: Expand all sub-menu toggles (multiple rounds for nested menus)
            # Use BOTH JavaScript DOM queries AND Playwright's accessibility-aware selectors
            # because Vue.js/React apps often render elements that aren't visible to querySelectorAll
            for expansion_round in range(4):
                expanded_count = 0

                # Method A: JavaScript DOM-based expansion (works for standard HTML)
                try:
                    js_expanded = page.evaluate(r"""
                        () => {
                            let count = 0;
                            const toggleSelectors = [
                                'button[class*="submenu"]', 'button[class*="toggle"]',
                                'button[aria-expanded="false"]',
                                '[class*="submenu-toggle"]', '[class*="sub-menu-toggle"]',
                                '[class*="menu-expand"]', '[class*="expand"]',
                                'button[aria-label*="Toggle"]', 'button[aria-label*="submenu"]',
                                '.has-children > button', '.has-submenu > button',
                                'li button[class*="arrow"]', 'li button[class*="caret"]',
                                'a[class*="toggle"]'
                            ];
                            const clicked = new Set();
                            for (const selector of toggleSelectors) {
                                document.querySelectorAll(selector).forEach(el => {
                                    const key = el.textContent + el.className;
                                    if (clicked.has(key)) return;
                                    if (el.getAttribute('aria-expanded') === 'true') return;
                                    try {
                                        if (el.offsetParent !== null) {
                                            el.click();
                                            clicked.add(key);
                                            count++;
                                        }
                                    } catch(e) {}
                                });
                            }
                            return count;
                        }
                    """)
                    expanded_count += js_expanded
                except Exception:
                    pass

                # Method B: Playwright role-based selectors (finds Vue.js/React virtual DOM elements)
                # These elements may not appear in querySelectorAll but ARE in the accessibility tree
                try:
                    pw_selectors = [
                        'role=button[name="Toggle Submenu"]',
                        'role=button[name="Toggle submenu"]',
                        'role=button[name*="toggle" i]',
                        'role=button[name*="submenu" i]',
                        'role=button[name*="expand" i]',
                        'text="▸"', 'text="▾"', 'text="►"', 'text="▼"',
                    ]
                    for pw_sel in pw_selectors:
                        try:
                            elements = page.locator(pw_sel).all()
                            for el in elements:
                                try:
                                    if el.is_visible():
                                        # Skip if already expanded
                                        aria_exp = el.get_attribute('aria-expanded')
                                        if aria_exp == 'true':
                                            continue
                                        el.click(timeout=1000)
                                        expanded_count += 1
                                        page.wait_for_timeout(200)
                                except Exception:
                                    continue
                        except Exception:
                            continue
                except Exception:
                    pass

                if expanded_count > 0:
                    try:
                        page.wait_for_timeout(500)
                    except Exception:
                        pass
                    print(f"[NAV] Expansion round {expansion_round + 1}: expanded {expanded_count} sub-menus")
                else:
                    break

            # Step 3: Extract ALL links now that everything is expanded
            post_links = page.evaluate(r"""
                () => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.getAttribute('href'))
                        .filter(h => h && !h.startsWith('#') && !h.startsWith('javascript:'));
                }
            """)

            new_links = set(post_links) - pre_links
            if new_links:
                print(f"[NAV] Hamburger menu revealed {len(new_links)} new links (was {len(pre_links)}, now {len(post_links)})")

            for href in post_links:
                normalized = self._normalize_url(current_url, href)
                if normalized and normalized not in self.visited:
                    if self._is_allowed_url(normalized):
                        discovered.add(normalized)

            # Step 4: Close the menu (click close button or press Escape)
            try:
                close_selectors = [
                    'button[aria-label*="close" i]', 'button[aria-label*="Close" i]',
                    'button:has-text("×")', 'button:has-text("✕")',
                    '.close-menu', '.menu-close', '[class*="close"]',
                ]
                closed = False
                for selector in close_selectors:
                    try:
                        els = page.query_selector_all(selector)
                        for el in els:
                            if el.is_visible():
                                el.click(timeout=1000)
                                closed = True
                                break
                        if closed:
                            break
                    except Exception:
                        continue
                if not closed:
                    page.keyboard.press("Escape")
                page.wait_for_timeout(300)
            except Exception:
                pass

            # Add all discovered URLs to queue
            for url in discovered:
                priority = any(kw in url.lower() for kw in ['api', 'admin', 'staff', 'login'])
                self._enqueue_url(queue, url, depth + 1, priority=priority)

            if discovered:
                print(f"[NAV] Total {len(discovered)} URLs discovered from hamburger menu exploration")

        except Exception as e:
            print(f"[!] Error in hamburger menu exploration: {e}")

        return discovered

    def _trigger_all_events(self, page, current_url, queue, depth):
        """Brute-force trigger events on interactive elements to discover hidden URLs."""
        discovered = set()
        try:
            # Get all elements with event listeners
            elements_with_events = page.evaluate(r"""
                () => {
                    const results = [];
                    const selectors = [
                        '[onclick]', '[onmouseover]', '[onmouseenter]', '[onfocus]',
                        '[onchange]', '[oninput]', '[onsubmit]',
                        'button', 'a', 'input[type="button"]', 'input[type="submit"]',
                        '[role="button"]', '[role="link"]', '[tabindex]',
                        '.clickable', '.btn', '.button', '.link',
                        '[data-action]', '[data-href]', '[data-url]', '[data-link]'
                    ];
                    const seen = new Set();
                    selectors.forEach(sel => {
                        document.querySelectorAll(sel).forEach((el, idx) => {
                            const id = el.id || el.className || `${sel}_${idx}`;
                            if (!seen.has(id)) {
                                seen.add(id);
                                results.push({
                                    selector: sel,
                                    index: idx,
                                    tag: el.tagName,
                                    text: (el.textContent || '').substring(0, 50).trim(),
                                    hasOnclick: !!el.onclick || el.hasAttribute('onclick'),
                                    dataHref: el.getAttribute('data-href') || el.getAttribute('data-url') || '',
                                });
                            }
                        });
                    });
                    return results.slice(0, 100);  // Limit to prevent slowdown
                }
            """)

            # Extract data-href and data-url attributes
            for el in elements_with_events:
                data_href = el.get('dataHref', '')
                if data_href:
                    normalized = self._normalize_url(current_url, data_href)
                    if normalized and normalized not in self.visited:
                        discovered.add(normalized)
                        print(f"[+] Found data-href URL: {normalized}")

            # Hover over elements to trigger onmouseover/onmouseenter
            # Uses fingerprint dedup to avoid re-hovering the same nav elements
            hover_selectors = ['[onmouseover]', '[onmouseenter]', '.dropdown', '.menu-item']
            for selector in hover_selectors:
                try:
                    elements = page.query_selector_all(selector)
                    for el in elements[:10]:  # Limit hover actions
                        try:
                            if el.is_visible():
                                if self._is_element_already_clicked(page, el):
                                    continue
                                el.hover()
                                page.wait_for_timeout(100)
                        except:
                            continue
                except:
                    continue

            # Re-extract URLs after hover events
            post_hover_urls = page.evaluate(r"""
                () => {
                    const urls = [];
                    document.querySelectorAll('a[href], [data-href], [data-url]').forEach(el => {
                        const href = el.getAttribute('href') || el.getAttribute('data-href') || el.getAttribute('data-url');
                        if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
                            urls.push(href);
                        }
                    });
                    return [...new Set(urls)];
                }
            """)

            for url in post_hover_urls:
                normalized = self._normalize_url(current_url, url)
                if normalized and normalized not in self.visited:
                    if self._is_allowed_url(normalized):
                        discovered.add(normalized)

            # Add discovered URLs to queue
            for url in discovered:
                priority = ('lab' in url.lower() or 'api' in url.lower())
                self._enqueue_url(queue, url, depth + 1, priority=priority)

        except Exception as e:
            print(f"[!] Error in event triggering: {e}")

        return discovered

    def _extract_spa_routes(self, page, base_url):
        """Extract routes from SPA frameworks (React, Vue, Angular)."""
        routes = set()
        try:
            spa_routes = page.evaluate(r"""
                () => {
                    const routes = [];

                    // React Router (check for __REACT_DEVTOOLS_GLOBAL_HOOK__ or router state)
                    try {
                        // Look for route definitions in window state
                        if (window.__REACT_ROUTER_CONTEXT__ || window.__PRELOADED_STATE__) {
                            const state = window.__PRELOADED_STATE__ || {};
                            JSON.stringify(state).match(/["']\/[a-zA-Z][^"']*["']/g)?.forEach(m => {
                                routes.push(m.replace(/["']/g, ''));
                            });
                        }
                    } catch(e) {}

                    // Vue Router
                    try {
                        if (window.__VUE_APP__ && window.__VUE_APP__.$router) {
                            window.__VUE_APP__.$router.options.routes?.forEach(r => {
                                if (r.path) routes.push(r.path);
                                r.children?.forEach(c => {
                                    if (c.path) routes.push(r.path + '/' + c.path);
                                });
                            });
                        }
                    } catch(e) {}

                    // Angular routes (look in window.ng or zone.js data)
                    try {
                        if (window.ng && window.getAllAngularRootElements) {
                            // Angular routes are harder to extract, skip for now
                        }
                    } catch(e) {}

                    // Look for route patterns in all script content
                    const scripts = Array.from(document.querySelectorAll('script')).map(s => s.textContent).join('');

                    // Common route patterns
                    const patterns = [
                        /path\s*:\s*["']([^"']+)["']/gi,
                        /route\s*:\s*["']([^"']+)["']/gi,
                        /url\s*:\s*["']([^"']+)["']/gi,
                        /["']\/[a-z][a-z0-9_\-\/]*["']/gi,
                    ];

                    patterns.forEach(pattern => {
                        let match;
                        while ((match = pattern.exec(scripts)) !== null) {
                            const path = match[1] || match[0].replace(/["']/g, '');
                            if (path.startsWith('/') && path.length > 1 && !path.includes('.')) {
                                routes.push(path);
                            }
                        }
                    });

                    return [...new Set(routes)];
                }
            """)

            for route in spa_routes:
                if route and route.startswith('/'):
                    normalized = self._normalize_url(base_url, route)
                    if normalized:
                        routes.add(normalized)

            if routes:
                print(f"[+] Extracted {len(routes)} SPA routes")

        except Exception as e:
            print(f"[!] Error extracting SPA routes: {e}")

        return routes

    def _setup_mutation_observer(self, page):
        """Setup DOM Mutation Observer to detect dynamically added elements."""
        try:
            page.evaluate(r"""
                () => {
                    window.__discoveredUrls = window.__discoveredUrls || new Set();

                    const observer = new MutationObserver((mutations) => {
                        mutations.forEach(mutation => {
                            mutation.addedNodes.forEach(node => {
                                if (node.nodeType !== 1) return;  // Only elements

                                // Check the node itself
                                const checkElement = (el) => {
                                    if (!el.getAttribute) return;

                                    // Check href
                                    const href = el.getAttribute('href');
                                    if (href && href.startsWith('/') && !href.startsWith('//')) {
                                        window.__discoveredUrls.add(href);
                                    }

                                    // Check onclick
                                    const onclick = el.getAttribute('onclick') || '';
                                    const patterns = [
                                        /location\.href\s*=\s*['"]([^'"]+)['"]/,
                                        /window\.location\s*=\s*['"]([^'"]+)['"]/
                                    ];
                                    patterns.forEach(p => {
                                        const match = onclick.match(p);
                                        if (match) window.__discoveredUrls.add(match[1]);
                                    });

                                    // Check data attributes
                                    ['data-href', 'data-url', 'data-link', 'data-action'].forEach(attr => {
                                        const val = el.getAttribute(attr);
                                        if (val && val.startsWith('/')) {
                                            window.__discoveredUrls.add(val);
                                        }
                                    });
                                };

                                checkElement(node);

                                // Check all descendants
                                if (node.querySelectorAll) {
                                    node.querySelectorAll('a, button, [onclick], [data-href], [data-url]').forEach(checkElement);
                                }
                            });
                        });
                    });

                    observer.observe(document.body, {
                        childList: true,
                        subtree: true
                    });

                    // Store observer reference for cleanup
                    window.__mutationObserver = observer;
                }
            """)
        except Exception as e:
            print(f"[!] Error setting up mutation observer: {e}")

    def _get_mutation_discovered_urls(self, page, base_url):
        """Get URLs discovered by the mutation observer."""
        urls = set()
        try:
            discovered = page.evaluate("() => Array.from(window.__discoveredUrls || [])")
            for url in discovered:
                normalized = self._normalize_url(base_url, url)
                if normalized and self._is_allowed_url(normalized):
                    urls.add(normalized)
            if urls:
                print(f"[+] Mutation observer found {len(urls)} new URLs")
        except:
            pass
        return urls

    def _extract_performance_urls(self, page, base_url):
        """Extract URLs from Performance API (captures all resources loaded)."""
        urls = set()
        try:
            entries = page.evaluate(r"""
                () => {
                    const urls = [];
                    if (window.performance && window.performance.getEntriesByType) {
                        // Get all resource timing entries
                        const entries = performance.getEntriesByType('resource');
                        entries.forEach(entry => {
                            if (entry.name) urls.push(entry.name);
                        });

                        // Get navigation entries
                        const navEntries = performance.getEntriesByType('navigation');
                        navEntries.forEach(entry => {
                            if (entry.name) urls.push(entry.name);
                        });
                    }
                    return urls;
                }
            """)

            for url in entries:
                if self._is_allowed_url(url, base_url):
                    urls.add(url)

        except Exception as e:
            pass
        return urls

    def _deep_url_discovery(self, page, current_url, queue, depth):
        """Comprehensive URL discovery using all methods."""
        if page.is_closed():
            return set()
        if not self._consume_interaction_budget(current_url, n=1):
            return set()
        self._recover_if_asset_navigation(page, current_url)
        all_discovered = set()

        # 1. Extract URLs from JavaScript
        js_urls = self._extract_urls_from_js(page, current_url)
        all_discovered.update(js_urls)

        # 2. Trigger events to discover hidden URLs
        event_urls = self._trigger_all_events(page, current_url, queue, depth)
        all_discovered.update(event_urls)

        # 3. Extract SPA routes
        spa_routes = self._extract_spa_routes(page, current_url)
        all_discovered.update(spa_routes)

        # 4. Get URLs from mutation observer
        mutation_urls = self._get_mutation_discovered_urls(page, current_url)
        all_discovered.update(mutation_urls)

        # 5. Get URLs from Performance API (all loaded resources)
        perf_urls = self._extract_performance_urls(page, current_url)
        all_discovered.update(perf_urls)

        # 6. Extract URLs from HTML comments (sometimes contain debug/test endpoints)
        try:
            comment_urls = page.evaluate(r"""
                () => {
                    const urls = [];
                    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
                    while (walker.nextNode()) {
                        const comment = walker.currentNode.textContent;
                        const matches = comment.match(/["']?(\/[a-zA-Z][^\s"'<>]*)/g);
                        if (matches) urls.push(...matches.map(m => m.replace(/["']/g, '')));
                    }
                    return urls;
                }
            """)
            for url in comment_urls:
                normalized = self._normalize_url(current_url, url)
                if normalized and normalized not in self.visited:
                    all_discovered.add(normalized)
        except:
            pass

        # 7. Check common API patterns (disabled in passive-only mode)
        if not self.passive_only:
            try:
                parsed = urlparse(current_url)
                base_path = parsed.path.rstrip('/')
                # Skip API probing for static files and API-like paths to avoid stacking
                static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot']
                api_markers = ['/api', '/graphql', '/rest', '/json', '/v1', '/v2', '/data']
                if not any(base_path.lower().endswith(ext) for ext in static_extensions) and '/static/' not in base_path:
                    if not any(m in base_path.lower() for m in api_markers):
                        common_api_suffixes = ['/api', '/v1', '/v2', '/graphql', '/rest', '/json', '/data']
                        for suffix in common_api_suffixes:
                            api_url = f"{parsed.scheme}://{parsed.netloc}{base_path}{suffix}"
                            if api_url not in self.visited:
                                all_discovered.add(api_url)
            except:
                pass

        # Add all discovered URLs to queue (prioritize important ones)
        for url in all_discovered:
            priority = any(kw in url.lower() for kw in ['lab', 'api', 'admin', 'test', 'debug'])
            self._enqueue_url(queue, url, depth + 1, priority=priority)

        return all_discovered

    def run(self):
        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            raise RuntimeError(f"Playwright not available: {e}")

        # Log AI status at start
        if self.ai_api_key:
            print(f"[AI] AI-powered crawling ENABLED (provider: {self.ai_provider})")
        else:
            print("[*] AI-powered crawling disabled (no API key provided)")

        self._log_scan('info', f'Starting crawl on {self.target_url}', {'target': self.target_url, 'max_depth': self.max_depth, 'max_pages': self.max_pages})

        queue = [(self.target_url, 0)]

        # Start mitmproxy for full traffic capture
        # Skip internal mitmproxy when routing through Burp — it handles capture
        # NOTE: use _os alias to avoid UnboundLocalError from `import os` later in this function
        import os as _os_mitm
        if _os_mitm.environ.get('DAST_USE_BURP_PROXY'):
            mitm_port = None
            print("[+] Burp proxy mode active — skipping internal mitmproxy")
        else:
            mitm_port = self._start_mitmproxy()

        with sync_playwright() as p:
            launch_args = []
            viewport_size = {"width": 1600, "height": 900}
            use_headed = self.show_browser or self.manual_mode or self.manual_only

            # On servers with Xvfb (DISPLAY set on Linux), default to headed mode
            # so the browser is visible via VNC for monitoring/debugging.
            import os, sys
            if not use_headed and sys.platform != 'darwin':
                display = os.environ.get('DISPLAY', '')
                if display:
                    use_headed = True
                    print(f"[*] DISPLAY={display} detected on server — auto-enabling headed mode (visible via VNC)")

            # Detect server/CI environment (EC2, Docker, headless Linux)
            import os, subprocess, sys
            is_server_env = (
                sys.platform != 'darwin'
                and not os.environ.get('DISPLAY')
            ) or os.path.exists('/.dockerenv') or os.environ.get('AWS_EXECUTION_ENV')

            if use_headed:
                launch_args = ["--window-position=0,0", "--window-size=1600,900"]
            # Verify display server is available for headed mode; fall back to headless.
            # macOS uses native windowing (no DISPLAY needed) — only gate this on Linux.
            if use_headed and sys.platform != 'darwin':
                display = os.environ.get('DISPLAY', '')
                if not display:
                    print("[!] show_browser requested but no DISPLAY set - falling back to headless")
                    use_headed = False
                else:
                    # On Linux, verify the X display is actually usable
                    try:
                        result = subprocess.run(['xdpyinfo', '-display', display],
                                                capture_output=True, timeout=3, text=True)
                        if result.returncode != 0:
                            print(f"[!] show_browser requested but display {display} not accessible - falling back to headless")
                            use_headed = False
                    except Exception:
                        print(f"[!] show_browser requested but cannot verify display {display} - falling back to headless")
                        use_headed = False

            # Add essential Chromium flags for server/CI environments (EC2, Docker, etc.)
            # These prevent crashes on headless Linux where /dev/shm is small,
            # no GPU is available, and the process may run as root.
            if is_server_env:
                server_flags = [
                    "--no-sandbox",              # Required when running as root
                    "--disable-gpu",             # No GPU on EC2/Docker
                    "--disable-dev-shm-usage",   # /dev/shm too small → use /tmp instead
                    "--disable-software-rasterizer",
                    "--disable-setuid-sandbox",
                    "--disable-background-networking",
                    "--disable-default-apps",
                    "--disable-sync",
                    "--no-first-run",
                    "--font-render-hinting=none", # Avoid font rendering issues
                ]
                for flag in server_flags:
                    if flag not in launch_args:
                        launch_args.append(flag)
                print(f"[*] Server environment detected - added Chromium flags for EC2/Docker stability")
                print(f"[!] WARNING: --no-sandbox is enabled. Browser process runs without sandboxing.")

            browser = p.chromium.launch(headless=not use_headed, args=launch_args)
            self._browser = browser
            context_opts = {
                'ignore_https_errors': True,
                'viewport': viewport_size,
                'screen': viewport_size,
            }
            # Route browser through Burp if requested, otherwise mitmproxy
            import os as _os
            _burp_proxy = _os.environ.get('DAST_USE_BURP_PROXY')
            if _burp_proxy:
                context_opts['proxy'] = {'server': 'http://127.0.0.1:8080'}
                print(f"[+] Browser routing through Burp proxy on port 8080")
            elif mitm_port:
                context_opts['proxy'] = {'server': f'http://127.0.0.1:{mitm_port}'}
                print(f"[+] Browser routing through mitmproxy on port {mitm_port}")
            context = browser.new_context(**context_opts)
            page = context.new_page()

            # If mitmproxy is active, skip CDP capture (mitmproxy handles it)
            if not mitm_port:
                self._setup_cdp_capture(context, page)

            # Setup request interception to capture XHR/Fetch URLs
            captured_requests, response_urls = self._setup_request_interception(page)

            if self.manual_only:
                try:
                    page.goto(self.target_url, wait_until="domcontentloaded", timeout=self.timeout)
                except Exception:
                    pass
                self.current_url = page.url or self.target_url
                queue = []

            # Setup mutation observer to detect dynamically added elements
            self._setup_mutation_observer(page)

            # Attempt login if credentials provided
            if not self.manual_only and self.login_url and self.username:
                login_success = self._do_login(page)
                self._extract_cookies(context)
                if login_success:
                    print(f"[+] Authenticated session established")
                    # IMPORTANT: After login, add the post-login page to the queue
                    # This ensures we crawl the authenticated area of the app
                    post_login_url = page.url
                    if post_login_url and post_login_url != self.login_url:
                        if post_login_url not in [u for u, _ in queue]:
                            queue.insert(0, (post_login_url, 0))  # Add at front with depth 0
                            print(f"[+] Added post-login page to queue: {post_login_url}")

                    # Also extract links from the current (post-login) page immediately
                    try:
                        post_login_links = page.evaluate("""
                            () => Array.from(document.querySelectorAll('a[href]'))
                                .map(a => a.href)
                                .filter(href => href && !href.startsWith('javascript:'))
                        """)
                        for link in post_login_links:
                            if self._enqueue_url(queue, link, 1):
                                print(f"[+] Found post-login link: {link}")
                    except:
                        pass

                    # Explore dropdown navigation (like bWAPP's bug selector)
                    # This discovers pages accessible via select/dropdown forms
                    self._explore_dropdown_navigation(page, post_login_url, queue, 0)
                else:
                    print(f"[!] Warning: Login may have failed - continuing anyway")

            seen_input_points = set()
            seen_forms = set()
            pages_since_check = 0

            # ===== Pre-crawl URL discovery =====
            # Discover URLs from sitemap.xml, robots.txt and JSON endpoints
            # BEFORE the main loop so the queue starts fully populated.
            # Skip pre-crawl discovery in manual_only mode - user browses manually.
            self._robots_data = {}
            if not self.manual_only:
                try:
                    _pc_parsed = urlparse(self.target_url)
                    _pc_base = f"{_pc_parsed.scheme}://{_pc_parsed.netloc}"
                except Exception:
                    _pc_base = self.target_url

                _pre_crawl_urls = set()
                _robots_sitemap_urls = []

                # 1. robots.txt (may also yield Sitemap directives)
                try:
                    self._robots_data = self._discover_robots_txt(_pc_base)
                    _robots_sitemap_urls = self._robots_data.get('sitemap_urls', [])
                    for u in self._robots_data.get('disallowed_paths', []):
                        if u not in self.visited:
                            _pre_crawl_urls.add(u)
                    for u in self._robots_data.get('allowed_paths', []):
                        if u not in self.visited:
                            _pre_crawl_urls.add(u)
                except Exception as e:
                    self._robots_data = {}
                    print(f"[!] robots.txt discovery failed: {e}")

                # 2. sitemap.xml
                _sitemap_count = 0
                try:
                    _sitemap_urls = self._discover_sitemap(_pc_base, extra_sitemap_urls=_robots_sitemap_urls)
                    _sitemap_count = len(_sitemap_urls)
                    _pre_crawl_urls.update(_sitemap_urls)
                except Exception as e:
                    print(f"[!] Sitemap discovery failed: {e}")

                # 3. JSON endpoint listings (e.g. /allEndPointJson, /scanner)
                _json_count = 0
                try:
                    _json_urls = self._discover_json_endpoint_urls(_pc_base)
                    _json_count = len(_json_urls)
                    _pre_crawl_urls.update(_json_urls)
                except Exception as e:
                    print(f"[!] JSON endpoint discovery failed: {e}")

                # 4. Seed URLs from file (e.g. gau output)
                _seed_count = 0
                if self.seed_urls_file:
                    try:
                        from urllib.parse import urlparse as _up
                        _target_host = _up(self.target_url).netloc.lower()
                        _junk_exts = {'.jpg','.jpeg','.png','.gif','.ico','.svg','.webp','.bmp',
                                      '.css','.js','.mjs','.map','.woff','.woff2','.ttf','.eot','.otf',
                                      '.mp4','.mp3','.avi','.mov','.pdf','.doc','.docx','.xls','.xlsx',
                                      '.zip','.gz','.tar','.rar','.xml','.rss','.txt'}
                        _junk_paths = ['/.well-known/','/wp-content/uploads/','/wp-includes/',
                                       '/static/img/','/assets/img/','/images/','/fonts/','/media/',
                                       '/cdn-cgi/','/feed/']
                        _seen = set()
                        with open(self.seed_urls_file, 'r') as _sf:
                            for _line in _sf:
                                _line = _line.strip()
                                if not _line or not _line.startswith('http'):
                                    continue
                                _p = _up(_line)
                                # Rewrite backend URLs to target host (proxy/facade pattern)
                                if _p.netloc.lower() != _target_host:
                                    _line = self._rewrite_url_to_target(_line)
                                    _p = _up(_line)
                                    if _p.netloc.lower() != _target_host:
                                        continue
                                # Skip junk extensions
                                _ext = os.path.splitext(_p.path)[1].lower()
                                if _ext in _junk_exts:
                                    continue
                                # Skip junk paths
                                _path_lower = _p.path.lower()
                                if any(jp in _path_lower for jp in _junk_paths):
                                    continue
                                # Deduplicate by path
                                _norm = _p.path.rstrip('/') or '/'
                                if _norm in _seen:
                                    continue
                                _seen.add(_norm)
                                _pre_crawl_urls.add(_line)
                                _seed_count += 1
                        print(f"[+] Seed file: loaded {_seed_count} URLs from {self.seed_urls_file}")
                        self._log_scan('info', f'Seed file: {_seed_count} URLs from {self.seed_urls_file}', {
                            'source': 'seed_file', 'count': _seed_count})
                    except Exception as e:
                        print(f"[!] Seed file error: {e}")

                # Pre-check: filter out dead URLs before adding to browser queue.
                # A fast parallel HEAD request check removes 404s/dead endpoints
                # so the browser doesn't waste time navigating to them.
                if _pre_crawl_urls:
                    _pre_count = len(_pre_crawl_urls)
                    _pre_crawl_urls = self._precheck_urls_alive(_pre_crawl_urls)
                    _filtered = _pre_count - len(_pre_crawl_urls)
                    if _filtered > 0:
                        print(f"[+] Pre-check filtered {_filtered} dead URLs, {len(_pre_crawl_urls)} alive")
                        self._log_scan('info', f'Pre-check: {_filtered} dead URLs filtered, {len(_pre_crawl_urls)} alive', {
                            'total': _pre_count, 'alive': len(_pre_crawl_urls), 'dead': _filtered
                        })

                # Add discovered (live) URLs to queue at depth 1
                if _pre_crawl_urls:
                    _added = 0
                    for url in sorted(_pre_crawl_urls):
                        if self._enqueue_url(queue, url, 1):
                            _added += 1
                    if _added:
                        print(f"[+] Pre-crawl discovery: added {_added} live URLs to queue "
                              f"(sitemap: {_sitemap_count}, json: {_json_count})")
                        self._log_scan('info',
                            f'Pre-crawl discovery: added {_added} live URLs '
                            f'(sitemap: {_sitemap_count}, json: {_json_count})',
                            {'sitemap': _sitemap_count, 'json': _json_count, 'total': _added})

                    # Auto-adjust max_pages if discovery reveals many URLs —
                    # enterprise apps routinely have 500-5000 endpoints.
                    if len(queue) > self.max_pages * 0.8:
                        _old_max = self.max_pages
                        self.max_pages = max(self.max_pages, len(queue) + 200)
                        if _old_max != self.max_pages:
                            print(f"[+] Auto-adjusted max_pages from {_old_max} to {self.max_pages} "
                                  f"to accommodate {len(queue)} discovered URLs")
            else:
                print("[*] Manual Proxy mode - skipping pre-crawl discovery and auto-crawl")

            while queue and len(self.visited) < self.max_pages and not self._stop_requested:
                # If the user closes the headed browser window mid-crawl, end gracefully
                # and keep already collected findings/results.
                if page.is_closed():
                    print("[!] Browser page was closed during crawl - finishing with partial results")
                    break
                self._pause_if_needed()
                if self.capture_on_resume and 'page' in locals():
                    self._capture_manual_snapshot(page)
                    self.capture_on_resume = False
                url, depth = queue.pop(0)
                if url in self.visited or depth > self.max_depth:
                    continue

                # Never leave target domain — reject any external URL that snuck into queue
                if not self._is_allowed_url(url):
                    self.visited.add(url)
                    continue

                # Smart skip: API/JSON endpoints from sitemap — don't navigate browser to them.
                # These are data endpoints (return JSON, not HTML) and waste crawl time.
                # Instead, record them as endpoints for scanning but don't load in browser.
                _url_path = urlparse(url).path.lower()
                _api_patterns = ('/api/', '/v1/', '/v2/', '/v3/', '/v4/', '/graphql', '/rest/', '/.json', '/feed', '/rss')
                if any(p in _url_path for p in _api_patterns):
                    self.visited.add(url)
                    self._add_endpoint_entry(url, source="sitemap-api", status=None)
                    # Still record it for active scanning (nuclei, etc.) but skip browser navigation
                    if not hasattr(self, '_api_endpoints_discovered'):
                        self._api_endpoints_discovered = []
                    self._api_endpoints_discovered.append(url)
                    continue

                # Smart skip: if we've seen 3+ consecutive 404s matching a URL pattern,
                # skip similar URLs to avoid wasting time on dead endpoints
                if not hasattr(self, '_404_pattern_counts'):
                    self._404_pattern_counts = {}
                _url_pattern_key = self._get_404_pattern(url)
                if _url_pattern_key and self._404_pattern_counts.get(_url_pattern_key, 0) >= 3:
                    self.visited.add(url)
                    continue

                if self.skip_asset_urls and self._is_probably_asset_url(url):
                    # Do not navigate to downloads/assets in the browser.
                    self.visited.add(url)
                    continue

                # Check for AI skip patterns
                if self._should_skip_url(url):
                    print(f"[AI] Skipping URL (matches skip pattern): {url}")
                    self.visited.add(url)
                    continue

                # Skip logout URLs — visiting them destroys the authenticated session
                _url_path_lower = urlparse(url).path.lower()
                if any(kw in _url_path_lower for kw in ('logout', 'signout', 'sign_out', 'log_out')):
                    print(f"[*] Skipping logout URL to preserve session: {url}")
                    self.visited.add(url)
                    self._add_endpoint_entry(url, source="headless", status=None)
                    continue

                # Check for stuck state every 5 pages
                pages_since_check += 1
                if pages_since_check >= 5:
                    pages_since_check = 0
                    if self._check_stuck(len(self.visited)):
                        print(f"[!] Crawl appears stuck at {len(self.visited)} pages")
                        if self.ai_api_key:
                            self._ai_recover_from_stuck(page, queue, url)
                        else:
                            self._basic_stuck_recovery(page, queue)

                try:
                    # Rate-limit: sleep between page visits to avoid 429s from WAFs/Varnish
                    if self.crawl_delay and self.crawl_delay > 0:
                        import time as _time
                        _time.sleep(self.crawl_delay)

                    # Avoid networkidle: many pages keep connections open which causes stalls.
                    goto_timeout = min(int(self.timeout or 15000), 12000)
                    response = page.goto(url, wait_until="domcontentloaded", timeout=goto_timeout)
                    try:
                        page.wait_for_load_state("networkidle", timeout=2000)
                    except Exception:
                        pass
                    status = response.status if response else None
                except Exception as e:
                    self.visited.add(url)  # Mark as visited to avoid infinite retry
                    if self._stop_requested:
                        break
                    # If page load fails, try AI recovery
                    if self.ai_api_key and 'timeout' in str(e).lower():
                        print(f"[AI] Page timeout on {url}, attempting recovery")
                        self._ai_recover_from_stuck(page, queue, url)
                    else:
                        print(f"[!] Page load failed for {url}: {str(e)[:100]}")
                    continue

                # If we landed on a non-HTML asset (e.g., PDF), don't attempt extraction.
                try:
                    ct = (response.headers.get("content-type", "") if response else "") or ""
                except Exception:
                    ct = ""
                if self.skip_asset_urls and (("application/pdf" in (ct or "").lower()) or (not self._is_html_content_type(ct))):
                    self.visited.add(url)
                    # Keep the headed browser from "sticking" on the PDF viewer.
                    try:
                        page.goto("about:blank", wait_until="domcontentloaded", timeout=3000)
                    except Exception:
                        pass
                    continue

                if self._stop_requested:
                    break

                # Check if we've been logged out and re-authenticate
                if self.login_url and self.username:
                    self._check_and_relogin(page)
                    # If we were on login page, re-navigate to original URL
                    if page.url != url:
                        try:
                            goto_timeout = min(int(self.timeout or 15000), 12000)
                            response = page.goto(url, wait_until="domcontentloaded", timeout=goto_timeout)
                            try:
                                page.wait_for_load_state("networkidle", timeout=2000)
                            except Exception:
                                pass
                            status = response.status if response else None
                        except:
                            continue

                self._pause_if_needed()
                if self.capture_on_resume and 'page' in locals():
                    self._capture_manual_snapshot(page)
                    self.capture_on_resume = False

                # Manual mode: pause for user interaction, then sync to current page
                manual_url = self._manual_pause_and_sync(page, url)
                if manual_url != url:
                    url = manual_url
                    status = None

                _canon = self._canonicalize_url(url)
                if url in self.visited or _canon in self.visited:
                    continue
                self.visited.add(url)
                self.visited.add(_canon)

                # Log every page visit
                method_str = 'GET'
                self._log_scan('info', f'Visiting [{status or "?"}] {url}', {
                    'url': url, 'status': status, 'depth': depth,
                    'method': method_str, 'visited': len(self.visited), 'queued': len(queue)
                })

                # Track 404 patterns — if many URLs with same pattern return 404,
                # skip remaining similar URLs to avoid wasting crawl time
                if status == 404:
                    if not hasattr(self, '_404_pattern_counts'):
                        self._404_pattern_counts = {}
                    _pat_key = self._get_404_pattern(url)
                    if _pat_key:
                        self._404_pattern_counts[_pat_key] = self._404_pattern_counts.get(_pat_key, 0) + 1
                        if self._404_pattern_counts[_pat_key] == 3:
                            # Count how many queued URLs match this dead pattern
                            _skip_count = sum(1 for q_url, _ in queue if self._get_404_pattern(q_url) == _pat_key)
                            if _skip_count > 0:
                                print(f"[SMART] Pattern '{_pat_key}' hit 3x 404s — will skip ~{_skip_count} similar queued URLs")

                # Only add successful responses to endpoints (skip 404s and errors)
                if status and status != 404:
                    self._add_endpoint_entry(url, source="headless", status=status)
                    # Collect query string parameters
                    self._add_params(url)

                    # Detect path parameters (like /users/123)
                    path_params = self._detect_path_parameters(url)
                    if path_params:
                        if not hasattr(self, '_detected_params'):
                            self._detected_params = []
                        for param in path_params:
                            param['url'] = url
                            param['source'] = 'path'
                            self._detected_params.append(param)

                    # AI parameter analysis (once per unique path pattern, limit to save API calls)
                    if self.ai_api_key and len(self.visited) <= 20:
                        ai_params = self._ai_analyze_parameters(page, url)
                        if ai_params:
                            if not hasattr(self, '_detected_params'):
                                self._detected_params = []
                            for param in ai_params:
                                param['url'] = url
                                self._detected_params.append(param)

                # Progress summary every 10 pages
                if len(self.visited) % 10 == 0:
                    print(f"[*] Progress: {len(self.visited)} pages visited, {len(queue)} in queue")
                    self._log_scan('info', f'Crawl progress: {len(self.visited)} pages visited, {len(queue)} in queue, {len(self.forms)} forms, {len(self.endpoints)} endpoints', {'visited': len(self.visited), 'queued': len(queue), 'forms': len(self.forms), 'endpoints': len(self.endpoints)})

                if not self.single_round:
                    # AI Navigator: analyze page and make smart crawl decisions
                    _ai_nav_decision = None
                    if self.ai_api_key:
                        _ai_nav_decision = self._ai_navigate_page(page, url, queue, depth)

                    if not self.passive_only:
                        self._click_through(page, url, depth, queue)

                        # Actively probe forms at the browser level (typing and clicking)
                        self._probe_browser_forms(page, url, queue, depth)

                        # Enumerate <select> navigation dropdowns to discover all
                        # pages reachable by choosing different option values
                        # (e.g. bWAPP portal with 159 bug options, admin panels, etc.)
                        self._enumerate_form_select_options(page, url, queue, depth)

                    # Deep URL discovery — skip if AI says this is a duplicate layout
                    # or if content hash matches a previously explored page
                    if self._ai_should_deep_explore(page, url):
                        self._deep_url_discovery(page, url, queue, depth)
                    else:
                        print(f"[AI-NAV] Skipping deep explore for {url[:80]} (duplicate/already explored)")

                # Extract HTML comments for credential hints and debug info
                self._extract_html_comments(page)

                # Extract WebSocket endpoints from JavaScript
                self._extract_websocket_endpoints(page)

                # Detect gRPC/protobuf indicators in JavaScript
                self._detect_grpc_indicators(page)

                # Extract browser storage (localStorage/sessionStorage)
                self._extract_browser_storage(page)

                # Extract event listeners for hidden functionality
                self._extract_event_listeners(page)

                # Extract data attributes for path parameters (data-id, data-order-id, etc.)
                data_attrs = self._extract_data_attributes(page, url)
                # Add URLs discovered from data attributes to queue
                for attr in data_attrs:
                    if attr.get('type') == 'url':
                        attr_url = attr.get('value')
                        if attr_url:
                            self._enqueue_url(queue, attr_url, depth + 1)

                # Ensure we're back on the current page for extraction.
                # In single_round mode, do not re-navigate — extract from current DOM only.
                if (not self.single_round) and page.url != url:
                    try:
                        goto_timeout = min(int(self.timeout or 15000), 12000)
                        page.goto(url, wait_until="domcontentloaded", timeout=goto_timeout)
                        try:
                            page.wait_for_load_state("networkidle", timeout=2000)
                        except Exception:
                            pass
                    except:
                        pass

                # Explore hamburger/nav menus to discover hidden navigation links.
                # Run on the first page and whenever we enter a new sub-site root
                # (e.g. /o/kes, /o/bes, /o/wfgms, /o/iphs for school district sites).
                if not self.single_round:
                    _is_root_page = (depth <= 1) or url.rstrip('/') == self.target_url.rstrip('/')
                    _path = url.split('?')[0].rstrip('/')
                    _is_subsite_root = bool(_path) and _path.count('/') <= 4 and not any(_path.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.pdf', '.gif', '.svg'])
                    if not hasattr(self, '_hamburger_explored_roots'):
                        self._hamburger_explored_roots = set()
                    _root_key = '/'.join(_path.split('/')[:5])  # Group by first 4 path segments
                    if (_is_root_page or _is_subsite_root) and _root_key not in self._hamburger_explored_roots:
                        self._hamburger_explored_roots.add(_root_key)
                        self._explore_hamburger_menus(page, url, queue, depth)

                # Expand collapsibles before extraction (can trigger navigation on some apps).
                # Skip in single_round mode to keep behavior strictly "visit once, extract once".
                if not self.single_round:
                    try:
                        page.evaluate("""
                            () => {
                                document.querySelectorAll('button.coll, [class*="collapse"], [data-toggle], [data-bs-toggle]').forEach(el => {
                                    try { el.click(); } catch(e) {}
                                });
                            }
                        """)
                        page.wait_for_timeout(500);
                    except:
                        pass

                links = []
                forms = []
                hidden = []
                uploads = []
                loose_inputs = []

                for frame in page.frames:
                    try:
                        data = self._extract_from_frame(frame)
                    except Exception:
                        continue
                    if not isinstance(data, dict):
                        continue
                    links.extend(data.get("links", []))
                    forms.extend(data.get("forms", []))
                    hidden.extend(data.get("hiddenFields", []))
                    uploads.extend(data.get("fileUploads", []))
                    loose_inputs.extend(data.get("looseInputs", []))
                    links.extend(data.get("dataLinks", []))
                    links.extend(data.get("optionLinks", []))

                # Collect hidden fields
                for h in hidden:
                    if h.get("name"):
                        self.hidden_fields.append({
                            "page": url,
                            "name": h.get("name"),
                            "value": h.get("value", ""),
                        })

                # Collect file uploads and request help if ask_for_help is enabled
                for u in uploads:
                    if u.get("name"):
                        self.file_uploads.append({
                            "page": url,
                            "name": u.get("name"),
                            "accept": u.get("accept", ""),
                        })

                for href in links:
                    normalized = self._normalize_url(url, href)
                    if normalized:
                        self._enqueue_url(queue, normalized, depth + 1)

                for form in forms:
                    action = self._normalize_url(url, form.get("action") or url)
                    if not action:
                        action = url
                    form_key = (url, action, (form.get("method") or "GET").upper())
                    if form_key in seen_forms:
                        continue
                    seen_forms.add(form_key)
                    form_entry = {
                        "url": url,
                        "action": action,
                        "method": form.get("method", "GET"),
                        "inputs": form.get("inputs", []),
                    }
                    self._add_form(form_entry)
                    field_names = [i.get('name','') for i in form_entry['inputs'] if i.get('name')]
                    self._log_scan('info', f'Form found: {form_entry["method"].upper()} {action[:80]} ({len(field_names)} fields: {", ".join(field_names[:5])})', {
                        'url': url, 'action': action, 'method': form_entry['method'], 'fields': field_names
                    })
                    self._add_params(action)
                    for inp in form_entry["inputs"]:
                        if not inp.get("name"):
                            continue
                        ip_key = (action, form_entry["method"], inp.get("name"))
                        if ip_key in seen_input_points:
                            continue
                        seen_input_points.add(ip_key)
                        input_point = {
                            "page": url,
                            "action": action,
                            "method": form_entry["method"],
                            "name": inp.get("name"),
                            "input_type": inp.get("type", "text"),
                        }
                        self._add_input_point(input_point)

                        # DAST: Scan this input point for vulnerabilities
                        if self.enable_scanning and self.scan_on_the_fly:
                            cookies_dict = {c.get('name'): c.get('value', '') for c in context.cookies() if c.get('name')}
                            self._scan_input_point(input_point, context, cookies_dict)

                # Submit GET/POST forms to discover additional URLs (same-domain only).
                # Skip in single_round mode to avoid extra request cycles.
                if not self.single_round:
                    self._submit_forms(context, url, forms, queue, depth)

                # Inputs outside forms (common in SPAs)
                for inp in loose_inputs:
                    name = inp.get("name") or ""
                    if not name:
                        continue
                    ip_key = (url, "GET", name)
                    if ip_key in seen_input_points:
                        continue
                    seen_input_points.add(ip_key)
                    input_point = {
                        "page": url,
                        "action": url,
                        "method": "GET",
                        "name": name,
                        "input_type": inp.get("type", "text"),
                    }
                    self._add_input_point(input_point)

                    # DAST: Scan this input point for vulnerabilities
                    if self.enable_scanning and self.scan_on_the_fly:
                        cookies_dict = {c.get('name'): c.get('value', '') for c in context.cookies() if c.get('name')}
                        self._scan_input_point(input_point, context, cookies_dict)

            if self.manual_only and not page.is_closed():
                _last_progress_update = 0.0
                try:
                    # Navigate to target and track it as visited
                    try:
                        cur_url = page.url
                        if cur_url and cur_url not in self.visited:
                            self.visited.add(cur_url)
                            self.current_url = cur_url
                    except Exception:
                        pass

                    while not page.is_closed() and not self._stop_requested:
                        now = time.time()
                        if now - self._last_manual_extract > 1.5:
                            self._manual_collect_input_points(page)
                            self._last_manual_extract = now

                            # Track current URL in visited set
                            try:
                                cur_url = page.url
                                if cur_url and cur_url not in self.visited:
                                    self.visited.add(cur_url)
                                self.current_url = cur_url
                            except Exception:
                                pass

                        # Send progress updates every 2 seconds for UI responsiveness
                        if now - _last_progress_update > 2.0:
                            _last_progress_update = now
                            if hasattr(self, '_progress_callback') and self._progress_callback:
                                try:
                                    cur_url = page.url if not page.is_closed() else self.current_url
                                except Exception:
                                    cur_url = self.current_url
                                try:
                                    self._progress_callback({
                                        'status': 'manual_browsing',
                                        'progress': min(50, len(self.visited)),
                                        'current_url': cur_url or '',
                                        'pages_found': len(self.visited),
                                        'forms_found': len(self.forms),
                                        'proxy_logs': len(self._proxy_logs),
                                        'input_points': len(self.input_points),
                                        'message': f'Manual browsing - {len(self.visited)} pages, {len(self._proxy_logs)} requests captured'
                                    })
                                except Exception:
                                    pass

                        page.wait_for_timeout(300)
                except Exception:
                    pass

            # Extract cookies at the end too
            self._extract_cookies(context)

            # Process captured XHR/Fetch requests
            for req in captured_requests:
                req_url = req.get('url', '')
                if req_url and req_url not in self.visited:
                    self._xhr_urls.add(req_url)
                    self._api_endpoints.append({
                        'url': req_url,
                        'method': req.get('method', 'GET'),
                        'type': req.get('type', 'xhr')
                    })

            # Process URLs found in API responses
            for url_path in response_urls:
                normalized = self._normalize_url(self.target_url, url_path)
                if normalized and normalized not in self.visited:
                    self._xhr_urls.add(normalized)

            if self._xhr_urls:
                print(f"[+] Captured {len(self._xhr_urls)} XHR/Fetch URLs (including from responses)")

            if self.show_browser and not self._stop_requested:
                try:
                    hold_ms = int(os.getenv("HEADLESS_SHOW_HOLD_MS", "5000"))
                except ValueError:
                    hold_ms = 5000
                if hold_ms > 0 and not page.is_closed():
                    try:
                        page.wait_for_timeout(hold_ms)
                    except Exception:
                        print("[!] Browser closed before final hold timeout - continuing")
            try:
                browser.close()
            except Exception:
                pass  # Browser may already be closed from stop request

        # Stop mitmproxy after browser is closed
        try:
            self._stop_mitmproxy()
        except Exception:
            pass

        # Post-crawl discovery enhancements (OpenAPI/GraphQL/method probing/code discovery)
        try:
            parsed_target = urlparse(self.target_url)
            base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
        except Exception:
            base_url = self.target_url

        try:
            self._static_js_param_discovery(base_url)
        except Exception:
            pass

        try:
            self._discover_openapi_specs(base_url)
        except Exception:
            pass

        try:
            self._discover_graphql_endpoints(base_url)
        except Exception:
            pass

        try:
            self._code_discovery_urls(base_url)
        except Exception:
            pass

        # Discover common paths that may not be linked
        try:
            self._discover_common_paths(base_url)
        except Exception:
            pass

        # Gobuster directory enumeration
        try:
            self._run_gobuster(base_url)
        except Exception as e:
            print(f"[Gobuster] Error during enumeration: {e}")

        # SPA fallback: parse discovered template HTML files for forms/params.
        try:
            self._extract_forms_from_template_urls(base_url)
        except Exception:
            pass

        # Probe HTTP methods for a subset of discovered URLs
        try:
            probe_candidates = []
            for ep in self.endpoints:
                if ep.get("url"):
                    probe_candidates.append(ep.get("url"))
            for ep in getattr(self, "_api_endpoints", []):
                if ep.get("url"):
                    probe_candidates.append(ep.get("url"))
            seen = set()
            unique_candidates = []
            for u in probe_candidates:
                if u not in seen:
                    seen.add(u)
                    unique_candidates.append(u)
            self._probe_http_methods(unique_candidates)
        except Exception:
            pass

        # Collect extracted data
        html_hints = getattr(self, '_html_hints', {'credentials': [], 'todos': [], 'debug_info': [], 'endpoints': []})
        data_attributes = getattr(self, '_data_attributes', [])
        dynamic_url_patterns = getattr(self, '_dynamic_url_patterns', [])
        detected_params = getattr(self, '_detected_params', [])

        # Deduplicate detected parameters
        seen_params = set()
        unique_params = []
        for p in detected_params:
            key = (p.get('name'), p.get('type'), p.get('source'))
            if key not in seen_params:
                seen_params.add(key)
                unique_params.append(p)

        # Deduplicate endpoints - keep best status (prefer 2xx over others, avoid 404)
        endpoint_map = {}
        for ep in self.endpoints:
            url = ep.get('url', '')
            status = ep.get('status')
            if url not in endpoint_map:
                endpoint_map[url] = ep
            else:
                existing_status = endpoint_map[url].get('status')
                # Prefer 2xx status codes
                if status and 200 <= status < 300:
                    endpoint_map[url] = ep
                elif existing_status and existing_status == 404 and status and status != 404:
                    endpoint_map[url] = ep

        # Filter out browser-probe "Test"-appended URLs where the base URL exists
        all_urls = set(endpoint_map.keys())
        probe_urls = set()
        for url in all_urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    # Check if any param value ends with "Test" and base exists
                    params = dict(p.split('=', 1) for p in parsed.query.split('&') if '=' in p)
                    for k, v in params.items():
                        if v.endswith('Test') and len(v) > 4:
                            clean_params = dict(params)
                            clean_params[k] = v[:-4]
                            clean_q = '&'.join(f'{ck}={cv}' for ck, cv in clean_params.items())
                            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{clean_q}"
                            if clean_url in all_urls:
                                probe_urls.add(url)
                                break
                elif parsed.path.endswith('Test'):
                    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path[:-4]}"
                    if clean_url in all_urls:
                        probe_urls.add(url)
            except Exception:
                pass

        # Filter out confirmed 404s and probe duplicates; keep status=None (JS-discovered)
        deduplicated_endpoints = [
            ep for ep in endpoint_map.values()
            if ep.get('status') != 404
            and ep.get('url', '') not in probe_urls
        ]

        # Also extract parameters from form inputs
        form_params = []
        for form in self.forms:
            for inp in form.get('inputs', []):
                if inp.get('name'):
                    param_type = self._infer_input_type(inp)
                    form_params.append({
                        'name': inp.get('name'),
                        'type': param_type,
                        'source': 'form',
                        'url': form.get('action', form.get('url')),
                        'input_type': inp.get('type', 'text')
                    })

        # Merge all parameters
        all_params = unique_params + form_params

        # Get new extraction data
        websocket_endpoints = getattr(self, '_websocket_endpoints', [])
        browser_storage = getattr(self, '_browser_storage', {'localStorage': [], 'sessionStorage': []})
        event_listeners = getattr(self, '_event_listeners', [])
        openapi_specs = getattr(self, '_openapi_specs', [])
        graphql_endpoints = getattr(self, '_graphql_endpoints', [])
        graphql_schemas = getattr(self, '_graphql_schemas', [])
        grpc_indicators = getattr(self, '_grpc_indicators', [])
        code_discovered_urls = getattr(self, '_code_discovered_urls', [])
        method_probe_map = getattr(self, '_method_probe_map', {})

        # Build vulnerability summary
        vuln_by_type = {}
        vuln_by_severity = {}
        for v in self.vulnerabilities:
            vtype = v.get('vuln_type', 'Unknown')
            vsev = v.get('severity', 'Medium')
            vuln_by_type[vtype] = vuln_by_type.get(vtype, 0) + 1
            vuln_by_severity[vsev] = vuln_by_severity.get(vsev, 0) + 1

        self._log_scan('info', f'Crawl complete: {len(deduplicated_endpoints)} endpoints, {len(self.forms)} forms, {len(all_params)} parameters', {
            'endpoints': len(deduplicated_endpoints),
            'forms': len(self.forms),
            'parameters': len(all_params),
            'vulnerabilities': len(self.vulnerabilities),
        })

        return {
            "summary": {
                "endpoints_found": len(deduplicated_endpoints),
                "forms_found": len(self.forms),
                "input_points_found": len(self.input_points),
                "parameters_found": len(all_params),
                "js_urls_found": len(self._js_urls),
                "xhr_urls_captured": len(self._xhr_urls),
                "credential_hints_found": len(html_hints.get('credentials', [])),
                "data_attributes_found": len(data_attributes),
                "dynamic_patterns_found": len(dynamic_url_patterns),
                "websocket_endpoints_found": len(websocket_endpoints),
                "storage_keys_found": len(browser_storage.get('localStorage', [])) + len(browser_storage.get('sessionStorage', [])),
                "event_listeners_found": len(event_listeners),
                "openapi_specs_found": len(openapi_specs),
                "graphql_endpoints_found": len(graphql_endpoints),
                "graphql_schemas_found": len(graphql_schemas),
                "grpc_indicators_found": len(grpc_indicators),
                "code_discovered_urls_found": len(code_discovered_urls),
                "sitemap_urls_found": len(getattr(self, '_sitemap_urls', [])),
                "robots_paths_found": len(getattr(self, '_robots_data', {}).get('disallowed_paths', [])),
                "json_endpoint_urls_found": len(getattr(self, '_json_discovered_urls', [])),
                "method_probe_targets": len(method_probe_map),
                "vulnerabilities_found": len(self.vulnerabilities),
            },
            "endpoints": deduplicated_endpoints,
            "forms": self.forms,
            "input_points": self.input_points,
            "parameters": self.parameters,
            "detected_parameters": all_params,
            "hidden_fields": self.hidden_fields,
            "file_uploads": self.file_uploads,
            "cookies": self.cookies,
            "js_discovered_urls": list(self._js_urls),
            "xhr_captured_urls": list(self._xhr_urls),
            "api_endpoints": self._api_endpoints,
            "html_hints": html_hints,
            "data_attributes": data_attributes,
            "dynamic_url_patterns": dynamic_url_patterns,
            "websocket_endpoints": websocket_endpoints,
            "browser_storage": browser_storage,
            "event_listeners": event_listeners,
            "openapi_specs": openapi_specs,
            "graphql_endpoints": graphql_endpoints,
            "graphql_schemas": graphql_schemas,
            "grpc_indicators": grpc_indicators,
            "code_discovered_urls": code_discovered_urls,
            "sitemap_urls": getattr(self, '_sitemap_urls', []),
            "robots_data": getattr(self, '_robots_data', {}),
            "json_discovered_urls": getattr(self, '_json_discovered_urls', []),
            "method_probes": method_probe_map,
            "manual_snapshots": self._manual_snapshots,
            "proxy_logs": self._proxy_logs,
            "vulnerabilities": self.vulnerabilities,
            "scan_summary": {
                "total_scanned": len(self._scanned_points),
                "vulnerabilities_found": len(self.vulnerabilities),
                "by_type": vuln_by_type,
                "by_severity": vuln_by_severity,
            },
        }
