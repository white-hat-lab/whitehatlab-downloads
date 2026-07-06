# -*- coding: utf-8 -*-
# burp_extension.py -- DAST-CLI Bridge for Burp Suite
#
# HOW TO LOAD:
#   1. Burp > Extender > Options > Python Environment > set Jython standalone JAR
#   2. Burp > Extender > Extensions > Add > Type: Python > select this file
#
# Starts a REST API on http://127.0.0.1:8090 that burp_mcp_server.py connects to.
#
# Endpoints:
#   GET  /health               -- check extension is alive
#   GET  /proxy/history        -- proxy history (?limit=N&url=filter&method=GET&status=200)
#   GET  /sitemap              -- site map (?host=example.com)
#   GET  /scanner/issues       -- passive/active scanner findings
#   POST /send                 -- send HTTP request through Burp, get response
#   GET  /scope                -- check if a URL is in scope (?url=...)
#   POST /scope/add            -- add URL to target scope  {"url": "https://..."}
#   POST /scan/active          -- trigger active scan     {"url": "https://..."}
#   GET  /search               -- search proxy history    (?q=token&in=all|request|response&limit=50)
#   GET  /repeater/tabs        -- list repeater tab names

from burp import IBurpExtender, IProxyListener, IScannerListener

import BaseHTTPServer
import SocketServer
import threading
import json
import sys
import traceback
from urlparse import urlparse, parse_qs

BRIDGE_PORT = 8090


# ---------------------------------------------------------------------------
# Extension entry point
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, IProxyListener, IScannerListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._out = callbacks.getStdout()
        self._err = callbacks.getStderr()
        self._scanner_issues = []

        callbacks.setExtensionName("DAST-CLI Bridge")
        callbacks.registerProxyListener(self)
        callbacks.registerScannerListener(self)

        self._start_bridge()
        self._print("DAST-CLI Bridge started on http://127.0.0.1:%d" % BRIDGE_PORT)

    def processProxyMessage(self, messageIsRequest, message):
        pass  # history is read via getProxyHistory(); no tracking needed here

    def newScanIssue(self, issue):
        self._scanner_issues.append(issue)

    def _print(self, msg):
        try:
            self._out.write((msg + "\n").encode("utf-8"))
        except Exception:
            pass

    def _start_bridge(self):
        ext = self

        class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass  # silence access log

            def do_GET(self):
                self.body_bytes = b""
                self._dispatch()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                self.body_bytes = self.rfile.read(length) if length > 0 else b""
                self._dispatch()

            def _dispatch(self):
                parsed = urlparse(self.path)
                path = parsed.path
                params = parse_qs(parsed.query)
                body_json = {}
                if self.body_bytes:
                    try:
                        body_json = json.loads(self.body_bytes.decode("utf-8"))
                    except Exception:
                        pass
                try:
                    result = route(path, params, body_json,
                                   ext._callbacks, ext._helpers, ext._scanner_issues)
                    self._respond(200, result)
                except Exception as e:
                    ext._print("Bridge error: " + traceback.format_exc())
                    self._respond(500, {"error": str(e)})

            def _respond(self, code, data):
                payload = json.dumps(data, default=str).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        class ThreadedServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
            daemon_threads = True

        server = ThreadedServer(("127.0.0.1", BRIDGE_PORT), Handler)
        t = threading.Thread(target=server.serve_forever)
        t.setDaemon(True)
        t.start()


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

def route(path, params, body, cb, helpers, scanner_issues):
    if path == "/health":
        return {"status": "ok", "extension": "DAST-CLI Bridge", "port": BRIDGE_PORT}

    elif path == "/proxy/history":
        return get_proxy_history(cb, helpers, params)

    elif path == "/sitemap":
        host = _param(params, "host")
        return get_sitemap(cb, helpers, host)

    elif path == "/scanner/issues":
        return get_scanner_issues(scanner_issues, helpers)

    elif path == "/send":
        return send_request(body, cb, helpers)

    elif path == "/scope":
        url = _param(params, "url")
        return check_scope(url, cb)

    elif path == "/scope/add":
        return add_to_scope(body, cb)

    elif path == "/scan/active":
        return start_active_scan(body, cb, helpers)

    elif path == "/search":
        return search_history(params, cb, helpers)

    else:
        return {"error": "Unknown endpoint: " + path}


def _param(params, key, default=None):
    vals = params.get(key, [])
    return vals[0] if vals else default


def _int_param(params, key, default):
    try:
        return int(_param(params, key, default))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def _serialize_message(cb, helpers, item):
    """Convert IHttpRequestResponse to a plain dict."""
    try:
        req = item.getRequest()
        resp = item.getResponse()
        service = item.getHttpService()

        req_info = helpers.analyzeRequest(item)
        url = str(req_info.getUrl())
        method = str(req_info.getMethod())
        req_headers = [str(h) for h in req_info.getHeaders()]

        body_offset = req_info.getBodyOffset()
        req_body = helpers.bytesToString(req[body_offset:]) if req else ""

        out = {
            "url": url,
            "method": method,
            "host": str(service.getHost()) if service else "",
            "port": service.getPort() if service else 0,
            "protocol": str(service.getProtocol()) if service else "",
            "request_headers": req_headers,
            "request_body": req_body[:2048],
        }

        if resp:
            resp_info = helpers.analyzeResponse(resp)
            resp_body_offset = resp_info.getBodyOffset()
            resp_body = helpers.bytesToString(resp[resp_body_offset:])
            out["status_code"] = resp_info.getStatusCode()
            out["response_headers"] = [str(h) for h in resp_info.getHeaders()]
            out["response_body"] = resp_body[:4096]
            out["response_length"] = len(resp)

        return out
    except Exception as e:
        return {"error": str(e)}


def get_proxy_history(cb, helpers, params):
    history = list(cb.getProxyHistory())
    total = len(history)
    limit = _int_param(params, "limit", 100)
    # after_index: only return items added AFTER this absolute index (0-based).
    # Use this to implement "clear" without touching Burp's internal storage.
    after_index = _int_param(params, "after_index", 0)
    url_filter = _param(params, "url")
    method_filter = (_param(params, "method") or "").upper() or None
    status_filter = _param(params, "status")

    # Only consider history entries after the clear watermark
    visible_history = history[after_index:] if after_index > 0 else history

    # Walk newest-first
    items = []
    for item in reversed(visible_history):
        if len(items) >= limit:
            break
        try:
            s = _serialize_message(cb, helpers, item)
            if url_filter and url_filter.lower() not in s.get("url", "").lower():
                continue
            if method_filter and s.get("method", "").upper() != method_filter:
                continue
            if status_filter and str(s.get("status_code", "")) != status_filter:
                continue
            items.append(s)
        except Exception:
            pass

    return {"count": len(items), "total_in_history": total, "visible_total": len(visible_history), "items": items}


def get_sitemap(cb, helpers, host_filter):
    try:
        prefix = host_filter if host_filter else None
        entries = list(cb.getSiteMap(prefix))
        urls = []
        for entry in entries[:500]:
            try:
                req_info = helpers.analyzeRequest(entry)
                url = str(req_info.getUrl())
                method = str(req_info.getMethod())
                status = 0
                if entry.getResponse():
                    status = helpers.analyzeResponse(entry.getResponse()).getStatusCode()
                urls.append({"url": url, "method": method, "status": status})
            except Exception:
                pass
        return {"count": len(urls), "urls": urls}
    except Exception as e:
        return {"error": str(e)}


def get_scanner_issues(issues, helpers):
    result = []
    for issue in issues:
        try:
            result.append({
                "issue_name": str(issue.getIssueName()),
                "severity": str(issue.getSeverity()),
                "confidence": str(issue.getConfidence()),
                "url": str(issue.getUrl()),
                "detail": str(issue.getIssueDetail() or ""),
                "background": str(issue.getIssueBackground() or ""),
                "remediation_detail": str(issue.getRemediationDetail() or ""),
            })
        except Exception:
            pass
    return {"count": len(result), "issues": result}


def send_request(body, cb, helpers):
    """Build and fire an HTTP request through Burp; return the response."""
    try:
        url_str = body.get("url", "")
        if not url_str:
            return {"error": "url is required"}

        method = body.get("method", "GET").upper()
        extra_headers = body.get("headers", {})
        req_body = body.get("body", "")

        from java.net import URL
        java_url = URL(url_str)
        host = str(java_url.getHost())
        port = java_url.getPort()
        protocol = str(java_url.getProtocol()).lower()
        if port == -1:
            port = 443 if protocol == "https" else 80
        use_https = (protocol == "https")

        service = helpers.buildHttpService(host, port, use_https)

        path = str(java_url.getPath()) or "/"
        if java_url.getQuery():
            path += "?" + str(java_url.getQuery())

        req_headers = [
            "%s %s HTTP/1.1" % (method, path),
            "Host: " + host,
            "Connection: close",
        ]
        for k, v in extra_headers.items():
            req_headers.append("%s: %s" % (k, v))

        req_bytes = helpers.buildHttpMessage(req_headers, helpers.stringToBytes(req_body))
        response_obj = cb.makeHttpRequest(service, req_bytes)
        resp = response_obj.getResponse()

        if resp:
            resp_info = helpers.analyzeResponse(resp)
            body_offset = resp_info.getBodyOffset()
            return {
                "status_code": resp_info.getStatusCode(),
                "headers": [str(h) for h in resp_info.getHeaders()],
                "body": helpers.bytesToString(resp[body_offset:])[:8192],
                "length": len(resp),
            }
        return {"error": "No response received"}
    except Exception as e:
        return {"error": str(e), "traceback": traceback.format_exc()}


def check_scope(url_str, cb):
    try:
        if not url_str:
            return {"error": "url parameter required"}
        from java.net import URL
        java_url = URL(url_str)
        in_scope = bool(cb.isInScope(java_url))
        return {"url": url_str, "in_scope": in_scope}
    except Exception as e:
        return {"error": str(e)}


def add_to_scope(body, cb):
    try:
        url_str = body.get("url", "")
        if not url_str:
            return {"error": "url is required"}
        from java.net import URL
        cb.includeInScope(URL(url_str))
        return {"status": "ok", "url": url_str, "action": "included in scope"}
    except Exception as e:
        return {"error": str(e)}


def start_active_scan(body, cb, helpers):
    try:
        url_str = body.get("url", "")
        if not url_str:
            return {"error": "url is required"}
        from java.net import URL
        java_url = URL(url_str)
        host = str(java_url.getHost())
        port = java_url.getPort()
        protocol = str(java_url.getProtocol()).lower()
        if port == -1:
            port = 443 if protocol == "https" else 80
        use_https = (protocol == "https")
        path = str(java_url.getPath()) or "/"
        if java_url.getQuery():
            path += "?" + str(java_url.getQuery())

        seed_req = helpers.stringToBytes(
            "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, host)
        )
        cb.doActiveScan(host, port, use_https, seed_req)
        return {"status": "active scan started", "url": url_str}
    except Exception as e:
        return {"error": str(e)}


def search_history(params, cb, helpers):
    q = _param(params, "q")
    if not q:
        return {"error": "q parameter required"}

    search_in = _param(params, "in", "all")
    limit = _int_param(params, "limit", 50)

    history = list(cb.getProxyHistory())
    matches = []

    for item in reversed(history):
        if len(matches) >= limit:
            break
        try:
            req = item.getRequest()
            resp = item.getResponse()
            req_str = helpers.bytesToString(req) if req else ""
            # Only read first 8KB of response to avoid OOM on large responses
            resp_str = helpers.bytesToString(resp[:8192]) if resp else ""

            q_lower = q.lower()
            in_req = q_lower in req_str.lower()
            in_resp = q_lower in resp_str.lower()

            hit = (search_in == "request" and in_req) or \
                  (search_in == "response" and in_resp) or \
                  (search_in == "all" and (in_req or in_resp))

            if hit:
                matches.append(_serialize_message(cb, helpers, item))
        except Exception:
            pass

    return {"query": q, "in": search_in, "count": len(matches), "items": matches}
