"""
MCP Server for DAST tools — runs as a stdio MCP server that Claude Code can connect to.
Exposes all DAST tools (authenticate, send_request, browser, callback, etc.)
"""
import json
import sys
import os

# Diagnostic log — helps debug MCP connection issues. Written to file, never stdout.
_DIAG_LOG = os.environ.get('DAST_MCP_DEBUG_LOG')
def _diag(msg):
    if not _DIAG_LOG:
        return
    try:
        import time as _t
        with open(_DIAG_LOG, 'a') as f:
            f.write(f"[{_t.strftime('%H:%M:%S')}] pid={os.getpid()} {msg}\n")
    except Exception:
        pass

_diag("mcp_server.py: starting")
_diag(f"cwd={os.getcwd()}")
_diag(f"argv={sys.argv}")
_diag(f"python={sys.executable}")

# Add current dir for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_diag(f"sys.path[0]={sys.path[0]}")

try:
    from mcp.server.stdio import stdio_server
    from mcp.server import Server
    from mcp import types
    _diag("mcp package imported OK")
except Exception as e:
    _diag(f"FATAL: mcp import failed: {e!r}")
    raise

# --- stdin byte sniffer ---
# Wraps sys.stdin.buffer so we log every byte claude sends us. Useful to prove
# whether the MCP handshake even reaches our server.
if _DIAG_LOG:
    try:
        _original_stdin_read = sys.stdin.buffer.read
        _original_stdin_readline = sys.stdin.buffer.readline
        def _sniff_read(n=-1):
            data = _original_stdin_read(n)
            _diag(f"stdin.read({n}) -> {len(data)} bytes: {data[:200]!r}")
            return data
        def _sniff_readline(limit=-1):
            data = _original_stdin_readline(limit)
            _diag(f"stdin.readline() -> {len(data)} bytes: {data[:200]!r}")
            return data
        sys.stdin.buffer.read = _sniff_read
        sys.stdin.buffer.readline = _sniff_readline
        _diag("stdin sniffer installed")
    except Exception as e:
        _diag(f"stdin sniffer install failed: {e!r}")

try:
    from agent import (
        _scan_state, _log, _get_session, _get_browser, _close_browser,
    )
    _diag("agent import OK")
except Exception as e:
    _diag(f"FATAL: agent import failed: {e!r}")
    raise

app = Server("dast-tools")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _text_result(text):
    return [types.TextContent(type="text", text=text)]


def _run_async(coro):
    """Run an async function synchronously."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

@app.list_tools()
async def list_tools():
    return [
        types.Tool(
            name="authenticate",
            description="Log in to the target application to get an authenticated session. Handles CSRF tokens automatically.",
            inputSchema={
                "type": "object",
                "properties": {
                    "login_url": {"type": "string", "description": "Login page URL"},
                    "username": {"type": "string", "description": "Username"},
                    "password": {"type": "string", "description": "Password"},
                },
                "required": ["login_url", "username", "password"],
            },
        ),
        types.Tool(
            name="get_crawl_results",
            description="Get previously crawled endpoints, forms, and parameters.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_baseline",
            description="Get the baseline response for a specific URL for comparison with attack responses.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to get baseline for"},
                    "method": {"type": "string", "description": "HTTP method (default GET)"},
                },
                "required": ["url"],
            },
        ),
        types.Tool(
            name="send_request",
            description="Send an HTTP request with a specific payload to test for vulnerabilities. Returns full response for analysis.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "method": {"type": "string", "description": "HTTP method (GET/POST)"},
                    "param": {"type": "string", "description": "Parameter name to inject payload into"},
                    "payload": {"type": "string", "description": "Payload value to send"},
                },
                "required": ["url", "method", "param", "payload"],
            },
        ),
        types.Tool(
            name="report_finding",
            description="Report a confirmed vulnerability with evidence. Only report CONFIRMED findings.",
            inputSchema={
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "Vulnerability type (sqli, xss, cmdi, ssti, lfi, etc.)"},
                    "severity": {"type": "string", "description": "Severity: critical, high, medium, low"},
                    "url": {"type": "string", "description": "Vulnerable URL"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "parameter": {"type": "string", "description": "Vulnerable parameter name"},
                    "payload": {"type": "string", "description": "Payload that exploited the vulnerability"},
                    "evidence": {"type": "string", "description": "What in the response proves exploitation"},
                    "request": {"type": "string", "description": "Full HTTP request sent"},
                    "curl_command": {"type": "string", "description": "Copy-paste curl command that reproduces the proof"},
                    "response_preview": {"type": "string", "description": "Relevant response body showing the vulnerability"},
                    "baseline_diff": {"type": "string", "description": "What changed compared to baseline"},
                    "risk_reasoning": {"type": "string", "description": "Why this is a security risk — explain the impact on confidentiality, integrity, or availability"},
                    "attack_narrative": {"type": "string", "description": "Realistic exploit scenario starting with 'An attacker could...'"},
                    "confidence": {"type": "string", "description": "confirmed (exploitation verified), likely (strong evidence), possible (needs verification)"},
                    "false_positive_risk": {"type": "string", "description": "False positive risk: low, medium, high"},
                },
                "required": ["vuln_type", "severity", "url", "method", "parameter", "payload", "evidence"],
            },
        ),
        types.Tool(
            name="get_scan_status",
            description="Get current scan progress — findings count and tests run.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="generate_callback",
            description="Generate a unique callback URL for blind SSRF/XXE/RCE testing. Returns a URL that logs any incoming request.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="check_callback",
            description="Check if a callback URL was hit by the target server. Confirms blind SSRF/XXE/RCE.",
            inputSchema={
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "The callback token from generate_callback"},
                },
                "required": ["token"],
            },
        ),
        types.Tool(
            name="browser_navigate",
            description="Navigate the browser to a URL and return the rendered page content, links, and forms.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to navigate to"},
                },
                "required": ["url"],
            },
        ),
        types.Tool(
            name="browser_click",
            description="Click an element on the page by CSS selector or text content.",
            inputSchema={
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector to click"},
                    "text": {"type": "string", "description": "Text content of element to click"},
                },
            },
        ),
        types.Tool(
            name="browser_fill_form",
            description="Fill form fields and submit. Fields is a JSON string of {field_name: value} pairs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "fields": {"type": "string", "description": "JSON string of {field_name: value} pairs"},
                    "submit_selector": {"type": "string", "description": "CSS selector for submit button"},
                },
                "required": ["fields"],
            },
        ),
        types.Tool(
            name="browser_get_page",
            description="Get the current browser page content, URL, and visible text.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="browser_js",
            description="Execute JavaScript in the browser and return the result.",
            inputSchema={
                "type": "object",
                "properties": {
                    "script": {"type": "string", "description": "JavaScript code to execute"},
                },
                "required": ["script"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Tool handlers — import and delegate to agent.py handlers
# ---------------------------------------------------------------------------

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    """Route tool calls to the appropriate handler in agent.py."""
    from agent import (
        authenticate, get_crawl_results, get_baseline,
        send_request, report_finding, get_scan_status,
        generate_callback, check_callback,
        browser_navigate, browser_click, browser_fill_form,
        browser_get_page, browser_js,
    )

    handler_map = {
        'authenticate': authenticate,
        'get_crawl_results': get_crawl_results,
        'get_baseline': get_baseline,
        'send_request': send_request,
        'report_finding': report_finding,
        'get_scan_status': get_scan_status,
        'generate_callback': generate_callback,
        'check_callback': check_callback,
        'browser_navigate': browser_navigate,
        'browser_click': browser_click,
        'browser_fill_form': browser_fill_form,
        'browser_get_page': browser_get_page,
        'browser_js': browser_js,
    }

    handler = handler_map.get(name)
    if not handler:
        return _text_result(f"Unknown tool: {name}")

    try:
        result = await handler(arguments)

        # Extract text from MCP-style response
        if isinstance(result, dict) and 'content' in result:
            texts = []
            for block in result['content']:
                if block.get('type') == 'text':
                    texts.append(block['text'])
            return _text_result('\n'.join(texts))
        return _text_result(json.dumps(result, default=str))
    except Exception as e:
        return _text_result(f"Tool error: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    _diag("entering stdio_server context")
    async with stdio_server() as (read_stream, write_stream):
        _diag("stdio_server ready, calling app.run")
        try:
            await app.run(read_stream, write_stream, app.create_initialization_options())
            _diag("app.run returned normally")
        except Exception as e:
            _diag(f"app.run raised: {e!r}")
            raise


if __name__ == "__main__":
    import asyncio
    _diag("calling asyncio.run(main())")
    try:
        asyncio.run(main())
    except Exception as e:
        _diag(f"top-level exception: {e!r}")
        raise
    finally:
        _diag("process exiting")
