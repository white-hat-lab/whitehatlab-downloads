#!/usr/bin/env python3
"""
WhiteHatLabs CLI

A production CLI for web application pentesting workflows.
Wired into the real crawler, agent, report generator, and database modules.

Commands:
  - scan   : start a new assessment
  - resume : resume a previous assessment
  - report : build a report from saved results
  - status : inspect a saved scan state

Usage:
  python whitehatlabs_cli.py scan https://target.com
  python whitehatlabs_cli.py status <scan_id>
  python whitehatlabs_cli.py report <scan_id> --format docx
  python whitehatlabs_cli.py resume <scan_id>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Real modules from the DAST codebase
from crawler import crawl
from agent import run_agent
from report_generator import generate_docx_report
import db


APP_NAME = "whitehatlabs"
# DAST-CLI uses an isolated data dir from ec2_DAST. Override via WHITELABS_DATA_DIR env var.
DEFAULT_DATA_DIR = Path(os.environ.get('WHITELABS_DATA_DIR') or str(Path.home() / ".whitehatlabs-cli"))
DEFAULT_SCANS_DIR = DEFAULT_DATA_DIR / "scans"
DEFAULT_OUTPUT_DIR = Path.cwd()


# -----------------------------
# Utilities
# -----------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def read_json(path: Path, default: Optional[Any] = None) -> Any:
    if not path.exists():
        return {} if default is None else default
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def normalize_target(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("target cannot be empty")
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    return value.rstrip("/")


def parse_targets(args_targets: List[str], file_path: Optional[str]) -> List[str]:
    targets: List[str] = []
    for item in args_targets:
        item = item.strip()
        if item:
            targets.append(normalize_target(item))

    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(normalize_target(line))

    deduped = list(dict.fromkeys(targets))
    if not deduped:
        raise ValueError("no targets provided")
    return deduped


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def cli_progress(phase: str, message: str) -> None:
    timestamp = datetime.now().strftime('%H:%M:%S')
    eprint(f"[{timestamp}] [{phase}] {message}")


# -----------------------------
# Data models
# -----------------------------

@dataclass
class ScanConfig:
    targets: List[str]
    scan_id: str
    created_at: str
    batch_size: int = 10
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    login_url: Optional[str] = None
    provider: str = "claude-code"
    verify_tls: bool = True
    # Browser crawling is disabled by default for CLI scans. Keep `headless`
    # for backward compatibility with existing scan config JSON files.
    browser_crawl: bool = False
    headless: bool = False
    max_urls: Optional[int] = None
    max_depth: Optional[int] = None
    max_pages: int = 200
    timeout: int = 120
    output_dir: str = ""
    notes: Optional[str] = None


@dataclass
class ScanState:
    scan_id: str
    status: str
    created_at: str
    updated_at: str
    targets: List[str]
    urls_collected: List[str]
    urls_hit: List[str]
    expected_tests: List[Dict[str, Any]]
    coverage: Dict[str, Any]
    coverage_summary: Dict[str, Any]
    finding_dedup: List[str]
    findings: List[Dict[str, Any]]
    errors: List[str]
    crawl_results: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)
    # Shared scratch space written by agent.py / dast_tool.py during execution.
    # Kept here so ScanState round-trips cleanly through save_state → load_state.
    baselines: Dict[str, Any] = field(default_factory=dict)
    auth: Dict[str, Any] = field(default_factory=dict)
    callbacks: Dict[str, Any] = field(default_factory=dict)
    target_url: str = ''
    batch_progress: Any = None
    attack_chains: List[Dict[str, Any]] = field(default_factory=list)
    checklist_coverage: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanState':
        """Construct a ScanState, silently ignoring unknown fields in the JSON.
        Forward-compat: state files produced by a newer agent won't crash the loader.
        """
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


# -----------------------------
# Storage (JSON file persistence)
# -----------------------------

class ScanStore:
    def __init__(self, base_dir: Path = DEFAULT_SCANS_DIR) -> None:
        self.base_dir = ensure_dir(base_dir)

    def scan_dir(self, scan_id: str) -> Path:
        return ensure_dir(self.base_dir / scan_id)

    def config_path(self, scan_id: str) -> Path:
        return self.scan_dir(scan_id) / "config.json"

    def state_path(self, scan_id: str) -> Path:
        return self.scan_dir(scan_id) / "state.json"

    def findings_path(self, scan_id: str) -> Path:
        return self.scan_dir(scan_id) / "findings.json"

    def save_config(self, config: ScanConfig) -> None:
        write_json(self.config_path(config.scan_id), asdict(config))

    def load_config(self, scan_id: str) -> ScanConfig:
        data = read_json(self.config_path(scan_id))
        return ScanConfig(**data)

    def save_state(self, state: ScanState) -> None:
        write_json(self.state_path(state.scan_id), asdict(state))
        write_json(self.findings_path(state.scan_id), state.findings)

    def load_state(self, scan_id: str) -> ScanState:
        data = read_json(self.state_path(scan_id))
        return ScanState.from_dict(data)


# -----------------------------
# Real Scanner (wraps crawler.py)
# -----------------------------

class ScannerEngine:
    """Wraps the real headless crawler to discover attack surface."""

    def collect_attack_surface(self, config: ScanConfig) -> Dict[str, Any]:
        """Crawl all targets and merge results."""
        merged: Dict[str, Any] = {
            'endpoints': [],
            'forms': [],
            'params': [],
            'baselines': {},
            'links': [],
            'js_urls': [],
            'xhr_urls': [],
            'canary_results': [],
        }

        seen_endpoints = set()

        for target in config.targets:
            eprint(f"[crawl] crawling {target} ...")
            try:
                result = crawl(
                    target_url=target,
                    max_pages=config.max_pages if config.max_urls is None else config.max_urls,
                    depth=config.max_depth or 5,
                    timeout=config.timeout,
                    username=config.auth_username,
                    password=config.auth_password,
                    login_url=config.login_url,
                    enable_browser=config.browser_crawl,
                    progress_cb=cli_progress,
                )
            except Exception as exc:
                eprint(f"[crawl] failed on {target}: {exc}")
                # Fallback: just the target URL itself
                result = {
                    'endpoints': [{'url': target, 'method': 'GET'}],
                    'forms': [], 'params': [], 'baselines': {},
                    'links': [], 'js_urls': [], 'xhr_urls': [],
                    'canary_results': [],
                }

            # Merge endpoints (dedup by method+url)
            for ep in result.get('endpoints', []):
                key = f"{ep.get('method', 'GET')} {ep.get('url', '')}"
                if key not in seen_endpoints:
                    seen_endpoints.add(key)
                    merged['endpoints'].append(ep)

            merged['forms'].extend(result.get('forms', []))
            merged['params'].extend(result.get('params', []))
            merged['baselines'].update(result.get('baselines', {}))
            merged['links'].extend(result.get('links', []))
            merged['js_urls'].extend(result.get('js_urls', []))
            merged['xhr_urls'].extend(result.get('xhr_urls', []))
            merged['canary_results'].extend(result.get('canary_results', []))

        # Apply max_urls limit if set
        if config.max_urls is not None:
            merged['endpoints'] = merged['endpoints'][:config.max_urls]

        urls = [ep.get('url', '') for ep in merged['endpoints']]
        eprint(f"[crawl] done — {len(merged['endpoints'])} endpoints, "
               f"{len(merged['forms'])} forms, {len(merged['params'])} params")

        return {
            'targets': config.targets,
            'urls': list(dict.fromkeys(urls)),
            'crawl_results': merged,
        }


# -----------------------------
# Real Agent (wraps agent.py)
# -----------------------------

class AgentRunner:
    """Wraps the real Claude Code agent for vulnerability testing."""

    def run(
        self,
        config: ScanConfig,
        crawl_results: Dict[str, Any],
        scan_id: str,
        resume: bool = False,
    ) -> Dict[str, Any]:
        """Run the agent. Returns dict with findings, logs, urls_hit."""

        # Build credentials dict if auth is configured
        credentials = None
        if config.auth_username and config.auth_password:
            credentials = {
                'username': config.auth_username,
                'password': config.auth_password,
                'login_url': config.login_url or config.targets[0] + '/login',
            }

        target_url = config.targets[0]
        baselines = crawl_results.get('baselines', {})

        eprint(f"[agent] starting on {target_url} (provider: {config.provider})")

        # run_agent is async — bridge with asyncio.run()
        findings, logs = asyncio.run(run_agent(
            target_url=target_url,
            crawl_results=crawl_results,
            baselines=baselines,
            max_turns=100,
            credentials=credentials,
            scan_id=scan_id,
            resume_context=True if resume else None,
        ))

        urls_hit = list({f.get('url', '') for f in findings if f.get('url')})

        eprint(f"[agent] done — {len(findings)} findings, {len(logs)} log entries")

        return {
            'findings': findings,
            'logs': logs,
            'urls_hit': urls_hit,
        }


# -----------------------------
# Report builder
# -----------------------------

def build_markdown_report(state: ScanState) -> str:
    """Quick markdown report for terminal output."""
    sev_counts: Dict[str, int] = {}
    for finding in state.findings:
        sev = str(finding.get("severity", "unknown")).upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    lines: List[str] = []
    lines.append(f"# WhiteHatLabs Report - {state.scan_id}")
    lines.append("")
    lines.append(f"- Status: {state.status}")
    lines.append(f"- Created: {state.created_at}")
    lines.append(f"- Updated: {state.updated_at}")
    lines.append(f"- Targets: {', '.join(state.targets)}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    if sev_counts:
        for sev, count in sorted(sev_counts.items()):
            lines.append(f"- {sev}: {count}")
    else:
        lines.append("- No findings recorded")
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    for key, value in state.coverage_summary.items():
        lines.append(f"- {key}: {value}")
    if state.checklist_coverage:
        lines.append("")
        lines.append("### Dynamic Coverage Ledger")
        for row in state.checklist_coverage[:100]:
            status = str(row.get("status", "")).replace("_", " ")
            category = row.get("category") or row.get("area") or "coverage"
            subcategory = row.get("subcategory") or ""
            label = f"{category} / {subcategory}" if subcategory else category
            target = f"{row.get('method', 'GET')} {row.get('url', '')}"
            reason = row.get("reason") or ""
            lines.append(f"- **{status}** `{target}` - {label}: {reason}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    if not state.findings:
        lines.append("No findings.")
    else:
        for finding in state.findings:
            fid = finding.get('id', finding.get('finding_id', 'N/A'))
            lines.append(f"### {fid} - {finding.get('vuln_type', 'unknown')}")
            lines.append("")
            lines.append(f"- Severity: {finding.get('severity', 'unknown')}")
            lines.append(f"- Proof Status: {finding.get('proof_status', 'unverified_hypothesis')}")
            lines.append(f"- Confidence: {finding.get('confidence', 'unknown')}")
            lines.append(f"- URL: {finding.get('url', 'N/A')}")
            lines.append(f"- Method: {finding.get('method', 'N/A')}")
            lines.append(f"- Parameter: {finding.get('parameter', 'N/A')}")
            lines.append(f"- Payload: {finding.get('payload', 'N/A')}")
            lines.append("")
            lines.append("**Evidence**")
            lines.append("")
            evidence = finding.get('evidence', '')
            if isinstance(evidence, list):
                evidence = '; '.join(evidence)
            lines.append(str(evidence))
            lines.append("")

    return "\n".join(lines)


def build_docx_report(state: ScanState, output_path: Path) -> Path:
    """Generate a professional DOCX report using report_generator.py."""
    scan_data = {
        'id': state.scan_id,
        'target_url': state.targets[0] if state.targets else 'unknown',
        'started_at': state.created_at,
        'ended_at': state.updated_at,
        'status': state.status,
        'crawl_results': state.crawl_results,
    }

    # Build proxy entries from crawl endpoints for the appendix
    proxy_entries = []
    for ep in state.crawl_results.get('endpoints', []):
        proxy_entries.append({
            'method': ep.get('method', 'GET'),
            'url': ep.get('url', ''),
            'status': 0,
            'length': 0,
            'tested': 1 if ep.get('url', '') in {f.get('url') for f in state.findings} else 0,
        })

    buffer = generate_docx_report(scan_data, state.findings, proxy_entries)
    output_path.write_bytes(buffer.getvalue())
    return output_path


# -----------------------------
# Dedup helper
# -----------------------------

def dedup_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate findings by vuln_type + url + parameter."""
    seen: set = set()
    result: List[Dict[str, Any]] = []
    for f in findings:
        key = (
            f.get('vuln_type', ''),
            f.get('url', ''),
            f.get('parameter', ''),
        )
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def ensure_claude_cli_auth() -> Optional[str]:
    """Return an error message if Claude CLI is unavailable or unauthenticated."""
    try:
        from agent import _get_claude_cli, _claude_cli_env
    except Exception as exc:
        return f"Claude CLI integration unavailable: {exc}"

    try:
        import subprocess as _sp
        claude_cli = _get_claude_cli()
        result = _sp.run(
            [claude_cli, '-p', 'hi', '--output-format', 'json', '--model', 'haiku', '--dangerously-skip-permissions'],
            capture_output=True,
            text=True,
            timeout=20,
            stdin=_sp.DEVNULL,
            env=_claude_cli_env(),
        )
        out = (result.stdout or '').strip()
        low = ((result.stderr or '') + '\n' + out).lower()
        if result.returncode != 0 or any(x in low for x in ('authentication_error', 'invalid authentication credentials', 'invalid api key', 'external api key')):
            return (
                "Claude authentication failed. Run:\n"
                f"  \"{claude_cli}\" logout\n"
                f"  \"{claude_cli}\" login"
            )
    except Exception as exc:
        return f"Claude CLI check failed: {exc}"
    return None


# -----------------------------
# Commands
# -----------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    auth_err = ensure_claude_cli_auth()
    if auth_err:
        eprint(f"error: {auth_err}")
        return 2

    try:
        targets = parse_targets(args.targets, args.targets_file)
    except Exception as exc:
        eprint(f"error: {exc}")
        return 2

    scan_id = args.scan_id or uuid.uuid4().hex[:16]
    store = ScanStore(Path(args.data_dir) / "scans")

    config = ScanConfig(
        targets=targets,
        scan_id=scan_id,
        created_at=utc_now_iso(),
        batch_size=args.batch_size,
        auth_username=args.auth_username,
        auth_password=args.auth_password,
        login_url=args.login_url,
        provider=args.provider,
        verify_tls=not args.insecure,
        browser_crawl=args.browser_crawl,
        max_urls=args.max_urls,
        max_depth=args.max_depth,
        max_pages=args.max_urls or 200,
        timeout=args.timeout,
        output_dir=str(Path(args.output_dir).resolve()),
        notes=args.notes,
    )
    store.save_config(config)

    state = ScanState(
        scan_id=scan_id,
        status="running",
        created_at=config.created_at,
        updated_at=config.created_at,
        targets=targets,
        urls_collected=[],
        urls_hit=[],
        expected_tests=[],
        coverage={},
        coverage_summary={},
        finding_dedup=[],
        findings=[],
        errors=[],
        crawl_results={},
        logs=[],
    )

    # Init DB for agent persistence
    db.init_db()
    db.create_project(
        scan_id=scan_id,
        target_url=targets[0],
        provider=config.provider,
        auth_username=config.auth_username,
        auth_password=config.auth_password,
        auth_login_url=config.login_url,
    )

    store.save_state(state)

    print(f"[scan] starting scan {scan_id}")
    print(f"[scan] targets: {', '.join(targets)}")

    try:
        # Phase 1: CRAWL
        state.status = "crawling"
        state.updated_at = utc_now_iso()
        store.save_state(state)

        scanner = ScannerEngine()
        surface = scanner.collect_attack_surface(config)

        state.urls_collected = surface['urls']
        state.crawl_results = surface['crawl_results']
        state.updated_at = utc_now_iso()
        store.save_state(state)

        print(f"[scan] crawl done: {len(state.urls_collected)} URLs discovered")

        repo_path = getattr(args, 'repo_path', None) or os.environ.get('DAST_REPO_PATH')
        active_findings = []
        if repo_path:
            try:
                import route_extractor
                root = targets[0].split('/benchmark', 1)[0].rstrip('/')
                routes = route_extractor.extract_routes(repo_path, root)
                endpoints = surface['crawl_results'].setdefault('endpoints', [])
                seen = {(ep.get('method', 'GET').upper(), ep.get('url', '')) for ep in endpoints}
                added = 0
                for r in routes:
                    key = (r.get('method', 'GET').upper(), r.get('url', ''))
                    if key not in seen:
                        seen.add(key)
                        endpoints.append(r)
                        added += 1
                    else:
                        for ep in endpoints:
                            if ep.get('url') == r.get('url') and ep.get('method', 'GET').upper() == r.get('method', 'GET').upper():
                                if r.get('params') and not ep.get('params'):
                                    ep['params'] = r.get('params')
                                if r.get('template') and not ep.get('template'):
                                    ep['template'] = r.get('template')
                                break
                if added:
                    print(f"[scan] source/openapi routes added: {added}")
                import active_checks
                active_findings = active_checks.run_active_checks(surface['crawl_results'], progress_cb=cli_progress)
                if active_findings:
                    print(f"[scan] active checks confirmed: {len(active_findings)} findings")
                state.crawl_results = surface['crawl_results']
                state.urls_collected = list(dict.fromkeys(ep.get('url', '') for ep in endpoints if ep.get('url')))
                store.save_state(state)
            except Exception as exc:
                eprint(f"[scan] source/openapi active checks skipped: {exc}")

        # Phase 2: AGENT SCAN
        state.status = "scanning"
        state.updated_at = utc_now_iso()
        store.save_state(state)

        agent = AgentRunner()
        result = agent.run(
            config=config,
            crawl_results=surface['crawl_results'],
            scan_id=scan_id,
        )

        # Dedup findings
        all_findings = dedup_findings(active_findings + result['findings'])

        # Phase 3: SOURCE-AWARE REMEDIATION VERIFICATION (optional)
        # Only runs when --repo-path is given. In blackbox mode (no source),
        # this is a no-op and findings pass through untouched.
        if repo_path and all_findings:
            state.status = "verifying"
            state.updated_at = utc_now_iso()
            store.save_state(state)
            print(f"[scan] source verification against {repo_path}")
            try:
                import source_verifier
                source_verifier.verify_findings(all_findings, repo_path, log=print)
            except Exception as exc:
                eprint(f"[scan] source verification skipped: {exc}")

        state.urls_hit = result['urls_hit']
        state.findings = all_findings
        state.logs = result['logs']
        state.finding_dedup = sorted({
            f"{f.get('vuln_type', '')}|{f.get('url', '')}|{f.get('parameter', '')}"
            for f in all_findings
        })
        state.status = "completed"
        state.updated_at = utc_now_iso()
        store.save_state(state)

        # Save to DB
        db.bulk_add_findings(scan_id, all_findings)
        db.update_project(scan_id, status='completed', ended_at=utc_now_iso())

        print(f"[scan] completed: {scan_id}")
        print(f"[scan] urls collected: {len(state.urls_collected)}")
        print(f"[scan] urls hit: {len(state.urls_hit)}")
        print(f"[scan] findings: {len(state.findings)}")

        if args.json:
            print_json(asdict(state))
        else:
            for finding in state.findings:
                sev = finding.get('severity', 'unknown').upper()
                vtype = finding.get('vuln_type', 'unknown')
                url = finding.get('url', '')
                param = finding.get('parameter', '')
                print(f"  {sev:<10} {vtype:<15} {url}  param={param}")

        return 0

    except KeyboardInterrupt:
        state.status = "interrupted"
        state.updated_at = utc_now_iso()
        state.errors.append("scan interrupted by user")
        store.save_state(state)
        db.update_project(scan_id, status='interrupted', ended_at=utc_now_iso())
        eprint("\nscan interrupted — resume with: whl resume " + scan_id)
        return 130

    except Exception as exc:
        state.status = "failed"
        state.updated_at = utc_now_iso()
        state.errors.append(str(exc))
        store.save_state(state)
        db.update_project(scan_id, status='failed', error=str(exc), ended_at=utc_now_iso())
        eprint(f"scan failed: {exc}")
        return 1


def cmd_resume(args: argparse.Namespace) -> int:
    auth_err = ensure_claude_cli_auth()
    if auth_err:
        eprint(f"error: {auth_err}")
        return 2

    store = ScanStore(Path(args.data_dir) / "scans")
    try:
        state = store.load_state(args.scan_id)
        config = store.load_config(args.scan_id)
    except Exception as exc:
        eprint(f"error: could not load scan {args.scan_id}: {exc}")
        return 2

    if state.status == "completed":
        print(f"[resume] scan {args.scan_id} already completed ({len(state.findings)} findings)")
        return 0

    print(f"[resume] resuming {args.scan_id} (was: {state.status})")

    try:
        # Preserve previous findings — agent skips already-tested URLs via DB
        prev_findings = list(state.findings) or list(db.get_findings(args.scan_id))
        prev_urls_hit = list(state.urls_hit)
        print(f"[resume] {len(prev_findings)} previous findings preserved")

        state.status = "scanning"
        state.logs = []
        state.updated_at = utc_now_iso()
        store.save_state(state)

        agent = AgentRunner()
        result = agent.run(
            config=config,
            crawl_results=state.crawl_results,
            scan_id=args.scan_id,
            resume=True,
        )

        # Merge previous + new findings, dedup
        all_findings = dedup_findings(prev_findings + result['findings'])

        state.urls_hit = list(dict.fromkeys(prev_urls_hit + result['urls_hit']))
        state.findings = all_findings
        state.logs = result['logs']
        state.finding_dedup = sorted({
            f"{f.get('vuln_type', '')}|{f.get('url', '')}|{f.get('parameter', '')}"
            for f in all_findings
        })
        state.status = "completed"
        state.updated_at = utc_now_iso()
        store.save_state(state)

        # Update DB
        db.bulk_add_findings(args.scan_id, all_findings)
        db.update_project(args.scan_id, status='completed', ended_at=utc_now_iso())

        print(f"[resume] completed: {args.scan_id}")
        print(f"[resume] total findings: {len(state.findings)}")

        for finding in all_findings:
            sev = finding.get('severity', 'unknown').upper()
            vtype = finding.get('vuln_type', 'unknown')
            url = finding.get('url', '')
            print(f"  {sev:<10} {vtype:<15} {url}")

        return 0

    except KeyboardInterrupt:
        state.status = "interrupted"
        state.updated_at = utc_now_iso()
        state.errors.append("resume interrupted by user")
        store.save_state(state)
        eprint("\nresume interrupted — resume again with: whl resume " + args.scan_id)
        return 130

    except Exception as exc:
        state.status = "failed"
        state.updated_at = utc_now_iso()
        state.errors.append(str(exc))
        store.save_state(state)
        eprint(f"resume failed: {exc}")
        return 1


def cmd_status(args: argparse.Namespace) -> int:
    store = ScanStore(Path(args.data_dir) / "scans")
    try:
        state = store.load_state(args.scan_id)
    except Exception as exc:
        eprint(f"error: could not load scan {args.scan_id}: {exc}")
        return 2

    sev_counts: Dict[str, int] = {}
    for f in state.findings:
        sev = f.get('severity', 'unknown').upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    payload = {
        "scan_id": state.scan_id,
        "status": state.status,
        "created_at": state.created_at,
        "updated_at": state.updated_at,
        "targets": state.targets,
        "urls_collected": len(state.urls_collected),
        "urls_hit": len(state.urls_hit),
        "findings": len(state.findings),
        "severity_breakdown": sev_counts,
        "coverage_summary": state.coverage_summary,
        "errors": state.errors,
    }
    print_json(payload)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    store = ScanStore(Path(args.data_dir) / "scans")
    try:
        state = store.load_state(args.scan_id)
    except Exception as exc:
        eprint(f"error: could not load scan {args.scan_id}: {exc}")
        return 2

    # Retroactive source verification: scan blackbox now, supply source later.
    repo_path = getattr(args, 'repo_path', None) or os.environ.get('DAST_REPO_PATH')
    if repo_path and state.findings:
        print(f"[report] source verification against {repo_path}")
        try:
            import source_verifier
            source_verifier.verify_findings(state.findings, repo_path, log=print)
            store.save_state(state)
            try:
                db.bulk_add_findings(args.scan_id, state.findings)
            except Exception:
                pass
        except Exception as exc:
            eprint(f"[report] source verification skipped: {exc}")

    out_dir = ensure_dir(Path(args.output_dir))
    fmt = args.format

    if fmt in ("markdown", "both"):
        report = build_markdown_report(state)
        md_path = out_dir / f"whitehatlabs-report-{args.scan_id}.md"
        md_path.write_text(report, encoding="utf-8")
        print(f"[report] markdown: {md_path}")

    if fmt in ("docx", "both"):
        docx_path = out_dir / f"whitehatlabs-report-{args.scan_id}.docx"
        try:
            build_docx_report(state, docx_path)
            print(f"[report] docx: {docx_path}")
        except Exception as exc:
            eprint(f"[report] docx generation failed: {exc}")
            return 1

    return 0


# -----------------------------
# Network scan command
# -----------------------------

def cmd_network(args: argparse.Namespace) -> int:
    """Run a network infrastructure scan."""
    auth_err = ensure_claude_cli_auth()
    if auth_err:
        eprint(f"error: {auth_err}")
        return 2

    targets = args.targets
    if not targets:
        eprint("error: no targets provided")
        return 2

    scan_id = args.scan_id or uuid.uuid4().hex[:16]

    target_lines = []
    for t in targets:
        t = t.strip()
        if t:
            target_lines.append(t)

    if not target_lines:
        eprint("error: no valid targets")
        return 2

    target_network = target_lines[0]
    scan_targets = {
        'targets': target_lines,
        'options': {
            'ports': args.ports,
            'rate': args.rate,
            'sudo_password': args.sudo_password,
        },
    }

    # Init network DB
    import network_db as net_db
    net_db.init_db()
    net_db.create_project(scan_id, target_network, name=f'Network scan — {target_network}')

    print(f"[network] starting scan {scan_id}")
    print(f"[network] targets: {', '.join(target_lines)}")
    print(f"[network] ports: {args.ports}, rate: {args.rate}")

    try:
        from network_agent import run_agent as network_run_agent

        findings, _ = asyncio.run(network_run_agent(
            target_network,
            scan_targets=scan_targets,
            max_turns=300,
            scan_id=scan_id,
        ))

        findings = dedup_findings(findings)
        net_db.bulk_add_findings(scan_id, findings)
        net_db.update_project(scan_id, status='completed')

        print(f"[network] completed: {scan_id}")
        print(f"[network] findings: {len(findings)}")

        for f in findings:
            sev = (f.get('severity') or 'unknown').upper()
            vtype = f.get('vuln_type', 'unknown')
            host = f.get('host', '')
            port = f.get('port', '')
            print(f"  {sev:<10} {vtype:<25} {host}:{port}")

        return 0

    except KeyboardInterrupt:
        eprint("\nnetwork scan interrupted")
        return 130
    except Exception as exc:
        eprint(f"network scan failed: {exc}")
        return 1


# -----------------------------
# Parser
# -----------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="whl",
        description="WhiteHatLabs CLI for web application pentesting workflows",
    )
    parser.add_argument(
        "--data-dir",
        default=str(DEFAULT_DATA_DIR),
        help="storage directory for scan state (default: ~/.whitehatlabs)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    scan = subparsers.add_parser("scan", help="start a new assessment")
    scan.add_argument("targets", nargs="*", help="target URLs")
    scan.add_argument("--targets-file", help="file containing targets, one per line")
    scan.add_argument("--scan-id", help="optional custom scan id")
    scan.add_argument("--provider", default="claude-code", help="agent provider name")
    scan.add_argument("--batch-size", type=int, default=10)
    scan.add_argument("--auth-username")
    scan.add_argument("--auth-password")
    scan.add_argument("--login-url")
    scan.add_argument("--max-urls", type=int, help="max URLs to crawl")
    scan.add_argument("--max-depth", type=int, help="max crawl depth")
    scan.add_argument("--timeout", type=int, default=120, help="crawl timeout in seconds")
    scan.add_argument("--notes")
    scan.add_argument("--repo-path", help="path to target source code; enables "
                      "source-aware remediation verification (omit for pure blackbox)")
    scan.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    scan.add_argument("--insecure", action="store_true", help="disable TLS verification")
    scan.add_argument("--browser-crawl", action="store_true",
                      help="enable optional Playwright browser crawling")
    scan.add_argument("--no-headless", action="store_true", help=argparse.SUPPRESS)
    scan.add_argument("--json", action="store_true", help="print final state as JSON")
    scan.set_defaults(func=cmd_scan)

    # resume
    resume = subparsers.add_parser("resume", help="resume a previous assessment")
    resume.add_argument("scan_id")
    resume.set_defaults(func=cmd_resume)

    # status
    status = subparsers.add_parser("status", help="show scan status")
    status.add_argument("scan_id")
    status.set_defaults(func=cmd_status)

    # report
    report = subparsers.add_parser("report", help="generate report from scan results")
    report.add_argument("scan_id")
    report.add_argument("--format", choices=["markdown", "docx", "both"], default="markdown",
                        help="output format (default: markdown)")
    report.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    report.add_argument("--repo-path", help="path to target source code; runs "
                        "source-aware remediation verification before rendering")
    report.set_defaults(func=cmd_report)

    # network
    network = subparsers.add_parser("network", help="start a network infrastructure scan")
    network.add_argument("targets", nargs="*", help="target IPs, CIDRs, or hostnames")
    network.add_argument("--scan-id", help="optional custom scan id")
    network.add_argument("--ports", default="1-65535", help="port range (default: 1-65535)")
    network.add_argument("--rate", type=int, default=1000, help="masscan rate (default: 1000)")
    network.add_argument("--sudo-password", help="sudo password for raw socket scans")
    network.set_defaults(func=cmd_network)

    return parser


# -----------------------------
# Entry point
# -----------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
