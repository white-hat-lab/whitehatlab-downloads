"""
Coverage Matrix — Single source of truth for what has and hasn't been tested.

Tracks every test unit (endpoint × param × vuln_type) through its lifecycle:
pending → baseline_done → attempted → confirmed/no_issue/error/skipped

Finding dedup is SEPARATE from coverage tracking.
"""
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs


# ---------------------------------------------------------------------------
# Vuln type → applicable input sources
# ---------------------------------------------------------------------------

VULN_APPLICABLE_SOURCES = {
    'sqli':            {'query', 'form', 'json', 'cookie', 'header'},
    'xss':             {'query', 'form', 'json'},
    'ssti':            {'query', 'form', 'json'},
    'cmdi':            {'query', 'form', 'json', 'header'},
    'lfi':             {'query', 'form', 'json'},
    'ssrf':            {'query', 'form', 'json'},
    'open_redirect':   {'query', 'form'},
    'xxe':             {'xml'},
    'ldap':            {'query', 'form'},
    'idor':            {'query', 'form', 'json', 'path'},
    'csrf':            {'method_level'},
    'mass_assignment': {'form', 'json'},
    'file_upload':     {'multipart'},
}

# Vuln classes that apply at method level (no specific param needed)
METHOD_LEVEL_VULNS = {'csrf'}

# Vuln classes for state-changing methods only
STATE_CHANGING_VULNS = {'csrf', 'mass_assignment'}
STATE_CHANGING_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}

# Default vuln classes to test for injection-type params
INJECTION_VULNS = {'sqli', 'xss', 'ssti', 'cmdi', 'lfi', 'ssrf', 'open_redirect', 'ldap'}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ParamInfo:
    name: str
    source: str  # query/form/json/xml/header/cookie/path/multipart


@dataclass
class EndpointInfo:
    method: str
    url: str
    normalized_key: str
    params: list  # list of ParamInfo
    baseline_done: bool = False
    discovery_status: str = 'pending'  # pending/done/failed


@dataclass
class TestUnit:
    """Single test unit: one param + one vuln_type on one endpoint."""
    endpoint_key: str
    method: str
    url: str
    param: str
    param_source: str
    vuln_type: str
    status: str = 'pending'  # pending/baseline_done/attempted/confirmed/no_issue/error/skipped
    baseline_done: bool = False
    payloads_attempted: int = 0
    last_status_code: int = 0
    last_response_len: int = 0
    last_elapsed: float = 0.0
    tested_at: str = ''
    skip_reason: str = ''
    evidence_ref: str = ''

    @property
    def key(self):
        return f"{self.method}|{self.url}|{self.param}|{self.vuln_type}"


# ---------------------------------------------------------------------------
# Coverage Matrix
# ---------------------------------------------------------------------------

class CoverageMatrix:
    """Tracks what has and hasn't been tested.
    Finding dedup is kept SEPARATE from coverage state."""

    def __init__(self):
        self._endpoints = {}       # endpoint_key -> EndpointInfo
        self._tests = {}           # test_key -> TestUnit
        self._finding_dedup = {}   # dedup_key -> finding_id
        self._discovery = {}       # endpoint_key -> 'pending'|'done'|'failed'

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_endpoint_key(method, url):
        """Normalize endpoint key: METHOD + base_path + sorted param names."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        param_names = sorted(parse_qs(parsed.query).keys()) if parsed.query else []
        return f"{method} {base} [{','.join(param_names)}]"

    @staticmethod
    def _make_test_key(method, url, param, vuln_type):
        parsed = urlparse(url)
        return f"{method}|{parsed.path}|{param}|{vuln_type}"

    @staticmethod
    def _make_finding_dedup_key(vuln_type, method, url, param, evidence_hash):
        parsed = urlparse(url)
        return f"{vuln_type}|{method}|{parsed.path}|{param}|{evidence_hash}"

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_endpoint(self, method, url, params=None, param_sources=None):
        """Register a discovered endpoint with its params.

        Args:
            method: HTTP method
            url: Full URL
            params: list of param names (strings)
            param_sources: dict mapping param_name -> source, or a default source string
        """
        key = self.normalize_endpoint_key(method, url)
        if key in self._endpoints:
            # Merge new params into existing endpoint
            ep = self._endpoints[key]
            existing_names = {p.name for p in ep.params}
            for p in (params or []):
                if p not in existing_names:
                    source = 'query'
                    if isinstance(param_sources, dict):
                        source = param_sources.get(p, 'query')
                    elif isinstance(param_sources, str):
                        source = param_sources
                    ep.params.append(ParamInfo(name=p, source=source))
            return ep

        param_list = []
        for p in (params or []):
            source = 'query'
            if isinstance(param_sources, dict):
                source = param_sources.get(p, 'query')
            elif isinstance(param_sources, str):
                source = param_sources
            param_list.append(ParamInfo(name=p, source=source))

        ep = EndpointInfo(
            method=method,
            url=url,
            normalized_key=key,
            params=param_list,
        )
        self._endpoints[key] = ep
        self._discovery[key] = 'done' if param_list else 'pending'
        return ep

    def register_param(self, endpoint_key, param, source='query'):
        """Add a discovered param to an existing endpoint."""
        ep = self._endpoints.get(endpoint_key)
        if not ep:
            return
        existing = {p.name for p in ep.params}
        if param not in existing:
            ep.params.append(ParamInfo(name=param, source=source))

    # ------------------------------------------------------------------
    # Test queue generation
    # ------------------------------------------------------------------

    def generate_test_queue(self):
        """Build ordered queue of TestUnits from registered endpoints.

        Maps vuln_types to applicable param_sources. Only generates tests
        for (param, vuln_type) combos that make sense given the param source.
        """
        queue = []

        for ep_key, ep in self._endpoints.items():
            # Method-level tests (CSRF, etc.)
            for vuln in METHOD_LEVEL_VULNS:
                if vuln in STATE_CHANGING_VULNS and ep.method not in STATE_CHANGING_METHODS:
                    continue
                test_key = self._make_test_key(ep.method, ep.url, '__method__', vuln)
                if test_key not in self._tests:
                    tu = TestUnit(
                        endpoint_key=ep_key,
                        method=ep.method,
                        url=ep.url,
                        param='__method__',
                        param_source='method_level',
                        vuln_type=vuln,
                    )
                    self._tests[test_key] = tu
                if self._tests[test_key].status == 'pending':
                    queue.append(self._tests[test_key])

            # Mass assignment: test at endpoint level for state-changing methods
            if ep.method in STATE_CHANGING_METHODS:
                for vuln in ('mass_assignment',):
                    test_key = self._make_test_key(ep.method, ep.url, '__body__', vuln)
                    if test_key not in self._tests:
                        tu = TestUnit(
                            endpoint_key=ep_key,
                            method=ep.method,
                            url=ep.url,
                            param='__body__',
                            param_source='form',
                            vuln_type=vuln,
                        )
                        self._tests[test_key] = tu
                    if self._tests[test_key].status == 'pending':
                        queue.append(self._tests[test_key])

            # Per-param tests
            for param_info in ep.params:
                for vuln, applicable_sources in VULN_APPLICABLE_SOURCES.items():
                    if vuln in METHOD_LEVEL_VULNS:
                        continue  # handled above
                    if vuln in STATE_CHANGING_VULNS:
                        continue  # handled above
                    if param_info.source not in applicable_sources:
                        continue  # vuln not applicable to this input type

                    test_key = self._make_test_key(ep.method, ep.url, param_info.name, vuln)
                    if test_key not in self._tests:
                        tu = TestUnit(
                            endpoint_key=ep_key,
                            method=ep.method,
                            url=ep.url,
                            param=param_info.name,
                            param_source=param_info.source,
                            vuln_type=vuln,
                        )
                        self._tests[test_key] = tu
                    if self._tests[test_key].status == 'pending':
                        queue.append(self._tests[test_key])

            # Endpoints with no params: still run passive/method-level checks
            if not ep.params and self._discovery.get(ep_key) == 'failed':
                # Mark all injection tests as skipped (no params to inject into)
                for vuln in INJECTION_VULNS:
                    test_key = self._make_test_key(ep.method, ep.url, '__none__', vuln)
                    if test_key not in self._tests:
                        tu = TestUnit(
                            endpoint_key=ep_key,
                            method=ep.method,
                            url=ep.url,
                            param='__none__',
                            param_source='none',
                            vuln_type=vuln,
                            status='skipped',
                            skip_reason='no_params_discovered',
                        )
                        self._tests[test_key] = tu

        return queue

    # ------------------------------------------------------------------
    # Status updates
    # ------------------------------------------------------------------

    def mark_baseline_done(self, endpoint_key):
        ep = self._endpoints.get(endpoint_key)
        if ep:
            ep.baseline_done = True
        # Also update all pending tests for this endpoint
        for tk, tu in self._tests.items():
            if tu.endpoint_key == endpoint_key and tu.status == 'pending':
                tu.baseline_done = True
                tu.status = 'baseline_done'

    def mark_attempted(self, test_key, status_code=0, response_len=0, elapsed=0.0):
        tu = self._tests.get(test_key)
        if not tu:
            # Auto-create if tool call doesn't match a pre-registered test
            return
        tu.status = 'attempted'
        tu.payloads_attempted += 1
        tu.last_status_code = status_code
        tu.last_response_len = response_len
        tu.last_elapsed = elapsed
        tu.tested_at = datetime.now(timezone.utc).isoformat()

    def mark_confirmed(self, test_key, finding_id):
        tu = self._tests.get(test_key)
        if tu:
            tu.status = 'confirmed'
            tu.evidence_ref = finding_id
            tu.tested_at = datetime.now(timezone.utc).isoformat()

    def mark_no_issue(self, test_key):
        tu = self._tests.get(test_key)
        if tu:
            tu.status = 'no_issue'
            tu.tested_at = datetime.now(timezone.utc).isoformat()

    def mark_error(self, test_key, error_msg=''):
        tu = self._tests.get(test_key)
        if tu:
            tu.status = 'error'
            tu.skip_reason = error_msg[:200]
            tu.tested_at = datetime.now(timezone.utc).isoformat()

    def mark_skipped(self, test_key, reason=''):
        tu = self._tests.get(test_key)
        if tu:
            tu.status = 'skipped'
            tu.skip_reason = reason[:200]
            tu.tested_at = datetime.now(timezone.utc).isoformat()

    def mark_discovery_done(self, endpoint_key, params_found):
        """Mark param discovery complete and register found params."""
        self._discovery[endpoint_key] = 'done'
        ep = self._endpoints.get(endpoint_key)
        if ep:
            ep.discovery_status = 'done'
        for param_name, source in params_found:
            self.register_param(endpoint_key, param_name, source)

    def mark_discovery_failed(self, endpoint_key):
        self._discovery[endpoint_key] = 'failed'
        ep = self._endpoints.get(endpoint_key)
        if ep:
            ep.discovery_status = 'failed'

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_status(self, test_key):
        tu = self._tests.get(test_key)
        return tu.status if tu else 'unknown'

    def get_pending_tests(self):
        return [tu for tu in self._tests.values() if tu.status in ('pending', 'baseline_done')]

    def get_untested_endpoints(self):
        """Endpoints where NO tests have been attempted."""
        tested_eps = set()
        for tu in self._tests.values():
            if tu.status not in ('pending', 'baseline_done'):
                tested_eps.add(tu.endpoint_key)
        return [ep for ek, ep in self._endpoints.items() if ek not in tested_eps]

    def get_partial_endpoints(self):
        """Endpoints where SOME but not all tests are done."""
        ep_stats = {}
        for tu in self._tests.values():
            if tu.endpoint_key not in ep_stats:
                ep_stats[tu.endpoint_key] = {'total': 0, 'done': 0}
            ep_stats[tu.endpoint_key]['total'] += 1
            if tu.status not in ('pending', 'baseline_done'):
                ep_stats[tu.endpoint_key]['done'] += 1
        return [
            self._endpoints[ek]
            for ek, stats in ep_stats.items()
            if 0 < stats['done'] < stats['total'] and ek in self._endpoints
        ]

    def get_retry_queue(self):
        """Test units that errored or timed out — worth retrying."""
        return [tu for tu in self._tests.values() if tu.status == 'error']

    def get_tests_for_endpoint(self, endpoint_key):
        """All test units for a given endpoint."""
        return [tu for tu in self._tests.values() if tu.endpoint_key == endpoint_key]

    def get_coverage_summary(self):
        """Aggregate coverage statistics."""
        total = len(self._tests)
        by_status = {}
        methods = set()
        vuln_classes = set()
        for tu in self._tests.values():
            by_status[tu.status] = by_status.get(tu.status, 0) + 1
            if tu.status not in ('pending', 'baseline_done', 'skipped'):
                methods.add(tu.method)
                vuln_classes.add(tu.vuln_type)

        eps_total = len(self._endpoints)
        eps_params_resolved = sum(
            1 for ep in self._endpoints.values()
            if ep.params or ep.discovery_status == 'done'
        )
        eps_unknown = sum(
            1 for ek, status in self._discovery.items()
            if status == 'pending'
        )

        return {
            'total_endpoints': eps_total,
            'params_resolved': eps_params_resolved,
            'unknown_params': eps_unknown,
            'total_tests': total,
            'pending': by_status.get('pending', 0) + by_status.get('baseline_done', 0),
            'attempted': by_status.get('attempted', 0),
            'confirmed': by_status.get('confirmed', 0),
            'no_issue': by_status.get('no_issue', 0),
            'error': by_status.get('error', 0),
            'skipped': by_status.get('skipped', 0),
            'methods': sorted(methods),
            'vuln_classes': sorted(vuln_classes),
        }

    # ------------------------------------------------------------------
    # Finding dedup (SEPARATE from coverage)
    # ------------------------------------------------------------------

    def is_duplicate_finding(self, vuln_type, method, url, param, evidence_hash):
        key = self._make_finding_dedup_key(vuln_type, method, url, param, evidence_hash)
        return key in self._finding_dedup

    def register_finding(self, vuln_type, method, url, param, evidence_hash, finding_id):
        key = self._make_finding_dedup_key(vuln_type, method, url, param, evidence_hash)
        self._finding_dedup[key] = finding_id

    # ------------------------------------------------------------------
    # Serialization (to/from DB records)
    # ------------------------------------------------------------------

    def to_db_records(self):
        """Export all test units as list of dicts for DB storage."""
        records = []
        for tk, tu in self._tests.items():
            records.append({
                'method': tu.method,
                'url': tu.url,
                'param': tu.param,
                'param_source': tu.param_source,
                'vuln_type': tu.vuln_type,
                'status': tu.status,
                'baseline_done': 1 if tu.baseline_done else 0,
                'payloads_attempted': tu.payloads_attempted,
                'last_status_code': tu.last_status_code,
                'last_response_len': tu.last_response_len,
                'last_elapsed': tu.last_elapsed,
                'skip_reason': tu.skip_reason,
                'evidence_ref': tu.evidence_ref,
                'tested_at': tu.tested_at or datetime.now(timezone.utc).isoformat(),
            })
        return records

    def from_db_records(self, records):
        """Load test units from DB records. Re-registers endpoints and tests."""
        for r in records:
            method = r['method']
            url = r['url']
            param = r.get('param', '')
            param_source = r.get('param_source', 'query')
            vuln_type = r.get('vuln_type', '')

            # Register endpoint if not already known
            ep_key = self.normalize_endpoint_key(method, url)
            if ep_key not in self._endpoints:
                self.register_endpoint(method, url)
            if param and param not in ('__method__', '__body__', '__none__'):
                self.register_param(ep_key, param, param_source)

            # Create/update test unit
            test_key = self._make_test_key(method, url, param, vuln_type)
            tu = TestUnit(
                endpoint_key=ep_key,
                method=method,
                url=url,
                param=param,
                param_source=param_source,
                vuln_type=vuln_type,
                status=r.get('status', 'pending'),
                baseline_done=bool(r.get('baseline_done', 0)),
                payloads_attempted=r.get('payloads_attempted', 0),
                last_status_code=r.get('last_status_code', 0),
                last_response_len=r.get('last_response_len', 0),
                last_elapsed=r.get('last_elapsed', 0.0),
                skip_reason=r.get('skip_reason', ''),
                evidence_ref=r.get('evidence_ref', ''),
                tested_at=r.get('tested_at', ''),
            )
            self._tests[test_key] = tu

    def mark_from_record(self, record):
        """Apply a single coverage record (used during resume to carry over completed tests)."""
        method = record['method']
        url = record['url']
        param = record.get('param', '')
        vuln_type = record.get('vuln_type', '')
        status = record.get('status', 'pending')

        test_key = self._make_test_key(method, url, param, vuln_type)
        if test_key in self._tests:
            self._tests[test_key].status = status
            self._tests[test_key].payloads_attempted = record.get('payloads_attempted', 0)
            self._tests[test_key].evidence_ref = record.get('evidence_ref', '')
        else:
            # Create test unit from record
            ep_key = self.normalize_endpoint_key(method, url)
            tu = TestUnit(
                endpoint_key=ep_key,
                method=method,
                url=url,
                param=param,
                param_source=record.get('param_source', 'query'),
                vuln_type=vuln_type,
                status=status,
                payloads_attempted=record.get('payloads_attempted', 0),
                evidence_ref=record.get('evidence_ref', ''),
            )
            self._tests[test_key] = tu


def make_evidence_hash(evidence_text):
    """Create a short hash of evidence text for finding dedup."""
    return hashlib.md5((evidence_text or '')[:500].encode()).hexdigest()[:8]
