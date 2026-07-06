"""Clean SQLite database layer for Pentest app."""
import sqlite3, os, threading, uuid, json
from datetime import datetime, timezone

_DATA_DIR = os.environ.get('PENTEST_DATA_DIR', os.path.expanduser('~/.pentest'))
os.makedirs(_DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(_DATA_DIR, 'pentest.db')

_lock = threading.Lock()

_FINDING_COLS = {
    'finding_id', 'severity', 'vuln_type', 'url', 'method', 'parameter',
    'payload', 'evidence', 'curl_command', 'request', 'response', 'source',
    'risk_reasoning', 'attack_narrative', 'confidence',
    'false_positive_risk', 'remediation_status', 'source_location',
    'source_sink', 'remediation_evidence', 'poc',
}

def _clean_finding(f):
    f = dict(f or {})
    if not f.get('finding_id') and f.get('id'):
        f['finding_id'] = f.get('id')
    if not f.get('response') and f.get('response_preview'):
        f['response'] = f.get('response_preview')
    return {k: v for k, v in f.items() if k in _FINDING_COLS}

def _conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA foreign_keys=ON')
    return c

def init_db():
    with _lock:
        c = _conn()
        c.executescript("""
        CREATE TABLE IF NOT EXISTS engagements (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            target_url  TEXT,
            status      TEXT DEFAULT 'idle',
            phase       TEXT DEFAULT '',
            progress    INTEGER DEFAULT 0,
            started_at  TEXT,
            ended_at    TEXT,
            error       TEXT,
            auth_username   TEXT,
            auth_password   TEXT,
            auth_login_url  TEXT,
            app_notes       TEXT,
            repo_path       TEXT,
            agent_backend   TEXT DEFAULT 'codex',
            use_burp_proxy  INTEGER DEFAULT 0,
            disable_fuzzers INTEGER DEFAULT 0,
            enable_browser  INTEGER DEFAULT 0,
            burp_watermark  INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            finding_id      TEXT,
            severity        TEXT,
            vuln_type       TEXT,
            url             TEXT,
            method          TEXT DEFAULT 'GET',
            parameter       TEXT,
            payload         TEXT,
            evidence        TEXT,
            curl_command    TEXT,
            request         TEXT,
            response        TEXT,
            source          TEXT DEFAULT 'agent',
            risk_reasoning  TEXT,
            attack_narrative TEXT,
            confidence      TEXT DEFAULT 'possible',
            false_positive_risk TEXT DEFAULT 'medium',
            remediation_status  TEXT,
            source_location     TEXT,
            source_sink         TEXT,
            remediation_evidence TEXT,
            poc             TEXT,
            created_at      TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS logs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            time            TEXT,
            phase           TEXT,
            message         TEXT,
            created_at      TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS proxy_entries (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            method          TEXT,
            url             TEXT,
            status          INTEGER DEFAULT 0,
            length          INTEGER DEFAULT 0,
            body_preview    TEXT DEFAULT '',
            request_headers TEXT DEFAULT '[]',
            request_body    TEXT DEFAULT '',
            response_headers TEXT DEFAULT '[]',
            response_body   TEXT DEFAULT '',
            tested          INTEGER DEFAULT 0,
            created_at      TEXT DEFAULT (datetime('now')),
            UNIQUE(engagement_id, method, url)
        );

        CREATE TABLE IF NOT EXISTS coverage (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id       TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            method              TEXT,
            url                 TEXT,
            surface             TEXT,
            category            TEXT,
            subcategory         TEXT,
            status              TEXT DEFAULT 'tested',
            reason              TEXT,
            evidence            TEXT,
            param               TEXT,
            param_source        TEXT,
            vuln_type           TEXT,
            payloads_attempted  INTEGER DEFAULT 0,
            last_status_code    INTEGER,
            last_response_len   INTEGER,
            skip_reason         TEXT,
            evidence_ref        TEXT,
            tested_at           TEXT,
            updated_at          TEXT DEFAULT (datetime('now')),
            UNIQUE(engagement_id, method, url, subcategory, surface)
        );

        CREATE INDEX IF NOT EXISTS idx_findings_eid ON findings(engagement_id);
        CREATE INDEX IF NOT EXISTS idx_logs_eid ON logs(engagement_id);
        CREATE INDEX IF NOT EXISTS idx_proxy_eid ON proxy_entries(engagement_id);
        """)
        _ensure_columns(c, 'proxy_entries', {
            'request_headers': "TEXT DEFAULT '[]'",
            'request_body': "TEXT DEFAULT ''",
            'response_headers': "TEXT DEFAULT '[]'",
            'response_body': "TEXT DEFAULT ''",
        })
        c.commit()
        c.close()

def _ensure_columns(conn, table, columns):
    existing = {row['name'] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    for name, definition in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

def _json_text(value):
    if isinstance(value, str):
        return value
    return json.dumps(value or [])

def _json_value(value):
    if isinstance(value, list):
        return value
    if not value:
        return []
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []

def new_id():
    return str(uuid.uuid4())[:8]

def utc_now():
    return datetime.now(timezone.utc).isoformat()

# ── Engagements ───────────────────────────────────────────────────────────────

def create_engagement(target_url, name=None, **kwargs):
    eid = new_id()
    if not name:
        from urllib.parse import urlparse
        h = urlparse(target_url).hostname or target_url or 'engagement'
        name = f"{h}-{eid}"
    with _lock:
        c = _conn()
        cols = ['id', 'name', 'target_url', 'status', 'started_at'] + list(kwargs.keys())
        vals = [eid, name, target_url, 'idle', utc_now()] + list(kwargs.values())
        placeholders = ','.join('?' * len(vals))
        c.execute(f"INSERT INTO engagements ({','.join(cols)}) VALUES ({placeholders})", vals)
        c.commit()
        c.close()
    return eid

def get_engagement(eid):
    c = _conn()
    row = c.execute("SELECT * FROM engagements WHERE id=?", (eid,)).fetchone()
    c.close()
    return dict(row) if row else None

def list_engagements():
    c = _conn()
    rows = c.execute("SELECT * FROM engagements ORDER BY created_at DESC").fetchall()
    c.close()
    return [dict(r) for r in rows]

def update_engagement(eid, **kwargs):
    if not kwargs:
        return
    with _lock:
        c = _conn()
        sets = ', '.join(f"{k}=?" for k in kwargs)
        c.execute(f"UPDATE engagements SET {sets} WHERE id=?", list(kwargs.values()) + [eid])
        c.commit()
        c.close()

def delete_engagement(eid):
    with _lock:
        c = _conn()
        c.execute("DELETE FROM engagements WHERE id=?", (eid,))
        c.commit()
        c.close()

def delete_all_engagements():
    with _lock:
        c = _conn()
        c.execute("DELETE FROM engagements")
        c.commit()
        c.close()

# ── Findings ──────────────────────────────────────────────────────────────────

def add_finding(eid, f):
    f = _clean_finding(f)
    cols = ['engagement_id'] + list(f.keys())
    vals = [eid] + list(f.values())
    with _lock:
        c = _conn()
        placeholders = ','.join('?' * len(vals))
        c.execute(f"INSERT OR IGNORE INTO findings ({','.join(cols)}) VALUES ({placeholders})", vals)
        c.commit()
        c.close()

def bulk_add_findings(eid, findings):
    with _lock:
        c = _conn()
        c.execute("DELETE FROM findings WHERE engagement_id=?", (eid,))
        for f in findings:
            f = _clean_finding(f)
            if not f:
                continue
            cols = ['engagement_id'] + list(f.keys())
            vals = [eid] + list(f.values())
            placeholders = ','.join('?' * len(vals))
            try:
                c.execute(f"INSERT OR IGNORE INTO findings ({','.join(cols)}) VALUES ({placeholders})", vals)
            except Exception as e:
                print(f"[db] failed to insert finding for {eid}: {e}")
        c.commit()
        c.close()

def get_findings(eid):
    c = _conn()
    rows = c.execute("SELECT * FROM findings WHERE engagement_id=? ORDER BY id", (eid,)).fetchall()
    c.close()
    return [dict(r) for r in rows]

def update_finding(finding_id, **kwargs):
    with _lock:
        c = _conn()
        sets = ', '.join(f"{k}=?" for k in kwargs)
        c.execute(f"UPDATE findings SET {sets} WHERE finding_id=?", list(kwargs.values()) + [finding_id])
        c.commit()
        c.close()

# ── Logs ──────────────────────────────────────────────────────────────────────

def add_log(eid, phase, message):
    t = datetime.now().strftime('%H:%M:%S')
    with _lock:
        c = _conn()
        c.execute("INSERT INTO logs (engagement_id, time, phase, message) VALUES (?,?,?,?)",
                  (eid, t, phase, message))
        c.commit()
        c.close()

def bulk_add_logs(eid, logs):
    with _lock:
        c = _conn()
        for l in logs:
            c.execute("INSERT INTO logs (engagement_id, time, phase, message) VALUES (?,?,?,?)",
                      (eid, l.get('time',''), l.get('phase',''), l.get('message','')))
        c.commit()
        c.close()

def replace_logs(eid, logs):
    with _lock:
        c = _conn()
        c.execute("DELETE FROM logs WHERE engagement_id=?", (eid,))
        for l in logs or []:
            c.execute("INSERT INTO logs (engagement_id, time, phase, message) VALUES (?,?,?,?)",
                      (eid, l.get('time',''), l.get('phase',''), l.get('message','')))
        c.commit()
        c.close()

def get_logs(eid, limit=5000):
    c = _conn()
    rows = c.execute("SELECT * FROM logs WHERE engagement_id=? ORDER BY id DESC LIMIT ?",
                     (eid, limit)).fetchall()
    c.close()
    return list(reversed([dict(r) for r in rows]))

# ── Proxy entries ─────────────────────────────────────────────────────────────

def bulk_add_proxy(eid, entries):
    with _lock:
        c = _conn()
        for e in entries:
            c.execute("""INSERT OR IGNORE INTO proxy_entries
                         (engagement_id, method, url, status, length, body_preview,
                          request_headers, request_body, response_headers, response_body, tested)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                      (eid, e.get('method','GET'), e.get('url',''),
                       e.get('status',0), e.get('length',0),
                       e.get('body_preview',''),
                       _json_text(e.get('request_headers')),
                       e.get('request_body',''),
                       _json_text(e.get('response_headers')),
                       e.get('response_body',''),
                       e.get('tested',0)))
        c.commit()
        c.close()

def replace_proxy_entries(eid, entries):
    with _lock:
        c = _conn()
        c.execute("DELETE FROM proxy_entries WHERE engagement_id=?", (eid,))
        for e in entries or []:
            c.execute("""INSERT OR IGNORE INTO proxy_entries
                         (engagement_id, method, url, status, length, body_preview,
                          request_headers, request_body, response_headers, response_body, tested)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                      (eid, e.get('method','GET'), e.get('url',''),
                       e.get('status',0), e.get('length',0),
                       e.get('body_preview',''),
                       _json_text(e.get('request_headers')),
                       e.get('request_body',''),
                       _json_text(e.get('response_headers')),
                       e.get('response_body',''),
                       e.get('tested',0)))
        c.commit()
        c.close()

def get_proxy_entries(eid):
    c = _conn()
    rows = c.execute("SELECT * FROM proxy_entries WHERE engagement_id=? ORDER BY id", (eid,)).fetchall()
    c.close()
    items = []
    for row in rows:
        item = dict(row)
        item['request_headers'] = _json_value(item.get('request_headers'))
        item['response_headers'] = _json_value(item.get('response_headers'))
        items.append(item)
    return items

def clear_proxy_entries(eid):
    with _lock:
        c = _conn()
        c.execute("DELETE FROM proxy_entries WHERE engagement_id=?", (eid,))
        c.commit()
        c.close()

def mark_proxy_tested(eid, method, url):
    with _lock:
        c = _conn()
        c.execute("UPDATE proxy_entries SET tested=1 WHERE engagement_id=? AND method=? AND url=?",
                  (eid, method, url))
        if c.execute("SELECT changes()").fetchone()[0] == 0:
            c.execute("INSERT OR IGNORE INTO proxy_entries (engagement_id,method,url,tested) VALUES (?,?,?,1)",
                      (eid, method, url))
        c.commit()
        c.close()

# ── Coverage ──────────────────────────────────────────────────────────────────

def upsert_coverage(eid, method, url, records):
    with _lock:
        c = _conn()
        for r in records:
            c.execute("""INSERT INTO coverage
                         (engagement_id,method,url,surface,category,subcategory,status,reason,evidence,updated_at)
                         VALUES (?,?,?,?,?,?,?,?,?,?)
                         ON CONFLICT(engagement_id,method,url,subcategory,surface)
                         DO UPDATE SET status=excluded.status, reason=excluded.reason,
                                       evidence=excluded.evidence, updated_at=excluded.updated_at""",
                      (eid, method, url,
                       r.get('surface',''), r.get('category',''), r.get('subcategory',''),
                       r.get('status','tested'), r.get('reason',''), r.get('evidence',''),
                       utc_now()))
        c.commit()
        c.close()

def bulk_upsert_coverage(eid, records):
    """Upsert CoverageMatrix.to_db_records() output (keyed by method+url+vuln_type+param)."""
    with _lock:
        c = _conn()
        for r in records:
            c.execute("""INSERT INTO coverage
                         (engagement_id,method,url,surface,category,subcategory,status,reason,evidence,
                          param,param_source,vuln_type,payloads_attempted,last_status_code,
                          last_response_len,skip_reason,evidence_ref,tested_at,updated_at)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                         ON CONFLICT(engagement_id,method,url,subcategory,surface)
                         DO UPDATE SET status=excluded.status, reason=excluded.reason,
                                       evidence=excluded.evidence, payloads_attempted=excluded.payloads_attempted,
                                       last_status_code=excluded.last_status_code,
                                       last_response_len=excluded.last_response_len,
                                       skip_reason=excluded.skip_reason, evidence_ref=excluded.evidence_ref,
                                       tested_at=excluded.tested_at, updated_at=excluded.updated_at""",
                      (eid,
                       r.get('method','GET'), r.get('url',''),
                       r.get('param_source',''), r.get('vuln_type',''), r.get('vuln_type',''),
                       r.get('status','tested'), r.get('skip_reason',''), r.get('evidence_ref',''),
                       r.get('param',''), r.get('param_source',''), r.get('vuln_type',''),
                       r.get('payloads_attempted',0), r.get('last_status_code'),
                       r.get('last_response_len'), r.get('skip_reason',''), r.get('evidence_ref',''),
                       r.get('tested_at'), utc_now()))
        c.commit()
        c.close()

def get_coverage(eid):
    c = _conn()
    rows = c.execute("SELECT * FROM coverage WHERE engagement_id=? ORDER BY url,subcategory", (eid,)).fetchall()
    c.close()
    return [dict(r) for r in rows]
