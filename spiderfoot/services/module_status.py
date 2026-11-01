"""Per-module status drawn from past scans: errors and produced results.

Used by Settings -> Modules to pass module errors and health through to the UI.
"""

import sqlite3
import threading
import time

RECENT = 7 * 86400
_CACHE = {}
_LOCK = threading.Lock()
TTL = 30


def _query(db_path: str, now: float) -> dict:
    out = {}
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        since_ms = int((now - RECENT) * 1000)
        for comp, total, recent, last in conn.execute(
                "SELECT component, COUNT(*), SUM(generated >= ?), MAX(generated) FROM tbl_scan_log "
                "WHERE type='ERROR' GROUP BY component", (since_ms,)):
            row = conn.execute(
                "SELECT message FROM tbl_scan_log WHERE component=? AND type='ERROR' AND generated=? LIMIT 1",
                (comp, last)).fetchone()
            out[comp] = {'errors': total or 0, 'errors7d': recent or 0, 'lastError': (row[0] if row else '')[:300],
                         'lastErrorAt': int((last or 0) / 1000)}
        for mod, n, last in conn.execute("SELECT module, COUNT(*), MAX(generated) FROM tbl_scan_results GROUP BY module"):
            out.setdefault(mod, {}).update({'events': n or 0, 'lastEventAt': int((last or 0) / 1000)})
    finally:
        conn.close()
    return out


def scan_stats(db_path: str, now=None) -> dict:
    """{module: {errors, errors7d, lastError, lastErrorAt, events, lastEventAt}}; cached briefly."""
    now = now or time.time()
    with _LOCK:
        hit = _CACHE.get(db_path)
        if hit and now - hit[0] < TTL:
            return hit[1]
    try:
        data = _query(db_path, now)
    except Exception:
        data = {}
    with _LOCK:
        _CACHE[db_path] = (now, data)
    return data


def blank() -> dict:
    return {'errors': 0, 'errors7d': 0, 'lastError': '', 'lastErrorAt': 0, 'events': 0, 'lastEventAt': 0}
