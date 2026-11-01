"""Per-module API usage tracking and limits.

Every HTTP request a module makes through ``SpiderFootHttp.fetchUrl`` is
attributed to that module (via a thread-local set by ``SpiderFootPlugin.poolExecute``),
counted per UTC day in ``tbl_module_usage`` and, if the user configured limits
for the module, throttled or blocked.

Limits live in the GLOBAL config key ``_module_limits`` (JSON):

    {"sfp_shodan": {"per_second": 1, "per_day": 100, "total": 1000,
                    "reset_date": "2026-12-01", "reset_every": "monthly",
                    "period_start": "2026-11-01", "enforce": true}}

* ``per_second``  - minimum spacing between calls (calls are delayed, never dropped)
* ``per_day``     - calls per UTC day; further calls are blocked
* ``total``       - calls per period (since ``period_start``); further calls are blocked
* ``reset_date``/``reset_every`` - when the period rolls over and how it repeats
* ``enforce``     - false = only display, never delay or block

Scans run in separate processes, so counters are flushed to SQLite every few
seconds and re-read when checking limits.
"""

import atexit
import calendar
import datetime
import json
import logging
import sqlite3
import threading
import time

log = logging.getLogger(__name__)

LIMITS_KEY = '_module_limits'
RESET_EVERY = ('none', 'daily', 'weekly', 'monthly', 'yearly')

_local = threading.local()


def set_module(name):
    """Attribute subsequent HTTP calls on this thread to ``name`` (None to clear)."""
    _local.module = name


def current_module():
    return getattr(_local, 'module', None)


# ---------------------------------------------------------------- limits helpers

def today_utc() -> datetime.date:
    return datetime.datetime.now(datetime.timezone.utc).date()


def _parse_date(value):
    try:
        return datetime.date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def advance(d: datetime.date, every: str) -> datetime.date:
    """Return the next reset date after ``d`` for a repeating period."""
    if every == 'daily':
        return d + datetime.timedelta(days=1)
    if every == 'weekly':
        return d + datetime.timedelta(days=7)
    if every == 'monthly':
        month = d.month % 12 + 1
        year = d.year + (1 if d.month == 12 else 0)
        return d.replace(year=year, month=month, day=min(d.day, calendar.monthrange(year, month)[1]))
    if every == 'yearly':
        try:
            return d.replace(year=d.year + 1)
        except ValueError:  # 29 Feb
            return d.replace(year=d.year + 1, day=28)
    return d


def normalize_limits(raw: dict) -> dict:
    """Validate user supplied limits. Raises ValueError with a readable message."""
    raw = raw or {}
    out = {}

    def number(key, kind):
        v = raw.get(key)
        if v in (None, ''):
            return 0
        try:
            n = kind(v)
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be a number") from None
        if n < 0:
            raise ValueError(f"{key} must not be negative")
        return n

    out['per_second'] = number('per_second', float)
    out['per_day'] = number('per_day', int)
    out['total'] = number('total', int)

    reset_date = raw.get('reset_date') or ''
    if reset_date and _parse_date(reset_date) is None:
        raise ValueError("reset_date must be YYYY-MM-DD")
    out['reset_date'] = reset_date

    every = raw.get('reset_every') or 'none'
    if every not in RESET_EVERY:
        raise ValueError("reset_every must be one of " + ", ".join(RESET_EVERY))
    out['reset_every'] = every

    start = raw.get('period_start') or ''
    if start and _parse_date(start) is None:
        raise ValueError("period_start must be YYYY-MM-DD")
    out['period_start'] = start
    out['enforce'] = bool(raw.get('enforce', True))
    return out


def roll_period(limits: dict, today: datetime.date) -> dict:
    """Return a copy of ``limits`` with the period rolled forward if the reset date passed."""
    lim = dict(limits)
    reset = _parse_date(lim.get('reset_date'))
    if reset is None or today < reset:
        return lim
    every = lim.get('reset_every', 'none')
    if every == 'none':
        lim['period_start'] = reset.isoformat()
        lim['reset_date'] = ''
        return lim
    while reset <= today:
        lim['period_start'] = reset.isoformat()
        reset = advance(reset, every)
    lim['reset_date'] = reset.isoformat()
    return lim


# ---------------------------------------------------------------- storage

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS tbl_module_usage ("
    " module TEXT NOT NULL, day TEXT NOT NULL, calls INTEGER DEFAULT 0,"
    " errors INTEGER DEFAULT 0, limited INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0,"
    " PRIMARY KEY (module, day))",
    "CREATE TABLE IF NOT EXISTS tbl_module_ratelimit ("
    " module TEXT PRIMARY KEY, rl_limit INTEGER, rl_remaining INTEGER, rl_reset TEXT, seen INTEGER)",
)


def connect(db_path):
    conn = sqlite3.connect(db_path, timeout=10)
    for stmt in SCHEMA:
        conn.execute(stmt)
    return conn


def load_limits(conn) -> dict:
    row = conn.execute("SELECT val FROM tbl_config WHERE scope='GLOBAL' AND opt=?", (LIMITS_KEY,)).fetchone()
    try:
        data = json.loads(row[0]) if row and row[0] else {}
    except ValueError:
        data = {}
    return data if isinstance(data, dict) else {}


def summarize(conn) -> dict:
    """Aggregate stored usage into {module: {day: (calls, errors, limited, blocked)}}."""
    out = {}
    for m, day, c, e, l, b in conn.execute("SELECT module, day, calls, errors, limited, blocked FROM tbl_module_usage"):
        out.setdefault(m, {})[day] = (c or 0, e or 0, l or 0, b or 0)
    return out


def load_ratelimits(conn) -> dict:
    return {m: {'limit': lim, 'remaining': rem, 'reset': rst, 'seen': seen}
            for m, lim, rem, rst, seen in conn.execute(
                "SELECT module, rl_limit, rl_remaining, rl_reset, seen FROM tbl_module_ratelimit")}


# ---------------------------------------------------------------- header parsing

_RL_LIMIT = ('x-ratelimit-limit', 'ratelimit-limit', 'x-rate-limit-limit', 'x-ratelimit-limit-day',
             'x-ratelimit-limit-minute', 'x-ratelimit-requests-limit')
_RL_REMAIN = ('x-ratelimit-remaining', 'ratelimit-remaining', 'x-rate-limit-remaining', 'x-ratelimit-remaining-day',
              'x-ratelimit-remaining-minute', 'x-ratelimit-requests-remaining')
_RL_RESET = ('x-ratelimit-reset', 'ratelimit-reset', 'x-rate-limit-reset', 'retry-after')


def _first_int(headers, names):
    for n in names:
        v = headers.get(n)
        if v is None:
            continue
        try:
            return int(str(v).split(',')[0].split(';')[0].strip())
        except ValueError:
            continue
    return None


def parse_ratelimit_headers(headers):
    """Extract (limit, remaining, reset) from common rate-limit response headers."""
    if not headers:
        return None
    lim = _first_int(headers, _RL_LIMIT)
    rem = _first_int(headers, _RL_REMAIN)
    rst = next((str(headers[n]) for n in _RL_RESET if headers.get(n)), None)
    if lim is None and rem is None:
        return None
    return {'limit': lim, 'remaining': rem, 'reset': rst}


# ---------------------------------------------------------------- tracker

class Tracker:
    """Counts calls, flushes them to SQLite and enforces configured limits."""

    FLUSH_EVERY = 5
    LIMITS_TTL = 30
    COUNTS_TTL = 5

    def __init__(self, db_path):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._pending = {}      # (module, day) -> [calls, errors, limited, blocked]
        self._ratelimit = {}
        self._next_slot = {}
        self._limits = {}
        self._limits_at = 0.0
        self._counts = {}       # module -> {'at', 'today', 'period', 'day', 'start'}
        self._warned = set()
        self._flusher = None
        atexit.register(self.flush)

    # -- internals
    def _bump(self, module, idx, n=1):
        key = (module, today_utc().isoformat())
        with self._lock:
            self._pending.setdefault(key, [0, 0, 0, 0])[idx] += n

    def _ensure_flusher(self):
        if self._flusher is None:
            self._flusher = threading.Thread(target=self._flush_loop, name='usage-flush', daemon=True)
            self._flusher.start()

    def _flush_loop(self):
        while True:
            time.sleep(self.FLUSH_EVERY)
            self.flush()

    def flush(self):
        with self._lock:
            pending, self._pending = self._pending, {}
            rl, self._ratelimit = self._ratelimit, {}
        if not pending and not rl:
            return
        try:
            conn = connect(self.db_path)
            try:
                for (m, day), (c, e, lim, b) in pending.items():
                    conn.execute(
                        "INSERT INTO tbl_module_usage (module, day, calls, errors, limited, blocked) VALUES (?,?,?,?,?,?) "
                        "ON CONFLICT(module, day) DO UPDATE SET calls=calls+excluded.calls, errors=errors+excluded.errors, "
                        "limited=limited+excluded.limited, blocked=blocked+excluded.blocked", (m, day, c, e, lim, b))
                for m, d in rl.items():
                    conn.execute("REPLACE INTO tbl_module_ratelimit (module, rl_limit, rl_remaining, rl_reset, seen) VALUES (?,?,?,?,?)",
                                 (m, d['limit'], d['remaining'], d['reset'], int(time.time())))
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            log.debug("Could not flush API usage: %s", e)
            with self._lock:  # put it back so it is not lost
                for k, v in pending.items():
                    cur = self._pending.setdefault(k, [0, 0, 0, 0])
                    for i in range(4):
                        cur[i] += v[i]

    def _limits_for(self, module):
        now = time.time()
        if now - self._limits_at > self.LIMITS_TTL:
            try:
                conn = connect(self.db_path)
                try:
                    self._limits = load_limits(conn)
                finally:
                    conn.close()
            except Exception as e:
                log.debug("Could not load API limits: %s", e)
            self._limits_at = now
        lim = self._limits.get(module)
        return roll_period(lim, today_utc()) if lim else None

    def _count(self, module, lim):
        """Calls made today and in the current period (stored + not yet re-read)."""
        now = time.time()
        today = today_utc().isoformat()
        start = lim.get('period_start') or ''
        c = self._counts.get(module)
        if c is None or now - c['at'] > self.COUNTS_TTL or c['day'] != today or c['start'] != start:
            self.flush()
            t = p = 0
            try:
                conn = connect(self.db_path)
                try:
                    for day, calls in conn.execute("SELECT day, calls FROM tbl_module_usage WHERE module=?", (module,)):
                        if day == today:
                            t += calls
                        if not start or day >= start:
                            p += calls
                finally:
                    conn.close()
            except Exception as e:
                log.debug("Could not read API usage: %s", e)
            c = self._counts[module] = {'at': now, 'today': t, 'period': p, 'day': today, 'start': start}
        return c

    # -- public API used by SpiderFootHttp
    def before(self, module):
        """Reserve a call. Returns (allowed, reason). May sleep to honour per_second."""
        self._ensure_flusher()
        lim = self._limits_for(module)
        wait = 0.0
        if lim and lim.get('enforce', True):
            counts = self._count(module, lim)
            if lim.get('per_day') and counts['today'] >= lim['per_day']:
                self._bump(module, 3)
                return False, f"daily limit of {lim['per_day']} calls reached"
            if lim.get('total') and counts['period'] >= lim['total']:
                self._bump(module, 3)
                return False, f"limit of {lim['total']} calls for this period reached"
            counts['today'] += 1
            counts['period'] += 1
            if lim.get('per_second'):
                interval = 1.0 / lim['per_second']
                with self._lock:
                    now = time.monotonic()
                    slot = max(now, self._next_slot.get(module, 0.0))
                    self._next_slot[module] = slot + interval
                    wait = slot - now
        self._bump(module, 0)
        if wait > 0:
            time.sleep(wait)
        return True, ''

    def after(self, module, res):
        code = (res or {}).get('code')
        try:
            n = int(code)
        except (TypeError, ValueError):
            n = None
        if n == 429:
            self._bump(module, 2)
        elif n is None or (n >= 400 and n != 404):
            self._bump(module, 1)
        rl = parse_ratelimit_headers((res or {}).get('headers'))
        if rl:
            with self._lock:
                self._ratelimit[module] = rl

    def warn_once(self, module, reason):
        if (module, reason) not in self._warned:
            self._warned.add((module, reason))
            log.warning("API usage limit: %s blocked - %s", module, reason)


_trackers = {}
_trackers_lock = threading.Lock()


def get_tracker(db_path):
    with _trackers_lock:
        t = _trackers.get(db_path)
        if t is None:
            t = _trackers[db_path] = Tracker(db_path)
        return t
