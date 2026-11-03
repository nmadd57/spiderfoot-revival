# -*- coding: utf-8 -*-
# -----------------------------------------------------------------
# Name:         api
# Purpose:      Flask API blueprint — faithful port of sfwebui.py
#               CherryPy endpoints so sfcli.py and external callers
#               keep working with identical JSON shapes.
# -----------------------------------------------------------------

import csv
import html
import json
import threading
import logging
import multiprocessing as mp
import re
import sqlite3
import string
import time
import uuid
from copy import deepcopy
from io import BytesIO, StringIO
from operator import itemgetter

from flask import Blueprint, Response, current_app, jsonify, request

import openpyxl

from spiderfoot import SpiderFootDb, SpiderFootHelpers, __version__
from spiderfoot.services import access, identity, relevance_job, relevance_view, report_job, scan_listing
from spiderfoot.services.preset_service import serialize_preset, validate_module_names

api_bp = Blueprint('api', __name__)

log = logging.getLogger(f"spiderfoot.{__name__}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_config():
    """Return the live SF config dict stored on the app."""
    return current_app.config['SF_CONFIG']


def get_default_config():
    """Return the original (default) SF config snapshot."""
    return current_app.config.get('SF_DEFAULT_CONFIG', get_config())


def get_db():
    """Create a SpiderFootDb handle using the current config."""
    return SpiderFootDb(get_config())


def get_logging_queue():
    """Return the multiprocessing logging queue."""
    return current_app.config.get('SF_LOGGING_QUEUE')


def jsonify_error(status, message):
    """Return a JSON error response matching the CherryPy format."""
    resp = jsonify({'error': {'http_status': status, 'message': message}})
    resp.status_code = int(status)
    return resp


def clean_user_input(input_list):
    """Sanitise user input (mirrors SpiderFootWebUi.cleanUserInput)."""
    ret = []
    for item in input_list:
        if not item:
            ret.append('')
            continue
        c = html.escape(item, True)
        ret.append(c)
    return ret


def _safe_filename(name: str) -> str:
    """Sanitize a string for use in Content-Disposition filename."""
    if not name:
        return "SpiderFoot"
    return re.sub(r'[^\w\-.]', '_', name)[:100]


_SENSITIVE_OPT_PATTERNS = ('api_key', 'apikey', 'password', 'secret', 'token', 'passphrase')


def _redact_secrets(opts: dict) -> dict:
    """Mask secret config keys before sending to clients."""
    REDACTED = ('_ai_openrouter_key', '_rel_embeddings_apikey')
    out = dict(opts)
    for k in REDACTED:
        if k in out and out[k]:
            out[k] = '********'
    return out


def _csv_safe(value) -> str:
    """Prevent CSV formula injection by prefixing dangerous characters."""
    s = str(value) if value is not None else ''
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + s
    return s


class _Relevance:
    """Relevance of the scans an export or search touches, loaded once per scan and only when it has any."""

    def __init__(self, dbh, include_unrelated: bool):
        self.dbh = dbh
        self.include = include_unrelated
        self._views = {}

    def view(self, scan_id):
        if scan_id not in self._views:
            try:
                self._views[scan_id] = relevance_view.View(self.dbh, scan_id)
            except Exception:
                self._views[scan_id] = None
        return self._views[scan_id]

    def skip(self, scan_id, h) -> bool:
        v = self.view(scan_id)
        return bool(v and v.hidden(h, self.include))

    def cols(self, scan_id, h):
        """(label, score) for an event, or ('', '') when the scan has no relevance data."""
        v = self.view(scan_id)
        if not v or not v.has_data or h not in v.map:
            return '', ''
        r = v.map[h]
        return r[1], round(r[0], 2)


def _include_unrelated() -> bool:
    return relevance_view.truthy(request.values.get('include_unrelated', ''))


def _search_scope(scan_id):
    """(refusal, allowed) for a search: administrators search everything; others only scans they can view.

    ``refusal`` is a response when the named scan is not viewable; ``allowed`` is the set of scan ids a
    search across all scans may return (None: no limit).
    """
    user = identity.current_user()
    if user is None or user.is_admin:
        return None, None
    dbh, settings = get_db(), identity.request_settings()
    if scan_id:
        if not access.can(user, scan_id, 'view', dbh, settings.unowned_visible):
            return jsonify_error('404', 'Scan not found.'), None
        return None, None
    return None, access.visible_scans(user, dbh, settings.unowned_visible)


def search_base(id=None, eventType=None, value=None, allowed=None, include_unrelated=True):
    """Core search logic (mirrors SpiderFootWebUi.searchBase).

    ``allowed`` limits the results to those scan ids (None: no limit). Rows end with the relevance label and score
    of the finding; ``include_unrelated=False`` leaves out what was scored as unrelated.
    """
    retdata = []

    if not id and not eventType and not value:
        return retdata

    if not value:
        value = ''

    regex = ""
    if value.startswith("/") and value.endswith("/"):
        regex = value[1:len(value) - 1]
        value = ""

    value = value.replace('*', '%')
    if value in [None, ""] and regex in [None, ""]:
        value = "%"
        regex = ""

    dbh = get_db()
    criteria = {
        'scan_id': id or '',
        'type': eventType or '',
        'value': value or '',
        'regex': regex or '',
    }

    try:
        data = dbh.search(criteria)
    except Exception:
        return retdata

    rel = _Relevance(dbh, include_unrelated)
    for row in data:
        if allowed is not None and row[12] not in allowed:
            continue
        if rel.skip(row[12], row[8]):
            continue
        lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
        escapeddata = html.escape(row[1])
        escapedsrc = html.escape(row[2])
        retdata.append([lastseen, escapeddata, escapedsrc,
                        row[3], row[5], row[6], row[7], row[8], row[10],
                        row[11], row[4], row[13], row[14], *rel.cols(row[12], row[8])])

    return retdata


def build_excel(data, column_names, sheet_name_index=0):
    """Build an Excel workbook from data rows (mirrors buildExcel)."""
    row_nums = dict()
    workbook = openpyxl.Workbook()
    default_sheet = workbook.active
    column_names.pop(sheet_name_index)
    allowed_sheet_chars = string.ascii_uppercase + string.digits + '_'

    for row in data:
        sheet_name = "".join(
            [c for c in str(row.pop(sheet_name_index)) if c.upper() in allowed_sheet_chars]
        )
        try:
            sheet = workbook[sheet_name]
        except KeyError:
            workbook.create_sheet(sheet_name)
            sheet = workbook[sheet_name]
            for col_num, column_title in enumerate(column_names, 1):
                cell = sheet.cell(row=1, column=col_num)
                cell.value = column_title
            row_nums[sheet_name] = 2

        for col_num, cell_value in enumerate(row, 1):
            cell = sheet.cell(row=row_nums[sheet_name], column=col_num)
            cell.value = cell_value

        row_nums[sheet_name] += 1

    if row_nums:
        workbook.remove(default_sheet)

    workbook._sheets.sort(key=lambda ws: ws.title)

    with BytesIO() as f:
        workbook.save(f)
        f.seek(0)
        return f.read()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@api_bp.route('/ping')
def ping():
    """CLI connectivity check."""
    return jsonify(["SUCCESS", __version__])


# Tables the SQL console may never read (tbl_config holds API keys).
_QUERY_DENIED_TABLES = frozenset({'tbl_config'})
_QUERY_DENIED_FUNCTIONS = frozenset({'load_extension'})


def query_authorizer(action, arg1, arg2, dbname, source):
    """SQLite authorizer for the read-only SQL console.

    Allows only SELECT statements (and the column reads, plain functions and recursive CTEs they
    need). Reads of ``tbl_config`` and the ``load_extension`` function are denied, as is every other
    action (ATTACH, PRAGMA, INSERT, UPDATE, DELETE, DDL, transactions, ...).
    """
    import sqlite3

    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        if str(arg1 or '').lower() in _QUERY_DENIED_TABLES:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION:
        if str(arg2 or '').lower() in _QUERY_DENIED_FUNCTIONS:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    if action == getattr(sqlite3, 'SQLITE_RECURSIVE', 33):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


@api_bp.route('/query', methods=['POST'])
def query():
    """Run a SELECT query against the database (CLI).

    Uses a read-only SQLite connection. Rejects semicolons and non-SELECTs.
    """
    import sqlite3

    q = request.values.get('query', '').strip()

    if not q:
        return jsonify_error('400', "Invalid query.")

    if not q.lower().startswith("select"):
        return jsonify_error('400', "Only SELECT queries are allowed.")

    if ';' in q:
        return jsonify_error('400', "Semicolons are not allowed in queries.")

    q_lower = q.lower()
    for keyword in ('attach', 'pragma', 'load_extension'):
        if re.search(r'\b' + keyword + r'\b', q_lower):
            return jsonify_error('400', f"'{keyword}' is not permitted.")
    for table in ('tbl_config',):
        if table in q_lower:
            return jsonify_error('400', f"Access to {table} is not permitted via this endpoint.")

    # Use the same database path as the main connection
    db_path = current_app.config.get('SF_CONFIG', {}).get('__database', '')
    if not db_path:
        return jsonify_error('500', "Database not configured.")

    try:
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        try:
            conn.set_authorizer(query_authorizer)
            cursor = conn.execute(q)
            data = cursor.fetchall()
            column_names = [c[0] for c in cursor.description]
            return jsonify([dict(zip(column_names, row)) for row in data])
        finally:
            conn.close()
    except Exception:
        current_app.logger.warning(f"Query endpoint error for query: {q}", exc_info=True)
        return jsonify_error('500', "Query failed.")


# -- Scan list ---------------------------------------------------------------

@api_bp.route('/scanlist')
def scanlist():
    """List all scans."""
    dbh = get_db()
    user, settings = identity.current_user(), identity.request_settings()
    data = access.filter_scan_list(user, dbh.scanInstanceList(), dbh, settings.unowned_visible)
    info = scan_listing.annotate([r[0] for r in data], user, dbh, settings)
    retdata = []

    for row in data:
        created = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[3]))
        riskmatrix = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        try:
            correlations = dbh.scanCorrelationSummary(row[0], by="risk")
            if correlations:
                for c in correlations:
                    riskmatrix[c[0]] = c[1]
        except Exception:
            pass

        if row[4] == 0:
            started = "Not yet"
        else:
            started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[4]))

        if row[5] == 0:
            finished = "Not yet"
        else:
            finished = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[5]))

        # owner name and your access level come after the columns the command line client reads
        retdata.append([row[0], row[1], row[2], created, started, finished, row[6], row[7], riskmatrix,
                        info[row[0]]['owner'], info[row[0]]['level']])

    return jsonify(retdata)


# -- Scan status -------------------------------------------------------------

@api_bp.route('/scanstatus', methods=['GET', 'POST'])
def scanstatus():
    """Basic scan info including status and risk matrix."""
    id = request.values.get('id', '')
    dbh = get_db()
    data = dbh.scanInstanceGet(id)

    if not data:
        return jsonify([])

    created = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data[2])) if data[2] else "Not yet"
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data[3])) if data[3] else "Not yet"
    ended = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data[4])) if data[4] else "Not yet"
    riskmatrix = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    try:
        correlations = dbh.scanCorrelationSummary(id, by="risk")
        if correlations:
            for c in correlations:
                riskmatrix[c[0]] = c[1]
    except Exception:
        pass

    return jsonify([data[0], data[1], created, started, ended, data[5], riskmatrix])


# -- Scan summary ------------------------------------------------------------

@api_bp.route('/scansummary', methods=['GET', 'POST'])
def scansummary():
    """Summary of scan results."""
    id = request.values.get('id', '')
    by = request.values.get('by', '')
    retdata = []

    dbh = get_db()

    try:
        scandata = dbh.scanResultSummary(id, by)
    except Exception:
        return jsonify(retdata)

    try:
        statusdata = dbh.scanInstanceGet(id)
    except Exception:
        return jsonify(retdata)

    for row in scandata:
        if row[0] == "ROOT":
            continue
        lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[2]))
        retdata.append([row[0], row[1], lastseen, row[3], row[4], statusdata[5]])

    return jsonify(retdata)


# -- Scan correlations -------------------------------------------------------

@api_bp.route('/scancorrelations', methods=['GET', 'POST'])
def scancorrelations():
    """Correlation results from a scan."""
    id = request.values.get('id', '')
    retdata = []

    dbh = get_db()
    try:
        corrdata = dbh.scanCorrelationList(id)
    except Exception:
        return jsonify(retdata)

    for row in corrdata:
        retdata.append([row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7]])

    return jsonify(retdata)


# -- Scan event results ------------------------------------------------------

@api_bp.route('/scaneventresults', methods=['GET', 'POST'])
def scaneventresults():
    """All event results for a scan."""
    id = request.values.get('id', '')
    eventType = request.values.get('eventType', None)
    # Coerce to a real bool — request.values are strings, and "0"/"false" are
    # truthy as strings. Pass as keyword: scanResultEvent's 3rd positional is
    # srcModule, not filterFp (signature gained params in the middle).
    filterfp = str(request.values.get('filterfp', '')).lower() in ('1', 'true', 'yes')
    correlationId = request.values.get('correlationId', None)
    retdata = []

    dbh = get_db()

    if not eventType:
        eventType = 'ALL'

    try:
        data = dbh.scanResultEvent(id, eventType, filterFp=filterfp, correlationId=correlationId)
    except Exception:
        return jsonify(retdata)

    rel = _Relevance(dbh, _include_unrelated())
    for row in data:
        if rel.skip(id, row[8]):
            continue
        lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
        retdata.append([
            lastseen,
            html.escape(row[1]),
            html.escape(row[2]),
            row[3],
            row[5],
            row[6],
            row[7],
            row[8],
            row[13],
            row[14],
            row[4],
            *rel.cols(id, row[8])
        ])

    return jsonify(retdata)


# -- Scan event results unique -----------------------------------------------

@api_bp.route('/scaneventresultsunique', methods=['GET', 'POST'])
def scaneventresultsunique():
    """Unique event results for a scan."""
    id = request.values.get('id', '')
    eventType = request.values.get('eventType', '')
    filterfp = request.values.get('filterfp', False)

    dbh = get_db()
    retdata = []

    try:
        data = dbh.scanResultEventUnique(id, eventType, filterfp)
    except Exception:
        return jsonify(retdata)

    for row in data:
        escaped = html.escape(row[0])
        retdata.append([escaped, row[1], row[2]])

    return jsonify(retdata)


# -- Scan options ------------------------------------------------------------

@api_bp.route('/scanopts', methods=['GET', 'POST'])
def scanopts():
    """Configuration used for the specified scan."""
    id = request.values.get('id', '')
    config = get_config()
    dbh = get_db()
    ret = dict()

    meta = dbh.scanInstanceGet(id)
    if not meta:
        return jsonify(ret)

    if meta[3] != 0:
        started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(meta[3]))
    else:
        started = "Not yet"

    if meta[4] != 0:
        finished = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(meta[4]))
    else:
        finished = "Not yet"

    ret['meta'] = [meta[0], meta[1], meta[2], started, finished, meta[5]]
    ret['config'] = dbh.scanConfigGet(id)
    ret['configdesc'] = dict()
    for key in list(ret['config'].keys()):
        if ':' not in key:
            globaloptdescs = config.get('__globaloptdescs__')
            if globaloptdescs:
                ret['configdesc'][key] = globaloptdescs.get(key, f"{key} (legacy)")
        else:
            [modName, modOpt] = key.split(':')
            if modName not in list(config.get('__modules__', {}).keys()):
                continue
            if modOpt not in list(config['__modules__'][modName].get('optdescs', {}).keys()):
                continue
            ret['configdesc'][key] = config['__modules__'][modName]['optdescs'][modOpt]

    return jsonify(ret)


# -- Scan log ----------------------------------------------------------------

@api_bp.route('/scanlog', methods=['GET', 'POST'])
def scanlog():
    """Scan log data."""
    id = request.values.get('id', '')
    limit = request.values.get('limit', None)
    rowId = request.values.get('rowId', None)
    reverse = request.values.get('reverse', None)

    dbh = get_db()
    retdata = []

    try:
        data = dbh.scanLogs(id, limit, rowId, reverse)
    except Exception:
        return jsonify(retdata)

    for row in data:
        generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0] / 1000))
        retdata.append([generated, row[1], row[2], html.escape(row[3]), row[4]])

    return jsonify(retdata)


# -- Scan errors -------------------------------------------------------------

@api_bp.route('/scanerrors', methods=['GET', 'POST'])
def scanerrors():
    """Scan error data."""
    id = request.values.get('id', '')
    # scanErrors() requires an int limit (0 == no limit). request.values are
    # strings/None, which would raise TypeError inside scanErrors and get
    # swallowed below — leaving the endpoint permanently returning [].
    try:
        limit = int(request.values.get('limit', 0))
    except (TypeError, ValueError):
        limit = 0

    dbh = get_db()
    retdata = []

    try:
        data = dbh.scanErrors(id, limit)
    except Exception:
        return jsonify(retdata)

    for row in data:
        generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0] / 1000))
        retdata.append([generated, row[1], html.escape(str(row[2]))])

    return jsonify(retdata)


# -- Scan delete -------------------------------------------------------------

@api_bp.route('/scandelete', methods=['POST'])
def scandelete():
    """Delete scan(s)."""
    id = request.values.get('id', '')

    if not id:
        return jsonify_error('404', "No scan specified")

    dbh = get_db()
    ids = id.split(',')

    for scan_id in ids:
        res = dbh.scanInstanceGet(scan_id)
        if not res:
            return jsonify_error('404', f"Scan {scan_id} does not exist")
        if res[5] in ["RUNNING", "STARTING", "STARTED"]:
            return jsonify_error('400', f"Scan {scan_id} is {res[5]}. You cannot delete running scans.")

    for scan_id in ids:
        dbh.scanInstanceDelete(scan_id)

    return jsonify("")


# -- Stop scan ---------------------------------------------------------------

@api_bp.route('/stopscan', methods=['POST'])
def stopscan():
    """Stop a running scan."""
    id = request.values.get('id', '')

    if not id:
        return jsonify_error('404', "No scan specified")

    dbh = get_db()
    ids = id.split(',')

    for scan_id in ids:
        res = dbh.scanInstanceGet(scan_id)
        if not res:
            return jsonify_error('404', f"Scan {scan_id} does not exist")

        scan_status = res[5]

        if scan_status == "FINISHED":
            return jsonify_error('400', f"Scan {scan_id} has already finished.")
        if scan_status == "ABORTED":
            return jsonify_error('400', f"Scan {scan_id} has already aborted.")
        if scan_status not in ["RUNNING", "STARTING"]:
            return jsonify_error('400', f"The running scan is currently in the state '{scan_status}', please try again later or restart SpiderFoot.")

    for scan_id in ids:
        dbh.scanInstanceSet(scan_id, status="ABORT-REQUESTED")

    return jsonify("")


# -- Module enable/disable ---------------------------------------------------

@api_bp.route('/modulestate', methods=['POST'])
def modulestate():
    """Enable or disable modules globally.

    JSON body: {"modules": ["sfp_x", ...], "enabled": true|false,
                "kind": "disabled" (default) | "default_off"}

    ``kind`` "default_off" marks modules that stay available but are not
    pre-selected on the New Scan page; here ``enabled`` means "on by default".
    """
    from spiderfoot.services import module_state

    body = request.get_json(silent=True) or {}
    if body.get('kind') == 'auto_disable':
        from spiderfoot.services import auto_disable
        get_db().configSet({auto_disable.KEY: '1' if body.get('enabled') else '0'})
        return jsonify(["SUCCESS", bool(body.get('enabled'))])

    names = body.get('modules')
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        return jsonify(["ERROR", "modules must be a list of module names"]), 400
    known = set(get_config().get('__modules__', {}))
    names = [n for n in names if n in known and not n.startswith('sfp__stor_')]

    key = module_state.KINDS.get(body.get('kind', 'disabled'))
    if key is None:
        return jsonify(["ERROR", "kind must be 'disabled' or 'default_off'"]), 400

    dbh = get_db()
    current = module_state.get_names(dbh, key)
    if body.get('enabled'):
        current -= set(names)
    else:
        current |= set(names)
    module_state.set_names(dbh, current, key)
    return jsonify(["SUCCESS", sorted(current)])


# -- API usage tracking, limits and key tests --------------------------------

def _usage_conn():
    from spiderfoot.services import usage
    return usage.connect(get_config()['__database'])


def _provider_info():
    try:
        from spiderfoot.services import api_quota
        return {m: p.opts for m, p in api_quota.PROVIDERS.items()}
    except Exception:
        return {}


QUOTA_CACHE_KEY = '_module_quota_cache'
QUOTA_FIELDS = ('ok', 'valid', 'message', 'used', 'limit', 'remaining', 'unit', 'resets', 'plan')


def _quota_cache():
    try:
        data = json.loads(get_db().configGet().get(QUOTA_CACHE_KEY) or '{}')
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _remember_quota(module, result):
    """Keep the last vendor quota result so the usage list can show it without re-querying."""
    cache = _quota_cache()
    cache[module] = {k: result.get(k) for k in QUOTA_FIELDS}
    cache[module]['at'] = int(time.time())
    get_db().configSet({QUOTA_CACHE_KEY: json.dumps(cache, sort_keys=True)})


def _save_limits(limits):
    dbh = get_db()
    from spiderfoot.services import usage
    dbh.configSet({usage.LIMITS_KEY: json.dumps(limits, sort_keys=True)})


@api_bp.route('/usage')
def usage_list():
    """Per-module API usage, limits and vendor rate-limit info."""
    from spiderfoot.blueprints.ui import _build_modules_data
    from spiderfoot.services import usage

    today = usage.today_utc()
    mods, _cats = _build_modules_data(include_disabled=True)
    conn = _usage_conn()
    try:
        stored = usage.summarize(conn)
        limits = usage.load_limits(conn)
        rates = usage.load_ratelimits(conn)
        issues = usage.load_issues(conn)
    finally:
        conn.close()
    providers = _provider_info()
    quotas = _quota_cache()
    try:
        from spiderfoot.services import api_quota
        costly = api_quota.COSTS_CALL
    except Exception:
        costly = set()

    out = []
    for name, m in mods.items():
        days = stored.get(name, {})
        lim = usage.roll_period(usage.normalize_limits(limits.get(name, {})), today)
        start = lim.get('period_start') or ''
        total = sum(v[0] for v in days.values())
        out.append({
            'id': name,
            'name': m['name'],
            'pricing': m['pricing'],
            'broken': m.get('broken', False),
            'requiresKey': m['requiresKey'],
            'keyConfigured': m['keyConfigured'],
            'calls_today': days.get(today.isoformat(), (0, 0, 0, 0))[0],
            'calls_period': sum(v[0] for d, v in days.items() if not start or d >= start),
            'calls_total': total,
            'errors': sum(v[1] for v in days.values()),
            'limited': sum(v[2] for v in days.values()),
            'blocked': sum(v[3] for v in days.values()),
            'last_day': max(days) if days else '',
            'vendor_rate': rates.get(name),
            'limits': lim,
            'has_limits': name in limits,
            'provider_opts': providers.get(name),
            'auto_check': name in providers and name not in costly,
            'quota': quotas.get(name),
            'key_issue': issues.get(name) if (m['requiresKey'] and m['keyConfigured']) else None,
        })
    return jsonify({'today': today.isoformat(), 'modules': out})


@api_bp.route('/usage/limits', methods=['POST'])
def usage_set_limits():
    """Set (or clear) the limits for one module."""
    from spiderfoot.services import usage

    body = request.get_json(silent=True) or {}
    module = body.get('module', '')
    if module not in get_config().get('__modules__', {}):
        return jsonify(["ERROR", "unknown module"]), 400
    try:
        lim = usage.normalize_limits(body.get('limits') or {})
    except ValueError:
        log.warning("Invalid usage limits for %s", module, exc_info=True)
        return jsonify(["ERROR", "Invalid limits: check the numbers and dates."]), 400

    conn = _usage_conn()
    try:
        limits = usage.load_limits(conn)
    finally:
        conn.close()

    if not (lim['per_second'] or lim['per_day'] or lim['total'] or lim['reset_date']):
        limits.pop(module, None)
    else:
        if (lim['total'] or lim['reset_date']) and not lim['period_start']:
            lim['period_start'] = usage.today_utc().isoformat()
        limits[module] = lim
    _save_limits(limits)
    return jsonify(["SUCCESS", limits.get(module)])


@api_bp.route('/modulesettings')
def module_settings_data():
    """All modules with options (secrets masked), status and key problems, for Settings -> Modules."""
    from spiderfoot.blueprints.ui import _build_module_settings
    return jsonify(_build_module_settings())


@api_bp.route('/ai/test', methods=['POST'])
def ai_test():
    """Test the AI endpoint with the values on the form: list models and send a tiny chat request.

    JSON body: {"base_url": "", "key": "", "model": ""}. A masked/empty key falls back to the saved one.
    """
    from spiderfoot.services import ai_service

    body = request.get_json(silent=True) or {}
    cfg = get_config()
    key = str(body.get('key') or '').strip()
    if not key or key == '********':
        key = cfg.get('_ai_openrouter_key', '') or ''
    base = str(body.get('base_url') if body.get('base_url') is not None else cfg.get('_ai_base_url', '') or '').strip()
    if base and not re.match(r'^https?://', base, re.I):
        return jsonify({"ok": False, "message": "The base URL must start with http:// or https://", "models": [], "modelCount": 0, "chat": None})
    model = str(body['model'] if 'model' in body else cfg.get('_ai_default_model', '') or '')
    return jsonify(ai_service.test_connection(base, key, model))


def _searxng_saved() -> dict:
    return (get_config().get('__modules__', {}).get('sfp_searxng', {}).get('opts')) or {}


@api_bp.route('/searxng/test', methods=['POST'])
def searxng_test():
    """Test a SearXNG instance with the form values (saved or not); a masked auth header falls back to the saved one.

    JSON body: the SearXNG module's connection options.
    """
    from sflib import SpiderFoot
    from spiderfoot.services import searxng

    body = request.get_json(silent=True) or {}
    saved = _searxng_saved()
    values = {k: body.get(k, saved.get(k)) for k in ('instance_url', 'auth_header', 'verify_ssl', 'categories', 'engines',
                                                     'language', 'safesearch', 'time_range')}
    if str(values.get('auth_header') or '').strip() in ('', '********'):
        values['auth_header'] = saved.get('auth_header', '')
    if isinstance(values.get('verify_ssl'), str):
        values['verify_ssl'] = values['verify_ssl'] not in ('0', 'false', 'False', '')
    for k in ('instance_url', 'categories', 'engines', 'language', 'time_range'):
        values[k] = clean_user_input([str(values.get(k) or '')])[0].strip()
    return jsonify(searxng.test_instance(SpiderFoot(get_config()), values))


@api_bp.route('/embeddings/test', methods=['POST'])
def embeddings_test():
    """Test the embeddings endpoint with the form values (saved or not) and list its models.

    JSON body: {"embeddings_url", "embeddings_apikey", "embeddings_model"}.
    """
    from spiderfoot.services import embeddings

    body = request.get_json(silent=True) or {}
    saved = _searxng_saved()
    key = str(body.get('embeddings_apikey') or '').strip()
    if key in ('', '********'):
        key = saved.get('embeddings_apikey', '') or ''
    url = clean_user_input([str(body.get('embeddings_url') if body.get('embeddings_url') is not None
                                else saved.get('embeddings_url', '') or '')])[0]
    model = body.get('embeddings_model')
    if model is None:
        model = saved.get('embeddings_model', '')
    return jsonify(embeddings.test_connection(url, key, str(model or '')))


_test_locks = {}
_test_sem = threading.BoundedSemaphore(3)


@api_bp.route('/moduletest', methods=['POST'])
def module_test():
    """Run one module against a sample (or the given target) and report what happened.

    JSON body: {"module": "sfp_x", "target": "optional"}
    """
    from sflib import SpiderFoot
    from spiderfoot.services import module_test as mt

    body = request.get_json(silent=True) or {}
    name = str(body.get('module', ''))
    target = clean_user_input([str(body.get('target', '') or '')])[0].strip() or None
    config = get_config()
    if name not in (config.get('__modules__') or {}):
        return jsonify(["ERROR", "Unknown module"]), 404
    lock = _test_locks.setdefault(name, threading.Lock())
    if not lock.acquire(blocking=False):
        return jsonify(["ERROR", "A test of this module is already running"]), 409
    if not _test_sem.acquire(blocking=False):
        lock.release()
        return jsonify(["ERROR", "Too many module tests are running; try again in a moment"]), 429
    try:
        try:
            saved = get_db().configGet()
        except Exception:
            saved = {}
        return jsonify(mt.run_module(name, config, SpiderFoot, target=target, saved=saved, db=get_db()))
    finally:
        _test_sem.release()
        lock.release()


@api_bp.route('/usage/issue/clear', methods=['POST'])
def usage_clear_issue():
    """Dismiss the recorded key problem for a module (or all with module='*')."""
    from spiderfoot.services import usage

    module = (request.get_json(silent=True) or {}).get('module', '')
    conn = _usage_conn()
    try:
        usage.clear_issues(conn, None if module == '*' else [module])
    finally:
        conn.close()
    return jsonify(["SUCCESS", ""])


def _clear_key_issues(modules):
    from spiderfoot.services import usage
    try:
        conn = _usage_conn()
        try:
            usage.clear_issues(conn, list(modules))
        finally:
            conn.close()
    except Exception:
        pass


@api_bp.route('/usage/reset', methods=['POST'])
def usage_reset_period():
    """Start a new counting period for a module now."""
    from spiderfoot.services import usage

    module = (request.get_json(silent=True) or {}).get('module', '')
    if module not in get_config().get('__modules__', {}):
        return jsonify(["ERROR", "unknown module"]), 400
    conn = _usage_conn()
    try:
        limits = usage.load_limits(conn)
    finally:
        conn.close()
    lim = usage.normalize_limits(limits.get(module, {}))
    lim['period_start'] = usage.today_utc().isoformat()
    limits[module] = lim
    _save_limits(limits)
    return jsonify(["SUCCESS", lim])


@api_bp.route('/usage/check', methods=['POST'])
def usage_check():
    """Ask the vendor for quota/key validity; optionally test (and save) new keys.

    JSON body: {"module": "sfp_x", "values": {"api_key": "..."}, "save": false}
    Option values that are omitted or "********" fall back to the saved key.
    """
    from spiderfoot.services import api_quota
    from sflib import SpiderFoot

    body = request.get_json(silent=True) or {}
    module = body.get('module', '')
    provider = api_quota.PROVIDERS.get(module)
    if not provider:
        return jsonify(["ERROR", "No quota checker for this module"]), 400

    config = get_config()
    try:
        saved = get_db().configGet()
    except Exception:
        saved = {}
    defaults = config.get('__modules__', {}).get(module, {}).get('opts', {})
    supplied = body.get('values') or {}
    values, new = {}, {}
    for opt in provider.opts:
        v = supplied.get(opt)
        if isinstance(v, str) and v.strip() and v != '********':
            values[opt] = new[f"{module}:{opt}"] = v.strip()
        else:
            values[opt] = saved.get(f"{module}:{opt}") or defaults.get(opt) or ''

    result = api_quota.check(module, values)
    result['saved'] = False
    if result.get('ok') and result.get('valid') and not new:
        _clear_key_issues([module])
    if not new:  # only remember results for the key that is actually in use
        _remember_quota(module, result)

    if body.get('save') and new and result.get('ok') and result.get('valid'):
        try:
            sf = SpiderFoot(config)
            new_config = sf.configUnserialize(new, deepcopy(config))
            current_app.config['SF_CONFIG'] = new_config
            get_db().configSet(sf.configSerialize(new_config))
            result['saved'] = True
            _remember_quota(module, result)
            _clear_key_issues([module])
        except Exception:
            log.exception("Saving a valid key for %s failed", module)
            result['message'] = "Key is valid but saving failed. See the server log."
    return jsonify(result)


# -- Start scan --------------------------------------------------------------

NAME_TARGET_TYPES = ("COMPANY_NAME", "HUMAN_NAME", "USERNAME", "BITCOIN_ADDRESS")


class ScanStartResult:
    """Outcome of start_scan_core().

    ok          - the scan process was started and registered
    scan_id     - id of the new scan (when ok)
    error       - message for the caller (when not ok)
    status      - HTTP status string for errors that have one ('429'), else ''
    target      - normalised target the scan was started with
    target_type - detected target type
    modules     - module ids the scan was started with (including the storage module)
    dropped     - {module: reason} for modules left out (disabled, auto-disabled, not for private IPs)
    """

    def __init__(self, ok=False, scan_id='', error='', status='', target='', target_type='', modules=None, dropped=None):
        self.ok = ok
        self.scan_id = scan_id
        self.error = error
        self.status = status
        self.target = target
        self.target_type = target_type
        self.modules = modules or []
        self.dropped = dropped or {}


def normalize_target(scantarget, target_type=None):
    """Detect and normalise a scan target (already passed through clean_user_input).

    Returns (target, target_type); (target, None) when the target is not recognised.
    A known ``target_type`` (rerunning a stored scan) skips detection.
    """
    # Detect on the unescaped input: clean_user_input() turns quotes into &quot;
    rawtarget = html.unescape(scantarget).strip()
    targetType = target_type or SpiderFootHelpers.targetTypeFromString(rawtarget)
    if targetType is None and ' ' in rawtarget and '"' not in rawtarget:
        # The UI sends names unquoted ("John Smith", "Acme Widgets LLC")
        targetType = SpiderFootHelpers.targetTypeFromString(f'"{rawtarget}"')
    if targetType is None:
        return scantarget, None
    if targetType in NAME_TARGET_TYPES:
        # Names are data for module queries; keep "&" and "'" (A&B LLC, O'Brien)
        scantarget = SpiderFootHelpers.stripTargetPrefix(rawtarget)
        scantarget = scantarget.replace("\"", "").strip()
    else:
        scantarget = scantarget.strip().lower()
    return scantarget, targetType


def start_scan_core(scanname, scantarget, modulelist='', typelist='', usecase='', config=None, dbh=None,
                    logging_queue=None, target_type=None, owner=None, context='', prune=None, report=None, related=False):
    """Validate the request, pick the modules and spawn the scan process.

    The one implementation behind the /startscan route and the MCP create_scan tool. Needs an
    application context (module availability is read the way the New Scan page reads it).
    ``owner`` is the id of the user who owns the new scan (None: unowned). ``context`` is the optional free
    text / ``key: value`` hints that help tell the target from namesakes, and ``prune`` (None: the setting's
    default) switches the scan-time pruning of unrelated matches. ``report`` (None: the settings decide) asks for a
    written report when the scan ends (True) or not (False). Returns a ScanStartResult; never raises for bad input.
    """
    from sflib import SpiderFoot
    from sfscan import startSpiderFootScanner

    # Rate limit: reject if too many scans are already running
    max_scans = config.get('_maxscans', 10)
    running_scans = dbh.scanInstanceList()
    # scanInstanceList() rows carry the status at index 6 (index 5 is the end time); index 5 is
    # checked as well because callers and tests have passed rows with the status there.
    running_count = sum(
        1 for scan in running_scans
        if any(v in ('RUNNING', 'STARTED', 'STARTING') for v in scan[5:7])
    )
    if running_count >= max_scans:
        return ScanStartResult(
            error=f"Maximum concurrent scans ({max_scans}) reached. Please wait for a running scan to complete.",
            status='429')

    scanname = clean_user_input([scanname])[0]
    if related:
        # Several known entities entered together: the first name/company is the target, the others are searched
        # independently in the same scan and correlated by the relevance layer.
        from spiderfoot.services import entities
        pl = entities.plan(html.unescape(str(scantarget)), lambda v: normalize_target(clean_user_input([v])[0])[1])
        if pl.error:
            return ScanStartResult(error=pl.error)
        scantarget, target_type = pl.primary[1], pl.primary[0]
        context = (str(context or '').strip() + '\n' + '\n'.join(pl.context_lines)).strip()
        if not scanname.strip():
            scanname = ' + '.join([pl.primary[1]] + [v for _t, v in pl.others])[:120]

    scantarget = clean_user_input([scantarget])[0]

    if not scanname:
        return ScanStartResult(error="Incorrect usage: scan name was not specified.")

    if not scantarget:
        return ScanStartResult(error="Incorrect usage: scan target was not specified.")

    if not typelist and not modulelist and not usecase:
        return ScanStartResult(error="Incorrect usage: no modules specified for scan.")

    scantarget, targetType = normalize_target(scantarget, target_type)
    if targetType is None:
        return ScanStartResult(error="Unrecognised target type.")

    cfg = deepcopy(config)
    if owner is not None:
        cfg['__scan_owner'] = owner
    cfg['__scan_context'] = relevance_view.clean_context(context)
    if prune is not None:
        cfg['__scan_prune'] = bool(prune)
    if report is not None:
        cfg['__scan_report'] = bool(report)
    sf = SpiderFoot(cfg)

    modlist = list()

    # User selected modules
    if modulelist:
        modlist = modulelist.replace('module_', '').split(',')

    # User selected types
    if len(modlist) == 0 and typelist:
        typesx = typelist.replace('type_', '').split(',')
        modlist = sf.modulesProducing(typesx)
        newmods = deepcopy(modlist)
        newmodcpy = deepcopy(newmods)

        while len(newmodcpy) > 0:
            for etype in sf.eventsToModules(newmodcpy):
                xmods = sf.modulesProducing([etype])
                for mod in xmods:
                    if mod not in modlist:
                        modlist.append(mod)
                        newmods.append(mod)
            newmodcpy = deepcopy(newmods)
            newmods = list()

    # User selected a use case
    if len(modlist) == 0 and usecase:
        for mod in config.get('__modules__', {}):
            if usecase == 'all' or usecase in config['__modules__'][mod].get('group', []):
                modlist.append(mod)

    from spiderfoot.blueprints.ui import _build_modules_data
    from spiderfoot.services import module_state
    disabled = module_state.get_disabled(dbh)
    all_modules, _cats = _build_modules_data(include_disabled=True)
    auto = {n: m['autoReason'] for n, m in all_modules.items() if m['autoReason']}
    dropped = {}
    for m in modlist:
        if m in disabled:
            dropped[m] = 'disabled by the operator'
        elif m in auto:
            dropped[m] = f'auto-disabled: {auto[m]}'
    modlist = [m for m in modlist if m not in dropped]

    if not modlist:
        return ScanStartResult(error="Incorrect usage: no enabled modules specified for scan.", dropped=dropped)

    # Add mandatory storage module
    if "sfp__stor_db" not in modlist:
        modlist.append("sfp__stor_db")
    modlist.sort()

    # Remove stdout module
    if "sfp__stor_stdout" in modlist:
        modlist.remove("sfp__stor_stdout")

    # For private IPs, strip modules that only work with public IPs
    if targetType in ('IP_ADDRESS', 'IPV6_ADDRESS', 'NETBLOCK_OWNER', 'NETBLOCKV6_OWNER'):
        if SpiderFootHelpers.isPrivateIP(scantarget):
            allowed = SpiderFootHelpers.PRIVATE_IP_COMPATIBLE_MODULES
            for m in modlist:
                if m not in allowed:
                    dropped[m] = 'does not work with private IP targets'
            modlist = [m for m in modlist if m in allowed]
            if not modlist or modlist == ['sfp__stor_db']:
                return ScanStartResult(error="No modules available for private IP targets.", dropped=dropped)

    scanId = SpiderFootHelpers.genScanInstanceId()

    try:
        p = mp.Process(target=startSpiderFootScanner, args=(logging_queue, scanname, scanId, scantarget, targetType, modlist, cfg))
        p.daemon = True
        p.start()
    except Exception:
        log.exception(f"[-] Scan [{scanId}] failed")
        return ScanStartResult(error=f"[-] Scan [{scanId}] failed to start. See the server log.")

    # Wait until the scan has initialized (timeout after 30s)
    wait = 0
    while dbh.scanInstanceGet(scanId) is None:
        log.info("Waiting for the scan to initialize...")
        time.sleep(1)
        wait += 1
        if wait >= 30:
            return ScanStartResult(error=f"Scan [{scanId}] failed to initialize within 30 seconds.")

    if owner is not None and dbh.scanOwnerGet(scanId) is None:
        dbh.scanOwnerSet(scanId, owner)

    return ScanStartResult(ok=True, scan_id=scanId, target=scantarget, target_type=targetType, modules=modlist, dropped=dropped)


def new_scan_owner(dbh=None):
    """Id of the user who owns a scan started now (None for the administrator of an installation without sign-in)."""
    user = identity.current_user()
    if user is None or (user.local and user.id is None and user.subject == 'local:admin'):
        return None
    return identity.ensure_user_id(user, dbh or get_db())


def _apply_share_with(dbh, scan_id, owner):
    """Grants asked for in the new scan form: ``share_with`` is a JSON list of {type, principal, level}."""
    raw = request.values.get('share_with', '')
    if not raw or owner is None:
        return
    try:
        wanted = json.loads(raw)
    except ValueError:
        return
    for item in wanted[:50] if isinstance(wanted, list) else []:
        try:
            ptype, principal, level = str(item['type']), str(item['principal']).strip(), str(item['level'])
            if ptype == 'user' and (not principal.isdigit() or not dbh.userGet(int(principal)) or int(principal) == owner):
                continue
            if ptype == 'group' and not 0 < len(principal) <= 200:
                continue
            dbh.aclSet(scan_id, ptype, principal, level, owner)
        except (KeyError, TypeError, ValueError):
            continue


@api_bp.route('/startscan', methods=['POST'])
def startscan():
    """Initiate a new scan."""
    dbh = get_db()
    owner = new_scan_owner(dbh)
    res = start_scan_core(
        request.values.get('scanname', ''),
        request.values.get('scantarget', ''),
        request.values.get('modulelist', ''),
        request.values.get('typelist', ''),
        request.values.get('usecase', ''),
        config=get_config(), dbh=dbh, logging_queue=get_logging_queue(), owner=owner,
        context=request.values.get('context', ''),
        prune=(relevance_view.truthy(request.values.get('prune')) if request.values.get('prune') not in (None, '') else None),
        report=(relevance_view.truthy(request.values.get('report')) if request.values.get('report') not in (None, '') else None),
        related=relevance_view.truthy(request.values.get('related', '')))
    if res.ok:
        _apply_share_with(dbh, res.scan_id, owner)
        return jsonify(["SUCCESS", res.scan_id])
    if res.status:
        return jsonify_error(res.status, res.error)
    return jsonify(["ERROR", res.error])


# -- Rerun scan --------------------------------------------------------------

@api_bp.route('/rerunscan', methods=['POST'])
def rerunscan():
    """Rerun a scan."""
    from sfscan import startSpiderFootScanner

    id = request.values.get('id', '')
    config = get_config()
    cfg = deepcopy(config)
    dbh = SpiderFootDb(cfg)
    owner = new_scan_owner(dbh)
    if owner is not None:
        cfg['__scan_owner'] = owner
    info = dbh.scanInstanceGet(id)

    if not info:
        return jsonify(["ERROR", "Invalid scan ID."])

    scanname = info[0]
    scantarget = info[1]
    old_ctx = dbh.scanContextGet(id)
    cfg['__scan_context'] = old_ctx['context']
    if old_ctx['exists']:
        cfg['__scan_prune'] = old_ctx['prune']
    if dbh.reportPrefGet(id) is not None:
        cfg['__scan_report'] = dbh.reportPrefGet(id)

    scanconfig = dbh.scanConfigGet(id)
    if not scanconfig:
        return jsonify(["ERROR", f"Error loading config from scan: {id}"])

    modlist = scanconfig['_modulesenabled'].split(',')
    if "sfp__stor_stdout" in modlist:
        modlist.remove("sfp__stor_stdout")

    targetType = dbh.scanTargetType(id) or SpiderFootHelpers.targetTypeFromString(scantarget)
    if not targetType:
        targetType = SpiderFootHelpers.targetTypeFromString(f'"{scantarget}"')

    if targetType not in ["HUMAN_NAME", "COMPANY_NAME", "USERNAME", "BITCOIN_ADDRESS"]:
        scantarget = scantarget.lower()

    scanId = SpiderFootHelpers.genScanInstanceId()
    logging_queue = get_logging_queue()

    try:
        p = mp.Process(target=startSpiderFootScanner, args=(logging_queue, scanname, scanId, scantarget, targetType, modlist, cfg))
        p.daemon = True
        p.start()
    except Exception:
        log.exception(f"[-] Scan [{scanId}] failed")
        return jsonify(["ERROR", f"[-] Scan [{scanId}] failed to start. See the server log."])

    wait = 0
    while dbh.scanInstanceGet(scanId) is None:
        log.info("Waiting for the scan to initialize...")
        time.sleep(1)
        wait += 1
        if wait >= 30:
            return jsonify(["ERROR", f"Scan [{scanId}] failed to initialize within 30 seconds."])

    if owner is not None and dbh.scanOwnerGet(scanId) is None:
        dbh.scanOwnerSet(scanId, owner)

    return jsonify(["SUCCESS", scanId])


# -- Rerun scan multi --------------------------------------------------------

@api_bp.route('/rerunscanmulti', methods=['POST'])
def rerunscanmulti():
    """Rerun multiple scans."""
    from sfscan import startSpiderFootScanner

    ids = request.values.get('ids', '')
    config = get_config()
    cfg = deepcopy(config)
    dbh = SpiderFootDb(cfg)
    owner = new_scan_owner(dbh)
    if owner is not None:
        cfg['__scan_owner'] = owner
    scan_ids = []

    for id in ids.split(","):
        info = dbh.scanInstanceGet(id)
        if not info:
            return jsonify(["ERROR", "Invalid scan ID."])

        scanconfig = dbh.scanConfigGet(id)
        scanname = info[0]
        scantarget = info[1]
        old_ctx = dbh.scanContextGet(id)
        cfg['__scan_context'] = old_ctx['context']
        if old_ctx['exists']:
            cfg['__scan_prune'] = old_ctx['prune']
        else:
            cfg.pop('__scan_prune', None)
        if dbh.reportPrefGet(id) is not None:
            cfg['__scan_report'] = dbh.reportPrefGet(id)
        else:
            cfg.pop('__scan_report', None)

        if len(scanconfig) == 0:
            return jsonify(["ERROR", "Something went wrong internally."])

        modlist = scanconfig['_modulesenabled'].split(',')
        if "sfp__stor_stdout" in modlist:
            modlist.remove("sfp__stor_stdout")

        targetType = dbh.scanTargetType(id) or SpiderFootHelpers.targetTypeFromString(scantarget)
        if targetType is None:
            targetType = SpiderFootHelpers.targetTypeFromString(f'"{scantarget}"')
        if targetType is None:
            return jsonify(["ERROR", "Invalid target type. Could not recognize it as a target SpiderFoot supports."])

        scanId = SpiderFootHelpers.genScanInstanceId()
        logging_queue = get_logging_queue()

        try:
            p = mp.Process(target=startSpiderFootScanner, args=(logging_queue, scanname, scanId, scantarget, targetType, modlist, cfg))
            p.daemon = True
            p.start()
        except Exception:
            log.exception(f"[-] Scan [{scanId}] failed")
            return jsonify(["ERROR", f"[-] Scan [{scanId}] failed to start. See the server log."])

        wait = 0
        while dbh.scanInstanceGet(scanId) is None:
            log.info("Waiting for the scan to initialize...")
            time.sleep(1)
            wait += 1
            if wait >= 30:
                return jsonify(["ERROR", f"Scan [{scanId}] failed to initialize within 30 seconds."])

        if owner is not None and dbh.scanOwnerGet(scanId) is None:
            dbh.scanOwnerSet(scanId, owner)
        scan_ids.append(scanId)

    return jsonify(["SUCCESS", scan_ids])


# -- Search ------------------------------------------------------------------

@api_bp.route('/search', methods=['GET', 'POST'])
def search():
    """Search scans."""
    id = request.values.get('id', None)
    eventType = request.values.get('eventType', None)
    value = request.values.get('value', None)

    refusal, allowed = _search_scope(id)
    if refusal is not None:
        return refusal
    try:
        return jsonify(search_base(id, eventType, value, allowed, include_unrelated=_include_unrelated()))
    except Exception:
        return jsonify([])


# -- Scan history ------------------------------------------------------------

@api_bp.route('/scanhistory', methods=['GET', 'POST'])
def scanhistory():
    """Historical data for a scan."""
    id = request.values.get('id', '')

    if not id:
        return jsonify_error('404', "No scan specified")

    dbh = get_db()

    try:
        return jsonify(dbh.scanResultHistory(id))
    except Exception:
        return jsonify([])


# -- Scan element type discovery ---------------------------------------------

@api_bp.route('/scanelementtypediscovery', methods=['GET', 'POST'])
def scanelementtypediscovery():
    """Scan element type discovery."""
    id = request.values.get('id', '')
    eventType = request.values.get('eventType', '')

    dbh = get_db()
    pc = dict()
    datamap = dict()
    retdata = dict()

    try:
        leafSet = dbh.scanResultEvent(id, eventType)
        [datamap, pc] = dbh.scanElementSourcesAll(id, leafSet)
    except Exception:
        return jsonify(retdata)

    pc.pop('ROOT', None)
    retdata['tree'] = SpiderFootHelpers.dataParentChildToTree(pc)
    retdata['data'] = datamap

    return jsonify(retdata)


# -- Event types -------------------------------------------------------------

@api_bp.route('/eventtypes')
def eventtypes():
    """List all event types."""
    dbh = get_db()
    types = dbh.eventTypes()
    ret = []

    for r in types:
        ret.append([r[1], r[0]])

    return jsonify(sorted(ret, key=itemgetter(0)))


# -- Modules -----------------------------------------------------------------

@api_bp.route('/modules')
def modules():
    """List all modules."""
    config = get_config()
    ret = []

    modinfo = list(config.get('__modules__', {}).keys())
    if not modinfo:
        return jsonify(ret)

    modinfo.sort()

    for m in modinfo:
        if "__" in m:
            continue
        ret.append({'name': m, 'descr': config['__modules__'][m]['descr']})

    return jsonify(ret)


# -- Correlation rules -------------------------------------------------------

@api_bp.route('/correlationrules')
def correlationrules():
    """List all correlation rules."""
    config = get_config()
    ret = []

    rules = config.get('__correlationrules__', [])
    if not rules:
        return jsonify(ret)

    for r in rules:
        ret.append({
            'id': r['id'],
            'name': r['meta']['name'],
            'descr': r['meta']['description'],
            'risk': r['meta']['risk'],
        })

    return jsonify(ret)


# -- Options raw -------------------------------------------------------------

@api_bp.route('/optsraw', methods=['GET', 'POST'])
def optsraw():
    """Return global and module settings as JSON."""
    config = _redact_secrets(get_config())
    ret = dict()

    for opt in config:
        if not opt.startswith('__'):
            ret["global." + opt] = config[opt]
            continue

        if opt == '__modules__':
            for mod in sorted(config['__modules__'].keys()):
                for mo in sorted(config['__modules__'][mod]['opts'].keys()):
                    if mo.startswith("_"):
                        continue
                    ret["module." + mod + "." + mo] = config['__modules__'][mod]['opts'][mo]

    return jsonify(['SUCCESS', {'data': ret}])


# -- Options export ----------------------------------------------------------

@api_bp.route('/optsexport', methods=['GET', 'POST'])
def optsexport():
    """Export configuration."""
    from sflib import SpiderFoot

    config = get_config()
    pattern = request.values.get('pattern', None)

    sf = SpiderFoot(config)
    conf = sf.configSerialize(config)
    content = ""

    for opt in sorted(conf):
        if ":_" in opt or opt.startswith("_"):
            continue
        # Skip sensitive options (API keys, passwords, etc.)
        opt_lower = opt.lower()
        if any(p in opt_lower for p in _SENSITIVE_OPT_PATTERNS):
            continue
        if pattern:
            if pattern in opt:
                content += f"{opt}={conf[opt]}\n"
        else:
            content += f"{opt}={conf[opt]}\n"

    return Response(
        content,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename="SpiderFoot.cfg"'}
    )


# -- Save settings raw ------------------------------------------------------

@api_bp.route('/savesettingsraw', methods=['POST'])
def savesettingsraw():
    """Save settings (raw/JSON), also used for reset to default."""
    from sflib import SpiderFoot

    allopts = request.values.get('allopts', '')

    config = get_config()

    # Reset config to default
    if allopts == "RESET":
        try:
            dbh = get_db()
            dbh.configClear()
            default_config = get_default_config()
            current_app.config['SF_CONFIG'] = deepcopy(default_config)
        except Exception:
            return jsonify(["ERROR", "Failed to reset settings"])
        return jsonify(["SUCCESS", ""])

    # Save settings
    try:
        dbh = get_db()
        useropts = json.loads(allopts)
        cleanopts = dict()
        for opt in list(useropts.keys()):
            val = clean_user_input([useropts[opt]])[0]
            # Skip masked API key placeholders — preserve existing value
            if val == '********':
                continue
            cleanopts[opt] = val
        problem = relevance_job.validate_settings(cleanopts, config) or report_job.validate_settings(cleanopts, config)
        if problem:
            return jsonify(["ERROR", problem])

        currentopts = deepcopy(config)
        sf = SpiderFoot(config)
        new_config = sf.configUnserialize(cleanopts, currentopts)
        current_app.config['SF_CONFIG'] = new_config
        dbh.configSet(sf.configSerialize(new_config))
    except Exception:
        log.exception("Processing submitted settings failed")
        return jsonify(["ERROR", "Processing one or more of your inputs failed. See the server log."])

    return jsonify(["SUCCESS", ""])


# -- Save settings (form-based) ---------------------------------------------

@api_bp.route('/savesettings', methods=['POST'])
def savesettings():
    """Save settings via form post (used by web UI)."""
    from sflib import SpiderFoot

    allopts = request.values.get('allopts', '')
    config_file = request.files.get('configFile', None)
    # The frontend import sends file contents as a form field, not a file upload
    config_text = request.values.get('configFile', '')

    config = get_config()

    if config_file or config_text:
        try:
            if config_file:
                contents = config_file.read()
                if isinstance(contents, bytes):
                    contents = contents.decode('utf-8')
            else:
                contents = config_text

            tmp = dict()
            for line in contents.split("\n"):
                if "=" not in line:
                    continue
                opt_array = line.strip().split("=")
                if len(opt_array) == 1:
                    opt_array.append("")
                tmp[opt_array[0]] = '='.join(opt_array[1:])

            allopts = json.dumps(tmp)
        except Exception:
            log.warning("Failed to parse uploaded settings file", exc_info=True)
            return jsonify(["ERROR", "Failed to parse input file. Was it generated from SpiderFoot?"])

    # Reset
    if allopts == "RESET":
        try:
            dbh = get_db()
            dbh.configClear()
            default_config = get_default_config()
            current_app.config['SF_CONFIG'] = deepcopy(default_config)
        except Exception:
            return jsonify(["ERROR", "Failed to reset settings"])
        return jsonify(["SUCCESS", ""])

    try:
        dbh = get_db()
        useropts = json.loads(allopts)
        cleanopts = dict()
        for opt in list(useropts.keys()):
            val = clean_user_input([useropts[opt]])[0]
            # Skip masked API key placeholders — preserve existing value
            if val == '********':
                continue
            cleanopts[opt] = val
        problem = relevance_job.validate_settings(cleanopts, config) or report_job.validate_settings(cleanopts, config)
        if problem:
            return jsonify(["ERROR", problem])

        currentopts = deepcopy(config)
        sf = SpiderFoot(config)
        new_config = sf.configUnserialize(cleanopts, currentopts)
        current_app.config['SF_CONFIG'] = new_config
        dbh.configSet(sf.configSerialize(new_config))
        # a changed key invalidates any recorded key problem for that module
        _clear_key_issues({o.split(':', 1)[0] for o in cleanopts
                           if ':' in o and any(t in o.lower() for t in ('api_key', 'apikey', 'api_id', 'accesstoken', 'secret'))})
    except Exception:
        log.exception("Processing submitted settings failed")
        return jsonify(["ERROR", "Processing one or more of your inputs failed. See the server log."])

    return jsonify(["SUCCESS", ""])


# -- Result set false positive -----------------------------------------------

@api_bp.route('/resultsetfp', methods=['POST'])
def resultsetfp():
    """Set results as false positive."""
    id = request.values.get('id', '')
    resultids = request.values.get('resultids', '')
    fp = request.values.get('fp', '')

    dbh = get_db()

    if fp not in ["0", "1"]:
        return jsonify(["ERROR", "No FP flag set or not set correctly."])

    try:
        ids = json.loads(resultids)
    except Exception:
        return jsonify(["ERROR", "No IDs supplied."])

    status = dbh.scanInstanceGet(id)
    if not status:
        return jsonify(["ERROR", f"Invalid scan ID: {id}"])

    if status[5] not in ["ABORTED", "FINISHED", "ERROR-FAILED"]:
        return jsonify(["WARNING", "Scan must be in a finished state when setting False Positives."])

    if fp == "0":
        data = dbh.scanElementSourcesDirect(id, ids)
        for row in data:
            if str(row[14]) == "1":
                return jsonify(["WARNING", f"Cannot unset element {id} as False Positive if a parent element is still False Positive."])

    childs = dbh.scanElementChildrenAll(id, ids)
    allIds = ids + childs

    ret = dbh.scanResultsUpdateFP(id, allIds, fp)
    if ret:
        return jsonify(["SUCCESS", ""])

    return jsonify(["ERROR", "Exception encountered."])


# -- Vacuum ------------------------------------------------------------------

@api_bp.route('/vacuum', methods=['POST'])
def vacuum():
    """Vacuum the database."""
    dbh = get_db()
    try:
        if dbh.vacuumDB():
            return jsonify(["SUCCESS", ""])
        return jsonify(["ERROR", "Vacuuming the database failed"])
    except Exception:
        log.exception("Vacuuming the database failed")
        return jsonify(["ERROR", "Vacuuming the database failed. See the server log."])


# -- Scan export logs (CSV) --------------------------------------------------

@api_bp.route('/scanexportlogs', methods=['GET', 'POST'])
def scanexportlogs():
    """Export scan logs as CSV."""
    id = request.values.get('id', '')
    dialect = request.values.get('dialect', 'excel')

    dbh = get_db()

    try:
        data = dbh.scanLogs(id, None, None, True)
    except Exception:
        return jsonify(["ERROR", "Scan ID not found."])

    if not data:
        return jsonify(["ERROR", "Scan ID not found."])

    fileobj = StringIO()
    parser = csv.writer(fileobj, dialect=dialect)
    parser.writerow(["Date", "Component", "Type", "Event", "Event ID"])
    for row in data:
        parser.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0] / 1000)),
            _csv_safe(row[1]),
            _csv_safe(row[2]),
            _csv_safe(row[3]),
            _csv_safe(row[4])
        ])

    return Response(
        fileobj.getvalue().encode('utf-8'),
        mimetype='application/csv',
        headers={
            'Content-Disposition': f'attachment; filename="SpiderFoot-{_safe_filename(str(id))}.log.csv"',
            'Pragma': 'no-cache'
        }
    )


# -- Scan correlations export ------------------------------------------------

@api_bp.route('/scancorrelationsexport', methods=['GET', 'POST'])
def scancorrelationsexport():
    """Export scan correlation data as CSV or Excel."""
    id = request.values.get('id', '')
    filetype = request.values.get('filetype', 'csv')
    dialect = request.values.get('dialect', 'excel')

    dbh = get_db()

    try:
        scaninfo = dbh.scanInstanceGet(id)
    except Exception:
        return jsonify(["ERROR", "Could not retrieve info for scan."])

    if not scaninfo:
        return jsonify(["ERROR", "Could not retrieve info for scan."])

    scan_name = scaninfo[0]

    try:
        correlations = dbh.scanCorrelationList(id)
    except Exception:
        return jsonify(["ERROR", "Could not retrieve correlations for scan."])

    headings = ["Rule Name", "Correlation", "Risk", "Description"]

    if filetype.lower() in ["xlsx", "excel"]:
        rows = []
        for row in correlations:
            correlation = row[1]
            rule_name = row[4]
            rule_risk = row[3]
            rule_description = row[5]
            rows.append([rule_name, correlation, rule_risk, rule_description])

        fname = f"{_safe_filename(scan_name)}-SpiderFoot-correlations.xlsx"

        return Response(
            build_excel(rows, headings, sheet_name_index=0),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename="{fname}"',
                'Pragma': 'no-cache'
            }
        )

    if filetype.lower() == 'csv':
        fileobj = StringIO()
        parser = csv.writer(fileobj, dialect=dialect)
        parser.writerow(headings)

        for row in correlations:
            correlation = row[1]
            rule_name = row[4]
            rule_risk = row[3]
            rule_description = row[5]
            parser.writerow([_csv_safe(rule_name), _csv_safe(correlation), _csv_safe(rule_risk), _csv_safe(rule_description)])

        fname = f"{_safe_filename(scan_name)}-SpiderFoot-correlations.csv"

        return Response(
            fileobj.getvalue().encode('utf-8'),
            mimetype='application/csv',
            headers={
                'Content-Disposition': f'attachment; filename="{fname}"',
                'Pragma': 'no-cache'
            }
        )

    return jsonify(["ERROR", "Invalid export filetype."])


# -- Scan event result export ------------------------------------------------

@api_bp.route('/scaneventresultexport', methods=['GET', 'POST'])
def scaneventresultexport():
    """Export scan event result data as CSV or Excel."""
    id = request.values.get('id', '')
    type_ = request.values.get('type', '')
    filetype = request.values.get('filetype', 'csv')
    dialect = request.values.get('dialect', 'excel')

    dbh = get_db()
    data = dbh.scanResultEvent(id, type_)
    rel = _Relevance(dbh, _include_unrelated())

    if filetype.lower() in ["xlsx", "excel"]:
        rows = []
        for row in data:
            if row[4] == "ROOT" or rel.skip(id, row[8]):
                continue
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
            datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
            rows.append([lastseen, str(row[4]), str(row[3]), str(row[2]), row[13], datafield, *rel.cols(id, row[8])])

        return Response(
            build_excel(rows, ["Updated", "Type", "Module", "Source", "F/P", "Data", "Relevance", "Relevance score"], sheet_name_index=1),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': 'attachment; filename=SpiderFoot.xlsx',
                'Pragma': 'no-cache'
            }
        )

    if filetype.lower() == 'csv':
        fileobj = StringIO()
        parser = csv.writer(fileobj, dialect=dialect)
        parser.writerow(["Updated", "Type", "Module", "Source", "F/P", "Data", "Relevance", "Relevance score"])
        for row in data:
            if row[4] == "ROOT" or rel.skip(id, row[8]):
                continue
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
            datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
            parser.writerow([lastseen, _csv_safe(row[4]), _csv_safe(row[3]), _csv_safe(row[2]), _csv_safe(row[13]), _csv_safe(datafield),
                             *rel.cols(id, row[8])])

        return Response(
            fileobj.getvalue().encode('utf-8'),
            mimetype='application/csv',
            headers={
                'Content-Disposition': 'attachment; filename=SpiderFoot.csv',
                'Pragma': 'no-cache'
            }
        )

    return jsonify(["ERROR", "Invalid export filetype."])


# -- Scan event result export multi ------------------------------------------

@api_bp.route('/scaneventresultexportmulti', methods=['GET', 'POST'])
def scaneventresultexportmulti():
    """Export scan event result data for multiple scans."""
    ids = request.values.get('ids', '')
    filetype = request.values.get('filetype', 'csv')
    dialect = request.values.get('dialect', 'excel')

    dbh = get_db()
    scaninfo = dict()
    data = list()
    scan_name = ""
    rel = _Relevance(dbh, _include_unrelated())

    for id in ids.split(','):
        scaninfo[id] = dbh.scanInstanceGet(id)
        if scaninfo[id] is None:
            continue
        scan_name = scaninfo[id][0]
        data = data + dbh.scanResultEvent(id)

    if not data:
        return Response('', status=204)

    if filetype.lower() in ["xlsx", "excel"]:
        rows = []
        for row in data:
            if row[4] == "ROOT" or rel.skip(row[12], row[8]):
                continue
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
            datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
            rows.append([scaninfo[row[12]][0], lastseen, str(row[4]), str(row[3]),
                         str(row[2]), row[13], datafield, *rel.cols(row[12], row[8])])

        if len(ids.split(',')) > 1 or scan_name == "":
            fname = "SpiderFoot.xlsx"
        else:
            fname = _safe_filename(scan_name) + "-SpiderFoot.xlsx"

        return Response(
            build_excel(rows, ["Scan Name", "Updated", "Type", "Module", "Source", "F/P", "Data", "Relevance", "Relevance score"], sheet_name_index=2),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename="{fname}"',
                'Pragma': 'no-cache'
            }
        )

    if filetype.lower() == 'csv':
        fileobj = StringIO()
        parser = csv.writer(fileobj, dialect=dialect)
        parser.writerow(["Scan Name", "Updated", "Type", "Module", "Source", "F/P", "Data", "Relevance", "Relevance score"])
        for row in data:
            if row[4] == "ROOT" or rel.skip(row[12], row[8]):
                continue
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
            datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
            parser.writerow([_csv_safe(scaninfo[row[12]][0]), lastseen, _csv_safe(row[4]), _csv_safe(row[3]),
                             _csv_safe(row[2]), _csv_safe(row[13]), _csv_safe(datafield), *rel.cols(row[12], row[8])])

        if len(ids.split(',')) > 1 or scan_name == "":
            fname = "SpiderFoot.csv"
        else:
            fname = _safe_filename(scan_name) + "-SpiderFoot.csv"

        return Response(
            fileobj.getvalue().encode('utf-8'),
            mimetype='application/csv',
            headers={
                'Content-Disposition': f'attachment; filename="{fname}"',
                'Pragma': 'no-cache'
            }
        )

    return jsonify(["ERROR", "Invalid export filetype."])


# -- Scan search result export -----------------------------------------------

@api_bp.route('/scansearchresultexport', methods=['GET', 'POST'])
def scansearchresultexport():
    """Export search result data as CSV or Excel."""
    id = request.values.get('id', '')
    eventType = request.values.get('eventType', None)
    value = request.values.get('value', None)
    filetype = request.values.get('filetype', 'csv')
    dialect = request.values.get('dialect', 'excel')

    refusal, allowed = _search_scope(id)
    if refusal is not None:
        return refusal
    data = search_base(id, eventType, value, allowed, include_unrelated=_include_unrelated())

    if not data:
        return Response('', status=204)

    if filetype.lower() in ["xlsx", "excel"]:
        rows = []
        for row in data:
            if row[10] == "ROOT":
                continue
            datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
            rows.append([row[0], str(row[10]), str(row[3]), str(row[2]), row[11], datafield, row[13], row[14]])

        return Response(
            build_excel(rows, ["Updated", "Type", "Module", "Source", "F/P", "Data", "Relevance", "Relevance score"], sheet_name_index=1),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': 'attachment; filename=SpiderFoot.xlsx',
                'Pragma': 'no-cache'
            }
        )

    if filetype.lower() == 'csv':
        fileobj = StringIO()
        parser = csv.writer(fileobj, dialect=dialect)
        parser.writerow(["Updated", "Type", "Module", "Source", "F/P", "Data", "Relevance", "Relevance score"])
        for row in data:
            if row[10] == "ROOT":
                continue
            datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
            parser.writerow([_csv_safe(row[0]), _csv_safe(row[10]), _csv_safe(row[3]), _csv_safe(row[2]), _csv_safe(row[11]), _csv_safe(datafield),
                             row[13], row[14]])

        return Response(
            fileobj.getvalue().encode('utf-8'),
            mimetype='application/csv',
            headers={
                'Content-Disposition': 'attachment; filename=SpiderFoot.csv',
                'Pragma': 'no-cache'
            }
        )

    return jsonify(["ERROR", "Invalid export filetype."])


# -- Scan export JSON multi --------------------------------------------------

@api_bp.route('/scanexportjsonmulti', methods=['GET', 'POST'])
def scanexportjsonmulti():
    """Export scan event result data in JSON format for multiple scans."""
    ids = request.values.get('ids', '')

    dbh = get_db()
    scaninfo = list()
    scan_name = ""
    rel = _Relevance(dbh, _include_unrelated())

    for id in ids.split(','):
        scan = dbh.scanInstanceGet(id)
        if scan is None:
            continue

        scan_name = scan[0]

        for row in dbh.scanResultEvent(id):
            if rel.skip(id, row[8]):
                continue
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
            event_data = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
            source_data = str(row[2])
            source_module = str(row[3])
            event_type = row[4]
            false_positive = row[13]

            if event_type == "ROOT":
                continue

            scaninfo.append({
                "data": event_data,
                "event_type": event_type,
                "module": source_module,
                "source_data": source_data,
                "false_positive": false_positive,
                "last_seen": lastseen,
                "scan_name": scan_name,
                "scan_target": scan[1],
                "relevance": rel.cols(id, row[8])[0],
                "relevance_score": rel.cols(id, row[8])[1],
            })

    if len(ids.split(',')) > 1 or scan_name == "":
        fname = "SpiderFoot.json"
    else:
        fname = _safe_filename(scan_name) + "-SpiderFoot.json"

    return Response(
        json.dumps(scaninfo).encode('utf-8'),
        mimetype='application/json; charset=utf-8',
        headers={
            'Content-Disposition': f'attachment; filename="{fname}"',
            'Pragma': 'no-cache'
        }
    )


# -- Scan viz ----------------------------------------------------------------

@api_bp.route('/scanviz', methods=['GET', 'POST'])
def scanviz():
    """Export entities from scan results for visualising."""
    id = request.values.get('id', '')
    gexf = request.values.get('gexf', '0')

    if not id:
        return Response('', status=204)

    dbh = get_db()
    data = dbh.scanResultEvent(id, filterFp=True)
    scan = dbh.scanInstanceGet(id)

    if not scan:
        return Response('', status=204)

    if not data:
        return Response('{"nodes":[],"edges":[]}', mimetype='application/json', status=200)

    scan_name = scan[0]
    root = scan[1]

    if gexf == "0":
        # buildGraphJson already returns a JSON string; wrapping it in jsonify
        # would double-encode it. Send as a raw application/json response.
        return Response(
            SpiderFootHelpers.buildGraphJson([root], data),
            mimetype='application/json',
        )

    fname = _safe_filename(scan_name) + "-SpiderFoot.gexf"

    return Response(
        SpiderFootHelpers.buildGraphGexf([root], "SpiderFoot Export", data),
        mimetype='application/gexf',
        headers={
            'Content-Disposition': f'attachment; filename="{fname}"',
            'Pragma': 'no-cache'
        }
    )


# -- Scan viz multi ----------------------------------------------------------

@api_bp.route('/scanvizmulti', methods=['GET', 'POST'])
def scanvizmulti():
    """Export entities from multiple scans in GEXF format."""
    ids = request.values.get('ids', '')
    gexf = request.values.get('gexf', '1')

    dbh = get_db()
    data = list()
    roots = list()
    scan_name = ""

    if not ids:
        return Response('', status=204)

    for id in ids.split(','):
        scan = dbh.scanInstanceGet(id)
        if not scan:
            continue
        data = data + dbh.scanResultEvent(id, filterFp=True)
        roots.append(scan[1])
        scan_name = scan[0]

    if not data:
        return Response('', status=204)

    if gexf == "0":
        # Not implemented yet
        return Response('', status=204)

    if len(ids.split(',')) > 1 or scan_name == "":
        fname = "SpiderFoot.gexf"
    else:
        fname = _safe_filename(scan_name) + "-SpiderFoot.gexf"

    return Response(
        SpiderFootHelpers.buildGraphGexf(roots, "SpiderFoot Export", data),
        mimetype='application/gexf',
        headers={
            'Content-Disposition': f'attachment; filename="{fname}"',
            'Pragma': 'no-cache'
        }
    )


# ---------------------------------------------------------------------------
# Scan presets
# ---------------------------------------------------------------------------


@api_bp.route('/presets', methods=['GET'])
def presets_list():
    """List all scan presets (built-in + user)."""
    dbh = get_db()
    return jsonify([serialize_preset(r) for r in dbh.presetList()])


@api_bp.route('/presets/<path:preset_id>', methods=['GET'])
def presets_get(preset_id):
    """Get a single preset by id."""
    dbh = get_db()
    r = dbh.presetGet(preset_id)
    if r is None:
        return jsonify_error('404', f"Preset {preset_id} not found")
    return jsonify(serialize_preset(r))


@api_bp.route('/presets', methods=['POST'])
def presets_create():
    """Create a user preset."""
    dbh = get_db()
    body = request.get_json(silent=True) or {}
    name = (body.get('name') or '').strip()
    description = body.get('description')
    modules = body.get('modules') or []

    if not name or len(name) > 60:
        return jsonify_error('400', "Name must be 1-60 characters")
    if description is not None and not isinstance(description, str):
        return jsonify_error('400', "description must be a string")
    if description is not None and len(description) > 200:
        return jsonify_error('400', "description must be 200 characters or fewer")
    if not isinstance(modules, list):
        return jsonify_error('400', "modules must be a list")

    sf_modules = get_config().get('__modules__') or {}
    valid, invalid = validate_module_names(modules, sf_modules)
    if invalid:
        return jsonify_error('400', f"Unknown modules: {', '.join(invalid)}")

    for existing in dbh.presetList():
        if existing['name'].lower() == name.lower():
            return jsonify_error('400', f"A preset named '{existing['name']}' already exists")

    preset_id = f"user:{uuid.uuid4().hex}"
    now_ms = int(time.time() * 1000)
    try:
        dbh.presetCreate(
            preset_id=preset_id,
            name=name,
            description=description,
            kind='user',
            sort_order=0,
            modules=valid,
            now_ms=now_ms,
        )
    except sqlite3.IntegrityError:
        # UNIQUE/CHECK constraint violation — most likely a name collision
        # that slipped past the prior presetList() check (TOCTOU race) or a
        # CHECK violation on `kind`. Always a client-facing data issue.
        log.warning("Preset create hit a constraint violation", exc_info=True)
        return jsonify_error('400', "The preset could not be saved: the name may already be in use.")
    except Exception:
        log.exception("Failed to create preset")
        return jsonify_error('500', "Failed to create preset. See the server log.")
    return jsonify(serialize_preset(dbh.presetGet(preset_id))), 201


@api_bp.route('/presets/<path:preset_id>', methods=['PATCH'])
def presets_update(preset_id):
    dbh = get_db()
    existing = dbh.presetGet(preset_id)
    if existing is None:
        return jsonify_error('404', f"Preset {preset_id} not found")
    if existing['kind'] == 'builtin':
        return jsonify_error('403', "Built-in presets are read-only")

    body = request.get_json(silent=True) or {}
    name = (body.get('name') or existing['name']).strip()
    description = body.get('description', existing['description'])
    modules = body.get('modules', existing['modules'])

    if not name or len(name) > 60:
        return jsonify_error('400', "Name must be 1-60 characters")
    if description is not None and not isinstance(description, str):
        return jsonify_error('400', "description must be a string")
    if description is not None and len(description) > 200:
        return jsonify_error('400', "description must be 200 characters or fewer")
    if not isinstance(modules, list):
        return jsonify_error('400', "modules must be a list")

    sf_modules = get_config().get('__modules__') or {}
    valid, invalid = validate_module_names(modules, sf_modules)
    if invalid:
        return jsonify_error('400', f"Unknown modules: {', '.join(invalid)}")

    # Name conflict — but allow keeping the same name on this preset
    for other in dbh.presetList():
        if other['id'] == preset_id:
            continue
        if other['name'].lower() == name.lower():
            return jsonify_error('400', f"A preset named '{other['name']}' already exists")

    try:
        dbh.presetUpdate(
            preset_id=preset_id, name=name, description=description,
            modules=valid, now_ms=int(time.time() * 1000),
        )
    except sqlite3.IntegrityError:
        log.warning("Preset update hit a constraint violation", exc_info=True)
        return jsonify_error('400', "The preset could not be saved: the name may already be in use.")
    except Exception:
        log.exception("Failed to update preset")
        return jsonify_error('500', "Failed to update preset. See the server log.")
    return jsonify(serialize_preset(dbh.presetGet(preset_id)))


# IMPORTANT: register the LITERAL /presets/default route BEFORE the
# <path:preset_id> route so Flask matches it first for DELETE.
@api_bp.route('/presets/default', methods=['DELETE'])
def presets_clear_default():
    dbh = get_db()
    dbh.presetClearDefault()
    return jsonify({'status': 'ok'})


@api_bp.route('/presets/<path:preset_id>', methods=['DELETE'])
def presets_delete(preset_id):
    dbh = get_db()
    existing = dbh.presetGet(preset_id)
    if existing is None:
        return jsonify_error('404', f"Preset {preset_id} not found")
    if existing['kind'] == 'builtin':
        return jsonify_error('403', "Built-in presets cannot be deleted")
    dbh.presetDelete(preset_id)
    return jsonify({'status': 'ok'})


@api_bp.route('/presets/<path:preset_id>/default', methods=['POST'])
def presets_set_default(preset_id):
    dbh = get_db()
    if dbh.presetGet(preset_id) is None:
        return jsonify_error('404', f"Preset {preset_id} not found")
    dbh.presetSetDefault(preset_id)
    return jsonify({'status': 'ok'})
