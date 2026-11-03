"""Writing a scan report: the job, its queue, the worker thread and the settings.

A report is a row in ``tbl_scan_report`` (a *version*). It is created ``queued`` by the scan process when the scan
ends (``enqueue_for_scan``, after the relevance assessment, which runs in the scan process before this is called) or
by a user, and is picked up by the worker thread of the web process, at most ``_report_concurrency`` at a time so a
local model is not overloaded. ``generate`` is idempotent and restartable: the digests and every finished section are
saved in the row, a restart puts a ``running`` row back in the queue and the next run reuses what is already written.
"""

import logging
import re
import threading
import time
import typing

from spiderfoot.services import report_digest as rd
from spiderfoot.services import report_render as rr
from spiderfoot.services import report_sections as rs
from spiderfoot.services.report_llm import ReportLLM, ReportLLMError

log = logging.getLogger(__name__)

DEFAULTS = {
    '_report_auto': True, '_report_include_aborted': True, '_report_model': '', '_report_max_calls': 24,
    '_report_max_tokens': 400000, '_report_section_tokens': 1800, '_report_appendix_max': 120,
    '_report_sections': ','.join(rs.SECTION_IDS), '_report_keep': 5, '_report_concurrency': 1, '_report_call_timeout': 150,
}
OPTDESCS = {
    '_report_auto': "Write a report with the AI assistant when a scan finishes.",
    '_report_include_aborted': "Also write a report (marked as partial) for scans that were aborted or failed.",
    '_report_model': "Model for reports (empty: the AI assistant default).",
    '_report_max_calls': "Most AI calls per report.",
    '_report_max_tokens': "Most AI tokens per report (as counted by the endpoint, including any prompt the server adds).",
    '_report_section_tokens': "Hard cap on the input tokens of one report section.",
    '_report_appendix_max': "Most findings a report may cite (rows of the appendix).",
    '_report_sections': "Sections to write: summary, scope, identity, findings, risks, limits, next.",
    '_report_keep': "Report versions to keep per scan.",
    '_report_concurrency': "Reports written at the same time (1 or 2).",
    '_report_call_timeout': "Seconds to wait for the AI endpoint on one call.",
}
INT_RANGES = {
    '_report_max_calls': (1, 200), '_report_max_tokens': (1000, 5000000), '_report_section_tokens': (500, 8000),
    '_report_appendix_max': (10, 400), '_report_keep': (3, 50), '_report_concurrency': (1, 2), '_report_call_timeout': (10, 900),
}
BOOL_KEYS = ('_report_auto', '_report_include_aborted')

TERMINAL_OK = ('FINISHED',)
TERMINAL_PARTIAL = ('ABORTED', 'ERROR-FAILED', 'FAILED')
RUNNING_STATES = ('RUNNING', 'STARTING', 'STARTED', 'ABORT-REQUESTED')


def on(cfg: dict, key: str, default: bool = True) -> bool:
    v = cfg.get(key, default)
    return v not in (False, 0, '0', 'false', 'False', None, '') if v is not None else default


def num(cfg: dict, key: str) -> int:
    try:
        return int(str(cfg.get(key, DEFAULTS[key])).strip())
    except ValueError:
        return int(DEFAULTS[key])


def enabled_sections(cfg: dict) -> typing.List[str]:
    raw = str(cfg.get('_report_sections', DEFAULTS['_report_sections']) or '')
    got = [s.strip() for s in raw.split(',') if s.strip() in rs.SECTION_IDS]
    return got or list(rs.SECTION_IDS)


def ai_ready(cfg: dict) -> bool:
    return ReportLLM.from_config(cfg) is not None


def validate_settings(opts: dict, current: typing.Optional[dict] = None) -> str:
    """'' when the report settings in ``opts`` (strings, as posted by the form) are acceptable, else a message."""
    for key, (lo, hi) in INT_RANGES.items():
        if key in opts:
            try:
                v = int(str(opts[key]).strip())
            except ValueError:
                return f"{key.replace('_report_', '').replace('_', ' ')} must be a whole number."
            if not lo <= v <= hi:
                return f"{key.replace('_report_', '').replace('_', ' ')} must be between {lo} and {hi}."
    for key in BOOL_KEYS:
        if key in opts and str(opts[key]).strip() not in ('0', '1'):
            return f"{key.replace('_report_', '').replace('_', ' ')} must be on or off."
    if '_report_sections' in opts:
        parts = [p.strip() for p in str(opts['_report_sections']).split(',') if p.strip()]
        if not parts or any(p not in rs.SECTION_IDS for p in parts):
            return "Sections must be a list of: " + ', '.join(rs.SECTION_IDS) + '.'
    if '_report_model' in opts and (len(str(opts['_report_model'])) > 200 or re.search(r"[\x00-\x1f]", str(opts['_report_model']))):
        return "The model name is not valid."
    return ''


# ----------------------------------------------------------------------------------------------------
# deciding when a report is written

def should_auto(cfg: dict, scan_status: str, pref: typing.Optional[bool], ready: bool, events: int = 1) -> typing.Tuple[bool, str]:
    """(write one, why not). ``pref`` is the choice made when the scan was started (None: the settings decide)."""
    if scan_status not in TERMINAL_OK + TERMINAL_PARTIAL:
        return False, 'the scan did not end'
    if scan_status in TERMINAL_PARTIAL and not on(cfg, '_report_include_aborted', True):
        return False, 'reports for aborted scans are switched off'
    if events <= 0:
        return False, 'the scan has no findings'
    if pref is False:
        return False, 'switched off for this scan'
    if pref is True:
        return True, ''
    if not on(cfg, '_report_auto', True):
        return False, 'automatic reports are switched off'
    if not ready:
        return False, 'the AI assistant is not configured'
    return True, ''


def enqueue_for_scan(cfg: dict, dbh, scan_id: str, *, force_pref: typing.Optional[bool] = None) -> typing.Optional[dict]:
    """Called when a scan has ended (and its relevance assessment is done): queue a report if one is wanted. Idempotent.

    Returns the queued row, or None. Never raises."""
    try:
        info = dbh.scanInstanceGet(scan_id)
        if not info:
            return None
        status, ended = info[5], int(info[4] or 0)
        pref = force_pref if force_pref is not None else dbh.reportPrefGet(scan_id)
        counts = dbh.reportModuleCounts(scan_id)
        events = sum(n for m, n in counts.items() if m != 'SpiderFoot UI') or sum(counts.values())
        ok, why = should_auto(cfg, status, pref, ai_ready(cfg), events)
        if not ok:
            log.info("report for %s not queued: %s", scan_id, why)
            return None
        for r in dbh.reportList(scan_id):
            if r['trigger'] == 'auto' and r['scan_ended'] == ended and r['status'] != 'failed':
                return None             # this end of the scan already has its automatic report
        row, created = dbh.reportCreate(scan_id, 'auto', str(cfg.get('_report_model') or ''), {'sections': enabled_sections(cfg)},
                                        None, status, ended)
        if created:
            wake()
        return row if created else None
    except Exception:
        log.exception("could not queue the report of %s", scan_id)
        return None


class ReportRefused(Exception):
    """A request that cannot be honoured; the message is safe to show."""

    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


def request_report(cfg: dict, dbh, scan_id: str, *, trigger: str = 'manual', model: str = '', requested_by: typing.Optional[int] = None,
                   sections: typing.Optional[typing.List[str]] = None) -> typing.Tuple[dict, bool]:
    """Queue a report on request. Returns (row, created); created is False when one is already queued or running."""
    info = dbh.scanInstanceGet(scan_id)
    if not info:
        raise ReportRefused('Scan not found.', 404)
    if info[5] in RUNNING_STATES:
        raise ReportRefused('The scan is still running; write the report when it has finished.')
    model = str(model or '').strip()[:200]
    opts = {'sections': [s for s in (sections or enabled_sections(cfg)) if s in rs.SECTION_IDS]}
    row, created = dbh.reportCreate(scan_id, trigger, model, opts, requested_by, info[5], int(info[4] or 0))
    if created:
        wake()
    return row, created


# ----------------------------------------------------------------------------------------------------
# generating

_active: typing.Set[str] = set()
_active_lock = threading.Lock()


def blocked(dbh, row: dict) -> str:
    """Why a queued report must wait ('' when it can start): the relevance assessment (it supplies the labels) or the scan itself."""
    info = dbh.scanInstanceGet(row['scan_id'])
    if info is None:
        return ''
    if info[5] in RUNNING_STATES:
        return 'Waiting for the scan to end.'
    run = dbh.relevanceRunGet(row['scan_id'])
    if run.get('status') in ('queued', 'running') and (time.time() - float(run.get('started') or time.time())) < 7200:
        return 'Waiting for the relevance assessment to finish.'
    return ''


def _secrets(cfg: dict, dbh) -> list:
    try:
        from spiderfoot.mcp.context import collect_secrets
        saved = dbh.configGet()
        return collect_secrets(cfg, saved)
    except Exception:
        return []


def _scrub(obj, secrets):
    from spiderfoot.mcp.context import scrub
    return scrub(obj, secrets)


def _progress(dbh, rid: int, done: int, total: int, phase: str, llm: typing.Optional[ReportLLM]) -> None:
    dbh.reportUpdate(rid, phase=phase, sections_done=done, sections_total=total, progress=round(0.1 + 0.85 * done / max(1, total), 3),
                     calls=llm.calls if llm else 0, tokens=llm.tokens if llm else 0,
                     prompt_tokens=llm.prompt_tokens if llm else 0, completion_tokens=llm.completion_tokens if llm else 0)


def _prompt(unit: rs.Unit, section_words: int) -> str:
    return f"SECTION: {unit.title}\nTASK: {unit.task} Keep it under {section_words} words.\nDATA:\n{unit.data}\n"


def generate(cfg: dict, report_id: int, *, dbh=None, llm: typing.Optional[ReportLLM] = None) -> dict:
    """Write one queued (or resumed) report. Returns the final row. Never raises."""
    from spiderfoot import SpiderFootDb
    own = dbh is None
    dbh = dbh or SpiderFootDb(cfg)
    row = dbh.reportGetById(report_id)
    if row is None:
        return {}
    if row['status'] == 'done':
        return row
    if row['status'] == 'queued' and not dbh.reportClaim(report_id):
        return dbh.reportGetById(report_id) or {}
    scan_id = row['scan_id']
    with _active_lock:
        if scan_id in _active:
            return row
        _active.add(scan_id)
    t0 = time.time()
    try:
        return _generate(cfg, dbh, dbh.reportGetById(report_id), llm, t0)
    except Exception:
        log.exception("report %s of scan %s failed", report_id, scan_id)
        try:
            dbh.reportUpdate(report_id, status='failed', phase='failed', ended=int(time.time()),
                             message='The report could not be written; see the server log.')
        except Exception:  # nosec B110
            pass
        return dbh.reportGetById(report_id) or {}
    finally:
        with _active_lock:
            _active.discard(scan_id)
        if own:
            try:
                dbh.close()
            except Exception:  # nosec B110
                pass


def _generate(cfg: dict, dbh, row: dict, llm: typing.Optional[ReportLLM], t0: float) -> dict:
    rid, scan_id = row['id'], row['scan_id']
    options = row.get('options') or {}
    cfg = dict(cfg)
    secrets = _secrets(cfg, dbh)
    appendix_max = num(cfg, '_report_appendix_max')
    section_tokens = num(cfg, '_report_section_tokens')

    # ---- digests (reused when the run is resumed)
    digest, index = None, None
    if row.get('digests') and row['digests'].get('version') == rd.DIGEST_VERSION and row.get('citations'):
        digest, index = row['digests'], rd.CitationIndex.from_dict(row['citations'])
    if digest is None:
        dbh.reportUpdate(rid, phase='reading the scan', progress=0.03)
        digest, index = rd.build(dbh, scan_id, cfg, appendix_max=appendix_max)
        digest, index_dict = _scrub(digest, secrets), _scrub(index.as_dict(), secrets)
        index = rd.CitationIndex.from_dict(index_dict)
        dbh.reportUpdate(rid, digests=digest, citations=index_dict, phase='digests ready', progress=0.08)
    sections = dict(row.get('sections') or {})

    # ---- who writes
    reason_no_ai = ''
    if llm is None:
        llm = ReportLLM.from_config(cfg, model=row.get('model') or '')
        if llm is None:
            reason_no_ai = "the AI assistant is off or not configured"
    if llm is not None:
        llm.max_calls = max(0, num(cfg, '_report_max_calls'))
        llm.max_tokens = max(0, num(cfg, '_report_max_tokens'))
    mode_ai = llm is not None
    enabled = options.get('sections') or enabled_sections(cfg)
    scan_modules = [m for m in str(dbh.scanConfigGet(scan_id).get('_modulesenabled', '')).split(',') if m]
    units = rs.build_units(digest, enabled, section_tokens, cfg, scan_modules)
    total = len(units)
    target = digest['scan']['target']
    known = index.known()

    done = sum(1 for u in units if u.uid in sections)
    for unit in units:
        if unit.uid in sections:
            continue
        _progress(dbh, rid, done, total, f"writing: {unit.title}", llm)
        res = {'uid': unit.uid, 'source': 'fallback', 'prose': '', 'note': '', 'used': [], 'dropped': [], 'bad_numbers': [],
               'sentences': 0, 'cited': 0}
        why = ''
        if not mode_ai:
            why = reason_no_ai
        elif unit.skip_ai:
            why = ''
        elif llm.dead:
            why = 'the AI endpoint stopped answering'
        elif not llm.budget_left:
            why = 'the call or token limit for this report was reached'
        if mode_ai and not why and not unit.skip_ai:
            prompt = _scrub(_prompt(unit, rs.MAX_WORDS.get(unit.section, 150)), secrets)
            try:
                text = llm.complete(prompt, target=target)
            except ReportLLMError as e:
                why = str(e)
                text = ''
            if text:
                text = rs.clean_prose(text)
                text, stats = rs.validate_citations(text, unit.offered, known)
                bad = rs.check_numbers(text, rs.numbers_in(unit.data) | rs.numbers_in(unit.facts))
                if text:
                    res.update(source='ai', prose=_scrub(text, secrets), used=stats['used'], dropped=stats['dropped'], bad_numbers=bad,
                               sentences=stats['sentences'], cited=stats['cited'])
                else:
                    why = 'the model returned nothing usable'
        if res['source'] != 'ai':
            res['prose'] = _scrub(unit.fallback, secrets)
            if unit.fallback and why:
                res['note'] = f"This part was generated without AI: {why}."
            elif mode_ai and unit.fallback and not unit.skip_ai:
                res['note'] = ''
            res['used'] = re.findall(r"\[([EC]\d+)\]", unit.fallback or '')
        sections[unit.uid] = res
        done += 1
        dbh.reportUpdate(rid, sections=sections)
        _progress(dbh, rid, done, total, f"written: {unit.title}", llm)

    # ---- assemble
    dbh.reportUpdate(rid, phase='assembling', progress=0.97)
    ordered = rs.reading_order(units)
    parts, used_all, warnings = [], [], []
    ai_sections = sum(1 for u in units if sections[u.uid]['source'] == 'ai')
    findings_heading_done = False
    for u in ordered:
        r = sections[u.uid]
        if u.section == 'findings' and not findings_heading_done:
            parts.append({'title': rs.SECTION_TITLES['findings'], 'level': 2, 'facts': '', 'prose': '', 'note': ''})
            findings_heading_done = True
        parts.append({'title': u.title, 'level': u.heading_level, 'facts': u.facts, 'prose': r['prose'],
                      'note': r['note'] if ai_sections else ''})
        used_all += [x for x in r['used'] if x not in used_all]
        used_all += [x for x in re.findall(r"\[([EC]\d+)\]", u.facts) if x not in used_all]
        if r['dropped']:
            warnings.append(f"{u.title}: {len(r['dropped'])} citation(s) to findings that do not exist or were not part of this section were removed.")
        if r['bad_numbers']:
            warnings.append(f"{u.title}: the figure(s) {', '.join(r['bad_numbers'][:6])} do not appear in the scan summary given to the model; check them.")
        if r['source'] == 'ai' and u.offered and r['sentences'] >= 3 and r['cited'] == 0:
            warnings.append(f"{u.title}: the model cited no findings; treat this section as unverified.")
    cited = sum(sections[u.uid]['cited'] for u in units)
    sentences = sum(sections[u.uid]['sentences'] for u in units)
    if mode_ai and sentences:
        warnings.append(f"{cited} of {sentences} sentences written by the model carry a citation.")
    fallback_reasons = sorted({sections[u.uid]['note'].split(': ', 1)[-1].rstrip('.') for u in units if sections[u.uid]['note']})
    for fr in fallback_reasons:
        warnings.append(f"Some parts were written without AI: {fr}.")

    rd.finalize_citations(dbh, scan_id, index)
    index_dict = _scrub(index.as_dict(), secrets)
    version = row['version']
    mode = 'ai' if ai_sections else 'deterministic'
    message = ''
    if not ai_sections:
        message = reason_no_ai or ('; '.join(fallback_reasons)[:200] if fallback_reasons else '')
    meta = {
        'scan_id': scan_id, 'scan_name': digest['scan']['name'], 'target': target, 'target_type': digest['scan']['target_type'],
        'scan_status': digest['scan']['status'], 'started': digest['scan']['started'], 'ended': digest['scan']['ended'],
        'duration': digest['scan']['duration'], 'version': version, 'created': row['created'], 'mode': mode,
        'model': llm.model if llm else '', 'model_used': ', '.join(llm.models_used) if llm and llm.models_used else '',
        'calls': llm.calls if llm else 0, 'tokens': llm.tokens if llm else 0, 'partial': digest['scan']['partial'], 'message': message,
    }
    markdown = rr.assemble(meta, parts, index_dict, used_all, warnings, appendix_max)
    markdown = _scrub(markdown, secrets)
    dbh.reportUpdate(
        rid, status='done', mode=mode, phase='done', progress=1.0, markdown=markdown, sections=sections, citations=index_dict,
        warnings=warnings, message=message, ended=int(time.time()), sections_done=len(units), sections_total=len(units),
        model=(llm.model if llm else row.get('model') or ''), model_used=meta['model_used'], calls=meta['calls'], tokens=meta['tokens'],
        prompt_tokens=llm.prompt_tokens if llm else 0, completion_tokens=llm.completion_tokens if llm else 0)
    try:
        dbh.reportPrune(scan_id, num(cfg, '_report_keep'))
    except Exception:
        log.debug("could not prune old reports", exc_info=True)
    if llm and llm.calls:
        _record_usage(dbh, scan_id, version, llm)
    log.info("report v%s of %s written in %.1fs (%s, %d calls, %d tokens)", version, scan_id, time.time() - t0, mode,
             meta['calls'], meta['tokens'])
    return dbh.reportGetById(rid) or {}


def _record_usage(dbh, scan_id: str, version: int, llm: ReportLLM) -> None:
    """Report spending shows up in the AI assistant's monthly cost like the summaries do."""
    try:
        from spiderfoot.services.ai_persistence import upsert_summary
        # the table only allows the kinds 'scan' and 'correlation'; a target id of "report-vN" keeps this apart from the scan summary
        upsert_summary(dbh, scan_id=scan_id, kind='scan', target_id=f"report-v{version}", model_requested=llm.model,
                       model_used=', '.join(llm.models_used) or llm.model, content='', status='complete', scan_ended=None,
                       prompt_tokens=llm.prompt_tokens, completion_tokens=llm.completion_tokens, cost_usd=llm.cost or None,
                       truncation_note=None)
    except Exception:
        log.debug("could not record report usage", exc_info=True)


# ----------------------------------------------------------------------------------------------------
# the queue and its worker

_worker: typing.Optional['_Worker'] = None
_worker_lock = threading.Lock()


class _Worker(threading.Thread):
    def __init__(self, getter: typing.Callable[[], dict], poll: float = 5.0):
        super().__init__(name='report-worker', daemon=True)
        self.getter = getter
        self.poll = poll
        self.event = threading.Event()
        self.stop = threading.Event()
        self.jobs: typing.List[threading.Thread] = []

    def run(self) -> None:
        from spiderfoot import SpiderFootDb
        try:
            dbh = SpiderFootDb(self.getter())
            n = dbh.reportReconcile()
            if n:
                log.info("%d report(s) interrupted by a restart were put back in the queue", n)
            dbh.close()
        except Exception:
            log.debug("report reconcile skipped", exc_info=True)
        while not self.stop.is_set():
            self.event.wait(self.poll)
            self.event.clear()
            try:
                self.step()
            except Exception:
                log.exception("report worker step failed")

    def step(self) -> None:
        from spiderfoot import SpiderFootDb
        cfg = self.getter()
        self.jobs = [j for j in self.jobs if j.is_alive()]
        limit = max(1, min(2, num(cfg, '_report_concurrency')))
        if len(self.jobs) >= limit:
            return
        dbh = SpiderFootDb(cfg)
        try:
            for row in dbh.reportQueued():
                if len(self.jobs) >= limit:
                    break
                with _active_lock:
                    if row['scan_id'] in _active:
                        continue
                why = blocked(dbh, row)
                if why:
                    if row['message'] != why:
                        dbh.reportUpdate(row['id'], phase='waiting', message=why)
                    continue
                if not dbh.reportClaim(row['id']):
                    continue
                t = threading.Thread(target=generate, args=(dict(self.getter()), row['id']), name=f"report-{row['scan_id']}", daemon=True)
                self.jobs.append(t)
                t.start()
        finally:
            dbh.close()


def start_worker(getter: typing.Callable[[], dict], poll: float = 5.0) -> '_Worker':
    """Start the report worker of this process (once). ``getter`` returns the live configuration."""
    global _worker
    with _worker_lock:
        if _worker is None or not _worker.is_alive():
            _worker = _Worker(getter, poll)
            _worker.start()
        return _worker


def worker_alive() -> bool:
    return _worker is not None and _worker.is_alive()


def wake() -> None:
    if _worker is not None:
        _worker.event.set()


def run_pending(cfg: dict, *, llm_factory: typing.Optional[typing.Callable[[], typing.Optional[ReportLLM]]] = None, dbh=None) -> typing.List[int]:
    """Write every queued report that is not blocked, in the calling thread (tests, the command line). Returns the row ids."""
    from spiderfoot import SpiderFootDb
    own = dbh is None
    dbh = dbh or SpiderFootDb(cfg)
    done = []
    try:
        for row in dbh.reportQueued(100):
            if blocked(dbh, row):
                continue
            generate(cfg, row['id'], dbh=dbh, llm=llm_factory() if llm_factory else None)
            done.append(row['id'])
    finally:
        if own:
            dbh.close()
    return done


# ----------------------------------------------------------------------------------------------------
# status for the UI, the API and the MCP server

def public_row(r: dict) -> dict:
    keys = ('version', 'status', 'mode', 'trigger', 'phase', 'progress', 'sections_done', 'sections_total', 'model', 'model_used', 'calls',
            'prompt_tokens', 'completion_tokens', 'tokens', 'message', 'scan_status', 'created', 'started', 'ended')
    return {k: r.get(k) for k in keys}


def status_payload(dbh, scan_id: str, cfg: typing.Optional[dict] = None) -> dict:
    rows = dbh.reportList(scan_id)
    active = next((r for r in rows if r['status'] in ('queued', 'running')), None)
    latest = next((r for r in rows if r['status'] == 'done'), None)
    return {
        'scan': scan_id, 'versions': [public_row(r) for r in rows], 'active': public_row(active) if active else None,
        'latest': public_row(latest) if latest else None, 'running': active is not None, 'worker': worker_alive(),
        'aiReady': ai_ready(cfg) if cfg is not None else None,
    }
