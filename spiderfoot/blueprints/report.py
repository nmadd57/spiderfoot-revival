"""Scan report routes: status, generate, delete, exports and the Report tab.

Reading a report (the tab, the status, the exports) needs view access to the scan. Writing one (generate,
regenerate, delete a version) needs edit access because it spends model tokens. See ``services/route_policy.py``.
The exports contain what the Report tab shows and nothing else: never a setting or a key.
"""

import json
import logging
import re
import time

from flask import Blueprint, Response, current_app, jsonify, render_template, request

from spiderfoot import SpiderFootDb
from spiderfoot.services import ai_service, report_job, report_render

log = logging.getLogger(__name__)

report_bp = Blueprint('report', __name__)
report_frag_bp = Blueprint('report_frag', __name__)

FORMATS = {'md': ('text/markdown; charset=utf-8', 'md'), 'html': ('text/html; charset=utf-8', 'html'),
           'json': ('application/json', 'json')}


def _db():
    return SpiderFootDb(current_app.config['SF_CONFIG'])


def _cfg() -> dict:
    return current_app.config['SF_CONFIG']


def _error(status: int, message: str):
    resp = jsonify({'error': {'http_status': str(status), 'message': message}})
    resp.status_code = status
    return resp


def _version(value):
    try:
        v = int(value)
        return v if v > 0 else None
    except (TypeError, ValueError):
        return None


def allowed_models(cfg: dict) -> list:
    ids = [m['id'] for m in ai_service.model_choices(cfg)]
    rm = str(cfg.get('_report_model') or '').strip()
    if rm and rm not in ids:
        ids.append(rm)
    return ids


def _user_id():
    from spiderfoot.services import identity
    try:
        return identity.current_user_id()
    except Exception:
        return None


@report_bp.route('/status', methods=['GET', 'POST'])
def status():
    """Versions of the scan's report and the state of the one being written."""
    scan_id = request.values.get('id', '')
    return jsonify(report_job.status_payload(_db(), scan_id, _cfg()))


@report_bp.route('/generate', methods=['POST'])
def generate():
    """Queue a new report version (the first or a regeneration). Form values: ``id``, optional ``model``."""
    scan_id = request.values.get('id', '')
    model = request.values.get('model', '').strip()
    cfg = _cfg()
    if model and model not in allowed_models(cfg):
        return _error(400, 'That model is not one of the configured models.')
    dbh = _db()
    try:
        row, created = report_job.request_report(cfg, dbh, scan_id, model=model, requested_by=_user_id())
    except report_job.ReportRefused as e:
        return _error(e.status, str(e))
    if created and not current_app.testing:
        report_job.start_worker(lambda a=current_app._get_current_object(): a.config['SF_CONFIG'])
    return jsonify({'ok': True, 'created': created, 'alreadyRunning': not created, 'report': report_job.public_row(row),
                    'aiReady': report_job.ai_ready(cfg)}), (202 if created else 200)


@report_bp.route('/delete', methods=['POST'])
def delete():
    """Delete one finished or failed version. Form values: ``id``, ``version``."""
    scan_id = request.values.get('id', '')
    version = _version(request.values.get('version'))
    if version is None:
        return _error(400, 'Name the version to delete.')
    removed = _db().reportDelete(scan_id, version)
    if not removed:
        return _error(404, 'No such version, or it is still being written.')
    return jsonify({'ok': True})


def export_body(report: dict, fmt: str, base: str):
    """(content type, extension, body) of an export."""
    ctype, ext = FORMATS[fmt]
    md = report['markdown'] or ''
    if fmt == 'md':
        body = md.replace('](/scaninfo?', f']({base}/scaninfo?') if base else md
    elif fmt == 'html':
        known = [e['id'] for e in report['citations'].get('events', [])] + [c['id'] for c in report['citations'].get('correlations', [])]
        title = f"Scan report: {report['digests'].get('scan', {}).get('target', report['scan_id'])}"
        body = report_render.export_html(md, title, known, base)
    else:
        body = json.dumps({
            'scan': report['scan_id'], 'version': report['version'], 'status': report['status'], 'mode': report['mode'],
            'model': report['model_used'] or report['model'], 'created': report['created'], 'ended': report['ended'],
            'usage': {'calls': report['calls'], 'prompt_tokens': report['prompt_tokens'], 'completion_tokens': report['completion_tokens'],
                      'tokens': report['tokens']},
            'warnings': report['warnings'], 'digests': report['digests'], 'citations': report['citations'],
            'sections': {k: {'source': v.get('source'), 'markdown': v.get('prose'), 'cited': v.get('used')} for k, v in report['sections'].items()},
            'markdown': md,
        }, indent=2, ensure_ascii=False)
    return ctype, ext, body


@report_bp.route('/export', methods=['GET'])
def export():
    """Download a report as ``md``, ``html`` or ``json``. Query: ``id``, ``format``, optional ``v`` (default: the newest finished one)."""
    scan_id = request.args.get('id', '')
    fmt = request.args.get('format', 'md')
    if fmt not in FORMATS:
        return _error(400, 'format must be md, html or json.')
    version = _version(request.args.get('v'))
    report = _db().reportGet(scan_id, version, onlyDone=True)
    if report is None:
        return _error(404, 'There is no finished report for this scan.')
    base = request.host_url.rstrip('/')
    ctype, ext, body = export_body(report, fmt, base)
    name = re.sub(r"[^A-Za-z0-9_.-]", '_', scan_id)[:40]
    resp = Response(body, mimetype=ctype.split(';')[0])
    resp.headers['Content-Type'] = ctype
    disposition = 'inline' if (fmt == 'html' and request.args.get('inline') == '1') else 'attachment'
    resp.headers['Content-Disposition'] = f'{disposition}; filename="spiderfoot-report-{name}-v{report["version"]}.{ext}"'
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    if fmt == 'html':
        resp.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
    return resp


def _fmt_time(ts) -> str:
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(ts)) if ts else ''


def _can_edit(scan_id: str, dbh) -> bool:
    from spiderfoot.services import access, identity
    user = identity.current_user()
    if user is None:
        return False
    try:
        return access.can(user, scan_id, 'edit', dbh, identity.request_settings().unowned_visible)
    except Exception:
        return False


@report_frag_bp.route('', methods=['GET'])
@report_frag_bp.route('/', methods=['GET'])
def view():
    """The Report tab of the scan page (htmx fragment; polls itself while a report is being written)."""
    scan_id = request.args.get('id', '')
    cfg = _cfg()
    dbh = _db()
    rows = dbh.reportList(scan_id)
    wanted = _version(request.args.get('v'))
    active = next((r for r in rows if r['status'] in ('queued', 'running')), None)
    if request.args.get('part') == 'progress':
        # polled every few seconds while a report is written; when it ends the whole tab is reloaded
        if active is None:
            resp = Response('')
            resp.headers['HX-Trigger'] = 'sf-report-changed'
        else:
            resp = Response(render_template('fragments/report_progress_box.html', scan_id=scan_id, active=active, worker=report_job.worker_alive()))
        resp.headers['Cache-Control'] = 'no-store'
        return resp
    shown = None
    if wanted is not None:
        shown = dbh.reportGet(scan_id, wanted)
    if shown is None:
        done = next((r for r in rows if r['status'] == 'done'), None)
        shown = dbh.reportGet(scan_id, done['version']) if done else None
    failed = next((r for r in rows if r['status'] == 'failed' and (not shown or r['version'] > shown['version'])), None)
    body_html, toc, known = '', [], []
    if shown and shown['status'] == 'done':
        known = [e['id'] for e in shown['citations'].get('events', [])] + [c['id'] for c in shown['citations'].get('correlations', [])]
        body_html = report_render.render_markdown(shown['markdown'], known)
        toc = report_render.toc(shown['markdown'])
    models = [m for m in ai_service.model_choices(cfg)]
    default_model = str(cfg.get('_report_model') or cfg.get('_ai_default_model') or '')
    versions = [dict(r, when=_fmt_time(r['created'])) for r in rows]
    resp = Response(render_template(
        'fragments/report_tab.html', scan_id=scan_id, shown=shown, body_html=body_html, toc=toc, active=active, failed=failed,
        versions=versions, can_edit=_can_edit(scan_id, dbh), ai_ready=report_job.ai_ready(cfg), models=models,
        default_model=default_model, worker=report_job.worker_alive(), enabled=True))
    resp.headers['Cache-Control'] = 'no-store'
    return resp
