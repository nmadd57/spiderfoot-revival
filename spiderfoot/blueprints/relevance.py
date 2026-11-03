"""Relevance routes: status, re-assessment, the user's corrections and the Settings > Relevance sample test.

Reading needs view access to the scan; marking findings and starting a re-assessment need edit access
(see ``services/route_policy.py``). The sample test is for administrators and never returns a key.
"""

import logging

from flask import Blueprint, current_app, jsonify, request

from spiderfoot import SpiderFootDb
from spiderfoot.services import relevance_job, relevance_view

log = logging.getLogger(__name__)

relevance_bp = Blueprint('relevance', __name__)

MAX_MARK = 5000


def _db():
    return SpiderFootDb(current_app.config['SF_CONFIG'])


def _error(status: int, message: str):
    resp = jsonify({'error': {'http_status': str(status), 'message': message}})
    resp.status_code = status
    return resp


def status_payload(dbh, scan_id: str) -> dict:
    view = relevance_view.View(dbh, scan_id)
    ctx = dbh.scanContextGet(scan_id)
    run = view.run
    return {
        'scan': scan_id, 'hasData': view.has_data, 'counts': view.counts(), 'overrides': len(view.overrides),
        'context': ctx['context'], 'prune': ctx['prune'],
        'run': {k: run.get(k) for k in ('status', 'phase', 'progress', 'method', 'calls', 'tokens', 'embedded', 'started', 'ended', 'message')},
        'running': relevance_job.is_running(scan_id) or run.get('status') in ('queued', 'running'),
    }


@relevance_bp.route('/status', methods=['GET', 'POST'])
def status():
    """Counts per label, the scan's hints and the state of the last assessment."""
    scan_id = request.values.get('id', '')
    dbh = _db()
    return jsonify(status_payload(dbh, scan_id))


@relevance_bp.route('/assess', methods=['POST'])
def assess():
    """Start (or restart) a full re-assessment of a scan in the background."""
    scan_id = request.values.get('id', '')
    dbh = _db()
    if not dbh.scanExists(scan_id):
        return _error(404, 'Scan not found.')
    cfg = current_app.config['SF_CONFIG']
    if not relevance_job.enabled(cfg):
        return _error(409, 'Relevance scoring is switched off in Settings.')
    if request.values.get('context') is not None:
        dbh.scanContextSet(scan_id, relevance_view.clean_context(request.values.get('context')), dbh.scanContextGet(scan_id)['prune'])
    started = relevance_job.start_job(cfg, scan_id)
    return jsonify({'ok': True, 'started': started, 'already': not started})


@relevance_bp.route('/mark', methods=['POST'])
def mark():
    """Record "this is mine" / "not related" for findings; ``scope=lineage`` applies it to everything below them too.

    Form values: ``id`` (scan), ``hashes`` (comma separated event hashes), ``verdict`` (mine | not_related | clear),
    ``scope`` (event | lineage).
    """
    scan_id = request.values.get('id', '')
    verdict = request.values.get('verdict', '')
    scope = request.values.get('scope', 'event')
    hashes = [h.strip() for h in request.values.get('hashes', '').split(',') if h.strip()]
    if verdict not in ('mine', 'not_related', 'clear'):
        return _error(400, 'verdict must be mine, not_related or clear.')
    if not hashes or len(hashes) > MAX_MARK:
        return _error(400, 'Name between 1 and %d findings.' % MAX_MARK)
    dbh = _db()
    rows = dbh.scanEventsForRelevance(scan_id)
    known = {r[0] for r in rows}
    hashes = [h for h in dict.fromkeys(hashes) if h in known]
    if not hashes:
        return _error(404, 'None of those findings belong to this scan.')
    targets = list(hashes)
    if scope == 'lineage':
        for h in hashes:
            targets.extend(relevance_view.descendants(rows, h))
        targets = list(dict.fromkeys(targets))
    elif scope != 'event':
        return _error(400, 'scope must be event or lineage.')
    if verdict == 'mine' and scope == 'lineage':
        targets = hashes          # what hangs off something you own is scored from it; only the finding itself is pinned
    from spiderfoot.services import identity
    uid = None
    try:
        uid = identity.current_user_id()
    except Exception:
        uid = None
    if verdict == 'clear':
        changed = dbh.overrideClear(scan_id, targets)
    else:
        changed = dbh.overrideSet(scan_id, targets, verdict, uid)
        # show the decision straight away; the re-assessment below recomputes what depends on it
        score, label, why = (1.0, 'confirmed', 'You marked this as yours') if verdict == 'mine' else (0.0, 'unrelated', 'You marked this as not related')
        dbh.relevanceStore(scan_id, [(h, score, label, [why], 'override') for h in targets])
    reassessing = False
    cfg = current_app.config['SF_CONFIG']
    if relevance_job.enabled(cfg):
        reassessing = relevance_job.start_job(cfg, scan_id)
    return jsonify({'ok': True, 'changed': changed, 'events': len(targets), 'reassessing': reassessing})


@relevance_bp.route('/test', methods=['POST'])
def test():
    """Score a sample pair through the real pipeline (administrators). JSON: {target, context, candidate, type}."""
    body = request.get_json(silent=True) or {}
    cfg = dict(current_app.config['SF_CONFIG'])
    # form values (saved or not) override the stored settings; masked keys fall back to the stored ones
    for key in ('_rel_embeddings_url', '_rel_embeddings_model', '_rel_ai_model'):
        if isinstance(body.get(key), str):
            cfg[key] = body[key].strip()
    k = body.get('_rel_embeddings_apikey')
    if isinstance(k, str) and k.strip() not in ('', '********'):
        cfg['_rel_embeddings_apikey'] = k.strip()
    for key in ('_rel_use_embeddings', '_rel_use_ai'):
        if key in body:
            cfg[key] = relevance_view.truthy(body[key])
    ctype = str(body.get('type') or 'HUMAN_NAME')
    if ctype not in ('HUMAN_NAME', 'COMPANY_NAME', 'PROFESSIONAL_LICENSE', 'SOCIAL_MEDIA', 'LINKED_URL_EXTERNAL'):
        ctype = 'HUMAN_NAME'
    result = relevance_job.test_pair(cfg, body.get('target'), body.get('context'), body.get('candidate'), ctype)
    return jsonify(result)
