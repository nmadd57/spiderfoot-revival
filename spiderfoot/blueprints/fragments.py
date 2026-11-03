import logging
import os
import time
from collections import OrderedDict

from flask import Blueprint, current_app, render_template, request

from spiderfoot import SpiderFootDb
from spiderfoot.services import access, ai_service, identity, relevance_job, relevance_view, scan_listing
from spiderfoot.services.event_service import (
    EVENT_CATEGORIES, categorize_event_summary,
    human_size, dedup_events, build_event_dict,
)

frag_bp = Blueprint('frag', __name__)

log = logging.getLogger(f"spiderfoot.{__name__}")


@frag_bp.after_request
def _no_store_fragments(response):
    # HTMX-swapped fragments must never be cached by the browser, otherwise
    # template edits (e.g. graph layout fix) appear stale until the user
    # clears site data. Fragments are cheap to re-render.
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    return response


def _get_db():
    """Create a SpiderFootDb handle using the current app config."""
    return SpiderFootDb(current_app.config['SF_CONFIG'])


def _load_scans(which=''):
    """Return a list of scan dicts with summary counts for rendering."""
    try:
        dbh = _get_db()
        user, settings = identity.current_user(), identity.request_settings()
        rows = access.filter_scan_list(user, dbh.scanInstanceList(), dbh, settings.unowned_visible)
        info = scan_listing.annotate([r[0] for r in rows], user, dbh, settings)
        rows = [r for r in rows if scan_listing.matches_filter(info[r[0]], which)]
    except Exception as e:
        log.warning("Fragment: could not load scan list: %s", e)
        return []

    INLINE_TYPES = {
        'INTERNET_NAME': 'hosts',
        'IP_ADDRESS': 'IPs',
        'EMAILADDR': 'emails',
        'TCP_PORT_OPEN': 'ports',
    }

    scans = []
    for row in rows:
        scan = {
            'id': row[0],
            'name': row[1],
            'target': row[2],
            'created': row[3],
            'started': row[4],
            'ended': row[5],
            'status': row[6],
            'num_results': int(row[7] or 0),
            'type_counts': [],
            'progress': None,
            'owner': info[row[0]]['owner'],
            'level': info[row[0]]['level'],
            'relation': info[row[0]]['relation'],
        }

        try:
            summary = dbh.scanResultSummary(scan['id'], 'type')
            counts = []
            for s in summary:
                etype = s[0]
                total = int(s[3] or 0)
                if etype in INLINE_TYPES and total > 0:
                    counts.append({'label': INLINE_TYPES[etype], 'count': total})
            scan['type_counts'] = sorted(counts, key=lambda x: -x['count'])[:3]
        except Exception:
            pass

        status = (scan['status'] or '').upper()
        if status == 'RUNNING':
            try:
                mod_summary = dbh.scanResultSummary(scan['id'], 'module')
                scan['progress'] = min(95, max(5, len(mod_summary) * 3))
            except Exception:
                pass

        scans.append(scan)
    return scans


def _can_edit(scan_id, dbh):
    user = identity.current_user()
    if user is None:
        return False
    try:
        return access.can(user, scan_id, 'edit', dbh, identity.request_settings().unowned_visible)
    except Exception:
        return False


def _hidden_by_type(dbh, scan_id):
    """{event type: number of events hidden as unrelated}; empty when the scan has no relevance data."""
    try:
        return {t: c.get('unrelated', 0) for t, c in dbh.relevanceCountsByType(scan_id).items() if c.get('unrelated')}
    except Exception:
        return {}


@frag_bp.route('/scan-table')
def scan_table():
    """Return the <tbody> rows for the scan table (HTMX swap target)."""
    which = request.args.get('show', '')
    scans = _load_scans(which if which in ('mine', 'shared') else '')
    return render_template('fragments/scan_tbody.html', scans=scans)


@frag_bp.route('/results-tab')
def results_tab():
    """Return HTML for a scan results tab (HTMX swap target)."""
    scan_id = request.args.get('id', '')
    tab = request.args.get('tab', 'summary')

    if not scan_id:
        return '<p class="text-sm text-slate-400 p-8 text-center">No scan selected.</p>'

    dbh = _get_db()

    if tab == 'summary':
        # Event summary by type: (type, event_descr, last_in, total, utotal)
        try:
            event_summary = dbh.scanResultSummary(scan_id, 'type')
        except Exception:
            event_summary = []

        # Build findings from correlations (table may not exist in older DBs)
        findings = []
        try:
            correlations = dbh.scanCorrelationList(scan_id)
            for c in correlations:
                findings.append({
                    'id': c[0],
                    'title': c[1],
                    'rule_id': c[2],
                    'risk': c[3] or 'INFO',
                    'rule_name': c[4],
                    'description': c[5] or '',
                    'event_count': c[7] if len(c) > 7 else 0,
                })
        except Exception as e:
            log.debug("Could not load correlations for %s: %s", scan_id, e)

        hidden = _hidden_by_type(dbh, scan_id)
        if hidden and request.args.get('rel', 'hide') == 'hide':
            event_summary = [(r[0], r[1], r[2], max(0, int(r[3] or 0) - hidden.get(r[0], 0)),
                              min(int(r[4] or 0), max(0, int(r[3] or 0) - hidden.get(r[0], 0)))) + tuple(r[5:])
                             for r in event_summary]
            event_summary = [r for r in event_summary if r[3] > 0]

        categories = categorize_event_summary(event_summary)

        return render_template(
            'fragments/results_summary.html',
            findings=findings,
            event_summary=event_summary,
            categories=categories,
        )

    elif tab == 'data':
        # Event rows are fetched client-side via /frag/events (respects stored
        # view mode, dedup, sort from localStorage). We only need the filter
        # dropdown and category chips for the controls shell.
        try:
            event_types = dbh.scanResultSummary(scan_id, 'type')
        except Exception:
            event_types = []

        hidden = _hidden_by_type(dbh, scan_id)
        hide_unrelated = bool(hidden) and request.args.get('rel', 'hide') == 'hide'
        if hide_unrelated:
            event_types = [(r[0], r[1], r[2], max(0, int(r[3] or 0) - hidden.get(r[0], 0))) + tuple(r[4:]) for r in event_types]
            event_types = [r for r in event_types if r[3] > 0]

        type_count_map = {}
        for et in event_types:
            type_count_map[et[0]] = int(et[3] or 0)

        cat_chips = []
        total_all = sum(type_count_map.values())
        cat_chips.append({'key': '', 'label': 'All', 'count': total_all})
        for cat_key, cat_info in EVENT_CATEGORIES.items():
            count = sum(type_count_map.get(t, 0) for t in cat_info['types'])
            if count > 0:
                cat_chips.append({'key': cat_key, 'label': cat_info['label'], 'count': count})

        try:
            rel_counts = dbh.relevanceCounts(scan_id)
        except Exception:
            rel_counts = {}
        return render_template(
            'components/event_table.html',
            event_types=event_types,
            scan_id=scan_id,
            cat_chips=cat_chips,
            has_relevance=sum(rel_counts.values()) > 0,
            rel_counts=rel_counts,
            can_edit=_can_edit(scan_id, dbh),
        )

    elif tab == 'graph':
        return render_template(
            'fragments/results_graph.html',
            scan_id=scan_id,
        )

    elif tab == 'timeline':
        # History: (hourmin, type, count)
        try:
            history = dbh.scanResultHistory(scan_id)
        except Exception:
            history = []

        return render_template(
            'fragments/results_timeline.html',
            history=history,
        )

    elif tab == 'correlations':
        try:
            correlations = dbh.scanCorrelationList(scan_id)
        except Exception:
            correlations = []

        sf_config = current_app.config.get('SF_CONFIG', {})
        ai_enabled = bool(sf_config.get('_ai_enabled'))
        default_model = sf_config.get('_ai_default_model', 'moonshotai/kimi-k2.6')
        all_models = ai_service.model_choices(sf_config)

        return render_template(
            'fragments/results_correlations.html',
            correlations=correlations,
            ai_enabled=ai_enabled,
            default_model=default_model,
            all_models=all_models,
        )

    elif tab == 'log':
        try:
            logs_raw = dbh.scanLogs(scan_id, limit=200, reverse=True)
        except Exception:
            logs_raw = []

        logs = []
        for row in logs_raw:
            raw_ts = row[0] / 1000 if row and row[0] else 0
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(raw_ts)) if raw_ts else ''
            logs.append({
                'time': ts,
                'component': row[1] if len(row) > 1 else '',
                'type': row[2] if len(row) > 2 else 'INFO',
                'message': row[3] if len(row) > 3 else '',
            })

        # Check if scan is still running — scanInstanceGet returns
        # (name, target, created, started, ended, status)
        scan_data = dbh.scanInstanceGet(scan_id)
        is_running = (
            scan_data
            and len(scan_data) > 5
            and scan_data[5] in ('RUNNING', 'STARTING', 'STARTED')
        )

        return render_template(
            'fragments/results_log.html',
            logs=logs,
            scan_id=scan_id,
            is_running=is_running,
        )

    return '<p class="text-sm text-slate-400 p-8 text-center">Unknown tab.</p>'


@frag_bp.route('/log-lines')
def log_lines():
    """Return just the log line divs for HTMX polling (no wrapper)."""
    scan_id = request.args.get('id', '')
    dbh = _get_db()

    try:
        logs_raw = dbh.scanLogs(scan_id, limit=200, reverse=True)
    except Exception:
        logs_raw = []

    logs = []
    for row in logs_raw:
        raw_ts = row[0] / 1000 if row and row[0] else 0
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(raw_ts)) if raw_ts else ''
        logs.append({
            'time': ts,
            'component': row[1] if len(row) > 1 else '',
            'type': row[2] if len(row) > 2 else 'INFO',
            'message': row[3] if len(row) > 3 else '',
        })

    return render_template('fragments/log_lines.html', logs=logs)


REL_MODES = ('hide', 'all', 'strong', 'unclear', 'unrelated')


def _rel_allows(mode: str, label) -> bool:
    """Whether the Relevance filter lets an event with this label through (no label: the scan has no relevance data)."""
    if label is None or mode == 'all':
        return True
    if mode == 'hide':
        return label != 'unrelated'
    if mode == 'strong':
        return label in ('confirmed', 'likely')
    return label == mode


@frag_bp.route('/events')
def events_fragment():
    """Return filtered event table rows (HTMX swap target for search/filter)."""
    scan_id = request.args.get('id', '')
    type_filter = request.args.get('type_filter', 'ALL')
    category_filter = request.args.get('category', '')
    query = request.args.get('q', '').strip().lower()
    sort_by = request.args.get('sort', 'data')
    group_by = request.args.get('group_by', '')
    dedup = request.args.get('dedup', '1')  # Default: deduplicated
    rel_mode = request.args.get('rel', 'hide')
    if rel_mode not in REL_MODES:
        rel_mode = 'hide'
    under = request.args.get('under', '')
    try:
        page = int(request.args.get('page', 1))
    except (ValueError, TypeError):
        page = 1
    per_page = 50

    if not scan_id:
        return ''

    dbh = _get_db()
    try:
        view = relevance_view.View(dbh, scan_id)
    except Exception:
        view = None
    if view is not None and not view.has_data:
        view = None

    # If category filter is set, expand to type codes
    if category_filter and category_filter in EVENT_CATEGORIES:
        allowed_types = set(EVENT_CATEGORIES[category_filter]['types'].keys())
    else:
        allowed_types = None

    # "Show only what hangs off this entity" (the collapsed "N findings under X hidden" lines)
    under_set = None
    under_info = None
    if under and view is not None:
        try:
            rows = dbh.scanEventsForRelevance(scan_id)
            under_set = set(relevance_view.descendants(rows, under)) | {under}
            ent = next((r for r in rows if r[0] == under), None)
            if ent is not None:
                under_info = {'hash': under, 'type': ent[1], 'data': relevance_view.short_data(ent[3]), 'count': len(under_set) - 1}
        except Exception:
            under_set = None

    # Events that the Relevance filter hides are not even read (the query copies the parent's data for every child,
    # which is heavy for big raw records); the parent's data is cut to what the page can show.
    hide_labels = None
    if view is not None and under_set is None:
        hide_labels = {'hide': ('unrelated',), 'strong': ('unclear', 'unrelated'), 'unclear': ('confirmed', 'likely', 'unrelated'),
                       'unrelated': ('confirmed', 'likely', 'unclear')}.get(rel_mode)
    try:
        raw_events = dbh.scanResultEvent(scan_id, type_filter or 'ALL', sourceLimit=4000, hideLabels=hide_labels,
                                         hashes=under_set if under_set is not None else None)
    except Exception:
        raw_events = []

    # What was left out as unrelated (before the text search): the count and the groups under their entity
    unrelated_rows = []
    if view is not None and rel_mode == 'hide' and under_set is None:
        try:
            types = None
            if allowed_types is not None:
                types = list(allowed_types)
            if type_filter and type_filter != 'ALL':
                types = [type_filter] if types is None else [t for t in types if t == type_filter]
            unrelated_rows = dbh.relevanceUnrelatedRows(scan_id, types)
        except Exception:
            unrelated_rows = []

    events = []
    for e in raw_events:
        etype = e[4]
        data_str = str(e[1] or '')
        source_str = str(e[2] or '')

        # Apply category filter
        if allowed_types and etype not in allowed_types:
            continue

        # Apply search filter (also searches source_data for URL context)
        if query:
            searchable = f"{data_str} {e[3] or ''} {e[10] or etype} {source_str}".lower()
            if query not in searchable:
                continue

        label = view.label(e[8]) if view is not None else None
        if under_set is not None:
            if e[8] not in under_set:
                continue
        elif not _rel_allows(rel_mode, label):
            continue

        evt = build_event_dict(e)
        evt['rel'] = view.info(e[8]) if view is not None else None
        events.append(evt)

    # Sorting
    _SORT_KEYS = {
        'data': lambda ev: (ev['data'] or '').lower(),
        'date': lambda ev: ev['generated'] or 0,
        'module': lambda ev: (ev['module'] or '').lower(),
        'type': lambda ev: (ev['type'] or '').lower(),
        'confidence': lambda ev: ev['confidence'] or 0,
        'relevance': lambda ev: (ev['rel'] or {}).get('score', 0.5),
    }
    sort_fn = _SORT_KEYS.get(sort_by, _SORT_KEYS['data'])
    reverse = sort_by in ('date', 'confidence', 'relevance')
    events.sort(key=sort_fn, reverse=reverse)

    raw_count = len(events)

    # Deduplicate: aggregate identical (type, data) into single rows
    if dedup == '1':
        events = dedup_events(events)

    total_count = len(events)

    # The unrelated findings that were left out, collapsed under the entity they hang off
    hidden_groups = []
    hidden_events = len(unrelated_rows)
    if unrelated_rows and not query:
        try:
            hidden_groups = relevance_view.hidden_groups(
                view, ({'hash': r[0], 'source_hash': r[1], 'type': r[2], 'data': r[3]} for r in unrelated_rows))
        except Exception:
            hidden_groups = []
    elif query:
        hidden_events = 0      # the count does not know about the text search

    common = dict(scan_id=scan_id, can_edit=_can_edit(scan_id, dbh), rel_mode=rel_mode, hidden_events=hidden_events,
                  hidden_groups=hidden_groups, under_info=under_info, has_relevance=view is not None)

    # Grouped view
    if group_by in ('module', 'type'):
        groups = OrderedDict()
        for evt in events:
            key = evt[group_by]
            if key not in groups:
                groups[key] = []
            groups[key].append(evt)

        grouped = []
        for key, items in groups.items():
            grouped.append({
                'label': key,
                'count': len(items),
                'events': items[:50],
                'total': len(items),
            })

        return render_template(
            'fragments/event_rows_grouped.html',
            groups=grouped,
            group_by=group_by,
            total_count=total_count,
            **common,
        )

    # Flat view with pagination
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    paged_events = events[start:start + per_page]

    return render_template(
        'fragments/event_rows.html',
        events=paged_events,
        page=page,
        total_pages=total_pages,
        total_count=total_count,
        raw_count=raw_count,
        dedup=dedup,
        **common,
    )


@frag_bp.route('/relevance-card')
def relevance_card():
    """The Relevance card of a scan page: counts per label, the last assessment, the Re-assess button."""
    scan_id = request.args.get('id', '')
    dbh = _get_db()
    from spiderfoot.blueprints.relevance import status_payload
    st = status_payload(dbh, scan_id)
    cfg = current_app.config.get('SF_CONFIG', {})
    run = st['run']
    seed = dbh.scanSeedInfo(scan_id)
    scorable = False
    if seed is not None:
        from spiderfoot.services import relevance_profile
        scorable = relevance_profile.TargetProfile(seed[0], seed[1] or 'HUMAN_NAME').scorable
    ctx_text = st['context']
    return render_template('fragments/relevance_card.html', scan_id=scan_id, st=st, run=run, scorable=scorable,
                           enabled=relevance_job.enabled(cfg), can_edit=_can_edit(scan_id, dbh),
                           labels=relevance_view.LABELS, label_text=relevance_view.LABEL_TEXT, ctx_text=ctx_text)


def _build_api_card_data(sf_config: dict, group_by: str = 'category') -> list:
    """Scan all modules for API key options and return a grouped list.

    Args:
        sf_config: SpiderFoot config dict with '__modules__' key
        group_by: Grouping mode — 'category' (default), 'usecase', or 'flat'

    Returns a list of dicts:
        {group, cards: [{mod_name, service_name, opt_key, value, configured}]}
    Groups are sorted with configured-first logic per group, then alphabetically.
    """

    USE_CASE_LABELS = {
        'Passive': 'Passive Recon',
        'Investigate': 'Investigation',
        'Footprint': 'Footprinting',
    }

    modules_cfg = sf_config.get('__modules__', {})
    raw_cards = []

    for mod_name, mod_cfg in modules_cfg.items():
        if mod_name.startswith('sfp__stor_'):
            continue

        meta = mod_cfg.get('meta', {})
        service_name = meta.get('name', mod_name)
        categories = meta.get('categories', [])
        use_cases = meta.get('useCases', [])
        data_source = meta.get('dataSource', {})
        website = data_source.get('website', '')
        opts = mod_cfg.get('opts', {})
        optdescs = mod_cfg.get('optdescs', {})

        # Determine group based on grouping mode
        if group_by == 'usecase':
            group = USE_CASE_LABELS.get(use_cases[0], use_cases[0]) if use_cases else 'Other'
        elif group_by == 'flat':
            group = 'All Services'
        else:
            group = categories[0] if categories else 'Other'

        # Collect all credential-like opts for this module into a single card
        # (modules with two or more credential fields, e.g. username + key,
        # used to render as multiple cards with the same service name).
        fields = []
        connection_opts = meta.get('connectionOpts') or []
        for opt_key, opt_val in opts.items():
            key_lower = opt_key.lower()
            if opt_key in connection_opts:
                continue  # rendered below, in the module's own order and required-ness
            if 'api_key' in key_lower or 'apikey' in key_lower:
                value = str(opt_val) if opt_val is not None else ''
                fields.append({
                    'opt_key': opt_key,
                    'label': optdescs.get(opt_key, opt_key),
                    'value': value,
                    'configured': bool(value and value.strip()),
                    'kind': 'secret',
                    'required': True,
                })

        # Self-hosted services (SearXNG, Vane...) list the options needed to connect
        # to the user's instance in meta['connectionOpts']; instance_url is required.
        for opt_key in connection_opts:
            if opt_key not in opts or any(f['opt_key'] == opt_key for f in fields):
                continue
            opt_val = opts[opt_key]
            if isinstance(opt_val, bool):
                kind, value = 'bool', '1' if opt_val else '0'
            else:
                value = str(opt_val) if opt_val is not None else ''
                kind = 'secret' if any(t in opt_key.lower() for t in
                                       ('auth', 'token', 'password', 'secret', 'apikey', 'api_key')) else 'text'
            fields.append({
                'opt_key': opt_key,
                'label': optdescs.get(opt_key, opt_key),
                'value': value,
                'configured': bool(value and value.strip()),
                'kind': kind,
                'required': opt_key == 'instance_url',
            })

        if not fields:
            continue

        raw_cards.append({
            'mod_name': mod_name,
            'service_name': service_name,
            'fields': fields,
            'configured': all(f['configured'] for f in fields if f['required']),
            'group': group,
            'website': website,
            'pricing': meta.get('pricing', 'local'),
            'broken': bool(meta.get('broken', False)),
        })

    # Group cards
    groups = {}
    for card in raw_cards:
        g = card['group']
        groups.setdefault(g, []).append(card)

    # Sort cards within each group: configured first, then alphabetically
    for g in groups:
        groups[g].sort(key=lambda c: (0 if c['configured'] else 1, c['service_name'].lower()))

    # Build ordered group list, sorted alphabetically by group name
    grouped = []
    for g in sorted(groups.keys()):
        configured_count = sum(1 for c in groups[g] if c['configured'])
        grouped.append({
            'group': g,
            'cards': groups[g],
            'configured_count': configured_count,
            'total_count': len(groups[g]),
        })

    return grouped


@frag_bp.route('/settings-section')
def settings_section():
    """Return a settings section fragment (HTMX swap target)."""
    section = request.args.get('section', 'general')
    sf_config = current_app.config.get('SF_CONFIG', {})

    # Load saved config from DB and merge
    try:
        dbh = _get_db()
        saved_config = dbh.configGet()
    except Exception as e:
        log.warning("settings_section: could not load config: %s", e)
        saved_config = {}

    config = dict(sf_config)
    config.update(saved_config)

    if section == 'general':
        return render_template('fragments/settings_general.html', config=config)

    elif section == 'modules':
        from spiderfoot.blueprints.ui import _build_module_settings
        from spiderfoot.services import auto_disable
        return render_template('fragments/settings_modules.html', modules=_build_module_settings(),
                               auto_disable=auto_disable.enabled(config))

    elif section == 'search':
        from spiderfoot.services import module_options
        mod = (sf_config.get('__modules__') or {}).get('sfp_searxng', {})
        fields = {f['opt']: f['value'] for f in module_options.build_fields('sfp_searxng', mod, saved_config)}
        return render_template('fragments/settings_search.html', v=fields)

    elif section == 'relevance':
        v = {}
        for key, default in relevance_job.DEFAULTS.items():
            val = config.get(key, default)
            if key == '_rel_embeddings_apikey':
                v[key] = '********' if str(val or '').strip() else ''
            elif isinstance(default, bool):
                v[key] = '1' if val not in (False, 0, '0', 'false', 'False', None) else '0'
            else:
                v[key] = str(val if val is not None else '')
        ai_ready = bool(config.get('_ai_enabled') and (config.get('_ai_base_url') or config.get('_ai_openrouter_key')))
        return render_template('fragments/settings_relevance.html', v=v, ai_models=ai_service.model_choices(config), ai_ready=ai_ready)

    elif section == 'proxy':
        return render_template('fragments/settings_proxy.html', config=config)

    elif section == 'database':
        db_path = sf_config.get('__database') or os.path.expanduser('~/.spiderfoot/spiderfoot.db')
        try:
            db_size = human_size(os.path.getsize(db_path))
        except OSError:
            db_size = 'Unknown'
        return render_template(
            'fragments/settings_database.html',
            db_path=db_path,
            db_size=db_size,
        )

    elif section == 'appearance':
        return render_template('fragments/settings_appearance.html')

    elif section == 'ai':
        from spiderfoot.services.ai_persistence import fetch_monthly_cost

        ai_models = ai_service.model_choices(config)
        try:
            month_start = int(time.time()) - 30 * 86400
            monthly_cost = fetch_monthly_cost(dbh, since_unix=month_start)
        except Exception:
            monthly_cost = 0.0
        return render_template(
            'fragments/settings_ai.html',
            config=config,
            ai_models=ai_models,
            monthly_cost=monthly_cost,
        )

    elif section == 'mcp':
        from spiderfoot.services import mcp_auth
        user = identity.current_user()
        status = mcp_auth.public_status(saved_config)
        status['isAdmin'] = bool(user and user.is_admin)
        status['sso'] = identity.request_settings().oidc_configured
        tokens = []
        if user is not None:
            now = time.time()
            tokens = [dict(t, expired=bool(t['expires'] and t['expires'] < now))
                      for t in _get_db().mcpTokenList(identity.current_user_id())]
        return render_template('fragments/settings_mcp.html', st=status, tokens=tokens)

    elif section == 'access':
        from spiderfoot.blueprints.access import settings_view
        from spiderfoot.services import session_auth
        auth = identity.request_settings()
        view = settings_view(auth, session_auth.external_origin(auth))
        view['legacyUsers'] = bool(current_app.config.get('SF_USERS'))
        users = []
        for u in _get_db().userList():
            row = identity.user_from_row(u, auth)
            users.append({'id': u['id'], 'name': u['display_name'] or u['username'], 'username': u['username'],
                          'email': u['email'], 'role': row.role if row else 'denied', 'groups': u['groups'],
                          'lastLogin': u['last_login'], 'local': u['subject'].startswith('local:')})
        return render_template('fragments/settings_access.html', view=view, users=users)

    return '<p class="text-sm text-slate-400 p-6">Unknown section.</p>'
