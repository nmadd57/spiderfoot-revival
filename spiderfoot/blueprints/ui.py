import logging

from flask import Blueprint, current_app, render_template, request

from spiderfoot import SpiderFootDb
from spiderfoot.__version__ import __version__
from spiderfoot.helpers import SpiderFootHelpers
from spiderfoot.services.preset_service import serialize_preset
from spiderfoot.services import ai_service
from spiderfoot.services.ai_persistence import (
    fetch_models_for_scan, fetch_cached
)

ui_bp = Blueprint('ui', __name__)

log = logging.getLogger(f"spiderfoot.{__name__}")


def _get_db():
    """Create a SpiderFootDb handle using the current app config."""
    return SpiderFootDb(current_app.config['SF_CONFIG'])


def _build_scan_list():
    """Return (scans, stats) for the dashboard.

    scans is a list of dicts with keys:
        id, name, target, created, started, ended, status, num_results,
        type_counts, progress

    stats is a dict with keys: running, completed, findings, total_events,
        queued, scans_with_findings, modules_total, modules_needing_keys
    """
    try:
        dbh = _get_db()
        rows = dbh.scanInstanceList()
    except Exception as e:
        log.warning("Could not load scan list: %s", e)
        return [], {'running': 0, 'completed': 0, 'findings': 0,
                    'total_events': 0, 'queued': 0, 'scans_with_findings': 0,
                    'modules_total': 0, 'modules_needing_keys': 0}

    INLINE_TYPES = {
        'INTERNET_NAME': 'hosts',
        'IP_ADDRESS': 'IPs',
        'EMAILADDR': 'emails',
        'TCP_PORT_OPEN': 'ports',
    }

    scans = []
    running = 0
    completed = 0
    findings = 0
    total_events = 0

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
        }
        scans.append(scan)

        status = (scan['status'] or '').upper()
        if status == 'RUNNING':
            running += 1
        elif status == 'FINISHED':
            completed += 1
        total_events += scan['num_results']

        # Inline type counts for scan row breakdown
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

        # Progress for running scans
        if status == 'RUNNING':
            try:
                mod_summary = dbh.scanResultSummary(scan['id'], 'module')
                scan['progress'] = min(95, max(5, len(mod_summary) * 3))
            except Exception:
                pass

    # Count correlations/findings across all scans
    try:
        for scan in scans:
            corrs = dbh.scanCorrelationList(scan['id'])
            if corrs:
                findings += len(corrs)
    except Exception:
        pass

    # Count modules and those needing keys
    sf_config = current_app.config.get('SF_CONFIG', {})
    modules_cfg = sf_config.get('__modules__', {})
    try:
        saved_config = dbh.configGet()
    except Exception:
        saved_config = {}

    modules_total = 0
    modules_needing_keys = 0
    for mod_name, mod_cfg in modules_cfg.items():
        if mod_name.startswith('sfp__stor_'):
            continue
        modules_total += 1
        opts = mod_cfg.get('opts', {})
        api_key_opts = [k for k in opts if any(
            term in k.lower() for term in ('api_key', 'apikey')
        )]
        if api_key_opts:
            has_key = False
            for opt_name in api_key_opts:
                val = saved_config.get(f'{mod_name}:{opt_name}', '') or opts.get(opt_name, '')
                if val:
                    has_key = True
                    break
            if not has_key:
                modules_needing_keys += 1

    stats = {
        'running': running,
        'completed': completed,
        'findings': findings,
        'total_events': total_events,
        'queued': 0,
        'scans_with_findings': sum(1 for s in scans if s['num_results'] > 0),
        'modules_total': modules_total,
        'modules_needing_keys': modules_needing_keys,
    }
    return scans, stats


@ui_bp.route('/')
def dashboard():
    scans, stats = _build_scan_list()
    has_running = any(
        (s.get('status') or '').upper() in ('RUNNING', 'STARTED', 'STARTING')
        for s in scans
    )
    poll_interval = '5s' if has_running else '30s'
    return render_template(
        'pages/dashboard.html',
        page_id='DASHBOARD',
        version=__version__,
        scans=scans,
        stats=stats,
        poll_interval=poll_interval,
    )


def _build_module_settings():
    """Everything the unified Settings -> Modules page needs, keyed by module id.

    Extends the New Scan module data with the editable options (secrets masked),
    scan-derived status (errors, results) and whether usage limits apply.
    """
    from spiderfoot.services import module_options, module_status

    mods, _cats = _build_modules_data(include_disabled=True)
    sf_config = current_app.config.get('SF_CONFIG', {})
    raw = sf_config.get('__modules__', {})
    try:
        saved = _get_db().configGet()
    except Exception:
        saved = {}
    stats = module_status.scan_stats(sf_config.get('__database')) if sf_config.get('__database') else {}
    for name, m in mods.items():
        fields = module_options.build_fields(name, raw.get(name, {}), saved)
        m['fields'] = fields
        m['configurable'] = bool(fields)
        m['stats'] = {**module_status.blank(), **stats.get(name, {})}
        # usage limits only make sense for modules that call a remote service
        m['canLimit'] = not name.startswith('sfp_tool_') and (m['pricing'] != 'local' or m['requiresKey'] or m['needsUrl'])
    return mods


def _build_modules_data(include_disabled=False):
    """Build module metadata for the new-scan page.

    Returns:
        tuple: (modules, categories)
            modules    — dict keyed by module name, ready for Jinja2 tojson
            categories — sorted list of unique category strings
    """
    sf_config = current_app.config.get('SF_CONFIG', {})
    raw = sf_config.get('__modules__', {})

    # Load saved config to check which API keys are configured
    try:
        dbh = _get_db()
        saved_config = dbh.configGet()
    except Exception:
        saved_config = {}

    modules = {}

    from spiderfoot.services import module_state
    disabled = module_state.parse(saved_config.get(module_state.KEY, ''))
    default_off = module_state.parse(saved_config.get(module_state.DEFAULT_OFF_KEY, ''))

    for mod_name, mod_cfg in raw.items():
        # Skip internal storage modules
        if mod_name.startswith('sfp__stor_'):
            continue
        # Skip modules disabled in Settings > Modules
        if mod_name in disabled and not include_disabled:
            continue

        meta = mod_cfg.get('meta', {})
        use_cases = meta.get('useCases', [])
        cats = meta.get('categories', [])
        flags = meta.get('flags', [])
        category = cats[0] if cats else 'Uncategorised'

        # Default enabled state: module is in 'Footprint' use case
        enabled = 'Footprint' in use_cases and mod_name not in default_off

        # Detect local tools: modules with 'tool' flag or that run local binaries
        is_local_tool = 'tool' in flags or mod_name.startswith('sfp_tool_')

        # Check if module requires an API key and if it's configured
        opts = mod_cfg.get('opts', {})
        api_key_opts = [k for k in opts if any(
            term in k.lower() for term in ('api_key', 'apikey', 'api_id', 'accesstoken')
        )]
        # Key-optional modules (e.g. hudsonrock, leakcheck) have key options but no 'apikey' flag.
        requires_key = len(api_key_opts) > 0 and 'apikey' in flags
        key_configured = False
        if requires_key:
            # Check saved config for any of the API key options
            for opt_name in api_key_opts:
                config_key = f'{mod_name}:{opt_name}'
                val = saved_config.get(config_key, '') or opts.get(opt_name, '')
                if val:
                    key_configured = True
                    break

        # Self-hosted service modules (SearXNG, Vane...) need an instance URL instead of a key
        needs_url = 'instance_url' in opts
        url_configured = bool(str(saved_config.get(f'{mod_name}:instance_url', '')
                                  or opts.get('instance_url', '')).strip())

        from spiderfoot.services import tools
        tool_missing = mod_name.startswith('sfp_tool_') and not tools.tool_installed(mod_name, opts, saved_config)

        modules[mod_name] = {
            'toolMissing': tool_missing,
            'name': meta.get('name', mod_name),
            'summary': meta.get('summary', mod_cfg.get('descr', '')),
            'category': category,
            'useCases': use_cases,
            'enabled': enabled,
            'requiresKey': requires_key,
            'keyConfigured': key_configured,
            'needsUrl': needs_url,
            'urlConfigured': url_configured,
            'isLocalTool': is_local_tool,
            'pricing': meta.get('pricing', 'local'),
            'broken': bool(meta.get('broken', False)),
            'disabled': mod_name in disabled,
            'defaultOff': mod_name in default_off,
            'privateIpOk': mod_name in SpiderFootHelpers.PRIVATE_IP_COMPATIBLE_MODULES,
        }

    from spiderfoot.services import auto_disable, usage
    reasons = auto_disable.compute(
        sf_config.get('__database'), saved_config,
        {n: (True, False, 'tool not installed') if m['toolMissing']
         else (m['requiresKey'], m['keyConfigured']) if not m['needsUrl']
         else (True, m['urlConfigured'], 'no instance URL') for n, m in modules.items()})
    issues = {}
    try:
        _conn = usage.connect(sf_config.get('__database'))
        try:
            issues = usage.load_issues(_conn)
        finally:
            _conn.close()
    except Exception:
        issues = {}
    for n, m in modules.items():
        m['autoReason'] = reasons.get(n, '')
        # Failures caused by the operator's own key (rejected, out of credits, rate limited)
        m['keyIssue'] = issues.get(n) if (m['requiresKey'] and m['keyConfigured']) else None
    if not include_disabled:
        modules = {n: m for n, m in modules.items() if not m['autoReason']}

    categories = sorted({m['category'] for m in modules.values()})
    return modules, categories


@ui_bp.route('/newscan')
def newscan():
    modules, categories = _build_modules_data()
    all_modules, _ = _build_modules_data(include_disabled=True)
    auto_hidden = sum(1 for m in all_modules.values() if m['autoReason'] and not m['disabled'])
    dbh = _get_db()
    presets = [serialize_preset(r) for r in dbh.presetList()]
    return render_template(
        'pages/scan_new.html',
        page_id='NEWSCAN',
        version=__version__,
        modules=modules,
        categories=categories,
        presets=presets,
        auto_hidden=auto_hidden,
    )


@ui_bp.route('/scaninfo')
def scaninfo():
    scan_id = request.args.get('id', '')
    if not scan_id:
        return render_template(
            'pages/scan_results.html',
            page_id='SCANINFO',
            version=__version__,
            scan=None,
            event_summary=[],
            correlations=[],
            findings=[],
            total_events=0,
            critical_count=0,
            warning_count=0,
            module_count=0,
            ai_enabled=False,
            default_model='',
            fallback_model='',
            all_models=[],
            cached=[],
            cached_models=[],
            selected='',
            active_cache=None,
        )

    try:
        dbh = _get_db()
        row = dbh.scanInstanceGet(scan_id)
    except Exception as e:
        log.warning("Could not load scan instance %s: %s", scan_id, e)
        row = None

    if not row:
        return render_template(
            'pages/scan_results.html',
            page_id='SCANINFO',
            version=__version__,
            scan=None,
            event_summary=[],
            correlations=[],
            findings=[],
            total_events=0,
            critical_count=0,
            warning_count=0,
            module_count=0,
            ai_enabled=False,
            default_model='',
            fallback_model='',
            all_models=[],
            cached=[],
            cached_models=[],
            selected='',
            active_cache=None,
        )

    # row: (name, seed_target, created, started, ended, status)
    scan = {
        'id': scan_id,
        'name': row[0],
        'target': row[1],
        'created': row[2],
        'started': row[3],
        'ended': row[4],
        'status': row[5],
    }

    # Event summary by type: (type, event_descr, last_in, total, utotal)
    try:
        event_summary = dbh.scanResultSummary(scan_id, 'type')
    except Exception:
        event_summary = []

    # Correlations: (id, title, rule_id, rule_risk, rule_name, rule_descr, rule_logic, event_count)
    try:
        correlations = dbh.scanCorrelationList(scan_id)
    except Exception:
        correlations = []

    # Build findings from correlations
    findings = []
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

    # Counts
    total_events = sum(int(row[3] or 0) for row in event_summary)
    unique_events = sum(int(row[4] or 0) for row in event_summary)
    high_count = sum(1 for f in findings if (f['risk'] or '').upper() == 'HIGH')
    medium_count = sum(1 for f in findings if (f['risk'] or '').upper() == 'MEDIUM')
    low_count = sum(1 for f in findings if (f['risk'] or '').upper() == 'LOW')
    critical_count = high_count
    warning_count = medium_count

    # Module count from summary by module
    try:
        mod_summary = dbh.scanResultSummary(scan_id, 'module')
        module_count = len(mod_summary)
    except Exception:
        module_count = 0

    # Scan duration
    scan_duration = ''
    if scan.get('started') and scan.get('ended'):
        try:
            duration_secs = int(scan['ended']) - int(scan['started'])
            if duration_secs > 0:
                mins, secs = divmod(duration_secs, 60)
                scan_duration = f"{mins}m {secs}s" if mins else f"{secs}s"
        except (ValueError, TypeError):
            pass

    # AI summary context (always populated; fragment hides itself if disabled)
    ai_enabled = bool(current_app.config['SF_CONFIG'].get('_ai_enabled'))
    default_model = current_app.config['SF_CONFIG'].get(
        '_ai_default_model', 'moonshotai/kimi-k2.6'
    )
    fallback_model = current_app.config['SF_CONFIG'].get(
        '_ai_fallback_model', 'z-ai/glm-5.1'
    )
    all_models = ai_service.model_choices(current_app.config['SF_CONFIG'])
    try:
        cached_models = fetch_models_for_scan(
            dbh, scan_id=scan_id, kind='scan', target_id=''
        )
        active_cache = fetch_cached(
            dbh, scan_id=scan_id, kind='scan', target_id='',
            model_requested=default_model,
        )
    except Exception:
        cached_models = []
        active_cache = None

    return render_template(
        'pages/scan_results.html',
        page_id='SCANINFO',
        version=__version__,
        scan=scan,
        event_summary=event_summary,
        correlations=correlations,
        findings=findings,
        total_events=total_events,
        unique_events=unique_events,
        critical_count=critical_count,
        warning_count=warning_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        module_count=module_count,
        scan_duration=scan_duration,
        ai_enabled=ai_enabled,
        default_model=default_model,
        fallback_model=fallback_model,
        all_models=all_models,
        cached=cached_models,
        cached_models=cached_models,
        selected=default_model,
        active_cache=active_cache,
    )


@ui_bp.route('/opts')
def settings():
    # Load saved config values for the default (General) section
    try:
        dbh = _get_db()
        saved_config = dbh.configGet()
    except Exception as e:
        log.warning("Could not load settings config: %s", e)
        saved_config = {}

    # Merge saved config over the live SF_CONFIG so defaults are available
    sf_config = current_app.config.get('SF_CONFIG', {})
    config = dict(sf_config)
    config.update(saved_config)

    return render_template(
        'pages/settings.html',
        page_id='SETTINGS',
        version=__version__,
        config=config,
    )
