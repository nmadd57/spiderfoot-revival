"""The MCP tool catalogue.

Each tool has a description written for an agent, a JSON Schema for its input and a handler that
returns a plain dict. Handlers raise ToolError for anything the agent should read and act on; every
other exception is logged on the server and reported as a generic failure.

Deliberately absent: anything that reads or changes API keys, settings, the passwd file or module
enable switches, and anything that runs raw SQL.
"""

import json
import logging
import time
from datetime import datetime, timezone

from spiderfoot import SpiderFootHelpers
from spiderfoot.mcp import catalog, guardrails, schema
from spiderfoot.mcp.context import ToolError, collect_secrets, scrub
from spiderfoot.services import module_options

log = logging.getLogger('spiderfoot.mcp')

MAX_ROWS = 300  # events, log lines or list entries returned by one call
DATA_LIMIT = 500  # characters of event data returned
TERMINAL = ('FINISHED', 'ABORTED', 'ERROR-FAILED')
RUNNING = ('RUNNING', 'STARTING', 'STARTED')
NAME_PREFIX = 'mcp: '

USE_CASES = ('Footprint', 'Investigate', 'Passive')
USE_CASE_TEXT = {
    'Footprint': 'Understand what the target exposes: hosts, IPs, ports, technologies. Mixes passive lookups with some active modules.',
    'Investigate': 'Deeper research including history and reputation; broadest set, many modules need API keys.',
    'Passive': 'Third-party data sources and public records only; designed to avoid direct contact with the target.',
}
TARGET_TYPES = ('INTERNET_NAME', 'IP_ADDRESS', 'IPV6_ADDRESS', 'NETBLOCK_OWNER', 'NETBLOCKV6_OWNER', 'EMAILADDR',
                'PHONE_NUMBER', 'HUMAN_NAME', 'USERNAME', 'BGP_AS_OWNER', 'COMPANY_NAME', 'BITCOIN_ADDRESS')
TARGET_TEXT = {
    'INTERNET_NAME': 'a domain or host name (example.com, www.example.com)',
    'IP_ADDRESS': 'an IPv4 address (93.184.216.34)',
    'IPV6_ADDRESS': 'an IPv6 address (2001:db8::1)',
    'NETBLOCK_OWNER': 'an IPv4 netblock in CIDR form (93.184.216.0/24)',
    'NETBLOCKV6_OWNER': 'an IPv6 netblock in CIDR form (2001:db8::/32)',
    'EMAILADDR': 'an email address (jane@example.com)',
    'PHONE_NUMBER': 'a phone number with country code (+15551234567)',
    'HUMAN_NAME': 'a person\'s name in double quotes ("Jane Doe")',
    'USERNAME': 'a username in double quotes ("janedoe")',
    'BGP_AS_OWNER': 'an autonomous system number (13335)',
    'COMPANY_NAME': 'a business name: prefix with business: or company: ("business:Acme Widgets LLC"), or quote a name that ends in a legal form ("Acme Widgets LLC")',
    'BITCOIN_ADDRESS': 'a Bitcoin address',
}
TARGET_EVENTS = {t: [t] for t in TARGET_TYPES}
TARGET_EVENTS['INTERNET_NAME'] = ['INTERNET_NAME', 'DOMAIN_NAME']


class Tool:
    def __init__(self, name, title, description, properties, required, annotations, handler):
        self.name = name
        self.title = title
        self.description = description
        self.input_schema = {'type': 'object', 'properties': properties, 'required': list(required),
                             'additionalProperties': False}
        self.annotations = annotations
        self.handler = handler

    def definition(self) -> dict:
        return {'name': self.name, 'title': self.title, 'description': self.description,
                'inputSchema': self.input_schema, 'annotations': dict(self.annotations)}


TOOLS = {}


def tool(name, title, description, properties=None, required=(), read_only=True, destructive=False,
         idempotent=None, open_world=False):
    def register(fn):
        TOOLS[name] = Tool(name, title, description, properties or {}, required, {
            'title': title,
            'readOnlyHint': read_only,
            'destructiveHint': destructive if not read_only else False,
            'idempotentHint': read_only if idempotent is None else idempotent,
            'openWorldHint': open_world,
        }, fn)
        return fn
    return register


def definitions() -> list:
    return [t.definition() for t in TOOLS.values()]


# ---------------------------------------------------------------------------------------------
# helpers

def _iso(seconds):
    try:
        return datetime.fromtimestamp(float(seconds), tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') if seconds else None
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _clip(value, limit):
    text = '' if value is None else str(value)
    return text if len(text) <= limit else text[:limit] + '...'


def _find_scan(dbh, scan_id):
    """(id, row) of an existing scan; row is (name, target, created, started, ended, status)."""
    for candidate in (scan_id, scan_id.upper()):
        row = dbh.scanInstanceGet(candidate)
        if row:
            return candidate, row
    raise ToolError(f"Scan '{scan_id}' does not exist. Use list_scans to see the scan ids.")


def _module_ids(selected: str) -> list:
    return sorted(m.strip() for m in (selected or '').split(',') if m.strip() and not m.startswith('sfp__stor_'))


def _scan_modules(dbh, scan_id):
    try:
        return _module_ids(dbh.scanConfigGet(scan_id).get('_modulesenabled', ''))
    except Exception:
        return []


def _summary(arguments) -> str:
    """Short, safe description of a call's arguments for the audit log."""
    if not isinstance(arguments, dict):
        return ''
    parts = []
    for key, value in list(arguments.items())[:8]:
        if isinstance(value, list):
            shown = ','.join(str(v)[:30] for v in value[:5]) + (f',+{len(value) - 5}' if len(value) > 5 else '')
            parts.append(f'{str(key)[:20]}=[{shown}]')
        else:
            parts.append(f'{str(key)[:20]}={_clip(value, 60)!r}')
    return ' '.join(parts)


def _unknown(index, ids):
    return [i for i in ids if i not in index]


def _get_module(index, mid):
    key = str(mid).strip()
    for candidate in (key, f'sfp_{key}', key.lower()):
        if candidate in index:
            return index[candidate]
    raise ToolError(f"Unknown module '{mid}'. Use list_modules to find module ids.")


def _page(items, args, key):
    limit, offset = args['limit'], args.get('offset', 0)
    window = items[offset:offset + limit]
    return {'total': len(items), 'offset': offset, 'returned': len(window), 'hasMore': offset + len(window) < len(items), key: window}


_LIMIT = {'type': 'integer', 'minimum': 1, 'maximum': MAX_ROWS, 'default': 50, 'description': f'How many entries to return (1-{MAX_ROWS}).'}
_OFFSET = {'type': 'integer', 'minimum': 0, 'default': 0, 'description': 'Entries to skip, for paging.'}
_SCAN_ID = {'type': 'string', 'minLength': 1, 'maxLength': 64, 'description': 'Scan id as returned by create_scan or list_scans (for example 499CFDE6).'}
_CONFIRM_ACTIVE = {'type': 'boolean', 'default': False, 'description': (
    'Set true to include active modules (those that send traffic to the target, such as port scanners and '
    'vulnerability tools). Only honoured when the operator allows active modules; otherwise they are left out.')}


# ---------------------------------------------------------------------------------------------
# read-only: modules, presets, targets

@tool('list_modules', 'List modules',
      'List SpiderFoot modules (data sources and analysers). Start here to see what can be run. Each entry has '
      'id, name, summary, category, pricing (free, free_key = free with an API key, paid, local), flags, whether '
      'it is active (sends traffic to the target; needs operator permission), whether an API key is required, and '
      'whether it is currently available. Unavailable modules (disabled by the operator, no API key, tool not '
      'installed, over quota, ...) are hidden unless only_available is false, and carry unavailableReason. '
      'Use produces/consumes with an event type id (see list_event_types) to find modules by what they do.',
      {
          'query': {'type': 'string', 'maxLength': 100, 'description': 'Text to look for in the module id, name and summary.'},
          'category': {'type': 'string', 'maxLength': 60, 'description': 'Category name, for example "DNS", "Passive DNS", "Search Engines" (case-insensitive).'},
          'pricing': {'type': 'string', 'enum': list(catalog.PRICING), 'description': 'Only modules with this pricing.'},
          'produces': {'type': 'string', 'maxLength': 60, 'description': 'Only modules that produce this event type, for example EMAILADDR.'},
          'consumes': {'type': 'string', 'maxLength': 60, 'description': 'Only modules that react to this event type, for example INTERNET_NAME.'},
          'active': {'type': 'boolean', 'description': 'true: only active modules; false: only modules that never contact the target.'},
          'only_available': {'type': 'boolean', 'default': True, 'description': 'Hide modules that cannot run right now.'},
          'limit': {'type': 'integer', 'minimum': 1, 'maximum': MAX_ROWS, 'default': 100, 'description': f'Entries to return (1-{MAX_ROWS}).'},
          'offset': _OFFSET,
      })
def list_modules(cc, args):
    index = catalog.module_index()
    query = args.get('query', '').strip().lower()
    category = args.get('category', '').strip().lower()
    produces = args.get('produces', '').strip().upper()
    consumes = args.get('consumes', '').strip().upper()
    rows = []
    for m in sorted(index.values(), key=lambda x: x['id']):
        if args['only_available'] and not m['available']:
            continue
        if query and query not in f"{m['id']} {m['name']} {m['summary']}".lower():
            continue
        if category and category not in [c.lower() for c in m['categories'] or [m['category']]]:
            continue
        if args.get('pricing') and m['pricing'] != args['pricing']:
            continue
        if produces and produces not in m['produces']:
            continue
        if consumes and consumes not in m['consumes']:
            continue
        if 'active' in args and m['active'] != args['active']:
            continue
        rows.append(catalog.brief(m))
    out = _page(rows, args, 'modules')
    out['categories'] = sorted({m['category'] for m in index.values()})
    return out


@tool('get_module', 'Get module details',
      'Details of one module: what it does, which event types it watches (consumes) and produces, pricing, flags, '
      'whether it is active, availability, and its non-secret options with their descriptions and defaults. API '
      'keys and other secrets are never shown and cannot be changed through this server.',
      {'module': {'type': 'string', 'minLength': 1, 'maxLength': 80, 'description': 'Module id, for example sfp_dnsresolve (the sfp_ prefix may be left out).'}},
      ['module'])
def get_module(cc, args):
    index = catalog.module_index()
    m = _get_module(index, args['module'])
    raw = cc.ctx.config.get('__modules__', {}).get(m['id'], {})
    fields = module_options.build_fields(m['id'], raw, {})
    defaults = raw.get('opts') or {}
    options = [{'name': f['opt'], 'type': f['kind'], 'default': defaults.get(f['opt']),
                'description': f['label'] if f['label'] != f['opt'] else ''}
               for f in fields if f['group'] == 'options']
    hidden = sum(1 for f in fields if f['group'] != 'options')
    out = catalog.brief(m)
    out.update({'description': m['descr'], 'categories': m['categories'], 'useCases': m['useCases'],
                'watches': m['consumes'], 'produces': m['produces'], 'options': options,
                'hiddenOptions': hidden,
                'note': 'Options are managed by the operator on the Settings page. Credentials and tool paths are not shown.'})
    return out


@tool('list_presets', 'List scan presets',
      'List the ready-made module selections for create_scan: the three use cases (Footprint, Investigate, Passive) '
      'and the named presets (for example Subdomain enum, Quick recon, Threat intel), each with the module ids it '
      'selects, how many are active, and how many are unavailable right now. Pass a preset id or name to create_scan '
      'as `preset`, or a use case name as `use_case`.')
def list_presets(cc, args):
    index = catalog.module_index()
    with cc.ctx.db() as dbh:
        rows = dbh.presetList()
    use_case_ids = {'builtin:footprint': 'Footprint', 'builtin:investigate': 'Investigate', 'builtin:passive': 'Passive'}
    presets = []
    for r in rows:
        ids = [m for m in r['modules'] if m in index]
        presets.append({
            'id': r['id'], 'name': r['name'], 'description': r['description'] or '', 'kind': r['kind'],
            'useCase': use_case_ids.get(r['id']),
            'moduleCount': len(ids),
            'activeModules': [m for m in ids if index[m]['active']],
            'unavailableCount': sum(1 for m in ids if not index[m]['available']),
            'modules': ids,
        })
    use_cases = []
    for uc in USE_CASES:
        members = [m for m in index.values() if uc in m['useCases']]
        use_cases.append({'name': uc, 'description': USE_CASE_TEXT[uc], 'moduleCount': len(members),
                          'availableCount': sum(1 for m in members if m['available']),
                          'activeCount': sum(1 for m in members if m['active'])})
    return {'useCases': use_cases, 'presets': presets,
            'note': 'Active modules are only started when the operator allows them and create_scan gets confirm_active=true.'}


@tool('suggest_modules', 'Suggest modules for a target',
      'Suggest modules that can work on a kind of target or event type, grouped by category, best matches first. '
      'Give either target_type (what you are scanning: INTERNET_NAME for a domain or host, IP_ADDRESS, EMAILADDR, '
      'HUMAN_NAME, COMPANY_NAME, ...) or event_type (any id from list_event_types), and optionally a goal in plain '
      'words ("find subdomains", "leaked credentials") to rank the results. Active modules are marked; they run '
      'only with operator permission and confirm_active. Pass the chosen ids as `modules` to create_scan.',
      {
          'target_type': {'type': 'string', 'enum': list(TARGET_TYPES), 'description': 'Kind of target; use validate_target to find it.'},
          'event_type': {'type': 'string', 'maxLength': 60, 'description': 'Event type id modules should consume, for example IP_ADDRESS.'},
          'goal': {'type': 'string', 'maxLength': 200, 'description': 'What you want to find out, in plain words.'},
          'include_active': {'type': 'boolean', 'default': True, 'description': 'false hides active modules.'},
          'only_available': {'type': 'boolean', 'default': True, 'description': 'false also lists modules that cannot run right now.'},
          'limit': {'type': 'integer', 'minimum': 1, 'maximum': 200, 'default': 60, 'description': 'Most modules to return (1-200).'},
      })
def suggest_modules(cc, args):
    if bool(args.get('target_type')) == bool(args.get('event_type')):
        raise ToolError('Give exactly one of target_type or event_type.')
    events = TARGET_EVENTS[args['target_type']] if args.get('target_type') else [args['event_type'].strip().upper()]
    index = catalog.module_index()
    with cc.ctx.db() as dbh:
        descr = {r[1]: r[0] for r in dbh.eventTypes()}
    if not args.get('target_type') and events[0] not in descr:
        raise ToolError(f"Unknown event type '{args['event_type']}'. Use list_event_types.")
    words = {w for w in ''.join(c if c.isalnum() else ' ' for c in args.get('goal', '').lower()).split() if len(w) >= 3}
    scored = []
    for m in index.values():
        if not set(events) & set(m['consumes']):
            continue
        if args['only_available'] and not m['available']:
            continue
        if m['active'] and not args['include_active']:
            continue
        text = ' '.join([m['id'], m['name'], m['summary'], m['category']] + [f"{p} {descr.get(p, '')}" for p in m['produces']]).lower()
        scored.append((sum(1 for w in words if w in text), m))
    scored.sort(key=lambda sm: (-sm[0], catalog.pricing_rank(sm[1]['pricing']), sm[1]['id']))
    chosen = scored[:args['limit']]
    groups = {}
    for score, m in chosen:
        entry = catalog.brief(m)
        if words:
            entry['relevance'] = score
        entry['produces'] = m['produces'][:12]
        groups.setdefault(m['category'], []).append(entry)
    return {'eventTypes': events, 'total': len(scored), 'returned': len(chosen),
            'groups': [{'category': c, 'modules': mods} for c, mods in groups.items()],
            'note': 'Modules also react to events other modules produce, so a scan finds more than these direct matches.'}


@tool('validate_target', 'Validate a scan target',
      'Check a scan target before creating a scan. Detects its type (domain, IP, netblock, email, phone, person, '
      'username, company, ASN, Bitcoin address), shows the normalised form that would be scanned, says whether it is '
      'private, loopback or link-local (those need operator permission), and which module sets apply. '
      'Names must be double-quoted ("Jane Doe"); businesses take a business: or company: prefix.',
      {'target': {'type': 'string', 'minLength': 1, 'maxLength': 300, 'description': 'The target exactly as you would scan it.'}},
      ['target'])
def validate_target(cc, args):
    from spiderfoot.blueprints.api import clean_user_input, normalize_target
    raw = args['target']
    target, ttype = normalize_target(clean_user_input([raw])[0])
    if ttype is None:
        return {'input': _clip(raw, 100), 'valid': False,
                'problem': 'Unrecognised target type.',
                'accepted': {t: TARGET_TEXT[t] for t in TARGET_TYPES}}
    scope = guardrails.assess_target(target, ttype)
    private_ok = cc.perms['private']
    index = catalog.module_index()
    events = set(TARGET_EVENTS.get(ttype, [ttype]))
    private_ip = ttype in guardrails.IP_TYPES + guardrails.NET_TYPES and SpiderFootHelpers.isPrivateIP(target)
    sets = []
    for uc in USE_CASES:
        members = [m for m in index.values() if uc in m['useCases'] and m['available']
                   and (not private_ip or m['privateIpOk'])]
        sets.append({'useCase': uc, 'availableModules': len(members), 'activeModules': sum(1 for m in members if m['active']),
                     'directlyApplicable': sum(1 for m in members if events & set(m['consumes']))})
    out = {'input': _clip(raw, 100), 'valid': True, 'targetType': ttype, 'description': TARGET_TEXT.get(ttype, ''),
           'target': target, 'private': scope['private'], 'privateKinds': scope['kinds'],
           'moduleSets': sets}
    if scope['private']:
        out['privateAllowed'] = private_ok
        out['note'] = (f"{scope['reason']}. " + ('The operator allows private targets.' if private_ok else
                       'The operator has not allowed private targets, so create_scan will refuse it.')
                       + (' Only modules that work with private IPs will run.' if private_ip else ''))
    else:
        out['note'] = 'Hostnames are also checked at create_scan time for private resolution.' if ttype == 'INTERNET_NAME' else ''
    return out


@tool('list_event_types', 'List event types',
      'List the event type ids that modules consume and produce (INTERNET_NAME, IP_ADDRESS, EMAILADDR, '
      'VULNERABILITY_CVE_HIGH, ...) with a description. Use them with list_modules produces/consumes, '
      'suggest_modules and get_scan_events event_type.',
      {'query': {'type': 'string', 'maxLength': 60, 'description': 'Text to look for in the id or description.'},
       'kind': {'type': 'string', 'enum': ['ENTITY', 'DESCRIPTOR', 'DATA', 'SUBENTITY', 'INTERNAL'],
                'description': 'ENTITY: things like hosts and addresses; DESCRIPTOR: facts about them (ports, banners, risks).'}})
def list_event_types(cc, args):
    query = args.get('query', '').strip().lower()
    with cc.ctx.db() as dbh:
        rows = dbh.eventTypes()
    out = [{'id': r[1], 'description': r[0], 'kind': r[3]} for r in sorted(rows, key=lambda r: r[1])
           if (not query or query in f'{r[1]} {r[0]}'.lower()) and (not args.get('kind') or r[3] == args['kind'])]
    return {'total': len(out), 'eventTypes': out}


# ---------------------------------------------------------------------------------------------
# read-only: scans

@tool('list_scans', 'List scans',
      'List scans, newest first, with id, name, target, status, event count and start/end times. Status is one of '
      'STARTING, RUNNING, FINISHED, ABORT-REQUESTED, ABORTED, ERROR-FAILED. A scan is done when it is FINISHED, '
      'ABORTED or ERROR-FAILED. Scans created through this server have names starting with "mcp: ".',
      {'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100, 'default': 25, 'description': 'Scans to return (1-100).'},
       'offset': _OFFSET,
       'status': {'type': 'string', 'enum': ['STARTING', 'STARTED', 'RUNNING', 'FINISHED', 'ABORT-REQUESTED', 'ABORTED', 'ERROR-FAILED'],
                  'description': 'Only scans in this status.'},
       'mcp_only': {'type': 'boolean', 'default': False, 'description': 'Only scans created through this server.'}})
def list_scans(cc, args):
    with cc.ctx.db() as dbh:
        rows = dbh.scanInstanceList()
    scans = []
    for r in rows:
        if args.get('status') and r[6] != args['status']:
            continue
        if args['mcp_only'] and not str(r[1]).startswith(NAME_PREFIX):
            continue
        scans.append({'scanId': r[0], 'name': r[1], 'target': r[2], 'status': r[6], 'events': int(r[7] or 0),
                      'created': _iso(r[3]), 'started': _iso(r[4]), 'ended': _iso(r[5])})
    return _page(scans, args, 'scans')


@tool('get_scan', 'Get scan status',
      'Status of one scan: state (done is true for FINISHED, ABORTED, ERROR-FAILED), target, timing, total events, '
      'correlation counts by risk, error count, the modules selected, how many have produced results, and an '
      'estimated progress percentage for running scans. Poll this (every 10-30 seconds) after create_scan until '
      'done is true, then read results with get_scan_summary and get_scan_events.',
      {'scan_id': _SCAN_ID}, ['scan_id'])
def get_scan(cc, args):
    with cc.ctx.db() as dbh:
        scan_id, row = _find_scan(dbh, args['scan_id'])
        by_type = dbh.scanResultSummary(scan_id, 'type')
        by_module = dbh.scanResultSummary(scan_id, 'module')
        risk = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for level, count in dbh.scanCorrelationSummary(scan_id, by='risk') or []:
            risk[level] = count
        errors = len(dbh.scanErrors(scan_id, 101))
        selected = _scan_modules(dbh, scan_id)
        ttype = dbh.scanTargetType(scan_id)
    name, target, created, started, ended, status = row
    with_results = len({m[0] for m in by_module} & set(selected))
    done = status in TERMINAL
    percent = 100 if status == 'FINISHED' else (None if done else min(95, max(5, round(100 * with_results / max(1, len(selected))))))
    end = ended if done else time.time()
    return {
        'scanId': scan_id, 'name': name, 'target': target, 'targetType': ttype, 'status': status, 'done': done,
        'created': _iso(created), 'started': _iso(started), 'ended': _iso(ended) if done else None,
        'durationSeconds': int(max(0, end - started)) if started else 0,
        'events': sum(int(t[3] or 0) for t in by_type), 'eventTypes': len(by_type),
        'lastEventAt': _iso(max([t[2] or 0 for t in by_type] or [0])),
        'correlations': risk, 'errors': min(errors, 100), 'moreErrors': errors > 100,
        'modulesSelected': len(selected), 'modulesWithResults': with_results, 'modules': selected,
        'progress': {'percent': percent, 'estimate': not done, 'basis': 'modules that have produced results so far'},
    }


@tool('get_scan_summary', 'Get scan event summary',
      'Counts of the events a scan found, by event type (with description, total and unique values, last seen) and '
      'by producing module. Use it to see what a scan found before reading events of one type with get_scan_events.',
      {'scan_id': _SCAN_ID}, ['scan_id'])
def get_scan_summary(cc, args):
    with cc.ctx.db() as dbh:
        scan_id, row = _find_scan(dbh, args['scan_id'])
        by_type = dbh.scanResultSummary(scan_id, 'type')
        by_module = dbh.scanResultSummary(scan_id, 'module')
    types = sorted(({'type': t[0], 'description': t[1], 'count': int(t[3] or 0), 'unique': int(t[4] or 0), 'lastSeen': _iso(t[2])}
                    for t in by_type), key=lambda x: -x['count'])
    modules = sorted(({'module': m[0], 'count': int(m[3] or 0), 'unique': int(m[4] or 0)} for m in by_module), key=lambda x: -x['count'])
    return {'scanId': scan_id, 'status': row[5], 'totalEvents': sum(t['count'] for t in types), 'byType': types, 'byModule': modules}


@tool('get_scan_events', 'Read scan events',
      'Read the events (findings) of a scan: type, data (cut to 500 characters), producing module, the source event '
      'it came from, confidence, risk, and time. Filter by event_type (exact id from get_scan_summary), module and a '
      'text query, and page with limit/offset (at most 300 per call). Works on running scans too and returns what '
      'has been found so far.',
      {'scan_id': _SCAN_ID,
       'event_type': {'type': 'string', 'maxLength': 60, 'description': 'Only this event type, for example INTERNET_NAME.'},
       'module': {'type': 'string', 'maxLength': 80, 'description': 'Only events produced by this module id.'},
       'query': {'type': 'string', 'maxLength': 200, 'description': 'Only events whose data contains this text (case-insensitive).'},
       'include_false_positives': {'type': 'boolean', 'default': False, 'description': 'Include events marked as false positives.'},
       'limit': _LIMIT, 'offset': _OFFSET}, ['scan_id'])
def get_scan_events(cc, args):
    with cc.ctx.db() as dbh:
        scan_id, row = _find_scan(dbh, args['scan_id'])
        rows = dbh.scanResultEvent(scan_id, args.get('event_type', '').strip() or 'ALL', args.get('module', '').strip() or None,
                                   filterFp=not args['include_false_positives'])
    query = args.get('query', '').strip().lower()
    if query:
        rows = [r for r in rows if query in str(r[1]).lower()]
    events = [{'type': r[4], 'data': _clip(r[1], DATA_LIMIT), 'truncated': len(str(r[1])) > DATA_LIMIT, 'module': r[3],
               'source': _clip(r[2], 200), 'confidence': r[5], 'risk': r[7], 'generated': _iso(r[0]),
               'falsePositive': bool(r[13])} for r in rows[args['offset']:args['offset'] + args['limit']]]
    out = {'scanId': scan_id, 'status': row[5], 'total': len(rows), 'offset': args['offset'], 'returned': len(events),
           'hasMore': args['offset'] + len(events) < len(rows), 'events': events}
    return out


@tool('get_scan_correlations', 'Get scan correlations',
      'The correlations (higher-level findings) SpiderFoot derived from a scan, such as shared hosting, exposed '
      'services or leaked data, each with title, rule, risk (HIGH, MEDIUM, LOW, INFO), description and the number '
      'of events behind it. Best read after the scan is done.',
      {'scan_id': _SCAN_ID, 'risk': {'type': 'string', 'enum': ['HIGH', 'MEDIUM', 'LOW', 'INFO'], 'description': 'Only this risk level.'},
       'limit': _LIMIT, 'offset': _OFFSET}, ['scan_id'])
def get_scan_correlations(cc, args):
    with cc.ctx.db() as dbh:
        scan_id, row = _find_scan(dbh, args['scan_id'])
        rows = dbh.scanCorrelationList(scan_id)
    items = [{'id': r[0], 'title': r[1], 'rule': r[2], 'risk': r[3], 'ruleName': r[4], 'description': _clip(r[5], 400),
              'events': int(r[7] or 0)} for r in rows if not args.get('risk') or r[3] == args['risk']]
    order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
    items.sort(key=lambda x: order.get(x['risk'], 9))
    out = _page(items, args, 'correlations')
    out.update({'scanId': scan_id, 'status': row[5]})
    return out


@tool('get_scan_log', 'Read scan log',
      'The log of a scan (module start-up, warnings, errors). Use it to find out why a scan has few results or '
      'failed. Filter by level; newest first by default; at most 300 lines per call.',
      {'scan_id': _SCAN_ID,
       'level': {'type': 'string', 'enum': ['CRITICAL', 'ERROR', 'WARNING', 'STATUS', 'INFO', 'DEBUG'], 'description': 'Only lines of this level.'},
       'newest_first': {'type': 'boolean', 'default': True, 'description': 'false returns the oldest lines first.'},
       'limit': _LIMIT}, ['scan_id'])
def get_scan_log(cc, args):
    with cc.ctx.db() as dbh:
        scan_id, row = _find_scan(dbh, args['scan_id'])
        rows = dbh.scanLogs(scan_id, limit=None if args.get('level') else args['limit'], reverse=args['newest_first'])
    if args.get('level'):
        rows = [r for r in rows if r[2] == args['level']][:args['limit']]
    lines = [{'time': _iso((r[0] or 0) / 1000), 'level': r[2], 'component': r[1], 'message': _clip(r[3], DATA_LIMIT)} for r in rows]
    return {'scanId': scan_id, 'status': row[5], 'returned': len(lines), 'log': lines}


# ---------------------------------------------------------------------------------------------
# writing

def _launch(cc, dbh, index, name, raw_target, module_ids, confirm_active, target_type=None):
    """The guarded path to a running scan, shared by create_scan and rerun_scan."""
    from spiderfoot.blueprints.api import clean_user_input, normalize_target, start_scan_core
    target, ttype = normalize_target(clean_user_input([raw_target])[0], target_type)
    if ttype is None:
        raise ToolError('Unrecognised target type. Use validate_target to see the accepted formats.')
    scope = guardrails.assess_target(target, ttype, resolve=True)
    if scope['private'] and not cc.perms['private']:
        raise ToolError(f"Refused: {scope['reason']}. The operator has not allowed MCP clients to scan private, loopback "
                        f"or link-local targets.")
    dropped = {}
    keep = []
    for mid in module_ids:
        m = index.get(mid)
        if m and m['active']:
            if not cc.perms['active']:
                dropped[mid] = 'active module: the operator has not allowed MCP clients to run active modules'
                continue
            if not confirm_active:
                dropped[mid] = 'active module: pass confirm_active=true to include it'
                continue
        keep.append(mid)
    if not keep:
        raise ToolError('No modules left to run. ' + _dropped_text(dropped))
    scan_name = (NAME_PREFIX + (name or raw_target).strip())[:100]
    res = start_scan_core(scan_name, raw_target, modulelist=','.join(keep), config=cc.ctx.config, dbh=dbh,
                          logging_queue=cc.ctx.logging_queue, target_type=target_type)
    dropped.update(res.dropped)
    if not res.ok:
        raise ToolError(res.error + (' ' + _dropped_text(dropped) if dropped else ''))
    status = (dbh.scanInstanceGet(res.scan_id) or [None] * 6)[5]
    modules = [m for m in res.modules if not m.startswith('sfp__stor_')]
    by_reason = {}
    for reason in dropped.values():
        by_reason[reason] = by_reason.get(reason, 0) + 1
    return {'scanId': res.scan_id, 'name': scan_name, 'target': res.target, 'targetType': res.target_type, 'status': status,
            'moduleCount': len(modules), 'modules': modules,
            'droppedCount': len(dropped), 'droppedByReason': by_reason,
            'dropped': [{'module': m, 'reason': r} for m, r in sorted(dropped.items())][:50],
            'next': 'Poll get_scan until done is true, then read results with get_scan_summary and get_scan_events.'}


def _dropped_text(dropped: dict) -> str:
    if not dropped:
        return ''
    reasons = {}
    for mid, reason in dropped.items():
        reasons.setdefault(reason, []).append(mid)
    parts = [f"{', '.join(sorted(ids)[:8])}{' ...' if len(ids) > 8 else ''} ({reason})" for reason, ids in reasons.items()]
    return 'Left out: ' + '; '.join(parts) + '.'


@tool('create_scan', 'Create and start a scan',
      'Start a new scan of a target. Choose the modules with exactly one of: modules (explicit ids), preset (id or '
      'name from list_presets) or use_case (Footprint, Investigate, Passive; Passive is designed to avoid direct contact with the target). '
      'Call validate_target first. Active modules (port scans, vulnerability and fingerprinting tools) are left out '
      'unless the operator allows them AND you set confirm_active=true; modules that are disabled or lack a key are '
      'left out too, and the result lists what was dropped and why. Private, loopback and link-local targets need '
      'operator permission. There is a limit on concurrent scans. Returns the scan id; then poll get_scan.',
      {'target': {'type': 'string', 'minLength': 1, 'maxLength': 300, 'description': 'What to scan: domain, IP, netblock, email, phone, "quoted name", business:Name, ASN, ...'},
       'name': {'type': 'string', 'maxLength': 80, 'description': 'Label for the scan (shown with an "mcp: " prefix). Defaults to the target.'},
       'modules': {'type': 'array', 'items': {'type': 'string', 'maxLength': 80}, 'maxItems': 300, 'description': 'Module ids to run, for example ["sfp_dnsresolve","sfp_crt"].'},
       'preset': {'type': 'string', 'maxLength': 100, 'description': 'Preset id or name from list_presets.'},
       'use_case': {'type': 'string', 'enum': list(USE_CASES), 'description': 'Footprint, Investigate or Passive.'},
       'confirm_active': _CONFIRM_ACTIVE}, ['target'], read_only=False, idempotent=False)
def create_scan(cc, args):
    cc.require('scan', 'start scans')
    chosen = [k for k in ('modules', 'preset', 'use_case') if args.get(k)]
    if len(chosen) != 1:
        raise ToolError('Give exactly one of modules, preset or use_case.')
    index = catalog.module_index()
    with cc.ctx.db() as dbh:
        if chosen[0] == 'modules':
            ids = list(dict.fromkeys(m.strip() for m in args['modules'] if m.strip() and not m.startswith('sfp__stor_')))
            unknown = _unknown(index, ids)
            if unknown:
                raise ToolError(f"Unknown module id(s): {', '.join(unknown[:10])}. Use list_modules to find ids.")
        elif chosen[0] == 'preset':
            wanted = args['preset'].strip().lower()
            found = [r for r in dbh.presetList() if wanted in (r['id'].lower(), r['name'].lower())]
            if not found:
                raise ToolError(f"Unknown preset '{args['preset']}'. Use list_presets.")
            ids = [m for m in found[0]['modules'] if m in index]
        else:
            ids = sorted(m['id'] for m in index.values() if args['use_case'] in m['useCases'])
        if not ids:
            raise ToolError('No modules selected.')
        return _launch(cc, dbh, index, args.get('name'), args['target'], ids, args['confirm_active'])


@tool('stop_scan', 'Stop a running scan',
      'Ask a running scan to stop. It finishes the work in progress and ends as ABORTED; poll get_scan to see it '
      'end. Results found so far are kept. Needs the operator\'s permission to run scans.',
      {'scan_id': _SCAN_ID}, ['scan_id'], read_only=False, destructive=False, idempotent=True)
def stop_scan(cc, args):
    cc.require('scan', 'start or stop scans')
    with cc.ctx.db() as dbh:
        scan_id, row = _find_scan(dbh, args['scan_id'])
        status = row[5]
        if status == 'FINISHED':
            raise ToolError(f'Scan {scan_id} has already finished.')
        if status == 'ABORTED':
            raise ToolError(f'Scan {scan_id} has already aborted.')
        if status == 'ABORT-REQUESTED':
            return {'scanId': scan_id, 'status': status, 'note': 'A stop was already requested.'}
        if status not in ('RUNNING', 'STARTING', 'STARTED'):
            raise ToolError(f"Scan {scan_id} is in the state '{status}' and cannot be stopped.")
        dbh.scanInstanceSet(scan_id, status='ABORT-REQUESTED')
    return {'scanId': scan_id, 'status': 'ABORT-REQUESTED', 'note': 'Poll get_scan until done is true.'}


@tool('rerun_scan', 'Rerun a scan',
      'Start a new scan with the same target and modules as an earlier scan. The same rules as create_scan apply: '
      'active modules need operator permission and confirm_active=true, private targets need permission, disabled '
      'modules are dropped, and the concurrent scan limit applies. The original scan is left untouched.',
      {'scan_id': _SCAN_ID, 'confirm_active': _CONFIRM_ACTIVE}, ['scan_id'], read_only=False, idempotent=False)
def rerun_scan(cc, args):
    cc.require('scan', 'start scans')
    index = catalog.module_index()
    known = set(cc.ctx.config.get('__modules__', {}))
    with cc.ctx.db() as dbh:
        scan_id, row = _find_scan(dbh, args['scan_id'])
        ids = _scan_modules(dbh, scan_id)
        if not ids:
            raise ToolError(f'The module list of scan {scan_id} cannot be read, so it cannot be rerun.')
        ttype = dbh.scanTargetType(scan_id) or SpiderFootHelpers.targetTypeFromString(row[1]) \
            or SpiderFootHelpers.targetTypeFromString(f'"{row[1]}"')
        name = row[0][len(NAME_PREFIX):] if str(row[0]).startswith(NAME_PREFIX) else row[0]
        gone = [m for m in ids if m not in known]
        out = _launch(cc, dbh, index, name, row[1], [m for m in ids if m in known], args['confirm_active'], ttype)
    if gone:
        out['dropped'] = (out['dropped'] + [{'module': m, 'reason': 'module no longer exists'} for m in gone])[:50]
        out['droppedCount'] += len(gone)
    out['rerunOf'] = scan_id
    return out


@tool('delete_scan', 'Delete a scan',
      'Permanently delete a finished scan with all its events, log and correlations. This cannot be undone. Only '
      'works when the operator allows deleting, the scan is not running, and confirm is true. Ask the person you are '
      'working for before deleting anything you did not create in this session.',
      {'scan_id': _SCAN_ID, 'confirm': {'type': 'boolean', 'default': False, 'description': 'Must be true to delete.'}},
      ['scan_id'], read_only=False, destructive=True, idempotent=True)
def delete_scan(cc, args):
    cc.require('delete', 'delete scans')
    if args['confirm'] is not True:
        raise ToolError('Deleting is permanent. Call again with confirm=true to delete the scan.')
    with cc.ctx.db() as dbh:
        scan_id, row = _find_scan(dbh, args['scan_id'])
        if row[5] in RUNNING or row[5] == 'ABORT-REQUESTED':
            raise ToolError(f"Scan {scan_id} is {row[5]}. Running scans cannot be deleted; stop it and wait for it to end.")
        dbh.scanInstanceDelete(scan_id)
    return {'scanId': scan_id, 'deleted': True}


# ---------------------------------------------------------------------------------------------
# dispatch

def call_tool(cc, name: str, arguments) -> dict:
    """Run a tool and return the MCP tool result. Never raises; problems come back with isError true."""
    tool_def = TOOLS[name]
    summary = _summary(arguments)
    started = time.monotonic()
    try:
        args = schema.validate(tool_def.input_schema, arguments)
        with cc.ctx.app.app_context():
            result = tool_def.handler(cc, args)
        result = scrub(result, collect_secrets(cc.ctx.config, cc.saved))
        text = json.dumps(result, separators=(',', ':'), ensure_ascii=False, default=str)
        log.info('mcp tool=%s client=%s args=[%s] outcome=ok ms=%d', name, cc.client, summary, (time.monotonic() - started) * 1000)
        return {'content': [{'type': 'text', 'text': text}], 'structuredContent': json.loads(text), 'isError': False}
    except ToolError as e:
        log.info('mcp tool=%s client=%s args=[%s] outcome=refused reason=%r', name, cc.client, summary, str(e)[:160])
        return {'content': [{'type': 'text', 'text': scrub(str(e), collect_secrets(cc.ctx.config, cc.saved))}], 'isError': True}
    except Exception:
        log.exception('mcp tool=%s client=%s args=[%s] outcome=failed', name, cc.client, summary)
        return {'content': [{'type': 'text', 'text': 'The tool failed unexpectedly. The details are in the server log.'}],
                'isError': True}
