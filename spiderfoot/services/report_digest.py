"""Deterministic digests of a scan, the input of the written report.

Nothing here talks to a model. The scan's events, relevance labels, correlations, log and module list are
reduced to small structured summaries (counts, top entities, identity-bearing findings grouped by category,
risks, coverage) and every finding that may be quoted gets a citation id (``E12``) in a :class:`CitationIndex`.
The report sections are then written one at a time from the part of the digest that concerns them.

Findings the relevance layer judged unrelated are only ever counted (by type and by reason class), never listed:
a reader of the scan may see the report, and the report must not leak what the scan's own view hides.
"""

import collections
import re
import time
import typing

from spiderfoot.services import relevance_view, usage

DIGEST_VERSION = 1

LABEL_RANK = {'confirmed': 0, 'likely': 1, 'unclear': 2, None: 2, 'unrelated': 9}
STRONG = ('confirmed', 'likely')

# category key -> (title, event types, type prefixes). The first category that claims a type wins, in this order.
CATEGORIES: 'collections.OrderedDict[str, dict]' = collections.OrderedDict([
    ('exposure', {'title': 'Exposure and leaks',
                  'types': {'PASSWORD_COMPROMISED', 'HASH_COMPROMISED', 'PUBLIC_CODE_REPO', 'CREDIT_CARD_NUMBER', 'IBAN_NUMBER',
                            'SOCIAL_SECURITY_NUMBER', 'ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED', 'DARKNET_MENTION_URL',
                            'DARKNET_MENTION_CONTENT', 'LEAKSITE_URL', 'LEAKSITE_CONTENT'},
                  'prefixes': ('CLOUD_STORAGE_BUCKET',), 'suffixes': ('_COMPROMISED',)}),
    ('reputation', {'title': 'Reputation and threat data',
                    'types': {'RANSOMWARE_VICTIM', 'DEFACED_INTERNET_NAME', 'DEFACED_IPADDR', 'DEFACED_AFFILIATE_INTERNET_NAME',
                              'DEFACED_COHOST'},
                    'prefixes': ('MALICIOUS_', 'BLACKLISTED_', 'VULNERABILITY_')}),
    ('people', {'title': 'People and accounts',
                'types': {'HUMAN_NAME', 'USERNAME', 'ACCOUNT_EXTERNAL_OWNED', 'DATE_HUMAN_DOB', 'ACCOUNT_EXTERNAL_USER_SHARED'}}),
    ('business', {'title': 'Businesses and filings',
                  'types': {'COMPANY_NAME', 'AFFILIATE_COMPANY_NAME', 'COMPANY_FILING', 'LEI', 'FEDERAL_AWARD', 'BUSINESS_REGISTRATION'}}),
    ('licences', {'title': 'Professional licences', 'types': {'PROFESSIONAL_LICENSE'}}),
    ('contact', {'title': 'Contact data (emails, phones, addresses)',
                 'types': {'EMAILADDR', 'EMAILADDR_GENERIC', 'EMAILADDR_DELIVERABLE', 'PHONE_NUMBER', 'PHYSICAL_ADDRESS', 'PHYSICAL_COORDINATES'}}),
    ('social', {'title': 'Social and web presence', 'types': {'SOCIAL_MEDIA', 'LINKED_URL_EXTERNAL', 'WEB_ANALYTICS_ID'}}),
    ('infrastructure', {'title': 'Infrastructure (domains, IPs, ports, certificates, technology)',
                        'types': {'DOMAIN_REGISTRAR', 'DOMAIN_WHOIS', 'OPERATING_SYSTEM', 'SOFTWARE_USED', 'DEVICE_TYPE', 'GEOINFO',
                                  'COUNTRY_NAME', 'DOMAIN_NAME', 'IP_ADDRESS', 'IPV6_ADDRESS', 'INTERNET_NAME'},
                        'prefixes': ('INTERNET_NAME', 'DOMAIN_NAME', 'IP_ADDRESS', 'IPV6_ADDRESS', 'TCP_PORT_OPEN', 'UDP_PORT_OPEN',
                                     'SSL_CERTIFICATE_ISSUE', 'WEBSERVER_TECHNOLOGY', 'WEBSERVER_BANNER', 'BGP_AS', 'NETBLOCK', 'DNS_',
                                     'CO_HOSTED', 'AFFILIATE_INTERNET_NAME', 'AFFILIATE_DOMAIN_NAME', 'AFFILIATE_IPADDR', 'PROVIDER_')}),
])
# counted but never listed: raw data, bulk, noise
SKIP_TYPES = frozenset({'ROOT', 'RAW_RIR_DATA', 'RAW_DNS_RECORDS', 'RAW_FILE_META', 'TARGET_WEB_CONTENT', 'SEARCH_ENGINE_WEB_CONTENT',
                        'HTTP_CODE', 'WIFI_ACCESS_POINT', 'LINKED_URL_INTERNAL', 'WEBSERVER_HTTPHEADERS', 'SSL_CERTIFICATE_RAW',
                        'CO_HOSTED_SITE', 'CO_HOSTED_SITE_DOMAIN', 'INTERNET_NAME_UNRESOLVED', 'TCP_PORT_OPEN_BANNER'})
CATEGORY_ORDER = tuple(CATEGORIES)
# finding categories in the order of the report
REPORT_ORDER = ('people', 'business', 'licences', 'contact', 'infrastructure', 'exposure', 'reputation', 'social')

NAME_SCAN_TYPES = ('HUMAN_NAME', 'COMPANY_NAME')

_URL_RE = re.compile(r"https?://[^\s<>\"']+")
_SFURL_RE = re.compile(r"</?SFURL>")


def category_of(etype: str) -> typing.Optional[str]:
    """The report category of an event type; None for types that are only counted."""
    if etype in SKIP_TYPES:
        return None
    for key, spec in CATEGORIES.items():
        if etype in spec['types'] or any(etype.startswith(p) for p in spec.get('prefixes', ())) \
                or any(etype.endswith(s) for s in spec.get('suffixes', ())):
            return key
    return None


def clean_data(data: str, limit: int = 160) -> str:
    """A finding's data on one line, without SFURL tags, cut to ``limit`` characters."""
    t = _SFURL_RE.sub('', str(data or ''))
    t = re.sub(r"\s+", ' ', t).strip()
    return t if len(t) <= limit else t[:limit - 1].rstrip() + '…'


def first_url(*texts: str) -> str:
    for t in texts:
        m = _URL_RE.search(_SFURL_RE.sub('', str(t or '')))
        if m:
            return m.group(0).rstrip('.,;)')
    return ''


def fmt(n) -> str:
    """Numbers as the report writes them: 11,245."""
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def reason_class(reason: str, target: str = '') -> str:
    """A relevance reason without names, places or identifiers, so reasons can be counted and quoted safely."""
    r = str(reason or '')
    if r.startswith('Found under'):
        return 'Found under something that is about another person or organisation'
    if r.startswith('A different person'):
        return 'A different person'
    r = re.sub(r"\(.*?\)", '', r)
    r = re.sub(r"\{.*", '', r)
    r = re.sub(r"https?://\S+", '', r)
    if re.match(r"^Different (middle|first|last)", r):
        r = r.split(':', 1)[0] + ', so probably another person'
    for tok in {t for t in re.split(r"\W+", str(target)) if len(t) >= 3}:
        r = re.sub(r"\b" + re.escape(tok) + r"(s|'s)?\b", '[name]', r, flags=re.I)
    r = re.sub(r"other \[name\]", 'other people with the name', r)
    r = re.sub(r"^\S*\d\S* ", 'An account name ', r)           # a handle at the start (jane.doe.792 goes by ...)
    r = re.sub(r"\s+", ' ', r).strip(' :,.;')
    return (r[:90] or 'No reason recorded')


def risk_level(score) -> str:
    try:
        v = int(score or 0)
    except (TypeError, ValueError):
        return 'INFO'
    return 'HIGH' if v >= 75 else 'MEDIUM' if v >= 50 else 'LOW' if v >= 25 else 'INFO'


class CitationIndex:
    """Citation ids for the findings the report may quote. ``E`` ids are events, ``C`` ids are correlations."""

    def __init__(self, cap: int = 120):
        self.cap = max(0, int(cap))
        self.events: 'collections.OrderedDict[str, dict]' = collections.OrderedDict()
        self.correlations: 'collections.OrderedDict[str, dict]' = collections.OrderedDict()
        self._by_hash: typing.Dict[str, str] = {}

    def add_event(self, item: dict) -> typing.Optional[str]:
        """Register a finding; returns its id (the existing one when it is already registered), None when the cap is reached."""
        h = item['hash']
        if h in self._by_hash:
            return self._by_hash[h]
        if len(self.events) >= self.cap:
            return None
        cid = f"E{len(self.events) + 1}"
        self.events[cid] = dict(item, id=cid)
        self._by_hash[h] = cid
        return cid

    def add_correlation(self, item: dict) -> str:
        cid = f"C{len(self.correlations) + 1}"
        self.correlations[cid] = dict(item, id=cid)
        return cid

    def known(self) -> typing.Set[str]:
        return set(self.events) | set(self.correlations)

    def as_dict(self) -> dict:
        return {'events': list(self.events.values()), 'correlations': list(self.correlations.values())}

    @classmethod
    def from_dict(cls, data: dict) -> 'CitationIndex':
        idx = cls(cap=10 ** 9)
        for e in (data or {}).get('events', []):
            idx.events[e['id']] = e
            idx._by_hash[e['hash']] = e['id']
        for c in (data or {}).get('correlations', []):
            idx.correlations[c['id']] = c
        return idx


class _Group:
    """Events with the same type and data, as one finding."""
    __slots__ = ('h', 'type', 'module', 'data', 'label', 'score', 'risk', 'count', 'gen', 'reasons', 'method', 'url', 'modules', 'override')

    def __init__(self, ev, label, score, reasons, method, override):
        self.h, self.type, self.module, self.data = ev[0], ev[1], ev[2], ev[3]
        self.label, self.score, self.reasons, self.method, self.override = label, score, reasons, method, override
        self.risk = int(ev[7] or 0)
        self.count = 1
        self.gen = ev[6] or 0
        self.url = ''
        self.modules = {ev[2]}

    def sort_key(self):
        return (LABEL_RANK.get(self.label, 2), -(self.risk or 0), -(self.score or 0), -self.count, -(self.gen or 0))


def _seconds(v) -> int:
    try:
        v = float(v or 0)
    except (TypeError, ValueError):
        return 0
    return int(v / 1000) if v > 1e11 else int(v)


def _top(counter, n: int) -> list:
    return [[k, v] for k, v in counter.most_common(n)]


def infer_profile(modules: typing.Iterable[str], cfg: dict, presets: typing.Optional[list] = None) -> str:
    """What the scan's module selection corresponds to: a saved preset, a use case, or a custom selection."""
    mods = {m for m in modules if not str(m).startswith('sfp__stor_')}
    if not mods:
        return 'unknown module selection'
    for p in presets or []:
        pm = {m for m in (p.get('modules') or []) if not str(m).startswith('sfp__stor_')}
        if pm and pm == mods:
            return f"preset \"{p.get('name') or p.get('id')}\""
    catalogue = (cfg or {}).get('__modules__') or {}
    for case in ('Footprint', 'Investigate', 'Passive'):
        group = {m for m, spec in catalogue.items() if case in (spec or {}).get('group', []) and not m.startswith('sfp__stor_')}
        if group and group == mods:
            return f"{case} use case"
    if catalogue and mods >= {m for m, spec in catalogue.items() if 'Passive' in (spec or {}).get('group', [])} and len(mods) > 50:
        return f"a broad selection of {len(mods)} modules"
    return f"a custom selection of {len(mods)} modules"


def _pick(groups: typing.List[_Group], quota: int, per_type: int) -> typing.List[_Group]:
    """The best ``quota`` findings, at most ``per_type`` of one event type before the rest are filled in."""
    ranked = sorted(groups, key=_Group.sort_key)
    chosen: typing.List[_Group] = []
    seen_types: typing.Counter = collections.Counter()
    seen_entities: typing.Counter = collections.Counter()
    leftovers = []
    for g in ranked:
        if len(chosen) >= quota:
            break
        entity = (g.type, g.data.split(' \u00b7 ')[0][:40].lower())          # ten filings of one company are one lead, not ten
        if seen_types[g.type] >= per_type or seen_entities[entity] >= 2:
            leftovers.append(g)
            continue
        seen_types[g.type] += 1
        seen_entities[entity] += 1
        chosen.append(g)
    for g in leftovers:
        if len(chosen) >= quota:
            break
        chosen.append(g)
    return sorted(chosen, key=_Group.sort_key)


def _item(g: _Group, cid: str) -> dict:
    return {'id': cid, 'hash': g.h, 'type': g.type, 'module': g.module, 'data': clean_data(g.data, 160), 'label': g.label,
            'score': round(g.score, 2) if g.score is not None else None, 'risk': g.risk, 'count': g.count,
            'url': g.url, 'reason': (g.reasons[0][:100] if (g.reasons and g.label in STRONG) else '')}


# findings per section before the cap on the whole report is applied
QUOTAS = {'people': 14, 'business': 12, 'licences': 12, 'contact': 14, 'infrastructure': 16, 'exposure': 14, 'reputation': 14,
          'social': 12, 'identity': 14, 'risks': 14}


def build(dbh, scan_id: str, cfg: typing.Optional[dict] = None, *, appendix_max: int = 120, now: typing.Optional[float] = None) -> typing.Tuple[dict, CitationIndex]:
    """The digest of a scan and its citation index. Raises ValueError when the scan does not exist."""
    cfg = cfg or {}
    info = dbh.scanInstanceGet(scan_id)
    if not info:
        raise ValueError("no such scan")
    name, target, created, started, ended, status = info
    rows = dbh.reportEvents(scan_id)
    rel = dbh.relevanceGet(scan_id)
    has_rel = bool(rel)
    ttype = dbh.scanTargetType(scan_id) or ('HUMAN_NAME' if has_rel else '')      # relevance rows exist for name scans only
    overrides = dbh.overrideGet(scan_id)
    rel_run = dbh.relevanceRunGet(scan_id)
    ctx = dbh.scanContextGet(scan_id)
    modules_enabled = [m for m in str(dbh.scanConfigGet(scan_id).get('_modulesenabled', '')).split(',') if m and not m.startswith('sfp__stor_')]
    started_s, ended_s = _seconds(started), _seconds(ended)
    duration = max(0, ended_s - started_s) if started_s and ended_s else 0

    by_type: typing.Counter = collections.Counter()
    by_module: typing.Counter = collections.Counter()
    label_counts: typing.Counter = collections.Counter()
    hidden_by_type: typing.Counter = collections.Counter()
    hidden_reasons: typing.Counter = collections.Counter()
    unclear_reasons: typing.Counter = collections.Counter()
    name_only = 0
    fp = 0
    total = 0
    seen_keys: typing.Set[tuple] = set()
    groups: typing.Dict[typing.Tuple[str, str], _Group] = {}
    mine_groups: typing.List[_Group] = []
    for ev in rows:
        h, etype, module = ev[0], ev[1], ev[2]
        if etype == 'ROOT':
            continue
        if ev[9]:
            fp += 1
            continue
        total += 1
        seen_keys.add((etype, str(ev[3] or '')[:300]))
        by_type[etype] += 1
        by_module[module] += 1
        r = rel.get(h)
        label = r[1] if r else None
        if label:
            label_counts[label] += 1
        if label == 'unrelated':
            hidden_by_type[etype] += 1
            if r[2]:
                hidden_reasons[reason_class(r[2][0], target)] += 1
            continue
        if label == 'unclear' and r[2]:
            unclear_reasons[reason_class(r[2][0], target)] += 1
        if r and any(re.search(r"name only|only the name|name match", x, re.I) for x in (r[2] or [])[:3]):
            name_only += 1
        cat = category_of(etype)
        if cat is None and h not in overrides:
            continue
        key = (etype, re.sub(r"\s+", ' ', str(ev[3] or '')).strip().lower()[:300])
        g = groups.get(key)
        if g is None:
            g = _Group(ev, label, r[0] if r else None, r[2] if r else [], r[3] if r else '', overrides.get(h, ''))
            groups[key] = g
        else:
            g.count += 1
            g.modules.add(module)
            if LABEL_RANK.get(label, 2) < LABEL_RANK.get(g.label, 2):
                g.h, g.label, g.score, g.reasons, g.method = h, label, (r[0] if r else None), (r[2] if r else []), (r[3] if r else '')
            g.risk = max(g.risk, int(ev[7] or 0))
    for g in groups.values():
        if g.override == 'mine':
            mine_groups.append(g)
        g.url = first_url(g.data)

    # unique findings per category
    cat_groups: typing.Dict[str, typing.List[_Group]] = {k: [] for k in CATEGORIES}
    for g in groups.values():
        c = category_of(g.type)
        if c:
            cat_groups[c].append(g)

    index = CitationIndex(appendix_max)
    active = [k for k in REPORT_ORDER if cat_groups[k]]
    # a global cap smaller than the sum of the quotas shrinks every section alike
    wanted = sum(QUOTAS[k] for k in active) + QUOTAS['identity'] + QUOTAS['risks']
    scale = min(1.0, max(0, appendix_max) / wanted) if wanted else 1.0

    def quota(key):
        return max(2, int(QUOTAS[key] * scale)) if appendix_max else 0

    def register(chosen: typing.List[_Group]) -> typing.List[dict]:
        out = []
        for g in chosen:
            cid = index.add_event({'hash': g.h, 'type': g.type, 'module': g.module, 'data': clean_data(g.data, 200), 'label': g.label,
                                   'score': round(g.score, 2) if g.score is not None else None, 'risk': g.risk, 'count': g.count,
                                   'url': g.url})
            if cid:
                out.append(_item(g, cid))
        return out

    cat_digest: typing.Dict[str, dict] = {}
    for key in REPORT_ORDER:
        gl = cat_groups[key]
        spec = CATEGORIES[key]
        lab = collections.Counter(g.label or 'unscored' for g in gl)
        types: typing.Dict[str, typing.Counter] = collections.defaultdict(collections.Counter)
        for g in gl:
            types[g.type][g.label or 'unscored'] += 1
        type_rows = sorted(([t, sum(c.values()), dict(c)] for t, c in types.items()), key=lambda x: -x[1])
        hidden = sum(n for t, n in hidden_by_type.items() if category_of(t) == key)
        cat_digest[key] = {
            'key': key, 'title': spec['title'], 'unique': len(gl), 'hidden': hidden, 'by_label': dict(lab),
            'events': sum(g.count for g in gl), 'types': type_rows[:12], 'items': [],
        }
    # risks and identity are chosen first so their findings keep their ids when the cap is tight
    risk_pool = [g for k in ('exposure', 'reputation') for g in cat_groups[k]] + \
                [g for k in ('infrastructure', 'contact', 'social', 'business', 'people', 'licences') for g in cat_groups[k] if g.risk >= 25]
    risk_pool = [g for g in {id(g): g for g in risk_pool}.values()]
    risk_items = register(_pick(risk_pool, quota('risks'), max(3, quota('risks') // 3)))

    name_scan = has_rel and ttype in NAME_SCAN_TYPES
    if name_scan:
        id_pool = [g for g in groups.values() if g.override == 'mine' or (g.label in STRONG and category_of(g.type) in
                   ('people', 'business', 'licences', 'contact', 'social'))]
        id_pool += [g for g in groups.values() if g.label == 'unclear' and category_of(g.type) in ('people', 'licences', 'social')]
    else:
        id_pool = [g for g in groups.values() if g.type in ('IP_ADDRESS', 'IPV6_ADDRESS', 'DOMAIN_REGISTRAR', 'COMPANY_NAME', 'BGP_AS_MEMBER',
                                                            'BGP_AS_OWNER', 'GEOINFO', 'COUNTRY_NAME', 'DOMAIN_WHOIS', 'HUMAN_NAME',
                                                            'EMAILADDR', 'PROVIDER_HOSTING', 'PHYSICAL_ADDRESS')]
    id_pool = list({id(g): g for g in id_pool}.values())
    id_items = register(_pick(id_pool, quota('identity'), max(3, quota('identity') // 3)))

    for key in REPORT_ORDER:
        if cat_groups[key]:
            q = quota(key)
            cat_digest[key]['items'] = register(_pick(cat_groups[key], q, max(2, q // 3)))

    # correlations
    corr_rows = dbh.reportCorrelations(scan_id)
    order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
    corr_rows = sorted(corr_rows, key=lambda r: (order.get(str(r[3]).upper(), 9), r[1]))
    corr_by_risk = collections.Counter(str(r[3]).upper() for r in corr_rows)
    corr_items = []
    for r in corr_rows[:12]:
        cid = index.add_correlation({'correlation_id': r[0], 'title': r[1], 'rule': r[2], 'risk': str(r[3]).upper(),
                                     'description': clean_data(r[4], 200), 'events': int(r[5] or 0)})
        corr_items.append(dict(index.correlations[cid]))

    # risk summary
    risk_levels: typing.Counter = collections.Counter()
    risky_types: typing.Counter = collections.Counter()
    for g in groups.values():
        if g.risk:
            risk_levels[risk_level(g.risk)] += 1
            risky_types[g.type] += 1
    exposure_counts = {k: cat_digest[k]['unique'] for k in ('exposure', 'reputation')}

    # coverage: modules without results, key and quota problems, other errors
    produced = dbh.reportModuleCounts(scan_id)
    silent = sorted(m for m in modules_enabled if not produced.get(m))
    key_problems: typing.Dict[str, dict] = {}
    other_errors: typing.Counter = collections.Counter()
    for comp, ltype, msg, n in dbh.reportLogProblems(scan_id):
        mod = str(comp or '').split('.')[-1]
        hit = usage.classify(msg) if ltype in ('ERROR', 'CRITICAL', 'WARNING') else None
        if hit and mod.startswith('sfp_'):
            cur = key_problems.get(mod)
            if cur is None or n > cur['count']:
                key_problems[mod] = {'module': mod, 'kind': hit[0], 'detail': hit[1][:120], 'count': int(n)}
            else:
                cur['count'] += int(n)
        elif ltype in ('ERROR', 'CRITICAL'):
            other_errors[mod or 'scan'] += int(n)
    kinds = collections.Counter(p['kind'] for p in key_problems.values())

    seed_events = sum(1 for ev in rows if ev[1] == ttype and ev[3] == target and not ev[9] and (rel.get(ev[0]) or (0, ''))[1] == 'confirmed')
    strong = label_counts.get('confirmed', 0) + label_counts.get('likely', 0)
    strong_excl_seed = max(0, strong - seed_events)
    unrelated = label_counts.get('unrelated', 0)
    if not name_scan:
        verdict = 'not applicable: this is not a person or business-name scan'
    elif strong_excl_seed >= 5:
        verdict = 'partly confirmed'
    elif strong_excl_seed >= 1:
        verdict = 'mostly unconfirmed: only a few findings are likely to be the target'
    else:
        verdict = 'unconfirmed: no finding besides the target itself is likely to belong to it'
    share = round(100.0 * unrelated / total, 1) if total and name_scan else 0.0

    duration_txt = f"{duration // 3600}h {duration % 3600 // 60}m" if duration >= 3600 else f"{duration // 60}m {duration % 60}s" if duration else ''
    try:
        presets = dbh.presetList()
    except Exception:
        presets = []
    digest = {
        'version': DIGEST_VERSION,
        'scan': {
            'id': scan_id, 'name': name, 'target': target, 'target_type': ttype, 'status': status, 'created': _seconds(created),
            'started': started_s, 'ended': ended_s, 'duration_s': duration, 'duration': duration_txt,
            'partial': status not in ('FINISHED',), 'modules_enabled': len(modules_enabled), 'modules_with_results': len(
                [m for m in produced if not m.startswith('sfp__stor_') and m != 'SpiderFoot UI']),
            'profile': infer_profile(modules_enabled, cfg, presets), 'context': ctx.get('context', ''), 'prune': bool(ctx.get('prune')),
        },
        'totals': {
            'events': total, 'unique': 0, 'false_positives': fp, 'by_label': dict(label_counts),
            'hidden_unrelated': unrelated, 'has_relevance': has_rel, 'types': _top(by_type, 15), 'type_count': len(by_type),
            'modules': _top(by_module, 10),
            'overrides': {'mine': sum(1 for v in overrides.values() if v == 'mine'),
                          'not_related': sum(1 for v in overrides.values() if v == 'not_related')},
        },
        'identity': {
            'name_scan': name_scan, 'verdict': verdict, 'strong': strong_excl_seed, 'confirmed': label_counts.get('confirmed', 0),
            'likely': label_counts.get('likely', 0), 'unclear': label_counts.get('unclear', 0), 'unrelated': unrelated,
            'excluded_share': share, 'excluded_by_type': _top(hidden_by_type, 8), 'excluded_by_reason': _top(hidden_reasons, 6),
            'unclear_by_reason': _top(unclear_reasons, 5), 'name_only': name_only,
            'method': rel_run.get('method', ''), 'relevance_status': rel_run.get('status', 'none'),
            'ai_calls': rel_run.get('calls', 0), 'items': id_items,
            'mine': [i['id'] for i in id_items if any(g.h == i['hash'] and g.override == 'mine' for g in mine_groups)],
        },
        'categories': cat_digest,
        'risks': {'levels': dict(risk_levels), 'risky_types': _top(risky_types, 8), 'exposure': exposure_counts, 'items': risk_items,
                  'correlations': corr_items, 'correlation_counts': dict(corr_by_risk), 'correlation_total': len(corr_rows)},
        'coverage': {
            'modules_enabled': len(modules_enabled), 'silent': [m for m in silent][:30], 'silent_count': len(silent),
            'key_problems': sorted(key_problems.values(), key=lambda p: -p['count'])[:15], 'key_problem_kinds': dict(kinds),
            'other_errors': _top(other_errors, 8), 'aborted': status != 'FINISHED', 'status': status,
            'hidden_unrelated': unrelated, 'unclear': label_counts.get('unclear', 0), 'name_only': name_only,
            'overrides': {'mine': sum(1 for v in overrides.values() if v == 'mine'),
                          'not_related': sum(1 for v in overrides.values() if v == 'not_related')},
        },
        'generated': int(now if now is not None else time.time()),
    }
    digest['totals']['unique'] = len(seen_keys)
    return digest, index


def event_facts(digest: dict) -> typing.Set[str]:
    """Every number that appears in the digest, as written in the report (``11,245`` and ``11245``): used to check the prose."""
    out: typing.Set[str] = set()

    def walk(o):
        if isinstance(o, bool):
            return
        if isinstance(o, (int, float)):
            n = int(o)
            out.add(str(n))
            out.add(fmt(n))
        elif isinstance(o, str):
            for m in re.findall(r"\d[\d,]*(?:\.\d+)?", o):
                out.add(m)
                out.add(m.replace(',', ''))
        elif isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)
    walk(digest)
    return out


def finalize_citations(dbh, scan_id: str, index: CitationIndex, base_url: str = '') -> None:
    """Fill in the source link of the registered findings (the page a finding was found on) for the appendix."""
    hashes = [e['hash'] for e in index.events.values()]
    found = dbh.reportEventsByHash(scan_id, hashes, dataLimit=2000)
    parents = [v[3] for v in found.values() if v[3] and v[3] not in found]
    pfound = dbh.reportEventsByHash(scan_id, parents, dataLimit=600) if parents else {}
    for e in index.events.values():
        row = found.get(e['hash'])
        if not row:
            continue
        e['source'] = relevance_view.short_data(pfound.get(row[3], found.get(row[3], ('', '', '')))[2], 120) if row[3] else ''
        e['url'] = e.get('url') or first_url(row[2], (pfound.get(row[3]) or found.get(row[3]) or ('', '', ''))[2])
