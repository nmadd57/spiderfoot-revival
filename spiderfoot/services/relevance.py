"""Relevance scoring: is a finding actually about the scan target?

A name match is not an identity match. This module scores every event of a person or business-name scan
between 0 and 1 for "is this about my target" from cheap local signals, then lets the embeddings and AI
stages (``relevance_embed``, ``relevance_llm``) adjust the borderline ones. Nothing is deleted: the
score, its label and the reasons are stored next to the event (``tbl_event_relevance``).

Stages (see TECHNICAL.md for the weights):

1. *Evidence* per event: which person or company name it carries and how that compares to the target
   (a different middle name is strong evidence of a different person), geography, identifiers shared with
   anchors (emails, usernames, phones, domains the user gave or marked as theirs), module reliability.
2. *Records*: events that describe the same record (same CRD / NPI / CIK number, or a phone number or
   address that appears in a sibling record) share their name evidence, so a registry's raw JSON can
   expose the middle name that the one-line summary left out.
3. *Lineage*: every event has a parent. An event without evidence of its own inherits its parent's score
   with a decay per event type; an event with evidence is damped by an unrelated parent. Processing is in
   ancestry order, once per event.
4. Optional embedding similarity and AI verdicts adjust the ``own`` score of borderline candidates and the
   lineage pass is repeated (it is cheap).
"""

import json
import math
import re
import typing

from spiderfoot.services import relevance_names as rn
from spiderfoot.services import relevance_profile as rp

LABELS = ('confirmed', 'likely', 'unclear', 'unrelated')

# Event types that carry the identity of a person, company or account. The scan-time gate only ever
# stops these (and what hangs off them); infrastructure events are never pruned on their own.
IDENTITY_TYPES = frozenset({
    'HUMAN_NAME', 'COMPANY_NAME', 'AFFILIATE_COMPANY_NAME', 'PROFESSIONAL_LICENSE', 'COMPANY_FILING', 'LEI',
    'SOCIAL_MEDIA', 'ACCOUNT_EXTERNAL_OWNED', 'USERNAME', 'LINKED_URL_EXTERNAL', 'PHYSICAL_ADDRESS',
    'EMAILADDR', 'PHONE_NUMBER', 'DARKNET_MENTION_CONTENT', 'RANSOMWARE_VICTIM', 'PUBLIC_CODE_REPO',
    'RAW_RIR_DATA',
})
# Types worth embedding / asking an AI about: they have text that says whose they are
TEXT_TYPES = frozenset({
    'HUMAN_NAME', 'COMPANY_NAME', 'AFFILIATE_COMPANY_NAME', 'PROFESSIONAL_LICENSE', 'COMPANY_FILING',
    'SOCIAL_MEDIA', 'ACCOUNT_EXTERNAL_OWNED', 'LINKED_URL_EXTERNAL', 'USERNAME',
})
SKIP_TYPES = frozenset({'ROOT'})

# how much of the parent's relevance an event without evidence of its own keeps
DECAY = {
    'RAW_RIR_DATA': 1.0, 'COMPANY_FILING': 0.95, 'LEI': 0.95, 'COMPANY_NAME': 0.85, 'AFFILIATE_COMPANY_NAME': 0.7,
    'PHYSICAL_ADDRESS': 0.8, 'PHYSICAL_COORDINATES': 0.9, 'PHONE_NUMBER': 0.8, 'EMAILADDR': 0.75,
    'EMAILADDR_GENERIC': 0.6, 'WIFI_ACCESS_POINT': 0.5, 'HUMAN_NAME': 0.8, 'LINKED_URL_EXTERNAL': 0.8,
}
DEFAULT_DECAY = 0.8

# score of a name comparison before adjustments
NAME_BASE = {
    'exact': 0.88, 'exact_initial': 0.78, 'name_only': 0.45, 'name_only_nomid': 0.55, 'initial_only': 0.30,
    'middle_as_first': 0.36, 'last_only': 0.12, 'conflict_initial': 0.12, 'conflict_middle': 0.04, 'different': 0.03,
}
CLASS_RANK = {'exact': 6, 'exact_initial': 5, 'name_only': 3, 'initial_only': 2, 'middle_as_first': 2, 'last_only': 1,
              'conflict_initial': 4, 'conflict_middle': 4, 'different': 0}
CONFLICTS = ('conflict_initial', 'conflict_middle')

MODULE_PRIOR = {            # reliability of a name hit from this module
    'sfp_searxng': -0.05, 'sfp_socialprofiles': -0.02, 'sfp_accounts': -0.03, 'sfp_social': -0.03,
}
SEARCH_PRIOR = {'person': 0.45, 'business': 0.60}   # a record found by searching the seed's name, no other evidence
PARENT_FLOOR = 0.4                                   # share of its own score an event keeps under an unrelated parent
INHERITED_MAX = 0.78                                 # what is derived from something is never 'confirmed' by lineage alone
UNCONFIRMED_LEAD = 0.75                              # derived events under a parent that is only 'unclear'
ANCHOR_BONUS = 0.45
GEO_MATCH, GEO_MISMATCH = 0.15, -0.35
ANCHOR_GEO_MATCH, ANCHOR_GEO_MISMATCH = 0.05, -0.12
HINT_WORDS_BONUS = 0.12
RELATIVE_BONUS = 0.15
CORROBORATION_STEP, CORROBORATION_MAX = 0.06, 0.12
WEAK_METHOD_PENALTY = -0.10


class Thresholds:
    """Score cut-offs of the labels (fractions 0..1)."""

    def __init__(self, hide_below: float = 0.25, likely: float = 0.55, confirmed: float = 0.80):
        self.hide_below = max(0.0, min(0.9, float(hide_below)))
        self.likely = max(self.hide_below, min(0.95, float(likely)))
        self.confirmed = max(self.likely, min(1.0, float(confirmed)))

    def label(self, score: float) -> str:
        if score >= self.confirmed:
            return 'confirmed'
        if score >= self.likely:
            return 'likely'
        if score >= self.hide_below:
            return 'unclear'
        return 'unrelated'

    @classmethod
    def from_config(cls, cfg: dict) -> 'Thresholds':
        def pct(key, default):
            try:
                return int(cfg.get(key, default)) / 100.0
            except (TypeError, ValueError):
                return default / 100.0
        return cls(pct('_rel_t_unrelated', 25), pct('_rel_t_likely', 55), pct('_rel_t_confirmed', 80))


class Ev:
    """A scan event reduced to what scoring needs."""
    __slots__ = ('h', 'type', 'module', 'data', 'parent', 'gen', 'fp', 'depth', 'ev', 'children')

    def __init__(self, h, etype, module, data, parent, gen=0, fp=0):
        self.h, self.type, self.module, self.data, self.parent, self.gen, self.fp = h, etype, module, str(data or ''), parent, gen, fp
        self.depth = 0
        self.ev = None
        self.children = None


class Res:
    """The relevance of one event."""
    __slots__ = ('score', 'label', 'reasons', 'method', 'own', 'locked')

    def __init__(self, score, label, reasons, method='heuristics', own=None, locked=False):
        self.score, self.label, self.reasons, self.method, self.own, self.locked = score, label, reasons, method, own, locked

    def as_dict(self) -> dict:
        return {'score': round(self.score, 3), 'label': self.label, 'reasons': list(self.reasons), 'method': self.method}


class Evidence:
    """What one event says about whose it is."""
    __slots__ = ('names', 'cls', 'cls_kind', 'company_sim', 'states', 'keys', 'text', 'idents', 'weak', 'has_name_field', 'url_slugs')

    def __init__(self):
        self.names = []        # [(Name, kind)] kind: written | slug | alias
        self.cls = None
        self.cls_kind = ''
        self.company_sim = None
        self.states = set()
        self.keys = set()
        self.text = ''
        self.idents = set()
        self.weak = False
        self.has_name_field = False
        self.url_slugs = []


_NAME_KEYS = re.compile(r"(^|_)(name|caption|person|full_?name|owner|holder|officer|registrant)$", re.I)
_OTHER_KEYS = re.compile(r"(other_?names|aliases|alias|aka|previous_?names|alt_?names)$", re.I)
_URL_RE = re.compile(r"https?://[^\s<>\"']+")
_KEY_RES = (
    ('crd', re.compile(r"\bCRD[ #:]*(\d{5,8})\b|\"ind_source_id\"\s*:\s*\"?(\d{5,8})|individual/summary/(\d{5,8})")),
    ('npi', re.compile(r"\bNPI[ #:]*(\d{10})\b|provider-view/(\d{10})|\"number\"\s*:\s*\"?(\d{10})\"?")),
    ('cik', re.compile(r"/edgar/data/(\d{4,10})/|\"cik\"\s*:\s*\"?(\d{4,10})")),
)
_WEAK_RE = re.compile(r"matched on name only|name match|name only", re.I)
_EMAIL_RE = rp.EMAIL_RE


def _walk_names(obj, out: list, depth: int = 0, budget: list = None) -> None:
    """Collect person names from a parsed JSON record (first/middle/last fields and name-like keys)."""
    if budget is None:
        budget = [250]
    if budget[0] <= 0 or depth > 5:
        return
    budget[0] -= 1
    if isinstance(obj, dict):
        first = last = middle = None
        for k, v in obj.items():
            if not isinstance(v, str):
                continue
            lk = k.lower()
            if 'first' in lk and 'name' in lk:
                first = v
            elif 'last' in lk and 'name' in lk:
                last = v
            elif 'middle' in lk and 'name' in lk:
                middle = v
        if first and last:
            out.append((rn.parse(' '.join(x for x in (first, middle, last) if x)), 'written'))
        for k, v in obj.items():
            if _OTHER_KEYS.search(k):
                for item in (v if isinstance(v, list) else [v]):
                    if isinstance(item, str):
                        out.append((rn.parse(item), 'alias'))
            elif isinstance(v, str) and _NAME_KEYS.search(k) and len(v) < 80:
                n = rn.parse(v)
                if n:
                    out.append((n, 'written'))
            elif isinstance(v, (dict, list)):
                _walk_names(v, out, depth + 1, budget)
    elif isinstance(obj, list):
        for item in obj[:60]:
            if isinstance(item, (dict, list)):
                _walk_names(item, out, depth + 1, budget)


def _json_companies(obj, out: list, depth: int = 0) -> None:
    if depth > 3:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and k.lower() in ('company', 'company_name', 'entity', 'organization', 'organisation', 'registrant', 'firm') and len(v) < 120:
                out.append(v)
            elif isinstance(v, (dict, list)):
                _json_companies(v, out, depth + 1)
    elif isinstance(obj, list):
        for item in obj[:30]:
            _json_companies(item, out, depth + 1)


def record_keys(text: str) -> set:
    keys = set()
    for kind, rx in _KEY_RES:
        for m in rx.finditer(text):
            val = next((g for g in m.groups() if g), None)
            if val:
                keys.add(f"{kind}:{val.lstrip('0')}")
    return keys


def url_slugs(url: str) -> list:
    """Every path segment of a profile URL that could name the account (the caller picks the strongest)."""
    m = re.match(r"https?://(?:www\.)?([^/?#]+)(/[^?#]*)?", url.strip())
    if not m:
        return []
    segs = [p.lstrip('@') for p in (m.group(2) or '').split('/') if p and len(p) > 1][:6]
    if len(segs) >= 2:
        segs.append(segs[-2] + '-' + segs[-1])      # /pub/dir/Nicholas/Thornwood
    return [x for x in segs if len(x) > 2]


def url_slug(url: str) -> str:
    """The part of a profile URL that names the account (``/in/<slug>``, ``/@handle``, last path element)."""
    m = re.match(r"https?://(?:www\.)?([^/?#]+)(/[^?#]*)?", url.strip())
    if not m:
        return ''
    path = [p for p in (m.group(2) or '').split('/') if p]
    if not path:
        return ''
    for i, p in enumerate(path):
        if p in ('in', 'pub', 'profile', 'people', 'user', 'users', 'u', 'name', 'author', 'show', 'player', 'players', 'person') and i + 1 < len(path):
            cand = path[i + 1]
            if cand in ('dir', 'show'):
                continue
            return cand
    last = path[-1]
    if last.startswith('@'):
        return last[1:]
    return last


def _norm_text(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", ' ', s.lower()).strip()


class Assessment:
    """Scores the events of one scan.

    ``events`` is an iterable of ``(hash, type, module, data, source_event_hash[, generated[, false_positive]])``.
    """

    def __init__(self, events: typing.Iterable, profile: rp.TargetProfile, thresholds: Thresholds = None,
                 overrides: typing.Optional[typing.Dict[str, str]] = None):
        self.profile = profile
        self.th = thresholds or Thresholds()
        self.overrides = dict(overrides or {})
        self.by_hash: typing.Dict[str, Ev] = {}
        for row in events:
            if row[1] in SKIP_TYPES:
                continue
            e = Ev(row[0], row[1], row[2] or '', row[3], row[4], row[5] if len(row) > 5 else 0, row[6] if len(row) > 6 else 0)
            self.by_hash[e.h] = e
        self.order: typing.List[Ev] = []
        self.seed: typing.Optional[Ev] = None
        self._build_tree()
        self.cluster_of: typing.Dict[str, int] = {}
        self.cluster_cls: typing.Dict[int, typing.Tuple[str, str, str]] = {}
        self.density_penalty = 0.0
        self.density_n = 0
        self.snippets: typing.Dict[str, str] = {}
        self.corroboration: typing.Dict[str, int] = {}
        self.adjust: typing.Dict[str, float] = {}      # own-score adjustments from embeddings: hash -> delta
        self.adjust_note: typing.Dict[str, str] = {}
        self.verdicts: typing.Dict[str, typing.Tuple[str, float, str]] = {}  # hash -> (same|different, conf, reason)
        self.method_flags: typing.Set[str] = set()
        self._prepared = False

    # ------------------------------------------------------------------ tree

    def _build_tree(self) -> None:
        by = self.by_hash
        kids: typing.Dict[str, list] = {}
        roots = []
        for e in by.values():
            if e.parent in by:
                kids.setdefault(e.parent, []).append(e)
            else:
                roots.append(e)
        # breadth first from the roots: parents always come before their children
        order = []
        queue = list(roots)
        for r in roots:
            r.depth = 0
        i = 0
        while i < len(queue):
            e = queue[i]
            i += 1
            order.append(e)
            for c in kids.get(e.h, ()):
                c.depth = e.depth + 1
                queue.append(c)
        # cycles (cannot happen with real data) leave events unvisited: append them as roots
        if len(order) < len(by):
            seen = {e.h for e in order}
            for e in by.values():
                if e.h not in seen:
                    order.append(e)
        self.order = order
        for e in roots:
            if e.type == self.profile.seed_type and e.parent in ('ROOT', '') and self.seed is None:
                self.seed = e
        if self.seed is None:
            for e in order:
                if e.depth == 0 and e.type == self.profile.seed_type:
                    self.seed = e
                    break

    # -------------------------------------------------------------- evidence

    def _evidence(self, e: Ev) -> Evidence:
        if e.ev is not None:
            return e.ev
        p = self.profile
        ev = Evidence()
        data = e.data[:6000]
        ev.text = _norm_text(data[:4000])
        ev.keys = record_keys(data)
        ev.states, _ = rp.geo_of(data[:1500]) if e.type not in ('RAW_RIR_DATA',) else (set(), set())
        if e.type == 'RAW_RIR_DATA':
            st, _w = rp.geo_of(data[:3000])
            ev.states = st
        if _WEAK_RE.search(data[:3000]):
            ev.weak = True
        names = []
        if p.kind == 'person' and p.name:
            t = e.type
            if t == 'HUMAN_NAME':
                n = rn.parse(data)
                if n:
                    names.append((n, 'written'))
                elif data.strip():
                    names.append((rn.Name(raw=data), 'written'))   # a single word or a non-person string
            elif t == 'PROFESSIONAL_LICENSE':
                head = re.split(r"\s+[·|•]\s+", data, 1)[0]
                n = rn.parse(head)
                if n:
                    names.append((n, 'written'))
            elif t == 'RAW_RIR_DATA':
                s = data.lstrip()
                if s[:1] in '{[':
                    try:
                        _walk_names(json.loads(s), names)
                    except (ValueError, RecursionError):
                        pass
            elif t in ('USERNAME',):
                ev.url_slugs.append(data)
            elif t in ('SOCIAL_MEDIA', 'ACCOUNT_EXTERNAL_OWNED', 'LINKED_URL_EXTERNAL'):
                for u in _URL_RE.findall(data)[:2]:
                    ev.url_slugs.extend(url_slugs(u))
            elif t in ('EMAILADDR', 'EMAILADDR_GENERIC'):
                ev.url_slugs.append(data.split('@', 1)[0])
            names = [(n, k) for n, k in names if n]
            # name classes
            for n, k in names:
                ev.names.append((n, k, rn.compare(p.name, n)))
            best = None
            for s in ev.url_slugs:
                c = rn.compare_slug(p.name, s)
                if c and (best is None or CLASS_RANK.get(c, 0) > CLASS_RANK.get(best[1], 0) or (c in CONFLICTS and best[1] not in ('exact', 'exact_initial'))):
                    best = (s, c)
            if best:
                ev.names.append((rn.Name(raw=best[0]), 'slug', best[1]))
        elif p.kind == 'business' and p.company_core:
            t = e.type
            names_c = []
            if t in ('COMPANY_NAME', 'AFFILIATE_COMPANY_NAME'):
                names_c.append(data)
            elif t in ('COMPANY_FILING', 'LEI'):
                names_c.append(re.split(r"\s+[·|]\s+", data, 1)[0])
            elif t == 'RAW_RIR_DATA' and data.lstrip()[:1] in '{[':
                try:
                    _json_companies(json.loads(data), names_c)
                except (ValueError, RecursionError):
                    pass
            if names_c:
                ev.company_sim = max(rn.company_similarity(p.company_core, c) for c in names_c)
        # identifiers for anchors
        if e.type in ('EMAILADDR', 'EMAILADDR_GENERIC'):
            ev.idents.add(data.strip().lower())
        elif e.type == 'PHONE_NUMBER':
            ph = rp.norm_phone(data)
            if ph:
                ev.idents.add(ph)
        elif e.type == 'USERNAME':
            ev.idents.add('@' + rp.norm_handle(data))
        elif e.type in ('INTERNET_NAME', 'DOMAIN_NAME'):
            ev.idents.add(rp.norm_domain(data))
        elif e.type in ('SOCIAL_MEDIA', 'ACCOUNT_EXTERNAL_OWNED', 'LINKED_URL_EXTERNAL'):
            for u in _URL_RE.findall(data)[:2]:
                s = url_slug(u)
                if s:
                    ev.idents.add('@' + rp.norm_handle(s))
                ev.idents.add(rp.norm_domain(u))
        else:
            for m in _EMAIL_RE.findall(data[:3000]):
                ev.idents.add(m.lower())
        if e.type == 'PHYSICAL_ADDRESS':
            ev.idents.add(_norm_text(data))
        e.ev = ev
        return ev

    @staticmethod
    def _best_class(items: typing.Iterable) -> typing.Tuple[typing.Optional[str], str, str]:
        """(class, kind, name) of the strongest evidence: a positive match with a middle name wins, then a conflict, then a bare match."""
        pos = conf = weak = None
        for cls, kind, who in items:
            if cls in ('exact', 'exact_initial'):
                if pos is None or CLASS_RANK[cls] > CLASS_RANK[pos[0]] or (kind == 'written' and pos[1] != 'written' and CLASS_RANK[cls] >= CLASS_RANK[pos[0]]):
                    pos = (cls, kind, who)
            elif cls in CONFLICTS:
                if conf is None or (cls == 'conflict_middle' and conf[0] != 'conflict_middle') or (kind != 'alias' and conf[1] == 'alias'):
                    conf = (cls, kind, who)
            elif cls in CLASS_RANK:
                if weak is None or CLASS_RANK[cls] > CLASS_RANK[weak[0]]:
                    weak = (cls, kind, who)
        return pos or conf or weak or (None, '', '')

    # -------------------------------------------------------------- records

    def _prepare(self) -> None:
        if self._prepared:
            return
        events = self.order
        for e in events:
            self._evidence(e)
        # --- union-find over record keys and sibling containment
        parent_of = {}

        def find(x):
            while parent_of.setdefault(x, x) != x:
                parent_of[x] = parent_of[parent_of[x]]
                x = parent_of[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent_of[rb] = ra

        key_first: typing.Dict[str, str] = {}
        for e in events:
            for k in e.ev.keys:
                if k in key_first:
                    union(key_first[k], e.h)
                else:
                    key_first[k] = e.h
                    find(e.h)
        groups: typing.Dict[tuple, list] = {}
        for e in events:
            groups.setdefault((e.parent, e.module), []).append(e)
        for members in groups.values():
            if len(members) < 2 or len(members) > 500:
                continue
            bigs = [m for m in members if m.type in ('RAW_RIR_DATA', 'PROFESSIONAL_LICENSE', 'COMPANY_FILING') and len(m.data) > 60][:60]
            if not bigs:
                continue
            big_norm = [(b, _norm_text(b.data[:6000]), re.sub(r"\D", '', b.data[:6000])) for b in bigs]
            for m in members:
                if m.type in ('PHYSICAL_ADDRESS', 'PHONE_NUMBER', 'COMPANY_NAME', 'EMAILADDR') and len(m.data) <= 160:
                    if m.type == 'PHONE_NUMBER':
                        ph = rp.norm_phone(m.data)
                        needle = ph
                        for b, bn, bd in big_norm:
                            if needle and needle in bd:
                                union(b.h, m.h)
                    else:
                        if m.type == 'PHYSICAL_ADDRESS':
                            needle = _norm_text(m.data.split(',')[0])
                        elif m.type == 'COMPANY_NAME':
                            needle = _norm_text(m.data)
                        else:
                            needle = m.data.lower()
                        if len(needle) < 6:
                            continue
                        for b, bn, bd in big_norm:
                            if needle in bn:
                                union(b.h, m.h)
        # --- cluster class
        members_by_root: typing.Dict[str, list] = {}
        for e in events:
            if e.h in parent_of:
                members_by_root.setdefault(find(e.h), []).append(e)
        cid = 0
        for root, members in members_by_root.items():
            if len(members) < 2:
                continue
            cid += 1
            for m in members:
                self.cluster_of[m.h] = cid
            items = [(c, k, self._who(n, k)) for m in members for (n, k, c) in m.ev.names]
            cls, kind, who = self._best_class(items)
            self.cluster_cls[cid] = (cls, kind, who)
        # --- namesake density: how many distinct people in the scan share the name without a middle name to compare
        distinct = set()
        for e in events:
            cls = self._event_class(e)[0]
            if cls in ('name_only', 'name_only_nomid') and e.parent in self.by_hash and self._is_search_child(e):
                distinct.add(('c', self.cluster_of[e.h]) if e.h in self.cluster_of else ('e', e.h))
        n = len(distinct)
        self.density_n = n
        self.density_penalty = min(0.10, 0.04 * math.log2(1 + n / 10.0)) if n >= 10 else 0.0
        # --- corroboration: the same value from several independent modules
        seen: typing.Dict[tuple, set] = {}
        for e in events:
            if e.type in IDENTITY_TYPES and e.type != 'RAW_RIR_DATA' and e.type != 'LINKED_URL_EXTERNAL':
                seen.setdefault((e.type, _norm_text(e.data[:300])), set()).add(e.module)
        self._modules_for = seen
        # titles and snippets of web search hits, to give the URL events some text to be judged on
        for e in events:
            if e.type == 'RAW_RIR_DATA' and e.module == 'sfp_searxng' and e.data[:60].lstrip().startswith('{'):
                try:
                    for r in json.loads(e.data).get('results') or []:
                        if isinstance(r, dict) and r.get('url'):
                            self.snippets[str(r['url'])] = (str(r.get('title') or '') + '. ' + str(r.get('snippet') or r.get('content') or ''))[:400]
                except (ValueError, AttributeError, RecursionError):
                    continue
        self._prepared = True

    def _is_search_child(self, e: Ev) -> bool:
        par = self.by_hash.get(e.parent)
        return par is not None and (par is self.seed or (par.type == self.profile.seed_type and par.depth <= 1))

    @staticmethod
    def _who(n: rn.Name, kind: str) -> str:
        return n.raw if kind == 'slug' else (n.full.title() if n else n.raw)

    def _event_class(self, e: Ev) -> typing.Tuple[typing.Optional[str], str, str]:
        """(class, kind, name) of an event, from its own names or its record."""
        ev = self._evidence(e)
        own = self._best_class((c, k, self._who(n, k)) for (n, k, c) in ev.names)
        cid = self.cluster_of.get(e.h)
        if cid is not None:
            ccls, ckind, cwho = self.cluster_cls.get(cid, (None, '', ''))
            if ccls is not None:
                # a record's strongest evidence wins over a weaker class of one of its summaries
                if own[0] is None:
                    return ccls, ckind, cwho
                if ccls in CONFLICTS or CLASS_RANK.get(ccls, 0) > CLASS_RANK.get(own[0], 0):
                    return ccls, ckind, cwho
        return own

    # -------------------------------------------------------------- scoring

    def _geo_delta(self, e: Ev, ev: Evidence, reasons: list) -> float:
        p = self.profile
        h = p.hints
        d = 0.0
        if ev.states:
            if h.states:
                if ev.states & h.states:
                    d += GEO_MATCH
                    reasons.append(f"Location ({', '.join(sorted(ev.states & h.states))}) matches what you told us")
                else:
                    d += GEO_MISMATCH
                    reasons.append(f"Located in {', '.join(sorted(ev.states))}, not {', '.join(sorted(h.states))}")
            elif p.anchor_states:
                top = {s for s, _c in sorted(p.anchor_states.items(), key=lambda x: -x[1])[:3]}
                if ev.states & top:
                    d += ANCHOR_GEO_MATCH
                    reasons.append("Same state as your confirmed findings")
                else:
                    d += ANCHOR_GEO_MISMATCH
                    reasons.append(f"Different state ({', '.join(sorted(ev.states))}) from your confirmed findings")
        if h.cities and any(c in ev.text for c in h.cities):
            d += 0.10
            reasons.append("Mentions a place you told us")
        return d

    def _hint_delta(self, e: Ev, ev: Evidence, reasons: list) -> float:
        h = self.profile.hints
        d = 0.0
        if h.employers and any(_norm_text(x) and _norm_text(x) in ev.text for x in h.employers):
            d += 0.25
            reasons.append("Mentions the employer you gave")
        if h.words:
            hits = [w for w in h.words if len(w) > 3 and w in ev.text.split()]
            if hits:
                d += HINT_WORDS_BONUS
                reasons.append("Mentions " + ', '.join(sorted(hits)[:3]) + " from your hints")
        for rel in h.relatives:
            n = rn.parse(rel)
            if n and _norm_text(n.last) in ev.text and _norm_text(n.first) in ev.text:
                d += RELATIVE_BONUS
                reasons.append(f"Names {rel}, a relative you listed")
                break
        by = h.birth_year
        if by and e.type in ('RAW_RIR_DATA', 'HUMAN_NAME', 'SOCIAL_MEDIA', 'LINKED_URL_EXTERNAL'):
            m = re.search(r"(?:born|dob|birth\w*|b\.)\D{0,14}((?:19|20)\d\d)", e.data[:3000], re.I)
            if m:
                if abs(int(m.group(1)) - by) <= 1:
                    d += 0.2
                    reasons.append("Birth year matches")
                else:
                    d -= 0.25
                    reasons.append(f"Born {m.group(1)}, not {by}")
        return d

    def _anchor_hit(self, e: Ev, ev: Evidence) -> typing.Optional[str]:
        av = self.profile.anchor_values
        if not av:
            return None
        for i in ev.idents:
            if i in av:
                return av[i]
        # an anchor email / domain / handle inside the text of a larger record
        if e.type in ('RAW_RIR_DATA', 'PUBLIC_CODE_REPO', 'LINKED_URL_EXTERNAL', 'DARKNET_MENTION_CONTENT'):
            low = e.data[:4000].lower()
            for k, why in av.items():
                if len(k) >= 6 and not k.startswith('@') and k in low:
                    return why
        return None

    def _own_person(self, e: Ev) -> typing.Optional[typing.Tuple[float, list]]:
        """(own score, reasons) of an event with evidence about whose it is, else None."""
        p = self.profile
        ev = self._evidence(e)
        cls, kind, who = self._event_class(e)
        reasons = []
        score = None
        if cls is not None:
            key = cls
            if cls == 'name_only' and not p.name.middles:
                key = 'name_only_nomid'
            base = NAME_BASE[key]
            written = kind == 'written'
            if not written and base > 0.2:
                base -= 0.05
            score = base
            reasons.append(self._name_reason(cls, kind, who))
            if cls in ('name_only', 'name_only_nomid') and self.density_penalty:
                score -= self.density_penalty
                reasons.append(f"Common name: {self.density_n} people in this scan share it")
        mp = MODULE_PRIOR.get(e.module, 0.0)
        if score is not None and mp and cls not in CONFLICTS and cls != 'different':
            score += mp
        if score is not None and ev.weak and cls not in CONFLICTS and cls != 'different':
            score += WEAK_METHOD_PENALTY
            reasons.append("The source says it matched on the name only")
        # employer hint: a company named like the employer you gave
        if score is None and e.type in ('COMPANY_NAME', 'AFFILIATE_COMPANY_NAME') and p.hints.employers:
            nm = _norm_text(rn.company_core(e.data))
            if nm and any(_norm_text(rn.company_core(x)) == nm for x in p.hints.employers):
                return 0.8, ["Matches the employer you gave"]
        if score is None:
            return None
        score += self._geo_delta(e, ev, reasons) + self._hint_delta(e, ev, reasons)
        why = self._anchor_hit(e, ev)
        if why:
            score += ANCHOR_BONUS
            reasons.append(f"Shares {why}")
            if cls in CONFLICTS or cls == 'different':
                score = max(score, 0.5)
        n_mods = len(self._modules_for.get((e.type, _norm_text(e.data[:300])), ())) - 1
        if n_mods > 0 and cls not in CONFLICTS and cls != 'different':
            score += min(CORROBORATION_MAX, CORROBORATION_STEP * n_mods)
            reasons.append(f"Also reported by {n_mods} other module{'s' if n_mods != 1 else ''}")
        if cls in CONFLICTS or cls == 'different':
            score = min(score, 0.30 if not why else 0.6)
        return max(0.0, min(0.97, score)), reasons

    def _name_reason(self, cls: str, kind: str, who: str) -> str:
        nm = self.profile.name.full.title()
        who = who or 'the record'
        what = {
            'exact': f"Name {who} matches including the middle name",
            'exact_initial': f"Name {who} matches (middle initial agrees)",
            'name_only': f"Only first and last name match ({who}); nothing to tell it apart from other {nm.split()[-1]}s",
            'initial_only': f"Only the first initial and surname match ({who})",
            'middle_as_first': f"{who} goes by the target's middle name",
            'last_only': f"Only the surname matches ({who})",
            'conflict_initial': f"Different middle initial: {who} vs {nm}",
            'conflict_middle': f"Different middle name: {who} vs {nm}, probably a different person",
            'different': f"A different person ({who})",
        }.get(cls, cls)
        if kind == 'slug':
            what = what.replace('Name ', 'The account name ')
        return what

    def _own_business(self, e: Ev) -> typing.Optional[typing.Tuple[float, list]]:
        ev = self._evidence(e)
        sim = ev.company_sim
        reasons = []
        score = None
        if sim is not None:
            if sim >= 0.99:
                score, why = 0.90, "Company name matches the target"
            elif sim >= 0.55:
                score, why = 0.60, "Company name is close to the target's"
            elif sim > 0:
                score, why = 0.35, "Company name shares only part of the target's name"
            else:
                par = self.by_hash.get(e.parent)
                if par is not None and par is self.seed and e.type == 'COMPANY_NAME':
                    score, why = 0.30, "A different company name from a search for the target"
                else:
                    return None
            reasons.append(why)
        if score is None:
            return None
        score += self._geo_delta(e, ev, reasons) + self._hint_delta(e, ev, reasons)
        why = self._anchor_hit(e, ev)
        if why:
            score += ANCHOR_BONUS
            reasons.append(f"Shares {why}")
        return max(0.0, min(0.97, score)), reasons

    def _own(self, e: Ev):
        r = self._own_person(e) if self.profile.kind == 'person' else self._own_business(e)
        if r is None:
            # identifiers shared with an anchor count even without a name
            ev = self._evidence(e)
            why = self._anchor_hit(e, ev)
            if why:
                return 0.85, [f"Shares {why}"]
            return None
        score, reasons = r
        d = self.adjust.get(e.h)
        if d:
            score = max(0.0, min(0.97, score + d))
            note = self.adjust_note.get(e.h)
            if note:
                reasons.append(note)
        v = self.verdicts.get(e.h)
        if v:
            verdict, conf, why = v
            if verdict == 'same':
                new = 0.55 + 0.35 * conf
                if new > score:
                    score = new
                reasons.append(f"AI: likely the same ({conf:.0%}){': ' + why if why else ''}")
            elif verdict == 'different':
                new = 0.30 - 0.25 * conf
                if new < score:
                    score = new
                reasons.append(f"AI: likely a different one ({conf:.0%}){': ' + why if why else ''}")
        return score, reasons

    def _short(self, e: Ev, n: int = 48) -> str:
        t = re.sub(r"\s+", ' ', e.data[:n * 3].strip())
        for pre in ('<SFURL>', '</SFURL>'):
            t = t.replace(pre, '')
        return t[:n] + ('...' if len(t) > n else '')

    def method_name(self) -> str:
        return 'heuristics' + ('+embeddings' if 'embeddings' in self.method_flags else '') + ('+ai' if 'ai' in self.method_flags else '')

    def run(self) -> typing.Dict[str, Res]:
        """Score every event, parents before children. Returns {hash: Res}."""
        self._prepare()
        res: typing.Dict[str, Res] = {}
        for e in self.order:
            res[e.h] = self.score_event(e, res.get(e.parent))
        return res

    def score_event(self, e: Ev, par: typing.Optional[Res]) -> Res:
        """The relevance of one event given its parent's result (None: the parent is unknown)."""
        p = self.profile
        th = self.th
        method = self.method_name()
        ov = self.overrides.get(e.h)
        if ov == 'mine':
            return Res(1.0, 'confirmed', ['You marked this as yours'], 'override', 1.0, True)
        if ov == 'not_related':
            return Res(0.0, 'unrelated', ['You marked this as not related'], 'override', 0.0, True)
        parent_ev = self.by_hash.get(e.parent)
        if e is self.seed or (parent_ev is None and e.type == p.seed_type and e.depth == 0):
            return Res(1.0, 'confirmed', ['This is the scan target'], 'seed', 1.0, True)
        if par is not None and par.method in ('override', 'override-lineage') and par.score <= 0.12 and (par.locked or par.method == 'override-lineage'):
            own = self._own(e)
            s = min(0.12, own[0]) if own else 0.05
            return Res(s, th.label(s), [f"Under something you marked not related ({self._short(parent_ev)})"], 'override-lineage', None)
        own = self._own(e)
        pscore = par.score if par is not None else 1.0
        if own is not None:
            o, reasons = own
            at_seed = parent_ev is self.seed or par is None
            factor = 1.0 if at_seed else (PARENT_FLOOR + (1 - PARENT_FLOOR) * pscore)
            s = o * factor
            if factor < 0.95:
                reasons = reasons + [f"Found under {self._short(parent_ev)} ({par.label})"]
            return Res(s, th.label(s), reasons, method, o)
        ev = self._evidence(e)
        reasons = []
        if parent_ev is self.seed or par is None:
            s = pscore * SEARCH_PRIOR.get(p.kind, 0.45) * (0.8 if e.module in MODULE_PRIOR else 1.0)
            reasons.append("Found by searching the target's name; nothing in it says whose it is")
        else:
            s = pscore * DECAY.get(e.type, DEFAULT_DECAY)
            if par.label == 'unclear' and par.method != 'seed':
                s *= UNCONFIRMED_LEAD
            if par.label in ('unrelated', 'unclear'):
                reasons.append(f"Found under {self._short(parent_ev)} ({par.label})")
            else:
                reasons.append(f"Derived from {self._short(parent_ev)} ({par.label})")
        s = min(s, INHERITED_MAX)
        # a place that disagrees with what we know makes an inherited score worse, one that agrees helps a little
        if ev.states and (p.hints.states or p.anchor_states):
            g = []
            gd = self._geo_delta(e, ev, g)
            if gd < 0:
                s *= 0.6
                reasons.extend(g)
            elif gd > 0:
                s = min(1.0, s + 0.05)
                reasons.extend(g)
        d = self.adjust.get(e.h)
        if d:
            s = max(0.0, min(0.97, s + d))
            if self.adjust_note.get(e.h):
                reasons.append(self.adjust_note[e.h])
        v = self.verdicts.get(e.h)
        if v:
            verdict, conf, why = v
            if verdict == 'same':
                s = max(s, 0.55 + 0.35 * conf) * (0.4 + 0.6 * pscore if par is not None and parent_ev is not self.seed else 1.0)
                reasons.append(f"AI: likely the same ({conf:.0%}){': ' + why if why else ''}")
            elif verdict == 'different':
                s = min(s, 0.30 - 0.25 * conf)
                reasons.append(f"AI: likely a different one ({conf:.0%}){': ' + why if why else ''}")
        return Res(s, th.label(s), reasons, method, None)

    # --------------------------------------------------------- candidates

    def candidates(self, res: typing.Dict[str, Res], low: float = 0.15, high: float = 0.75) -> typing.List[Ev]:
        """Events that are worth the embeddings / AI stage: identity text, borderline score, not locked."""
        out = []
        for e in self.order:
            r = res.get(e.h)
            if r is None or r.locked or e.type not in TEXT_TYPES:
                continue
            if low <= r.score <= high:
                out.append(e)
        return out

    def event_text(self, e: Ev, limit: int = 240) -> str:
        """Short plain text describing the event for embeddings and the AI stage (no HTML or URL noise)."""
        t = e.data
        if e.type in ('SOCIAL_MEDIA', 'LINKED_URL_EXTERNAL', 'ACCOUNT_EXTERNAL_OWNED'):
            urls = _URL_RE.findall(t)
            t = re.sub(r"</?SFURL>", ' ', t)
            if urls:
                u = urls[0]
                m = re.match(r"https?://(?:www\.)?([^/?#]+)(/[^?#]*)?", u)
                host = m.group(1) if m else ''
                path = re.sub(r"[/_\-.]+", ' ', (m.group(2) or '') if m else '')
                t = f"{host} {path}"
                if self.snippets.get(u):
                    t += ' - ' + self.snippets[u]
        elif e.type == 'PROFESSIONAL_LICENSE':
            t = re.sub(r"https?://\S+", '', t)
        elif e.type == 'COMPANY_FILING':
            t = re.sub(r"https?://\S+", '', t)
        t = re.sub(r"<[^>]+>", ' ', t)
        t = re.sub(r"https?://\S+", ' ', t)
        t = re.sub(r"\s+", ' ', t).strip(' ·|')
        return f"{e.type.replace('_', ' ').lower()}: {t}"[:limit]

    def group_key(self, e: Ev) -> str:
        return f"{e.type}|{_norm_text(self.event_text(e, 400))}"

    # ------------------------------------------------------------- summary

    def summarize(self, res: typing.Dict[str, Res]) -> dict:
        counts = {k: 0 for k in LABELS}
        for r in res.values():
            counts[r.label] += 1
        return counts


class LiveScorer(Assessment):
    """Incremental scoring while a scan runs: one event at a time, parents already scored.

    Record clusters, the namesake density and the corroboration of other modules are not known yet, so only
    the event's own evidence and its lineage count. This is what the scan-time gate uses.
    """

    def __init__(self, profile: rp.TargetProfile, thresholds: Thresholds = None, overrides: dict = None):
        super().__init__([], profile, thresholds, overrides)
        self.results: typing.Dict[str, Res] = {}
        self._prepared = True
        self._modules_for = {}

    def add(self, h: str, etype: str, module: str, data: str, parent: str) -> Res:
        """Score a new event (its parent must have been added before; an unknown parent is treated as the target)."""
        par_ev = self.by_hash.get(parent)
        e = Ev(h, etype, module, data, parent)
        e.depth = par_ev.depth + 1 if par_ev is not None else 0
        self.by_hash[h] = e
        if self.seed is None and par_ev is None and etype == self.profile.seed_type:
            self.seed = e
        r = self.score_event(e, self.results.get(parent))
        self.results[h] = r
        return r
