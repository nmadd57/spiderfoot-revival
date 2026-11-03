"""Reading relevance for display: labels, filtering, lineage and the collapsed "N findings under X hidden" groups."""

import re
import typing

LABELS = ('confirmed', 'likely', 'unclear', 'unrelated')
LABEL_TEXT = {'confirmed': 'Confirmed', 'likely': 'Likely', 'unclear': 'Unclear', 'unrelated': 'Unrelated'}
LABEL_HINT = {
    'confirmed': 'Proven to belong to the target (the target itself, an identifier you gave, or something you marked as yours).',
    'likely': 'Probably about the target.',
    'unclear': 'Could be the target or somebody with the same name; nothing settles it.',
    'unrelated': 'Almost certainly about somebody or something else.',
}

TRUE = ('1', 'true', 'yes', 'on')


def clean_context(text) -> str:
    """User supplied context hints: control characters removed, at most 4000 characters (HTML is escaped on output)."""
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", '', str(text or '')).strip()[:4000]


def truthy(value) -> bool:
    return str(value).strip().lower() in TRUE


class View:
    """The relevance state of one scan, loaded once per request."""

    def __init__(self, dbh, scan_id: str):
        self.scan_id = scan_id
        self.map = dbh.relevanceGet(scan_id)          # hash -> (score, label, reasons, method)
        self.overrides = dbh.overrideGet(scan_id)
        self.run = dbh.relevanceRunGet(scan_id)
        self.has_data = bool(self.map)

    def label(self, h: str) -> typing.Optional[str]:
        r = self.map.get(h)
        return r[1] if r else None

    def score(self, h: str) -> typing.Optional[float]:
        r = self.map.get(h)
        return r[0] if r else None

    def reasons(self, h: str) -> list:
        r = self.map.get(h)
        return r[2] if r else []

    def hidden(self, h: str, include_unrelated: bool) -> bool:
        """Whether an event is left out of a default view."""
        if include_unrelated:
            return False
        r = self.map.get(h)
        return bool(r and r[1] == 'unrelated')

    def info(self, h: str) -> dict:
        r = self.map.get(h)
        if not r:
            return {}
        return {'score': round(r[0], 3), 'label': r[1], 'reasons': r[2], 'method': r[3], 'override': self.overrides.get(h, '')}

    def counts(self) -> dict:
        c = {k: 0 for k in LABELS}
        for r in self.map.values():
            c[r[1]] = c.get(r[1], 0) + 1
        return c


def descendants(rows: typing.Iterable, root: str, limit: int = 100000) -> typing.List[str]:
    """Hashes of every event below ``root`` (rows: (hash, ..., source_event_hash) with source at index 4)."""
    kids: typing.Dict[str, list] = {}
    for r in rows:
        kids.setdefault(r[4], []).append(r[0])
    out, stack = [], [root]
    while stack and len(out) < limit:
        for c in kids.get(stack.pop(), ()):
            out.append(c)
            stack.append(c)
    return out


def hidden_groups(view: View, events: typing.Iterable[dict], top: int = 25) -> typing.List[dict]:
    """Collapse unrelated events under their highest unrelated ancestor.

    ``events``: dicts with ``hash``, ``source_hash``, ``type`` and ``data``. Returns the biggest groups as
    ``{'hash', 'type', 'data', 'count'}``: one line each, "N findings under <entity> hidden" (``count`` leaves out the entity itself).
    """
    by_hash = {e['hash']: e for e in events}
    top_of: typing.Dict[str, str] = {}

    def root_of(h: str) -> str:
        path = []
        cur = h
        while True:
            if cur in top_of:
                res = top_of[cur]
                break
            e = by_hash.get(cur)
            if e is None or view.label(cur) != 'unrelated':
                res = path[-1] if path else cur
                break
            path.append(cur)
            nxt = e['source_hash']
            if nxt not in by_hash or view.label(nxt) != 'unrelated':
                res = cur
                break
            cur = nxt
        for p in path:
            top_of[p] = res
        return res

    counts: typing.Dict[str, int] = {}
    for h, e in by_hash.items():
        if view.label(h) == 'unrelated':
            r = root_of(h)
            counts[r] = counts.get(r, 0) + 1
    groups = []
    for r, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        if n < 3:
            break                       # an entity with fewer than two findings under it is not worth a line of its own
        e = by_hash[r]
        groups.append({'hash': r, 'type': e['type'], 'data': short_data(e['data']), 'count': n - 1})
        if len(groups) >= top:
            break
    return groups


def short_data(data: str, n: int = 70) -> str:
    t = re.sub(r"</?SFURL>", '', str(data or ''))
    t = re.sub(r"\s+", ' ', t).strip()
    return t[:n] + ('...' if len(t) > n else '')
