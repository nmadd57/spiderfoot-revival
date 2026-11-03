"""Several known entities entered together as one subject (a name and an address, an email and a company ...).

Each entity is searched on its own in the same scan; the relevance layer then trusts findings that agree with more
than one of them. ``plan`` splits the input, types every entity and turns the extra ones into context hint lines
(``entity: TYPE | value`` for the scan engine, plus ordinary hints such as ``address:`` for the scorer).
"""

import re
import typing

from spiderfoot.services import relevance_names as rn

STREET_SUFFIX = (r"(?:st|street|ave|avenue|rd|road|blvd|boulevard|dr|drive|ln|lane|ct|court|way|pl|place|pkwy|parkway|hwy|"
                 r"highway|cir|circle|ter|terrace|sq|square|trl|trail|row|loop|pike)")
ADDRESS_RE = re.compile(r"^\s*\d{1,6}[A-Za-z]?\s+(?:[A-Za-z0-9.'\-]+\s+){0,4}?" + STREET_SUFFIX + r"\b\.?(?:[\s,]|$)", re.I)
PO_BOX_RE = re.compile(r"^\s*p\.?\s?o\.?\s*box\s+\d+", re.I)
ZIP_TAIL_RE = re.compile(r"\b[A-Za-z]{2}\s+\d{5}(?:-\d{4})?\s*$")
TAIL_RE = re.compile(r"^(?:[A-Za-z]{2}|\d{5}(?:-\d{4})?|[A-Za-z]{2}\s+\d{5}(?:-\d{4})?|usa|us|united states)$", re.I)
SUFFIX_WORDS = {'inc', 'llc', 'ltd', 'corp', 'co', 'plc', 'llp', 'lp', 'pllc', 'pc', 'gmbh', 'ag', 'sa'}
PRIMARY_TYPES = ('HUMAN_NAME', 'COMPANY_NAME', 'INTERNET_NAME', 'EMAILADDR', 'PHONE_NUMBER', 'USERNAME', 'IP_ADDRESS',
                 'IPV6_ADDRESS', 'NETBLOCK_OWNER', 'BGP_AS_OWNER', 'BITCOIN_ADDRESS', 'PHYSICAL_ADDRESS')
HINT_KEY = {'PHYSICAL_ADDRESS': 'address', 'EMAILADDR': 'email', 'PHONE_NUMBER': 'phone', 'INTERNET_NAME': 'domain',
            'USERNAME': 'username', 'COMPANY_NAME': 'employer', 'HUMAN_NAME': 'relative'}
MAX_ENTITIES = 12
MAX_ALIASES = 6
AKA_RE = re.compile(r"^\s*(?:a\.?k\.?a\.?|aliases|alias|also known as|nicknames?|maiden name|n[ée]e|formerly|variations?)\s*[:\-]?\s+(.+)$", re.I)
SAME_PERSON = ('exact', 'exact_initial', 'name_only')


def _list(text: str) -> typing.List[str]:
    return [x.strip(' .') for x in re.split(r"[,/|;]|\s+or\s+", text) if x.strip(' .')]


def split_variations(value: str) -> typing.Tuple[str, typing.List[str]]:
    """``Nicholas Madden (Nick, Tom Madden)`` / ``Nicholas Madden aka Nick`` -> (base, [variations])."""
    m = re.match(r"^(.*?)\s*\(([^()]+)\)\s*$", value)
    if m and m.group(1).strip():
        return m.group(1).strip(), _list(m.group(2))
    parts = re.split(r"\s+(?:a\.?k\.?a\.?|also known as)\s+", value, maxsplit=1, flags=re.I)
    if len(parts) == 2 and parts[0].strip():
        return parts[0].strip(), _list(parts[1])
    return value, []


def full_variation(variation: str, primary: str) -> str:
    """A one-word variation (Nick) borrows the target's last name."""
    toks = variation.split()
    last = primary.split()[-1] if primary.split() else ''
    return f"{variation} {last}".strip() if len(toks) == 1 and last else variation


def is_address(value: str) -> bool:
    v = str(value or '').strip()
    return bool(ADDRESS_RE.match(v) or PO_BOX_RE.match(v) or (v[:1].isdigit() and ZIP_TAIL_RE.search(v)))


def split_entities(text: str) -> typing.List[str]:
    """Entities are separated by newlines or semicolons; on a single line also by commas (address parts stay together)."""
    lines = [ln.strip() for ln in re.split(r"[\n\r;]+", str(text or '')) if ln.strip()]
    if len(lines) == 1:
        pieces: typing.List[str] = []
        for part in (p.strip() for p in re.split(r",(?![^()]*\))", lines[0]) if p.strip()):
            prev = pieces[-1] if pieces else ''
            tail = bool(TAIL_RE.match(part)) or (not re.search(r"\d|@", part) and len(part.split()) <= 2)
            if prev and (part.lower().strip('.') in SUFFIX_WORDS or (is_address(prev) and tail)):
                pieces[-1] = prev + ', ' + part
            else:
                pieces.append(part)
        lines = pieces
    out, seen = [], set()
    for ln in lines:
        if ln.lower() not in seen:
            seen.add(ln.lower())
            out.append(ln)
    return out[:MAX_ENTITIES]


class Plan:
    def __init__(self):
        self.error = ''
        self.primary: typing.Tuple[str, str] = ('', '')      # (type, value)
        self.others: typing.List[typing.Tuple[str, str]] = []
        self.aliases: typing.List[str] = []
        self.context_lines: typing.List[str] = []


def plan(text: str, type_of: typing.Callable[[str], typing.Optional[str]]) -> Plan:
    """``type_of(value)`` returns the scan target type of a value or None."""
    p = Plan()
    ents = []
    aliases: typing.List[str] = []
    for v in split_entities(text):
        am = AKA_RE.match(v)
        if am:
            aliases.extend(_list(am.group(1)))
            continue
        if not is_address(v):
            v, extra = split_variations(v)
            aliases.extend(extra)
        t = 'PHYSICAL_ADDRESS' if is_address(v) else type_of(v)
        if not t:
            p.error = f"Unrecognised entity: {v[:60]}"
            return p
        ents.append((t, re.sub(r"^(?:business|company)\s*:\s*", '', v.strip(), flags=re.I) if t == 'COMPANY_NAME' else v.strip()))
    if not ents:
        p.error = "No entities were entered."
        return p
    idx = next((i for i, (t, _v) in enumerate(ents) if t in ('HUMAN_NAME', 'COMPANY_NAME')), None)
    if idx is None:
        idx = next((i for i, (t, _v) in enumerate(ents) if t in PRIMARY_TYPES), None)
    if idx is None:
        p.error = "No usable entity was entered."
        return p
    p.primary = ents[idx]
    pn = rn.parse(p.primary[1]) if p.primary[0] == 'HUMAN_NAME' else None
    others = []
    for i, (t, v) in enumerate(ents):
        if i == idx:
            continue
        # another name that is just a variation of the target's (Nick for Nicholas) is the same person
        if pn and t == 'HUMAN_NAME' and rn.compare(pn, rn.parse(v)) in SAME_PERSON:
            aliases.append(v)
        else:
            others.append((t, v))
    p.others = others
    if pn:
        seen = {p.primary[1].lower()}
        for a in aliases:
            a = full_variation(a, p.primary[1])
            if a.lower() not in seen and len(p.aliases) < MAX_ALIASES:
                seen.add(a.lower())
                p.aliases.append(a)
        for a in p.aliases:
            p.context_lines.append(f"entity: HUMAN_NAME | {a}")
            p.context_lines.append(f"alias: {a}")
    for t, v in p.others:
        p.context_lines.append(f"entity: {t} | {v}")
        key = HINT_KEY.get(t)
        if key:
            p.context_lines.append(f"{key}: {v}")
    return p


def entities_in_context(context: str) -> typing.List[typing.Tuple[str, str]]:
    """The ``entity: TYPE | value`` lines of a scan's context, in order."""
    out = []
    for line in str(context or '').splitlines():
        m = re.match(r"^\s*entity\s*:\s*([A-Z_]+)\s*\|\s*(.+?)\s*$", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out[:MAX_ENTITIES]
