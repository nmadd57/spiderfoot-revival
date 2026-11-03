"""Several known entities entered together as one subject (a name and an address, an email and a company ...).

Each entity is searched on its own in the same scan; the relevance layer then trusts findings that agree with more
than one of them. ``plan`` splits the input, types every entity and turns the extra ones into context hint lines
(``entity: TYPE | value`` for the scan engine, plus ordinary hints such as ``address:`` for the scorer).
"""

import re
import typing

STREET_SUFFIX = (r"(?:st|street|ave|avenue|rd|road|blvd|boulevard|dr|drive|ln|lane|ct|court|way|pl|place|pkwy|parkway|hwy|"
                 r"highway|cir|circle|ter|terrace|sq|square|trl|trail|row|loop|pike)")
ADDRESS_RE = re.compile(r"^\s*\d{1,6}[A-Za-z]?\s+(?:[A-Za-z0-9.'\-]+\s+){0,4}?" + STREET_SUFFIX + r"\b\.?(?:[\s,]|$)", re.I)
PO_BOX_RE = re.compile(r"^\s*p\.?\s?o\.?\s*box\s+\d+", re.I)
ZIP_TAIL_RE = re.compile(r"\b[A-Za-z]{2}\s+\d{5}(?:-\d{4})?\s*$")
TAIL_RE = re.compile(r"^(?:[A-Za-z]{2}|\d{5}(?:-\d{4})?|[A-Za-z]{2}\s+\d{5}(?:-\d{4})?|usa|us|united states)$", re.I)
SUFFIX_WORDS = {'inc', 'llc', 'ltd', 'corp', 'co', 'plc', 'llp', 'lp', 'pllc', 'pc', 'gmbh', 'ag', 'sa'}
PRIMARY_TYPES = ('HUMAN_NAME', 'COMPANY_NAME', 'INTERNET_NAME', 'EMAILADDR', 'PHONE_NUMBER', 'USERNAME', 'IP_ADDRESS',
                 'IPV6_ADDRESS', 'NETBLOCK_OWNER', 'BGP_AS_OWNER', 'BITCOIN_ADDRESS')
HINT_KEY = {'PHYSICAL_ADDRESS': 'address', 'EMAILADDR': 'email', 'PHONE_NUMBER': 'phone', 'INTERNET_NAME': 'domain',
            'USERNAME': 'username', 'COMPANY_NAME': 'employer', 'HUMAN_NAME': 'relative'}
MAX_ENTITIES = 12


def is_address(value: str) -> bool:
    v = str(value or '').strip()
    return bool(ADDRESS_RE.match(v) or PO_BOX_RE.match(v) or (v[:1].isdigit() and ZIP_TAIL_RE.search(v)))


def split_entities(text: str) -> typing.List[str]:
    """Entities are separated by newlines or semicolons; on a single line also by commas (address parts stay together)."""
    lines = [ln.strip() for ln in re.split(r"[\n\r;]+", str(text or '')) if ln.strip()]
    if len(lines) == 1:
        pieces: typing.List[str] = []
        for part in (p.strip() for p in lines[0].split(',') if p.strip()):
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
        self.context_lines: typing.List[str] = []


def plan(text: str, type_of: typing.Callable[[str], typing.Optional[str]]) -> Plan:
    """``type_of(value)`` returns the scan target type of a value or None."""
    p = Plan()
    ents = []
    for v in split_entities(text):
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
        p.error = "Add at least a name, company, domain, email, phone, username or IP address besides the address."
        return p
    p.primary = ents[idx]
    p.others = [e for i, e in enumerate(ents) if i != idx]
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
