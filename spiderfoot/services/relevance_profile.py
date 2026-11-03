"""The target profile for relevance scoring: the seed, the user's context hints and the anchors.

Context hints are free text or ``key: value`` lines (location, city, state, employer, industry, age,
born, email, username, domain, phone, relative, note). Anything that looks like an email address, a
phone number, a domain, an ``@handle`` or a four-digit birth year is picked out of free text as well.
"""

import re
import typing

from spiderfoot.services import relevance_names as rn

US_STATES = {
    'AL': 'alabama', 'AK': 'alaska', 'AZ': 'arizona', 'AR': 'arkansas', 'CA': 'california', 'CO': 'colorado',
    'CT': 'connecticut', 'DE': 'delaware', 'FL': 'florida', 'GA': 'georgia', 'HI': 'hawaii', 'ID': 'idaho',
    'IL': 'illinois', 'IN': 'indiana', 'IA': 'iowa', 'KS': 'kansas', 'KY': 'kentucky', 'LA': 'louisiana',
    'ME': 'maine', 'MD': 'maryland', 'MA': 'massachusetts', 'MI': 'michigan', 'MN': 'minnesota',
    'MS': 'mississippi', 'MO': 'missouri', 'MT': 'montana', 'NE': 'nebraska', 'NV': 'nevada',
    'NH': 'new hampshire', 'NJ': 'new jersey', 'NM': 'new mexico', 'NY': 'new york', 'NC': 'north carolina',
    'ND': 'north dakota', 'OH': 'ohio', 'OK': 'oklahoma', 'OR': 'oregon', 'PA': 'pennsylvania',
    'RI': 'rhode island', 'SC': 'south carolina', 'SD': 'south dakota', 'TN': 'tennessee', 'TX': 'texas',
    'UT': 'utah', 'VT': 'vermont', 'VA': 'virginia', 'WA': 'washington', 'WV': 'west virginia',
    'WI': 'wisconsin', 'WY': 'wyoming', 'DC': 'district of columbia',
}
STATE_BY_NAME = {v: k for k, v in US_STATES.items()}
# two-letter words that are also states but rarely mean one in running text
_AMBIGUOUS_ABBR = {'IN', 'OR', 'ME', 'OK', 'HI', 'LA', 'MA', 'PA', 'DE', 'ID', 'AL', 'CO', 'MD', 'MS', 'MO', 'NE', 'OH', 'AR'}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
PHONE_RE = re.compile(r"(?<![\w.])(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|us|uk|edu|gov|info|biz|dev|app|me|ca|de|fr|nl|au)\b", re.I)
HANDLE_RE = re.compile(r"(?<![\w@])@([A-Za-z0-9_.]{2,30})\b")
YEAR_RE = re.compile(r"\b(19[2-9]\d|20[01]\d)\b")

KEY_GROUPS = {
    'location': ('location', 'city', 'state', 'region', 'country', 'lives', 'live', 'address', 'town', 'zip', 'from', 'based'),
    'employer': ('employer', 'company', 'works', 'work', 'org', 'organisation', 'organization', 'job', 'workplace', 'school', 'university'),
    'industry': ('industry', 'field', 'profession', 'occupation', 'role', 'title', 'sector'),
    'age': ('age', 'born', 'birth', 'birthday', 'dob', 'year'),
    'email': ('email', 'emails', 'mail', 'e-mail'),
    'username': ('username', 'usernames', 'handle', 'handles', 'user', 'nick', 'alias', 'account'),
    'domain': ('domain', 'domains', 'website', 'site', 'url', 'web', 'blog'),
    'phone': ('phone', 'phones', 'tel', 'mobile', 'cell'),
    'relative': ('relative', 'relatives', 'spouse', 'wife', 'husband', 'partner', 'brother', 'sister', 'father', 'mother',
                 'son', 'daughter', 'family', 'parent', 'friend', 'colleague'),
}
_KEY_LOOKUP = {w: g for g, ws in KEY_GROUPS.items() for w in ws}

STOP = set("""a an the and or of in at on for to with from by is are was were be as it this that these those my his her their
our your who whom lives live living works work worked working born based located near around city state area county""".split())


def norm_phone(value: str) -> str:
    digits = re.sub(r'\D', '', str(value or ''))
    return digits[-10:] if len(digits) >= 10 else ''


def norm_domain(value: str) -> str:
    v = str(value or '').strip().lower()
    v = re.sub(r'^[a-z]+://', '', v).split('/')[0].split('?')[0].lstrip('@')
    return v[4:] if v.startswith('www.') else v


def norm_handle(value: str) -> str:
    return re.sub(r'[^a-z0-9]', '', str(value or '').lower().lstrip('@'))


def geo_of(text: str) -> typing.Tuple[set, set]:
    """(US state codes, lower-case words) found in a piece of text. Only strong patterns count for states."""
    if not text:
        return set(), set()
    states = set()
    low = text.lower()
    for m in re.finditer(r"(?:,|\s)\s*([A-Z]{2})(?:\s+\d{5}(?:-\d{4})?|\s*[,;)]|\s*\.(?:\s|$)|\s*$|\s*[\u00b7|])", text):
        code = m.group(1)
        if code in US_STATES:
            states.add(code)
    for m in re.finditer(r"\bUS-([A-Z]{2})\b", text):
        if m.group(1) in US_STATES:
            states.add(m.group(1))
    for m in re.finditer(r"\(([A-Z]{2})\)", text):
        if m.group(1) in US_STATES:
            states.add(m.group(1))
    for name, code in STATE_BY_NAME.items():
        if name in low and re.search(r"\b" + re.escape(name) + r"\b", low):
            if name == 'washington' and 'washington, dc' in low:
                continue
            states.add(code)
    return states, set(re.findall(r"[a-z]{3,}", low))


class Hints:
    """Parsed context hints."""

    def __init__(self):
        self.raw = ''
        self.states = set()
        self.cities = set()       # lower-case city or place names
        self.places = set()       # all other location words (country, county ...)
        self.employers = []
        self.industries = []
        self.birth_year = None
        self.age = None
        self.emails = set()
        self.usernames = set()
        self.domains = set()
        self.phones = set()
        self.relatives = []
        self.notes = []
        self.words = set()        # content words of employers, industries, relatives, notes

    def empty(self) -> bool:
        return not any((self.states, self.cities, self.places, self.employers, self.industries, self.birth_year, self.age,
                        self.emails, self.usernames, self.domains, self.phones, self.relatives, self.notes))

    def to_dict(self) -> dict:
        return {
            'states': sorted(self.states), 'cities': sorted(self.cities), 'places': sorted(self.places),
            'employers': self.employers, 'industries': self.industries, 'birthYear': self.birth_year, 'age': self.age,
            'emails': sorted(self.emails), 'usernames': sorted(self.usernames), 'domains': sorted(self.domains),
            'phones': sorted(self.phones), 'relatives': self.relatives, 'notes': self.notes,
        }


def _add_location(h: Hints, value: str) -> None:
    for part in re.split(r"[;|/]|,(?=\s*[A-Za-z])", value):
        part = part.strip(' .')
        if not part:
            continue
        up = part.upper()
        if up in US_STATES:
            h.states.add(up)
            continue
        if part.lower() in STATE_BY_NAME:
            h.states.add(STATE_BY_NAME[part.lower()])
            continue
        s, _ = geo_of(part)
        if s:
            h.states |= s
            rest = re.sub(r"\b(" + '|'.join(re.escape(n) for n in STATE_BY_NAME) + r")\b", ' ', part.lower())
            rest = re.sub(r"\b[A-Za-z]{2}\b", ' ', rest) if re.search(r"\b[A-Z]{2}\b", part) else rest
            rest = rest.strip()
            if rest:
                h.cities.add(rest)
            continue
        if part.lower() in ('usa', 'us', 'united states', 'u.s.', 'u.s.a.'):
            h.places.add('united states')
            continue
        h.cities.add(part.lower())
    h.words |= {w for w in re.findall(r"[a-z]{3,}", value.lower()) if w not in STOP}
    return None


def parse_context(text: str) -> Hints:
    """Parse free text / ``key: value`` lines into :class:`Hints` (never raises)."""
    h = Hints()
    text = str(text or '')[:4000]
    h.raw = text.strip()
    if not h.raw:
        return h
    leftover = []
    for line in re.split(r"[\n\r]+", h.raw):
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z][A-Za-z \-]{1,24})\s*[:=]\s*(.+)$", line)
        group = _KEY_LOOKUP.get(m.group(1).strip().lower().split()[0]) if m else None
        if m and group:
            _apply(h, group, m.group(2).strip())
        else:
            leftover.append(line)
    free = ' \n'.join(leftover)
    for e in EMAIL_RE.findall(free):
        h.emails.add(e.lower())
    free_wo = EMAIL_RE.sub(' ', free)
    for p in PHONE_RE.findall(free_wo):
        if norm_phone(p):
            h.phones.add(norm_phone(p))
    for hd in HANDLE_RE.findall(free_wo):
        h.usernames.add(norm_handle(hd))
    for d in DOMAIN_RE.findall(free_wo):
        h.domains.add(norm_domain(d))
    for y in re.findall(r"(?:born|b\.|birth\w*|dob)\D{0,12}((?:19|20)\d\d)", free_wo, re.I):
        h.birth_year = int(y)
    m = re.search(r"\bage[d]?\s*[:=]?\s*(\d{2})\b|\b(\d{2})\s*(?:years? old|yo|y/o)\b", free_wo, re.I)
    if m:
        h.age = int(m.group(1) or m.group(2))
    s, _ = geo_of(free_wo)
    h.states |= s
    for name, code in STATE_BY_NAME.items():
        if re.search(r"\b" + re.escape(name) + r"\b", free_wo.lower()):
            h.states.add(code)
    for m in re.finditer(r"(?i:\b(?:lives?|living|based|located|from|in|near)\s+(?:in|near|at)?\s*)([A-Z][A-Za-z.\- ]{2,30}?)(?:,|\.|;|\s+and\b|\s+works?\b|$)", free_wo):
        city = m.group(1).strip().lower()
        if city and city not in STATE_BY_NAME and city not in STOP:
            h.cities.add(city)
    for m in re.finditer(r"(?i:\b(?:works?|worked|employed|working)\s+(?:at|for|with)\s+)([A-Z][\w&.\-' ]{1,40}?)(?:,|\.|;|\s+in\b|\s+as\b|$)", free_wo):
        h.employers.append(m.group(1).strip())
    h.notes.extend(ln for ln in leftover if ln)
    h.words |= {w for ln in leftover for w in re.findall(r"[a-z]{3,}", ln.lower()) if w not in STOP}
    h.words -= {c for c in h.cities}  # city words are matched through the location rules
    return h


def _apply(h: Hints, group: str, value: str) -> None:
    if group == 'location':
        _add_location(h, value)
    elif group == 'employer':
        h.employers.extend(v.strip() for v in re.split(r"[;|]", value) if v.strip())
        h.words |= {w for w in re.findall(r"[a-z]{3,}", value.lower()) if w not in STOP}
    elif group == 'industry':
        h.industries.extend(v.strip() for v in re.split(r"[;|,]", value) if v.strip())
        h.words |= {w for w in re.findall(r"[a-z]{3,}", value.lower()) if w not in STOP}
    elif group == 'age':
        m = re.search(r"\b((?:19|20)\d\d)\b", value)
        if m:
            h.birth_year = int(m.group(1))
        else:
            m = re.search(r"\b(\d{2})\b", value)
            if m:
                h.age = int(m.group(1))
    elif group == 'email':
        h.emails |= {e.lower() for e in EMAIL_RE.findall(value)}
    elif group == 'username':
        h.usernames |= {norm_handle(v) for v in re.split(r"[,;\s]+", value) if norm_handle(v)}
    elif group == 'domain':
        h.domains |= {norm_domain(v) for v in re.split(r"[,;\s]+", value) if norm_domain(v)}
    elif group == 'phone':
        h.phones |= {norm_phone(v) for v in re.split(r"[;|]", value) if norm_phone(v)}
    elif group == 'relative':
        h.relatives.extend(v.strip() for v in re.split(r"[;|,]", value) if v.strip())
        h.words |= {w for w in re.findall(r"[a-z]{3,}", value.lower()) if w not in STOP}


class TargetProfile:
    """What the scan is about, as far as the scorer is concerned."""

    def __init__(self, seed: str, seed_type: str = 'HUMAN_NAME', context: str = ''):
        self.seed = str(seed or '').strip()
        self.seed_type = seed_type or 'HUMAN_NAME'
        self.kind = {'HUMAN_NAME': 'person', 'COMPANY_NAME': 'business'}.get(self.seed_type, 'other')
        self.name = rn.parse(self.seed) if self.kind == 'person' else rn.Name()
        self.company_core = rn.company_core(self.seed) if self.kind == 'business' else ''
        self.hints = parse_context(context)
        self.context = str(context or '')
        # values the scan itself proves belong to the target: normalised value -> why
        self.anchor_values: typing.Dict[str, str] = {}
        self.anchor_hashes: typing.Set[str] = set()
        self.negative_hashes: typing.Set[str] = set()
        self.anchor_states: typing.Dict[str, int] = {}
        self.confirmed_texts: typing.List[str] = []
        self._load_hint_anchors()

    @property
    def scorable(self) -> bool:
        """Relevance scoring is for person and business-name scans; never for domains, IPs and the like."""
        return self.kind in ('person', 'business')

    def _load_hint_anchors(self) -> None:
        h = self.hints
        for e in h.emails:
            self.anchor_values[e] = 'an email address you gave'
        for d in h.domains:
            self.anchor_values[d] = 'a domain you gave'
        for u in h.usernames:
            if len(u) >= 3:
                self.anchor_values['@' + u] = 'a username you gave'
        for p in h.phones:
            self.anchor_values[p] = 'a phone number you gave'

    def add_anchor_event(self, etype: str, data: str, why: str = 'marked as yours') -> None:
        """Make an event's identifier (email, username, phone, domain) an anchor."""
        data = str(data or '')
        if etype in ('EMAILADDR', 'EMAILADDR_GENERIC'):
            self.anchor_values[data.strip().lower()] = why
        elif etype in ('USERNAME',):
            u = norm_handle(data)
            if len(u) >= 3:
                self.anchor_values['@' + u] = why
        elif etype in ('PHONE_NUMBER',):
            p = norm_phone(data)
            if p:
                self.anchor_values[p] = why
        elif etype in ('INTERNET_NAME', 'DOMAIN_NAME'):
            self.anchor_values[norm_domain(data)] = why
        elif etype in ('PHYSICAL_ADDRESS',):
            self.anchor_values[re.sub(r"\W+", ' ', data.lower()).strip()] = why
            st, _ = geo_of(data)
            for s in st:
                self.anchor_states[s] = self.anchor_states.get(s, 0) + 1

    def text(self, extra: typing.Iterable[str] = ()) -> str:
        """Short description used as the embeddings / adjudication reference."""
        bits = [self.seed]
        h = self.hints
        if self.kind == 'person':
            bits[0] = f"Person: {self.name.full.title() if self.name else self.seed}"
        elif self.kind == 'business':
            bits[0] = f"Company: {self.seed}"
        if h.states or h.cities:
            bits.append('Location: ' + ', '.join(sorted(h.cities) + [US_STATES[s].title() for s in sorted(h.states)]))
        if h.employers:
            bits.append('Employer: ' + '; '.join(h.employers[:3]))
        if h.industries:
            bits.append('Field: ' + '; '.join(h.industries[:3]))
        if h.birth_year:
            bits.append(f"Born {h.birth_year}")
        elif h.age:
            bits.append(f"Age {h.age}")
        if h.relatives:
            bits.append('Related: ' + '; '.join(h.relatives[:4]))
        if h.notes and not (h.states or h.cities or h.employers):
            bits.append(' '.join(h.notes)[:200])
        for t in list(extra)[:6]:
            bits.append(t)
        return '. '.join(bits)[:600]

    def summary(self) -> dict:
        return {'kind': self.kind, 'seed': self.seed, 'hints': self.hints.to_dict(),
                'anchors': len(self.anchor_values) + len(self.anchor_hashes), 'negatives': len(self.negative_hashes)}
