"""Name handling for the relevance scorer: parsing, nicknames and comparing a candidate to the target.

Pure functions, no I/O. A name match is not an identity match: the result of :func:`compare` is a class
(``exact``, ``name_only``, ``conflict_middle`` ...) that the scorer turns into evidence, and a middle
name that differs from the target's is treated as strong evidence of a different person.
"""

import re
import unicodedata

# Credentials and generational suffixes that follow a name ("Nicholas A Thornwood, MD", "John Smith Jr.")
SUFFIXES = {
    'jr', 'sr', 'ii', 'iii', 'iv', 'v', 'md', 'do', 'dds', 'dmd', 'phd', 'esq', 'cpa', 'rn', 'np', 'pa', 'dc',
    'dpm', 'dvm', 'pharmd', 'mba', 'cfp', 'chfc', 'jd', 'mph', 'msw', 'lcsw', 'od', 'pt', 'cfa', 'dr',
}
TITLES = {'mr', 'mrs', 'ms', 'miss', 'dr', 'prof', 'sir', 'rev', 'hon'}

# first name -> its common short forms; matching is symmetric (see :func:`first_matches`)
NICKNAMES = {
    'nicholas': {'nick', 'nicky', 'nik', 'nico', 'nickie', 'nic', 'klaus'},
    'thomas': {'tom', 'tommy', 'thom', 'tomas'},
    'william': {'will', 'bill', 'billy', 'willy', 'liam', 'wil'},
    'robert': {'rob', 'bob', 'bobby', 'robbie', 'bert', 'robby'},
    'richard': {'rich', 'rick', 'ricky', 'dick', 'richie'},
    'james': {'jim', 'jimmy', 'jamie', 'jas'},
    'john': {'jack', 'johnny', 'jon', 'johnnie'},
    'michael': {'mike', 'mick', 'mikey', 'mickey'},
    'christopher': {'chris', 'topher', 'kit'},
    'joseph': {'joe', 'joey', 'jo'},
    'edward': {'ed', 'eddie', 'ted', 'teddy', 'ned'},
    'daniel': {'dan', 'danny'},
    'david': {'dave', 'davey', 'davy'},
    'matthew': {'matt', 'matty'},
    'anthony': {'tony'},
    'andrew': {'andy', 'drew'},
    'steven': {'steve', 'stevie'}, 'stephen': {'steve', 'stevie'},
    'benjamin': {'ben', 'benny', 'benji'},
    'samuel': {'sam', 'sammy'},
    'alexander': {'alex', 'xander', 'sandy'},
    'jonathan': {'jon', 'jonny'},
    'timothy': {'tim', 'timmy'},
    'patrick': {'pat', 'paddy'},
    'charles': {'chuck', 'charlie', 'chas'},
    'elizabeth': {'liz', 'beth', 'lizzie', 'betty', 'eliza', 'libby'},
    'katherine': {'kate', 'katie', 'kathy', 'kat', 'kath'}, 'catherine': {'kate', 'katie', 'cathy', 'cat'},
    'margaret': {'maggie', 'meg', 'peggy', 'marge', 'greta'},
    'jennifer': {'jen', 'jenny', 'jenn'},
    'susan': {'sue', 'susie', 'suzy'},
    'rebecca': {'becky', 'becca'},
    'deborah': {'deb', 'debbie', 'debra'},
    'patricia': {'pat', 'patty', 'trish', 'tricia'},
    'victoria': {'vicky', 'vicki', 'tori'},
    'gregory': {'greg'}, 'kenneth': {'ken', 'kenny'}, 'ronald': {'ron', 'ronnie'}, 'donald': {'don', 'donnie'},
    'lawrence': {'larry', 'laurence'}, 'gerald': {'jerry', 'gerry'}, 'raymond': {'ray'},
    'frederick': {'fred', 'freddie', 'fritz'}, 'theodore': {'ted', 'teddy', 'theo'},
    'zachary': {'zach', 'zack'}, 'joshua': {'josh'}, 'nathaniel': {'nate', 'nathan'},
    'peter': {'pete'}, 'philip': {'phil'}, 'walter': {'walt', 'wally'},
}

COMMON_FIRST = set('''
james john robert michael william david richard joseph thomas charles christopher daniel matthew anthony mark donald steven paul
andrew joshua kenneth kevin brian george edward ronald timothy jason jeffrey ryan jacob gary nicholas eric jonathan stephen larry
justin scott brandon benjamin samuel gregory alexander frank patrick raymond jack dennis jerry tyler aaron jose adam nathan henry
douglas zachary peter kyle walter ethan jeremy harold keith christian roger noah gerald carl terry sean austin arthur lawrence
jesse dylan bryan joe jordan billy bruce albert willie gabriel logan alan juan wayne roy ralph randy eugene vincent russell elijah
louis bobby philip johnny mary patricia jennifer linda elizabeth barbara susan jessica sarah karen nancy lisa margaret betty sandra
ashley kimberly emily donna michelle carol amanda dorothy melissa deborah stephanie rebecca sharon laura cynthia kathleen amy
angela shirley anna brenda pamela emma nicole helen samantha katherine christine debra rachel carolyn janet catherine maria heather
diane ruth julie olivia joyce virginia victoria kelly lauren christina joan evelyn judith megan andrea cheryl hannah jacqueline
martha gloria teresa ann sara madison frances kathryn janice jean abigail alice julia judy sophia grace denise amber doris marilyn
danielle beverly isabella theresa diana natalie brittany charlotte marie kayla alexis lori saba tom nick steve mike bob bill jim
dan dave matt tony andy ben sam alex chris rob rick pat ted ken ron don jon josh tim tash tashtego dorian erik glen ziad barry
wesley scott carlos eyal dan brian roger adam charles michael fabian rolf connie gilbert saba
'''.split())
_FILE_EXT = {'htm', 'html', 'php', 'aspx', 'asp', 'jsp', 'shtml', 'cfm', 'pdf', 'jpg', 'png'}
_ORG_WORDS = {
    'inc', 'incorporated', 'corp', 'corporation', 'llc', 'llp', 'lp', 'ltd', 'limited', 'plc', 'gmbh', 'co', 'company', 'holdings',
    'group', 'bank', 'trust', 'fund', 'partners', 'associates', 'services', 'systems', 'technologies', 'technology', 'solutions',
    'international', 'capital', 'financial', 'securities', 'insurance', 'university', 'college', 'school', 'hospital', 'foundation',
    'institute', 'association', 'society', 'council', 'department', 'authority', 'agency', 'industries', 'enterprises', 'ventures',
    'investments', 'management', 'consulting', 'network', 'networks', 'labs', 'laboratories', 'pharma', 'energy', 'media', 'global',
}
_PARTICLES = {'van', 'von', 'de', 'der', 'den', 'del', 'della', 'di', 'da', 'la', 'le', 'du', 'st', 'mac', 'mc', 'bin', 'al', 'el'}


def _fold(text: str) -> str:
    return unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode('ascii')


def tokens(text: str) -> list:
    """Lower-cased letter tokens of a string (accents folded, punctuation and digits dropped)."""
    return re.findall(r"[a-z]+", _fold(str(text or '')).lower().replace("'", ''))


class Name:
    """A person's name split into first, middle names and last name (all lower case, no punctuation)."""

    __slots__ = ('first', 'middles', 'last', 'raw')

    def __init__(self, first: str = '', middles=(), last: str = '', raw: str = ''):
        self.first, self.middles, self.last, self.raw = first, tuple(middles), last, raw

    def __bool__(self) -> bool:
        return bool(self.first and self.last)

    def __repr__(self) -> str:
        return f"Name({self.first!r}, {self.middles!r}, {self.last!r})"

    @property
    def full(self) -> str:
        return ' '.join(x for x in (self.first, *self.middles, self.last) if x)


def parse(text: str) -> Name:
    """Parse "First Middle Last", "Last, First Middle" or "First M. Last, MD" into a :class:`Name`.

    Returns an empty (falsy) Name for strings that do not look like a person's name (one word, too many
    words, digits, or words such as Inc/LLC).
    """
    raw = _fold(str(text or '')).strip()
    if not raw or len(raw) > 80:
        return Name(raw=raw)
    parts = [p.strip() for p in raw.split(',')]
    inverted = False
    if len(parts) >= 2:
        # "D.O." / "M.D." -> "do" / "md": a credential after the comma
        tail = [re.sub(r'[^a-z]', '', w.lower()) for w in ' '.join(parts[1:]).split()]
        tail = [t for t in tail if t]
        if tail and all(t in SUFFIXES for t in tail):
            raw = parts[0]  # "Nicholas Andrew Thornwood, MD"
        elif len(parts) == 2 and tail:
            inverted = True  # "Thornwood, Nicholas Thomas"
        else:
            raw = parts[0]
    if inverted:
        words = [t for t in tokens(parts[1]) if t not in SUFFIXES] + tokens(parts[0])
    else:
        words = tokens(raw)
    words = [w for w in words if w not in TITLES]
    if any(w in _ORG_WORDS for w in words):
        return Name(raw=raw)
    while len(words) > 2 and words[-1] in SUFFIXES:
        words.pop()
    if len(words) < 2 or len(words) > 5:
        return Name(raw=raw)
    # keep surname particles together with the last name ("van der Berg")
    last_start = len(words) - 1
    while last_start > 1 and words[last_start - 1] in _PARTICLES:
        last_start -= 1
    last = ''.join(words[last_start:])
    return Name(words[0], words[1:last_start], last, raw)


def first_matches(a: str, b: str) -> bool:
    """Same first name, allowing the common short forms (Nick/Nicholas) and a bare initial is NOT a match."""
    if not a or not b:
        return False
    if a == b:
        return True
    if len(a) == 1 or len(b) == 1:
        return False
    for full, shorts in NICKNAMES.items():
        group = shorts | {full}
        if a in group and b in group:
            return True
    # "Nicolas"/"Nicholas" style spelling variants
    return len(a) > 4 and len(b) > 4 and abs(len(a) - len(b)) <= 1 and a[:4] == b[:4] and a[-3:] == b[-3:]


def last_matches(a: str, b: str) -> bool:
    if not a or not b:
        return False
    if a == b:
        return True
    return bool(set(re.split(r'[-\s]', a)) & set(re.split(r'[-\s]', b))) and min(len(a), len(b)) > 3


def _middle_relation(target: tuple, cand: tuple) -> str:
    """'same' | 'initial_same' | 'conflict_initial' | 'conflict_full' | 'unknown' for two middle-name lists."""
    if not target or not cand:
        return 'unknown'
    t_full = [m for m in target if len(m) > 1]
    c_full = [m for m in cand if len(m) > 1]
    if t_full and c_full:
        if set(t_full) & set(c_full):
            return 'same'
        return 'conflict_full'
    t_init = {m[0] for m in target}
    c_init = {m[0] for m in cand}
    if t_init & c_init:
        return 'initial_same'
    return 'conflict_initial'


def compare(target: Name, cand: Name) -> str:
    """Relationship of a candidate name to the target name.

    Classes, strongest first: ``exact`` (first, last and middle agree), ``exact_initial`` (middle initial
    agrees), ``name_only`` (first and last agree, nothing to compare in the middle), ``initial_only`` (first
    initial and last), ``middle_as_first`` (goes by the target's middle name), ``last_only``,
    ``conflict_initial`` / ``conflict_middle`` (first and last agree but the middle names differ), ``different``.
    """
    if not target or not cand:
        return 'unknown'
    f_ok = first_matches(target.first, cand.first)
    l_ok = last_matches(target.last, cand.last)
    if f_ok and l_ok:
        rel = _middle_relation(target.middles, cand.middles)
        if rel == 'same':
            return 'exact'
        if rel == 'initial_same':
            return 'exact_initial'
        if rel == 'conflict_full':
            return 'conflict_middle'
        if rel == 'conflict_initial':
            return 'conflict_initial'
        return 'name_only'
    if l_ok and target.first and cand.first and len(cand.first) == 1 and cand.first == target.first[0]:
        return 'initial_only'
    if l_ok and target.middles and any(first_matches(m, cand.first) for m in target.middles if len(m) > 1):
        return 'middle_as_first'
    if l_ok and not cand.first:
        return 'last_only'
    return 'different'


# ---------------------------------------------------------------------------------------------
# Handles and slugs ("nick.thornwood.35", "nicholasthomasthornwood", "thornwoodic")

def slug_tokens(slug: str) -> list:
    """Name-like letter tokens of a handle or URL segment: ids ("0k54av", "96a21336"), counters and file extensions are dropped."""
    out = []
    for part in re.split(r'[^a-z0-9]+', _fold(str(slug or '')).lower()):
        if not part or part in _FILE_EXT:
            continue
        groups = re.findall(r'\d+', part)
        if re.search(r'[a-z]', part) and len(groups) >= 2:
            continue                      # mixed id such as 0k54av
        if part.isdigit():
            continue
        out.extend(t for t in re.split(r'\d+', part) if t)
    return out


def compare_slug(target: Name, slug: str) -> str:
    """Compare a username / profile slug to the target; same classes as :func:`compare`, or '' (no name in it).

    A slug is weaker evidence than a written name, so callers weight the result less.
    """
    if not target:
        return ''
    parts = slug_tokens(slug)
    low = ''.join(parts) if len(parts) == 1 else re.sub(r'[^a-z]', '', _fold(str(slug or '')).lower())
    if not parts:
        return ''
    joined_full = ''.join(x for x in (target.first, *target.middles, target.last))
    if len(low) >= 8 and low == joined_full:
        return 'exact'
    if len(parts) == 1 and len(low) > 6:
        # one run of letters: look for first+last, last+first, initial+last
        variants = [target.first + target.last, target.last + target.first]
        shorts = {target.first[:1]} | NICKNAMES.get(target.first, set()) | {f for f, s in NICKNAMES.items() if target.first in s}
        variants += [s + target.last for s in shorts]
        if any(low == v for v in variants):
            return 'name_only'
        if low.startswith(target.first) and low.endswith(target.last) and len(target.middles) and len(low) > len(target.first + target.last):
            mid = low[len(target.first):len(low) - len(target.last)]
            if mid and target.middles[0].startswith(mid[:1]):
                return 'exact_initial' if len(mid) == 1 else 'exact'
            return 'conflict_initial' if len(mid) == 1 else 'conflict_middle'
        return ''
    # separated tokens: build a Name out of them
    toks = [p for p in parts if p not in SUFFIXES]
    last_ok = any(last_matches(target.last, p) for p in toks)
    if not last_ok:
        # last name first ("thornwood.nick") is still a name
        return ''
    others = [p for p in toks if not last_matches(target.last, p)]
    if not others:
        return 'last_only'
    cand = Name(others[0], others[1:], target.last)
    res = compare(target, cand)
    if res == 'different':
        if len(others[0]) == 1:
            return 'initial_only' if others[0] == target.first[:1] else 'different'
        # only a recognisable first name makes a different word evidence of a different person
        return 'different' if others[0] in COMMON_FIRST else ''
    return res


def company_core(name: str) -> str:
    """A company name reduced to a comparable core (no legal forms, punctuation or case)."""
    from spiderfoot.helpers import SpiderFootHelpers
    return SpiderFootHelpers.normalizeCompanyName(name or '')


def company_similarity(a: str, b: str) -> float:
    """0..1 similarity of two company names after normalisation (1 = same core)."""
    ca, cb = company_core(a), company_core(b)
    if not ca or not cb:
        return 0.0
    if ca == cb:
        return 1.0
    ta, tb = ca.split(), cb.split()
    if ta[:len(tb)] == tb or tb[:len(ta)] == ta:
        shorter = min(len(ta), len(tb))
        return 0.55 + 0.1 * min(shorter, 3)
    inter = set(ta) & set(tb)
    if not inter:
        return 0.0
    return round(0.5 * len(inter) / max(len(set(ta)), len(set(tb))), 2)


def strip_name(text: str, name: Name) -> str:
    """Remove the target's own name (and common short forms of the first name) from a text.

    Embedding similarity on a text that contains the target's name only measures that the name is in it, which every
    namesake shares. Without the name, what remains is the context (places, jobs, topics) that tells people apart.
    """
    if not name:
        return text
    words = {name.first, name.last, *name.middles}
    words |= NICKNAMES.get(name.first, set()) | {f for f, short in NICKNAMES.items() if name.first in short}
    words = {w for w in words if len(w) > 1}
    if not words:
        return text
    rx = re.compile(r"\b(?:" + '|'.join(sorted((re.escape(w) for w in words), key=len, reverse=True)) + r")\b", re.I)
    return re.sub(r"\s+", ' ', rx.sub(' ', text)).strip(' ,.-:;')
