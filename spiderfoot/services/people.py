"""Small helpers for matching person and business names across public registries."""

import re

_PREFIX = {'mr', 'mrs', 'ms', 'miss', 'dr', 'prof', 'professor', 'sir', 'hon', 'rev'}
_SUFFIX = {'jr', 'sr', 'ii', 'iii', 'iv', 'v', 'md', 'do', 'phd', 'esq', 'cpa', 'dds', 'dvm', 'rn', 'np', 'pa', 'mba', 'cfp'}
_LEGAL = {'inc', 'incorporated', 'corp', 'corporation', 'co', 'company', 'llc', 'llp', 'lp', 'ltd', 'limited', 'plc',
          'pllc', 'pc', 'pa', 'gmbh', 'sa', 'ag', 'nv', 'bv', 'the', 'and'}


def _words(text: str) -> list:
    return [w for w in re.split(r"[^\w']+", str(text or '').lower().replace('.', '')) if w]


def split_name(name: str):
    """(first, last, tokens) for a person's name, ignoring titles, suffixes and middle names.

    Accepts "First Middle Last" and "Last, First Middle". Returns None if there are not at
    least two name tokens, so single words never trigger a registry search.
    """
    text = str(name or '').strip()
    if ',' in text:
        last_part, _, rest = text.partition(',')
        text = f"{rest.strip()} {last_part.strip()}"
    tokens = [t for t in _words(text) if t not in _PREFIX and t not in _SUFFIX]
    if len(tokens) < 2:
        return None
    return tokens[0], tokens[-1], tokens


def same_person(name: str, first: str, last: str, other_names=()) -> bool:
    """True if ``name`` (or one of ``other_names``) has this first and last name."""
    for candidate in [name, *other_names]:
        parts = split_name(candidate)
        if parts and parts[0] == str(first).lower() and parts[1] == str(last).lower():
            return True
    return False


def name_in_text(first: str, last: str, text: str) -> bool:
    """True if both the first and last name occur as words in ``text`` (any order)."""
    words = set(_words(text))
    return str(first).lower() in words and str(last).lower() in words


def company_key(name: str) -> str:
    """Normalised company name for comparison: no case, punctuation or legal suffixes."""
    words = [w for w in _words(name) if w not in _LEGAL]
    return ' '.join(words)


def same_company(a: str, b: str) -> bool:
    ka, kb = company_key(a), company_key(b)
    return bool(ka) and ka == kb
