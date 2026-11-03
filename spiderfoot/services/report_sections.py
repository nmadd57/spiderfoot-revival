"""The report's sections: what each one is given, what it is asked, and the deterministic text that stands in for it.

Every section is written from its own small, explicit prompt: a fixed instruction, a ``DATA`` block built from the
digest (counts and citation-numbered findings, cut to a hard token cap) and nothing else. The parts a model must not
be trusted with (counts, dates, lists of modules) are written by Python as a *facts* block that is printed before the
prose. If a section cannot be written by the model (no endpoint, call or token cap, failure) the fallback text, built
from the same digest, takes its place.
"""

import collections
import re
import typing

from spiderfoot.services import ai_service
from spiderfoot.services import report_digest as rd

SECTION_IDS = ('summary', 'scope', 'identity', 'findings', 'risks', 'limits', 'next')
SECTION_TITLES = {
    'summary': 'Executive summary', 'scope': 'Target and scope', 'identity': 'Identity and attribution assessment',
    'findings': 'Key findings', 'risks': 'Risks and notable items', 'limits': 'Confidence and limitations',
    'next': 'Recommended next steps',
}
# the order they appear in the report
REPORT_SEQUENCE = ('summary', 'scope', 'identity', 'findings', 'risks', 'limits', 'next')
# the order they are written in: what matters most first, so an endpoint that gives out still leaves the core of the report
WRITE_SEQUENCE = ('summary', 'identity', 'risks', 'findings', 'limits', 'next', 'scope')

MAX_WORDS = {'summary': 150, 'scope': 80, 'identity': 200, 'findings': 150, 'risks': 150, 'limits': 90, 'next': 150}

TASKS = {
    'summary': ("Write the executive summary: 3 to 4 sentences, then 3 short bullets with the most important points. Lead with who or "
                "what was scanned and how certain the identification is (use ASSESSMENT). Then the biggest risk, if there is one, and "
                "the main limitation."),
    'scope': ("Write 2 to 4 sentences: what was scanned, when, for how long, which module selection was used, whether context hints "
              "were supplied, and whether the scan finished. Do not list modules."),
    'identity': ("Assess who or what the target appears to be. Use three short parts in bold: **Confirmed**, **Likely**, "
                 "**Unclear or excluded**. Use ASSESSMENT as the verdict. Say how many findings were excluded as other people or "
                 "organisations and why (EXCLUDED). Name the findings that support the identification with their ids. Do not "
                 "name excluded people."),
    'findings': ("Summarise this category of findings: what was found, which findings are most relevant to the target, which are only "
                 "name matches. Do not repeat the COUNTS line; give a figure only when it adds meaning, and then exactly as in COUNTS. "
                 "Only the listed findings are shown: do not say anything about the others. Bullets, most relevant first."),
    'risks': ("List the notable risks in order of severity: correlations, leaks and breaches, malicious or blacklisted entries, "
              "vulnerabilities, findings with a risk score. If DATA shows none, say that no risk findings were reported. Do not "
              "invent severity."),
    'limits': ("Write one short paragraph on how far this report can be trusted: name-only matches, how many findings were hidden as "
               "unrelated, whether the scan was cut short, modules that returned nothing, and API key or quota problems (name the "
               "modules)."),
    'next': ("Recommend 4 to 6 concrete next steps as bullets: which hints (place, employer, birth year, email, username) to add, which "
             "API keys or modules would improve the result, which unclear findings to check by hand. Base every step on DATA."),
}

HINT_KEYS = ('location', 'employer', 'born', 'email', 'username', 'relative')
HINT_ALIASES = {
    'location': ('location', 'city', 'state', 'place', 'lives'),
    'employer': ('employer', 'company', 'works', 'organisation', 'organization', 'field', 'industry'),
    'born': ('born', 'birth', 'age', 'year'), 'email': ('email', 'e-mail'), 'username': ('username', 'handle', 'user'),
    'relative': ('relative', 'spouse', 'wife', 'husband', 'family'),
}


class Unit(typing.NamedTuple):
    """One thing the report needs: a section, or one category of the findings section."""
    uid: str                 # 'summary', 'cat:people', ...
    section: str             # one of SECTION_IDS
    title: str
    heading_level: int
    facts: str               # markdown written by Python
    data: str                # the DATA block
    task: str
    offered: frozenset       # citation ids the model may use
    fallback: str            # markdown used when the model cannot write it
    skip_ai: bool = False    # nothing to ask (an empty category)


# ----------------------------------------------------------------------------------------------------
# small helpers

def words(t: str) -> str:
    return str(t or '').replace('_', ' ').lower()


def short_module(m: str) -> str:
    return str(m or '').replace('sfp_', '').replace('sfp__', '')


def plural(n: int, one: str, many: typing.Optional[str] = None) -> str:
    return f"{rd.fmt(n)} {one if n == 1 else (many or one + 's')}"


LABEL_WORD = {'confirmed': 'confirmed', 'likely': 'likely', 'unclear': 'unclear', None: 'not scored', 'unscored': 'not scored'}


def item_line(i: dict, with_reason: bool = False) -> str:
    bits = [f"[{i['id']}]", words(i['type']), short_module(i['module']), i['data']]
    tail = []
    if i.get('label') is not None:
        tail.append(LABEL_WORD.get(i['label'], i['label']))
    if i.get('count', 1) > 1:
        tail.append(f"seen {i['count']} times")
    if i.get('risk'):
        tail.append(f"risk score {i['risk']}")
    if with_reason and i.get('reason'):
        tail.append(i['reason'])
    return ' | '.join(bits) + (' | ' + ', '.join(tail) if tail else '')


def label_phrase(by_label: dict) -> str:
    parts = []
    for k in ('confirmed', 'likely', 'unclear', 'unscored'):
        n = by_label.get(k, 0)
        if n:
            parts.append(f"{rd.fmt(n)} {LABEL_WORD[k]}")
    return ', '.join(parts) or 'none'


def date_text(ts: int) -> str:
    import time
    return time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(ts)) if ts else 'unknown'


def hints_given(context: str) -> typing.List[str]:
    low = str(context or '').lower()
    given = []
    for key, aliases in HINT_ALIASES.items():
        if any(re.search(r"(^|\n|;|,)\s*" + re.escape(a) + r"\s*[:=]", low) for a in aliases):
            given.append(key)
    return given


def fit_lines(header: typing.List[str], items: typing.List[str], cap_tokens: int, footer: typing.Optional[typing.List[str]] = None) -> str:
    """Join the DATA block, dropping the last (lowest ranked) item lines until it is under the token cap."""
    footer = footer or []
    items = list(items)
    while True:
        text = '\n'.join(header + items + footer)
        if ai_service.estimate_tokens(text) <= cap_tokens or not items:
            break
        items.pop()
    if ai_service.estimate_tokens(text) > cap_tokens:           # the fixed part alone is too long: hard cut
        text = text[: int(cap_tokens * ai_service._CHARS_PER_TOKEN)]
    return text


def headline(d: dict) -> str:
    s, t = d['scan'], d['totals']
    return (f"{rd.fmt(t['events'])} events from {rd.fmt(s['modules_with_results'])} modules ({rd.fmt(t['unique'])} distinct findings, "
            f"{rd.fmt(t['type_count'])} event types)")


def assessment_line(d: dict) -> str:
    i, t = d['identity'], d['totals']
    if not i['name_scan']:
        return "Not a person or business-name scan: findings are not scored for identity."
    return (f"{i['verdict']}. {rd.fmt(i['confirmed'])} confirmed (includes the target itself), {rd.fmt(i['likely'])} likely, "
            f"{rd.fmt(i['unclear'])} unclear, {rd.fmt(i['unrelated'])} unrelated of {rd.fmt(t['events'])} events "
            f"({i['excluded_share']:g}% excluded)")


def keyless_candidates(d: dict, cfg: dict, scan_modules: typing.Iterable[str], limit: int = 8) -> typing.List[str]:
    """Modules that watch the target type, need an API key that is not set and were not part of the scan."""
    ttype = d['scan']['target_type']
    have = set(scan_modules)
    out = []
    for name, spec in sorted(((cfg or {}).get('__modules__') or {}).items()):
        spec = spec or {}
        if name in have or name.startswith('sfp__stor_') or ttype not in (spec.get('consumes') or []):
            continue
        opts = spec.get('opts') or {}
        keys = [k for k in opts if 'api_key' in k.lower() or k.lower().endswith('apikey')]
        if keys and all(not str(opts.get(k) or '').strip() for k in keys) and 'apikey' in [str(f).lower() for f in (spec.get('meta') or {}).get('flags', [])]:
            out.append(short_module(name))
        if len(out) >= limit:
            break
    return out


# ----------------------------------------------------------------------------------------------------
# units

def build_units(d: dict, enabled: typing.Iterable[str], cap_tokens: int, cfg: typing.Optional[dict] = None,
                scan_modules: typing.Iterable[str] = ()) -> typing.List[Unit]:
    """The units of the report in the order they are *written*; ``order_key`` gives the reading order."""
    enabled = set(enabled)
    units: typing.List[Unit] = []
    s, t, ident, risks, cov = d['scan'], d['totals'], d['identity'], d['risks'], d['coverage']
    cats = d['categories']
    target_line = f"TARGET: {s['target']} (type {words(s['target_type']) or 'unknown'})"

    for sec in WRITE_SEQUENCE:
        if sec not in enabled:
            continue
        if sec == 'summary':
            lines = [target_line,
                     f"SCAN: {s['status']}{' (partial results)' if s['partial'] else ''}, {headline(d)}",
                     f"ASSESSMENT: {assessment_line(d)}",
                     "FINDINGS PER CATEGORY (distinct findings about the target / hidden as unrelated):"]
            for k in rd.REPORT_ORDER:
                c = cats[k]
                if c['unique'] or c['hidden']:
                    lines.append(f"- {c['title']}: {rd.fmt(c['unique'])} / {rd.fmt(c['hidden'])}")
            lines.append(f"RISKS: {risk_phrase(d)}")
            items = [item_line(i, True) for i in ident['items'][:6]] + [item_line(i) for i in risks['items'][:4]]
            lines.append(f"LIMITS: {limit_phrase(d)}")
            offered = frozenset([i['id'] for i in ident['items'][:6]] + [i['id'] for i in risks['items'][:4]])
            data = fit_lines(lines, ['KEY FINDINGS:'] + items if items else [], cap_tokens)
            units.append(Unit('summary', 'summary', SECTION_TITLES['summary'], 2, '', data, TASKS['summary'], offered,
                              fallback_summary(d)))
        elif sec == 'scope':
            facts = scope_table(d)
            data = '\n'.join([target_line, f"NAME: {s['name']}", f"STATUS: {s['status']}", f"STARTED: {date_text(s['started'])}",
                              f"ENDED: {date_text(s['ended'])}", f"DURATION: {s['duration'] or 'unknown'}",
                              f"MODULES: {s['modules_enabled']} enabled, {s['modules_with_results']} returned results; selection: {s['profile']}",
                              f"CONTEXT HINTS: {s['context'] or 'none supplied'}",
                              f"PRUNING OF UNRELATED MATCHES: {'on' if s['prune'] else 'off'}"])
            units.append(Unit('scope', 'scope', SECTION_TITLES['scope'], 2, facts, data, TASKS['scope'], frozenset(),
                              f"{s['target']} was scanned with {s['profile']}; the scan {s['status'].lower()} after {s['duration'] or 'an unknown time'}."))
        elif sec == 'identity':
            hdr = [target_line, f"ASSESSMENT: {assessment_line(d)}",
                   f"CONTEXT HINTS: {s['context'] or 'none supplied'}"]
            if ident['name_scan']:
                hdr.append("EXCLUDED (counts only): " + ('; '.join(f"{n} {words(t_)}" for t_, n in ident['excluded_by_type'][:5]) or 'nothing'))
                hdr.append("WHY EXCLUDED: " + ('; '.join(f"{n} x {r}" for r, n in ident['excluded_by_reason'][:4]) or 'no reasons recorded'))
                hdr.append("WHY UNCLEAR: " + ('; '.join(f"{n} x {r}" for r, n in ident['unclear_by_reason'][:4]) or 'none'))
                hdr.append(f"YOUR CORRECTIONS: {t['overrides']['mine']} marked as the target's, {t['overrides']['not_related']} marked not related")
            body = [item_line(i, True) for i in ident['items']]
            units.append(Unit('identity', 'identity', SECTION_TITLES['identity'], 2, '', fit_lines(hdr, ['FINDINGS:'] + body if body else [], cap_tokens),
                              TASKS['identity'], frozenset(i['id'] for i in ident['items']), fallback_identity(d)))
        elif sec == 'findings':
            for k in rd.REPORT_ORDER:
                c = cats[k]
                if not c['unique'] and not c['hidden']:
                    continue
                facts = category_counts(c)
                hdr = [target_line, f"CATEGORY: {c['title']}", "COUNTS: " + category_counts_plain(c, ident['name_scan']),
                       f"LISTED: the {len(c['items'])} most relevant of {rd.fmt(c['unique'])} distinct findings; the rest are not shown"]
                lines = [item_line(i, True) for i in c['items']]
                units.append(Unit(f'cat:{k}', 'findings', c['title'], 3, facts, fit_lines(hdr, ['FINDINGS:'] + lines if lines else [], cap_tokens),
                                  TASKS['findings'], frozenset(i['id'] for i in c['items']), fallback_category(c), skip_ai=not c['items']))
        elif sec == 'risks':
            hdr = [target_line, f"RISKS: {risk_phrase(d)}"]
            lines = [item_line(i) for i in risks['items']]
            lines += [f"[{c['id']}] correlation | {c['risk']} | {c['title']}: {c['description']} ({c['events']} matching events)"
                      for c in risks['correlations']]
            offered = frozenset([i['id'] for i in risks['items']] + [c['id'] for c in risks['correlations']])
            units.append(Unit('risks', 'risks', SECTION_TITLES['risks'], 2, '', fit_lines(hdr, ['FINDINGS:'] + lines if lines else [], cap_tokens),
                              TASKS['risks'], offered, fallback_risks(d), skip_ai=not lines))
        elif sec == 'limits':
            facts = limit_bullets(d)
            hdr = [target_line, f"LIMITS: {limit_phrase(d)}"] + [re.sub(r"\*\*", '', b) for b in facts.split('\n')]
            units.append(Unit('limits', 'limits', SECTION_TITLES['limits'], 2, facts, fit_lines(hdr, [], cap_tokens), TASKS['limits'], frozenset(),
                              ''))
        elif sec == 'next':
            given = hints_given(s['context'])
            missing = [h for h in HINT_KEYS if h not in given]
            cand = keyless_candidates(d, cfg or {}, scan_modules)
            hdr = [target_line, f"ASSESSMENT: {assessment_line(d)}",
                   f"HINTS ALREADY GIVEN: {', '.join(given) or 'none'}", f"HINTS THAT WOULD HELP: {', '.join(missing)}",
                   "API KEY OR QUOTA PROBLEMS: " + ('; '.join(f"{short_module(p['module'])} ({p['kind']})" for p in cov['key_problems'][:6]) or 'none'),
                   f"MODULES THAT RETURNED NOTHING: {rd.fmt(cov['silent_count'])}" + (
                       ' (' + ', '.join(short_module(m) for m in cov['silent'][:8]) + ')' if cov['silent'] else ''),
                   f"MODULES WITH NO API KEY THAT COULD RUN ON THIS TARGET: {', '.join(cand) or 'none identified'}",
                   f"UNCLEAR FINDINGS TO CHECK: {rd.fmt(ident['unclear'])}; SCAN STATUS: {cov['status']}"]
            units.append(Unit('next', 'next', SECTION_TITLES['next'], 2, '', fit_lines(hdr, [], cap_tokens), TASKS['next'], frozenset(),
                              fallback_next(d, missing, cand)))
    return units


def reading_order(units: typing.List[Unit]) -> typing.List[Unit]:
    idx = {s: i for i, s in enumerate(REPORT_SEQUENCE)}
    cat_idx = {f'cat:{k}': i for i, k in enumerate(rd.REPORT_ORDER)}
    return sorted(units, key=lambda u: (idx[u.section], cat_idx.get(u.uid, 0)))


# ----------------------------------------------------------------------------------------------------
# Python-written facts and fallbacks

def risk_phrase(d: dict) -> str:
    r = d['risks']
    bits = []
    if r['correlation_total']:
        bits.append(f"{plural(r['correlation_total'], 'correlation')} (" + ', '.join(
            f"{n} {k.lower()}" for k, n in sorted(r['correlation_counts'].items(), key=lambda kv: rd_order(kv[0]))) + ")")
    if r['levels']:
        bits.append("findings with a risk score: " + ', '.join(f"{n} {k.lower()}" for k, n in sorted(r['levels'].items(), key=lambda kv: rd_order(kv[0]))))
    ex = r['exposure']
    if ex.get('exposure'):
        bits.append(f"{plural(ex['exposure'], 'exposure/leak finding')}")
    if ex.get('reputation'):
        bits.append(f"{plural(ex['reputation'], 'reputation/threat finding')}")
    return '; '.join(bits) or 'none reported'


def rd_order(level: str) -> int:
    return {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}.get(level, 9)


def limit_phrase(d: dict) -> str:
    c, i = d['coverage'], d['identity']
    bits = []
    if c['aborted']:
        bits.append(f"scan status {c['status']} (partial results)")
    if i['name_scan']:
        bits.append(f"{rd.fmt(i['unrelated'])} findings hidden as unrelated, {rd.fmt(i['unclear'])} unclear, {rd.fmt(i['name_only'])} name-only matches")
    if c['silent_count']:
        bits.append(f"{plural(c['silent_count'], 'module')} returned nothing")
    if c['key_problems']:
        bits.append(f"{plural(len(c['key_problems']), 'module')} with API key or quota problems")
    return '; '.join(bits) or 'no limitations recorded'


def scope_table(d: dict) -> str:
    s = d['scan']
    rows = [('Target', f"{s['target']} ({words(s['target_type']) or 'unknown type'})"), ('Scan', s['name']), ('Status', s['status']),
            ('Started', date_text(s['started'])), ('Ended', date_text(s['ended'])), ('Duration', s['duration'] or 'unknown'),
            ('Modules', f"{rd.fmt(s['modules_enabled'])} enabled, {rd.fmt(s['modules_with_results'])} returned results ({s['profile']})"),
            ('Events', headline(d)), ('Context hints', s['context'].replace('\n', '; ') if s['context'] else 'none supplied'),
            ('Pruning of unrelated matches', 'on' if s['prune'] else 'off')]
    return '| | |\n|---|---|\n' + '\n'.join(f"| {a} | {md_cell(b)} |" for a, b in rows)


def md_cell(t: str) -> str:
    return str(t).replace('|', '\\|').replace('\n', ' ')


def category_counts_plain(c: dict, scored: bool) -> str:
    txt = f"{plural(c['unique'], 'distinct finding')}"
    if scored:
        txt += f" ({label_phrase(c['by_label'])})"
        txt += f"; {rd.fmt(c['hidden'])} more were hidden as unrelated"
    if c['types']:
        txt += "; by type: " + ', '.join(f"{words(t_)} {rd.fmt(n)}" for t_, n, _ in c['types'][:6])
    return txt


def category_counts(c: dict) -> str:
    return "**Counts:** " + category_counts_plain(c, True) + "."


def fallback_summary(d: dict) -> str:
    i = d['identity']
    out = [f"- {d['scan']['target']}: {headline(d)}.", f"- Identification: {assessment_line(d)}.", f"- Risks: {risk_phrase(d)}.",
           f"- Limits: {limit_phrase(d)}."]
    cites = ' '.join(f"[{x['id']}]" for x in i['items'][:3])
    if cites:
        out[1] = out[1][:-1] + f". Supporting findings: {cites}."
    return '\n'.join(out)


def fallback_identity(d: dict) -> str:
    i = d['identity']
    if not i['name_scan']:
        return "This scan is not scored for identity. " + (
            "Findings that describe the target: " + '; '.join(f"{words(x['type'])} {x['data']} [{x['id']}]" for x in i['items'][:8]) if i['items'] else "")
    out = [f"**Assessment:** {assessment_line(d)}."]
    for label, title in (('confirmed', 'Confirmed'), ('likely', 'Likely'), ('unclear', 'Unclear')):
        its = [x for x in i['items'] if x.get('label') == label][:6]
        if its:
            out.append(f"**{title}:** " + '; '.join(f"{words(x['type'])} {x['data']} [{x['id']}]" for x in its) + ".")
    if i['excluded_by_reason']:
        out.append("**Excluded:** " + '; '.join(f"{rd.fmt(n)} x {r.lower()}" for r, n in i['excluded_by_reason'][:4]) + ".")
    return '\n\n'.join(out)


def fallback_category(c: dict) -> str:
    if not c['items']:
        return f"Nothing in this category could be tied to the target; {rd.fmt(c['hidden'])} findings were hidden as unrelated." if c['hidden'] \
            else "Nothing was found in this category."
    return '\n'.join(f"- {words(x['type'])}: {x['data']} ({LABEL_WORD.get(x.get('label'), 'not scored')}) [{x['id']}]" for x in c['items'][:10])


def fallback_risks(d: dict) -> str:
    r = d['risks']
    if not r['items'] and not r['correlations']:
        return "No risk findings, leaks, threat-list entries or correlations were reported."
    out = []
    for c in r['correlations'][:6]:
        out.append(f"- {c['risk'].title()}: {c['title']} ({plural(c['events'], 'matching event')}) [{c['id']}]")
    for x in r['items'][:8]:
        out.append(f"- {words(x['type'])}: {x['data']} [{x['id']}]")
    return '\n'.join(out)


def limit_bullets(d: dict) -> str:
    c, i = d['coverage'], d['identity']
    out = []
    if c['aborted']:
        out.append(f"- **Partial results.** The scan ended as {c['status']}, so findings that later modules would have produced are missing.")
    if i['name_scan']:
        out.append(f"- **Name matches.** {plural(i['unclear'], 'finding')} are unclear and {rd.fmt(i['name_only'])} rest on the name alone; "
                   f"{plural(i['unrelated'], 'finding')} were hidden as unrelated and are only counted here.")
    if c['silent_count']:
        out.append(f"- **Modules without results.** {plural(c['silent_count'], 'module')} returned nothing"
                   + (': ' + ', '.join(short_module(m) for m in c['silent'][:10]) + (' ...' if c['silent_count'] > 10 else '') if c['silent'] else '') + '.')
    for p in c['key_problems'][:8]:
        out.append(f"- **{short_module(p['module'])}** reported a {p['kind']} problem ({rd.fmt(p['count'])} times): {p['detail']}")
    if c['other_errors']:
        out.append("- **Other errors** in the scan log: " + ', '.join(f"{short_module(m)} {rd.fmt(n)}" for m, n in c['other_errors'][:6]) + '.')
    if not out:
        out.append("- No limitations were recorded: the scan finished and every module that ran returned results.")
    return '\n'.join(out)


def fallback_next(d: dict, missing: typing.List[str], cand: typing.List[str]) -> str:
    out = []
    if d['identity']['name_scan'] and missing:
        out.append("- Add context hints (" + ', '.join(missing[:4]) + ") on the scan page and run the relevance assessment again, so namesakes can be told apart.")
    for p in d['coverage']['key_problems'][:3]:
        out.append(f"- Fix the {p['kind']} problem of {short_module(p['module'])} (Settings, API keys) and rerun the scan.")
    if cand:
        out.append("- Consider adding API keys for: " + ', '.join(cand[:6]) + '.')
    if d['coverage']['aborted']:
        out.append("- Rerun the scan to completion; this report covers partial results only.")
    if d['identity']['unclear']:
        out.append(f"- Review the {rd.fmt(d['identity']['unclear'])} unclear findings by hand and mark the ones that are the target's.")
    return '\n'.join(out) or "- No follow-up is suggested by the data."


# ----------------------------------------------------------------------------------------------------
# checking what the model wrote

CITE_GROUP = re.compile(r"\[\s*([EC]\d+(?:\s*(?:[,;/&]|\band\b)?\s*[EC]\d+)*)\s*\]", re.I)
CITE_PAREN = re.compile(r"\(\s*([EC]\d+(?:\s*(?:[,;/&]|\band\b)?\s*[EC]\d+)*)\s*\)", re.I)
CITE_MIXED = re.compile(r"\[[^\[\]]*\b[EC]\d+\b[^\[\]]*\]", re.I)         # "[E12 shows ...]": a bracket with an id and words
CITE_BARE = re.compile(r"(?<![\[\w/.-])([EC]\d+)(?![\w\]/-])")
NUMBER_RE = re.compile(r"(?<![\w.\[])\d[\d,]*(?:\.\d+)?(?![\w\]])")


def clean_prose(text: str) -> str:
    """Remove what a chat model adds around the answer: fences, headings, greetings, a trailing offer."""
    t = re.sub(r"<think>.*?</think>", ' ', text or '', flags=re.S | re.I).strip()
    t = re.sub(r"^```\w*\s*|\s*```$", '', t)
    t = re.sub(r"^\s{0,3}#{1,6}\s+.*$", '', t, flags=re.M)                 # the report supplies the headings
    t = re.sub(r"^(sure|certainly|here is|here's|below is)[^\n]*\n+", '', t, flags=re.I)
    t = re.sub(r"\n+(let me know|i hope|feel free|if you (need|would like))[^\n]*$", '', t, flags=re.I)
    t = re.sub(r"\n{3,}", '\n\n', t)
    return t.strip()


def validate_citations(text: str, offered: typing.Iterable[str], known: typing.Iterable[str]) -> typing.Tuple[str, dict]:
    """Keep the citations that point at findings the section was given; drop the rest.

    Returns (text, stats): ``used`` ids, ``dropped`` ids that were invented or not offered, and the share of sentences
    that carry a citation.
    """
    offered, known = {o.upper() for o in offered}, {k.upper() for k in known}
    used: typing.List[str] = []
    dropped: typing.List[str] = []

    def rewrite(m):
        keep = []
        for x in re.findall(r"[EC]\d+", m.group(0).upper()):
            if x in offered and x in known:
                keep.append(x)
                if x not in used:
                    used.append(x)
            else:
                dropped.append(x)
        return ' '.join(f"[{x}]" for x in dict.fromkeys(keep))

    text = CITE_GROUP.sub(rewrite, text)
    text = CITE_PAREN.sub(rewrite, text)
    text = CITE_MIXED.sub(lambda m: rewrite(m) if not re.fullmatch(r"\[(E|C)\d+\]", m.group(0)) else m.group(0), text)

    def bare(m):
        x = m.group(1).upper()
        if x in offered and x in known:
            if x not in used:
                used.append(x)
            return f"[{x}]"
        return m.group(0)
    text = CITE_BARE.sub(bare, text)
    text = re.sub(r"[ \t]+([.,;:])", r"\1", text)
    text = re.sub(r"[ \t]{2,}", ' ', text)
    sentences = [s for s in re.split(r"(?<=[.!?])\s+|\n+", text) if len(s.strip()) > 25]
    cited = sum(1 for s in sentences if re.search(r"\[[EC]\d+\]", s))
    return text.strip(), {'used': used, 'dropped': dropped, 'sentences': len(sentences), 'cited': cited}


def numbers_in(text: str) -> typing.Set[str]:
    out = set()
    for m in NUMBER_RE.findall(re.sub(r"\[[EC]\d+\]", ' ', str(text or ''))):
        m = m.rstrip(',.')
        out.add(m)
        out.add(m.replace(',', ''))
    return out


def check_numbers(text: str, allowed: typing.Set[str]) -> typing.List[str]:
    """Figures in the prose that are not in the data the section was given (small numbers, years and list markers are ignored)."""
    bad = []
    for m in NUMBER_RE.findall(re.sub(r"\[[EC]\d+\]", ' ', text)):
        m = m.rstrip(',.')
        plain = m.replace(',', '')
        if not plain or '.' in plain and plain.endswith('.'):
            continue
        try:
            v = float(plain)
        except ValueError:
            continue
        if v < 10 or (1900 <= v <= 2100 and '.' not in plain and ',' not in m):
            continue
        if m in allowed or plain in allowed:
            continue
        if m not in bad:
            bad.append(m)
    return bad


def counter(items) -> collections.Counter:
    return collections.Counter(items)
