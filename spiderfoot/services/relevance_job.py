"""Running a relevance assessment: the staged pipeline, its status, the background job and the scan-time gate.

``assess_scan`` is idempotent and restartable: it recomputes every score from the stored events, the user's
overrides and the scan's context hints, then replaces the stored scores. Its progress is written to
``tbl_relevance_run`` so the scan page can show it. ``start_job`` runs it on a worker thread so a web request
never waits for the embeddings or AI endpoints.
"""

import logging
import threading
import time
import typing

from spiderfoot.services import relevance as rv
from spiderfoot.services import relevance_embed as re_
from spiderfoot.services import relevance_llm as rl
from spiderfoot.services import relevance_profile as rp

log = logging.getLogger(__name__)

DEFAULTS = {
    '_rel_enabled': True, '_rel_prune_default': True, '_rel_auto_assess': True,
    '_rel_use_embeddings': True, '_rel_embeddings_url': '', '_rel_embeddings_model': '', '_rel_embeddings_apikey': '',
    '_rel_use_ai': True, '_rel_ai_model': '',
    '_rel_t_unrelated': 25, '_rel_t_likely': 55, '_rel_t_confirmed': 80,
    '_rel_max_llm_calls': 8, '_rel_max_llm_tokens': 150000, '_rel_max_embed_texts': 1500, '_rel_embed_mid': 50,
}

_running: typing.Dict[str, threading.Thread] = {}
_running_lock = threading.Lock()


def enabled(cfg: dict) -> bool:
    return cfg.get('_rel_enabled', True) not in (False, 0, '0', 'false', 'False')


def prune_default(cfg: dict) -> bool:
    return cfg.get('_rel_prune_default', True) not in (False, 0, '0', 'false', 'False')


def build_profile(dbh, scan_id: str, overrides: typing.Optional[dict] = None, events_by_hash: typing.Optional[dict] = None
                  ) -> typing.Optional[rp.TargetProfile]:
    """The profile of a scan (None when the scan does not exist). Scans of domains, IPs... get a profile that is not ``scorable``."""
    info = dbh.scanSeedInfo(scan_id)
    if info is None:
        return None
    seed, ttype = info
    ctx = dbh.scanContextGet(scan_id)['context']
    prof = rp.TargetProfile(seed, ttype or 'HUMAN_NAME', ctx)
    for h, verdict in (overrides or {}).items():
        if verdict == 'mine':
            prof.anchor_hashes.add(h)
            ev = (events_by_hash or {}).get(h)
            if ev is not None:
                prof.add_anchor_event(ev[0], ev[1])
        else:
            prof.negative_hashes.add(h)
    return prof


def _profile_text(a: rv.Assessment, res: dict, limit: int = 4) -> str:
    """The reference text for the AI: the target, the hints and the best-confirmed attributes."""
    extra = []
    ranked = sorted((e for e in a.order if e is not a.seed and res[e.h].score >= a.th.confirmed and e.type in rv.TEXT_TYPES),
                    key=lambda e: -res[e.h].score)
    seen = set()
    for e in ranked:
        t = a.event_text(e, 120)
        if t not in seen:
            seen.add(t)
            extra.append(t)
        if len(extra) >= limit:
            break
    return a.profile.text(extra)


def context_text(a: rv.Assessment, res: dict, limit: int = 4) -> str:
    """What the target is like apart from the name (hints and confirmed attributes), for the embeddings signal. '' when unknown."""
    h = a.profile.hints
    bits = []
    if h.states or h.cities:
        bits.append('Location: ' + ', '.join(sorted(h.cities) + [rp.US_STATES[s].title() for s in sorted(h.states)]))
    if h.employers:
        bits.append('Employer: ' + '; '.join(h.employers[:3]))
    if h.industries:
        bits.append('Field: ' + '; '.join(h.industries[:3]))
    if h.notes and not bits:
        bits.append(' '.join(h.notes)[:200])
    ranked = sorted((e for e in a.order if e is not a.seed and res[e.h].score >= a.th.confirmed and e.type in rv.TEXT_TYPES),
                    key=lambda e: -res[e.h].score)
    for e in ranked[:limit]:
        t = embed_text(a, e)
        if len(t) > 24:
            bits.append(t)
    return '. '.join(bits)[:600]


def embed_text(a: rv.Assessment, e: rv.Ev) -> str:
    """The finding's text without the target's own name (so the similarity is about context, not about the name)."""
    p = a.profile
    t = a.event_text(e)
    if p.kind == 'person':
        return rn_strip(t, p.name)
    if p.kind == 'business' and p.company_core:
        import re
        for w in set(p.company_core.lower().split()):
            if len(w) > 2:
                t = re.sub(r"\b" + re.escape(w) + r"\b", ' ', t, flags=re.I)
        return ' '.join(t.split())
    return t


def rn_strip(text, name):
    from spiderfoot.services import relevance_names
    return relevance_names.strip_name(text, name)


def _subtree_sizes(a: rv.Assessment) -> typing.Dict[str, int]:
    size = {e.h: 1 for e in a.order}
    for e in reversed(a.order):
        if e.parent in size:
            size[e.parent] += size[e.h]
    return size


def assess_scan(cfg: dict, scan_id: str, *, dbh=None, network: bool = True, embed_client=None, adjudicator=None,
                progress: bool = True) -> dict:
    """Score every event of a scan and store the result. Returns a summary dict (never raises for a missing endpoint)."""
    from spiderfoot import SpiderFootDb
    own_db = dbh is None
    dbh = dbh or SpiderFootDb(cfg)
    t0 = time.time()
    summary: typing.Dict[str, typing.Any] = {'scan': scan_id, 'skipped': '', 'method': 'heuristics', 'calls': 0, 'tokens': 0,
                                             'embedded': 0, 'counts': {}, 'seconds': 0, 'notes': []}

    def status(**kw):
        if progress:
            try:
                dbh.relevanceRunSet(scan_id, **kw)
            except Exception:  # nosec B110 - status is best effort
                log.debug("could not write the relevance status", exc_info=True)

    try:
        status(status='running', phase='reading events', progress=0.02, started=int(t0), ended=0, message='', calls=0, tokens=0, embedded=0)
        rows = dbh.scanEventsForRelevance(scan_id)
        by_hash = {r[0]: (r[1], r[3]) for r in rows}
        overrides = dbh.overrideGet(scan_id)
        profile = build_profile(dbh, scan_id, overrides, by_hash)
        if profile is None:
            summary['skipped'] = 'no such scan'
            status(status='failed', message='No such scan.', ended=int(time.time()))
            return summary
        if not profile.scorable:
            summary['skipped'] = 'Relevance scoring is for person and business-name scans.'
            status(status='skipped', message=summary['skipped'], ended=int(time.time()))
            return summary
        th = rv.Thresholds.from_config(cfg)
        a = rv.Assessment(rows, profile, th, overrides)
        status(phase='scoring', progress=0.15)
        res = a.run()
        # confirmed addresses become anchors for geography, then score again
        states = {}
        for e in a.order:
            if e.type == 'PHYSICAL_ADDRESS' and e is not a.seed and res[e.h].score >= th.confirmed:
                st, _ = rp.geo_of(e.data)
                for s in st:
                    states[s] = states.get(s, 0) + 1
        if states and not profile.anchor_states:
            profile.anchor_states = states
            res = a.run()
        summary['counts'] = a.summarize(res)

        # ---- embeddings
        client = embed_client if embed_client is not None else (re_.EmbeddingClient.from_config(cfg) if network else None)
        if client is not None:
            status(phase='embeddings', progress=0.3)
            _embedding_stage(a, res, client, dbh, cfg, summary)
            res = a.run()
            summary['counts'] = a.summarize(res)

        # ---- AI adjudication
        judge = adjudicator if adjudicator is not None else (rl.Adjudicator.from_config(cfg) if network else None)
        if judge is not None and judge.max_calls > 0:
            status(phase='ai', progress=0.6)
            _llm_stage(a, res, judge, summary, lambda frac: status(progress=0.6 + 0.3 * frac, calls=judge.calls, tokens=judge.tokens))
            res = a.run()

        status(phase='saving', progress=0.95)
        counts = a.summarize(res)
        summary['counts'] = counts
        summary['method'] = a.method_name()
        # events outside the tree walk (none) keep nothing; replace all rows in one go
        dbh.relevanceDelete(scan_id)
        dbh.relevanceStore(scan_id, ((h, r.score, r.label, r.reasons, r.method) for h, r in res.items()))
        summary['seconds'] = round(time.time() - t0, 2)
        status(status='done', phase='done', progress=1.0, method=summary['method'], calls=summary['calls'], tokens=summary['tokens'],
               embedded=summary['embedded'], ended=int(time.time()), counts=counts, message=' '.join(summary['notes'])[:300])
        summary['_assessment'] = a
        summary['_results'] = res
        return summary
    except Exception:
        log.exception("relevance assessment of %s failed", scan_id)
        status(status='failed', message='The assessment failed; see the server log.', ended=int(time.time()))
        summary['skipped'] = 'failed'
        return summary
    finally:
        if own_db:
            try:
                dbh.close()
            except Exception:  # nosec B110
                pass


def _embedding_stage(a: rv.Assessment, res: dict, client: re_.EmbeddingClient, dbh, cfg: dict, summary: dict) -> None:
    ctx = context_text(a, res)
    if not ctx:
        summary['notes'].append("Embeddings were not used: nothing is known about the target besides the name. Add context hints "
                                "(a place, an employer...) so findings can be compared on more than the name.")
        return
    cands = a.candidates(res)
    if not cands:
        return
    groups: typing.Dict[str, list] = {}
    for e in cands:
        groups.setdefault(a.group_key(e), []).append(e)
    # most borderline groups first, bounded
    keys = sorted(groups, key=lambda k: abs(res[groups[k][0].h].score - 0.4))
    max_texts = int(cfg.get('_rel_max_embed_texts', re_.DEFAULT_MAX_TEXTS) or re_.DEFAULT_MAX_TEXTS)
    keys = keys[:max_texts * 2]
    texts = {k: embed_text(a, groups[k][0]) for k in keys}
    vecs, stats = re_.embed_cached(client, dbh, [ctx] + list(texts.values()), max_new=max_texts)
    summary['embedded'] = stats['sent']
    if stats['error']:
        summary['notes'].append(f"Embeddings: {stats['error']}")
    pv = vecs.get(ctx[:re_.TEXT_LIMIT])
    if pv is None:
        summary['notes'].append("Embeddings were not used (the profile could not be embedded).")
        return
    mid_sim = int(cfg.get('_rel_embed_mid', 50) or 50) / 100.0
    used = 0
    for k in keys:
        v = vecs.get(texts[k][:re_.TEXT_LIMIT])
        if v is None:
            continue
        sim = re_.cosine(pv, v)
        d = re_.similarity_delta(sim, mid=mid_sim)
        note = f"Context similarity {sim:.0%} ({'+' if d >= 0 else ''}{d * 100:.0f} points)"
        for e in groups[k]:
            a.adjust[e.h] = d
            a.adjust_note[e.h] = note
        used += 1
    if used:
        a.method_flags.add('embeddings')


LLM_PERSON_TYPES = frozenset({'HUMAN_NAME', 'PROFESSIONAL_LICENSE', 'SOCIAL_MEDIA', 'ACCOUNT_EXTERNAL_OWNED', 'LINKED_URL_EXTERNAL', 'USERNAME'})
LLM_BUSINESS_TYPES = frozenset({'COMPANY_NAME', 'AFFILIATE_COMPANY_NAME', 'COMPANY_FILING', 'SOCIAL_MEDIA', 'LINKED_URL_EXTERNAL', 'HUMAN_NAME'})


def _llm_stage(a: rv.Assessment, res: dict, judge: rl.Adjudicator, summary: dict, tick=None) -> None:
    th = a.th
    sizes = _subtree_sizes(a)
    # For a person, the model judges what names a person or an account (it has no basis to say a company or a filing "is" somebody);
    # companies found under a weak lead are handled by lineage. For a business target the company names are the point.
    kinds = LLM_PERSON_TYPES if a.profile.kind == 'person' else LLM_BUSINESS_TYPES
    cands = [e for e in a.candidates(res, low=max(0.0, th.hide_below - 0.12), high=th.likely)
             if res[e.h].label in ('unclear', 'unrelated') and res[e.h].score >= th.hide_below - 0.12 and e.type in kinds]
    if not cands:
        return
    groups: typing.Dict[str, list] = {}
    for e in cands:
        groups.setdefault(a.group_key(e), []).append(e)
    order = sorted(groups, key=lambda k: -sum(sizes.get(e.h, 1) for e in groups[k]))
    cap = judge.max_calls * judge.batch_size
    order = order[:cap]
    items, id_to_key = [], {}
    for i, k in enumerate(order, 1):
        rep = groups[k][0]
        items.append({'id': str(i), 'type': rep.type.replace('_', ' ').lower(), 'text': a.event_text(rep, 220).split(': ', 1)[-1]})
        id_to_key[str(i)] = k
    profile_text = _profile_text(a, res)
    verdicts = {}
    for i in range(0, len(items), judge.batch_size):
        if not judge.budget_left:
            break
        verdicts.update(judge.judge(profile_text, items[i:i + judge.batch_size]))
        if tick:
            tick(min(1.0, (i + judge.batch_size) / max(1, len(items))))
    summary['calls'], summary['tokens'] = judge.calls, judge.tokens
    if judge.errors:
        summary['notes'].append("AI: " + judge.errors[0])
    applied = 0
    for rid, (verdict, conf, why) in verdicts.items():
        if verdict == 'unknown':
            continue
        for e in groups[id_to_key[rid]]:
            a.verdicts[e.h] = (verdict, conf, why)
            applied += 1
    if verdicts:
        a.method_flags.add('ai')
    if len(order) < len(groups):
        summary['notes'].append(f"AI looked at {len(order)} of {len(groups)} borderline groups (call cap).")


# ---------------------------------------------------------------------------------------------
# background job

def start_job(cfg: dict, scan_id: str, *, network: bool = True) -> bool:
    """Run an assessment on a worker thread. False when one is already running for the scan."""
    with _running_lock:
        t = _running.get(scan_id)
        if t is not None and t.is_alive():
            return False
        from spiderfoot import SpiderFootDb
        dbh = SpiderFootDb(cfg)
        try:
            dbh.relevanceRunSet(scan_id, status='queued', phase='queued', progress=0.0, message='', ended=0)
        finally:
            dbh.close()

        def work():
            try:
                assess_scan(dict(cfg), scan_id, network=network)
            finally:
                with _running_lock:
                    _running.pop(scan_id, None)

        t = threading.Thread(target=work, name=f"relevance-{scan_id}", daemon=True)
        _running[scan_id] = t
        t.start()
        return True


def is_running(scan_id: str) -> bool:
    with _running_lock:
        t = _running.get(scan_id)
        return t is not None and t.is_alive()


# ---------------------------------------------------------------------------------------------
# scan-time gate

GATE_TYPES = rv.IDENTITY_TYPES


class RelevanceGate:
    """Stops the fan-out from findings that are about somebody else.

    Used by the scan engine for every event before it is dispatched to the modules: it scores the event live
    (the deterministic scorer, nothing slow) and, for a clearly unrelated identity-bearing event, asks for it
    to be stored without being passed on. Events whose parent was held back are held back too. The scores are
    buffered and written to ``tbl_event_relevance`` so the results page can show why.
    """

    def __init__(self, dbh, scan_id: str, profile: rp.TargetProfile, thresholds: rv.Thresholds, prune: bool = True,
                 flush_every: int = 150, similarity=None):
        self.dbh = dbh
        self.scan_id = scan_id
        self.prune = bool(prune)
        self.scorer = rv.LiveScorer(profile, thresholds)
        self.th = thresholds
        self.held: typing.Set[str] = set()
        self.pending: typing.List[tuple] = []
        self.flush_every = flush_every
        self.count = 0
        self.held_count = 0
        self.similarity = similarity       # optional callable(text) -> cosine to the profile from the cache, or None
        self._last_flush = time.time()

    @classmethod
    def for_scan(cls, dbh, scan_id: str, cfg: dict, target: str, target_type: str, context: str, prune: bool):
        prof = rp.TargetProfile(target, target_type, context)
        if not prof.scorable or not enabled(cfg):
            return None
        return cls(dbh, scan_id, prof, rv.Thresholds.from_config(cfg), prune)

    def check(self, h: str, etype: str, module: str, data: str, parent: str) -> bool:
        """Score one event. True when it must not be passed on to the modules."""
        if etype == 'ROOT' or not data:
            return False
        r = self.scorer.add(h, etype, module, data, parent)
        self.count += 1
        hold = False
        if self.prune and r.method != 'seed':
            if parent in self.held:
                hold = True
                r.reasons = r.reasons + ['Its source was held back as unrelated, so it was not followed up']
            elif etype in GATE_TYPES and r.score < self.th.hide_below:
                hold = True
                if self.similarity is not None:
                    try:
                        sim = self.similarity(self.scorer.event_text(self.scorer.by_hash[h]))
                    except Exception:
                        sim = None
                    if sim is not None and sim >= 0.65:
                        hold = False
        if hold:
            self.held.add(h)
            self.held_count += 1
            r.reasons = r.reasons + ['Not followed up by other modules (prune unrelated matches)']
        self.pending.append((h, r.score, r.label, r.reasons, 'scan-gate' if hold else 'scan-live'))
        if len(self.pending) >= self.flush_every or (self.pending and time.time() - self._last_flush > 3):
            self.flush()
        return hold

    def flush(self) -> None:
        rows, self.pending = self.pending, []
        self._last_flush = time.time()
        if rows:
            try:
                self.dbh.relevanceStore(self.scan_id, rows)
            except Exception:
                log.debug("could not store live relevance scores", exc_info=True)


# ---------------------------------------------------------------------------------------------
# Settings > Relevance: score a sample pair through the real pipeline

def test_pair(cfg: dict, target: str, context: str, candidate: str, candidate_type: str = 'HUMAN_NAME', *,
              embed_client=None, adjudicator=None) -> dict:
    """Score one made-up finding against a made-up target and report every signal. Never raises, never returns a key."""
    out: typing.Dict[str, typing.Any] = {'ok': True, 'signals': [], 'message': ''}
    target, candidate = str(target or '').strip()[:200], str(candidate or '').strip()[:300]
    if not target or not candidate:
        return {'ok': False, 'signals': [], 'message': 'Enter a target and a finding to compare.'}
    seed_type = 'COMPANY_NAME' if rp_looks_like_company(target) else 'HUMAN_NAME'
    prof = rp.TargetProfile(target, seed_type, context)
    if not prof.scorable:
        return {'ok': False, 'signals': [], 'message': 'That does not look like a person or company name.'}
    th = rv.Thresholds.from_config(cfg)
    events = [('seed', seed_type, 'SpiderFoot UI', target, 'ROOT', 0, 0),
              ('cand', candidate_type, 'sample', candidate, 'seed', 1, 0)]
    a = rv.Assessment(events, prof, th)
    res = a.run()
    r = res['cand']
    out['signals'].append({'stage': 'heuristics', 'score': round(r.score, 3), 'label': r.label, 'reasons': r.reasons})
    client = embed_client if embed_client is not None else re_.EmbeddingClient.from_config(cfg, timeout=20)
    if client is None:
        out['signals'].append({'stage': 'embeddings', 'skipped': 'No embeddings endpoint is configured (or it is switched off).'})
    else:
        t0 = time.time()
        # a lone candidate is always "borderline" for the test, whatever its score
        ptext = context_text(a, res)
        ctext = embed_text(a, a.by_hash['cand'])
        if not ptext:
            out['signals'].append({'stage': 'embeddings', 'skipped': 'Nothing is known about the target besides the name. '
                                   'Add a context hint (a place, an employer) to compare findings on more than the name.'})
        else:
            vecs, stats = re_.embed_cached(client, None, [ptext, ctext], max_new=4)
            pv, cv = vecs.get(ptext[:re_.TEXT_LIMIT]), vecs.get(ctext[:re_.TEXT_LIMIT])
            if pv is None or cv is None:
                out['signals'].append({'stage': 'embeddings', 'skipped': stats.get('error') or 'No vectors came back.'})
            else:
                sim = re_.cosine(pv, cv)
                mid = int(cfg.get('_rel_embed_mid', 50) or 50) / 100.0
                d = re_.similarity_delta(sim, mid=mid)
                a.adjust['cand'], a.adjust_note['cand'] = d, f"Context similarity {sim:.0%} ({'+' if d >= 0 else ''}{d * 100:.0f} points)"
                a.method_flags.add('embeddings')
                out['signals'].append({'stage': 'embeddings', 'similarity': round(sim, 3), 'delta': round(d, 3),
                                       'ms': int((time.time() - t0) * 1000), 'model': client.model, 'compared': ctext[:160]})
    judge = adjudicator if adjudicator is not None else rl.Adjudicator.from_config(cfg)
    if judge is None or judge.max_calls < 1:
        out['signals'].append({'stage': 'ai', 'skipped': 'The AI assistant is off, not configured or not allowed for relevance.'})
    else:
        t0 = time.time()
        verdicts = judge.judge(prof.text(), [{'id': '1', 'type': candidate_type.replace('_', ' ').lower(), 'text': a.event_text(a.by_hash['cand'], 220).split(': ', 1)[-1]}])
        if '1' in verdicts:
            v, conf, why = verdicts['1']
            out['signals'].append({'stage': 'ai', 'verdict': v, 'confidence': round(conf, 2), 'reason': why,
                                   'ms': int((time.time() - t0) * 1000), 'tokens': judge.tokens})
            if v != 'unknown':
                a.verdicts['cand'] = (v, conf, why)
                a.method_flags.add('ai')
        else:
            out['signals'].append({'stage': 'ai', 'skipped': judge.errors[0] if judge.errors else 'The model did not return a usable answer.'})
    final = a.run()['cand']
    out['final'] = {'score': round(final.score, 3), 'label': final.label, 'method': a.method_name(), 'reasons': final.reasons}
    return out


def rp_looks_like_company(text: str) -> bool:
    from spiderfoot.helpers import SpiderFootHelpers
    return SpiderFootHelpers.looksLikeCompanyName(f'"{text}"') or bool(SpiderFootHelpers.companyPrefixName(text))


# ---------------------------------------------------------------------------------------------
# settings validation

INT_RANGES = {
    '_rel_t_unrelated': (0, 95), '_rel_t_likely': (1, 99), '_rel_t_confirmed': (2, 100),
    '_rel_max_llm_calls': (0, 200), '_rel_max_llm_tokens': (0, 2000000), '_rel_max_embed_texts': (0, 20000), '_rel_embed_mid': (0, 100),
}
BOOL_KEYS = ('_rel_enabled', '_rel_prune_default', '_rel_auto_assess', '_rel_use_embeddings', '_rel_use_ai')
URL_KEYS = ('_rel_embeddings_url',)


def validate_settings(opts: dict, current: typing.Optional[dict] = None) -> str:
    """'' when the relevance settings in ``opts`` (strings, as posted by the form) are acceptable, else a message."""
    from spiderfoot.services import urlcheck
    current = current or {}
    for key, (lo, hi) in INT_RANGES.items():
        if key in opts:
            try:
                v = int(str(opts[key]).strip())
            except ValueError:
                return f"{key.replace('_rel_', '').replace('_', ' ')} must be a whole number."
            if not lo <= v <= hi:
                return f"{key.replace('_rel_', '').replace('_', ' ')} must be between {lo} and {hi}."
    for key in BOOL_KEYS:
        if key in opts and str(opts[key]).strip() not in ('0', '1'):
            return f"{key.replace('_rel_', '').replace('_', ' ')} must be on or off."
    for key in URL_KEYS:
        if opts.get(key):
            _url, problem = urlcheck.check_http_url(str(opts[key]), resolve=False)
            if problem:
                return problem

    def num(key, default):
        try:
            return int(str(opts.get(key, current.get(key, default))).strip())
        except ValueError:
            return default
    if not num('_rel_t_unrelated', 25) <= num('_rel_t_likely', 55) <= num('_rel_t_confirmed', 80):
        return "The thresholds must rise: hide below, then likely, then confirmed."
    return ''
