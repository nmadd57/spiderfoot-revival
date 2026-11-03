"""The scan-time gate: unrelated findings are stored but not followed up (checked in a real scan with fake modules)."""
import sys
import types
import uuid

import pytest

from spiderfoot import SpiderFootDb, SpiderFootEvent, SpiderFootPlugin
from spiderfoot.services import relevance as rv
from spiderfoot.services import relevance_job as job
from spiderfoot.services import relevance_profile as rp
from test.unit.services.relevance_fixture import TARGET

SEEN = {'follow': []}


class SfpTEmitter(SpiderFootPlugin):
    meta = {'name': 'Emitter'}
    opts = {}

    def setup(self, sfc, userOpts=None):
        self.sf = sfc
        self.opts = dict(userOpts or {})
        self.__name__ = 'sfp_t_emitter'

    def watchedEvents(self):
        return ['HUMAN_NAME']

    def producedEvents(self):
        return ['HUMAN_NAME', 'COMPANY_NAME']

    def handleEvent(self, event):
        if event.module != 'SpiderFoot UI':
            return
        for name in ('Dana Q Pellham', 'Marcus E Thornwood', 'Marcus Adrian Thornwood'):
            self.notifyListeners(SpiderFootEvent('HUMAN_NAME', name, self.__name__, event))


class SfpTFollow(SpiderFootPlugin):
    meta = {'name': 'Follow'}
    opts = {}

    def setup(self, sfc, userOpts=None):
        self.sf = sfc
        self.opts = dict(userOpts or {})
        self.__name__ = 'sfp_t_follow'

    def watchedEvents(self):
        return ['HUMAN_NAME']

    def producedEvents(self):
        return ['PHYSICAL_ADDRESS']

    def handleEvent(self, event):
        if event.module == 'SpiderFoot UI':
            return
        SEEN['follow'].append(event.data)
        self.notifyListeners(SpiderFootEvent('PHYSICAL_ADDRESS', f'1 Follow St for {event.data}', self.__name__, event))


@pytest.fixture
def fake_modules(monkeypatch):
    import modules.sfp__stor_db as stor
    mods = {'sfp_t_emitter': SfpTEmitter, 'sfp_t_follow': SfpTFollow}
    for name, cls in mods.items():
        m = types.ModuleType('modules.' + name)
        setattr(m, name, cls)
        monkeypatch.setitem(sys.modules, 'modules.' + name, m)
    registry = {n: {'opts': {}} for n in mods}
    registry['sfp__stor_db'] = {'opts': dict(stor.sfp__stor_db.opts)}
    SEEN['follow'] = []
    yield registry
    # SpiderFootScanner keeps its module registries in class-level dicts; leave them as we found them for the other tests
    from sfscan import SpiderFootScanner
    SpiderFootScanner._SpiderFootScanner__moduleInstances.clear()
    SpiderFootScanner._SpiderFootScanner__modconfig.clear()


def run_scan(tmp_path, registry, prune, context=''):
    from sfscan import SpiderFootScanner
    opts = {'_debug': False, '__logging': True, '__outputfilter': None, '_useragent': 'x', '_dnsserver': '', '_fetchtimeout': 5,
            '_internettlds': 'com\norg', '_internettlds_cache': 72, '_genericusers': 'admin', '__database': str(tmp_path / 'scan.db'),
            '__modules__': registry, '__correlationrules__': [], '_socks1type': '', '_socks2addr': '', '_socks3port': '',
            '_socks4user': '', '_socks5pwd': '', '__logstdout': False, '_maxthreads': 12, '__scan_prune': prune, '__scan_context': context}
    scan_id = uuid.uuid4().hex[:8].upper()
    sc = SpiderFootScanner('t', scan_id, TARGET, 'HUMAN_NAME', ['sfp__stor_db', 'sfp_t_emitter', 'sfp_t_follow'], opts)
    return sc, scan_id, SpiderFootDb({'__database': opts['__database']})


class TestGateInAScan:
    def test_unrelated_name_is_stored_but_not_followed_up(self, tmp_path, fake_modules):
        sc, scan_id, dbh = run_scan(tmp_path, fake_modules, prune=True)
        assert sc.status == 'FINISHED'
        stored = {r[1] for r in dbh.scanResultEvent(scan_id, 'HUMAN_NAME')}
        assert {'Dana Q Pellham', 'Marcus E Thornwood', 'Marcus Adrian Thornwood'} <= stored       # nothing is deleted
        followed = set(SEEN['follow'])
        assert 'Marcus E Thornwood' in followed
        assert 'Dana Q Pellham' not in followed and 'Marcus Adrian Thornwood' not in followed      # fan-out stopped
        addresses = {r[1] for r in dbh.scanResultEvent(scan_id, 'PHYSICAL_ADDRESS')}
        assert addresses == {'1 Follow St for Marcus E Thornwood'}

    def test_switch_off_follows_everything(self, tmp_path, fake_modules):
        sc, scan_id, dbh = run_scan(tmp_path, fake_modules, prune=False)
        assert {'Dana Q Pellham', 'Marcus Adrian Thornwood', 'Marcus E Thornwood'} <= set(SEEN['follow'])
        assert dbh.scanContextGet(scan_id) == {'context': '', 'prune': False, 'exists': True}

    def test_scores_are_stored_with_reasons_and_final_assessment_runs(self, tmp_path, fake_modules):
        sc, scan_id, dbh = run_scan(tmp_path, fake_modules, prune=True, context='location: Massachusetts')
        by_data = {r[1]: r[8] for r in dbh.scanResultEvent(scan_id, 'HUMAN_NAME')}
        rel = dbh.relevanceGet(scan_id)
        assert rel[by_data['Dana Q Pellham']][1] == 'unrelated' and rel[by_data['Marcus Adrian Thornwood']][1] == 'unrelated'
        assert rel[by_data['Marcus E Thornwood']][1] in ('likely', 'confirmed')
        assert rel[by_data['Dana Q Pellham']][3] == 'heuristics'                 # the post-scan assessment replaced the live scores
        run = dbh.relevanceRunGet(scan_id)
        assert run['status'] == 'done' and dbh.scanContextGet(scan_id)['context'] == 'location: Massachusetts'

    def test_scans_of_other_targets_are_never_gated(self, tmp_path, fake_modules):
        from sfscan import SpiderFootScanner
        opts = {'_debug': False, '__logging': True, '__outputfilter': None, '_useragent': 'x', '_dnsserver': '', '_fetchtimeout': 5,
                '_internettlds': 'com\norg', '_internettlds_cache': 72, '_genericusers': 'admin', '__database': str(tmp_path / 'd.db'),
                '__modules__': fake_modules, '__correlationrules__': [], '_socks1type': '', '_socks2addr': '', '_socks3port': '',
                '_socks4user': '', '_socks5pwd': '', '__logstdout': False, '_maxthreads': 12, '__scan_prune': True}
        sc = SpiderFootScanner('t', 'DOM00001', 'example.com', 'INTERNET_NAME', ['sfp__stor_db'], opts)
        assert sc._SpiderFootScanner__gate is None


class TestGateUnit:
    def gate(self, dbh, prune=True, context=''):
        prof = rp.TargetProfile(TARGET, 'HUMAN_NAME', context)
        dbh.scanInstanceCreate('G1', 'x', TARGET)
        return job.RelevanceGate(dbh, 'G1', prof, rv.Thresholds(), prune)

    @pytest.fixture
    def dbh(self, tmp_path):
        d = SpiderFootDb({'__database': str(tmp_path / 'g.db')}, init=True)
        yield d
        d.close()

    def test_decisions_and_lineage(self, dbh):
        g = self.gate(dbh)
        assert not g.check('seed', 'HUMAN_NAME', 'SpiderFoot UI', TARGET, 'ROOT')
        assert g.check('p1', 'HUMAN_NAME', 'm', 'Marcus Adrian Thornwood', 'seed')           # a different middle name
        assert g.check('a1', 'PHYSICAL_ADDRESS', 'm', '1 Elsewhere St', 'p1')                # held because its source was held
        assert not g.check('u1', 'USERNAME', 'm', 'marcus.elias.thornwood', 'seed')
        assert not g.check('x1', 'IP_ADDRESS', 'm', '203.0.113.9', 'seed')                   # infrastructure is not an identity
        assert g.held_count == 2

    def test_prune_off_scores_but_never_holds(self, dbh):
        g = self.gate(dbh, prune=False)
        g.check('seed', 'HUMAN_NAME', 'SpiderFoot UI', TARGET, 'ROOT')
        assert not g.check('p1', 'HUMAN_NAME', 'm', 'Marcus Adrian Thornwood', 'seed')
        g.flush()
        assert dbh.relevanceGet('G1')['p1'][1] == 'unrelated'

    def test_buffered_rows_are_flushed(self, dbh):
        g = self.gate(dbh)
        g.check('seed', 'HUMAN_NAME', 'SpiderFoot UI', TARGET, 'ROOT')
        g.check('p1', 'HUMAN_NAME', 'm', 'Marcus Adrian Thornwood', 'seed')
        assert dbh.relevanceGet('G1') == {}
        g.flush()
        got = dbh.relevanceGet('G1')
        assert got['p1'][3] == 'scan-gate' and 'prune' in ' '.join(got['p1'][2])

    def test_cached_similarity_can_veto_a_hold(self, dbh):
        g = self.gate(dbh)
        g.similarity = lambda text: 0.9
        g.check('seed', 'HUMAN_NAME', 'SpiderFoot UI', TARGET, 'ROOT')
        assert not g.check('p1', 'HUMAN_NAME', 'm', 'Marcus Adrian Thornwood', 'seed')

    def test_overhead_per_event_is_small(self, dbh):
        import time
        g = self.gate(dbh)
        g.check('seed', 'HUMAN_NAME', 'SpiderFoot UI', TARGET, 'ROOT')
        t0 = time.time()
        for i in range(5000):
            g.check(f'e{i}', 'PHYSICAL_ADDRESS', 'm', f'{i} Some St, Town, ST 12345', 'seed')
        assert (time.time() - t0) / 5000 < 0.002

    def test_for_scan_skips_non_name_targets_and_disabled(self, dbh):
        assert job.RelevanceGate.for_scan(dbh, 'x', {}, 'example.com', 'INTERNET_NAME', '', True) is None
        assert job.RelevanceGate.for_scan(dbh, 'x', {'_rel_enabled': False}, TARGET, 'HUMAN_NAME', '', True) is None
        assert job.RelevanceGate.for_scan(dbh, 'x', {}, TARGET, 'HUMAN_NAME', '', True) is not None
