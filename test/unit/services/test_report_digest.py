"""The deterministic digests: counts, categories, identity, risks, coverage, citation ids."""
import json

import pytest

from spiderfoot.services import report_digest as rd
from test.unit.services import report_helpers as rh
from test.unit.services.relevance_fixture import TARGET, namesake_events


@pytest.fixture
def namesake(tmp_path):
    cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'))
    dbh = rh.seed_namesake(cfg)
    digest, index = rd.build(dbh, 'NS000001', cfg)
    return cfg, dbh, digest, index


@pytest.fixture
def infra(tmp_path):
    cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'))
    dbh = rh.seed_infra(cfg)
    digest, index = rd.build(dbh, 'INF00001', cfg)
    return cfg, dbh, digest, index


class TestScanFacts:
    def test_header_facts(self, namesake):
        _, _, d, _ = namesake
        s = d['scan']
        assert s['target'] == TARGET and s['status'] == 'FINISHED' and not s['partial']
        assert s['duration_s'] == 599 and s['duration'] == '9m 59s'
        assert s['context'] == 'location: Missouri' and s['modules_enabled'] == 3
        assert d['totals']['events'] == len(namesake_events()) - 1        # without the ROOT row
        assert d['totals']['has_relevance'] is True

    def test_aborted_scan_is_partial(self, tmp_path):
        cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'))
        dbh = rh.seed_namesake(cfg, status='ABORTED')
        d, _ = rd.build(dbh, 'NS000001', cfg)
        assert d['scan']['partial'] is True and d['coverage']['aborted'] is True

    def test_unknown_scan(self, tmp_path):
        cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'))
        dbh = rh.seed_infra(cfg)
        with pytest.raises(ValueError):
            rd.build(dbh, 'NOPE0000', cfg)

    def test_profile_is_inferred(self):
        cfg = {'__modules__': {'sfp_a': {'group': ['Footprint']}, 'sfp_b': {'group': ['Footprint', 'Passive']}, 'sfp_c': {'group': ['Passive']}}}
        assert rd.infer_profile(['sfp_a', 'sfp_b', 'sfp__stor_db'], cfg) == 'Footprint use case'
        assert rd.infer_profile(['sfp_a'], cfg).startswith('a custom selection')
        assert rd.infer_profile(['sfp_a', 'sfp_c'], cfg, [{'id': 'p1', 'name': 'Mine', 'modules': ['sfp_a', 'sfp_c']}]) == 'preset "Mine"'


class TestIdentity:
    def test_namesakes_are_counted_not_listed(self, namesake):
        _, _, d, index = namesake
        i = d['identity']
        assert i['name_scan'] and i['unrelated'] > 0 and i['strong'] >= 2
        assert i['verdict'].startswith('mostly unconfirmed')
        listed = json.dumps(d['categories']) + json.dumps(i['items']) + json.dumps(d['risks'])
        for hidden in ('MARCUS ADRIAN THORNWOOD', 'Dana Q Pellham', 'Globex', 'legal@globex.test', '1 TEST ST'):
            assert hidden not in listed
        # the cited findings never include an unrelated one
        assert all(e['label'] != 'unrelated' for e in index.events.values())

    def test_exclusion_reasons_carry_no_names(self, namesake):
        _, _, d, _ = namesake
        text = json.dumps(d['identity']['excluded_by_reason'] + d['identity']['unclear_by_reason'])
        for name in ('Thornwood', 'Marcus', 'Pellham', 'Adrian'):
            assert name not in text
        assert any('middle' in r for r, _ in d['identity']['excluded_by_reason'])

    def test_reason_class(self):
        assert rd.reason_class('A different person (Jane Roe)') == 'A different person'
        assert rd.reason_class('Found under Jane Roe (a different person)') .startswith('Found under something')
        assert 'Roe' not in rd.reason_class('Only first and last name match; nothing to tell it apart from other Roes', 'Jane Roe')
        assert rd.reason_class('Different middle name: Jane A Roe vs Jane B Roe, probably', 'Jane Roe') == 'Different middle name, so probably another person'

    def test_a_marked_finding_is_listed_and_counted(self, tmp_path):
        cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'))
        dbh = rh.seed_namesake(cfg)
        dbh.overrideSet('NS000001', ['bc2_lic'], 'mine')
        from spiderfoot.services import relevance_job as job
        job.assess_scan(cfg, 'NS000001', dbh=dbh, network=False)
        d, index = rd.build(dbh, 'NS000001', cfg)
        assert d['totals']['overrides']['mine'] == 1
        mine = d['identity']['mine']
        assert mine and index.events[mine[0]]['hash'] == 'bc2_lic'

    def test_infra_scan_is_not_scored(self, infra):
        _, _, d, _ = infra
        assert d['identity']['name_scan'] is False and 'not applicable' in d['identity']['verdict']
        assert d['totals']['has_relevance'] is False
        assert any(i['type'] == 'IP_ADDRESS' for i in d['identity']['items'])


class TestCategoriesRisksCoverage:
    def test_categories_of_the_infra_scan(self, infra):
        _, _, d, _ = infra
        c = d['categories']
        assert c['infrastructure']['unique'] >= 4 and c['exposure']['unique'] == 1 and c['reputation']['unique'] == 1
        assert {t[0] for t in c['infrastructure']['types']} >= {'TCP_PORT_OPEN', 'IP_ADDRESS'}
        assert c['people']['unique'] == 0

    def test_risks_and_correlations(self, infra):
        _, _, d, index = infra
        r = d['risks']
        assert r['levels'] == {'HIGH': 1, 'MEDIUM': 1}
        assert r['correlation_total'] == 1 and r['correlation_counts'] == {'HIGH': 1}
        assert r['correlations'][0]['id'].startswith('C') and r['correlations'][0]['id'] in index.correlations
        assert any(i['type'] == 'VULNERABILITY_CVE_HIGH' for i in r['items'])

    def test_coverage_names_silent_modules_and_key_problems(self, infra):
        _, _, d, _ = infra
        cov = d['coverage']
        assert 'sfp_silent' in cov['silent'] and 'sfp_shodan' in cov['silent']
        assert cov['key_problems'][0]['module'] == 'sfp_shodan' and cov['key_problems'][0]['kind'] == 'rejected'
        assert ('sfp_other', 1) in [tuple(x) for x in cov['other_errors']]

    def test_digest_is_json_serialisable_and_numbers_are_extractable(self, infra):
        _, _, d, _ = infra
        json.dumps(d)
        facts = rd.event_facts(d)
        assert str(d['totals']['events']) in facts and rd.fmt(11245) == '11,245'


class TestCitationIndex:
    def test_ids_are_stable_and_capped(self):
        idx = rd.CitationIndex(cap=2)
        assert idx.add_event({'hash': 'a', 'type': 'T'}) == 'E1'
        assert idx.add_event({'hash': 'a', 'type': 'T'}) == 'E1'
        assert idx.add_event({'hash': 'b', 'type': 'T'}) == 'E2'
        assert idx.add_event({'hash': 'c', 'type': 'T'}) is None
        assert idx.add_correlation({'title': 'x'}) == 'C1'
        assert idx.known() == {'E1', 'E2', 'C1'}
        again = rd.CitationIndex.from_dict(idx.as_dict())
        assert again.known() == idx.known()

    def test_a_small_cap_shrinks_every_section(self, tmp_path):
        cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'))
        dbh = rh.seed_namesake(cfg)
        d, index = rd.build(dbh, 'NS000001', cfg, appendix_max=6)
        assert len(index.events) <= 6
        d0, index0 = rd.build(dbh, 'NS000001', cfg, appendix_max=0)
        assert len(index0.events) == 0

    def test_source_links_for_the_appendix(self, namesake):
        _, dbh, _, index = namesake
        rd.finalize_citations(dbh, 'NS000001', index)
        social = [e for e in index.events.values() if e['type'] == 'SOCIAL_MEDIA']
        assert social and all(e['url'].startswith('https://') for e in social)

    def test_digest_is_fast_on_a_large_scan(self, tmp_path):
        import time
        cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'))
        dbh = rh.seed_infra(cfg)
        dbh.dbh.executemany("INSERT INTO tbl_scan_results (scan_instance_id,hash,type,generated,confidence,visibility,risk,module,data,false_positive,source_event_hash)"
                            " VALUES ('INF00001',?,?,?,100,100,0,'sfp_x',?,0,'seed')",
                            [(f'big{i}', 'INTERNET_NAME', rh.NOW_MS, f'h{i}.example.test') for i in range(20000)])
        dbh.conn.commit()
        t = time.time()
        d, _ = rd.build(dbh, 'INF00001', cfg)
        assert d['totals']['events'] > 20000 and time.time() - t < 15
