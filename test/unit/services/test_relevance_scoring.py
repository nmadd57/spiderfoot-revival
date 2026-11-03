"""The deterministic scorer and lineage propagation on the synthetic namesake scan and on generated trees."""
import time

from spiderfoot.services import relevance as rv
from spiderfoot.services import relevance_profile as rp
from test.unit.services.relevance_fixture import TARGET, namesake_events


def assess(context='', overrides=None, rows=None, **kw):
    prof = rp.TargetProfile(TARGET, 'HUMAN_NAME', context)
    a = rv.Assessment(rows or namesake_events(), prof, overrides=overrides, **kw)
    return a, a.run()


class TestProfile:
    def test_structured_and_free_text_hints(self):
        h = rp.parse_context('Lives in Boston, MA. Works at Acme Robotics as an engineer. born 1985\n'
                             'email: me@example.com\nusername: @nickm\nphone: (617) 555-0100\nrelative: Jane Thornwood')
        assert 'MA' in h.states and 'boston' in h.cities
        assert h.employers == ['Acme Robotics'] and h.birth_year == 1985
        assert h.emails == {'me@example.com'} and 'nickm' in h.usernames and h.phones == {'6175550100'}
        assert h.relatives == ['Jane Thornwood']

    def test_empty_and_garbage_context(self):
        assert rp.parse_context('').empty()
        assert rp.parse_context('\x00\x01 ??? :::').states == set()

    def test_profile_kinds(self):
        assert rp.TargetProfile('Jane Doe', 'HUMAN_NAME').scorable
        assert rp.TargetProfile('Acme Widgets LLC', 'COMPANY_NAME').scorable
        assert not rp.TargetProfile('example.com', 'INTERNET_NAME').scorable

    def test_hint_identifiers_become_anchors(self):
        p = rp.TargetProfile('Jane Doe', 'HUMAN_NAME', 'email: jane@doe.test\nusername: janed\nphone: 617-555-0100\nwebsite: doe.test')
        assert {'jane@doe.test', '@janed', '6175550100', 'doe.test'} <= set(p.anchor_values)

    def test_geo(self):
        assert rp.geo_of('332 W PLANK RD, ALTOONA, PA, 16602')[0] == {'PA'}
        assert rp.geo_of('4 Chase, Brooklyn, New York, US-NY, US')[0] == {'NY'}


class TestNamesakePattern:
    def test_target_and_its_own_records(self):
        a, res = assess()
        assert res['seed'].label == 'confirmed'
        assert res['user_exact'].label in ('likely', 'confirmed')
        assert res['acct_exact'].label in ('likely', 'confirmed')
        assert res['fb_initial'].label in ('likely', 'unclear')
        assert res['fb_nameonly'].label == 'unclear'         # unknown is not unrelated
        assert res['fb_nothing'].label == 'unclear'

    def test_other_middle_name_is_unrelated_and_takes_its_record_along(self):
        a, res = assess()
        for key in ('npi_lic', 'npi_raw', 'npi_addr', 'npi_phone', 'fb_other_mid'):
            assert res[key].label == 'unrelated', key
        assert any('middle' in r.lower() for r in res['npi_lic'].reasons)

    def test_record_numbers_share_evidence(self):
        """The one-line broker summary has no middle name; its raw record (same CRD) lists another middle initial."""
        a, res = assess()
        assert res['bc_lic'].label == 'unrelated' and res['bc_raw'].label == 'unrelated'
        assert res['bc_firm'].label == 'unrelated'            # the firm is in the same record
        assert res['bc2_lic'].label == 'unclear' and res['bc2_raw'].label == 'unclear'

    def test_everything_below_an_unrelated_entity_is_unrelated(self):
        a, res = assess()
        for key in ['firm_lei', 'firm_addr', 'firm_coord', 'firm_mail'] + [f'firm_wifi{i}' for i in range(5)]:
            assert res[key].label == 'unrelated', key
        for key in ('officer', 'officer_co', 'officer_addr', 'officer_mail'):
            assert res[key].label == 'unrelated', key

    def test_an_unconfirmed_lead_decays_quickly(self):
        a, res = assess()
        assert res['acme'].label == 'unclear'                 # a name-only full-text hit stays visible
        assert res['acme_addr'].score < res['acme'].score
        assert res['acme_wifi'].label == 'unrelated'

    def test_reasons_are_readable(self):
        a, res = assess()
        for r in res.values():
            assert r.reasons and all(isinstance(x, str) and x for x in r.reasons)
        assert 'Found under' in ' '.join(res['firm_wifi0'].reasons)

    def test_label_counts_cover_every_event(self):
        a, res = assess()
        assert sum(a.summarize(res).values()) == len(res) == len(namesake_events()) - 1   # ROOT is not scored


class TestHintsAndAnchors:
    def test_location_hint_lowers_a_record_elsewhere(self):
        rows = namesake_events()
        _, base = assess(rows=rows)
        _, hinted = assess('location: Massachusetts', rows=rows)
        assert hinted['bc2_lic'].score <= base['bc2_lic'].score
        # a registry address in another state is worse than one with no place at all
        assert hinted['acme_addr'].score < base['acme_addr'].score

    def test_matching_location_raises_a_name_only_record(self):
        rows = namesake_events() + [('x1', 'PHYSICAL_ADDRESS', 'sfp_brokercheck', 'Boston, MA, 02110', 'bc2_lic', 99.0, 0)]
        _, base = assess(rows=rows)
        _, hinted = assess('lives in Boston, MA', rows=rows)
        assert hinted['x1'].score >= base['x1'].score

    def test_shared_email_with_hint_is_proof(self):
        rows = namesake_events() + [('mail1', 'EMAILADDR', 'sfp_email', 'mthornwood@example-mail.test', 'seed', 99.0, 0)]
        _, base = assess(rows=rows)
        _, hinted = assess('email: mthornwood@example-mail.test', rows=rows)
        assert hinted['mail1'].score > base['mail1'].score and hinted['mail1'].label in ('likely', 'confirmed')
        assert any('Shares' in r for r in hinted['mail1'].reasons)

    def test_employer_hint_matches_company(self):
        _, res = assess('employer: Acme Widgets')
        assert res['acme'].score > assess()[1]['acme'].score

    def test_birth_year_mismatch_hurts(self):
        rows = namesake_events() + [('b1', 'RAW_RIR_DATA', 'sfp_x', '{"name": "Marcus E Thornwood", "born": 1950}', 'seed', 99.0, 0)]
        _, base = assess('born: 1990', rows=rows)
        assert any('Born 1950' in r for r in base['b1'].reasons)


class TestOverrides:
    def test_mine_wins_and_lets_children_inherit(self):
        a, res = assess(overrides={'npi_lic': 'mine'})
        assert res['npi_lic'].label == 'confirmed' and res['npi_lic'].method == 'override'

    def test_not_related_wins_over_a_confirmed_score(self):
        a, res = assess(overrides={'user_exact': 'not_related'})
        assert res['user_exact'].label == 'unrelated'
        assert res['acct_exact'].label == 'unrelated' and 'marked not related' in res['acct_exact'].reasons[0]

    def test_override_on_unrelated_branch_does_not_leak(self):
        a, res = assess(overrides={'bc_firm': 'not_related', 'acme': 'mine'})
        assert res['acme'].label == 'confirmed'
        assert res['bc2_lic'].label == 'unclear'


class TestLineageEngine:
    def test_children_never_scored_before_parents(self):
        rows = [('c', 'EMAILADDR', 'm', 'a@b.test', 'b', 3, 0), ('b', 'PHYSICAL_ADDRESS', 'm', '1 A St', 'a', 2, 0),
                ('a', 'COMPANY_NAME', 'm', 'Globex Corporation', 'seed', 1, 0), ('seed', 'HUMAN_NAME', 'SpiderFoot UI', TARGET, 'ROOT', 0, 0)]
        a, res = assess(rows=rows)
        assert [e.h for e in a.order] == ['seed', 'a', 'b', 'c']

    def test_deep_chain_has_no_recursion_limit(self):
        rows = [('seed', 'HUMAN_NAME', 'SpiderFoot UI', TARGET, 'ROOT', 0, 0)]
        prev = 'seed'
        for i in range(3000):
            rows.append((f'e{i}', 'COMPANY_NAME', 'm', f'Chain Co {i}', prev, i, 0))
            prev = f'e{i}'
        a, res = assess(rows=rows)
        assert len(res) == 3001

    def test_twenty_thousand_events_in_seconds(self):
        rows = [('seed', 'HUMAN_NAME', 'SpiderFoot UI', TARGET, 'ROOT', 0, 0)]
        for p in range(200):
            rows.append((f'p{p}', 'HUMAN_NAME', 'sfp_us_state_registries', f'Person{p} Q Name{p}', 'seed', 1, 0))
            for c in range(100):
                kind = ('PHYSICAL_ADDRESS', 'EMAILADDR', 'COMPANY_FILING', 'WIFI_ACCESS_POINT', 'RAW_RIR_DATA')[c % 5]
                rows.append((f'p{p}c{c}', kind, 'sfp_x', f'{kind} {p} {c} {"x" * 200}', f'p{p}', 2, 0))
        assert len(rows) > 20000
        t0 = time.time()
        a, res = assess(rows=rows)
        assert time.time() - t0 < 10
        assert all(res[f'p{p}'].label == 'unrelated' for p in range(0, 200, 17))

    def test_missing_parent_is_treated_as_a_root(self):
        rows = [('seed', 'HUMAN_NAME', 'SpiderFoot UI', TARGET, 'ROOT', 0, 0), ('o', 'COMPANY_NAME', 'm', 'Orphan Co', 'gone', 1, 0)]
        a, res = assess(rows=rows)
        assert 'o' in res


class TestThresholds:
    def test_labels_follow_the_thresholds(self):
        th = rv.Thresholds(0.3, 0.6, 0.9)
        assert [th.label(s) for s in (0.1, 0.3, 0.6, 0.9)] == ['unrelated', 'unclear', 'likely', 'confirmed']

    def test_thresholds_are_kept_in_order(self):
        th = rv.Thresholds(0.9, 0.2, 0.1)
        assert th.hide_below <= th.likely <= th.confirmed

    def test_from_config(self):
        th = rv.Thresholds.from_config({'_rel_t_unrelated': 40, '_rel_t_likely': 60, '_rel_t_confirmed': 95})
        assert (th.hide_below, th.likely, th.confirmed) == (0.4, 0.6, 0.95)
        assert rv.Thresholds.from_config({'_rel_t_unrelated': 'junk'}).hide_below == 0.25

    def test_a_stricter_hide_threshold_hides_more(self):
        _, loose = assess()
        prof = rp.TargetProfile(TARGET, 'HUMAN_NAME')
        a = rv.Assessment(namesake_events(), prof, rv.Thresholds(0.6, 0.7, 0.9))
        strict = a.run()
        assert sum(r.label == 'unrelated' for r in strict.values()) > sum(r.label == 'unrelated' for r in loose.values())


class TestBusinessScan:
    def rows(self):
        return [('seed', 'COMPANY_NAME', 'SpiderFoot UI', 'Acme Widgets, Inc.', 'ROOT', 0, 0),
                ('same', 'COMPANY_NAME', 'sfp_gleif', 'ACME WIDGETS INC', 'seed', 1, 0),
                ('close', 'COMPANY_NAME', 'sfp_gleif', 'Acme Widgets Holdings LLC', 'seed', 2, 0),
                ('other', 'COMPANY_NAME', 'sfp_gleif', 'Zenith Bakery LLC', 'seed', 3, 0),
                ('other_addr', 'PHYSICAL_ADDRESS', 'sfp_gleif', '1 Baker St', 'other', 4, 0),
                ('officer', 'HUMAN_NAME', 'sfp_sec_edgar', 'Pat Lee', 'same', 5, 0),
                ('addr', 'PHYSICAL_ADDRESS', 'sfp_gleif', '1 Main St', 'seed', 6, 0)]

    def test_company_names(self):
        prof = rp.TargetProfile('Acme Widgets, Inc.', 'COMPANY_NAME')
        res = rv.Assessment(self.rows(), prof).run()
        assert res['same'].label == 'confirmed'
        assert res['close'].label in ('likely', 'unclear')
        assert res['other'].label == 'unclear' and res['other_addr'].label == 'unrelated'
        assert res['officer'].label in ('likely', 'confirmed')     # people of a confirmed company are relevant
        assert res['addr'].label in ('likely', 'confirmed')

    def test_non_name_targets_are_not_scorable(self):
        assert not rp.TargetProfile('example.com', 'INTERNET_NAME').scorable
