"""Section prompts, token caps, citation validation, figure checks and the deterministic fallbacks."""
import re

import pytest

from spiderfoot.services import ai_service
from spiderfoot.services import report_digest as rd
from spiderfoot.services import report_sections as rs
from test.unit.services import report_helpers as rh


@pytest.fixture
def world(tmp_path):
    cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'))
    dbh = rh.seed_namesake(cfg)
    digest, index = rd.build(dbh, 'NS000001', cfg)
    return cfg, digest, index


def units_of(world, cap=1800, enabled=rs.SECTION_IDS):
    cfg, digest, index = world
    return {u.uid: u for u in rs.build_units(digest, enabled, cap, cfg, [])}


class TestUnits:
    def test_every_enabled_section_has_a_unit(self, world):
        units = units_of(world)
        assert {'summary', 'scope', 'identity', 'risks', 'limits', 'next'} <= set(units)
        assert {'cat:people', 'cat:business', 'cat:licences', 'cat:contact', 'cat:social'} <= set(units)
        assert 'cat:infrastructure' not in units          # nothing in it, not even hidden findings

    def test_sections_can_be_switched_off(self, world):
        assert set(units_of(world, enabled=('summary', 'next'))) == {'summary', 'next'}

    def test_writing_order_puts_the_core_first(self, world):
        cfg, digest, _ = world
        order = [u.uid for u in rs.build_units(digest, rs.SECTION_IDS, 1800, cfg, [])]
        assert order[0] == 'summary' and order[1] == 'identity' and order[-1] == 'scope'
        reading = [u.uid for u in rs.reading_order(rs.build_units(digest, rs.SECTION_IDS, 1800, cfg, []))]
        assert reading[:3] == ['summary', 'scope', 'identity'] and reading[-1] == 'next'

    def test_prompt_contains_only_its_own_data(self, world):
        units = units_of(world)
        data = units['cat:licences'].data
        assert 'CATEGORY: Professional licences' in data and 'FINRA BrokerCheck' in data
        assert 'facebook' not in data.lower()                   # that is the social unit's
        for hidden in ('MARCUS ADRIAN', 'Pellham', 'Globex'):
            assert hidden not in ''.join(u.data for u in units.values())

    def test_offered_ids_are_the_ids_in_the_data(self, world):
        for uid, u in units_of(world).items():
            in_data = set(re.findall(r"^\[([EC]\d+)\]", u.data, flags=re.M))
            assert in_data <= set(u.offered), uid
            if uid.startswith('cat:'):
                assert in_data == set(u.offered)

    def test_a_listed_sample_is_marked_as_a_sample(self, world):
        assert 'LISTED:' in units_of(world)['cat:social'].data

    def test_assessment_line_is_computed(self, world):
        _, digest, _ = world
        line = rs.assessment_line(digest)
        assert line.startswith('mostly unconfirmed') and 'unrelated of' in line

    def test_hints_given(self):
        assert rs.hints_given('location: Boston\nEmployer: Acme') == ['location', 'employer']
        assert rs.hints_given('') == []

    def test_modules_that_could_run_are_suggested(self, world):
        cfg, digest, _ = world
        cfg = dict(cfg, __modules__={
            'sfp_keyed': {'consumes': ['HUMAN_NAME'], 'opts': {'api_key': ''}, 'meta': {'flags': ['apikey']}},
            'sfp_have': {'consumes': ['HUMAN_NAME'], 'opts': {'api_key': 'x'}, 'meta': {'flags': ['apikey']}},
            'sfp_other': {'consumes': ['IP_ADDRESS'], 'opts': {'api_key': ''}, 'meta': {'flags': ['apikey']}}})
        assert rs.keyless_candidates(digest, cfg, []) == ['keyed']
        assert rs.keyless_candidates(digest, cfg, ['sfp_keyed']) == []


class TestTokenCaps:
    def test_the_data_block_is_cut_to_the_cap(self, world):
        for cap in (500, 800, 1800):
            for uid, u in units_of(world, cap=cap).items():
                assert ai_service.estimate_tokens(u.data) <= cap, (uid, cap)

    def test_lowest_ranked_items_go_first(self):
        header = ['HEAD']
        items = [f'[E{i}] item number {i} ' + 'x' * 100 for i in range(1, 30)]
        text = rs.fit_lines(header, items, 200)
        assert '[E1]' in text and '[E29]' not in text and ai_service.estimate_tokens(text) <= 200

    def test_a_fixed_part_over_the_cap_is_hard_cut(self):
        assert ai_service.estimate_tokens(rs.fit_lines(['y' * 5000], [], 100)) <= 100


class TestCitationValidation:
    def check(self, text, offered=('E1', 'E2', 'E3'), known=('E1', 'E2', 'E3', 'E4', 'C1')):
        return rs.validate_citations(text, offered, known)

    def test_valid_citations_are_kept(self):
        text, st = self.check("One [E1]. Two [E2, E3].")
        assert text == "One [E1]. Two [E2] [E3]." and st['used'] == ['E1', 'E2', 'E3'] and not st['dropped']

    def test_invented_and_not_offered_ids_are_dropped(self):
        text, st = self.check("A [E99]. B [E4]. C [E1].")
        assert 'E99' not in text and 'E4' not in text and '[E1]' in text
        assert set(st['dropped']) == {'E99', 'E4'}

    def test_other_shapes_are_normalised(self):
        text, st = self.check("Seen in (E2) and E3 and [E1 shows this].")
        assert '[E2]' in text and '[E3]' in text and '[E1]' in text and 'shows' not in text

    def test_case_is_ignored_and_sentence_coverage_counted(self):
        text, st = self.check("The first sentence has a source [e1]. The second sentence has none at all.")
        assert '[E1]' in text and st['sentences'] == 2 and st['cited'] == 1


class TestFigures:
    def test_figures_in_the_data_pass(self):
        allowed = rs.numbers_in("11,245 events from 29 modules; 3 likely; port 443; id [E12]")
        assert rs.check_numbers("There were 11,245 events and 11245 rows on port 443 in 2026.", allowed) == []

    def test_invented_figures_are_flagged(self):
        allowed = rs.numbers_in("29 modules, 11,245 events")
        assert rs.check_numbers("There were 12,000 events, 17 modules and 3 hits.", allowed) == ['12,000', '17']

    def test_small_numbers_years_and_citations_are_ignored(self):
        assert rs.check_numbers("In 1999 and 2024, [E123] had 7 hits.", set()) == []


class TestCleaning:
    def test_chat_padding_is_removed(self):
        raw = "<think>hmm</think>Sure, here is the section:\n\n## Heading\n\nThe real text.\n\nLet me know if you need more."
        assert rs.clean_prose(raw) == "The real text."

    def test_fences_are_removed(self):
        assert rs.clean_prose("```markdown\nText here\n```") == "Text here"


class TestFallbacks:
    def test_every_unit_has_usable_fallback_text(self, world):
        for uid, u in units_of(world).items():
            if uid != 'limits':          # limits is the Python-written facts block
                assert u.fallback.strip(), uid
        assert units_of(world)['limits'].facts.strip()

    def test_fallback_cites_only_offered_findings(self, world):
        for uid, u in units_of(world).items():
            for cid in re.findall(r"\[([EC]\d+)\]", u.fallback):
                assert cid in u.offered or uid in ('summary',), (uid, cid)

    def test_empty_category_is_not_asked_of_the_model(self, tmp_path):
        cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'))
        dbh = rh.seed_namesake(cfg)
        dbh.overrideSet('NS000001', [h for h in dbh.relevanceGet('NS000001')], 'not_related')
        from spiderfoot.services import relevance_job as job
        job.assess_scan(cfg, 'NS000001', dbh=dbh, network=False)
        d, _ = rd.build(dbh, 'NS000001', cfg)
        u = {x.uid: x for x in rs.build_units(d, rs.SECTION_IDS, 1800, cfg, [])}
        assert u['cat:licences'].skip_ai and 'hidden as unrelated' in u['cat:licences'].fallback
