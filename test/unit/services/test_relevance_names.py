"""Name parsing and comparison: middle names decide between people with the same first and last name."""
import pytest

from spiderfoot.services import relevance_names as rn

T = rn.parse('Nicholas Thomas Thornwood')


class TestParse:
    @pytest.mark.parametrize('text,expected', [
        ('Nicholas Andrew Thornwood, MD', ('nicholas', ('andrew',), 'thornwood')),
        ('NICHOLAS JAMES THORNWOOD, D.O.', ('nicholas', ('james',), 'thornwood')),
        ('Thornwood, Nicholas Thomas', ('nicholas', ('thomas',), 'thornwood')),
        ('Dr. Nicholas Thornwood', ('nicholas', (), 'thornwood')),
        ('Nicholas T. Thornwood Jr', ('nicholas', ('t',), 'thornwood')),
        ('Ludwig van der Berg', ('ludwig', (), 'vanderberg')),
    ])
    def test_forms(self, text, expected):
        n = rn.parse(text)
        assert (n.first, n.middles, n.last) == expected

    @pytest.mark.parametrize('text', ['Thornwood', 'Acme Widgets Inc.', 'Nicholas Thornwood Holdings LLC', '', 'x' * 120, 'Springfield Hospital'])
    def test_not_a_person(self, text):
        assert not rn.parse(text)


class TestCompare:
    @pytest.mark.parametrize('text,expected', [
        ('Nicholas Thomas Thornwood', 'exact'),
        ('Nicholas T. Thornwood', 'exact_initial'),
        ('Nick Thornwood', 'name_only'),
        ('Nicholas Thornwood', 'name_only'),
        ('NICHOLAS ANDREW THORNWOOD, MD', 'conflict_middle'),
        ('Nicholas R Thornwood', 'conflict_initial'),
        ('Thomas Thornwood', 'middle_as_first'),
        ('Michael F Murray', 'different'),
    ])
    def test_classes(self, text, expected):
        assert rn.compare(T, rn.parse(text)) == expected

    def test_target_without_middle_name_cannot_conflict(self):
        t = rn.parse('John Smith')
        assert rn.compare(t, rn.parse('John Quincy Smith')) == 'name_only'

    def test_nicknames_are_symmetric(self):
        assert rn.first_matches('nick', 'nicholas') and rn.first_matches('nicholas', 'nick')
        assert rn.first_matches('bill', 'william')
        assert not rn.first_matches('n', 'nicholas')


class TestSlugs:
    @pytest.mark.parametrize('slug,expected', [
        ('nicholas.thomas.thornwood', 'exact'),
        ('nicholasthomasthornwood', 'exact'),
        ('nick.thornwood.35', 'name_only'),
        ('nick.o.thornwood', 'conflict_initial'),
        ('nicholas-thornwood-0k54av', 'name_only'),
        ('Thornwood-Nicholas.htm', 'name_only'),
        ('JetsFan006', ''),
        ('Thornwood_(film)', ''),
        ('john.thornwood.35', 'different'),
    ])
    def test_slug(self, slug, expected):
        assert rn.compare_slug(T, slug) == expected


class TestCompanies:
    def test_similarity(self):
        assert rn.company_similarity('Acme Widgets, Inc.', 'ACME WIDGETS LLC') == 1.0
        assert 0.5 < rn.company_similarity('Acme Widgets', 'Acme Widgets Holdings') < 1.0
        assert rn.company_similarity('Acme Widgets', 'Globex Corporation') == 0.0

    def test_strip_name_leaves_context(self):
        t = rn.parse('Nicholas Thomas Thornwood')
        out = rn.strip_name('Nick Thornwood - Software Engineer, Boston (Nicholas)', t)
        assert 'Thornwood' not in out and 'Nick' not in out and 'Software Engineer' in out
