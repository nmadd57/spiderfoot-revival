import json
import unittest
from unittest import mock

import pytest

from modules.sfp_sec_edgar import sfp_sec_edgar
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget

SEARCH = {"hits": {"hits": [
    {"_id": "2098", "_source": {"entity": "ACME UNITED CORP (ACU)"}},
    {"_id": "999", "_source": {"entity": "ACME UNITED HOLDINGS LTD (CIK 0000000999)"}},
]}}
SUBMISSION = {
    "cik": "0000002098", "name": "ACME UNITED CORP", "tickers": ["ACU"], "phone": "203-254-6060",
    "website": "", "addresses": {
        "business": {"street1": "1 WATERVIEW DRIVE", "city": "SHELTON", "stateOrCountry": "CT", "zipCode": "06484"},
        "mailing": {"street1": "1 WATERVIEW DRIVE", "city": "SHELTON", "stateOrCountry": "CT", "zipCode": "06484"},
    },
    "filings": {"recent": {"filingDate": ["2026-10-01"], "form": ["10-Q"]}},
}


@pytest.mark.usefixtures
class TestModuleSecEdgar(unittest.TestCase):

    def test_opts(self):
        module = sfp_sec_edgar()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_watched_and_produced(self):
        module = sfp_sec_edgar()
        self.assertEqual(module.watchedEvents(), ["COMPANY_NAME", "HUMAN_NAME"])
        self.assertIn("COMPANY_FILING", module.producedEvents())
        self.assertIsInstance(module.producedEvents(), list)

    def _run(self, target, responses, opts=None):
        sf = SpiderFoot(self.default_options)
        module = sfp_sec_edgar()
        module.setup(sf, {**self.default_options, **(opts or {})})
        module.setTarget(SpiderFootTarget(target, 'COMPANY_NAME'))
        calls = []

        def fetch(url, **kwargs):
            calls.append(url)
            for key, body in responses.items():
                if key in url:
                    return {'code': '200', 'content': json.dumps(body)}
            return {'code': '404', 'content': None}

        sf.fetchUrl = fetch
        events = []
        module.notifyListeners = events.append
        root = SpiderFootEvent('ROOT', target, '', '')
        module.handleEvent(SpiderFootEvent('COMPANY_NAME', target, 'SpiderFoot UI', root))
        return events, calls

    def test_exact_match_reports_only_matching_filer(self):
        events, calls = self._run("Acme United Corporation",
                                  {"search-index": SEARCH, "CIK0000002098": SUBMISSION})
        types = [e.eventType for e in events]
        self.assertIn("RAW_RIR_DATA", types)
        self.assertIn("PHYSICAL_ADDRESS", types)
        self.assertNotIn("COMPANY_NAME", types)  # same company, only the legal form differs
        self.assertIn("+12032546060", [e.data for e in events if e.eventType == "PHONE_NUMBER"])
        self.assertEqual(1, len([e for e in events if e.eventType == "PHYSICAL_ADDRESS"]))
        self.assertFalse(any("CIK0000000999" in c for c in calls))
        # searched on the core name so "Corporation" doesn't miss "CORP"
        self.assertIn("keysTyped=ACME+UNITED", calls[0])

    def test_no_match_emits_nothing(self):
        events, _ = self._run("Nothing Like It Inc", {"search-index": SEARCH})
        self.assertEqual([], events)

    def test_blocked_sets_error_state(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_sec_edgar()
        module.setup(sf, dict(self.default_options))
        module.setTarget(SpiderFootTarget("Acme", 'COMPANY_NAME'))
        sf.fetchUrl = lambda url, **kw: {'code': '403', 'content': 'blocked'}
        module.notifyListeners = lambda e: self.fail("no events expected")
        root = SpiderFootEvent('ROOT', "Acme", '', '')
        module.handleEvent(SpiderFootEvent('COMPANY_NAME', "Acme", 'SpiderFoot UI', root))
        self.assertTrue(module.errorState)


EX21 = {"hits": {"hits": [
    {"_id": "0001628280-26-003942:meta-ex211.htm", "_source": {
        "ciks": ["0001326801"], "display_names": ["Meta Platforms, Inc.  (META)  (CIK 0001326801)"],
        "file_type": "EX-21.1", "file_date": "2026-01-29"}},
    {"_id": "0001326801-19-000009:fb-ex211.htm", "_source": {
        "ciks": ["0001326801"], "display_names": ["Facebook Inc  (META)  (CIK 0001326801)"],
        "file_type": "EX-21.1", "file_date": "2019-01-31"}},
    {"_id": "0000000000-26-000001:other-10k.htm", "_source": {
        "ciks": ["0000000002"], "display_names": ["Mentions It Corp  (CIK 0000000002)"],
        "file_type": "10-K", "file_date": "2026-02-01"}},
]}}


@pytest.mark.usefixtures
class TestModuleSecEdgarParents(unittest.TestCase):

    def test_parent_from_exhibit_21(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_sec_edgar()
        module.setup(sf, dict(self.default_options))
        module.setTarget(SpiderFootTarget("Instagram, LLC", 'COMPANY_NAME'))
        calls = []

        def fetch(url, **kwargs):
            calls.append(url)
            if "forms=10-K" in url:
                return {'code': '200', 'content': json.dumps(EX21)}
            return {'code': '200', 'content': json.dumps({"hits": {"hits": []}})}

        sf.fetchUrl = fetch
        events = []
        module.notifyListeners = events.append
        root = SpiderFootEvent('ROOT', "Instagram, LLC", '', '')
        module.handleEvent(SpiderFootEvent('COMPANY_NAME', "Instagram, LLC", 'SpiderFoot UI', root))

        self.assertIn("q=%22Instagram%2C+LLC%22", calls[-1])
        self.assertEqual(["Meta Platforms, Inc."],
                         [e.data for e in events if e.eventType == "AFFILIATE_COMPANY_NAME"])
        raw = [json.loads(e.data) for e in events if e.eventType == "RAW_RIR_DATA"]
        self.assertEqual(1, len(raw))  # newest exhibit per parent CIK only
        self.assertEqual("2026-01-29", raw[0]['filed'])
        self.assertTrue(raw[0]['exhibit'].endswith("/1326801/000162828026003942/meta-ex211.htm"))


NIKE = {'name': 'NIKE, Inc.', 'cik': '320187', 'entityType': 'operating', 'sic': '3021',
        'sicDescription': 'Rubber & Plastics Footwear', 'tickers': ['NKE'], 'exchanges': ['NYSE'],
        'stateOfIncorporation': 'OR', 'fiscalYearEnd': '0531', 'ein': '930584541', 'formerNames': [],
        'phone': '5036713173',
        'addresses': {'business': {'street1': 'ONE BOWERMAN DRIVE', 'city': 'BEAVERTON', 'stateOrCountry': 'OR', 'zipCode': '97005'}},
        'filings': {'recent': {'form': ['4', '10-K', '8-K', '10-Q'], 'filingDate': ['2026-10-01', '2026-07-20', '2026-06-27', '2026-04-01'],
                               'accessionNumber': ['0000320187-26-000010', '0000320187-26-000008', '0000320187-26-000007', '0000320187-26-000003'],
                               'primaryDocument': ['x4.xml', 'nke-10k.htm', 'nke-8k.htm', 'nke-10q.htm']}}}
COOK_SELF = {'name': 'COOK TIMOTHY D', 'cik': '1214156', 'entityType': 'other'}


def fts_hit(form, date, adsh, doc, names, ciks):
    return {'_id': f"{adsh}:{doc}", '_source': {'form': form, 'file_date': date, 'adsh': adsh, 'display_names': names, 'ciks': ciks}}


@pytest.mark.usefixtures
class TestModuleSecEdgarPeople(unittest.TestCase):
    """A person's name leads to the public companies it appears in, and on to their filings."""

    def setUp(self):
        self.sf = SpiderFoot(dict(self.default_options))
        self.module = sfp_sec_edgar()
        self.module.__name__ = 'sfp_sec_edgar'
        self.module.opts = dict(sfp_sec_edgar.opts)
        self.module.setup(self.sf, {**self.default_options, 'delay': 0})
        self.module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        self.out = []
        self.module.notifyListeners = lambda e: self.out.append(e)
        self.module.checkForStop = lambda: False
        self.root = SpiderFootEvent('ROOT', 'x', '', None)

    def feed(self, etype, data, src='test'):
        self.module.handleEvent(SpiderFootEvent(etype, data, src, self.root))

    def by_type(self, etype):
        return [e.data for e in self.out if e.eventType == etype]

    def serve(self, routes):
        def fetch(url, *a, **kw):
            for needle, body in routes:
                if needle in url:
                    return {'code': '200', 'content': json.dumps(body)}
            return {'code': '404', 'content': None}
        return mock.patch.object(self.sf, 'fetchUrl', side_effect=fetch)

    def test_person_to_companies_and_filings(self):
        hits = {'hits': {'hits': [
            fts_hit('4', '2021-10-08', '0001127602-21-026859', 'doc4.xml',
                    ['COOK TIMOTHY D  (CIK 0001214156)', 'NIKE, Inc.  (NKE)  (CIK 0000320187)'], ['0001214156', '0000320187']),
            fts_hit('4', '2017-09-25', '0000320187-17-000156', 'doc4.xml',
                    ['COOK TIMOTHY D  (CIK 0001214156)', 'NIKE INC  (NKE)  (CIK 0000320187)'], ['0001214156', '0000320187']),
        ]}}
        with self.serve([('search-index', hits), ('CIK0000320187.json', NIKE), ('CIK0001214156.json', COOK_SELF)]):
            self.feed('HUMAN_NAME', 'Timothy Cook')
        self.assertEqual(self.by_type('COMPANY_NAME'), ['NIKE, Inc.'])
        filings = self.by_type('COMPANY_FILING')
        self.assertTrue(any('Form 4 · 2021-10-08' in f and '/data/320187/000112760221026859/doc4.xml' in f for f in filings), filings)
        self.assertTrue(any('Form 10-K · 2026-07-20' in f for f in filings))  # the company's own recent filings
        self.assertIn('ONE BOWERMAN DRIVE, BEAVERTON, OR 97005', self.by_type('PHYSICAL_ADDRESS'))
        evidence = [json.loads(d) for d in self.by_type('RAW_RIR_DATA') if '"person"' in d][0]
        self.assertEqual(evidence['appearsIn'], {'4': 2})
        self.assertIn('name only', evidence['note'])

    def test_one_word_name_and_no_hits(self):
        with self.serve([('search-index', {'hits': {'hits': []}})]) as f:
            self.feed('HUMAN_NAME', 'Madonna')
            f.assert_not_called()
            self.feed('HUMAN_NAME', 'Nobody Atall')
        self.assertEqual(self.out, [])

    def test_non_operating_filers_are_not_companies(self):
        hits = {'hits': {'hits': [fts_hit('4', '2020-01-01', '0001-20-1', 'd.xml',
                                          ['COOK TIMOTHY D  (CIK 0001214156)', 'SMITH JANE  (CIK 0000999)'], ['0001214156', '0000999'])]}}
        with self.serve([('search-index', hits), ('CIK0000000999.json', {'name': 'SMITH JANE', 'entityType': 'other'})]):
            self.feed('HUMAN_NAME', 'Timothy Cook')
        self.assertEqual(self.by_type('COMPANY_NAME'), [])

    def test_person_search_can_be_turned_off(self):
        self.module.opts['person_search'] = False
        with self.serve([]) as f:
            self.feed('HUMAN_NAME', 'Timothy Cook')
            f.assert_not_called()

    def test_company_filings_are_entities_and_default_to_the_useful_forms(self):
        typeahead = {'hits': {'hits': [{'_id': '320187', '_source': {'entity': 'NIKE INC (NKE)'}}]}}
        with self.serve([('keysTyped', typeahead), ('CIK0000320187.json', NIKE), ('search-index', {'hits': {'hits': []}})]):
            self.feed('COMPANY_NAME', 'Nike Inc.')
        filings = self.by_type('COMPANY_FILING')
        self.assertEqual(len(filings), 3)  # the Form 4 is not in the default form list
        self.assertTrue(all('NIKE, Inc. · Form' in f for f in filings))
        self.assertEqual(self.by_type('PHONE_NUMBER'), ['+15036713173'])

    def test_empty_form_list_reports_every_form(self):
        self.module.opts['filing_forms'] = ''
        typeahead = {'hits': {'hits': [{'_id': '320187', '_source': {'entity': 'NIKE INC (NKE)'}}]}}
        with self.serve([('keysTyped', typeahead), ('CIK0000320187.json', NIKE), ('search-index', {'hits': {'hits': []}})]):
            self.feed('COMPANY_NAME', 'Nike Inc.')
        self.assertEqual(len(self.by_type('COMPANY_FILING')), 4)

    def test_ignores_its_own_companies(self):
        with self.serve([]) as f:
            self.feed('COMPANY_NAME', 'Nike Inc.', src='sfp_sec_edgar')
            f.assert_not_called()

    def test_blocked_request_sets_error_state(self):
        with mock.patch.object(self.sf, 'fetchUrl', return_value={'code': '403', 'content': 'x'}), \
                mock.patch.object(self.module, 'error') as err:
            self.feed('HUMAN_NAME', 'Timothy Cook')
        self.assertTrue(self.module.errorState)
        self.assertIn('contact email', err.call_args[0][0])

    def test_a_reset_connection_is_retried_once(self):
        typeahead = {'hits': {'hits': [{'_id': '320187', '_source': {'entity': 'NIKE INC (NKE)'}}]}}
        replies = [{'code': 'None', 'content': None, 'status': 'reset'},
                   {'code': '200', 'content': json.dumps(typeahead)},
                   {'code': '200', 'content': json.dumps(NIKE)},
                   {'code': '200', 'content': json.dumps({'hits': {'hits': []}})}]
        with mock.patch('modules.sfp_sec_edgar.time.sleep'), mock.patch.object(self.sf, 'fetchUrl', side_effect=replies) as f:
            self.feed('COMPANY_NAME', 'Nike Inc.')
        self.assertEqual(f.call_count, 4)
        self.assertTrue(self.by_type('COMPANY_FILING'))

    def test_contact_email_goes_into_the_user_agent(self):
        self.module.opts['contact_email'] = 'me@example.org'
        self.assertTrue(self.module._useragent().endswith('me@example.org'))


if __name__ == '__main__':
    unittest.main()
