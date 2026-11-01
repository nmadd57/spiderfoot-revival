import json
import unittest

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
        self.assertEqual(module.watchedEvents(), ["COMPANY_NAME"])
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


if __name__ == '__main__':
    unittest.main()


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
