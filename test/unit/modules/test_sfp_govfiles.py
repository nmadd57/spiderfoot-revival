import json
import unittest

import pytest

from modules.sfp_govfiles import sfp_govfiles
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from spiderfoot.services import api_quota

COMPANY = {
    "kind": "company", "jurisdiction_code": "us_ma", "entity_number": "001234567",
    "legal_name": "ACME WIDGETS, INC.", "status": "active", "status_raw": "Active",
    "legal_form": "corporation", "domicile": "domestic", "formed_on": "1999-01-02",
    "addresses": {
        "registered": {"street_address": "84 State St", "locality": "Boston", "region": "MA",
                       "postal_code": "02109"},
        "headquarters": {"street_address": "1 Main St", "street_address_2": "Suite 2",
                         "locality": "Worcester", "region": "MA", "postal_code": "01608"},
    },
    "parties": [
        {"type": "company", "name": "CT CORPORATION SYSTEM", "roles": [{"kind": "registered_agent"}]},
        {"type": "person", "name": "JANE Q DOE", "roles": [{"kind": "officer", "title": "President"}]},
        {"type": "company", "name": "Acme Holdings LLC", "roles": [{"kind": "shareholder"}]},
    ],
    "relationships": [
        {"kind": "home_entity", "entity": {"name": "Acme Widgets Inc", "jurisdiction_code": "us_de"}},
    ],
    "contact": {"phone": "(508) 555-0100", "websites": ["https://www.acmewidgets.com/about"]},
    "names": [{"name": "Acme Gadgets", "kind": "trading"}],
    "search_url": "https://example.invalid/search", "as_of": "2026-10-01",
}

# Shaped after SearchResponseV2 in https://docs.govfiles.dev/openapi.json
SEARCH = {
    "page": 1,
    "summary": {"total_matches": 2, "returned": 2, "jurisdictions_searched": ["us_ma", "us_nh"]},
    "results": [
        {"match": {"matched_field": "name", "matched_value": "ACME WIDGETS, INC."}, "company": COMPANY},
        {"match": {"matched_field": "name", "matched_value": "ACME WIDGETS HOLDINGS LLC"},
         "company": {"jurisdiction_code": "us_nh", "entity_number": "9", "legal_name": "ACME WIDGETS HOLDINGS LLC"}},
    ],
}


@pytest.mark.usefixtures
class TestModuleGovfiles(unittest.TestCase):

    def test_opts(self):
        module = sfp_govfiles()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def _module(self, opts=None):
        sf = SpiderFoot(self.default_options)
        module = sfp_govfiles()
        # Scans replace _internettlds with the downloaded public suffix list
        module.setup(sf, {**self.default_options, '_internettlds': "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n", 'api_key': 'k', **(opts or {})})
        module.setTarget(SpiderFootTarget("Acme Widgets Inc", 'COMPANY_NAME'))
        return sf, module

    def test_jurisdictions(self):
        _sf, m = self._module({'jurisdictions': 'MA, nh,us_vt,bogus!'})
        self.assertEqual("us_ma,us_nh,us_vt", m.jurisdictions())
        _sf, m = self._module({'jurisdictions': 'all'})
        self.assertEqual("all", m.jurisdictions())

    def test_handle_event(self):
        sf, module = self._module()
        calls = []

        def fetch(url, **kwargs):
            calls.append((url, kwargs))
            return {'code': '200', 'content': json.dumps(SEARCH)}

        sf.fetchUrl = fetch
        events = []
        module.notifyListeners = events.append
        root = SpiderFootEvent('ROOT', "Acme Widgets Inc", '', '')
        module.handleEvent(SpiderFootEvent('COMPANY_NAME', "Acme Widgets Inc", 'SpiderFoot UI', root))

        self.assertEqual(1, len(calls))
        url, kwargs = calls[0]
        body = json.loads(kwargs['postData'])
        self.assertEqual('"ACME WIDGETS"', body['q'])
        self.assertEqual("us_ct,us_ma,us_me,us_nh,us_ri,us_vt", body['jurisdictions'])
        self.assertEqual('k', kwargs['headers']['X-API-Key'])

        raw = [json.loads(e.data) for e in events if e.eventType == "RAW_RIR_DATA"]
        self.assertEqual(["Massachusetts"], [r['state'] for r in raw])  # Holdings LLC is a different name

        by_type = {}
        for e in events:
            by_type.setdefault(e.eventType, set()).add(e.data)
        self.assertEqual({"1 Main St, Suite 2, Worcester, MA 01608"}, by_type["PHYSICAL_ADDRESS"])
        self.assertEqual({"Jane Q Doe"}, by_type["HUMAN_NAME"])
        self.assertEqual({"Acme Holdings LLC"}, by_type["AFFILIATE_COMPANY_NAME"])
        self.assertEqual({"+15085550100"}, by_type["PHONE_NUMBER"])
        self.assertEqual({"www.acmewidgets.com"}, by_type["AFFILIATE_INTERNET_NAME"])
        self.assertNotIn("COMPANY_NAME", by_type)  # other_names is off by default

    def test_out_of_credits_stops_module(self):
        sf, module = self._module()
        sf.fetchUrl = lambda url, **kw: {'code': '402', 'content': '{"detail": "Insufficient credits"}'}
        module.notifyListeners = lambda e: self.fail("no events expected")
        root = SpiderFootEvent('ROOT', "Acme Widgets Inc", '', '')
        module.handleEvent(SpiderFootEvent('COMPANY_NAME', "Acme Widgets Inc", 'SpiderFoot UI', root))
        self.assertTrue(module.errorState)

    def test_quota_parser(self):
        r = api_quota._parse_govfiles({"balance": 987, "overage_enabled": False})
        self.assertTrue(r['ok'])
        self.assertEqual(987, r['remaining'])
        self.assertEqual('credits', r['unit'])


if __name__ == '__main__':
    unittest.main()
