import json
import unittest
from urllib.parse import urlparse

import pytest

from modules.sfp_us_state_registries import sfp_us_state_registries
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget

CT = [
    {"name": "ACME UNITED CORPORATION", "accountnumber": "0071976", "status": "Active",
     "billingstreet": "1 WATERVIEW DRIVE", "billingcity": "SHELTON", "billingstate": "CT",
     "billingpostalcode": "06484", "mailing_address": "1 WATERVIEW DRIVE , ,SHELTON ,CT ,United States ,06484",
     "business_email_address": "info@acmeunited.example"},
    {"name": "ACME UNITED FOUNDATION, INC.", "accountnumber": "0062632", "status": "Dissolved",
     "billingstreet": "No information provided"},
]
CO = [
    {"entityid": "1", "entityname": "ACME UNITED CORP, Dissolved May 1, 2001", "entitystatus": "Dissolved",
     "principaladdress1": "9 Main St", "principalcity": "Denver", "principalstate": "CO",
     "principalzipcode": "80202", "agentfirstname": "JANE", "agentlastname": "DOE"},
]
OR = [
    {"registry_number": "5", "business_name": "ACME UNITED CORPORATION", "associated_name_type": "REGISTERED AGENT",
     "entity_of_record_name": "C T CORPORATION SYSTEM", "address": "1 Agent Way", "city": "Salem", "state": "OR"},
    {"registry_number": "5", "business_name": "ACME UNITED CORPORATION",
     "associated_name_type": "PRINCIPAL PLACE OF BUSINESS", "address": "1 WATERVIEW DRIVE", "city": "SHELTON",
     "state": "CT", "zip": "06484"},
    {"registry_number": "5", "business_name": "ACME UNITED CORPORATION",
     "associated_name_type": "AUTHORIZED REPRESENTATIVE", "first_name": "WALTER", "last_name": "JOHNSEN"},
]


@pytest.mark.usefixtures
class TestModuleUsStateRegistries(unittest.TestCase):

    def test_opts(self):
        module = sfp_us_state_registries()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_like_pattern(self):
        p = sfp_us_state_registries.likePattern
        self.assertEqual("ACME%WIDGETS%", p("Acme Widgets, Inc."))
        self.assertEqual("A%B%", p("A&B LLC"))
        self.assertEqual("O%BRIEN%", p("O'Brien Co"))
        self.assertIsNone(p("!!!"))

    def test_handle_event(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_us_state_registries()
        module.setup(sf, {**self.default_options, 'state_ny': False, 'state_tx': False})
        module.setTarget(SpiderFootTarget("Acme United Corp", 'COMPANY_NAME'))
        urls = []

        def fetch(url, **kwargs):
            urls.append(url)
            for host, rows in (("data.ct.gov", CT), ("data.colorado.gov", CO), ("data.oregon.gov", OR)):
                if host in url:
                    return {'code': '200', 'content': json.dumps(rows)}
            return {'code': '404', 'content': None}

        sf.fetchUrl = fetch
        events = []
        module.notifyListeners = events.append
        root = SpiderFootEvent('ROOT', "Acme United Corp", '', '')
        module.handleEvent(SpiderFootEvent('COMPANY_NAME', "Acme United Corp", 'SpiderFoot UI', root))

        self.assertEqual(3, len(urls))
        self.assertFalse(any(urlparse(u).hostname in {"data.ny.gov", "data.texas.gov"} for u in urls))
        self.assertIn("like+%27ACME%25UNITED%25%27", urls[0])

        raw = [json.loads(e.data) for e in events if e.eventType == "RAW_RIR_DATA"]
        self.assertEqual({"Colorado", "Connecticut", "Oregon"}, {r['state'] for r in raw})
        self.assertNotIn("ACME UNITED FOUNDATION, INC.", [r['name'] for r in raw])

        addrs = {e.data for e in events if e.eventType == "PHYSICAL_ADDRESS"}
        self.assertIn("1 WATERVIEW DRIVE, SHELTON, CT 06484", addrs)
        self.assertFalse(any("No information" in a for a in addrs))

        people = {e.data for e in events if e.eventType == "HUMAN_NAME"}
        self.assertEqual({"Jane Doe", "Walter Johnsen"}, people)
        self.assertEqual(["info@acmeunited.example"], [e.data for e in events if e.eventType == "EMAILADDR"])


if __name__ == '__main__':
    unittest.main()
