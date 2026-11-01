import json
import unittest

import pytest

from modules.sfp_openfda import sfp_openfda
from test.unit.modules._fedtest import by_type, run

RECALLS = {"results": [
    {"recalling_firm": "Acme Medical, Inc.", "recall_number": "Z-1", "classification": "Class II",
     "address_1": "1 Main St", "address_2": "N/A", "city": "Boston", "state": "MA", "postal_code": "02110"},
    {"recalling_firm": "Acme Medical Devices LLC", "recall_number": "Z-2", "classification": "Class I"},
]}
REGS = {"results": [{"establishment_type": ["Manufacture Medical Device"], "registration": {
    "registration_number": "123", "name": "ACME MEDICAL INC", "address_line_1": "9 Lab Rd", "city": "Lowell",
    "state_code": "MA", "zip_code": "01850", "iso_country_code": "US",
    "us_agent": {"name": "Jane Doe", "email_address": "jane@acmemed.example"}}}]}


@pytest.mark.usefixtures
class TestModuleOpenfda(unittest.TestCase):

    def test_opts(self):
        self.assertEqual(len(sfp_openfda().opts), len(sfp_openfda().optdescs))

    def test_handle_event(self):
        events, calls = run(self, sfp_openfda, "Acme Medical Inc",
                            [("device/enforcement", '200', RECALLS), ("registrationlisting", '200', REGS)])
        self.assertEqual(4, len(calls))  # 3 recall types + registrations; drug/food 404 = no matches
        t = by_type(events)
        raw = [json.loads(r) for r in t["RAW_RIR_DATA"]]
        recall = next(r for r in raw if 'recalls_found' in r)
        self.assertEqual(1, recall['recalls_found'])
        self.assertEqual({"Class II": 1}, recall['by_classification'])
        self.assertIn("1 Main St, Boston, MA 02110", t["PHYSICAL_ADDRESS"])
        self.assertIn("9 Lab Rd, Lowell, MA 01850", t["PHYSICAL_ADDRESS"])
        self.assertEqual(["Jane Doe"], t["HUMAN_NAME"])
        self.assertEqual(["jane@acmemed.example"], t["EMAILADDR"])

    def test_rate_limit_stops_module(self):
        events, calls = run(self, sfp_openfda, "Acme Medical Inc", [("api.fda.gov", '429', "{}")])
        self.assertEqual(1, len(calls))
        self.assertEqual([], events)


if __name__ == '__main__':
    unittest.main()
