import json
import unittest
import urllib.parse

import pytest

from modules.sfp_dol_enforcement import sfp_dol_enforcement
from spiderfoot import SpiderFootHelpers
from spiderfoot.services import api_quota
from test.unit.modules._fedtest import by_type, run

INSPECTIONS = {"data": [
    {"activity_nr": 1, "estab_name": "ACME UNITED CORPORATION - MED NAP DIVISION", "site_address": "301 MARIANNE ST",
     "site_city": "BROOKSVILLE", "site_state": "FL", "site_zip": "34601", "open_date": "2023-06-06T00:00:00",
     "insp_type": "B", "insp_scope": "B", "safety_hlth": "S", "naics_code": "322291"},
    {"activity_nr": 2, "estab_name": "ACME UNITED CORP", "site_address": "100 HICKS ST", "site_city": "Bridgeport",
     "site_state": "CT", "site_zip": "00000", "open_date": "1979-12-05T00:00:00", "insp_type": "H"},
    {"activity_nr": 3, "estab_name": "ACME UNITED HOLDINGS, LLC", "site_address": "9 ELSEWHERE"},
]}
VIOLATIONS = {"data": [
    {"activity_nr": 1, "viol_type": "S", "initial_penalty": 11162.0, "current_penalty": 6139.0},
    {"activity_nr": 1, "viol_type": "O", "initial_penalty": 0.0, "current_penalty": 0.0},
    {"activity_nr": 1, "viol_type": "S", "initial_penalty": 5.0, "current_penalty": 5.0, "delete_flag": "X"},
    {"activity_nr": 2, "viol_type": "S", "initial_penalty": 240.0, "current_penalty": 240.0},
]}
WHD = {"data": [
    {"case_id": 10, "legal_name": "Acme United Corporation", "trade_nm": "Acme", "street_addr_1_txt": "1 Main St",
     "cty_nm": "Shelton", "st_cd": "CT", "zip_cd": "06484", "case_violtn_cnt": 3, "flsa_violtn_cnt": 2,
     "fmla_violtn_cnt": 1, "bw_atp_amt": 1500.5, "cmp_assd": 200.0, "findings_end_date": "2024-01-01T00:00:00"},
    {"case_id": 11, "legal_name": "Acme United Foods LLC", "trade_nm": "Acme Foods", "case_violtn_cnt": 9},
]}


def _filter(url):
    return json.loads(urllib.parse.parse_qs(urllib.parse.urlparse(url).query)['filter_object'][0])


@pytest.mark.usefixtures
class TestModuleDolEnforcement(unittest.TestCase):

    def test_opts(self):
        self.assertEqual(len(sfp_dol_enforcement().opts), len(sfp_dol_enforcement().optdescs))

    def test_name_patterns_cover_both_cases(self):
        self.assertEqual(["ACME%UNITED%", "Acme%United%"],
                         sfp_dol_enforcement.namePatterns(SpiderFootHelpers.normalizeCompanyName("Acme United Corp")))

    def test_handle_event(self):
        events, calls = run(self, sfp_dol_enforcement, "Acme United Corporation",
                            [("OSHA/inspection", '200', INSPECTIONS), ("OSHA/violation", '200', VIOLATIONS),
                             ("WHD/enforcement", '200', WHD)], {'api_key': 'test-key'})
        urls = [c[0] for c in calls]
        self.assertEqual(3, len(urls))
        self.assertTrue(all("X-API-KEY=test-key" in u for u in urls))
        self.assertEqual({"ACME%UNITED%", "Acme%United%"}, {f['value'] for f in _filter(urls[0])['or']})
        self.assertEqual({'field': "activity_nr", 'operator': "in", 'value': [1, 2]}, _filter(urls[1]))
        self.assertEqual({"legal_name", "trade_nm"}, {f['field'] for f in _filter(urls[2])['or']})

        t = by_type(events)
        osha, whd = [json.loads(r) for r in t["RAW_RIR_DATA"]]
        self.assertEqual(2, osha['inspections_found'])  # HOLDINGS, LLC is another company
        self.assertEqual(3, osha['violations_in_listed'])  # deleted citation ignored
        self.assertEqual({"Serious": 2, "Other-than-serious": 1}, osha['violations_by_type'])
        self.assertEqual(6379.0, osha['current_penalties_in_listed'])
        self.assertEqual("Complaint", osha['list'][0]['type'])
        self.assertEqual(1, whd['cases_found'])
        self.assertEqual(1500.5, whd['back_wages_in_listed'])
        self.assertEqual({"FLSA (minimum wage/overtime)": 2, "FMLA": 1}, whd['list'][0]['violations_by_law'])
        self.assertIn("301 MARIANNE ST, BROOKSVILLE, FL 34601", t["PHYSICAL_ADDRESS"])
        self.assertIn("100 HICKS ST, Bridgeport, CT", t["PHYSICAL_ADDRESS"])  # 00000 zip dropped

    def test_rejected_key_stops_module(self):
        events, calls = run(self, sfp_dol_enforcement, "Acme United Corporation",
                            [("apiprod.dol.gov", '401', "bad key")], {'api_key': 'test-key'})
        self.assertEqual(1, len(calls))
        self.assertEqual([], events)

    def test_no_key(self):
        events, calls = run(self, sfp_dol_enforcement, "Acme United Corporation", [])
        self.assertEqual([], calls)

    def test_quota_parser(self):
        self.assertTrue(api_quota._parse_dol({"data": []})['valid'])
        self.assertFalse(api_quota._parse_dol({})['ok'])


if __name__ == '__main__':
    unittest.main()
