import json
import unittest

import pytest

from modules.sfp_epa_echo import sfp_epa_echo
from test.unit.modules._fedtest import by_type, run

FACILITIES = {"Results": {"Facilities": [
    {"RegistryID": "1", "FacName": "136430 - ACME UNITED CORPORATION", "FacStreet": "1 MAIN ST",
     "FacCity": "FREMONT", "FacState": "NC", "FacZip": "27830", "FacTotalPenalties": "$5,000",
     "CAAComplianceStatus": "Violation Identified"},
    {"RegistryID": "2", "FacName": "ACME UNITED CORP - PLANT 2", "FacStreet": "2 MAIN ST",
     "FacCity": "FREMONT", "FacState": "NC"},
    {"RegistryID": "3", "FacName": "ACME UNITED HOLDINGS", "FacStreet": "3 MAIN ST"},
]}}


@pytest.mark.usefixtures
class TestModuleEpaEcho(unittest.TestCase):

    def test_opts(self):
        self.assertEqual(len(sfp_epa_echo().opts), len(sfp_epa_echo().optdescs))

    def _run(self, opts=None):
        return run(self, sfp_epa_echo, "Acme United Corp",
                   [("get_facilities", '200', {"Results": {"QueryID": "42"}}),
                    ("get_qid", '200', FACILITIES)], opts)

    def test_prefix_match(self):
        events, calls = self._run()
        self.assertIn("qid=42", calls[1][0])
        raw = [json.loads(d) for d in by_type(events)["RAW_RIR_DATA"]]
        self.assertEqual(["1", "2"], [r['registry_id'] for r in raw])
        self.assertEqual("$5,000", raw[0]['penalties_5yr'])

    def test_exact_match(self):
        events, _ = self._run({'name_match': 'exact'})
        raw = [json.loads(d) for d in by_type(events)["RAW_RIR_DATA"]]
        self.assertEqual(["1"], [r['registry_id'] for r in raw])


if __name__ == '__main__':
    unittest.main()
