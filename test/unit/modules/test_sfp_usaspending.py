import json
import unittest

import pytest

from modules.sfp_usaspending import sfp_usaspending
from test.unit.modules._fedtest import by_type, run

RID = "779b3e3e-364f-7cbc-28a4-a2b4484b86f4-C"
SEARCH = {"results": [
    {"id": RID, "name": "ACME UNITED CORP", "recipient_level": "C", "amount": 100.0, "uei": "U1"},
    {"id": "aaaa-P", "name": "ACME UNITED HOLDINGS LLC", "recipient_level": "P", "amount": 5.0},
]}
PROFILE = {"name": "ACME UNITED CORP", "uei": "U1", "duns": "1", "parent_name": "ACME PARENT INC",
           "parents": [{"parent_name": "ACME PARENT INC"}, {"parent_name": "ACME UNITED CORPORATION"}],
           "location": {"address_line1": "1 WATERVIEW DR", "city_name": "SHELTON", "state_code": "CT",
                        "zip": "06484", "zip4": "1234", "country_code": "USA"},
           "total_transaction_amount": 100.0}


@pytest.mark.usefixtures
class TestModuleUsaspending(unittest.TestCase):

    def test_opts(self):
        self.assertEqual(len(sfp_usaspending().opts), len(sfp_usaspending().optdescs))

    def test_handle_event(self):
        events, calls = run(self, sfp_usaspending, "Acme United Corporation",
                            [(f"/recipient/{RID}/", '200', PROFILE), ("/recipient/", '200', SEARCH)])
        self.assertEqual("ACME UNITED", json.loads(calls[0][1]['postData'])['keyword'])
        t = by_type(events)
        self.assertEqual(1, len(t["RAW_RIR_DATA"]))
        self.assertEqual(["1 WATERVIEW DR, SHELTON, CT 06484-1234"], t["PHYSICAL_ADDRESS"])
        self.assertEqual(["ACME PARENT INC"], t["AFFILIATE_COMPANY_NAME"])  # own name not repeated


if __name__ == '__main__':
    unittest.main()
