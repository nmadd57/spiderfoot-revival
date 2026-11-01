import json
import unittest

import pytest

from modules.sfp_fdic import sfp_fdic
from test.unit.modules._fedtest import by_type, run

BANKS = {"data": [
    {"data": {"NAME": "Acme Bank, National Association", "CERT": 1, "ACTIVE": 1, "ADDRESS": "1 Main St",
              "CITY": "Boston", "STALP": "MA", "ZIP": "02110", "NAMEHCR": "ACME BANCORP INC",
              "WEBADDR": "http://www.acmebank.com"}},
    {"data": {"NAME": "Acme Bank of Maine", "CERT": 2, "ACTIVE": 1}},
]}


@pytest.mark.usefixtures
class TestModuleFdic(unittest.TestCase):

    def test_opts(self):
        self.assertEqual(len(sfp_fdic().opts), len(sfp_fdic().optdescs))

    def test_handle_event(self):
        events, calls = run(self, sfp_fdic, "Acme Bank", [("api.fdic.gov", '200', BANKS)])
        self.assertIn("NAME%3A%22ACME+BANK%22", calls[0][0])
        t = by_type(events)
        self.assertEqual([1], [json.loads(r)['fdic_cert'] for r in t["RAW_RIR_DATA"]])
        self.assertEqual(["1 Main St, Boston, MA 02110"], t["PHYSICAL_ADDRESS"])
        self.assertEqual(["ACME BANCORP INC"], t["AFFILIATE_COMPANY_NAME"])
        self.assertEqual(["www.acmebank.com"], t["AFFILIATE_INTERNET_NAME"])


if __name__ == '__main__':
    unittest.main()
