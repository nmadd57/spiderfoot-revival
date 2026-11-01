import json
import unittest

import pytest

from modules.sfp_irs_nonprofits import sfp_irs_nonprofits
from test.unit.modules._fedtest import by_type, run

SEARCH = {"organizations": [
    {"ein": 43314093, "strein": "04-3314093", "name": "Acme Health Corporation"},
    {"ein": 1, "name": "Acme Health Foundation"},
]}
ORG = {"organization": {"name": "Acme Health Corporation", "address": "1 MAIN ST", "city": "Boston", "state": "MA",
                        "zipcode": "02118", "subsection_code": 3, "careofname": "% KAREN G FINE"},
       "filings_with_data": [{"tax_prd_yr": 2023, "totrevenue": 10, "pdf_url": "https://example.invalid/990.pdf"}]}


@pytest.mark.usefixtures
class TestModuleIrsNonprofits(unittest.TestCase):

    def test_opts(self):
        self.assertEqual(len(sfp_irs_nonprofits().opts), len(sfp_irs_nonprofits().optdescs))

    def test_handle_event(self):
        events, calls = run(self, sfp_irs_nonprofits, "Acme Health Corp",
                            [("search.json", '200', SEARCH), ("organizations/43314093.json", '200', ORG)])
        self.assertEqual(2, len(calls))
        t = by_type(events)
        rec = json.loads(t["RAW_RIR_DATA"][0])
        self.assertEqual("501(c)(3)", rec['subsection'])
        self.assertEqual(2023, rec['filings'][0]['tax_year'])
        self.assertEqual(["1 MAIN ST, Boston, MA 02118"], t["PHYSICAL_ADDRESS"])
        self.assertEqual(["Karen G Fine"], t["HUMAN_NAME"])


if __name__ == '__main__':
    unittest.main()
