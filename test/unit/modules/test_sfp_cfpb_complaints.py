import json
import unittest

import pytest

from modules.sfp_cfpb_complaints import sfp_cfpb_complaints
from test.unit.modules._fedtest import by_type, run

COMPANIES = {"hits": {"total": {"value": 3}}, "aggregations": {"company": {"company": {"buckets": [
    {"key": "ACME BANK, N.A. HOLDINGS", "doc_count": 1}, {"key": "ACME BANK INC.", "doc_count": 2}]}}}}
DETAIL = {
    "hits": {"total": {"value": 2}, "hits": [{"_source": {
        "complaint_id": "9", "date_received": "2026-10-01T00:00:00Z", "product": "Mortgage",
        "issue": "Servicing", "state": "MA", "company_response": "Closed with explanation"}}]},
    "aggregations": {
        "product": {"product": {"buckets": [{"key": "Mortgage", "doc_count": 2}]}},
        "timely": {"timely": {"buckets": [{"key": "Yes", "doc_count": 3}, {"key": "No", "doc_count": 1}]}},
    },
}


@pytest.mark.usefixtures
class TestModuleCfpbComplaints(unittest.TestCase):

    def test_opts(self):
        self.assertEqual(len(sfp_cfpb_complaints().opts), len(sfp_cfpb_complaints().optdescs))

    def test_handle_event(self):
        events, calls = run(self, sfp_cfpb_complaints, "Acme Bank, Inc.",
                            [("search_term=", '200', COMPANIES), ("company=", '200', DETAIL)])
        self.assertEqual(2, len(calls))
        self.assertIn("company=ACME+BANK+INC.", calls[1][0])
        rec = json.loads(by_type(events)["RAW_RIR_DATA"][0])
        self.assertEqual(2, rec['total_complaints'])
        self.assertEqual(75.0, rec['timely_response_rate'])
        self.assertEqual([["Mortgage", 2]], rec['top_products'])
        self.assertEqual("9", rec['recent'][0]['url'].rsplit("/", 1)[-1])


if __name__ == '__main__':
    unittest.main()
