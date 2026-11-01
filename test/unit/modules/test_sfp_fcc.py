import json
import unittest

import pytest

from modules.sfp_fcc import sfp_fcc
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget

FORM499 = """<?xml version="1.0" encoding="ISO-8859-1"?>
<Filer499QueryResults RecordCount="3">
  <Filer>
    <Form_499_ID>801003</Form_499_ID>
    <Filer_ID_Info>
      <Legal_Name>Otelco Telephone LLC</Legal_Name>
      <doing_business_as>Otelco Telephone LLC</doing_business_as>
      <holding_company>OTELCO INC</holding_company>
      <FRN>0018538512</FRN>
      <hq_address><address_line>505 Third Avenue East</address_line><city>Oneonta</city>
        <state>AL</state><zip_code>35121</zip_code></hq_address>
      <Customer_Inquiries_telephone>2056253591</Customer_Inquiries_telephone>
    </Filer_ID_Info>
    <Agent_for_Service_Of_Process>
      <dc_agent_email>STATREP@COGENCYGLOBAL.COM</dc_agent_email>
      <alternate_agent_email>reg@otelco.example</alternate_agent_email>
    </Agent_for_Service_Of_Process>
    <FCC_Registration_information>
      <Chief_Executive_Officer>Richard Clark</Chief_Executive_Officer>
      <Chairman_or_Senior_Officer>Contact Contact</Chairman_or_Senior_Officer>
    </FCC_Registration_information>
    <jurisdiction_state>maine</jurisdiction_state>
  </Filer>
  <Filer>
    <Form_499_ID>900001</Form_499_ID>
    <Filer_ID_Info>
      <Legal_Name>Otelco Mid-Missouri LLC</Legal_Name>
      <holding_company>Otelco Telephone LLC</holding_company>
    </Filer_ID_Info>
  </Filer>
  <Filer>
    <Form_499_ID>900002</Form_499_ID>
    <Filer_ID_Info>
      <Legal_Name>Some Reseller Inc</Legal_Name>
      <doing_business_as>Otelco Telephone</doing_business_as>
    </Filer_ID_Info>
  </Filer>
</Filer499QueryResults>"""

GRANTEES = [{"grantee_code": "ZZZ", "grantee_name": "OTELCO TELEPHONE, LLC", "mailing_address": "1 Main St",
             "city": "Oneonta", "state": "Alabama", "zip_code": "35121", "country": "United States",
             "contact_name": "Jane Doe"}]
ECFS = {"filing": [
    {"id_submission": "1", "date_disseminated": "2026-10-01T00:00:00Z", "submissiontype": {"description": "COMMENT"},
     "proceedings": [{"name": "17-97", "description_display": "Call Authentication"}],
     "filers": [{"name": "Otelco Telephone LLC"}], "authors": [{"name": "A Lawyer"}]},
    {"id_submission": "2", "filers": [{"name": "Unrelated Corp"}]},
]}


@pytest.mark.usefixtures
class TestModuleFcc(unittest.TestCase):

    def test_opts(self):
        module = sfp_fcc()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_handle_event(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_fcc()
        module.setup(sf, dict(self.default_options))
        module.setTarget(SpiderFootTarget("Otelco Telephone LLC", 'COMPANY_NAME'))
        urls = []

        def fetch(url, **kwargs):
            urls.append(url)
            if "form499" in url:
                return {'code': '200', 'content': FORM499}
            if "3b3k-34jp" in url:
                return {'code': '200', 'content': json.dumps(GRANTEES)}
            if "a6ec-cry4" in url:
                return {'code': '200', 'content': "[]"}
            if "ecfs" in url:
                return {'code': '200', 'content': json.dumps(ECFS)}
            return {'code': '404', 'content': None}

        sf.fetchUrl = fetch
        events = []
        module.notifyListeners = events.append
        root = SpiderFootEvent('ROOT', "Otelco Telephone LLC", '', '')
        module.handleEvent(SpiderFootEvent('COMPANY_NAME', "Otelco Telephone LLC", 'SpiderFoot UI', root))

        self.assertEqual(4, len(urls))
        self.assertIn("LegalName=OTELCO+TELEPHONE", urls[0])
        self.assertIn("api_key=DEMO_KEY", urls[3])

        raw = [json.loads(e.data) for e in events if e.eventType == "RAW_RIR_DATA"]
        sources = [r['source'] for r in raw]
        self.assertEqual(1, sources.count("FCC Form 499 Filer Database"))  # DBA-only match ignored
        self.assertIn("FCC equipment authorization grantee", sources)
        ecfs = next(r for r in raw if r['source'] == "FCC ECFS filings")
        self.assertEqual(["1"], [f['id'] for f in ecfs['filings']])

        by_type = {}
        for e in events:
            by_type.setdefault(e.eventType, set()).add(e.data)
        self.assertEqual({"Otelco Mid-Missouri LLC"}, by_type["AFFILIATE_COMPANY_NAME"])
        self.assertEqual({"Richard Clark", "Jane Doe"}, by_type["HUMAN_NAME"])
        self.assertEqual({"reg@otelco.example"}, by_type["EMAILADDR"])
        self.assertEqual({"+12056253591"}, by_type["PHONE_NUMBER"])
        self.assertIn("505 Third Avenue East, Oneonta, AL 35121", by_type["PHYSICAL_ADDRESS"])


if __name__ == '__main__':
    unittest.main()
