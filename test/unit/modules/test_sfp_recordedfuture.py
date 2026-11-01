import unittest

from modules.sfp_recordedfuture import sfp_recordedfuture


class TestModuleRecordedfuture(unittest.TestCase):

    def test_opts(self):
        module = sfp_recordedfuture()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_events(self):
        module = sfp_recordedfuture()
        self.assertEqual(set(module.watchedEvents()), set(sfp_recordedfuture.EVENT_MAP))
        for _kind, produced in sfp_recordedfuture.EVENT_MAP.values():
            self.assertIn(produced, module.producedEvents())

    def test_parse_risk(self):
        data = {"data": {"risk": {"score": 89, "criticalityLabel": "Very Malicious",
                                  "evidenceDetails": [{"rule": "Recent C&C", "evidenceString": "1 sighting"}]}}}
        r = sfp_recordedfuture.parseRisk(data)
        self.assertEqual((r['score'], r['label']), (89, "Very Malicious"))
        self.assertEqual(r['evidence'], ["Recent C&C: 1 sighting"])

    def test_parse_risk_empty(self):
        self.assertEqual(sfp_recordedfuture.parseRisk(None)['score'], 0)
