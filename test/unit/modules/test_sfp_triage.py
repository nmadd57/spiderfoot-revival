import unittest

from modules.sfp_triage import sfp_triage


class TestModuleTriage(unittest.TestCase):

    def test_opts(self):
        module = sfp_triage()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_events(self):
        module = sfp_triage()
        self.assertEqual(set(module.watchedEvents()), set(sfp_triage.EVENT_MAP))
        for _field, produced in sfp_triage.EVENT_MAP.values():
            self.assertIn(produced, module.producedEvents())

    def test_parsers(self):
        self.assertEqual(sfp_triage.sampleIds({"data": [{"id": "260101-abc"}, {"x": 1}]}), ["260101-abc"])
        self.assertEqual(sfp_triage.sampleIds(None), [])
        self.assertEqual(sfp_triage.sampleScore({"score": 9}), 9)
        self.assertEqual(sfp_triage.sampleScore(None), 0)
