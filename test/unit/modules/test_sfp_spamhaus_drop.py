import unittest

from modules.sfp_spamhaus_drop import sfp_spamhaus_drop


class TestModuleSpamhausDrop(unittest.TestCase):

    def test_opts(self):
        module = sfp_spamhaus_drop()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_events_are_lists(self):
        module = sfp_spamhaus_drop()
        self.assertIsInstance(module.watchedEvents(), list)
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta(self):
        meta = sfp_spamhaus_drop.meta
        self.assertIn(meta['pricing'], ('free', 'free_key', 'paid', 'local'))

    def test_parse_and_match(self):
        s = sfp_spamhaus_drop.parseList('{"cidr":"1.10.16.0/20","sblid":"SBL1"}\n{"type":"metadata"}\n')
        from netaddr import IPAddress
        self.assertIn(IPAddress("1.10.20.1"), s)
        self.assertNotIn(IPAddress("1.11.0.1"), s)
