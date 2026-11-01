import unittest

from modules.sfp_firehol import sfp_firehol


class TestModuleFirehol(unittest.TestCase):

    def test_opts(self):
        module = sfp_firehol()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_events_are_lists(self):
        module = sfp_firehol()
        self.assertIsInstance(module.watchedEvents(), list)
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta(self):
        meta = sfp_firehol.meta
        self.assertIn(meta['pricing'], ('free', 'free_key', 'paid', 'local'))

    def test_parse_and_match(self):
        s = sfp_firehol.parseList("# c\n1.2.3.0/24\nnot-an-ip\n5.6.7.8\n")
        from netaddr import IPAddress
        self.assertIn(IPAddress("1.2.3.9"), s)
        self.assertIn(IPAddress("5.6.7.8"), s)
        self.assertNotIn(IPAddress("9.9.9.9"), s)
