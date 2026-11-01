import unittest

from modules.sfp_crt_org import sfp_crt_org


class TestModuleCrtOrg(unittest.TestCase):

    def test_opts(self):
        module = sfp_crt_org()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_events_are_lists(self):
        module = sfp_crt_org()
        self.assertIsInstance(module.watchedEvents(), list)
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta(self):
        meta = sfp_crt_org.meta
        self.assertIn(meta['pricing'], ('free', 'free_key', 'paid', 'local'))

    def test_extract_names(self):
        data = [{"name_value": "a.example.com\n*.example.com\nme@example.com"}, {"name_value": "Bad Name"}]
        self.assertEqual(sfp_crt_org.extractNames(data), {"a.example.com", "example.com"})
