import unittest

from modules.sfp_chainabuse import sfp_chainabuse


class TestModuleChainabuse(unittest.TestCase):

    def test_opts(self):
        module = sfp_chainabuse()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_events_are_lists(self):
        module = sfp_chainabuse()
        self.assertIsInstance(module.watchedEvents(), list)
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta(self):
        meta = sfp_chainabuse.meta
        self.assertIn(meta['pricing'], ('free', 'free_key', 'paid', 'local'))

    def test_report_list(self):
        self.assertEqual(sfp_chainabuse.reportList([{"a": 1}]), [{"a": 1}])
        self.assertEqual(sfp_chainabuse.reportList({"reports": [1, 2]}), [1, 2])
        self.assertEqual(sfp_chainabuse.reportList(None), [])
