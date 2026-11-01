import unittest

from modules.sfp_rapiddns import sfp_rapiddns


class TestModuleRapiddns(unittest.TestCase):

    def test_opts(self):
        module = sfp_rapiddns()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_events_are_lists(self):
        module = sfp_rapiddns()
        self.assertIsInstance(module.watchedEvents(), list)
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta(self):
        meta = sfp_rapiddns.meta
        self.assertIn(meta['pricing'], ('free', 'free_key', 'paid', 'local'))

    def test_parse_hosts(self):
        html = "<td>a.example.com</td><td>evil.org</td><td>example.com</td><td>x.y.example.com</td>"
        self.assertEqual(sfp_rapiddns.parseHosts(html, "example.com"),
                         {"a.example.com", "example.com", "x.y.example.com"})
