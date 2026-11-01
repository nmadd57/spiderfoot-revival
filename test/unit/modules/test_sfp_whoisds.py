import io
import unittest
import zipfile

from modules.sfp_whoisds import sfp_whoisds


class TestModuleWhoisds(unittest.TestCase):

    def test_opts(self):
        module = sfp_whoisds()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_events_are_lists(self):
        module = sfp_whoisds()
        self.assertIsInstance(module.watchedEvents(), list)
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta(self):
        meta = sfp_whoisds.meta
        self.assertIn(meta['pricing'], ('free', 'free_key', 'paid', 'local'))

    def test_feed_url(self):
        import datetime
        self.assertTrue(sfp_whoisds.feedUrl(datetime.date(2026, 10, 31)).endswith("MjAyNi0xMC0zMS56aXA=/nrd"))

    def test_parse_zip_and_lookalikes(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("domain-names.txt", "acme-login.com\nexample.org\nacme.com\n")
        domains = sfp_whoisds.parseZip(buf.getvalue())
        self.assertEqual(sfp_whoisds.lookalikes("acme", "acme.com", domains), ["acme-login.com"])
