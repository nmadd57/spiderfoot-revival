import shutil
import tempfile
import unittest

from spiderfoot.services import tools


class TestTools(unittest.TestCase):
    def test_missing_tool_without_path(self):
        self.assertFalse(tools.tool_installed('sfp_tool_nmap', {'nmappath': ''}, {}))

    def test_configured_path_must_exist(self):
        with tempfile.TemporaryDirectory() as d:
            exe = f'{d}/whatweb'
            open(exe, 'w').close()
            opts = {'whatweb_path': '', 'ruby_path': '/usr/bin/ruby'}
            self.assertTrue(tools.tool_installed('sfp_tool_whatweb', opts, {'sfp_tool_whatweb:whatweb_path': exe}))
            self.assertFalse(tools.tool_installed('sfp_tool_whatweb', opts, {'sfp_tool_whatweb:whatweb_path': f'{d}/nope'}))

    def test_dir_path_and_path_lookup(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(tools.tool_installed('sfp_tool_nuclei', {'nuclei_path': d + '/'}, {}))
        self.assertEqual(tools.tool_installed('sfp_tool_bbot_enum', {'bbot_path': ''}, {}), bool(shutil.which('bbot')))

    def test_no_path_option_assumed_ok(self):
        self.assertTrue(tools.tool_installed('sfp_tool_x', {'foo': 1}, {}))
