import unittest

from sflib import SpiderFoot


class TestToolPathLoad(unittest.TestCase):
    def ref(self):
        return {'__modules__': {
            'sfp_tool_nmap': {'opts': {'nmappath': '/usr/bin/', 'timeout': 5}},
            'sfp_other': {'opts': {'somepath': '/x'}}}}

    def load(self, saved):
        return SpiderFoot({'__database': ':memory:'}).configUnserialize(saved, self.ref())['__modules__']

    def test_blank_saved_path_keeps_default(self):
        m = self.load({'sfp_tool_nmap:nmappath': ''})
        self.assertEqual(m['sfp_tool_nmap']['opts']['nmappath'], '/usr/bin/')

    def test_real_saved_path_wins(self):
        m = self.load({'sfp_tool_nmap:nmappath': '/opt/nmap/'})
        self.assertEqual(m['sfp_tool_nmap']['opts']['nmappath'], '/opt/nmap/')

    def test_other_modules_unaffected(self):
        m = self.load({'sfp_other:somepath': ''})
        self.assertEqual(m['sfp_other']['opts']['somepath'], '')
