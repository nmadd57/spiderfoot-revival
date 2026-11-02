import sqlite3
import tempfile
import time
import unittest

from spiderfoot.services import module_options as mo
from spiderfoot.services import module_status as ms


class TestFields(unittest.TestCase):
    CFG = {
        'opts': {'api_key': '', 'maxpages': 3, 'verify': True, 'ratio': 0.5, 'exts': ['a', 'b'],
                 'nmappath': '', 'host': 'x', '_internal': 1},
        'optdescs': {'api_key': 'The API key', 'maxpages': 'Pages'},
        'meta': {'connectionOpts': ['host']},
    }

    def fields(self, name, saved=None):
        return {f['opt']: f for f in mo.build_fields(name, self.CFG, saved or {})}

    def test_internal_options_hidden(self):
        self.assertNotIn('_internal', self.fields('sfp_x'))

    def test_secret_masked_and_never_leaked(self):
        f = self.fields('sfp_x', {'sfp_x:api_key': 'super-secret-value'})['api_key']
        self.assertEqual(f['value'], mo.MASK)
        self.assertNotIn('super-secret-value', str(f))
        self.assertEqual(self.fields('sfp_x')['api_key']['value'], '')

    def test_kinds_and_values(self):
        f = self.fields('sfp_x')
        self.assertEqual((f['verify']['kind'], f['verify']['value']), ('bool', '1'))
        self.assertEqual((f['maxpages']['kind'], f['maxpages']['value']), ('number', '3'))
        self.assertEqual(f['ratio']['kind'], 'number')
        self.assertEqual((f['exts']['kind'], f['exts']['value']), ('list', 'a,b'))
        self.assertEqual(f['maxpages']['label'], 'Pages')

    def test_saved_value_overrides_default(self):
        self.assertEqual(self.fields('sfp_x', {'sfp_x:maxpages': 9})['maxpages']['value'], '9')

    def test_groups_and_order(self):
        fl = mo.build_fields('sfp_tool_nmap', self.CFG, {})
        groups = {f['opt']: f['group'] for f in fl}
        self.assertEqual(groups['api_key'], 'credentials')
        self.assertEqual(groups['host'], 'credentials')
        self.assertEqual(groups['nmappath'], 'tool')
        self.assertEqual(groups['maxpages'], 'options')
        self.assertEqual([f['group'] for f in fl], sorted([f['group'] for f in fl], key=['credentials', 'tool', 'options'].index))
        # non-tool modules never get a "tool" group
        self.assertEqual(self.fields('sfp_x')['nmappath']['group'], 'options')

    def test_no_options(self):
        self.assertEqual(mo.build_fields('sfp_y', {'opts': {'_x': 1}}, {}), [])


class TestConnectionOptions(unittest.TestCase):
    def test_self_hosted_service(self):
        cfg = {'opts': {'instance_url': 'http://s', 'auth_header': 'Authorization: Bearer abc123', 'verify_ssl': True, 'pages': 2},
               'meta': {'connectionOpts': ['instance_url', 'auth_header', 'verify_ssl']}}
        f = {x['opt']: x for x in mo.build_fields('sfp_s', cfg, {})}
        self.assertEqual((f['instance_url']['kind'], f['instance_url']['value'], f['instance_url']['group']), ('text', 'http://s', 'credentials'))
        self.assertEqual((f['auth_header']['kind'], f['auth_header']['value']), ('secret', mo.MASK))
        self.assertNotIn('abc123', str(f))
        self.assertEqual((f['verify_ssl']['kind'], f['verify_ssl']['value']), ('bool', '1'))
        self.assertEqual(f['pages']['group'], 'options')


class TestStatus(unittest.TestCase):
    def test_scan_stats(self):
        with tempfile.NamedTemporaryFile(suffix='.db') as t:
            c = sqlite3.connect(t.name)
            c.execute("CREATE TABLE tbl_scan_log (scan_instance_id TEXT, generated INT, component TEXT, type TEXT, message TEXT)")
            c.execute("CREATE TABLE tbl_scan_results (module TEXT, generated INT)")
            now = int(time.time() * 1000)
            old = now - 30 * 86400 * 1000
            c.executemany("INSERT INTO tbl_scan_log VALUES ('s',?,?,?,?)", [
                (old, 'sfp_a', 'ERROR', 'old failure'), (now - 5000, 'sfp_a', 'ERROR', 'latest failure'),
                (now, 'sfp_a', 'INFO', 'fine')])
            c.executemany("INSERT INTO tbl_scan_results VALUES (?,?)", [('sfp_a', now - 9000), ('sfp_b', now)])
            c.commit()
            c.close()
            s = ms.scan_stats(t.name, now=time.time() + 100)
            self.assertEqual((s['sfp_a']['errors'], s['sfp_a']['errors7d']), (2, 1))
            self.assertEqual(s['sfp_a']['lastError'], 'latest failure')
            self.assertEqual(s['sfp_a']['events'], 1)
            self.assertEqual(s['sfp_b']['events'], 1)
            self.assertNotIn('lastError', s['sfp_b'])

    def test_missing_db_is_empty(self):
        self.assertEqual(ms.scan_stats('/nonexistent/x.db', now=time.time() + 1000), {})


class TestToolPathDefaults(unittest.TestCase):
    def test_empty_saved_path_uses_default(self):
        cfg = {'opts': {'nmappath': '/usr/bin/'}, 'optdescs': {}}
        f = mo.build_fields('sfp_tool_nmap', cfg, {'sfp_tool_nmap:nmappath': ''})[0]
        self.assertEqual(f['value'], '/usr/bin/')
        f = mo.build_fields('sfp_tool_nmap', cfg, {'sfp_tool_nmap:nmappath': '/opt/nmap/'})[0]
        self.assertEqual(f['value'], '/opt/nmap/')
