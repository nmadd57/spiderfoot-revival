import os
import stat
import tempfile
import unittest
from unittest import mock

from sflib import SpiderFoot
from spiderfoot import SpiderFootHelpers
from spiderfoot.services import ai_service, module_test as mt


class TestSamples(unittest.TestCase):
    def test_prefers_domain_then_ip(self):
        self.assertEqual(mt.pick_sample(['IP_ADDRESS', 'DOMAIN_NAME'])[:2], ('DOMAIN_NAME', 'example.com'))
        self.assertEqual(mt.pick_sample(['IP_ADDRESS'])[:2], ('IP_ADDRESS', '8.8.8.8'))

    def test_no_sample(self):
        self.assertIsNone(mt.pick_sample(['TARGET_WEB_CONTENT']))

    def test_user_target(self):
        self.assertEqual(mt.pick_sample(['IP_ADDRESS'], '1.2.3.4'), ('IP_ADDRESS', '1.2.3.4', 'IP_ADDRESS', '1.2.3.4'))
        self.assertEqual(mt.pick_sample(['DOMAIN_NAME'], 'foo.org')[0], 'DOMAIN_NAME')
        self.assertEqual(mt.pick_sample(['INTERNET_NAME'], 'a.b.foo.org')[0], 'INTERNET_NAME')
        self.assertIsNone(mt.pick_sample(['IP_ADDRESS'], 'foo.org'))
        self.assertIsNone(mt.pick_sample(['IP_ADDRESS'], '???'))

    def test_places(self):
        self.assertEqual(mt.pick_sample(['PHYSICAL_ADDRESS', 'PHYSICAL_COORDINATES'])[0], 'PHYSICAL_ADDRESS')
        self.assertEqual(mt.pick_sample(['PHYSICAL_COORDINATES'], '48.85, 2.29')[:2], ('PHYSICAL_COORDINATES', '48.85, 2.29'))
        self.assertEqual(mt.pick_sample(['PHYSICAL_ADDRESS'], '1 Main Street, Springfield')[0], 'PHYSICAL_ADDRESS')
        self.assertIsNone(mt.pick_sample(['IP_ADDRESS'], '1 Main Street, Springfield'))

    def test_redaction_drops_query(self):
        r = mt._redact('https://api.example.com/v1/x?key=SECRET&q=1')
        self.assertEqual(r, {'host': 'api.example.com', 'path': '/v1/x'})


class TestRunModule(unittest.TestCase):
    def config(self, *names):
        mods = SpiderFootHelpers.loadModulesAsDict('modules', ['sfp_template.py'])
        cfg = dict(self.default_options)
        cfg['__modules__'] = {n: mods[n] for n in names}
        return cfg

    def test_skip_without_key(self):
        res = mt.run_module('sfp_shodan', self.config('sfp_shodan'), SpiderFoot)
        self.assertEqual(res['status'], 'skip')
        self.assertIn('API key', res['summary'])

    def test_invasive_needs_a_target(self):
        res = mt.run_module('sfp_portscan_tcp', self.config('sfp_portscan_tcp'), SpiderFoot)
        self.assertEqual(res['status'], 'skip')
        self.assertIn('invasive', res['summary'])

    def test_unknown_module(self):
        self.assertEqual(mt.run_module('sfp_nope', self.config(), SpiderFoot)['status'], 'skip')

    def test_running_a_test_does_not_touch_the_module_options(self):
        import modules.sfp_countryname as m
        before = dict(m.sfp_countryname.opts)
        mt.run_module('sfp_countryname', self.config('sfp_countryname'), SpiderFoot, target='+14155550100')
        self.assertEqual(before, m.sfp_countryname.opts)

    def test_offline_module_produces_events(self):
        res = mt.run_module('sfp_countryname', self.config('sfp_countryname'), SpiderFoot, target='+14155550100')
        self.assertEqual(res['status'], 'pass', res)
        self.assertTrue(any(e['type'] == 'COUNTRY_NAME' for e in res['events']))
        self.assertEqual(res['errors'], [])

    def test_non_key_message_is_a_note_not_a_failure(self):
        def noisy(self_, event):
            self_.error("No information available for that IP")

        with mock.patch('modules.sfp_countryname.sfp_countryname.handleEvent', noisy):
            res = mt.run_module('sfp_countryname', self.config('sfp_countryname'), SpiderFoot, target='+14155550100')
        self.assertEqual(res['status'], 'warn')
        self.assertEqual(res['errors'], [])
        self.assertIn('No information available for that IP', res['notes'])
        self.assertIsNone(res['keyProblem'])

    def test_exception_fails(self):
        def boom(self_, event):
            raise RuntimeError("kaput")

        with mock.patch('modules.sfp_countryname.sfp_countryname.handleEvent', boom):
            res = mt.run_module('sfp_countryname', self.config('sfp_countryname'), SpiderFoot, target='+14155550100')
        self.assertEqual(res['status'], 'fail')
        self.assertIn('RuntimeError', res['summary'])
        self.assertNotIn('kaput', res['summary'])
        self.assertNotIn('kaput', ' '.join(res['errors']))

    def test_key_problem_message_is_classified(self):
        def boom(self_, event):
            self_.error("Zero Account Balance")

        with mock.patch('modules.sfp_countryname.sfp_countryname.handleEvent', boom):
            res = mt.run_module('sfp_countryname', self.config('sfp_countryname'), SpiderFoot, target='+14155550100')
        self.assertEqual(res['keyProblem']['kind'], 'quota')


class TestTool(unittest.TestCase):
    def test_not_installed(self):
        self.assertEqual(mt.test_tool('sfp_tool_nmap', {'nmappath': ''}, {})['status'], 'fail')

    def test_installed_runs_version(self):
        with tempfile.TemporaryDirectory() as d:
            exe = os.path.join(d, 'nmap')
            with open(exe, 'w') as f:
                f.write('#!/bin/sh\necho "Nmap version 9.99"\n')
            os.chmod(exe, os.stat(exe).st_mode | stat.S_IEXEC)
            res = mt.test_tool('sfp_tool_nmap', {'nmappath': d + '/'}, {})
            self.assertEqual(res['status'], 'pass', res)
            self.assertEqual(res['events'][0]['data'], 'Nmap version 9.99')


class TestAi(unittest.TestCase):
    def test_models_url(self):
        self.assertEqual(ai_service._models_url(''), 'https://openrouter.ai/api/v1/models')
        self.assertEqual(ai_service._models_url('http://h:11434/v1'), 'http://h:11434/v1/models')
        self.assertEqual(ai_service._models_url('http://h/v1/chat/completions'), 'http://h/v1/models')

    def test_parse_models(self):
        self.assertEqual([m['id'] for m in ai_service.parse_models({'data': [{'id': 'b'}, {'id': 'a'}, {'id': 'a'}]})], ['a', 'b'])
        self.assertEqual([m['id'] for m in ai_service.parse_models({'models': [{'name': 'llama3'}, {'model': 'qwen'}]})], ['llama3', 'qwen'])
        self.assertEqual([m['id'] for m in ai_service.parse_models(['x', 'y'])], ['x', 'y'])
        self.assertEqual(ai_service.parse_models({}), [])

    def _resp(self, code, payload=None):
        r = mock.Mock(status_code=code)
        r.json.return_value = payload
        return r

    def test_connection_lists_models_and_chats(self):
        with mock.patch('requests.get', return_value=self._resp(200, {'data': [{'id': 'm1'}, {'id': 'm2'}]})) as g, \
                mock.patch('requests.post', return_value=self._resp(200, {})) as p:
            out = ai_service.test_connection('http://llm:8080/v1', 'secret-key', 'm1')
        self.assertTrue(out['ok'])
        self.assertEqual(out['modelCount'], 2)
        self.assertTrue(out['chat']['ok'] and out['chat']['known'])
        self.assertEqual(g.call_args[0][0], 'http://llm:8080/v1/models')
        self.assertEqual(p.call_args[0][0], 'http://llm:8080/v1/chat/completions')
        self.assertNotIn('secret-key', str(out))

    def test_rejected_key_and_unreachable(self):
        with mock.patch('requests.get', return_value=self._resp(401)):
            out = ai_service.test_connection('http://llm/v1', 'k')
        self.assertFalse(out['ok'])
        self.assertIn('rejected', out['message'])
        import requests
        with mock.patch('requests.get', side_effect=requests.exceptions.ConnectionError('x')):
            self.assertFalse(ai_service.test_connection('http://llm/v1', '')['ok'])

    def test_unknown_model_hint(self):
        with mock.patch('requests.get', return_value=self._resp(200, {'data': [{'id': 'm1'}]})), \
                mock.patch('requests.post', return_value=self._resp(404)):
            out = ai_service.test_connection('http://llm/v1', '', 'ghost')
        self.assertFalse(out['chat']['ok'])
        self.assertIn('not in the model list', out['chat']['message'])
