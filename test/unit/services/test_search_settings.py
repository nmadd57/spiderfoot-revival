import json
import unittest
from unittest import mock

import requests

from sflib import SpiderFoot
from spiderfoot.services import embeddings, searxng


def page(urls, unresponsive=()):
    return {'code': '200', 'content': json.dumps({'results': [{'url': u, 'title': 't', 'content': 'c'} for u in urls],
                                                 'unresponsive_engines': [list(e) for e in unresponsive]})}


class TestSearxngInstanceTest(unittest.TestCase):
    def sf(self):
        return SpiderFoot(dict(self.default_options))

    def run_test(self, reply, **values):
        sf = self.sf()
        with mock.patch.object(sf, 'fetchUrl', return_value=reply) as f:
            out = searxng.test_instance(sf, {'instance_url': 'http://searx:8080', **values})
        return out, f

    def test_success_lists_results_and_blocked_engines(self):
        out, f = self.run_test(page(['https://a/1', 'https://a/2', 'https://a/3', 'https://a/4'],
                                    [('google', 'access denied'), ('duckduckgo', 'CAPTCHA')]))
        self.assertTrue(out['ok'])
        self.assertEqual(out['count'], 4)
        self.assertEqual(out['urls'], ['https://a/1', 'https://a/2', 'https://a/3'])
        self.assertEqual(out['unresponsive'], ['google (access denied)', 'duckduckgo (CAPTCHA)'])
        self.assertIn('searx:8080/search', f.call_args[0][0])
        self.assertIn('format=json', f.call_args[0][0])

    def test_uses_the_unsaved_values_and_auth_header(self):
        out, f = self.run_test(page(['https://a/1']), auth_header='X-Key: abc', engines='bing', verify_ssl=False)
        self.assertEqual(f.call_args[1]['headers']['X-Key'], 'abc')
        self.assertFalse(f.call_args[1]['verify'])
        self.assertIn('engines=bing', f.call_args[0][0])

    def test_empty_results_are_a_warning_not_a_failure_to_connect(self):
        out, _ = self.run_test(page([], [('google', 'access denied')]))
        self.assertFalse(out['ok'])
        self.assertIn('JSON works', out['message'])
        self.assertEqual(out['unresponsive'], ['google (access denied)'])

    def test_problems_are_explained(self):
        sso = '<html>Sign in with PocketID <a href="/oauth2/start">x</a></html>'
        out, _ = self.run_test({'code': '403', 'content': sso})
        self.assertIn('sign-in page', out['message'])
        out, _ = self.run_test({'code': '403', 'content': '<h1>no</h1>'})
        self.assertIn('JSON output is disabled', out['message'])
        out, _ = self.run_test({'code': 'None', 'content': None, 'status': 'refused'})
        self.assertIn('Could not reach', out['message'])

    def test_needs_a_url_and_adds_a_scheme(self):
        sf = self.sf()
        self.assertFalse(searxng.test_instance(sf, {'instance_url': ' '})['ok'])
        with mock.patch.object(sf, 'fetchUrl', return_value=page(['https://a/1'])) as f:
            searxng.test_instance(sf, {'instance_url': 'searx:8080/'})
        self.assertTrue(f.call_args[0][0].startswith('http://searx:8080/search?'))

    def test_a_test_never_touches_the_saved_configuration(self):
        sf = self.sf()
        sf.opts['__modules__'] = {'sfp_searxng': {'opts': {'instance_url': 'http://saved:1'}}}
        with mock.patch.object(sf, 'fetchUrl', return_value=page(['https://a/1'])):
            searxng.test_instance(sf, {'instance_url': 'http://other:2'})
        self.assertEqual(searxng.config(sf)['instance_url'], 'http://saved:1')


class Resp:
    def __init__(self, code, payload=None):
        self.status_code = code
        self._p = payload

    def json(self):
        if self._p is None:
            raise ValueError('no json')
        return self._p


class TestEmbeddings(unittest.TestCase):
    def test_urls(self):
        self.assertEqual(embeddings.endpoint('llm:8080/v1/'), 'http://llm:8080/v1/embeddings')
        self.assertEqual(embeddings.endpoint('http://llm/v1/embeddings'), 'http://llm/v1/embeddings')
        self.assertEqual(embeddings.models_url('http://llm/v1/embeddings'), 'http://llm/v1/models')
        self.assertEqual(embeddings.endpoint(''), '')

    def test_success_with_models(self):
        with mock.patch('requests.get', return_value=Resp(200, {'data': [{'id': 'nomic'}, {'id': 'bge'}]})) as g, \
                mock.patch('requests.post', return_value=Resp(200, {'data': [{'index': 0, 'embedding': [0.1] * 768}]})) as p:
            out = embeddings.test_connection('http://llm/v1', 'secret', 'nomic')
        self.assertTrue(out['ok'])
        self.assertEqual(out['dimensions'], 768)
        self.assertEqual([m['id'] for m in out['models']], ['bge', 'nomic'])
        self.assertEqual(p.call_args[1]['json'], {'input': ['SpiderFoot embeddings test'], 'model': 'nomic'})
        self.assertEqual(p.call_args[1]['headers']['Authorization'], 'Bearer secret')
        self.assertEqual(g.call_args[0][0], 'http://llm/v1/models')
        self.assertNotIn('secret', str(out))

    def test_works_without_a_model_list(self):
        with mock.patch('requests.get', return_value=Resp(404)), \
                mock.patch('requests.post', return_value=Resp(200, {'data': [{'embedding': [1, 2, 3]}]})):
            out = embeddings.test_connection('http://llm/v1')
        self.assertTrue(out['ok'] and out['models'] == [])

    def test_failures(self):
        with mock.patch('requests.get', return_value=Resp(200, {'data': [{'id': 'nomic'}]})):
            with mock.patch('requests.post', return_value=Resp(401)):
                self.assertIn('rejected the API key', embeddings.test_connection('http://llm/v1', 'k')['message'])
            with mock.patch('requests.post', return_value=Resp(404)):
                self.assertIn('not in its model list', embeddings.test_connection('http://llm/v1', '', 'ghost')['message'])
            with mock.patch('requests.post', return_value=Resp(200, {'oops': 1})):
                self.assertIn('did not return an embedding', embeddings.test_connection('http://llm/v1')['message'])
        with mock.patch('requests.get', side_effect=requests.exceptions.ConnectionError()), \
                mock.patch('requests.post', side_effect=requests.exceptions.ConnectionError()):
            self.assertIn('Could not reach', embeddings.test_connection('http://llm/v1')['message'])
        self.assertIn('Enter the embeddings endpoint URL', embeddings.test_connection('')['message'])
