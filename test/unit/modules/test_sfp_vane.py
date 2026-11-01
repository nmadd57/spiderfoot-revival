import json
import unittest

import pytest

from modules.sfp_vane import sfp_vane
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget

# Shaped after docs/API/SEARCH.md and src/app/api/{providers,search}/route.ts in ItzCrazyKns/Vane
PROVIDERS = {"providers": [
    {"id": "11111111-1111-1111-1111-111111111111", "name": "Ollama",
     "chatModels": [{"name": "Llama", "key": "llama3.1:8b"}, {"name": "Qwen", "key": "qwen3:14b"}],
     "embeddingModels": []},
    {"id": "22222222-2222-2222-2222-222222222222", "name": "Embeddings",
     "chatModels": [], "embeddingModels": [{"name": "Nomic", "key": "nomic-embed-text-v1.5"}]},
]}
ANSWER = {
    "message": "Acme Widgets is a manufacturer headquartered in Shelton, CT [1][2].",
    "sources": [
        {"content": "...", "metadata": {"title": "About Acme", "url": "https://acme.com/about"}},
        {"content": "...", "metadata": {"title": "News", "url": "https://news.example.org/acme"}},
        {"content": "...", "metadata": {"title": "Dup", "url": "https://news.example.org/acme"}},
        {"content": "...", "metadata": {"title": "No URL"}},
    ],
}


@pytest.mark.usefixtures
class TestModuleVane(unittest.TestCase):

    def test_opts(self):
        module = sfp_vane()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_pick(self):
        p = PROVIDERS['providers']
        self.assertEqual(("11111111-1111-1111-1111-111111111111", "llama3.1:8b"), sfp_vane._pick(p, 'chatModels', '', ''))
        self.assertEqual(("11111111-1111-1111-1111-111111111111", "qwen3:14b"),
                         sfp_vane._pick(p, 'chatModels', 'ollama', 'qwen3:14b'))
        self.assertEqual(("22222222-2222-2222-2222-222222222222", "nomic-embed-text-v1.5"),
                         sfp_vane._pick(p, 'embeddingModels', '', ''))
        self.assertIsNone(sfp_vane._pick(p, 'chatModels', 'ollama', 'missing'))
        self.assertIsNone(sfp_vane._pick(p, 'chatModels', 'nope', ''))

    def _run(self, routes, opts=None, module_name='SpiderFoot UI', target="acme.com", ttype="INTERNET_NAME",
             etype="COMPANY_NAME", value="Acme Widgets Inc"):
        sf = SpiderFoot(self.default_options)
        module = sfp_vane()
        module.setup(sf, {**self.default_options, 'instance_url': 'http://vane:3000/', **(opts or {})})
        module.setTarget(SpiderFootTarget(target, ttype))
        calls = []

        def fetch(url, **kwargs):
            calls.append((url, kwargs))
            for path, (code, body) in routes.items():
                if url.endswith(path):
                    return {'code': code, 'content': body if isinstance(body, str) else json.dumps(body), 'status': 'x'}
            return {'code': '404', 'content': '{}'}

        sf.fetchUrl = fetch
        events = []
        module.notifyListeners = events.append
        root = SpiderFootEvent('ROOT', target, '', '')
        module.handleEvent(SpiderFootEvent(etype, value, module_name, root))
        return module, events, calls

    def test_handle_event(self):
        module, events, calls = self._run({'/api/providers': ('200', PROVIDERS), '/api/search': ('200', ANSWER)},
                                          {'auth_header': 'Authorization: Bearer t'})
        self.assertEqual(["http://vane:3000/api/providers", "http://vane:3000/api/search"], [c[0] for c in calls])
        body = json.loads(calls[1][1]['postData'])
        self.assertEqual({'providerId': "11111111-1111-1111-1111-111111111111", 'key': "llama3.1:8b"}, body['chatModel'])
        self.assertEqual({'providerId': "22222222-2222-2222-2222-222222222222", 'key': "nomic-embed-text-v1.5"},
                         body['embeddingModel'])
        self.assertEqual(["web"], body['sources'])
        self.assertEqual("balanced", body['optimizationMode'])
        self.assertFalse(body['stream'])
        self.assertIn('"Acme Widgets Inc"', body['query'])
        self.assertEqual("Bearer t", calls[1][1]['headers']['Authorization'])

        types = [(e.eventType, e.data) for e in events]
        abstract = next(d for t, d in types if t == "DESCRIPTION_ABSTRACT")
        self.assertIn("LLM-generated", abstract)
        self.assertIn("[2] News https://news.example.org/acme", abstract)
        self.assertIn(("LINKED_URL_INTERNAL", "https://acme.com/about"), types)
        self.assertEqual(1, types.count(("LINKED_URL_EXTERNAL", "https://news.example.org/acme")))
        raw = json.loads(next(d for t, d in types if t == "RAW_RIR_DATA"))
        self.assertEqual(2, len(raw['sources']))

    def test_name_target_sources_are_external(self):
        _m, events, _c = self._run({'/api/providers': ('200', PROVIDERS), '/api/search': ('200', ANSWER)},
                                   target="Acme Widgets Inc", ttype="COMPANY_NAME")
        links = [(e.eventType, e.data) for e in events if e.eventType.startswith("LINKED_URL")]
        self.assertEqual([("LINKED_URL_EXTERNAL", "https://acme.com/about"),
                          ("LINKED_URL_EXTERNAL", "https://news.example.org/acme")], links)

    def test_only_scan_target_by_default(self):
        _m, events, calls = self._run({'/api/providers': ('200', PROVIDERS)}, module_name="sfp_company")
        self.assertEqual([], calls)
        _m, events, calls = self._run({'/api/providers': ('200', PROVIDERS), '/api/search': ('200', ANSWER)},
                                      {'target_only': False}, module_name="sfp_company")
        self.assertEqual(2, len(calls))

    def test_missing_model_reports_available(self):
        module, events, calls = self._run({'/api/providers': ('200', PROVIDERS)}, {'chat_model': 'gpt-5'})
        self.assertTrue(module.errorState)
        self.assertEqual(1, len(calls))
        self.assertEqual([], events)

    def test_search_error(self):
        module, events, _calls = self._run({'/api/providers': ('200', PROVIDERS),
                                            '/api/search': ('500', {"message": "Search error"})})
        self.assertEqual([], events)

    def test_unreachable(self):
        module, events, calls = self._run({'/api/providers': ('None', None)})
        self.assertTrue(module.errorState)


if __name__ == '__main__':
    unittest.main()
