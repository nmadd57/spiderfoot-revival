import json
import unittest
import urllib.parse

import pytest

from modules.sfp_searxng import parse_header, sfp_searxng
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


def _page(*urls, unresponsive=None):
    """A SearXNG /search?format=json body (see searx/webutils.py:get_json_response)."""
    return {
        'query': 'q', 'answers': [], 'corrections': [], 'infoboxes': [], 'suggestions': [],
        'unresponsive_engines': unresponsive or [],
        'results': [{'url': u, 'title': f"t{i}", 'content': f"c{i}", 'engine': "duckduckgo",
                     'engines': ["duckduckgo", "brave"], 'score': 1.0, 'category': "general",
                     'publishedDate': None} for i, u in enumerate(urls)],
    }


@pytest.mark.usefixtures
class TestModuleSearxng(unittest.TestCase):

    def test_opts(self):
        module = sfp_searxng()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_parse_header(self):
        self.assertEqual({'Authorization': 'Basic abc=='}, parse_header('Authorization: Basic abc=='))
        self.assertEqual({}, parse_header(''))
        self.assertEqual({}, parse_header('no-colon'))

    def _run(self, target, ttype, etype, value, pages, opts=None):
        sf = SpiderFoot(self.default_options)
        module = sfp_searxng()
        module.setup(sf, {**self.default_options, 'instance_url': 'searx.local:8080', **(opts or {})})
        module.setTarget(SpiderFootTarget(target, ttype))
        calls = []

        def fetch(url, **kwargs):
            calls.append((url, kwargs))
            q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            body = pages.get(int(q['pageno'][0]))
            if isinstance(body, tuple):
                return {'code': body[0], 'content': body[1], 'status': 'x'}
            return {'code': '200', 'content': json.dumps(body or _page())}

        sf.fetchUrl = fetch
        events = []
        module.notifyListeners = events.append
        root = SpiderFootEvent('ROOT', target, '', '')
        module.handleEvent(SpiderFootEvent(etype, value, 'SpiderFoot UI', root))
        return module, events, calls

    def test_site_search(self):
        pages = {1: _page("https://www.example.com/a", "https://example.com/b", "https://other.org/x"),
                 2: _page("https://dev.example.com/c", "https://www.example.com/a")}
        _m, events, calls = self._run("example.com", "INTERNET_NAME", "INTERNET_NAME", "example.com", pages,
                                      {'auth_header': 'X-Token: abc', 'verify_ssl': False})
        url, kwargs = calls[0]
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        self.assertTrue(url.startswith("http://searx.local:8080/search?"))
        self.assertEqual(['site:example.com'], q['q'])
        self.assertEqual(['json'], q['format'])
        self.assertEqual(['general'], q['categories'])
        self.assertEqual('abc', kwargs['headers']['X-Token'])
        self.assertFalse(kwargs['verify'])
        self.assertEqual(2, len(calls))

        by_type = {}
        for e in events:
            by_type.setdefault(e.eventType, []).append(e.data)
        self.assertEqual(["https://www.example.com/a", "https://example.com/b", "https://dev.example.com/c"],
                         by_type["LINKED_URL_INTERNAL"])
        self.assertEqual(["www.example.com", "dev.example.com"], by_type["INTERNET_NAME"])
        raw = json.loads(by_type["RAW_RIR_DATA"][0])
        self.assertEqual(3, len(raw['results']))
        self.assertNotIn("other.org", json.dumps(raw))

    def test_domain_and_hostname_searched_once(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_searxng()
        module.setup(sf, {**self.default_options, 'instance_url': 'http://searx', 'pages': 1})
        module.setTarget(SpiderFootTarget("example.com", "INTERNET_NAME"))
        calls = []
        sf.fetchUrl = lambda url, **kw: calls.append(url) or {'code': '200', 'content': json.dumps(_page())}
        module.notifyListeners = lambda e: None
        root = SpiderFootEvent('ROOT', "example.com", '', '')
        module.handleEvent(SpiderFootEvent("INTERNET_NAME", "example.com", 'SpiderFoot UI', root))
        module.handleEvent(SpiderFootEvent("DOMAIN_NAME", "example.com", 'SpiderFoot UI', root))
        self.assertEqual(1, len(calls))

    def test_phrase_search(self):
        pages = {1: _page("https://news.example.org/story", "https://acme.com/about")}
        _m, events, calls = self._run("acme.com", "INTERNET_NAME", "COMPANY_NAME", 'Acme "Widgets" Inc', pages,
                                      {'pages': 1})
        q = urllib.parse.parse_qs(urllib.parse.urlparse(calls[0][0]).query)
        self.assertEqual(['"Acme Widgets Inc"'], q['q'])
        types = [(e.eventType, e.data) for e in events]
        self.assertIn(("LINKED_URL_EXTERNAL", "https://news.example.org/story"), types)
        self.assertIn(("LINKED_URL_INTERNAL", "https://acme.com/about"), types)

    def test_json_disabled_stops_module(self):
        module, events, calls = self._run("example.com", "INTERNET_NAME", "INTERNET_NAME", "example.com",
                                          {1: ('403', 'Forbidden')})
        self.assertTrue(module.errorState)
        self.assertEqual([], events)

    def test_proxy_login_page_stops_module(self):
        module, events, _calls = self._run("example.com", "INTERNET_NAME", "INTERNET_NAME", "example.com",
                                           {1: ('200', '<html>Sign in</html>')})
        self.assertTrue(module.errorState)

    def test_no_url(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_searxng()
        module.setup(sf, dict(self.default_options))
        module.setTarget(SpiderFootTarget("example.com", "INTERNET_NAME"))
        sf.fetchUrl = lambda url, **kw: self.fail("no request expected")
        root = SpiderFootEvent('ROOT', "example.com", '', '')
        module.handleEvent(SpiderFootEvent("INTERNET_NAME", "example.com", 'SpiderFoot UI', root))
        self.assertTrue(module.errorState)


if __name__ == '__main__':
    unittest.main()


def _fake_embeddings(vocab):
    """A fetchUrl stand-in for an OpenAI-compatible /embeddings endpoint.

    Each text gets a bag-of-words vector over vocab, so similarity is predictable.
    """
    def embed(text):
        words = text.lower().replace(".", " ").replace("(", " ").replace(")", " ").split()
        return [float(words.count(w)) + 0.01 for w in vocab]

    def handler(url, **kwargs):
        body = json.loads(kwargs['postData'])
        data = [{'object': 'embedding', 'index': i, 'embedding': embed(t)} for i, t in enumerate(body['input'])]
        # Out of order on purpose: clients must sort by index
        return {'code': '200', 'content': json.dumps({'object': 'list', 'data': list(reversed(data)),
                                                      'model': body.get('model')})}
    return handler


@pytest.mark.usefixtures
class TestModuleSearxngEmbeddings(unittest.TestCase):

    RESULTS = _page("https://acme.com/team", "https://recipes.example/john-smith-pie", "https://news.example/acme-cto")
    TITLES = ["John Smith joins Acme Widgets as CTO", "John Smith's famous apple pie recipe",
              "Acme Widgets names John Smith CTO"]

    def setUp(self):
        for r, t in zip(self.RESULTS['results'], self.TITLES):
            r['title'], r['content'] = t, ""

    def _run(self, opts, embed_handler=None):
        sf = SpiderFoot(self.default_options)
        module = sfp_searxng()
        module.setup(sf, {**self.default_options, 'instance_url': 'http://searx', 'pages': 1,
                          'embeddings_url': 'http://embed.local:8080/v1', 'embeddings_model': 'nomic-embed-text-v1.5',
                          **opts})
        module.setTarget(SpiderFootTarget("Acme Widgets Inc", "COMPANY_NAME"))
        calls = []
        embed_handler = embed_handler or _fake_embeddings(["acme", "widgets", "john", "smith", "cto", "pie", "recipe"])

        def fetch(url, **kwargs):
            calls.append((url, kwargs))
            if urllib.parse.urlparse(url).hostname == "embed.local":
                return embed_handler(url, **kwargs)
            return {'code': '200', 'content': json.dumps(self.RESULTS)}

        sf.fetchUrl = fetch
        events = []
        module.notifyListeners = events.append
        root = SpiderFootEvent('ROOT', "Acme Widgets Inc", '', '')
        module.handleEvent(SpiderFootEvent("HUMAN_NAME", "John Smith", 'sfp_company', root))
        return module, events, calls

    def test_ranks_by_similarity_to_target_context(self):
        module, events, calls = self._run({'embeddings_apikey': 'sk-test'})
        url, kwargs = calls[1]
        self.assertEqual("http://embed.local:8080/v1/embeddings", url)
        body = json.loads(kwargs['postData'])
        self.assertEqual("nomic-embed-text-v1.5", body['model'])
        self.assertEqual("John Smith (Acme Widgets Inc)", body['input'][0])  # phrase + scan target
        self.assertEqual(4, len(body['input']))
        self.assertEqual("Bearer sk-test", kwargs['headers']['Authorization'])
        self.assertTrue(kwargs['noLog'])

        raw = json.loads(next(e.data for e in events if e.eventType == "RAW_RIR_DATA"))
        self.assertEqual("John Smith (Acme Widgets Inc)", raw['ranked_against'])
        self.assertEqual("https://recipes.example/john-smith-pie", raw['results'][-1]['url'])  # least relevant last
        sims = [r['similarity'] for r in raw['results']]
        self.assertEqual(sims, sorted(sims, reverse=True))
        self.assertEqual(3, len([e for e in events if e.eventType.startswith("LINKED_URL")]))  # 0 = keep all

    def test_min_similarity_drops_irrelevant_results(self):
        module, events, _calls = self._run({'min_similarity': 70})
        urls = [e.data for e in events if e.eventType.startswith("LINKED_URL")]
        self.assertNotIn("https://recipes.example/john-smith-pie", urls)
        self.assertIn("https://acme.com/team", urls)
        raw = json.loads(next(e.data for e in events if e.eventType == "RAW_RIR_DATA"))
        self.assertEqual(1, raw['dropped_below_min_similarity'])

    def test_embeddings_failure_falls_back_to_unranked(self):
        module, events, calls = self._run({'min_similarity': 90},
                                          lambda url, **kw: {'code': '404', 'content': '{"error": "model not found"}'})
        self.assertTrue(module.embeddingsFailed)
        self.assertFalse(module.errorState)  # SearXNG results still reported
        self.assertEqual(3, len([e for e in events if e.eventType.startswith("LINKED_URL")]))
        raw = json.loads(next(e.data for e in events if e.eventType == "RAW_RIR_DATA"))
        self.assertNotIn('ranked_against', raw)

    def test_site_search_is_not_ranked(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_searxng()
        module.setup(sf, {**self.default_options, 'instance_url': 'http://searx', 'pages': 1,
                          'embeddings_url': 'http://embed.local/v1', 'min_similarity': 99})
        module.setTarget(SpiderFootTarget("example.com", "INTERNET_NAME"))
        calls = []
        sf.fetchUrl = lambda url, **kw: calls.append(url) or {
            'code': '200', 'content': json.dumps(_page("https://www.example.com/a"))}
        events = []
        module.notifyListeners = events.append
        root = SpiderFootEvent('ROOT', "example.com", '', '')
        module.handleEvent(SpiderFootEvent("INTERNET_NAME", "example.com", 'SpiderFoot UI', root))
        self.assertEqual(1, len(calls))
        self.assertIn("https://www.example.com/a", [e.data for e in events])

    def test_endpoint_normalisation(self):
        m = sfp_searxng()
        for given, want in [("http://e/v1", "http://e/v1/embeddings"), ("http://e/v1/", "http://e/v1/embeddings"),
                            ("e:8080/v1/embeddings", "http://e:8080/v1/embeddings"), ("", "")]:
            m.opts = {'embeddings_url': given}
            self.assertEqual(want, m.embeddingsEndpoint(), given)


@pytest.mark.usefixtures
class TestModuleSearxngRegressions(unittest.TestCase):
    """Bugs found running real scans against a local SearXNG/embeddings stub."""

    def _module(self, target, ttype, calls, page):
        sf = SpiderFoot(self.default_options)
        module = sfp_searxng()
        module.setup(sf, {**self.default_options, 'instance_url': 'http://searx', 'pages': 1})
        module.setTarget(SpiderFootTarget(target, ttype))
        sf.fetchUrl = lambda url, **kw: calls.append(url) or {'code': '200', 'content': json.dumps(page)}
        return module

    def test_own_and_covered_subdomains_are_not_searched_again(self):
        calls, events = [], []
        module = self._module("example.com", "INTERNET_NAME", calls, _page("https://www.example.com/a"))
        module.notifyListeners = events.append
        root = SpiderFootEvent('ROOT', "example.com", '', '')
        target_evt = SpiderFootEvent("INTERNET_NAME", "example.com", 'SpiderFoot UI', root)
        module.handleEvent(target_evt)
        found = next(e for e in events if e.eventType == "INTERNET_NAME")  # www.example.com, from this module
        module.handleEvent(found)
        module.handleEvent(SpiderFootEvent("INTERNET_NAME", "mail.example.com", 'sfp_dnsresolve', target_evt))
        module.handleEvent(SpiderFootEvent("INTERNET_NAME", "other-site.org", 'sfp_dnsresolve', target_evt))
        self.assertEqual(["site:example.com", "site:other-site.org"],
                         [urllib.parse.parse_qs(urllib.parse.urlparse(u).query)['q'][0] for u in calls])

    def test_name_targets_report_external_urls(self):
        calls, events = [], []
        module = self._module("John Smith", "HUMAN_NAME", calls, _page("https://acme.com/team"))
        module.notifyListeners = events.append
        root = SpiderFootEvent('ROOT', "John Smith", '', '')
        module.handleEvent(SpiderFootEvent("HUMAN_NAME", "John Smith", 'SpiderFoot UI', root))
        self.assertEqual([("LINKED_URL_EXTERNAL", "https://acme.com/team")],
                         [(e.eventType, e.data) for e in events if e.eventType.startswith("LINKED_URL")])
