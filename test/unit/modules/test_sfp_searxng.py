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
