import json
import unittest
from unittest import mock

from modules.sfp_onioncity import sfp_onioncity
from modules.sfp_openstreetmap import sfp_openstreetmap
from modules.sfp_pastebin import sfp_pastebin
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from spiderfoot.services import searxng


def searx_page(urls):
    return {'code': '200', 'content': json.dumps({'results': [{'url': u, 'title': 't', 'content': 'c'} for u in urls]})}


class SfBase(unittest.TestCase):
    def sf(self, instance_url='http://searx:8080', **extra):
        opts = dict(self.default_options)
        opts['__modules__'] = {'sfp_searxng': {'opts': {'instance_url': instance_url, 'pages': 2, 'auth_header': '', **extra}}}
        return SpiderFoot(opts)


class TestSearxngService(SfBase):
    def test_config_needs_an_instance(self):
        self.assertTrue(searxng.available(self.sf()))
        self.assertFalse(searxng.available(self.sf('')))
        self.assertEqual(searxng.config(self.sf('searx:8080'))['instance_url'], 'http://searx:8080')

    def test_search_collects_urls_across_pages_without_duplicates(self):
        sf = self.sf()
        pages = [searx_page(['https://a.example/1', 'https://a.example/2']),
                 searx_page(['https://a.example/2', 'https://a.example/3']),
                 searx_page([])]
        with mock.patch.object(sf, 'fetchUrl', side_effect=pages) as f:
            res = searxng.search(sf, 'site:example.com')
        self.assertEqual(res['urls'], ['https://a.example/1', 'https://a.example/2', 'https://a.example/3'])
        self.assertIn('searx:8080/search?q=site%3Aexample.com', res['webSearchUrl'])
        self.assertIn('pageno=2', f.call_args_list[1][0][0])
        self.assertIn('format=json', f.call_args_list[0][0][0])

    def test_auth_header_is_sent(self):
        sf = self.sf(auth_header='X-Token: abc')
        with mock.patch.object(sf, 'fetchUrl', return_value=searx_page(['https://x/1'])) as f:
            searxng.search(sf, 'q', pages=1)
        self.assertEqual(f.call_args[1]['headers']['X-Token'], 'abc')

    def test_errors_return_none_and_are_reported(self):
        for code, text in (('403', 'JSON output'), ('401', 'authentication'), ('429', 'rate limited'), ('None', 'Could not reach')):
            sf = self.sf()
            with mock.patch.object(sf, 'fetchUrl', return_value={'code': code, 'content': None, 'status': 'x'}), \
                    mock.patch.object(sf, 'error') as err:
                self.assertIsNone(searxng.search(sf, 'q'))
            self.assertIn(text, err.call_args[0][0])

    def test_html_reply_is_reported(self):
        sf = self.sf()
        with mock.patch.object(sf, 'fetchUrl', return_value={'code': '200', 'content': '<html>login</html>'}), \
                mock.patch.object(sf, 'error') as err:
            self.assertIsNone(searxng.search(sf, 'q'))
        self.assertIn('did not return JSON', err.call_args[0][0])


class TestWebSearch(SfBase):
    def test_web_search_uses_searxng(self):
        sf = self.sf()
        with mock.patch.object(sf, 'fetchUrl', return_value=searx_page(['https://x/1'])) as f:
            res = sf.webSearch('site:example.com', {'timeout': 5})
        self.assertEqual(res['urls'], ['https://x/1'])
        self.assertIn('searx:8080/search', f.call_args[0][0])

    def test_without_a_backend(self):
        sf = self.sf('')
        with mock.patch.object(sf, 'error') as err:
            self.assertIsNone(sf.webSearch('q', {'timeout': 5}))
        self.assertIn('No web search backend', err.call_args[0][0])

    def test_web_search_available(self):
        self.assertTrue(self.sf().webSearchAvailable())
        self.assertFalse(self.sf('').webSearchAvailable())

    def test_google_and_bing_helpers_are_gone(self):
        sf = self.sf()
        self.assertFalse(hasattr(sf, 'googleIterate'))
        self.assertFalse(hasattr(sf, 'bingIterate'))


class TestModules(SfBase):
    def run_module(self, cls, sf, opts=None, event_type='INTERNET_NAME', data='example.com'):
        module = cls()
        module.__name__ = cls.__name__
        module.opts = dict(cls.opts)  # setup() merges global options into the class-level dict otherwise
        module.setup(sf, {**self.default_options, **(opts or {})})
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        out = []
        module.notifyListeners = lambda e: out.append(e)
        module.checkForStop = lambda: False
        root = SpiderFootEvent('ROOT', 'example.com', '', None)
        module.handleEvent(SpiderFootEvent(event_type, data, 'test', root))
        return module, out

    def test_search_modules_need_searxng(self):
        module, out = self.run_module(sfp_pastebin, self.sf(''), event_type='EMAILADDR', data='a@example.com')
        self.assertTrue(module.errorState)
        self.assertEqual(out, [])
        module, _ = self.run_module(sfp_onioncity, self.sf(''))
        self.assertTrue(module.errorState)

    def test_pastebin_through_searxng(self):
        sf = self.sf()
        with mock.patch.object(sf, 'fetchUrl', return_value=searx_page(['https://pastebin.com/abc'])) as f:
            module, out = self.run_module(sfp_pastebin, sf, event_type='EMAILADDR', data='a@example.com')
        self.assertFalse(module.errorState)
        self.assertIn('site%3Apastebin.com', f.call_args_list[0][0][0])

    def test_modules_declare_web_search_and_no_keys(self):
        for cls in (sfp_pastebin, sfp_onioncity):
            self.assertTrue(cls.meta['usesWebSearch'])
            self.assertNotIn('apikey', cls.meta['flags'])
            self.assertFalse([o for o in cls.opts if 'key' in o or 'cse' in o], cls.__name__)

    def test_google_and_bing_modules_are_removed(self):
        import os
        for name in ('googlesearch', 'googlemaps', 'bingsearch', 'bingsharedip'):
            self.assertFalse(os.path.exists(f'modules/sfp_{name}.py'), name)


class TestGeocoder(SfBase):
    def setUp(self):
        self.sf_ = self.sf()
        self.module = sfp_openstreetmap()
        self.module.__name__ = 'sfp_openstreetmap'
        self.module.setup(self.sf_, {'delay': 0, '_fetchtimeout': 5})
        self.out = []
        self.module.notifyListeners = lambda e: self.out.append(e)
        self.root = SpiderFootEvent('ROOT', 'example.com', '', None)

    def feed(self, etype, data, src='test'):
        self.module.handleEvent(SpiderFootEvent(etype, data, src, self.root))

    def test_forward_geocode(self):
        reply = {'code': '200', 'content': json.dumps([{'lat': '48.8584', 'lon': '2.2945'}])}
        with mock.patch.object(self.sf_, 'fetchUrl', return_value=reply) as f:
            self.feed('PHYSICAL_ADDRESS', 'Champ de Mars, Paris')
        self.assertEqual([(e.eventType, e.data) for e in self.out], [('PHYSICAL_COORDINATES', '48.8584,2.2945')])
        self.assertIn('/search?', f.call_args[0][0])
        self.assertIn('SpiderFoot-Revival', f.call_args[1]['useragent'])

    def test_reverse_geocode(self):
        reply = {'code': '200', 'content': json.dumps({'display_name': 'Eiffel Tower, Paris, France'})}
        with mock.patch.object(self.sf_, 'fetchUrl', return_value=reply) as f:
            self.feed('PHYSICAL_COORDINATES', '48.8584,2.2945')
        self.assertEqual([(e.eventType, e.data) for e in self.out], [('PHYSICAL_ADDRESS', 'Eiffel Tower, Paris, France')])
        self.assertIn('/reverse?', f.call_args[0][0])

    def test_reverse_can_be_turned_off_and_rejects_bad_input(self):
        with mock.patch.object(self.sf_, 'fetchUrl') as f:
            self.module.opts['reverse'] = False
            self.feed('PHYSICAL_COORDINATES', '48.8,2.2')
            self.module.opts['reverse'] = True
            self.feed('PHYSICAL_COORDINATES', 'not coordinates')
            self.feed('PHYSICAL_COORDINATES', '95.0,2.0')
        f.assert_not_called()
        self.assertEqual(self.out, [])

    def test_never_consumes_its_own_output(self):
        with mock.patch.object(self.sf_, 'fetchUrl') as f:
            self.feed('PHYSICAL_COORDINATES', '48.8584,2.2945', src='sfp_openstreetmap')
        f.assert_not_called()

    def test_custom_nominatim_url_and_blocking(self):
        self.module.opts['nominatim_url'] = 'nominatim.internal:8080'
        with mock.patch.object(self.sf_, 'fetchUrl', return_value={'code': '429', 'content': 'x'}) as f, \
                mock.patch.object(self.module, 'error') as err:
            self.feed('PHYSICAL_ADDRESS', '1 Main St')
        self.assertTrue(f.call_args[0][0].startswith('https://nominatim.internal:8080/search?'))
        self.assertEqual(self.out, [])
        self.assertIn('refused', err.call_args[0][0])
