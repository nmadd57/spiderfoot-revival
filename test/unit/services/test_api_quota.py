import unittest
from unittest import mock

from spiderfoot.services import api_quota as q

KEYS = ['ok', 'valid', 'message', 'used', 'limit', 'remaining', 'unit', 'resets', 'plan']


class _Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def json(self):
        return self._body


class TestParsers(unittest.TestCase):
    def test_shodan(self):
        r = q._parse_shodan({'plan': 'dev', 'query_credits': 90, 'usage_limits': {'query_credits': 100}})
        self.assertEqual((r['used'], r['limit'], r['remaining'], r['plan']), (10, 100, 90, 'dev'))
        self.assertTrue(r['ok'] and r['valid'])

    def test_virustotal(self):
        r = q._parse_virustotal({'data': {'api_requests_daily': {'user': {'allowed': 500, 'used': 20}}}})
        self.assertEqual((r['used'], r['limit'], r['remaining']), (20, 500, 480))
        self.assertEqual(r['unit'], 'requests/day')

    def test_hunter(self):
        r = q._parse_hunter({'data': {'plan_name': 'Free', 'reset_date': '2026-11-30',
                                      'requests': {'searches': {'used': 5, 'available': 50}}}})
        self.assertEqual((r['used'], r['limit'], r['remaining']), (5, 50, 45))
        self.assertEqual((r['resets'], r['plan']), ('2026-11-30', 'Free'))

    def test_fullhunt_consistent_and_inconsistent(self):
        r = q._parse_fullhunt({'user_credits': {'credits_usage': 2, 'total_credits_per_month': 10, 'remaining_credits': 8}})
        self.assertEqual((r['used'], r['limit'], r['remaining']), (2, 10, 8))
        r = q._parse_fullhunt({'user_credits': {'credits_usage': 0, 'total_credits_per_month': 5, 'remaining_credits': 10}})
        self.assertEqual((r['used'], r['limit'], r['remaining']), (0, 10, 10))

    def test_whoisxmlapi(self):
        r = q._parse_whoisxmlapi({'data': [{'credits': 100}, {'credits': 50}]})
        self.assertEqual(r['remaining'], 150)
        self.assertIsNone(q._parse_whoisxmlapi({})['remaining'])

    def test_hybrid_analysis(self):
        r = q._parse_hybrid_analysis({'api_key': 'x', 'auth_level_name': 'restricted'})
        self.assertTrue(r['valid'])
        self.assertEqual(r['plan'], 'restricted')
        self.assertFalse(q._parse_hybrid_analysis({})['ok'])

    def test_netlas(self):
        r = q._parse_netlas({'plan': {'name': 'Community', 'coins': 2500},
                             'api_key': {'next_time_coins_will_be_updated': '2026-12-01'}})
        self.assertEqual((r['limit'], r['plan'], r['resets']), (2500, 'Community', '2026-12-01'))
        self.assertIsNone(r['used'])

    def test_abuseipdb(self):
        r = q._parse_abuseipdb({'X-RateLimit-Limit': '1000', 'X-RateLimit-Remaining': '990',
                                'X-RateLimit-Reset': '1793577600'})
        self.assertEqual((r['used'], r['limit'], r['remaining']), (10, 1000, 990))
        self.assertTrue(r['resets'].endswith('Z'))
        self.assertIn('one request', r['message'])

    def test_greynoise(self):
        r = q._parse_greynoise({'message': 'pong', 'offering': 'enterprise', 'plan': 'Business'})
        self.assertEqual(r['plan'], 'Business')
        self.assertEqual(q._parse_greynoise({'offering': 'community'})['plan'], 'community')

    def test_ipinfo(self):
        r = q._parse_ipinfo({'requests': {'month': 10, 'limit': 50000, 'remaining': 49990}})
        self.assertEqual((r['used'], r['limit'], r['remaining']), (10, 50000, 49990))
        r = q._parse_ipinfo({})
        self.assertTrue(r['valid'])
        self.assertIsNone(r['limit'])

    def test_alienvault(self):
        r = q._parse_alienvault({'username': 'someone'})
        self.assertTrue(r['ok'] and r['valid'])


class TestCheck(unittest.TestCase):
    def test_unknown_module(self):
        r = q.check('sfp_nonexistent', {})
        self.assertEqual(set(r), set(KEYS))
        self.assertFalse(r['ok'])
        self.assertIsNone(r['valid'])
        self.assertEqual(r['message'], 'No quota checker for this module')

    def test_missing_values(self):
        for vals in ({}, {'api_key': ''}, {'api_key': '  '}):
            r = q.check('sfp_shodan', vals)
            self.assertFalse(r['ok'])
            self.assertIsNone(r['valid'])
            self.assertIn('api_key', r['message'])

    def test_network_error_does_not_raise_or_leak(self):
        with mock.patch('requests.get', side_effect=RuntimeError('boom secret-key-123')):
            r = q.check('sfp_shodan', {'api_key': 'secret-key-123'})
        self.assertFalse(r['ok'])
        self.assertIsNone(r['valid'])
        self.assertNotIn('secret-key-123', str(r))

    def test_status_handling(self):
        cases = ((401, False), (403, False), (429, None), (500, None))
        for status, valid in cases:
            with mock.patch('requests.get', return_value=_Resp(status)):
                r = q.check('sfp_shodan', {'api_key': 'k'})
            self.assertFalse(r['ok'])
            self.assertIs(r['valid'], valid)
        with mock.patch('requests.get', return_value=_Resp(429)):
            self.assertEqual(q.check('sfp_shodan', {'api_key': 'k'})['message'], 'rate limited')

    def test_success_and_bad_json(self):
        body = {'plan': 'dev', 'query_credits': 5, 'usage_limits': {'query_credits': 10}}
        with mock.patch('requests.get', return_value=_Resp(200, body)) as g:
            r = q.check('sfp_shodan', {'api_key': 'k'})
            self.assertEqual(g.call_args[1]['timeout'], 15)
        self.assertEqual(r['used'], 5)
        with mock.patch('requests.get', return_value=_Resp(200, ['x'])):
            self.assertFalse(q.check('sfp_shodan', {'api_key': 'k'})['ok'])

    def test_abuseipdb_uses_headers(self):
        with mock.patch('requests.get', return_value=_Resp(200, {}, {'X-RateLimit-Limit': '10', 'X-RateLimit-Remaining': '9'})):
            r = q.check('sfp_abuseipdb', {'api_key': 'k'})
        self.assertEqual((r['limit'], r['remaining'], r['used']), (10, 9, 1))

    def test_all_providers_declare_opts(self):
        for name, prov in q.PROVIDERS.items():
            self.assertTrue(prov.opts, name)


if __name__ == '__main__':
    unittest.main()
