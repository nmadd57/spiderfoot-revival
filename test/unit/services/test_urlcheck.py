import socket
import unittest
from unittest import mock

from spiderfoot.services import ai_service, embeddings, urlcheck


class TestCheckHttpUrl(unittest.TestCase):
    def ok(self, url, **kw):
        out, problem = urlcheck.check_http_url(url, **kw)
        self.assertIsNone(problem, url)
        return out

    def bad(self, url, **kw):
        out, problem = urlcheck.check_http_url(url, **kw)
        self.assertIsNone(out, url)
        self.assertTrue(problem)
        return problem

    def test_lan_loopback_and_public_endpoints_are_allowed(self):
        self.assertEqual(self.ok('192.168.1.10:11434/v1', resolve=False), 'http://192.168.1.10:11434/v1')
        self.assertEqual(self.ok('http://127.0.0.1:8080', resolve=False), 'http://127.0.0.1:8080')
        self.assertEqual(self.ok('https://api.example.com/v1/?x=1#frag', resolve=False), 'https://api.example.com/v1/?x=1')
        self.assertEqual(self.ok('http://[::1]:9000/v1', resolve=False), 'http://[::1]:9000/v1')

    def test_only_http_and_https(self):
        for url in ('file:///etc/passwd', 'ftp://host/x', 'gopher://host', 'javascript:alert(1)'):
            self.bad(url, resolve=False)

    def test_credentials_in_the_url_are_refused(self):
        self.assertIn('credentials', self.bad('http://user:pw@host/v1', resolve=False))
        self.bad('http://user@host/v1', resolve=False)

    def test_metadata_and_link_local_addresses_are_refused(self):
        for url in ('http://169.254.169.254/latest/meta-data', 'http://169.254.10.1', 'http://[fe80::1]/', 'http://0.0.0.0:80',
                    'http://224.0.0.1/', 'http://[::ffff:169.254.169.254]/'):
            self.bad(url, resolve=False)

    def test_a_name_resolving_to_a_blocked_address_is_refused(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 80))]
        with mock.patch('socket.getaddrinfo', return_value=fake):
            self.bad('http://metadata.example/v1')
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.5', 80))]
        with mock.patch('socket.getaddrinfo', return_value=fake):
            self.ok('http://llm.lan:8080/v1')

    def test_unresolvable_names_are_left_to_fail_at_request_time(self):
        with mock.patch('socket.getaddrinfo', side_effect=socket.gaierror):
            self.ok('http://no-such-host.invalid/v1')

    def test_empty_bad_port_and_no_host(self):
        self.bad('')
        self.bad('http://host:99999/', resolve=False)
        self.bad('http:///path', resolve=False)


class TestEndpointsUseIt(unittest.TestCase):
    def test_ai_test_refuses_a_metadata_url_without_a_request(self):
        with mock.patch('requests.get') as g:
            out = ai_service.test_connection('http://169.254.169.254/v1', 'k')
        g.assert_not_called()
        self.assertFalse(out['ok'])
        self.assertIn('not allowed', out['message'])

    def test_embeddings_test_refuses_it_too(self):
        with mock.patch('requests.get') as g, mock.patch('requests.post') as p:
            out = embeddings.test_connection('file:///etc/passwd')
        g.assert_not_called()
        p.assert_not_called()
        self.assertFalse(out['ok'])
        self.assertIn('http', out['message'])
