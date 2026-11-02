import socket
import unittest

import sflib


class TestIpv4First(unittest.TestCase):
    def test_ipv4_sorted_before_ipv6_keeping_order(self):
        def fake(*a, **k):
            return [(socket.AF_INET6, 1, 6, '', ('2001::1', 443, 0, 0)),
                    (socket.AF_INET, 1, 6, '', ('1.1.1.1', 443)),
                    (socket.AF_INET6, 1, 6, '', ('2001::2', 443, 0, 0)),
                    (socket.AF_INET, 1, 6, '', ('2.2.2.2', 443))]
        wrapped = sflib._prefer_ipv4(fake)
        self.assertTrue(wrapped._ipv4_first)
        self.assertEqual([r[4][0] for r in wrapped('x', 443)], ['1.1.1.1', '2.2.2.2', '2001::1', '2001::2'])

    def test_custom_dns_server_installs_the_wrapper(self):
        original = socket.getaddrinfo
        opts = {'_dnsserver': '127.0.0.1', '_useragent': 'x', '_fetchtimeout': 5, '_internettlds': '', '_internettlds_cache': 1}
        try:
            for _ in range(2):  # every new SpiderFoot object re-installs the override; it must never stack
                sflib.SpiderFoot(opts)
                self.assertTrue(getattr(socket.getaddrinfo, '_ipv4_first', False))
                self.assertIsNone(getattr(socket.getaddrinfo.__closure__[0].cell_contents, '_ipv4_first', None))
        finally:
            socket.getaddrinfo = original

    def test_no_wrapper_without_a_custom_dns_server(self):
        original = socket.getaddrinfo
        try:
            sflib.SpiderFoot({'_dnsserver': '', '_useragent': 'x', '_fetchtimeout': 5, '_internettlds': '', '_internettlds_cache': 1})
            self.assertIs(socket.getaddrinfo, original)
        finally:
            socket.getaddrinfo = original
