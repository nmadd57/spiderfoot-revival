import json
import unittest
from unittest import mock

from modules.sfp_censys import sfp_censys
from spiderfoot import SpiderFootEvent

HOST = {"result": {"resource": {
    "ip": "192.0.2.10",
    "location": {"city": "Paris", "country": "France", "continent": "Europe"},
    "autonomous_system": {"asn": 64500, "bgp_prefix": "192.0.2.0/24", "name": "EXAMPLE"},
    "operating_system": {"vendor": "Canonical", "product": "Ubuntu", "version": "22.04"},
    "services": [
        {"port": 22, "protocol": "SSH", "transport_protocol": "tcp", "banner": "SSH-2.0-OpenSSH_9.6",
         "scan_time": "2099-01-01T00:00:00Z",
         "software": [{"vendor": "OpenBSD", "product": "OpenSSH", "version": "9.6"}]},
        {"port": 53, "protocol": "DNS", "transport_protocol": "udp", "scan_time": "2099-01-01T00:00:00Z"},
        {"port": 443, "protocol": "HTTP", "transport_protocol": "tcp", "scan_time": "2099-01-01T00:00:00Z",
         "endpoints": [{"http": {"headers": {"Server": {"headers": ["nginx"]}}}}]},
    ],
}}}


class TestCensysPlatform(unittest.TestCase):

    def _run(self, response):
        module = sfp_censys()
        module.sf = mock.Mock()
        module.opts = dict(module.opts, censys_api_key="token", _fetchtimeout=5, delay=0)
        module.results = {}
        module.errorState = False
        module.sf.fetchUrl.return_value = response
        module.sf.validIpNetwork.return_value = True
        events = []
        module.notifyListeners = lambda e: events.append(e)
        module.__name__ = "sfp_censys"
        root = SpiderFootEvent("ROOT", "x", "", None)
        evt = SpiderFootEvent("IP_ADDRESS", "192.0.2.10", "test", root)
        module.handleEvent(evt)
        return module, events

    def test_request_shape(self):
        module, _ = self._run({"code": "200", "content": json.dumps(HOST)})
        args, kwargs = module.sf.fetchUrl.call_args
        self.assertEqual(args[0], "https://api.platform.censys.io/v3/global/asset/host/192.0.2.10")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer token")
        self.assertIn("vnd.censys.api.v3.host", kwargs["headers"]["Accept"])
        self.assertNotIn("X-Organization-ID", kwargs["headers"])

    def test_events(self):
        _, events = self._run({"code": "200", "content": json.dumps(HOST)})
        got = {(e.eventType, e.data) for e in events}
        self.assertIn(("TCP_PORT_OPEN", "192.0.2.10:22"), got)
        self.assertIn(("UDP_PORT_OPEN", "192.0.2.10:53"), got)
        self.assertIn(("BGP_AS_MEMBER", "64500"), got)
        self.assertIn(("NETBLOCK_MEMBER", "192.0.2.0/24"), got)
        self.assertIn(("OPERATING_SYSTEM", "Canonical Ubuntu 22.04"), got)
        self.assertIn(("SOFTWARE_USED", "OpenBSD OpenSSH 9.6"), got)
        self.assertIn(("GEOINFO", "Paris, France, Europe"), got)
        self.assertIn(("TCP_PORT_OPEN_BANNER", "SSH-2.0-OpenSSH_9.6"), got)
        self.assertIn(("WEBSERVER_HTTPHEADERS", json.dumps({"Server": "nginx"})), got)

    def test_old_record_skipped(self):
        old = json.loads(json.dumps(HOST))
        for s in old["result"]["resource"]["services"]:
            s["scan_time"] = "2001-01-01T00:00:00Z"
        _, events = self._run({"code": "200", "content": json.dumps(old)})
        self.assertEqual([e.eventType for e in events], ["RAW_RIR_DATA"])

    def test_unauthorised_sets_error_state(self):
        module, events = self._run({"code": "401", "content": "{}"})
        self.assertTrue(module.errorState)
        self.assertEqual(events, [])

    def test_helpers(self):
        self.assertEqual(sfp_censys.parseTime("1970-01-01T00:00:10Z"), 10)
        self.assertEqual(sfp_censys.flattenHeaders({"A": {"headers": ["x", "y"]}, "B": "z", "C": None}), {"A": "x, y", "B": "z"})
