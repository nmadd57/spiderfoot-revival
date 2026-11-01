import base64
import json
import unittest
from unittest import mock

from modules.sfp_zoomeye import sfp_zoomeye


class TestModuleZoomeye(unittest.TestCase):

    def test_opts(self):
        module = sfp_zoomeye()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_build_query(self):
        self.assertEqual(sfp_zoomeye.buildQuery("IP_ADDRESS", "1.2.3.4"), 'ip="1.2.3.4"')
        self.assertEqual(sfp_zoomeye.buildQuery("DOMAIN_NAME", "example.com"), 'domain="example.com"')
        self.assertEqual(sfp_zoomeye.buildQuery("INTERNET_NAME", "a.example.com"), 'hostname="a.example.com"')

    def test_text_flattening(self):
        self.assertEqual(sfp_zoomeye._text({"name": "Linux"}), "Linux")
        self.assertEqual(sfp_zoomeye._text(["a", "b"]), "a, b")
        self.assertEqual(sfp_zoomeye._text(None), "")
        self.assertEqual(sfp_zoomeye._text(443), "443")

    def _module(self, response):
        module = sfp_zoomeye()
        module.sf = mock.Mock()
        module.sf.fetchUrl.return_value = response
        module.opts = dict(module.opts, api_key="k", _fetchtimeout=5, request_delay=0)
        module.errorState = False
        return module

    def test_request_is_v2_post_with_base64_query(self):
        module = self._module({"code": "200", "content": json.dumps({"code": 60000, "data": [{"ip": "1.2.3.4"}]})})
        data = module.queryHost('ip="1.2.3.4"', 2)
        self.assertEqual(data["data"][0]["ip"], "1.2.3.4")
        args, kwargs = module.sf.fetchUrl.call_args
        self.assertEqual(args[0], "https://api.zoomeye.ai/v2/search")
        body = json.loads(kwargs["postData"])
        self.assertEqual(base64.b64decode(body["qbase64"]).decode(), 'ip="1.2.3.4"')
        self.assertEqual(body["page"], 2)
        self.assertEqual(kwargs["headers"]["API-KEY"], "k")

    def test_no_credits_sets_error_state(self):
        module = self._module({"code": "402", "content": '{"error":"credits_insufficient"}'})
        module.error = mock.Mock()
        self.assertIsNone(module.queryHost('ip="1.2.3.4"'))
        self.assertTrue(module.errorState)
