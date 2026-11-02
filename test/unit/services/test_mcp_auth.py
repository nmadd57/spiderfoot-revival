import os
import unittest
from unittest import mock

from spiderfoot.services import mcp_auth as m


class TestMcpAuth(unittest.TestCase):
    def test_token_round_trip_and_storage(self):
        token, digest, hint, created = m.new_token()
        self.assertTrue(token.startswith('sfmcp_') and len(token) > 40)
        self.assertEqual(hint, token[:10])
        self.assertNotIn(token, digest)
        saved = m.token_settings(digest, hint, created)
        self.assertTrue(m.verify(token, saved))
        self.assertFalse(m.verify(token + 'x', saved))
        self.assertFalse(m.verify('', saved))
        self.assertFalse(m.verify(token, {}))
        self.assertNotIn(token, ''.join(str(v) for v in saved.values()))

    def test_tokens_are_unique(self):
        self.assertNotEqual(m.new_token()[0], m.new_token()[0])

    def test_enabled_needs_a_token(self):
        self.assertFalse(m.enabled({}))
        self.assertFalse(m.enabled({m.ENABLED: '1'}))
        self.assertTrue(m.enabled({m.ENABLED: '1', m.TOKEN_HASH: 'abc'}))
        self.assertFalse(m.enabled({m.ENABLED: '0', m.TOKEN_HASH: 'abc'}))

    def test_permission_defaults_are_least_privilege(self):
        self.assertEqual(m.permissions({}), {'scan': True, 'delete': False, 'active': False, 'private': False})
        self.assertEqual(m.permissions({m.ALLOW_DELETE: '1', m.ALLOW_SCAN: '0'})['delete'], True)
        self.assertEqual(m.permissions({m.ALLOW_SCAN: '0'})['scan'], False)

    def test_revoke_switches_the_server_off(self):
        saved = {m.ENABLED: '1', **m.token_settings('h', 'sfmcp_ab12', 5)}
        saved.update(m.revoked_settings())
        self.assertFalse(m.enabled(saved))
        self.assertFalse(m.public_status(saved)['hasToken'])

    def test_authorization_header(self):
        self.assertEqual(m.from_authorization_header('Bearer abc'), 'abc')
        self.assertEqual(m.from_authorization_header('bearer   abc '), 'abc')
        for bad in ('', None, 'Basic abc', 'Bearer', 'abc'):
            self.assertIsNone(m.from_authorization_header(bad))

    def test_listen_port_from_environment(self):
        with mock.patch.dict(os.environ, {'SF_MCP_PORT': '5002'}):
            self.assertEqual(m.listen_port(), 5002)
        for bad in ('0', '', 'x', '70000', '-1'):
            with mock.patch.dict(os.environ, {'SF_MCP_PORT': bad}):
                self.assertEqual(m.listen_port(), 0)

    def test_public_status_never_contains_the_hash(self):
        saved = {m.ENABLED: '1', **m.token_settings('deadbeef', 'sfmcp_ab12', 7)}
        self.assertNotIn('deadbeef', str(m.public_status(saved)))
