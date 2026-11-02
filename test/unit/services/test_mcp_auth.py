import os
import unittest
from unittest import mock

from spiderfoot.services import mcp_auth as m


class TestMcpAuth(unittest.TestCase):
    def test_token_format_and_hashing(self):
        token, digest, hint, created = m.new_token()
        self.assertTrue(token.startswith('sfmcp_') and len(token) > 40)
        self.assertEqual(hint, token[:10])
        self.assertNotIn(token, digest)
        self.assertEqual(digest, m.hash_token(token))
        self.assertNotEqual(digest, m.hash_token(token + 'x'))
        self.assertGreater(created, 0)

    def test_tokens_are_unique(self):
        self.assertNotEqual(m.new_token()[0], m.new_token()[0])

    def test_enabled_is_just_the_switch(self):
        # The shared token is gone: users hold their own tokens, so only the switch decides
        self.assertFalse(m.enabled({}))
        self.assertTrue(m.enabled({m.ENABLED: '1'}))
        self.assertFalse(m.enabled({m.ENABLED: '0'}))
        self.assertFalse(m.enabled({m.ENABLED: '0', '_mcp_token_hash': 'abc'}))
        self.assertTrue(m.enabled({m.ENABLED: '1', '_mcp_token_hash': ''}))

    def test_permission_defaults_are_least_privilege(self):
        self.assertEqual(m.permissions({}), {'scan': True, 'delete': False, 'active': False, 'private': False})
        self.assertEqual(m.permissions({m.ALLOW_DELETE: '1', m.ALLOW_SCAN: '0'})['delete'], True)
        self.assertEqual(m.permissions({m.ALLOW_SCAN: '0'})['scan'], False)

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

    def test_public_status_ignores_the_retired_shared_token(self):
        saved = {m.ENABLED: '1', '_mcp_token_hash': 'deadbeef', '_mcp_token_hint': 'sfmcp_ab12'}
        status = m.public_status(saved)
        self.assertNotIn('deadbeef', str(status))
        self.assertNotIn('hasToken', status)
        self.assertEqual(set(status), {'enabled', 'permissions', 'listening', 'port'})
