from unittest import mock

from spiderfoot.mcp import server, wsgi
from spiderfoot.services import mcp_auth


class TestHealth:
    def test_open_and_minimal(self, env):
        client = env.client()
        assert client.get('/health').get_json() == {'ok': True}
        env.configure(enabled=0)
        resp = client.get('/health')
        assert resp.status_code == 200
        assert resp.get_json() == {'ok': True}

    def test_no_version_or_headers_leak(self, env):
        resp = env.client().get('/health')
        assert resp.get_data(as_text=True) == '{"ok":true}'

    def test_unknown_path(self, env):
        assert env.client().get('/elsewhere').status_code == 404


class TestAuth:
    def test_valid_token(self, env):
        assert env.post(env.rpc('ping')).status_code == 200

    def test_missing_token(self, env):
        resp = env.post(env.rpc('ping'), token=None)
        assert resp.status_code == 401
        assert resp.headers['WWW-Authenticate'] == 'Bearer'

    def test_invalid_token(self, env):
        resp = env.post(env.rpc('ping'), token='sfmcp_not-the-token')
        assert resp.status_code == 401
        assert resp.headers['WWW-Authenticate'] == 'Bearer'

    def test_wrong_scheme(self, env):
        resp = env.post(env.rpc('ping'), token=None, headers={'Authorization': 'Basic ' + env.token})
        assert resp.status_code == 401

    def test_disabled_server(self, env):
        env.configure(enabled=0)
        resp = env.post(env.rpc('ping'))
        assert resp.status_code == 403
        assert resp.get_json() == {'error': 'MCP server is disabled'}
        # a wrong token learns nothing either
        assert env.post(env.rpc('ping'), token='sfmcp_bad').status_code == 403

    def test_retired_shared_token_is_ignored(self, env):
        # An old database may still hold the shared token's hash; it grants nothing
        env.db().configSet({'_mcp_token_hash': mcp_auth.hash_token('sfmcp_old-shared-token')})
        assert env.post(env.rpc('ping'), token='sfmcp_old-shared-token').status_code == 401

    def test_revoked_token_stops_working_immediately(self, env):
        assert env.post(env.rpc('ping')).status_code == 200
        env.db().mcpTokenRevoke(env.admin['id'], env.db().mcpTokenList(env.admin['id'])[0]['id'])
        assert env.post(env.rpc('ping')).status_code == 401

    def test_expired_token_is_refused(self, env):
        import time
        token = env.token_for(env.admin['id'], expires=int(time.time()) - 5)
        assert env.post(env.rpc('ping'), token=token).status_code == 401

    def test_settings_are_read_on_every_request(self, env):
        client = env.client()
        assert env.post(env.rpc('ping'), client=client).status_code == 200
        env.configure(enabled=0)
        assert env.post(env.rpc('ping'), client=client).status_code == 403
        env.configure(enabled=1)
        assert env.post(env.rpc('ping'), client=client).status_code == 200

    def test_get_is_405_with_note(self, env):
        resp = env.client().get('/mcp', headers={'Authorization': 'Bearer ' + env.token})
        assert resp.status_code == 405
        assert 'note' in resp.get_json()
        assert resp.headers['Allow'] == 'POST'

    def test_get_without_token_is_401(self, env):
        assert env.client().get('/mcp').status_code == 401

    def test_database_failure_fails_closed(self, env):
        with mock.patch('spiderfoot.mcp.context.McpContext.saved', side_effect=OSError('boom')):
            resp = env.post(env.rpc('ping'))
        assert resp.status_code == 503
        assert 'boom' not in resp.get_data(as_text=True)


class TestThrottle:
    def test_blocks_after_ten_failures(self, env):
        client = env.client()
        statuses = [env.post(env.rpc('ping'), token='sfmcp_bad', client=client).status_code for _ in range(12)]
        assert statuses[:10] == [401] * 10
        assert statuses[10:] == [429, 429]
        blocked = env.post(env.rpc('ping'), token='sfmcp_bad', client=client)
        assert int(blocked.headers['Retry-After']) >= 1
        # the throttle protects the token too: even the right one waits
        assert env.post(env.rpc('ping'), client=client).status_code == 429

    def test_successful_calls_are_not_counted(self, env):
        client = env.client()
        assert all(env.post(env.rpc('ping'), client=client).status_code == 200 for _ in range(30))

    def test_window_expires(self):
        now = [0.0]
        t = wsgi.FailureThrottle(limit=3, window=60, clock=lambda: now[0])
        for _ in range(3):
            t.record_failure('1.2.3.4')
        assert t.retry_after('1.2.3.4') > 0
        assert t.retry_after('5.6.7.8') == 0
        now[0] = 61
        assert t.retry_after('1.2.3.4') == 0

    def test_table_is_bounded(self):
        t = wsgi.FailureThrottle(max_clients=5)
        for i in range(50):
            t.record_failure(f'10.0.0.{i}')
        assert len(t._failures) <= 5


class TestOrigin:
    def test_no_origin_is_fine(self, env):
        assert env.post(env.rpc('ping')).status_code == 200

    def test_same_host_and_local_origins(self, env):
        for origin, host in [('http://localhost:3000', 'mcp.example.net'), ('http://127.0.0.1', 'mcp.example.net'),
                             ('http://[::1]:8080', 'mcp.example.net'), ('https://mcp.example.net', 'mcp.example.net:5092'),
                             ('https://MCP.example.net:9', 'mcp.example.net')]:
            resp = env.post(env.rpc('ping'), headers={'Origin': origin, 'Host': host})
            assert resp.status_code == 200, (origin, host)

    def test_foreign_origin_is_rejected(self, env):
        for origin in ('http://evil.example', 'http://localhost.evil.example', 'null', 'file://', 'http://127.0.0.1.evil.example'):
            resp = env.post(env.rpc('ping'), headers={'Origin': origin, 'Host': 'mcp.example.net'})
            assert resp.status_code == 403, origin

    def test_origin_checked_before_token(self, env):
        resp = env.post(env.rpc('ping'), token=None, headers={'Origin': 'http://evil.example'})
        assert resp.status_code == 403


class TestListener:
    def test_not_started_without_port(self, env):
        with mock.patch.dict('os.environ', {}, clear=False) as environ:
            environ.pop('SF_MCP_PORT', None)
            with mock.patch.object(server, 'make_server') as make:
                assert server.start_listener(env.app) is None
                make.assert_not_called()

    def test_zero_port_is_off(self, env):
        with mock.patch.dict('os.environ', {'SF_MCP_PORT': '0'}), mock.patch.object(server, 'make_server') as make:
            assert server.start_listener(env.app) is None
            make.assert_not_called()

    def test_starts_threaded_server_on_configured_address(self, env):
        fake = mock.Mock()
        with mock.patch.dict('os.environ', {'SF_MCP_PORT': '5092', 'SF_MCP_HOST': '127.0.0.1'}), \
                mock.patch.object(server, 'make_server', return_value=fake) as make:
            assert server.start_listener(env.app) is fake
        args, kwargs = make.call_args
        assert args[:2] == ('127.0.0.1', 5092)
        assert kwargs == {'threaded': True}
        import time
        for _ in range(50):
            if fake.serve_forever.called:
                break
            time.sleep(0.01)
        fake.serve_forever.assert_called_once()

    def test_bind_failure_does_not_raise(self, env):
        with mock.patch.dict('os.environ', {'SF_MCP_PORT': '5092'}), mock.patch.object(server, 'make_server', side_effect=OSError('in use')):
            assert server.start_listener(env.app) is None
