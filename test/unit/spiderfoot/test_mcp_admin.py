# test/unit/spiderfoot/test_mcp_admin.py
"""Settings > Agent (MCP): the admin API and the settings fragment."""
import json
import re
from unittest import mock

import pytest
from flask import render_template

from spiderfoot import SpiderFootDb
from spiderfoot.app import create_app
from spiderfoot.services import mcp_auth

SECRET = 'zq-internal-detail-9431'


@pytest.fixture
def app(tmp_path):
    path = str(tmp_path / 'x.db')
    SpiderFootDb({'__database': path}, init=True)
    app = create_app(config={'__database': path, '__modules__': {}, '__correlationrules__': [], '_debug': '0'})
    app.config['TESTING'] = True
    app.config['SF_USERS'] = {}
    return app


@pytest.fixture
def client(app):
    c = app.test_client()
    html = c.get('/').data.decode()
    token = re.search(r'<meta name="csrf-token" content="([^"]+)"', html).group(1)
    c.environ_base['HTTP_X_CSRF_TOKEN'] = token
    return c


def saved(app):
    return SpiderFootDb(app.config['SF_CONFIG']).configGet()


class TestCsrf:
    def test_posts_need_csrf(self, app):
        c = app.test_client()
        for path in ('/api/mcp/settings', '/api/mcp/token', '/api/mcp/token/revoke'):
            assert c.post(path, json={}).status_code == 403

    def test_get_needs_no_csrf(self, app):
        assert app.test_client().get('/api/mcp/settings').status_code == 200


class TestSettings:
    def test_defaults(self, client):
        d = client.get('/api/mcp/settings').get_json()
        assert d['enabled'] is False
        assert d['permissions'] == {'scan': True, 'delete': False, 'active': False, 'private': False}
        assert 'token' not in d

    def test_write_permissions_only_touches_given_keys(self, client, app):
        r = client.post('/api/mcp/settings', json={'allow_delete': True, 'allow_scan': False})
        assert r.status_code == 200
        assert r.get_json()['permissions'] == {'scan': False, 'delete': True, 'active': False, 'private': False}
        s = saved(app)
        assert s[mcp_auth.ALLOW_DELETE] == '1' and s[mcp_auth.ALLOW_SCAN] == '0'
        assert mcp_auth.ALLOW_ACTIVE not in s and mcp_auth.ENABLED not in s
        assert client.get('/api/mcp/settings').get_json()['permissions']['delete'] is True

    @pytest.mark.parametrize('body', [None, [], {}, {'enabled': 'yes'}, {'allow_scan': 1}, {'allow_scan': None},
                                      {'allow_scan': True, 'bogus': True}, {'_mcp_token_hash': True}])
    def test_validation(self, client, app, body):
        r = client.post('/api/mcp/settings', json=body)
        assert r.status_code == 400
        assert set(r.get_json()) == {'error'}
        assert mcp_auth.ALLOW_SCAN not in saved(app)

    def test_not_json(self, client):
        r = client.post('/api/mcp/settings', data='enabled=1', content_type='text/plain')
        assert r.status_code == 400

    def test_enable_needs_no_shared_token(self, client, app):
        # Users hold personal tokens now, so the switch is all an operator sets
        r = client.post('/api/mcp/settings', json={'enabled': True})
        assert r.status_code == 200 and r.get_json()['enabled'] is True
        assert mcp_auth.enabled(saved(app))

    def test_status_has_no_token_fields(self, client):
        d = client.get('/api/mcp/settings').get_json()
        assert 'hasToken' not in d and 'tokenHint' not in d and d['isAdmin'] is True

    def test_retired_shared_token_removed_from_the_database(self, app):
        path = app.config['SF_CONFIG']['__database']
        import sqlite3
        conn = sqlite3.connect(path)
        conn.execute("REPLACE INTO tbl_config VALUES ('GLOBAL', '_mcp_token_hash', 'deadbeef')")
        conn.commit()
        conn.close()
        assert '_mcp_token_hash' not in saved(app)  # opening the database migrates it away


class TestToken:
    def test_token_shown_once_and_only_hash_stored(self, client, app):
        r = client.post('/api/mcp/tokens', json={'name': 'laptop'})
        assert r.status_code == 200
        d = r.get_json()
        token = d['token']
        assert token.startswith('sfmcp_')
        [t] = d['tokens']
        assert t['name'] == 'laptop' and t['hint'] == token[:10] and t['last_used'] == 0 and t['expires']
        assert 'hash' not in t
        db = SpiderFootDb(app.config['SF_CONFIG'])
        row = db.mcpTokenByHash(mcp_auth.hash_token(token))
        assert row and row['name'] == 'laptop'
        assert token not in json.dumps(saved(app))
        assert 'no-store' in r.headers['Cache-Control']

        later = client.get('/api/mcp/tokens')
        text = later.get_data(as_text=True)
        assert token not in text and mcp_auth.hash_token(token) not in text
        assert token not in client.get('/frag/settings-section?section=mcp').get_data(as_text=True)

    def test_defaults_and_validation(self, client):
        d = client.post('/api/mcp/tokens', json={}).get_json()
        assert d['tokens'][0]['name'] == 'Agent'
        t = d['tokens'][0]
        assert abs((t['expires'] - t['created']) - 90 * 86400) < 5  # 90 days unless told otherwise
        never = client.post('/api/mcp/tokens', json={'name': 'x\x00y\n' + 'z' * 100, 'days': 0}).get_json()
        newest = never['tokens'][0]
        assert newest['expires'] is None and len(newest['name']) <= 60 and '\x00' not in newest['name']
        for bad in ({'days': -1}, {'days': 'soon'}, {'days': True}, {'days': 99999}):
            assert client.post('/api/mcp/tokens', json=bad).status_code == 400

    def test_limit_per_user(self, client):
        for _ in range(25):
            assert client.post('/api/mcp/tokens', json={}).status_code == 200
        assert client.post('/api/mcp/tokens', json={}).status_code == 400

    def test_revoke_own_token(self, client, app):
        d = client.post('/api/mcp/tokens', json={'name': 'a'}).get_json()
        tid = d['tokens'][0]['id']
        r = client.delete(f'/api/mcp/tokens/{tid}')
        assert r.status_code == 200 and r.get_json()['tokens'] == []
        assert SpiderFootDb(app.config['SF_CONFIG']).mcpTokenByHash(mcp_auth.hash_token(d['token'])) is None
        assert client.delete(f'/api/mcp/tokens/{tid}').status_code == 404

    def test_logs_carry_no_token(self, client, caplog):
        import logging
        with caplog.at_level(logging.INFO):
            d = client.post('/api/mcp/tokens', json={}).get_json()
            client.post('/api/mcp/settings', json={'allow_delete': True})
            client.delete(f"/api/mcp/tokens/{d['tokens'][0]['id']}")
        text = caplog.text
        assert 'MCP token created' in text and 'MCP permissions changed: scan=1 delete=1 active=0 private=0' in text
        assert d['token'] not in text and mcp_auth.hash_token(d['token']) not in text

    def test_old_endpoints_are_gone(self, client):
        assert client.post('/api/mcp/token').status_code == 404
        assert client.post('/api/mcp/token/revoke').status_code == 404


class TestNoExceptionText:
    @pytest.mark.parametrize('method,path,body', [
        ('get', '/api/mcp/settings', None),
        ('post', '/api/mcp/settings', {'allow_scan': True}),
        ('get', '/api/mcp/tokens', None),
        ('post', '/api/mcp/tokens', {}),
        ('delete', '/api/mcp/tokens/1', None),
    ])
    def test_failures_are_generic(self, client, method, path, body):
        db = mock.Mock()
        db.configGet.side_effect = RuntimeError(SECRET)
        db.configSet.side_effect = RuntimeError(SECRET)
        db.mcpTokenList.side_effect = RuntimeError(SECRET)
        db.mcpTokenRevoke.side_effect = RuntimeError(SECRET)
        with mock.patch('spiderfoot.blueprints.mcp_admin._db', return_value=db), \
                mock.patch('spiderfoot.blueprints.mcp_admin.identity.current_user_id', return_value=1):
            r = getattr(client, method)(path, json=body) if body is not None else getattr(client, method)(path)
        assert r.status_code == 500
        assert SECRET not in r.get_data(as_text=True)
        assert set(r.get_json()) == {'error'}


class TestFragment:
    def render(self, app, **env):
        saved_cfg = env.pop('saved', {})
        with app.test_request_context('/'):
            with mock.patch.dict('os.environ', env):
                return render_template('fragments/settings_mcp.html', st=dict(mcp_auth.public_status(saved_cfg), isAdmin=True, sso=False),
                                       tokens=[])

    def test_nav_entry(self, client):
        assert "'Agent (MCP)'" in open('spiderfoot/templates/pages/settings.html').read()
        assert 'Agent (MCP)' in client.get('/opts').get_data(as_text=True)

    def test_not_listening(self, app):
        with mock.patch.dict('os.environ', {}, clear=False):
            import os
            os.environ.pop('SF_MCP_PORT', None)
            html = self.render(app)
        assert 'SF_MCP_PORT' in html and 'mcpSettings(' in html
        assert '"listening": false' in html
        for name in ('list_modules', 'get_scan_log', 'create_scan', 'delete_scan', 'rerun_scan', 'validate_target'):
            assert name in html
        assert 'Bearer &lt;your token&gt;' in html or 'Bearer <your token>' in html

    def test_listening(self, app):
        html = self.render(app, saved={mcp_auth.ENABLED: '1'}, SF_MCP_PORT='5093')
        assert '"port": 5093' in html and '"listening": true' in html

    def test_section_route(self, client, app):
        r = client.get('/frag/settings-section?section=mcp')
        assert r.status_code == 200 and 'Agent (MCP)' in r.get_data(as_text=True)
        d = client.post('/api/mcp/tokens', json={'name': 'phone'}).get_json()
        html = client.get('/frag/settings-section?section=mcp').get_data(as_text=True)
        assert 'phone' in html and d['token'] not in html and mcp_auth.hash_token(d['token']) not in html
