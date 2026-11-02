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
        assert d['enabled'] is False and d['hasToken'] is False
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

    def test_enable_needs_a_token(self, client, app):
        r = client.post('/api/mcp/settings', json={'enabled': True})
        assert r.status_code == 400
        assert 'token' in r.get_json()['error'].lower()
        assert mcp_auth.ENABLED not in saved(app)
        # Disabling without a token is fine
        assert client.post('/api/mcp/settings', json={'enabled': False}).status_code == 200

    def test_enable_after_token(self, client, app):
        client.post('/api/mcp/token')
        r = client.post('/api/mcp/settings', json={'enabled': True})
        assert r.status_code == 200 and r.get_json()['enabled'] is True
        assert mcp_auth.enabled(saved(app))


class TestToken:
    def test_token_shown_once_and_only_hash_stored(self, client, app):
        r = client.post('/api/mcp/token')
        assert r.status_code == 200
        d = r.get_json()
        token = d['token']
        assert token.startswith('sfmcp_') and d['hasToken'] and d['tokenHint'] == token[:10]
        assert d['enabled'] is False  # generating does not enable
        s = saved(app)
        assert s[mcp_auth.TOKEN_HASH] == mcp_auth.hash_token(token)
        assert token not in json.dumps(s)
        assert mcp_auth.verify(token, s)
        assert 'no-store' in r.headers['Cache-Control']

        later = client.get('/api/mcp/settings')
        text = later.get_data(as_text=True)
        assert token not in text and s[mcp_auth.TOKEN_HASH] not in text
        assert 'token' not in later.get_json()
        assert token not in client.get('/frag/settings-section?section=mcp').get_data(as_text=True)

    def test_rotation_invalidates_old_token(self, client, app):
        old = client.post('/api/mcp/token').get_json()['token']
        new = client.post('/api/mcp/token').get_json()['token']
        assert old != new
        s = saved(app)
        assert not mcp_auth.verify(old, s) and mcp_auth.verify(new, s)

    def test_status_never_has_hash(self, client, app):
        client.post('/api/mcp/token')
        h = saved(app)[mcp_auth.TOKEN_HASH]
        for resp in (client.get('/api/mcp/settings'), client.post('/api/mcp/settings', json={'allow_scan': True})):
            assert h not in resp.get_data(as_text=True)

    def test_revoke_disables(self, client, app):
        token = client.post('/api/mcp/token').get_json()['token']
        client.post('/api/mcp/settings', json={'enabled': True})
        r = client.post('/api/mcp/token/revoke')
        assert r.status_code == 200
        d = r.get_json()
        assert d['enabled'] is False and d['hasToken'] is False and d['tokenHint'] == ''
        s = saved(app)
        assert not mcp_auth.verify(token, s) and not mcp_auth.enabled(s)

    def test_logs_carry_no_token(self, client, caplog):
        import logging
        with caplog.at_level(logging.INFO):
            token = client.post('/api/mcp/token').get_json()['token']
            client.post('/api/mcp/settings', json={'allow_delete': True})
            client.post('/api/mcp/token/revoke')
        text = caplog.text
        assert 'MCP token rotated' in text and 'MCP permissions changed: scan=1 delete=1 active=0 private=0' in text
        assert token not in text and mcp_auth.hash_token(token) not in text


class TestNoExceptionText:
    @pytest.mark.parametrize('method,path,body', [
        ('get', '/api/mcp/settings', None),
        ('post', '/api/mcp/settings', {'allow_scan': True}),
        ('post', '/api/mcp/token', None),
        ('post', '/api/mcp/token/revoke', None),
    ])
    def test_failures_are_generic(self, client, method, path, body):
        with mock.patch('spiderfoot.blueprints.mcp_admin.get_db', side_effect=RuntimeError(SECRET)):
            r = getattr(client, method)(path, json=body) if body is not None else getattr(client, method)(path)
        assert r.status_code == 500
        assert SECRET not in r.get_data(as_text=True)
        assert set(r.get_json()) == {'error'}

    def test_db_write_failure_is_generic(self, client):
        db = mock.Mock()
        db.configGet.return_value = {}
        db.configSet.side_effect = IOError(SECRET)
        with mock.patch('spiderfoot.blueprints.mcp_admin.get_db', return_value=db):
            r = client.post('/api/mcp/token')
        assert r.status_code == 500 and SECRET not in r.get_data(as_text=True)


class TestFragment:
    def render(self, app, **env):
        saved_cfg = env.pop('saved', {})
        with app.test_request_context('/'):
            with mock.patch.dict('os.environ', env):
                return render_template('fragments/settings_mcp.html', st=mcp_auth.public_status(saved_cfg))

    def test_nav_entry(self, client):
        assert "'Agent (MCP)'" in open('spiderfoot/templates/pages/settings.html').read()
        assert 'Agent (MCP)' in client.get('/opts').get_data(as_text=True)

    def test_no_token_not_listening(self, app):
        with mock.patch.dict('os.environ', {}, clear=False):
            import os
            os.environ.pop('SF_MCP_PORT', None)
            html = self.render(app)
        assert 'SF_MCP_PORT' in html and 'mcpSettings(' in html
        assert '"hasToken": false' in html and '"listening": false' in html
        for name in ('list_modules', 'get_scan_log', 'create_scan', 'delete_scan', 'rerun_scan', 'validate_target'):
            assert name in html
        assert 'Bearer &lt;your token&gt;' in html or 'Bearer <your token>' in html

    def test_token_listening(self, app):
        s = mcp_auth.token_settings('deadbeef' * 8, 'sfmcp_ab12', 1700000000)
        s[mcp_auth.ENABLED] = '1'
        html = self.render(app, saved=s, SF_MCP_PORT='5093')
        assert '"hasToken": true' in html and '"port": 5093' in html and '"listening": true' in html
        assert 'sfmcp_ab12' in html
        assert 'deadbeef' * 8 not in html  # the stored hash never reaches the page

    def test_section_route(self, client, app):
        r = client.get('/frag/settings-section?section=mcp')
        assert r.status_code == 200 and 'Agent (MCP)' in r.get_data(as_text=True)
        client.post('/api/mcp/token')
        html = client.get('/frag/settings-section?section=mcp').get_data(as_text=True)
        h = saved(app)[mcp_auth.TOKEN_HASH]
        assert '"hasToken": true' in html and h not in html
