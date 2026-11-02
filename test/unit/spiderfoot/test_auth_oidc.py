"""Native OIDC sign-in against a fake provider (no network): the happy paths and every way a token can be wrong."""
import base64
import json
import logging
import time
from urllib.parse import parse_qs, quote, urlsplit

import pytest

from test.unit import identity_helpers as h

pytestmark = pytest.mark.usefixtures('no_network')


@pytest.fixture
def no_network(monkeypatch):
    import requests

    def refuse(*a, **k):
        raise AssertionError('the tests must not touch the network')
    monkeypatch.setattr(requests, 'get', refuse)
    monkeypatch.setattr(requests, 'post', refuse)


@pytest.fixture
def idp(monkeypatch):
    provider = h.FakeIdp()
    provider.install(monkeypatch)
    yield provider
    h.oidc.clear_cache()


@pytest.fixture
def app(tmp_path, idp):
    application = h.make_app(tmp_path)
    h.configure_sso(application)
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def start(client, next_url='/'):
    resp = client.get('/auth/login?start=1&next=' + quote(next_url, safe=''))
    assert resp.status_code == 302, resp.get_data(as_text=True)
    return resp.headers['Location']


def sign_in_flow(client, idp, claims=None, next_url='/', **overrides):
    """Drive login to the callback; returns the callback response."""
    auth_url = start(client, next_url)
    code, q = idp.issue_code(auth_url, claims, **overrides)
    return client.get('/auth/callback?code=' + code + '&state=' + q['state'])


class TestUnauthenticated:
    def test_browser_is_sent_to_the_login_page(self, client):
        r = client.get('/scaninfo?id=ABC', headers={'Accept': 'text/html'})
        assert r.status_code == 302
        assert r.headers['Location'] == '/auth/login?next=/scaninfo%3Fid%3DABC'

    def test_navigation_header_also_counts(self, client):
        r = client.get('/', headers={'Sec-Fetch-Mode': 'navigate'})
        assert r.status_code == 302 and r.headers['Location'].startswith('/auth/login')

    def test_script_requests_get_401_json(self, client):
        r = client.get('/api/scanlist', headers={'Sec-Fetch-Mode': 'cors', 'Accept': 'application/json'})
        assert r.status_code == 401 and r.get_json()['login'] == '/auth/login'
        assert 'WWW-Authenticate' not in r.headers

    def test_htmx_requests_are_told_to_redirect(self, client):
        r = client.get('/frag/scan-table', headers={'HX-Request': 'true'})
        assert r.status_code == 401 and r.headers['HX-Redirect'] == '/auth/login'

    def test_api_clients_get_401_without_a_basic_popup_when_there_is_no_password_file(self, client):
        r = client.get('/api/scanlist')
        assert r.status_code == 401 and 'WWW-Authenticate' not in r.headers

    def test_health_check_and_static_stay_open(self, client):
        assert client.get('/api/ping').status_code == 200
        assert client.get('/static/css/custom.css').status_code == 200

    def test_login_page_offers_sso(self, client):
        r = client.get('/auth/login?next=/x')
        html = r.get_data(as_text=True)
        assert r.status_code == 200 and 'Sign in with SSO' in html and 'start=1' in html
        assert 'Basic authentication' not in html

    def test_login_page_mentions_basic_only_when_password_users_exist(self, app, client):
        app.config['SF_USERS'] = {'robot': 'x'}
        assert 'HTTP Basic authentication' in client.get('/auth/login').get_data(as_text=True)

    def test_login_page_without_sso(self, tmp_path):
        application = h.make_app(tmp_path)
        application.config['SF_USERS'] = {'robot': 'x'}
        html = application.test_client().get('/auth/login').get_data(as_text=True)
        assert 'not set up' in html and 'Sign in with SSO' not in html

    def test_password_file_users_still_get_the_basic_challenge_from_api_clients(self, app, client):
        app.config['SF_USERS'] = {'robot': 'x'}
        r = client.get('/api/scanlist')
        assert r.status_code == 401 and r.headers['WWW-Authenticate'].startswith('Basic')
        browser_script = client.get('/api/scanlist', headers={'Sec-Fetch-Mode': 'cors'})
        assert 'WWW-Authenticate' not in browser_script.headers  # never pop the browser dialog for a script call


class TestHappyPath:
    def test_admin_login(self, app, client, idp):
        r = sign_in_flow(client, idp, idp.claims('root', groups=['sf-admins', 'x']), next_url='/scaninfo?id=ZZ')
        assert r.status_code == 302 and r.headers['Location'] == '/scaninfo?id=ZZ'
        me = client.get('/auth/me').get_json()
        assert me['role'] == 'admin' and me['isAdmin'] and me['username'] == 'root' and me['auth'] == 'oidc'
        assert sorted(me['groups']) == ['sf-admins', 'x'] and me['email'] == 'root@example.test'
        row = h.db(app).userGetBySubject('root')
        assert row and row['role'] == 'admin' and row['last_login'] > 0 and row['groups'] == ['sf-admins', 'x']

    def test_user_login(self, app, client, idp):
        sign_in_flow(client, idp, idp.claims('ursula', groups=['sf-users']))
        me = client.get('/auth/me').get_json()
        assert me['role'] == 'user' and not me['isAdmin']

    def test_cookie_flags_and_lifetime(self, app, client, idp):
        h.db(app).configSet({'_auth_session_hours': '2'})
        r = sign_in_flow(client, idp)
        cookie = [c for c in r.headers.getlist('Set-Cookie') if c.startswith('session=')][0]
        assert 'HttpOnly' in cookie and 'SameSite=Lax' in cookie and 'Secure' not in cookie
        assert 'Expires=' in cookie
        with client.session_transaction() as sess:
            assert abs(sess['exp'] - sess['iat'] - 7200) <= 1 and sess['uid']

    def test_cookie_is_secure_on_https(self, app, idp):
        client = app.test_client()
        client.get('/auth/login')  # nothing to see
        auth_url = client.get('/auth/login?start=1', base_url='https://sf.test').headers['Location']
        code, q = idp.issue_code(auth_url)
        r = client.get('/auth/callback?code=' + code + '&state=' + q['state'], base_url='https://sf.test')
        cookie = [c for c in r.headers.getlist('Set-Cookie') if c.startswith('session=')][0]
        assert 'Secure' in cookie and 'HttpOnly' in cookie

    def test_forwarded_proto_counts_only_when_a_proxy_is_trusted(self, app, idp):
        client = app.test_client()
        hdr = {'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'public.example'}
        auth_url = client.get('/auth/login?start=1', headers=hdr).headers['Location']
        assert parse_qs(urlsplit(auth_url).query)['redirect_uri'] == ['http://localhost/auth/callback']
        h.db(app).configSet({'_auth_trust_proxy': '1'})
        auth_url = client.get('/auth/login?start=1', headers=hdr).headers['Location']
        assert parse_qs(urlsplit(auth_url).query)['redirect_uri'] == ['https://public.example/auth/callback']

    def test_redirect_uri_override(self, app, client):
        h.db(app).configSet({'_oidc_redirect_uri': 'https://sf.example.com/auth/callback'})
        q = parse_qs(urlsplit(start(client)).query)
        assert q['redirect_uri'] == ['https://sf.example.com/auth/callback']

    def test_authorization_request_has_state_nonce_pkce_and_scopes(self, client):
        q = parse_qs(urlsplit(start(client)).query)
        assert q['client_id'] == [h.CLIENT_ID] and q['response_type'] == ['code']
        assert q['code_challenge_method'] == ['S256'] and len(q['code_challenge'][0]) >= 43
        assert len(q['state'][0]) >= 24 and len(q['nonce'][0]) >= 24
        assert q['scope'] == ['openid profile email groups']
        assert 'client_secret' not in q

    def test_login_regenerates_the_session(self, app, client, idp):
        with client.session_transaction() as sess:
            sess['fixated'] = 'attacker-value'
            sess['csrf_token'] = 'old-token'
        sign_in_flow(client, idp)
        with client.session_transaction() as sess:
            assert 'fixated' not in sess and sess['csrf_token'] != 'old-token'
            assert 'oidc_tx' not in sess

    def test_groups_are_refreshed_at_every_login(self, app, client, idp):
        sign_in_flow(client, idp, idp.claims('rita', groups=['sf-users', 'old']))
        client.get('/auth/logout')
        sign_in_flow(client, idp, idp.claims('rita', groups=['sf-users', 'new']))
        assert h.db(app).userGetBySubject('rita')['groups'] == ['new', 'sf-users']

    def test_groups_from_userinfo_when_the_token_has_none(self, app, client, idp):
        idp.userinfo_claims = {'sub': 'carl', 'groups': ['sf-admins']}
        sign_in_flow(client, idp, idp.claims('carl', groups=None))
        assert client.get('/auth/me').get_json()['role'] == 'admin'

    def test_userinfo_for_another_subject_is_ignored(self, app, client, idp):
        idp.userinfo_claims = {'sub': 'someone-else', 'groups': ['sf-admins']}
        h.db(app).configSet({'_oidc_user_groups': ''})
        sign_in_flow(client, idp, idp.claims('carl', groups=None))
        assert client.get('/auth/me').get_json()['role'] == 'user'

    def test_custom_groups_claim_and_scopes(self, app, client, idp):
        h.db(app).configSet({'_oidc_groups_claim': 'roles', '_oidc_scopes': 'openid email'})
        auth_url = start(client)
        assert parse_qs(urlsplit(auth_url).query)['scope'] == ['openid email']
        code, q = idp.issue_code(auth_url, idp.claims('dana', groups=None, roles=['sf-admins']))
        client.get('/auth/callback?code=' + code + '&state=' + q['state'])
        assert client.get('/auth/me').get_json()['role'] == 'admin'

    def test_public_client_without_a_secret_uses_pkce_only(self, app, client, idp, monkeypatch):
        h.db(app).configSet({'_oidc_client_secret': ''})
        seen = {}

        def post(url, data, basic=None):
            seen.update(data=data, basic=basic)
            raise h.oidc.OidcError('token_refused')
        monkeypatch.setattr(h.oidc, 'http_post_form', post)
        auth_url = start(client)
        code, q = idp.issue_code(auth_url)
        client.get('/auth/callback?code=' + code + '&state=' + q['state'])
        assert seen['basic'] is None and 'client_secret' not in seen['data'] and seen['data']['client_id'] == h.CLIENT_ID
        assert seen['data']['code_verifier']

    def test_secret_is_posted_when_the_provider_wants_it_there(self, app, client, idp):
        idp.discovery_doc['token_endpoint_auth_methods_supported'] = ['client_secret_post']
        h.oidc.clear_cache()
        sign_in_flow(client, idp)
        assert client.get('/auth/me').status_code == 200


class TestDenied:
    def test_outsider_gets_a_friendly_403_and_a_log_line(self, app, client, idp, caplog):
        with caplog.at_level(logging.WARNING, logger='spiderfoot.auth'):
            r = sign_in_flow(client, idp, idp.claims('mallory', groups=['nobody']))
        assert r.status_code == 403
        html = r.get_data(as_text=True)
        assert 'not in a group that may use SpiderFoot' in html and 'Sign out' in html
        assert 'login denied' in caplog.text and 'mallory' not in caplog.text
        assert h.db(app).userGetBySubject('mallory') is None  # no account is created for a denied login
        assert client.get('/auth/me', headers={'Accept': 'text/html'}).status_code == 302  # and there is no session

    def test_no_groups_at_all_is_denied_when_user_groups_are_required(self, app, client, idp):
        r = sign_in_flow(client, idp, idp.claims('nogroups', groups=None))
        assert r.status_code == 403

    def test_any_account_may_enter_when_no_user_group_is_configured(self, app, client, idp):
        h.db(app).configSet({'_oidc_user_groups': ''})
        r = sign_in_flow(client, idp, idp.claims('anyone', groups=None))
        assert r.status_code == 302 and client.get('/auth/me').get_json()['role'] == 'user'

    def test_losing_a_group_takes_effect_on_the_next_request(self, app, client, idp):
        sign_in_flow(client, idp, idp.claims('gone', groups=['sf-users']))
        assert client.get('/auth/me').status_code == 200
        h.db(app).userUpsert('gone', 'gone', groups=['nothing'], role='user', login=False)
        r = client.get('/auth/me')
        assert r.status_code == 403 and 'not allowed' in r.get_data(as_text=True).lower()

    def test_role_follows_the_mapping_as_it_changes(self, app, client, idp):
        sign_in_flow(client, idp, idp.claims('shift', groups=['sf-users']))
        assert client.get('/auth/me').get_json()['role'] == 'user'
        h.db(app).configSet({'_oidc_admin_groups': 'sf-users'})
        assert client.get('/auth/me').get_json()['role'] == 'admin'

    def test_previously_known_account_that_is_denied_has_its_groups_updated(self, app, client, idp):
        sign_in_flow(client, idp, idp.claims('flip', groups=['sf-users']))
        client.get('/auth/logout')
        r = sign_in_flow(client, idp, idp.claims('flip', groups=['elsewhere']))
        assert r.status_code == 403
        assert h.db(app).userGetBySubject('flip')['groups'] == ['elsewhere']


class TestBadTokens:
    @pytest.mark.parametrize('why,overrides', [
        ('wrong audience', {'aud': 'someone-elses-client'}),
        ('audience list without us', {'aud': ['a', 'b']}),
        ('wrong issuer', {'iss': 'https://evil.test'}),
        ('wrong nonce', {'nonce': 'not-the-nonce'}),
        ('expired', {'exp': int(time.time()) - 3600}),
        ('not yet valid', {'nbf': int(time.time()) + 3600}),
        ('no subject', {'sub': None}),
        ('no expiry', {'exp': None}),
        ('several audiences, wrong azp', {'aud': [h.CLIENT_ID, 'other'], 'azp': 'other'}),
    ])
    def test_rejected(self, app, client, idp, why, overrides):
        r = sign_in_flow(client, idp, idp.claims('eve', groups=['sf-admins']), **{k: v for k, v in overrides.items()})
        self._failed(client, r, app)

    def _failed(self, client, r, app):
        assert r.status_code == 302 and r.headers['Location'] == '/auth/login?error=failed', r.headers.get('Location')
        assert client.get('/auth/me', headers={'Accept': 'text/html'}).status_code == 302
        assert h.db(app).userList() == []

    def test_nonce_missing_from_token(self, app, client, idp, monkeypatch):
        claims = idp.claims('eve')
        original = idp.http_post_form

        def post(url, data, basic=None):
            out = original(url, data, basic)
            payload = idp.claims('eve')
            payload.pop('nonce', None)
            out['id_token'] = idp.mint(payload)
            return out
        monkeypatch.setattr(h.oidc, 'http_post_form', post)
        auth_url = start(client)
        code, q = idp.issue_code(auth_url, claims)
        r = client.get('/auth/callback?code=' + code + '&state=' + q['state'])
        self._failed(client, r, app)

    def test_signed_with_another_key(self, app, client, idp, monkeypatch):
        original = idp.http_post_form

        def post(url, data, basic=None):
            out = original(url, data, basic)
            out['id_token'] = idp.mint(idp.claims('eve', groups=['sf-admins'], nonce=parse_qs(urlsplit(auth_url).query)['nonce'][0]),
                                       key_name='attacker')
            return out
        monkeypatch.setattr(h.oidc, 'http_post_form', post)
        auth_url = start(client)
        code, q = idp.issue_code(auth_url)
        self._failed(client, client.get('/auth/callback?code=' + code + '&state=' + q['state']), app)

    def test_tampered_payload(self, app, client, idp, monkeypatch):
        original = idp.http_post_form

        def post(url, data, basic=None):
            out = original(url, data, basic)
            head, payload, sig = out['id_token'].split('.')
            fake = base64.urlsafe_b64encode(b'{"iss":"%s","aud":"%s","sub":"admin","exp":%d,"nonce":"x","groups":["sf-admins"]}'
                                            % (h.ISSUER.encode(), h.CLIENT_ID.encode(), int(time.time()) + 600)).rstrip(b'=').decode()
            out['id_token'] = '.'.join([head, fake, sig])
            return out
        monkeypatch.setattr(h.oidc, 'http_post_form', post)
        auth_url = start(client)
        code, q = idp.issue_code(auth_url)
        self._failed(client, client.get('/auth/callback?code=' + code + '&state=' + q['state']), app)

    @pytest.mark.parametrize('token_maker', ['none', 'hs256', 'garbage', 'opaque'])
    def test_unsafe_algorithms_and_junk(self, app, client, idp, monkeypatch, token_maker):
        original = idp.http_post_form
        claims = None

        def post(url, data, basic=None):
            out = original(url, data, basic)
            nonce = parse_qs(urlsplit(auth_url).query)['nonce'][0]
            payload = idp.claims('eve', groups=['sf-admins'], nonce=nonce)
            if token_maker == 'none':
                import json
                enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()  # noqa: E731
                out['id_token'] = enc({'alg': 'none', 'typ': 'JWT'}) + '.' + enc(payload) + '.'
            elif token_maker == 'hs256':
                from authlib.jose import jwt
                out['id_token'] = jwt.encode({'alg': 'HS256', 'kid': 'kid-main'}, payload, 'a-shared-secret-of-sufficient-length-x').decode()
            elif token_maker == 'garbage':
                out['id_token'] = 'not.a.jwt'
            else:
                out['id_token'] = 'opaque-value'
            return out
        monkeypatch.setattr(h.oidc, 'http_post_form', post)
        auth_url = start(client)
        code, q = idp.issue_code(auth_url, claims)
        self._failed(client, client.get('/auth/callback?code=' + code + '&state=' + q['state']), app)

    def test_state_mismatch(self, app, client, idp):
        auth_url = start(client)
        code, q = idp.issue_code(auth_url)
        r = client.get('/auth/callback?code=' + code + '&state=forged')
        assert r.headers['Location'] == '/auth/login?error=expired'

    def test_callback_without_a_started_login(self, client):
        r = client.get('/auth/callback?code=abc&state=def')
        assert r.status_code == 302 and 'error=expired' in r.headers['Location']

    def test_replayed_callback(self, app, client, idp):
        auth_url = start(client)
        code, q = idp.issue_code(auth_url)
        url = '/auth/callback?code=' + code + '&state=' + q['state']
        assert client.get(url).status_code == 302
        client.get('/auth/logout')
        assert 'error=expired' in client.get(url).headers['Location']

    def test_login_transaction_expires(self, app, client, idp):
        auth_url = start(client)
        code, q = idp.issue_code(auth_url)
        with client.session_transaction() as sess:
            sess['oidc_tx'] = dict(sess['oidc_tx'], at=int(time.time()) - 3600)
        assert 'error=expired' in client.get('/auth/callback?code=' + code + '&state=' + q['state']).headers['Location']

    def test_provider_error_is_not_echoed(self, client):
        start(client)
        with client.session_transaction() as sess:
            state = sess['oidc_tx']['state']
        r = client.get('/auth/callback?error=access_denied&error_description=SECRET-DETAIL&state=' + state)
        assert r.status_code == 302 and r.headers['Location'] == '/auth/login?error=failed'
        page = client.get(r.headers['Location']).get_data(as_text=True)
        assert 'SECRET-DETAIL' not in page and 'access_denied' not in page and 'Sign-in failed' in page

    def test_token_endpoint_failure(self, app, client, idp):
        idp.fail_token = True
        auth_url = start(client)
        code, q = idp.issue_code(auth_url)
        assert client.get('/auth/callback?code=' + code + '&state=' + q['state']).headers['Location'] == '/auth/login?error=failed'

    def test_unreachable_provider(self, app, client, monkeypatch):
        def boom(url, headers=None):
            raise h.oidc.OidcError('unreachable', 'The identity provider could not be reached.')
        monkeypatch.setattr(h.oidc, 'http_get_json', boom)
        h.oidc.clear_cache()
        r = client.get('/auth/login?start=1')
        assert r.headers['Location'] == '/auth/login?error=unavailable'
        assert 'could not be reached' in client.get(r.headers['Location']).get_data(as_text=True)

    def test_discovery_for_another_issuer_is_refused(self, app, client, idp):
        idp.discovery_doc['issuer'] = 'https://evil.test'
        h.oidc.clear_cache()
        assert client.get('/auth/login?start=1').headers['Location'] == '/auth/login?error=unavailable'

    def test_insecure_endpoints_are_refused(self, app, client, idp):
        idp.discovery_doc['token_endpoint'] = 'http://idp.test/token'
        h.oidc.clear_cache()
        assert client.get('/auth/login?start=1').headers['Location'] == '/auth/login?error=unavailable'

    def test_unknown_key_triggers_one_refresh_then_fails(self, app, client, idp):
        r = sign_in_flow(client, idp)  # warms the key cache
        assert r.status_code == 302
        client.get('/auth/logout')
        before = len([x for x in idp.requests if x[1].endswith('/keys')])
        # rotate to a new key: the provider serves it, the cached copy does not have it
        idp.key_name = 'rotated'
        r = sign_in_flow(client, idp)
        assert r.status_code == 302 and client.get('/auth/me').status_code == 200
        assert len([x for x in idp.requests if x[1].endswith('/keys')]) == before + 1


class TestRedirects:
    @pytest.mark.parametrize('target', [
        '//evil.example/x', 'https://evil.example/', 'http://evil.example', '/\\evil.example', '\\\\evil.example',
        'javascript:alert(1)', '/%2f/evil.example', '/%5cevil.example', 'evil.example', '/ok\r\nSet-Cookie: x=1', '/' + 'a' * 600,
        '/auth/callback?code=1', '', '/\t/evil.example',
    ])
    def test_open_redirects_are_neutralised(self, app, client, idp, target):
        r = sign_in_flow(client, idp, next_url=target)
        assert r.status_code == 302 and r.headers['Location'] == '/', target

    @pytest.mark.parametrize('target', ['/', '/scaninfo?id=ABC123', '/opts', '/newscan#top'])
    def test_same_site_paths_are_kept(self, app, client, idp, target):
        assert sign_in_flow(client, idp, next_url=target).headers['Location'] == target

    def test_login_page_keeps_the_safe_next(self, client):
        html = client.get('/auth/login?next=//evil.example').get_data(as_text=True)
        assert 'evil.example' not in html


class TestLogout:
    def test_clears_the_session_and_uses_the_provider_end_session_endpoint(self, app, client, idp):
        sign_in_flow(client, idp)
        r = client.get('/auth/logout')
        assert r.status_code == 302 and r.headers['Location'].startswith('https://idp.test/logout?')
        assert 'post_logout_redirect_uri=' in r.headers['Location'] and 'client_id=sf-client' in r.headers['Location']
        assert client.get('/api/scanlist').status_code == 401

    def test_without_an_end_session_endpoint(self, app, client, idp):
        del idp.discovery_doc['end_session_endpoint']
        h.oidc.clear_cache()
        sign_in_flow(client, idp)
        r = client.get('/auth/logout')
        assert r.headers['Location'] == '/auth/login?signed_out=1'
        assert 'signed out' in client.get(r.headers['Location']).get_data(as_text=True)
        assert client.get('/auth/me').status_code == 401

    def test_logout_works_with_post_and_csrf(self, app, client, idp):
        sign_in_flow(client, idp)
        with client.session_transaction() as sess:
            token = sess['csrf_token']
        assert client.post('/auth/logout').status_code == 403
        assert client.post('/auth/logout', headers={'X-CSRF-Token': token}).status_code == 302


class TestSessionLifetime:
    def test_session_ends_after_the_lifetime(self, app, client, idp):
        h.db(app).configSet({'_auth_session_hours': '1'})
        sign_in_flow(client, idp)
        with client.session_transaction() as sess:
            sess['iat'] -= 3 * 3600
            sess['exp'] = int(time.time()) - 5
        assert client.get('/api/scanlist').status_code == 401

    def test_shortening_the_setting_applies_to_existing_sessions(self, app, client, idp):
        h.db(app).configSet({'_auth_session_hours': '12'})
        sign_in_flow(client, idp)
        assert client.get('/api/scanlist').status_code == 200
        with client.session_transaction() as sess:
            sess['iat'] -= 2 * 3600
        h.db(app).configSet({'_auth_session_hours': '1'})
        assert client.get('/api/scanlist').status_code == 401

    def test_a_forged_session_is_worthless(self, app, client):
        client.set_cookie('session', 'eyJ1aWQiOjF9.AAAAAA.invalid')
        assert client.get('/api/scanlist').status_code == 401

    def test_session_for_a_deleted_user(self, app, client, idp):
        sign_in_flow(client, idp)
        import sqlite3
        conn = sqlite3.connect(app.config['SF_CONFIG']['__database'])
        conn.execute('DELETE FROM tbl_users')
        conn.commit()
        conn.close()
        assert client.get('/api/scanlist').status_code == 401


class TestBasicAuthKeepsWorking:
    def test_basic_users_are_administrators_and_skip_csrf(self, tmp_path, idp):
        from spiderfoot.app import _hash_password
        app = h.make_app(tmp_path)
        h.configure_sso(app)
        app.config['SF_USERS'] = {'robot': _hash_password('pw-1234')}
        client = app.test_client()
        auth = {'Authorization': 'Basic ' + base64.b64encode(b'robot:pw-1234').decode()}
        assert client.get('/api/scanlist', headers=auth).status_code == 200
        assert client.get('/auth/me', headers=auth).get_json()['auth'] == 'basic'
        assert client.post('/api/mcp/settings', json={'allow_scan': True}, headers=auth).status_code == 200  # admin-only, no CSRF token
        bad = {'Authorization': 'Basic ' + base64.b64encode(b'robot:wrong').decode()}
        assert client.get('/api/scanlist', headers=bad).status_code == 401

    def test_basic_header_does_not_bypass_csrf_for_a_session(self, app, client, idp):
        sign_in_flow(client, idp, idp.claims('root', groups=['sf-admins']))
        r = client.post('/api/mcp/settings', json={'allow_scan': True}, headers={'Authorization': 'Basic Zm9vOmJhcg=='})
        assert r.status_code == 403


class TestSecretsNeverServed:
    def test_client_secret_appears_nowhere(self, app, client, idp):
        sign_in_flow(client, idp, idp.claims('root', groups=['sf-admins']))
        bodies = []
        for path in ('/', '/opts', '/auth/me', '/api/access/settings', '/api/access/users', '/frag/settings-section?section=access',
                     '/frag/settings-section?section=mcp', '/api/mcp/settings', '/api/optsraw', '/api/optsexport', '/auth/login'):
            r = client.get(path)
            bodies.append(r.get_data(as_text=True) + str(r.headers))
        r = client.post('/api/access/test', json={})
        bodies.append(r.get_data(as_text=True))
        assert not any(h.CLIENT_SECRET in b for b in bodies)
        assert h.CLIENT_SECRET in str(h.db(app).configGet())  # it is stored, just never served


class TestHardening:
    def test_a_provider_cannot_claim_the_local_namespace(self, app, client, idp):
        r = sign_in_flow(client, idp, idp.claims('local:admin', groups=['sf-users']))
        assert r.status_code == 302 and r.headers['Location'] == '/auth/login?error=failed'
        assert h.db(app).userList() == []

    def test_api_clients_of_a_denied_account_get_json(self, app, client, idp):
        sign_in_flow(client, idp, idp.claims('gone', groups=['sf-users']))
        h.db(app).userUpsert('gone', 'gone', groups=['nothing'], role='user', login=False)
        r = client.get('/api/scanlist', headers={'Sec-Fetch-Mode': 'cors'})
        assert r.status_code == 403 and 'error' in r.get_json()

    def test_settings_page_state_is_valid_json_for_each_role(self, app, client, idp):
        import re
        sign_in_flow(client, idp, idp.claims('root', groups=['sf-admins']))
        html = client.get('/opts').get_data(as_text=True)
        allowed = json.loads(re.search(r"x-data='\{ allowed: (\[[^\]]*\])", html).group(1))
        assert allowed[0] == 'general' and 'access' in allowed
        client.get('/auth/logout')
        sign_in_flow(client, idp, idp.claims('ursula', groups=['sf-users']))
        html = client.get('/opts').get_data(as_text=True)
        assert json.loads(re.search(r"x-data='\{ allowed: (\[[^\]]*\])", html).group(1)) == ['appearance', 'mcp']
