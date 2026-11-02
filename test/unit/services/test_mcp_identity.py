"""The MCP server acts as a user: personal tokens, OIDC access tokens, and the same access rules as the web interface."""
import base64
import json
import time

import pytest

from spiderfoot.services import mcp_auth
from test.unit import identity_helpers as h


def owned_scan(env, scan_id, owner, status='FINISHED', target='example.com'):
    env.seed_scan(scan_id, target=target, status=status)
    env.db().scanOwnerSet(scan_id, owner['id'] if owner else None)
    return scan_id


@pytest.fixture
def team(env):
    """Three users and a few scans: Olivia owns A (shared: Edith edit, Vic view); Sam owns B; C has no owner."""
    env.users = {n: env.make_user(n, ['sf-users']) for n in ('olivia', 'edith', 'vic', 'sam')}
    owned_scan(env, 'SCAN_A', env.users['olivia'], status='RUNNING', target='a.example')
    owned_scan(env, 'SCAN_B', env.users['sam'], target='b.example')
    owned_scan(env, 'SCAN_C', None, target='c.example')
    env.db().aclSet('SCAN_A', 'user', str(env.users['edith']['id']), 'edit')
    env.db().aclSet('SCAN_A', 'user', str(env.users['vic']['id']), 'view')
    env.tokens = {n: env.token_for(u['id']) for n, u in env.users.items()}
    return env


def call_as(env, who, tool, **arguments):
    resp = env.post(env.rpc('tools/call', {'name': tool, 'arguments': arguments}), token=env.tokens[who] if who in getattr(env, 'tokens', {}) else who)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    result = resp.get_json()['result']
    return result['isError'], (result['content'][0]['text'] if result['isError'] else result['structuredContent'])


class TestPersonalTokens:
    def test_token_identifies_its_owner(self, team):
        err, out = call_as(team, 'olivia', 'list_scans')
        assert not err and [s['scanId'] for s in out['scans']] == ['SCAN_A']

    def test_each_user_sees_only_their_own_and_shared_scans(self, team):
        seen = {who: sorted(s['scanId'] for s in call_as(team, who, 'list_scans')[1]['scans']) for who in team.users}
        assert seen == {'olivia': ['SCAN_A'], 'edith': ['SCAN_A'], 'vic': ['SCAN_A'], 'sam': ['SCAN_B']}
        admin = sorted(s['scanId'] for s in team.call('list_scans')[1]['scans'])
        assert admin == ['SCAN_A', 'SCAN_B', 'SCAN_C']

    def test_list_reports_your_access(self, team):
        by_id = {s['scanId']: s for s in call_as(team, 'vic', 'list_scans')[1]['scans']}
        assert by_id['SCAN_A']['yourAccess'] == 'view'
        assert {s['scanId']: s['yourAccess'] for s in call_as(team, 'olivia', 'list_scans')[1]['scans']} == {'SCAN_A': 'owner'}

    def test_hidden_scans_do_not_exist_for_a_user(self, team):
        for tool in ('get_scan', 'get_scan_summary', 'get_scan_events', 'get_scan_correlations', 'get_scan_log', 'stop_scan', 'rerun_scan'):
            err, text = call_as(team, 'sam', tool, scan_id='SCAN_A')
            assert err and 'does not exist' in text, tool
        team.configure(allow_delete=1)
        err, text = call_as(team, 'sam', 'delete_scan', scan_id='SCAN_A', confirm=True)
        assert err and 'does not exist' in text
        assert team.db().scanExists('SCAN_A')

    def test_unowned_scans_are_for_admins(self, team):
        err, text = call_as(team, 'olivia', 'get_scan', scan_id='SCAN_C')
        assert err and 'does not exist' in text
        assert not team.call('get_scan', scan_id='SCAN_C')[0]

    def test_unowned_scans_can_be_made_visible(self, team):
        team.db().configSet({'_auth_unowned_visible': '1'})
        assert not call_as(team, 'olivia', 'get_scan', scan_id='SCAN_C')[0]
        err, text = call_as(team, 'olivia', 'stop_scan', scan_id='SCAN_C')
        assert err and 'view access' in text

    def test_view_access_reads_but_cannot_stop(self, team):
        assert not call_as(team, 'vic', 'get_scan_summary', scan_id='SCAN_A')[0]
        err, text = call_as(team, 'vic', 'stop_scan', scan_id='SCAN_A')
        assert err and 'Not permitted' in text and 'view access' in text
        assert team.db().scanInstanceGet('SCAN_A')[5] == 'RUNNING'
        err, text = call_as(team, 'vic', 'rerun_scan', scan_id='SCAN_A')
        assert err and 'Not permitted' in text

    def test_edit_access_can_stop_and_rerun_but_not_delete(self, team):
        assert not call_as(team, 'edith', 'stop_scan', scan_id='SCAN_A')[0]
        assert team.db().scanInstanceGet('SCAN_A')[5] == 'ABORT-REQUESTED'
        err, out = call_as(team, 'edith', 'rerun_scan', scan_id='SCAN_A')
        assert not err
        assert team.db().scanOwnerGet(out['scanId']) == team.users['edith']['id']  # the clone is the caller's
        team.configure(allow_delete=1)
        err, text = call_as(team, 'edith', 'delete_scan', scan_id='SCAN_B', confirm=True)
        assert err and 'does not exist' in text
        team.db().scanInstanceSet('SCAN_A', status='FINISHED')
        err, text = call_as(team, 'edith', 'delete_scan', scan_id='SCAN_A', confirm=True)
        assert err and 'edit access' in text and 'delete' in text
        assert team.db().scanExists('SCAN_A')

    def test_owner_deletes_only_with_the_operator_permission_and_confirm(self, team):
        team.db().scanInstanceSet('SCAN_A', status='FINISHED')
        err, text = call_as(team, 'olivia', 'delete_scan', scan_id='SCAN_A', confirm=True)
        assert err and 'operator has not allowed' in text
        team.configure(allow_delete=1)
        err, text = call_as(team, 'olivia', 'delete_scan', scan_id='SCAN_A')
        assert err and 'confirm' in text
        assert not call_as(team, 'olivia', 'delete_scan', scan_id='SCAN_A', confirm=True)[0]
        assert not team.db().scanExists('SCAN_A') and team.db().aclList('SCAN_A') == []

    def test_admin_may_delete_anyones_scan(self, team):
        team.configure(allow_delete=1)
        assert not team.call('delete_scan', scan_id='SCAN_B', confirm=True)[0]

    def test_create_scan_records_the_caller_as_owner(self, team):
        err, out = call_as(team, 'sam', 'create_scan', target='example.org', modules=['sfp_dnsresolve'])
        assert not err and team.db().scanOwnerGet(out['scanId']) == team.users['sam']['id']
        assert out['scanId'] in {s['scanId'] for s in call_as(team, 'sam', 'list_scans')[1]['scans']}
        assert out['scanId'] not in {s['scanId'] for s in call_as(team, 'olivia', 'list_scans')[1]['scans']}
        assert team.launched[-1]['name'].startswith('mcp: ')

    def test_operator_guardrails_apply_to_everyone(self, team):
        err, out = call_as(team, 'sam', 'create_scan', target='example.org', modules=['sfp_dnsresolve', 'sfp_portscan_tcp'], confirm_active=True)
        assert not err and [d['module'] for d in out['dropped']] == ['sfp_portscan_tcp']
        err, text = call_as(team, 'sam', 'create_scan', target='10.0.0.5', modules=['sfp_dnsresolve'])
        assert err and 'private' in text.lower()
        team.configure(allow_scan=0)
        err, text = call_as(team, 'sam', 'create_scan', target='example.org', modules=['sfp_dnsresolve'])
        assert err and 'operator' in text
        err, text = call_as(team, 'edith', 'stop_scan', scan_id='SCAN_A')
        assert err and 'operator' in text

    def test_tokens_are_per_user_and_independent(self, team):
        assert team.tokens['olivia'] != team.tokens['sam']
        team.db().mcpTokenRevoke(team.users['sam']['id'], team.db().mcpTokenList(team.users['sam']['id'])[0]['id'])
        assert team.post(team.rpc('ping'), token=team.tokens['sam']).status_code == 401
        assert team.post(team.rpc('ping'), token=team.tokens['olivia']).status_code == 200

    def test_last_used_is_recorded(self, team):
        assert team.db().mcpTokenList(team.users['sam']['id'])[0]['last_used'] == 0
        team.post(team.rpc('ping'), token=team.tokens['sam'])
        assert team.db().mcpTokenList(team.users['sam']['id'])[0]['last_used'] > 0

    def test_expiry(self, team):
        old = team.token_for(team.users['sam']['id'], expires=int(time.time()) - 1)
        soon = team.token_for(team.users['sam']['id'], expires=int(time.time()) + 600)
        assert team.post(team.rpc('ping'), token=old).status_code == 401
        assert team.post(team.rpc('ping'), token=soon).status_code == 200

    def test_only_the_hash_is_stored(self, team):
        import sqlite3
        conn = sqlite3.connect(team.db_path)
        stored = [r[0] for r in conn.execute('SELECT hash FROM tbl_mcp_tokens')]
        conn.close()
        assert mcp_auth.hash_token(team.tokens['sam']) in stored and team.tokens['sam'] not in str(stored)

    def test_tool_output_never_contains_tokens_or_secrets(self, team):
        text = json.dumps([call_as(team, 'olivia', 'list_scans')[1], call_as(team, 'olivia', 'get_scan', scan_id='SCAN_A')[1]])
        assert team.tokens['olivia'] not in text and mcp_auth.hash_token(team.tokens['olivia']) not in text


class TestRoleIsEvaluatedAtUse:
    @pytest.fixture
    def sso(self, team, monkeypatch):
        idp = h.FakeIdp()
        idp.install(monkeypatch)
        team.db().configSet({'_oidc_issuer': h.ISSUER, '_oidc_client_id': h.CLIENT_ID, '_oidc_admin_groups': 'sf-admins',
                             '_oidc_user_groups': 'sf-users'})
        team.idp = idp
        return team

    def test_losing_the_group_disables_the_token_at_once(self, sso):
        assert sso.post(sso.rpc('ping'), token=sso.tokens['sam']).status_code == 200
        sso.db().userUpsert('oidc|sam', 'sam', groups=['somewhere-else'], role='user', login=False)
        resp = sso.post(sso.rpc('ping'), token=sso.tokens['sam'])
        assert resp.status_code == 403 and 'not allowed' in resp.get_json()['error']
        assert sso.post(sso.rpc('ping'), token=sso.tokens['olivia']).status_code == 200

    def test_changing_the_mapping_applies_immediately(self, sso):
        sso.db().configSet({'_oidc_user_groups': 'only-this-group'})
        assert sso.post(sso.rpc('ping'), token=sso.tokens['sam']).status_code == 403
        sso.db().configSet({'_oidc_user_groups': 'sf-users'})
        assert sso.post(sso.rpc('ping'), token=sso.tokens['sam']).status_code == 200

    def test_promotion_and_demotion(self, sso):
        assert call_as(sso, 'sam', 'get_scan', scan_id='SCAN_A')[0]  # hidden from an ordinary user
        sso.db().userUpsert('oidc|sam', 'sam', groups=['sf-admins'], role='user', login=False)
        assert not call_as(sso, 'sam', 'get_scan', scan_id='SCAN_A')[0]  # an administrator now
        assert len(call_as(sso, 'sam', 'list_scans')[1]['scans']) == 3
        sso.db().userUpsert('oidc|sam', 'sam', groups=['sf-users'], role='user', login=False)
        assert [s['scanId'] for s in call_as(sso, 'sam', 'list_scans')[1]['scans']] == ['SCAN_B']

    def test_local_administrators_keep_working(self, sso):
        assert sso.post(sso.rpc('ping')).status_code == 200  # the synthetic admin's token

    def test_denied_attempts_do_not_count_as_failed_logins(self, sso):
        sso.db().userUpsert('oidc|sam', 'sam', groups=['x'], role='user', login=False)
        client = sso.client()
        codes = [sso.post(sso.rpc('ping'), token=sso.tokens['sam'], client=client).status_code for _ in range(15)]
        assert set(codes) == {403}


class TestOidcAccessTokens:
    @pytest.fixture
    def sso(self, env, monkeypatch):
        idp = h.FakeIdp()
        idp.install(monkeypatch)
        env.db().configSet({'_oidc_issuer': h.ISSUER, '_oidc_client_id': h.CLIENT_ID, '_oidc_admin_groups': 'sf-admins',
                            '_oidc_user_groups': 'sf-users'})
        env.idp = idp
        return env

    def bearer(self, env, **claims):
        return env.idp.mint(env.idp.claims(**claims))

    def test_valid_token_maps_to_a_user_by_subject(self, sso):
        token = self.bearer(sso, sub='alice', groups=['sf-users'])
        resp = sso.post(sso.rpc('ping'), token=token)
        assert resp.status_code == 200
        row = sso.db().userGetBySubject('alice')
        assert row and row['groups'] == ['sf-users'] and row['role'] == 'user' and row['email'] == 'alice@example.test'
        # the same person later: the same row
        sso.post(sso.rpc('ping'), token=self.bearer(sso, sub='alice', groups=['sf-users', 'new']))
        assert len(sso.db().userList()) == 2  # local admin + alice
        assert sso.db().userGetBySubject('alice')['groups'] == ['new', 'sf-users']

    def test_rules_apply_to_the_token_user(self, sso):
        alice = self.bearer(sso, sub='alice', groups=['sf-users'])
        sso.seed_scan('MINE', target='mine.example')
        sso.seed_scan('THEIRS', target='theirs.example')
        row = sso.db().userGetBySubject('alice') or sso.db().userUpsert('alice', 'alice', groups=['sf-users'], login=False)
        sso.db().scanOwnerSet('MINE', row['id'])
        resp = sso.post(sso.rpc('tools/call', {'name': 'list_scans', 'arguments': {}}), token=alice)
        assert [s['scanId'] for s in resp.get_json()['result']['structuredContent']['scans']] == ['MINE']

    def test_admin_group_gives_admin_rights(self, sso):
        sso.seed_scan('ANY', target='any.example')
        token = self.bearer(sso, sub='boss', groups=['sf-admins'])
        resp = sso.post(sso.rpc('tools/call', {'name': 'get_scan', 'arguments': {'scan_id': 'ANY'}}), token=token)
        assert not resp.get_json()['result']['isError']

    def test_groups_fall_back_to_userinfo(self, sso):
        sso.idp.userinfo_claims = {'sub': 'bob', 'groups': ['sf-admins']}
        token = sso.idp.mint(sso.idp.claims('bob', groups=None))
        assert sso.post(sso.rpc('ping'), token=token).status_code == 200
        assert sso.db().userGetBySubject('bob')['role'] == 'admin'

    def test_userinfo_answers_for_another_subject_are_ignored(self, sso):
        sso.idp.userinfo_claims = {'sub': 'mallory', 'groups': ['sf-admins']}
        token = sso.idp.mint(sso.idp.claims('bob', groups=None))
        assert sso.post(sso.rpc('ping'), token=token).status_code == 403  # no groups, user groups are required

    def test_userinfo_is_cached_briefly(self, sso):
        sso.idp.userinfo_claims = {'sub': 'bob', 'groups': ['sf-users']}
        token = sso.idp.mint(sso.idp.claims('bob', groups=None))
        for _ in range(3):
            sso.post(sso.rpc('ping'), token=token)
        assert len([r for r in sso.idp.requests if r[1].endswith('/userinfo')]) == 1

    def test_denied_groups(self, sso):
        resp = sso.post(sso.rpc('ping'), token=self.bearer(sso, sub='eve', groups=['strangers']))
        assert resp.status_code == 403 and sso.db().userGetBySubject('eve') is None

    def test_audience_is_the_client_id_or_the_configured_mcp_audience(self, sso):
        assert sso.post(sso.rpc('ping'), token=self.bearer(sso, sub='a1', aud=h.CLIENT_ID)).status_code == 200
        assert sso.post(sso.rpc('ping'), token=self.bearer(sso, sub='a2', aud='https://mcp.example')).status_code == 401
        sso.db().configSet({'_oidc_mcp_audience': 'https://mcp.example'})
        assert sso.post(sso.rpc('ping'), token=self.bearer(sso, sub='a3', aud='https://mcp.example')).status_code == 200
        assert sso.post(sso.rpc('ping'), token=self.bearer(sso, sub='a4', aud=['x', 'https://mcp.example'])).status_code == 200

    @pytest.mark.parametrize('why', ['wrong issuer', 'expired', 'other key', 'no subject', 'tampered', 'none alg', 'hs256', 'garbage', 'opaque'])
    def test_invalid_tokens(self, sso, why):
        idp = sso.idp
        enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()  # noqa: E731
        claims = idp.claims('eve', groups=['sf-admins'])
        if why == 'wrong issuer':
            token = idp.mint(claims, iss='https://evil.test')
        elif why == 'expired':
            token = idp.mint(claims, exp=int(time.time()) - 3600)
        elif why == 'other key':
            token = idp.mint(claims, key_name='attacker')
        elif why == 'no subject':
            token = idp.mint({k: v for k, v in claims.items() if k != 'sub'})
        elif why == 'tampered':
            head, payload, sig = idp.mint(claims).split('.')
            token = '.'.join([head, enc(dict(claims, sub='root')), sig])
        elif why == 'none alg':
            token = enc({'alg': 'none'}) + '.' + enc(claims) + '.'
        elif why == 'hs256':
            from authlib.jose import jwt
            token = jwt.encode({'alg': 'HS256', 'kid': 'kid-main'}, claims, 'a-shared-secret-of-sufficient-length-x').decode()
        elif why == 'garbage':
            token = 'a.b.c'
        else:
            token = 'opaque-access-token-value'
        resp = sso.post(sso.rpc('ping'), token=token)
        assert resp.status_code == 401, why
        assert sso.db().userGetBySubject('eve') is None

    def test_jwt_is_refused_when_sign_in_is_not_configured(self, env, monkeypatch):
        idp = h.FakeIdp()
        idp.install(monkeypatch)
        assert env.post(env.rpc('ping'), token=idp.mint(idp.claims())).status_code == 401

    def test_failed_attempts_are_throttled(self, sso):
        client = sso.client()
        codes = [sso.post(sso.rpc('ping'), token='sfmcp_wrong', client=client).status_code for _ in range(12)]
        assert codes[:10] == [401] * 10 and codes[10:] == [429, 429]


class TestDiscovery:
    def test_challenge_points_at_the_metadata_when_sign_in_is_configured(self, env, monkeypatch):
        resp = env.post(env.rpc('ping'), token=None)
        assert resp.headers['WWW-Authenticate'] == 'Bearer'  # no sign-in configured: nothing to point at
        h.FakeIdp().install(monkeypatch)
        env.db().configSet({'_oidc_issuer': h.ISSUER, '_oidc_client_id': h.CLIENT_ID})
        resp = env.post(env.rpc('ping'), token=None)
        assert resp.status_code == 401
        assert resp.headers['WWW-Authenticate'] == 'Bearer resource_metadata="http://localhost/.well-known/oauth-protected-resource"'

    def test_protected_resource_metadata(self, env, monkeypatch):
        client = env.client()
        assert client.get('/.well-known/oauth-protected-resource').status_code == 404
        h.FakeIdp().install(monkeypatch)
        env.db().configSet({'_oidc_issuer': h.ISSUER, '_oidc_client_id': h.CLIENT_ID})
        for path in ('/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'):
            resp = client.get(path, headers={'Host': 'mcp.example:5094'})
            assert resp.status_code == 200
            assert resp.get_json() == {'resource': 'http://mcp.example:5094/mcp', 'authorization_servers': [h.ISSUER],
                                       'bearer_methods_supported': ['header'], 'resource_name': 'SpiderFoot MCP server'}
            assert 'secret' not in resp.get_data(as_text=True).lower()
        assert client.post('/.well-known/oauth-protected-resource').status_code == 405

    def test_metadata_needs_no_credentials_and_works_while_the_server_is_off(self, env, monkeypatch):
        h.FakeIdp().install(monkeypatch)
        env.db().configSet({'_oidc_issuer': h.ISSUER, '_oidc_client_id': h.CLIENT_ID})
        env.configure(enabled=0)
        assert env.client().get('/.well-known/oauth-protected-resource').status_code == 200

    def test_forwarded_headers_only_when_trusted(self, env, monkeypatch):
        h.FakeIdp().install(monkeypatch)
        env.db().configSet({'_oidc_issuer': h.ISSUER, '_oidc_client_id': h.CLIENT_ID})
        headers = {'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'agents.example.com'}
        assert env.client().get('/.well-known/oauth-protected-resource', headers=headers).get_json()['resource'] == 'http://localhost/mcp'
        env.db().configSet({'_auth_trust_proxy': '1'})
        assert env.client().get('/.well-known/oauth-protected-resource', headers=headers).get_json()['resource'] == 'https://agents.example.com/mcp'


class TestClientAddress:
    def test_forwarded_for_is_ignored_unless_a_proxy_is_trusted(self, env):
        client = env.client()
        for i in range(10):
            env.post(env.rpc('ping'), token='sfmcp_bad', client=client, headers={'X-Forwarded-For': f'203.0.113.{i}'})
        # all ten failures were counted against the real peer, so the next call is throttled whatever it claims
        assert env.post(env.rpc('ping'), token='sfmcp_bad', client=client, headers={'X-Forwarded-For': '198.51.100.7'}).status_code == 429

    def test_trusted_proxy_separates_clients(self, env):
        env.db().configSet({'_auth_trust_proxy': '1'})
        client = env.client()
        for _ in range(10):
            env.post(env.rpc('ping'), token='sfmcp_bad', client=client, headers={'X-Forwarded-For': '203.0.113.9'})
        assert env.post(env.rpc('ping'), token='sfmcp_bad', client=client, headers={'X-Forwarded-For': '203.0.113.9'}).status_code == 429
        # another client behind the same proxy is not affected
        assert env.post(env.rpc('ping'), client=client, headers={'X-Forwarded-For': '198.51.100.7'}).status_code == 200

    def test_the_entry_the_proxy_appended_is_used(self, env, monkeypatch):
        monkeypatch.setenv('SF_TRUST_PROXY', '1')
        client = env.client()
        spoof = {'X-Forwarded-For': '1.1.1.1, 203.0.113.9'}  # the client claims 1.1.1.1; the proxy added the real address
        for _ in range(10):
            env.post(env.rpc('ping'), token='sfmcp_bad', client=client, headers=spoof)
        assert env.post(env.rpc('ping'), token='sfmcp_bad', client=client, headers={'X-Forwarded-For': '2.2.2.2, 203.0.113.9'}).status_code == 429
