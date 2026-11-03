"""The group registry through the real request path: admin endpoints, live role changes, seen groups, migration, pickers."""
import json
import re

import pytest

from spiderfoot.services import groups as g
from test.unit import identity_helpers as h
from test.unit.services.conftest import fake_modules

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
def world(tmp_path, idp):
    """SSO on with a registry: sf-admins (admin), sf-users (user). Root is an admin, Sam a user, Ozzy is in an unregistered group."""
    app = h.make_app(tmp_path, modules=fake_modules())
    h.configure_sso(app, admin_groups='', user_groups='')
    h.set_registry(app, admin=['sf-admins'], user=['sf-users'])
    users = {name: h.add_user(app, name, groups) for name, groups in (
        ('root', ['sf-admins']), ('sam', ['sf-users']), ('ozzy', ['dex-extra']), ('dual', ['sf-users', 'sf-admins']))}
    return app, users


def client_for(app, user):
    return h.sign_in(app.test_client(), user)


def names(resp):
    return {x['name']: x['role'] for x in resp.get_json()['groups']}


def status_of(app, user, path='/api/scanlist'):
    return client_for(app, user).get(path).status_code


def flow(client, idp, claims):
    resp = client.get('/auth/login?start=1')
    code, q = idp.issue_code(resp.headers['Location'], claims)
    return client.get('/auth/callback?code=' + code + '&state=' + q['state'])


class TestAccessControlOfTheEndpoints:
    ROUTES = [('get', '/api/access/groups', None), ('post', '/api/access/groups', {'name': 'x', 'role': 'user'}),
              ('post', '/api/access/groups/update', {'name': 'sf-users', 'role': 'admin'}), ('post', '/api/access/groups/remove', {'name': 'sf-users'})]

    @pytest.mark.parametrize('method,path,body', ROUTES)
    def test_plain_users_get_403_and_nothing_changes(self, world, method, path, body):
        app, users = world
        c = client_for(app, users['sam'])
        r = getattr(c, method)(path, json=body) if body else getattr(c, method)(path)
        assert r.status_code == 403
        assert names(client_for(app, users['root']).get('/api/access/groups')) == {'sf-admins': 'admin', 'sf-users': 'user'}

    @pytest.mark.parametrize('method,path,body', ROUTES)
    def test_unauthenticated_requests_are_refused(self, world, method, path, body):
        app, _ = world
        r = getattr(app.test_client(), method)(path, json=body, headers={'Sec-Fetch-Mode': 'cors'}) if body else app.test_client().get(path, headers={'Sec-Fetch-Mode': 'cors'})
        assert r.status_code == 401

    @pytest.mark.parametrize('path,body', [(p, b) for m, p, b in ROUTES if m == 'post'])
    def test_csrf_token_is_required(self, world, path, body):
        app, users = world
        c = client_for(app, users['root'])
        del c.environ_base['HTTP_X_CSRF_TOKEN']
        assert c.post(path, json=body).status_code == 403
        c.environ_base['HTTP_X_CSRF_TOKEN'] = 'wrong'
        assert c.post(path, json=body).status_code == 403
        assert 'x' not in names(client_for(app, users['root']).get('/api/access/groups'))

    def test_responses_are_not_cached(self, world):
        app, users = world
        assert client_for(app, users['root']).get('/api/access/groups').headers['Cache-Control'].startswith('no-store')


class TestAddingGroups:
    def test_list_shape_counts_members_and_who_added(self, world):
        app, users = world
        d = client_for(app, users['root']).get('/api/access/groups').get_json()
        rows = {x['name']: x for x in d['groups']}
        assert rows['sf-admins']['members'] == 2 and rows['sf-users']['members'] == 2  # root+dual, sam+dual
        assert rows['sf-admins']['addedBy'] == 'tests' and rows['sf-admins']['added'] == 1_700_000_000
        assert [x['name'] for x in d['groups']][0] == 'sf-admins'  # admin groups first
        assert d['effectiveDefault'] == 'none' and d['defaultRole'] == '' and d['source'] == 'stored' and d['ssoOn']
        assert rows['sf-admins']['mine'] is True and rows['sf-users']['mine'] is False
        assert 'secret' not in json.dumps(d).lower()

    def test_add_group(self, world):
        app, users = world
        c = client_for(app, users['root'])
        r = c.post('/api/access/groups', json={'name': '  team-a ', 'role': 'user', 'description': 'The A team'})
        assert r.status_code == 200
        row = {x['name']: x for x in r.get_json()['groups']}['team-a']
        assert row['role'] == 'user' and row['description'] == 'The A team' and row['addedBy'] == 'root' and row['added'] > 0
        saved = json.loads(h.db(app).configGet()['_oidc_groups'])
        assert 'team-a' in [e['name'] for e in saved]

    @pytest.mark.parametrize('body', [
        {'name': '', 'role': 'user'}, {'name': '   ', 'role': 'user'}, {'name': 'a' * 101, 'role': 'user'}, {'name': 'a,b', 'role': 'user'},
        {'name': 'bad\x00name', 'role': 'user'}, {'name': 'new\nline', 'role': 'user'}, {'name': 'ok', 'role': 'root'}, {'name': 'ok'},
        {'name': 'ok', 'role': 'user', 'description': 'd' * 201}, {'name': 'ok', 'role': 'user', 'description': 'bad\x07'},
        {'name': ['list'], 'role': 'user'}, {'role': 'user'}, {},
    ])
    def test_validation(self, world, body):
        app, users = world
        c = client_for(app, users['root'])
        r = c.post('/api/access/groups', json=body)
        assert r.status_code == 400 and set(r.get_json()) == {'error'}
        assert names(c.get('/api/access/groups')) == {'sf-admins': 'admin', 'sf-users': 'user'}

    def test_duplicates_are_refused_but_case_counts(self, world):
        app, users = world
        c = client_for(app, users['root'])
        r = c.post('/api/access/groups', json={'name': 'sf-users', 'role': 'admin'})
        assert r.status_code == 409 and 'already' in r.get_json()['error']
        assert names(c.get('/api/access/groups'))['sf-users'] == 'user'
        assert c.post('/api/access/groups', json={'name': 'SF-Users', 'role': 'user'}).status_code == 200

    def test_the_boundary_lengths_are_accepted(self, world):
        app, users = world
        c = client_for(app, users['root'])
        assert c.post('/api/access/groups', json={'name': 'n' * 100, 'role': 'user', 'description': 'd' * 200}).status_code == 200

    def test_a_json_body_is_required(self, world):
        app, users = world
        assert client_for(app, users['root']).post('/api/access/groups', data='nope').status_code == 400


class TestChangingAndRemoving:
    def test_change_role_description_and_remove(self, world):
        app, users = world
        c = client_for(app, users['root'])
        c.post('/api/access/groups', json={'name': 'team-a', 'role': 'user'})
        r = c.post('/api/access/groups/update', json={'name': 'team-a', 'role': 'admin', 'description': 'now admins'})
        row = {x['name']: x for x in r.get_json()['groups']}['team-a']
        assert row['role'] == 'admin' and row['description'] == 'now admins'
        r = c.post('/api/access/groups/update', json={'name': 'team-a', 'description': ''})
        assert {x['name']: x for x in r.get_json()['groups']}['team-a']['role'] == 'admin'
        assert 'team-a' not in names(c.post('/api/access/groups/remove', json={'name': 'team-a'}))

    def test_nothing_to_change_unknown_group_and_bad_role(self, world):
        app, users = world
        c = client_for(app, users['root'])
        assert c.post('/api/access/groups/update', json={'name': 'sf-users'}).status_code == 400
        assert c.post('/api/access/groups/update', json={'name': 'nope', 'role': 'user'}).status_code == 404
        assert c.post('/api/access/groups/update', json={'name': 'sf-users', 'role': 'owner'}).status_code == 400
        assert c.post('/api/access/groups/remove', json={'name': 'nope'}).status_code == 404
        assert names(c.get('/api/access/groups')) == {'sf-admins': 'admin', 'sf-users': 'user'}

    def test_the_last_admin_group_cannot_be_removed_or_demoted(self, world):
        app, users = world
        c = client_for(app, users['root'])
        r = c.post('/api/access/groups/remove', json={'name': 'sf-admins'})
        assert r.status_code == 400 and 'last admin group' in r.get_json()['error']
        r = c.post('/api/access/groups/update', json={'name': 'sf-admins', 'role': 'user'})
        assert r.status_code == 400
        assert names(c.get('/api/access/groups'))['sf-admins'] == 'admin'

    def test_you_cannot_take_your_own_admin_access_away(self, world):
        app, users = world
        c = client_for(app, users['root'])
        c.post('/api/access/groups', json={'name': 'second-admins', 'role': 'admin'})
        for call in (lambda: c.post('/api/access/groups/remove', json={'name': 'sf-admins'}),
                     lambda: c.post('/api/access/groups/update', json={'name': 'sf-admins', 'role': 'user'})):
            r = call()
            assert r.status_code == 400 and 'your own administrator access' in r.get_json()['error']
        assert names(c.get('/api/access/groups'))['sf-admins'] == 'admin'
        # someone else's group can go
        assert c.post('/api/access/groups/remove', json={'name': 'second-admins'}).status_code == 200

    def test_a_user_in_two_admin_groups_may_remove_one(self, world):
        app, users = world
        c = client_for(app, users['root'])
        c.post('/api/access/groups', json={'name': 'sf-extra', 'role': 'admin'})
        h.add_user(app, 'root', ['sf-admins', 'sf-extra'], subject='oidc|root')
        assert c.post('/api/access/groups/remove', json={'name': 'sf-extra'}).status_code == 200

    def test_guards_do_not_apply_while_sso_is_off(self, tmp_path):
        app = h.make_app(tmp_path)
        c = app.test_client()
        token = re.search(r'name="csrf-token" content="([^"]+)"', c.get('/').get_data(as_text=True)).group(1)
        c.environ_base['HTTP_X_CSRF_TOKEN'] = token
        assert c.post('/api/access/groups', json={'name': 'a', 'role': 'admin'}).status_code == 200
        assert c.post('/api/access/groups/remove', json={'name': 'a'}).status_code == 200

    def test_a_damaged_registry_locks_sso_users_out_and_refuses_changes_from_a_local_admin(self, world):
        import base64
        from spiderfoot.app import _hash_password
        app, users = world
        app.config['SF_USERS'] = {'robot': _hash_password('pw-9999')}
        h.db(app).configSet({'_oidc_groups': '{broken'})
        assert client_for(app, users['root']).get('/api/scanlist').status_code == 403  # nobody is let in by a damaged list
        auth = {'Authorization': 'Basic ' + base64.b64encode(b'robot:pw-9999').decode()}
        r = app.test_client().post('/api/access/groups', json={'name': 'x', 'role': 'user'}, headers=auth)
        assert r.status_code == 409 and 'damaged' in r.get_json()['error']


class TestChangesApplyWithoutRestart:
    def test_outsider_gains_and_loses_access_and_roles_follow(self, world):
        app, users = world
        root = client_for(app, users['root'])
        assert status_of(app, users['ozzy']) == 403
        assert root.post('/api/access/groups', json={'name': 'dex-extra', 'role': 'user'}).status_code == 200
        assert status_of(app, users['ozzy']) == 200
        assert status_of(app, users['ozzy'], '/api/access/groups') == 403
        root.post('/api/access/groups/update', json={'name': 'dex-extra', 'role': 'admin'})
        assert status_of(app, users['ozzy'], '/api/access/groups') == 200
        root.post('/api/access/groups/update', json={'name': 'dex-extra', 'role': 'user'})
        assert status_of(app, users['ozzy'], '/api/access/groups') == 403
        root.post('/api/access/groups/remove', json={'name': 'dex-extra'})
        assert status_of(app, users['ozzy']) == 403

    def test_admin_beats_user_for_a_member_of_both(self, world):
        app, users = world
        assert client_for(app, users['dual']).get('/auth/me').get_json()['role'] == 'admin'

    def test_a_removed_group_stops_a_personal_session_at_once(self, world):
        app, users = world
        c = client_for(app, users['sam'])
        assert c.get('/api/scanlist').status_code == 200
        root = client_for(app, users['root'])
        root.post('/api/access/groups', json={'name': 'sf-other-users', 'role': 'user'})
        root.post('/api/access/groups/remove', json={'name': 'sf-users'})
        assert c.get('/api/scanlist').status_code == 403  # a User group remains, so unlisted accounts are turned away


class TestUnlistedAccounts:
    def test_default_role_through_the_settings_endpoint(self, world):
        app, users = world
        root = client_for(app, users['root'])
        assert status_of(app, users['ozzy']) == 403  # automatic with a user group registered: denied
        r = root.post('/api/access/settings', json={'oidc_default_role': 'user'})
        assert r.status_code == 200 and r.get_json()['fields']['oidc_default_role'] == 'user'
        assert status_of(app, users['ozzy']) == 200
        assert root.get('/api/access/groups').get_json()['effectiveDefault'] == 'user'
        root.post('/api/access/settings', json={'oidc_default_role': 'none'})
        assert status_of(app, users['ozzy']) == 403
        root.post('/api/access/settings', json={'oidc_default_role': ''})
        assert root.get('/api/access/groups').get_json()['defaultRole'] == ''

    def test_only_valid_values_and_environment_locks(self, world, monkeypatch):
        app, users = world
        root = client_for(app, users['root'])
        assert root.post('/api/access/settings', json={'oidc_default_role': 'admin'}).status_code == 400
        monkeypatch.setenv('SF_OIDC_DEFAULT_ROLE', 'none')
        r = root.post('/api/access/settings', json={'oidc_default_role': 'user'})
        assert r.get_json()['ignored'] == ['oidc_default_role'] and 'oidc_default_role' in r.get_json()['env']
        assert root.get('/api/access/groups').get_json()['defaultRoleLocked'] is True

    def test_automatic_matches_the_old_behaviour(self, tmp_path):
        app = h.make_app(tmp_path)
        h.configure_sso(app, admin_groups='sf-admins', user_groups='')  # an old install without user groups
        outsider = h.add_user(app, 'out', ['whatever'])
        assert client_for(app, outsider).get('/auth/me').get_json()['role'] == 'user'
        h.set_registry(app, admin=['sf-admins'], user=['sf-users'])
        assert client_for(app, outsider).get('/auth/me').status_code == 403


class TestSeenAtSignIn:
    def test_groups_of_known_users_that_are_not_registered(self, world):
        app, users = world
        d = client_for(app, users['root']).get('/api/access/groups').get_json()
        assert d['seen'] == [{'name': 'dex-extra', 'users': 1, 'denied': False, 'mine': False}]

    def test_denied_sign_ins_leave_their_groups_for_the_admin(self, world, idp):
        app, users = world
        r = flow(app.test_client(), idp, idp.claims('stranger', groups=['dex-newcomers', 'sf-nobody']))
        assert r.status_code == 403 and h.db(app).userGetBySubject('stranger') is None
        d = client_for(app, users['root']).get('/api/access/groups').get_json()
        seen = {x['name']: x for x in d['seen']}
        assert seen['dex-newcomers']['denied'] is True and seen['dex-newcomers']['users'] == 0 and 'dex-extra' in seen

    def test_adding_a_seen_group_moves_it_to_the_registry_and_lets_the_person_in(self, world, idp):
        app, users = world
        stranger = app.test_client()
        assert flow(stranger, idp, idp.claims('stranger', groups=['dex-newcomers'])).status_code == 403
        root = client_for(app, users['root'])
        d = root.post('/api/access/groups', json={'name': 'dex-newcomers', 'role': 'user'}).get_json()
        assert 'dex-newcomers' not in [x['name'] for x in d['seen']] and 'dex-newcomers' in [x['name'] for x in d['groups']]
        again = app.test_client()
        r = flow(again, idp, idp.claims('stranger', groups=['dex-newcomers']))
        assert r.status_code == 302 and again.get('/auth/me').get_json()['role'] == 'user'

    def test_seen_denied_list_is_bounded(self, world, idp):
        app, users = world
        c = app.test_client()
        flow(c, idp, idp.claims('stranger', groups=[f'bulk-{i:03d}' for i in range(150)]))
        stored = json.loads(h.db(app).configGet()['_oidc_denied_groups'])
        assert 0 < len(stored) <= g.MAX_DENIED

    def test_group_names_cannot_inject_markup_into_the_fragment(self, world):
        app, users = world
        h.add_user(app, 'evil', ['<script>alert(1)</script>'])
        html = client_for(app, users['root']).get('/frag/settings-section?section=access').get_data(as_text=True)
        assert '<script>alert(1)</script>' not in html  # tojson escapes the angle brackets inside the attribute


class TestMigration:
    def test_old_lists_become_the_registry_when_the_admin_page_is_first_used(self, tmp_path):
        app = h.make_app(tmp_path)
        h.configure_sso(app, admin_groups='sf-admins, ops', user_groups='sf-users')
        root = h.add_user(app, 'root', ['sf-admins'])
        assert '_oidc_groups' not in h.db(app).configGet()
        d = client_for(app, root).get('/api/access/groups').get_json()
        assert {x['name']: x['role'] for x in d['groups']} == {'sf-admins': 'admin', 'ops': 'admin', 'sf-users': 'user'}
        assert {x['addedBy'] for x in d['groups']} == {'migrated'}
        assert len(json.loads(h.db(app).configGet()['_oidc_groups'])) == 3
        h.db(app).configSet({'_oidc_user_groups': 'ignored-now'})  # the old keys are only read for the migration
        assert 'ignored-now' not in [x['name'] for x in client_for(app, root).get('/api/access/groups').get_json()['groups']]

    def test_the_settings_fragment_also_migrates(self, tmp_path):
        app = h.make_app(tmp_path)
        h.configure_sso(app, admin_groups='sf-admins', user_groups='')
        root = h.add_user(app, 'root', ['sf-admins'])
        html = client_for(app, root).get('/frag/settings-section?section=access').get_data(as_text=True)
        assert 'sf-admins' in html and '_oidc_groups' in h.db(app).configGet()

    def test_environment_values_seed_an_empty_registry_and_do_not_lock(self, tmp_path, monkeypatch):
        monkeypatch.setenv('SF_OIDC_ADMIN_GROUPS', 'env-admins')
        monkeypatch.setenv('SF_OIDC_USER_GROUPS', 'env-users')
        app = h.make_app(tmp_path)
        h.configure_sso(app, admin_groups='', user_groups='')
        root = h.add_user(app, 'root', ['env-admins'])
        c = client_for(app, root)
        d = c.get('/api/access/groups').get_json()
        assert {x['name']: x['role'] for x in d['groups']} == {'env-admins': 'admin', 'env-users': 'user'}
        assert {x['addedBy'] for x in d['groups']} == {'environment'}
        assert c.post('/api/access/groups', json={'name': 'more', 'role': 'user'}).status_code == 200  # nothing is locked
        view = c.get('/api/access/settings').get_json()
        assert 'oidc_admin_groups' not in view['env'] and 'oidc_admin_groups' not in view['fields']
        monkeypatch.setenv('SF_OIDC_ADMIN_GROUPS', 'changed-seed')
        assert 'changed-seed' not in names(c.get('/api/access/groups'))  # seeds count only while the registry is empty

    def test_the_old_form_fields_are_gone(self, world):
        app, users = world
        r = client_for(app, users['root']).post('/api/access/settings', json={'oidc_admin_groups': ['x']})
        assert r.status_code == 400


class TestSettingsPage:
    def test_fragment_has_the_groups_card_and_no_old_fields(self, world):
        app, users = world
        html = client_for(app, users['root']).get('/frag/settings-section?section=access').get_data(as_text=True)
        for text in ('Add a group', 'Seen at sign-in', 'Unlisted accounts', 'Signed-in users without a registered group are',
                     'Add as User', 'Add as Admin', 'Using Dex as the identity provider', 'openid profile email groups', '/auth/callback',
                     'sf-admins', 'dex-extra'):
            assert text in html, text
        assert 'Admin groups' not in html and 'x-model="f.oidc_admin_groups"' not in html and 'confirm(' not in html
        assert h.CLIENT_SECRET not in html

    def test_test_connection_reports_groups_scope_and_claims(self, world):
        app, users = world
        r = client_for(app, users['root']).post('/api/access/test', json={})
        d = r.get_json()
        assert d['ok'] and d['groups_scope'] is True and d['groups_claim'] is True
        assert d['claims_supported'] == ['email', 'groups', 'sub'] and h.CLIENT_SECRET not in json.dumps(d)

    def test_test_connection_for_a_provider_without_groups(self, world, idp):
        app, users = world
        idp.discovery_doc['scopes_supported'] = ['openid', 'email']
        idp.discovery_doc['claims_supported'] = ['sub']
        h.oidc.clear_cache()
        d = client_for(app, users['root']).post('/api/access/test', json={}).get_json()
        assert d['groups_scope'] is False and d['groups_claim'] is False
        idp.discovery_doc.pop('scopes_supported')
        idp.discovery_doc.pop('claims_supported')
        h.oidc.clear_cache()
        d = client_for(app, users['root']).post('/api/access/test', json={}).get_json()
        assert d['groups_scope'] is None and d['claims_supported'] is None


class TestSharingPicker:
    def test_suggests_registered_and_seen_groups(self, world):
        app, users = world
        client_for(app, users['root']).post('/api/access/groups', json={'name': 'registered-only', 'role': 'user'})
        got = client_for(app, users['sam']).get('/api/groups').get_json()
        assert 'registered-only' in got and 'sf-admins' in got and 'dex-extra' in got
        assert got == sorted(set(got), key=lambda n: (n.lower(), n))

    def test_works_when_nobody_has_signed_in_yet(self, tmp_path):
        app = h.make_app(tmp_path)
        h.configure_sso(app, admin_groups='', user_groups='')
        h.set_registry(app, admin=['a-admins'], user=['u-users'])
        sam = h.add_user(app, 'sam', ['u-users'])
        assert client_for(app, sam).get('/api/groups').get_json() == ['a-admins', 'sam'][:0] + ['a-admins', 'u-users']


class TestDexShapedLogin:
    """Dex puts groups in the ID token as an array, may leave the claim out, and its sub is an opaque string."""
    SUB = 'CgVhbGljZRIFbG9jYWw'

    def claims(self, idp, groups=None, **extra):
        out = idp.claims(self.SUB, groups=None, preferred_username='alice', email='alice@example.test', name='Alice Example', **extra)
        if groups is not None:
            out['groups'] = groups  # any shape: list, string
        return out

    def test_groups_array(self, world, idp):
        app, _ = world
        c = app.test_client()
        assert flow(c, idp, self.claims(idp, groups=['sf-admins'])).status_code == 302
        me = c.get('/auth/me').get_json()
        assert me['role'] == 'admin' and me['username'] == 'alice' and me['name'] == 'Alice Example' and me['subject'] == self.SUB

    def test_claim_omitted_means_no_groups(self, world, idp):
        app, _ = world
        assert flow(app.test_client(), idp, self.claims(idp)).status_code == 403  # a user group is registered: unlisted are denied
        h.set_registry(app, admin=['sf-admins'])
        c = app.test_client()
        assert flow(c, idp, self.claims(idp)).status_code == 302 and c.get('/auth/me').get_json()['groups'] == []

    def test_claim_as_a_single_string(self, world, idp):
        app, _ = world
        c = app.test_client()
        assert flow(c, idp, self.claims(idp, groups='sf-users')).status_code == 302
        assert c.get('/auth/me').get_json()['groups'] == ['sf-users']
        c2 = app.test_client()
        flow(c2, idp, self.claims(idp, groups='sf-admins, other'))
        assert c2.get('/auth/me').get_json()['role'] == 'admin'

    def test_groups_from_userinfo_when_the_id_token_has_none(self, world, idp):
        app, _ = world
        idp.userinfo_claims = {'sub': self.SUB, 'groups': ['sf-admins']}
        c = app.test_client()
        flow(c, idp, self.claims(idp))
        assert c.get('/auth/me').get_json()['role'] == 'admin'

    def test_groups_with_spaces_match_exactly(self, world, idp):
        app, users = world
        client_for(app, users['root']).post('/api/access/groups', json={'name': 'Family Members', 'role': 'user'})
        c = app.test_client()
        assert flow(c, idp, self.claims(idp, groups=['Family Members'])).status_code == 302
        assert flow(app.test_client(), idp, self.claims(idp, groups=['family members'])).status_code == 403
