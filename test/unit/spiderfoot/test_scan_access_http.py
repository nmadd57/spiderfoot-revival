"""Scan lists, search, sharing and ownership through the real request path."""
import json
from unittest import mock

import pytest

from spiderfoot.event import SpiderFootEvent
from test.unit import identity_helpers as h
from test.unit.services.conftest import fake_modules


@pytest.fixture
def world(tmp_path):
    app = h.make_app(tmp_path, modules=fake_modules())
    h.configure_sso(app)
    users = {name: h.add_user(app, name, groups) for name, groups in (
        ('root', ['sf-admins']), ('olivia', ['sf-users', 'team-o']), ('edith', ['sf-users']), ('vic', ['sf-users']),
        ('gail', ['sf-users', 'editors']), ('sam', ['sf-users']))}
    ids = {n: u['id'] for n, u in users.items()}
    for sid, owner, target in (('S_OLIVIA', ids['olivia'], 'olivia.example'), ('S_SAM', ids['sam'], 'sam.example'),
                               ('S_LEGACY', None, 'legacy.example')):
        h.seed_scan(app, sid, owner=owner, target=target)
        store_events(app, sid, target)
    dbh = h.db(app)
    dbh.aclSet('S_OLIVIA', 'user', str(ids['edith']), 'edit')
    dbh.aclSet('S_OLIVIA', 'user', str(ids['vic']), 'view')
    dbh.aclSet('S_OLIVIA', 'group', 'editors', 'edit')
    return app, users


def store_events(app, scan_id, target):
    dbh = h.db(app)
    root = SpiderFootEvent('ROOT', target, '', None)
    seed = SpiderFootEvent('INTERNET_NAME', target, 'SpiderFoot UI', root)
    dbh.scanEventStore(scan_id, root)
    dbh.scanEventStore(scan_id, seed)
    dbh.scanEventStore(scan_id, SpiderFootEvent('INTERNET_NAME', 'www.' + target, 'sfp_crt', seed))


def client_for(app, user):
    return h.sign_in(app.test_client(), user)


def scan_ids(resp):
    return sorted(row[0] for row in resp.get_json())


class TestScanList:
    @pytest.mark.parametrize('who,expected', [
        ('root', ['S_LEGACY', 'S_OLIVIA', 'S_SAM']), ('olivia', ['S_OLIVIA']), ('edith', ['S_OLIVIA']), ('vic', ['S_OLIVIA']),
        ('gail', ['S_OLIVIA']), ('sam', ['S_SAM']),
    ])
    def test_json_list_is_filtered(self, world, who, expected):
        app, users = world
        assert scan_ids(client_for(app, users[who]).get('/api/scanlist')) == expected

    def test_rows_carry_owner_and_your_level_after_the_columns_the_cli_reads(self, world):
        app, users = world
        rows = {r[0]: r for r in client_for(app, users['edith']).get('/api/scanlist').get_json()}
        row = rows['S_OLIVIA']
        assert len(row) == 11 and row[1].startswith('scan ') and row[9] == 'Olivia' and row[10] == 'edit'
        root_rows = {r[0]: r for r in client_for(app, users['root']).get('/api/scanlist').get_json()}
        assert root_rows['S_LEGACY'][9] == '' and root_rows['S_LEGACY'][10] == 'owner'

    def test_dashboard_lists_only_visible_scans_and_counts_only_them(self, world):
        app, users = world
        html = client_for(app, users['sam']).get('/').get_data(as_text=True)
        assert 'sam.example' in html and 'olivia.example' not in html and 'legacy.example' not in html
        assert 'Mine' in html and 'Shared with me' in html
        admin = client_for(app, users['root']).get('/').get_data(as_text=True)
        assert all(t in admin for t in ('sam.example', 'olivia.example', 'legacy.example'))
        assert 'Shared with me' not in admin

    def test_filters_mine_and_shared(self, world):
        app, users = world
        c = client_for(app, users['edith'])
        assert 'olivia.example' in c.get('/?show=shared').get_data(as_text=True)
        assert 'olivia.example' not in c.get('/?show=mine').get_data(as_text=True)
        o = client_for(app, users['olivia'])
        assert 'olivia.example' in o.get('/?show=mine').get_data(as_text=True)
        assert 'olivia.example' not in o.get('/?show=shared').get_data(as_text=True)
        table = c.get('/frag/scan-table?show=shared').get_data(as_text=True)
        assert 'olivia.example' in table and 'sam.example' not in table

    def test_row_badges_and_buttons_follow_the_level(self, world):
        app, users = world
        shared = client_for(app, users['vic']).get('/frag/scan-table').get_data(as_text=True)
        assert 'Owner: Olivia' in shared and 'Shared &middot; view' in shared
        assert 'hx-post="/api/scandelete' not in shared
        mine = client_for(app, users['olivia']).get('/frag/scan-table').get_data(as_text=True)
        assert 'Mine' in mine and 'hx-post="/api/scandelete' in mine

    def test_everything_stays_visible_without_sign_in(self, tmp_path):
        app = h.make_app(tmp_path)
        h.seed_scan(app, 'ANY', owner=5, target='any.example')
        c = app.test_client()
        assert scan_ids(c.get('/api/scanlist')) == ['ANY']
        html = c.get('/scaninfo?id=ANY').get_data(as_text=True)
        assert 'any.example' in html and 'Sharing' not in html
        assert 'Shared with me' not in c.get('/').get_data(as_text=True)


class TestSearch:
    def test_global_search_only_returns_visible_scans(self, world):
        app, users = world
        rows = client_for(app, users['sam']).get('/api/search?value=*example*&eventType=INTERNET_NAME').get_json()
        assert rows and all('sam.example' in r[1] for r in rows)
        assert len(client_for(app, users['root']).get('/api/search?value=*example*&eventType=INTERNET_NAME').get_json()) >= 6

    def test_search_inside_a_hidden_scan_is_404(self, world):
        app, users = world
        r = client_for(app, users['sam']).get('/api/search?id=S_OLIVIA&value=*example*')
        assert r.status_code == 404

    def test_search_inside_a_shared_scan(self, world):
        app, users = world
        rows = client_for(app, users['vic']).get('/api/search?id=S_OLIVIA&value=*example*').get_json()
        assert rows and all('olivia.example' in r[1] for r in rows)

    def test_search_export_is_filtered_too(self, world):
        app, users = world
        r = client_for(app, users['sam']).get('/api/scansearchresultexport?value=*example*&eventType=INTERNET_NAME')
        text = r.get_data(as_text=True)
        assert 'sam.example' in text and 'olivia.example' not in text and 'legacy.example' not in text
        assert client_for(app, users['sam']).get('/api/scansearchresultexport?id=S_OLIVIA&value=*example*').status_code == 404


class TestMultiScanExports:
    def test_mixed_requests_are_refused_as_a_whole(self, world):
        app, users = world
        c = client_for(app, users['olivia'])
        for path in ('scaneventresultexportmulti', 'scanexportjsonmulti', 'scanvizmulti'):
            assert c.get(f'/api/{path}?ids=S_OLIVIA,S_SAM').status_code == 404
            assert c.get(f'/api/{path}?ids=S_OLIVIA').status_code in (200, 204)

    def test_exports_for_a_viewer(self, world):
        app, users = world
        c = client_for(app, users['vic'])
        csv = c.get('/api/scaneventresultexportmulti?ids=S_OLIVIA').get_data(as_text=True)
        assert 'olivia.example' in csv
        assert c.get('/api/scanviz?id=S_OLIVIA&gexf=0').status_code == 200
        assert c.get('/api/scanviz?id=S_SAM&gexf=0').status_code == 404


class TestSharing:
    def test_owner_shares_with_a_group_and_members_see_the_scan(self, world):
        app, users = world
        owner = client_for(app, users['olivia'])
        r = owner.post('/api/scan/S_OLIVIA/access', json={'type': 'group', 'principal': 'team-x', 'level': 'view'})
        assert r.status_code == 200
        body = r.get_json()
        assert {'type': 'group', 'principal': 'team-x', 'name': 'team-x', 'level': 'view'} in body['grants']
        assert body['canManage'] and body['yourLevel'] == 'owner' and body['owner']['name'] == 'Olivia'
        member = h.add_user(app, 'xena', ['sf-users', 'team-x'])
        c = client_for(app, member)
        assert scan_ids(c.get('/api/scanlist')) == ['S_OLIVIA']
        assert c.get('/api/scanstatus?id=S_OLIVIA').status_code == 200
        assert c.post('/api/stopscan', data={'id': 'S_OLIVIA'}).status_code == 403  # view only

    def test_view_then_edit_then_removed(self, world):
        app, users = world
        owner = client_for(app, users['olivia'])
        member = h.add_user(app, 'xena', ['sf-users', 'team-x'])
        c = client_for(app, member)
        owner.post('/api/scan/S_OLIVIA/access', json={'type': 'group', 'principal': 'team-x', 'level': 'view'})
        assert c.post('/api/resultsetfp', data={'id': 'S_OLIVIA', 'fp': '1', 'resultids': '[]'}).status_code == 403
        owner.post('/api/scan/S_OLIVIA/access', json={'type': 'group', 'principal': 'team-x', 'level': 'edit'})
        r = c.post('/api/resultsetfp', data={'id': 'S_OLIVIA', 'fp': '1', 'resultids': '[]'})
        assert r.status_code == 200  # through the gate; the handler answers
        assert c.post('/api/scandelete', data={'id': 'S_OLIVIA'}).status_code == 403
        listing = owner.get('/api/scan/S_OLIVIA/access').get_json()
        assert [g['level'] for g in listing['grants'] if g['principal'] == 'team-x'] == ['edit']  # updated, not duplicated
        r = owner.delete('/api/scan/S_OLIVIA/access', json={'type': 'group', 'principal': 'team-x'})
        assert r.status_code == 200 and all(g['principal'] != 'team-x' for g in r.get_json()['grants'])
        assert c.get('/api/scanstatus?id=S_OLIVIA').status_code == 404  # access ends at once

    def test_share_with_a_user(self, world):
        app, users = world
        owner = client_for(app, users['olivia'])
        r = owner.post('/api/scan/S_OLIVIA/access', json={'type': 'user', 'principal': str(users['sam']['id']), 'level': 'edit'})
        assert r.status_code == 200
        assert {'type': 'user', 'principal': str(users['sam']['id']), 'name': 'Sam', 'level': 'edit'} in r.get_json()['grants']
        assert 'S_OLIVIA' in scan_ids(client_for(app, users['sam']).get('/api/scanlist'))

    def test_view_grantee_cannot_share_and_does_not_see_other_grants(self, world):
        app, users = world
        c = client_for(app, users['vic'])
        listing = c.get('/api/scan/S_OLIVIA/access').get_json()
        assert listing['yourLevel'] == 'view' and not listing['canManage'] and not listing['canSeeGrants'] and listing['grants'] == []
        for method, body in (('post', {'type': 'group', 'principal': 'x', 'level': 'view'}), ('delete', {'type': 'user', 'principal': '1'})):
            assert getattr(c, method)('/api/scan/S_OLIVIA/access', json=body).status_code == 403
        assert len(h.db(app).aclList('S_OLIVIA')) == 3

    def test_edit_grantee_sees_the_list_read_only(self, world):
        app, users = world
        c = client_for(app, users['edith'])
        listing = c.get('/api/scan/S_OLIVIA/access').get_json()
        assert listing['yourLevel'] == 'edit' and listing['canSeeGrants'] and not listing['canManage']
        assert len(listing['grants']) == 3
        assert c.post('/api/scan/S_OLIVIA/access', json={'type': 'group', 'principal': 'x', 'level': 'view'}).status_code == 403
        assert c.delete('/api/scan/S_OLIVIA/access', json={'type': 'group', 'principal': 'editors'}).status_code == 403
        assert c.post('/api/scandelete', data={'id': 'S_OLIVIA'}).status_code == 403

    def test_group_grantee_acts_with_the_group_level(self, world):
        app, users = world
        c = client_for(app, users['gail'])  # in 'editors'
        assert c.get('/api/scan/S_OLIVIA/access').get_json()['yourLevel'] == 'edit'
        assert c.post('/api/scan/S_OLIVIA/access', json={'type': 'group', 'principal': 'x', 'level': 'view'}).status_code == 403

    def test_nobody_can_grant_more_than_edit(self, world):
        app, users = world
        for who in ('olivia', 'root'):
            r = client_for(app, users[who]).post('/api/scan/S_OLIVIA/access', json={'type': 'group', 'principal': 'x', 'level': 'owner'})
            assert r.status_code == 400

    def test_an_outsider_cannot_even_see_the_sharing_of_a_scan(self, world):
        app, users = world
        c = client_for(app, users['sam'])
        assert c.get('/api/scan/S_OLIVIA/access').status_code == 404
        assert c.post('/api/scan/S_OLIVIA/access', json={'type': 'group', 'principal': 'sam-group', 'level': 'view'}).status_code == 404

    def test_admin_can_share_anything_and_assign_owners(self, world):
        app, users = world
        admin = client_for(app, users['root'])
        assert admin.post('/api/scan/S_SAM/access', json={'type': 'group', 'principal': 'auditors', 'level': 'view'}).status_code == 200
        legacy = admin.get('/api/scan/S_LEGACY/access').get_json()
        assert legacy['unowned'] and legacy['owner'] is None and legacy['canManage']
        r = admin.post('/api/scan/S_LEGACY/owner', json={'user_id': users['olivia']['id']})
        assert r.status_code == 200 and r.get_json()['owner']['name'] == 'Olivia'
        assert 'S_LEGACY' in scan_ids(client_for(app, users['olivia']).get('/api/scanlist'))
        assert client_for(app, users['olivia']).post('/api/scan/S_LEGACY/owner', json={'user_id': 1}).status_code == 403

    @pytest.mark.parametrize('body', [
        {'type': 'team', 'principal': 'x', 'level': 'view'}, {'type': 'group', 'principal': 'x', 'level': 'admin'},
        {'type': 'group', 'principal': '', 'level': 'view'}, {'type': 'group', 'principal': 'a\x00b', 'level': 'view'},
        {'type': 'group', 'principal': 'g' * 201, 'level': 'view'}, {'type': 'user', 'principal': '9999', 'level': 'view'},
        {'type': 'user', 'principal': 'abc', 'level': 'view'}, {}, {'type': 'group', 'principal': 'x'},
    ])
    def test_bad_requests(self, world, body):
        app, users = world
        r = client_for(app, users['olivia']).post('/api/scan/S_OLIVIA/access', json=body)
        assert r.status_code == 400 and set(r.get_json()) == {'error'}
        assert len(h.db(app).aclList('S_OLIVIA')) == 3

    def test_sharing_with_the_owner_is_pointless(self, world):
        app, users = world
        r = client_for(app, users['olivia']).post('/api/scan/S_OLIVIA/access', json={'type': 'user', 'principal': str(users['olivia']['id']), 'level': 'view'})
        assert r.status_code == 400

    def test_removing_a_missing_grant(self, world):
        app, users = world
        assert client_for(app, users['olivia']).delete('/api/scan/S_OLIVIA/access', json={'type': 'group', 'principal': 'nope'}).status_code == 404

    def test_changes_need_csrf(self, world):
        app, users = world
        c = client_for(app, users['olivia'])
        c.environ_base.pop('HTTP_X_CSRF_TOKEN')
        assert c.post('/api/scan/S_OLIVIA/access', json={'type': 'group', 'principal': 'x', 'level': 'view'}).status_code == 403

    def test_deleting_the_scan_removes_the_grants(self, world):
        app, users = world
        assert client_for(app, users['olivia']).post('/api/scandelete', data={'id': 'S_OLIVIA'}).status_code == 200
        assert h.db(app).aclList('S_OLIVIA') == []

    def test_scan_page_shows_the_sharing_panel_by_level(self, world):
        app, users = world
        html = client_for(app, users['olivia']).get('/scaninfo?id=S_OLIVIA').get_data(as_text=True)
        assert 'scanSharing(' in html and 'Re-scan' in html
        view = client_for(app, users['vic']).get('/scaninfo?id=S_OLIVIA').get_data(as_text=True)
        assert 'scanSharing(' in view and 'Re-scan' not in view
        edit = client_for(app, users['edith']).get('/scaninfo?id=S_OLIVIA').get_data(as_text=True)
        assert 'Re-scan' in edit


class TestPickers:
    def test_user_picker_has_names_but_no_emails_or_groups(self, world):
        app, users = world
        r = client_for(app, users['olivia']).get('/api/users?q=ed')
        assert [u['name'] for u in r.get_json()] == ['Edith']
        text = r.get_data(as_text=True)
        assert '@example.test' not in text and 'sf-users' not in text

    def test_local_accounts_are_not_offered(self, world):
        app, users = world
        h.db(app).userUpsert('local:admin', 'admin', role='admin', login=False)
        assert 'admin' not in [u['username'] for u in client_for(app, users['olivia']).get('/api/users').get_json()]

    def test_group_suggestions(self, world):
        app, users = world
        groups = client_for(app, users['olivia']).get('/api/groups').get_json()
        assert 'editors' in groups and 'team-o' in groups


class TestOwnershipOfNewScans:
    @pytest.fixture
    def launch(self, world):
        app, users = world
        launched = []
        with mock.patch('spiderfoot.services.tools.tool_installed', return_value=False), \
                mock.patch('spiderfoot.blueprints.api.mp', h.fake_process_namespace(launched)):
            yield app, users, launched

    def test_new_scan_belongs_to_the_user_who_started_it(self, launch):
        app, users, launched = launch
        c = client_for(app, users['olivia'])
        r = c.post('/api/startscan', data={'scanname': 'mine', 'scantarget': 'example.org', 'modulelist': 'sfp_dnsresolve'})
        assert r.get_json()[0] == 'SUCCESS', r.get_json()
        sid = r.get_json()[1]
        assert launched[-1]['cfg_owner'] == users['olivia']['id']
        assert h.db(app).scanOwnerGet(sid) == users['olivia']['id']
        assert sid in scan_ids(c.get('/api/scanlist'))
        assert sid not in scan_ids(client_for(app, users['sam']).get('/api/scanlist'))

    def test_share_with_in_the_new_scan_form(self, launch):
        app, users, launched = launch
        share = json.dumps([{'type': 'group', 'principal': 'team-z', 'level': 'edit'},
                            {'type': 'user', 'principal': str(users['sam']['id']), 'level': 'view'},
                            {'type': 'user', 'principal': str(users['olivia']['id']), 'level': 'view'},  # the owner: skipped
                            {'type': 'group', 'principal': 'x', 'level': 'owner'}, {'type': 'bogus'}, 'junk'])
        form = {'scanname': 's', 'scantarget': 'example.org', 'modulelist': 'sfp_dnsresolve', 'share_with': share}
        r = client_for(app, users['olivia']).post('/api/startscan', data=form)
        sid = r.get_json()[1]
        grants = {(g['principal_type'], g['principal'], g['level']) for g in h.db(app).aclList(sid)}
        assert grants == {('group', 'team-z', 'edit'), ('user', str(users['sam']['id']), 'view')}

    def test_rerun_needs_edit_and_the_new_scan_is_the_callers(self, launch):
        app, users, launched = launch
        assert client_for(app, users['vic']).post('/api/rerunscan', data={'id': 'S_OLIVIA'}).status_code == 403
        r = client_for(app, users['edith']).post('/api/rerunscan', data={'id': 'S_OLIVIA'})
        assert r.get_json()[0] == 'SUCCESS', r.get_json()
        new = r.get_json()[1]
        assert h.db(app).scanOwnerGet(new) == users['edith']['id']
        assert new not in scan_ids(client_for(app, users['olivia']).get('/api/scanlist'))  # a clone is its creator's own

    def test_basic_auth_user_owns_what_it_starts(self, tmp_path):
        from spiderfoot.app import _hash_password
        import base64
        app = h.make_app(tmp_path, modules=fake_modules())
        app.config['SF_USERS'] = {'robot': _hash_password('pw-9999')}
        launched = []
        auth = {'Authorization': 'Basic ' + base64.b64encode(b'robot:pw-9999').decode()}
        with mock.patch('spiderfoot.services.tools.tool_installed', return_value=False), \
                mock.patch('spiderfoot.blueprints.api.mp', h.fake_process_namespace(launched)):
            r = app.test_client().post('/api/startscan', headers=auth, data={'scanname': 's', 'scantarget': 'example.org', 'modulelist': 'sfp_dnsresolve'})
        assert r.get_json()[0] == 'SUCCESS'
        row = h.db(app).userGetBySubject('local:robot')
        assert row and row['role'] == 'admin' and h.db(app).scanOwnerGet(r.get_json()[1]) == row['id']

    def test_scans_stay_unowned_without_sign_in(self, tmp_path):
        app = h.make_app(tmp_path, modules=fake_modules())
        launched = []
        with mock.patch('spiderfoot.services.tools.tool_installed', return_value=False), \
                mock.patch('spiderfoot.blueprints.api.mp', h.fake_process_namespace(launched)):
            c = app.test_client()
            token = __import__('re').search(r'name="csrf-token" content="([^"]+)"', c.get('/').get_data(as_text=True)).group(1)
            r = c.post('/api/startscan', headers={'X-CSRF-Token': token},
                       data={'scanname': 's', 'scantarget': 'example.org', 'modulelist': 'sfp_dnsresolve'})
        assert r.get_json()[0] == 'SUCCESS' and h.db(app).scanOwnerGet(r.get_json()[1]) is None


class TestSettingsAccess:
    def test_save_masks_and_never_returns_the_secret(self, world):
        app, users = world
        c = client_for(app, users['root'])
        r = c.post('/api/access/settings', json={'oidc_client_secret': 'brand-new-secret-value', 'oidc_scopes': 'openid email groups'})
        assert r.status_code == 200
        body = r.get_data(as_text=True)
        assert 'brand-new-secret-value' not in body and r.get_json()['secretSet'] is True
        assert h.db(app).configGet()['_oidc_client_secret'] == 'brand-new-secret-value'
        assert 'brand-new-secret-value' not in c.get('/api/access/settings').get_data(as_text=True)
        assert 'brand-new-secret-value' not in c.get('/frag/settings-section?section=access').get_data(as_text=True)

    def test_blank_or_masked_secret_keeps_the_saved_one(self, world):
        app, users = world
        c = client_for(app, users['root'])
        for value in ('', '********', None):
            c.post('/api/access/settings', json={'oidc_client_secret': value, 'oidc_client_id': h.CLIENT_ID})
        assert h.db(app).configGet()['_oidc_client_secret'] == h.CLIENT_SECRET
        assert c.post('/api/access/settings', json={'clear_secret': True}).get_json()['secretSet'] is False

    def test_environment_values_win_and_cannot_be_changed(self, world, monkeypatch):
        app, users = world
        monkeypatch.setenv('SF_OIDC_ISSUER', 'https://env-idp.test')
        c = client_for(app, users['root'])
        r = c.post('/api/access/settings', json={'oidc_issuer': 'https://other.test', 'oidc_scopes': 'openid email'})
        d = r.get_json()
        assert d['ignored'] == ['oidc_issuer'] and d['fields']['oidc_issuer'] == 'https://env-idp.test' and 'oidc_issuer' in d['env']
        assert h.db(app).configGet()['_oidc_issuer'] == h.ISSUER

    @pytest.mark.parametrize('body', [
        {'oidc_issuer': 'http://idp.example.com'}, {'oidc_issuer': 'https://idp.example.com/?x=1'}, {'oidc_issuer': 'ftp://x'},
        {'oidc_scopes': 'email profile'}, {'auth_session_hours': 'many'}, {'auth_session_hours': '0'}, {'auth_session_hours': '99999'},
        {'oidc_enabled': 'maybe'}, {'bogus_setting': 'x'}, {'oidc_issuer': 'x' * 2500},
    ])
    def test_validation(self, world, body):
        app, users = world
        r = client_for(app, users['root']).post('/api/access/settings', json=body)
        assert r.status_code == 400 and set(r.get_json()) == {'error'}

    def test_http_is_fine_for_localhost(self, world):
        app, users = world
        assert client_for(app, users['root']).post('/api/access/settings', json={'oidc_issuer': 'http://127.0.0.1:5095'}).status_code == 200

    def test_cannot_lock_everyone_out(self, world):
        app, users = world
        c = client_for(app, users['root'])
        r = c.post('/api/access/settings', json={'oidc_admin_groups': []})
        assert r.status_code == 400 and 'admin group' in r.get_json()['error']
        r = c.post('/api/access/settings', json={'oidc_admin_groups': ['somebody-else']})
        assert r.status_code == 400 and 'your own administrator access' in r.get_json()['error']
        assert h.db(app).configGet()['_oidc_admin_groups'] == 'sf-admins'
        assert c.post('/api/access/settings', json={'oidc_admin_groups': ['sf-admins', 'more']}).status_code == 200

    def test_turning_sso_on_needs_an_explicit_acknowledgement(self, tmp_path):
        app = h.make_app(tmp_path)
        c = app.test_client()
        token = __import__('re').search(r'name="csrf-token" content="([^"]+)"', c.get('/').get_data(as_text=True)).group(1)
        c.environ_base['HTTP_X_CSRF_TOKEN'] = token
        body = {'oidc_issuer': h.ISSUER, 'oidc_client_id': h.CLIENT_ID, 'oidc_admin_groups': ['sf-admins']}
        r = c.post('/api/access/settings', json=body)
        assert r.status_code == 400 and 'Confirm' in r.get_json()['error']
        no_admin = c.post('/api/access/settings', json={**body, 'oidc_admin_groups': [], 'acknowledge': True})
        assert no_admin.status_code == 400
        assert c.post('/api/access/settings', json={**body, 'acknowledge': True}).status_code == 200
        assert c.get('/api/scanlist', headers={'Sec-Fetch-Mode': 'cors'}).status_code == 401  # now everyone has to sign in

    def test_connection_test_reports_the_provider_without_secrets(self, world, monkeypatch):
        app, users = world
        idp = h.FakeIdp()
        idp.install(monkeypatch)
        c = client_for(app, users['root'])
        d = c.post('/api/access/test', json={}).get_json()
        assert d['ok'] and d['issuer'] == h.ISSUER and d['keys'] == 1 and d['groups_scope'] is True and d['pkce'] is True
        assert d['userinfo_endpoint'].endswith('/userinfo') and h.CLIENT_SECRET not in json.dumps(d)
        idp.discovery_doc['scopes_supported'] = ['openid', 'email']
        h.oidc.clear_cache()
        assert c.post('/api/access/test', json={}).get_json()['groups_scope'] is False

    def test_connection_test_failures_are_plain(self, world, monkeypatch):
        app, users = world

        def boom(url, headers=None):
            raise h.oidc.OidcError('unreachable', 'The identity provider could not be reached.')
        monkeypatch.setattr(h.oidc, 'http_get_json', boom)
        h.oidc.clear_cache()
        d = client_for(app, users['root']).post('/api/access/test', json={'oidc_issuer': 'https://down.example.com'}).get_json()
        assert d == {'ok': False, 'message': 'The identity provider could not be reached.'}
        assert client_for(app, users['root']).post('/api/access/test', json={'oidc_issuer': 'http://plain.example.com'}).get_json()['ok'] is False

    def test_users_directory_is_read_only_and_complete(self, world):
        app, users = world
        rows = client_for(app, users['root']).get('/api/access/users').get_json()
        by_name = {r['username']: r for r in rows}
        assert by_name['root']['role'] == 'admin' and by_name['olivia']['role'] == 'user' and 'editors' in by_name['gail']['groups']
        assert client_for(app, users['root']).post('/api/access/users', json={}).status_code == 405

    def test_access_page_renders_for_admins(self, world):
        app, users = world
        html = client_for(app, users['root']).get('/frag/settings-section?section=access').get_data(as_text=True)
        assert 'accessSettings(' in html and 'Test connection' in html and '/auth/callback' in html and 'Olivia' in html
