"""Every route is classified, every scan-bearing route is gated, and the gate gives the right answer for each kind of user."""
import inspect
import re

import pytest

from spiderfoot.services import access, identity, route_policy
from test.unit import identity_helpers as h

SCAN_OWNED, SCAN_LEGACY, SCAN_OTHER = 'OWNED001', 'LEGACY01', 'OTHER001'


@pytest.fixture(scope='module')
def world(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('policy')
    app = h.make_app(tmp)
    h.configure_sso(app)
    users = {
        'admin': h.add_user(app, 'root', ['sf-admins']),
        'owner': h.add_user(app, 'olivia', ['sf-users', 'team-o']),
        'editor': h.add_user(app, 'edith', ['sf-users']),
        'viewer': h.add_user(app, 'vic', ['sf-users']),
        'group_editor': h.add_user(app, 'gail', ['sf-users', 'editors']),
        'group_viewer': h.add_user(app, 'gus', ['sf-users', 'readers']),
        'stranger': h.add_user(app, 'sam', ['sf-users']),
    }
    third = h.add_user(app, 'third', ['sf-users'])
    h.seed_scan(app, SCAN_OWNED, owner=users['owner']['id'])
    h.seed_scan(app, SCAN_LEGACY, owner=None)
    h.seed_scan(app, SCAN_OTHER, owner=third['id'])
    dbh = h.db(app)
    dbh.aclSet(SCAN_OWNED, 'user', str(users['editor']['id']), 'edit')
    dbh.aclSet(SCAN_OWNED, 'user', str(users['viewer']['id']), 'view')
    dbh.aclSet(SCAN_OWNED, 'group', 'editors', 'edit')
    dbh.aclSet(SCAN_OWNED, 'group', 'readers', 'view')
    corr = dbh.correlationResultCreate(SCAN_OWNED, 'Title', 'rule', 'descr', 'HIGH', 'rule_id', 'logic: x', [])
    return app, users, corr


def rules(app):
    return [r for r in app.url_map.iter_rules()]


class TestEveryRouteIsClassified:
    def test_no_route_is_missing_from_the_policy_table(self, world):
        app, _, _ = world
        missing = sorted({r.endpoint for r in rules(app) if route_policy.table_policy(r.endpoint) is None})
        assert not missing, f'These routes have no entry in spiderfoot/services/route_policy.py (add one): {missing}'

    def test_no_stale_entries(self, world):
        app, _, _ = world
        endpoints = {r.endpoint.replace('api_compat.', 'api.') for r in rules(app)}
        stale = sorted(set(route_policy.POLICIES) - endpoints)
        assert not stale, f'Policy entries for routes that no longer exist: {stale}'

    def test_views_that_take_a_scan_id_are_gated(self, world):
        """A view that reads a scan or correlation id must be a scan route or a filtered list; if this fails, a new
        scan-bearing route was added without access control."""
        app, _, _ = world
        pattern = re.compile(r"""(?:request\.(?:values|args|form|json)\.get(?:list)?\(\s*['"](?:id|ids|scan_id|scanid|scan|correlation_id)['"]"""
                             r"""|request\.(?:values|args|form)\[\s*['"](?:id|ids|scan_id)['"])""")
        offenders = []
        for rule in rules(app):
            policy = route_policy.table_policy(rule.endpoint)
            view = app.view_functions[rule.endpoint]
            takes_id = bool({'scan_id', 'correlation_id'} & set(rule.arguments)) or bool(pattern.search(inspect.getsource(view)))
            if takes_id and policy.kind not in ('scan', 'filtered', 'admin'):
                offenders.append((rule.endpoint, policy.kind))
        assert not offenders, f'Routes that read a scan id but are not gated by scan access: {offenders}'

    def test_scan_policies_name_the_argument_the_view_reads(self, world):
        app, _, _ = world
        for rule in rules(app):
            policy = route_policy.table_policy(rule.endpoint)
            if policy.kind != 'scan':
                continue
            if policy.where == 'path':
                assert policy.arg in rule.arguments, rule.endpoint
            else:
                assert f"'{policy.arg}'" in inspect.getsource(app.view_functions[rule.endpoint]), rule.endpoint

    def test_filtered_routes_really_filter(self, world):
        app, _, _ = world
        for rule in rules(app):
            if route_policy.table_policy(rule.endpoint).kind == 'filtered':
                source = inspect.getsource(app.view_functions[rule.endpoint])
                assert re.search(r'filter_scan_list|visible_scans|_search_scope|_build_scan_list|_load_scans', source), rule.endpoint

    def test_an_unlisted_route_is_for_administrators_only(self, tmp_path):
        app = h.make_app(tmp_path)
        h.configure_sso(app)

        @app.route('/brand-new-route')
        def brand_new():
            return 'ok'
        user = h.add_user(app, 'plain', ['sf-users'])
        admin = h.add_user(app, 'boss', ['sf-admins'])
        plain = h.sign_in(app.test_client(), user)
        boss = h.sign_in(app.test_client(), admin)
        assert plain.get('/brand-new-route').status_code == 403
        assert boss.get('/brand-new-route').status_code == 200


def url_for_rule(rule, corr, scan=SCAN_OWNED, arg_value=None):
    """A concrete URL for a rule, naming the scan wherever the policy looks for it."""
    policy = route_policy.table_policy(rule.endpoint)
    path = rule.rule
    for name in rule.arguments:
        value = corr if name == 'correlation_id' else (scan if name == 'scan_id' else 'x')
        path = re.sub(r'<(?:[^:>]+:)?' + name + '>', value, path)
    if policy.where == 'values':
        value = arg_value or scan
        path += ('&' if '?' in path else '?') + f'{policy.arg}={value}'
    return path


def scan_rules(app):
    seen, out = set(), []
    for rule in rules(app):
        policy = route_policy.table_policy(rule.endpoint)
        key = rule.endpoint.replace('api_compat.', 'api.')
        if policy.kind == 'scan' and key not in seen and rule.endpoint != 'static':
            seen.add(key)
            out.append(rule)
    return out


RANK = {'none': 0, 'view': 1, 'edit': 2, 'owner': 3}
PERSONA_LEVEL = {'admin': 'owner', 'owner': 'owner', 'editor': 'edit', 'viewer': 'view', 'group_editor': 'edit',
                 'group_viewer': 'view', 'stranger': 'none'}


class TestScanGate:
    """route_policy.authorize decides; run it for every scan route and every kind of user."""

    @pytest.mark.parametrize('persona', list(PERSONA_LEVEL))
    def test_every_scan_route_for_every_persona(self, world, persona):
        app, users, corr = world
        row = users[persona]
        checked = 0
        for rule in scan_rules(app):
            policy = route_policy.table_policy(rule.endpoint)
            method = [m for m in sorted(rule.methods) if m not in ('HEAD', 'OPTIONS')][0]
            with app.test_request_context(url_for_rule(rule, corr), method=method) as ctx:
                assert ctx.request.endpoint == rule.endpoint or rule.endpoint.startswith('api_compat')
                settings = identity.load_settings(h.db(app))
                user = identity.user_from_row(row, settings)
                refused = route_policy.authorize(user, settings, lambda: h.db(app))
            allowed = RANK[PERSONA_LEVEL[persona]] >= RANK[policy.level]
            assert (refused is None) == allowed, f'{rule.endpoint} for {persona}: expected {"allow" if allowed else "refuse"}'
            if not allowed:
                want = 404 if PERSONA_LEVEL[persona] == 'none' else 403
                assert refused.status_code == want, f'{rule.endpoint} for {persona}'
            checked += 1
        assert checked >= 25

    def test_multi_id_routes_need_every_scan(self, world):
        app, users, corr = world
        user = identity.user_from_row(users['owner'], identity.load_settings(h.db(app)))
        multi = [r for r in scan_rules(app) if route_policy.table_policy(r.endpoint).multi]
        assert len(multi) >= 6
        for rule in multi:
            method = [m for m in sorted(rule.methods) if m not in ('HEAD', 'OPTIONS')][0]
            for ids, ok in ((SCAN_OWNED, True), (f'{SCAN_OWNED},{SCAN_OTHER}', False), (f'{SCAN_OTHER},{SCAN_OWNED}', False),
                            (f'{SCAN_OWNED},', True)):
                with app.test_request_context(url_for_rule(rule, corr, arg_value=ids), method=method):
                    refused = route_policy.authorize(user, identity.load_settings(h.db(app)), lambda: h.db(app))
                assert (refused is None) == ok, (rule.endpoint, ids)

    def test_repeated_parameter_cannot_smuggle_a_scan_in(self, world):
        app, users, corr = world
        user = identity.user_from_row(users['stranger'], identity.load_settings(h.db(app)))
        with app.test_request_context(f'/api/scanstatus?id={SCAN_OTHER}&id={SCAN_OWNED}'):
            assert route_policy.authorize(user, identity.load_settings(h.db(app)), lambda: h.db(app)).status_code == 404

    def test_the_root_level_copy_of_the_api_follows_the_same_policy(self, world):
        app, users, corr = world
        c = h.sign_in(app.test_client(), users['stranger'])
        for path in ('/api/scanstatus', '/scanstatus', '/api/scansummary', '/scansummary'):
            assert c.get(f'{path}?id={SCAN_OWNED}').status_code == 404, path

    def test_unowned_legacy_scan_is_admin_only(self, world):
        app, users, corr = world
        settings = identity.load_settings(h.db(app))
        for persona in ('owner', 'viewer', 'stranger'):
            user = identity.user_from_row(users[persona], settings)
            assert access.scan_level(user, SCAN_LEGACY, h.db(app)) == access.NONE
        assert access.scan_level(identity.user_from_row(users['admin'], settings), SCAN_LEGACY, h.db(app)) == access.OWNER

    def test_unowned_visible_setting_makes_legacy_scans_readable(self, tmp_path):
        app = h.make_app(tmp_path)
        h.configure_sso(app, _auth_unowned_visible='1')
        h.seed_scan(app, 'LEG', owner=None)
        user = h.add_user(app, 'reader', ['sf-users'])
        c = h.sign_in(app.test_client(), user)
        assert c.get('/api/scanstatus?id=LEG').status_code == 200
        assert c.post('/api/stopscan', data={'id': 'LEG'}).status_code == 403  # visible, not editable


class TestHttpDenials:
    """The same gate through the real request path (denied requests never reach the handler)."""

    def test_no_access_is_404_everywhere_on_the_api(self, world):
        app, users, corr = world
        c = h.sign_in(app.test_client(), users['stranger'])
        for rule in scan_rules(app):
            if rule.endpoint.startswith('api_compat'):
                continue
            method = [m for m in sorted(rule.methods) if m not in ('HEAD', 'OPTIONS')][0]
            r = c.open(url_for_rule(rule, corr), method=method)
            assert r.status_code == 404, f'{rule.endpoint} answered {r.status_code} to someone with no access'

    def test_view_access_cannot_change_anything(self, world):
        app, users, corr = world
        c = h.sign_in(app.test_client(), users['viewer'])
        for path, data in (('/api/stopscan', {'id': SCAN_OWNED}), ('/api/scandelete', {'id': SCAN_OWNED}),
                           ('/api/rerunscan', {'id': SCAN_OWNED}), ('/api/resultsetfp', {'id': SCAN_OWNED, 'fp': '1', 'resultids': '[]'}),
                           ('/api/rerunscanmulti', {'ids': SCAN_OWNED})):
            assert c.post(path, data=data).status_code == 403, path
        assert h.db(app).scanExists(SCAN_OWNED)

    def test_edit_access_cannot_delete(self, world):
        app, users, corr = world
        c = h.sign_in(app.test_client(), users['editor'])
        assert c.post('/api/scandelete', data={'id': SCAN_OWNED}).status_code == 403
        assert c.post(f'/api/scan/{SCAN_OWNED}/access', json={'type': 'group', 'principal': 'x', 'level': 'view'}).status_code == 403
        assert h.db(app).scanExists(SCAN_OWNED)

    def test_other_users_scans_cannot_be_deleted_by_guessing_ids_in_a_list(self, world):
        app, users, corr = world
        c = h.sign_in(app.test_client(), users['owner'])
        r = c.post('/api/scandelete', data={'id': f'{SCAN_OWNED},{SCAN_OTHER}'})
        assert r.status_code == 404 and h.db(app).scanExists(SCAN_OWNED) and h.db(app).scanExists(SCAN_OTHER)

    def test_pages_and_fragments_hide_scans_too(self, world):
        app, users, corr = world
        c = h.sign_in(app.test_client(), users['stranger'])
        page = c.get(f'/scaninfo?id={SCAN_OWNED}')
        assert page.status_code == 404 and 'OWNED001' not in page.get_data(as_text=True).replace('Scan not found', '')
        for path in (f'/frag/results-tab?id={SCAN_OWNED}&tab=summary', f'/frag/events?id={SCAN_OWNED}', f'/frag/log-lines?id={SCAN_OWNED}',
                     f'/frag/scan/{SCAN_OWNED}/summary', f'/frag/correlation/{corr}/explain'):
            assert c.get(path).status_code == 404, path

    def test_a_viewer_can_read_through_pages_and_fragments(self, world):
        app, users, corr = world
        c = h.sign_in(app.test_client(), users['viewer'])
        assert c.get(f'/scaninfo?id={SCAN_OWNED}').status_code == 200
        assert c.get(f'/frag/results-tab?id={SCAN_OWNED}&tab=summary').status_code == 200
        assert c.get(f'/api/scanstatus?id={SCAN_OWNED}').status_code == 200
        assert c.get(f'/api/scanexportlogs?id={SCAN_OWNED}').status_code not in (403, 404)


ADMIN_ONLY = [
    ('post', '/api/query', {'query': 'select 1'}), ('post', '/api/modulestate', {}), ('get', '/api/usage', None),
    ('post', '/api/usage/limits', {}), ('get', '/api/modulesettings', None), ('post', '/api/ai/test', {}),
    ('post', '/api/searxng/test', {}), ('post', '/api/embeddings/test', {}), ('post', '/api/moduletest', {}),
    ('post', '/api/usage/issue/clear', {}), ('post', '/api/usage/reset', {}), ('post', '/api/usage/check', {}),
    ('get', '/api/optsraw', None), ('get', '/api/optsexport', None), ('post', '/api/savesettingsraw', {}),
    ('post', '/api/savesettings', {}), ('post', '/api/vacuum', {}), ('post', '/api/presets', {}),
    ('delete', '/api/presets/default', None), ('delete', '/api/presets/x', None), ('post', '/api/presets/x/default', {}),
    ('patch', '/api/presets/x', {}), ('post', '/api/mcp/settings', {'allow_scan': True}), ('get', '/api/access/settings', None),
    ('post', '/api/access/settings', {'oidc_issuer': 'https://x.test'}), ('post', '/api/access/test', {}), ('get', '/api/access/users', None),
    ('get', '/api/access/groups', None), ('post', '/api/access/groups', {'name': 'x', 'role': 'user'}),
    ('post', '/api/access/groups/update', {'name': 'x', 'role': 'admin'}), ('post', '/api/access/groups/remove', {'name': 'x'}),
    (('post'), f'/api/scan/{SCAN_OWNED}/owner', {'user_id': 1}),
    ('get', '/frag/settings-section?section=general', None), ('get', '/frag/settings-section?section=modules', None),
    ('get', '/frag/settings-section?section=ai', None), ('get', '/frag/settings-section?section=access', None),
    ('get', '/frag/settings-section?section=proxy', None), ('get', '/frag/settings-section?section=database', None),
    ('get', '/frag/settings-section?section=search', None), ('get', '/frag/settings-section', None),
    ('get', '/query', None),
]
USER_OK = [
    ('get', '/'), ('get', '/newscan'), ('get', '/opts'), ('get', '/api/modules'), ('get', '/api/eventtypes'),
    ('get', '/api/correlationrules'), ('get', '/api/presets'), ('get', '/api/scanlist'), ('get', '/frag/scan-table'),
    ('get', '/frag/settings-section?section=appearance'), ('get', '/frag/settings-section?section=mcp'),
    ('get', '/api/mcp/settings'), ('get', '/api/mcp/tokens'), ('get', '/api/users'), ('get', '/api/groups'), ('get', '/auth/me'),
]


class TestAdminOnly:
    @pytest.mark.parametrize('method,path,body', ADMIN_ONLY)
    def test_plain_users_are_refused(self, world, method, path, body):
        app, users, corr = world
        c = h.sign_in(app.test_client(), users['owner'])
        r = getattr(c, method)(path, json=body) if body is not None else getattr(c, method)(path)
        if path == '/query':
            assert r.status_code in (403, 404, 405)
        else:
            assert r.status_code == 403, f'{method} {path} answered {r.status_code}'

    @pytest.mark.parametrize('method,path,body', ADMIN_ONLY[:3] + ADMIN_ONLY[13:16])
    def test_admins_get_through(self, world, method, path, body):
        app, users, corr = world
        c = h.sign_in(app.test_client(), users['admin'])
        r = getattr(c, method)(path, json=body) if body is not None else getattr(c, method)(path)
        assert r.status_code != 403

    @pytest.mark.parametrize('method,path', USER_OK)
    def test_plain_users_can_use_the_rest(self, world, method, path):
        app, users, corr = world
        c = h.sign_in(app.test_client(), users['owner'])
        assert getattr(c, method)(path).status_code == 200, path

    def test_settings_page_for_users_has_no_admin_sections_or_values(self, world):
        app, users, corr = world
        html = h.sign_in(app.test_client(), users['owner']).get('/opts').get_data(as_text=True)
        assert 'Appearance' in html and 'Agent (MCP)' in html
        for hidden in ('Proxy / TOR', 'AI Assistant', "'Access'", 'Web Search', 'settings_general', '_socks1type'):
            assert hidden not in html
        admin_html = h.sign_in(app.test_client(), users['admin']).get('/opts').get_data(as_text=True)
        assert 'Proxy / TOR' in admin_html and 'Access' in admin_html

    def test_other_users_tokens_are_not_reachable(self, world):
        app, users, corr = world
        mine = h.sign_in(app.test_client(), users['owner'])
        theirs = h.sign_in(app.test_client(), users['editor'])
        token_id = mine.post('/api/mcp/tokens', json={'name': 'mine'}).get_json()['tokens'][0]['id']
        assert theirs.get('/api/mcp/tokens').get_json()['tokens'] == []
        assert theirs.delete(f'/api/mcp/tokens/{token_id}').status_code == 404
        assert len(mine.get('/api/mcp/tokens').get_json()['tokens']) == 1

    def test_unauthenticated_requests_never_reach_a_handler(self, world):
        app, users, corr = world
        c = app.test_client()
        for rule in rules(app):
            if route_policy.table_policy(rule.endpoint).kind == 'public' or rule.endpoint == 'static':
                continue
            method = [m for m in sorted(rule.methods) if m not in ('HEAD', 'OPTIONS')][0]
            r = c.open(re.sub(r'<[^>]+>', 'x', rule.rule), method=method)
            assert r.status_code in (401, 302, 403), (rule.endpoint, r.status_code)
