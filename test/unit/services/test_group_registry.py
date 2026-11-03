"""The group registry: validation, role resolution, migration from the old lists and environment seeds, Dex-shaped claims."""
import json

import pytest

from spiderfoot.services import groups as g
from spiderfoot.services import identity, oidc

NOW = 1_700_000_000


def reg(*items):
    return [g._entry(n, r, '', 'tester', NOW) for n, r in items]


class TestNames:
    @pytest.mark.parametrize('raw,expected', [('spiderfoot', 'spiderfoot'), ('  padded  ', 'padded'), ('Team Alpha', 'Team Alpha'),
                                              ('a' * 100, 'a' * 100), ('über-gruppe', 'über-gruppe')])
    def test_valid(self, raw, expected):
        assert g.clean_name(raw) == expected

    @pytest.mark.parametrize('raw', ['', '   ', 'a' * 101, 'a,b', 'tab\there', 'nl\nhere', 'nul\x00', 'del\x7f', 'line sep', None, 7, ['x']])
    def test_invalid(self, raw):
        with pytest.raises(g.GroupError):
            g.clean_name(raw)

    @pytest.mark.parametrize('raw', ['', 'root', 'ADMIN ', None, 3])
    def test_role_must_be_admin_or_user(self, raw):
        if str(raw).strip().lower() in ('admin',):
            assert g.clean_role(raw) == 'admin'
        else:
            with pytest.raises(g.GroupError):
                g.clean_role(raw)

    def test_description_limits(self):
        assert g.clean_description(None) == '' and g.clean_description('  hi ') == 'hi'
        assert g.clean_description('d' * 200) == 'd' * 200
        for bad in ('d' * 201, 'x\x00y', 5):
            with pytest.raises(g.GroupError):
                g.clean_description(bad)


class TestChanges:
    def test_add_change_remove(self):
        r = g.add([], ' ops ', 'user', 'Operations', 'nick', NOW)
        assert r == [{'name': 'ops', 'role': 'user', 'description': 'Operations', 'added_by': 'nick', 'added': NOW}]
        r = g.change(r, 'ops', role='admin')
        assert r[0]['role'] == 'admin' and r[0]['description'] == 'Operations'
        r = g.change(r, 'ops', description='')
        assert r[0]['description'] == ''
        assert g.remove(r, 'ops') == []

    def test_duplicates_are_refused_exactly_but_case_differs(self):
        r = g.add([], 'Ops', 'user', '', 'n')
        with pytest.raises(g.GroupError) as e:
            g.add(r, ' Ops ', 'admin', '', 'n')
        assert e.value.status == 409
        assert len(g.add(r, 'ops', 'user', '', 'n')) == 2  # case-sensitive: a different group

    def test_unknown_group(self):
        for fn in (lambda: g.change([], 'x', role='user'), lambda: g.remove([], 'x')):
            with pytest.raises(g.GroupError) as e:
                fn()
            assert e.value.status == 404

    def test_invalid_role_on_change_leaves_registry_alone(self):
        r = reg(('a', 'user'))
        with pytest.raises(g.GroupError):
            g.change(r, 'a', role='root')
        assert r[0]['role'] == 'user'

    def test_limit(self):
        r = [g._entry(f'g{i}', 'user') for i in range(g.MAX_GROUPS)]
        with pytest.raises(g.GroupError):
            g.add(r, 'one-more', 'user', '', 'n')

    def test_storage_round_trip_and_garbage(self):
        r = reg(('a', 'admin'), ('b', 'user'))
        parsed, ok = g.parse(g.dumps(r))
        assert ok and parsed == r
        assert g.parse('') == (None, True) and g.parse(None) == (None, True)
        assert g.parse('not json') == (None, False) and g.parse('{"a":1}') == (None, False)
        parsed, ok = g.parse(json.dumps([{'name': 'ok', 'role': 'user'}, {'name': 'bad,name', 'role': 'user'}, {'name': 'x', 'role': 'root'}, 5]))
        assert ok and [e['name'] for e in parsed] == ['ok']

    def test_duplicate_names_in_storage_keep_the_admin_entry(self):
        parsed, _ = g.parse(json.dumps([{'name': 'a', 'role': 'user'}, {'name': 'a', 'role': 'admin'}, {'name': 'b', 'role': 'admin'}, {'name': 'b', 'role': 'user'}]))
        assert {e['name']: e['role'] for e in parsed} == {'a': 'admin', 'b': 'admin'}


class TestResolve:
    R = reg(('admins', 'admin'), ('users', 'user'), ('Mixed', 'user'))

    @pytest.mark.parametrize('groups,default,expected', [
        (['admins'], 'none', 'admin'), (['users'], 'none', 'user'), (['users', 'admins'], 'none', 'admin'),  # admin beats user
        (['admins', 'users'], 'user', 'admin'),
        (['other'], 'none', 'denied'), (['other'], 'user', 'user'), ([], 'none', 'denied'), ([], 'user', 'user'),
        (['mixed'], 'none', 'denied'), (['Mixed'], 'none', 'user'),  # exact, case-sensitive
        ([' admins '], 'none', 'admin'),  # whitespace around a stored value is trimmed
        (None, 'none', 'denied'),
    ])
    def test_resolve(self, groups, default, expected):
        assert g.resolve(groups, self.R, default) == expected

    def test_default_role_automatic_follows_the_old_semantics(self):
        only_admins = reg(('a', 'admin'))
        with_users = reg(('a', 'admin'), ('u', 'user'))
        assert g.effective_default('', only_admins) == 'user'  # no user group: any signed-in account is a user (as before)
        assert g.effective_default('', with_users) == 'none'  # a user group makes membership required (as before)
        assert g.effective_default('user', with_users) == 'user'
        assert g.effective_default('none', only_admins) == 'none'
        assert g.effective_default('bogus', only_admins) == 'user'
        assert g.effective_default('user', only_admins, readable=False) == 'none'  # a damaged registry lets nobody in


class TestMigration:
    def test_nothing_stored_builds_from_old_options_and_env_seeds(self):
        r, source = g.effective(None, True, 'old-admins, shared', 'old-users', 'env-admins', 'env-users,old-users', NOW)
        assert source == 'migrated'
        assert {e['name']: e['role'] for e in r} == {'old-admins': 'admin', 'shared': 'admin', 'old-users': 'user', 'env-admins': 'admin', 'env-users': 'user'}
        by = {e['name']: e for e in r}
        assert by['old-admins']['added_by'] == 'migrated' and by['env-admins']['added_by'] == 'environment'

    def test_admin_wins_when_a_name_is_in_both_old_lists(self):
        r, _ = g.effective(None, True, 'x', 'x', '', '', NOW)
        assert [(e['name'], e['role']) for e in r] == [('x', 'admin')]

    def test_stored_registry_ignores_old_options_and_seeds(self):
        stored = reg(('only', 'admin'))
        r, source = g.effective(stored, True, 'old', 'old2', 'env', 'env2', NOW)
        assert r == stored and source == 'stored'

    def test_empty_stored_registry_takes_the_env_seeds_only(self):
        r, _ = g.effective([], True, 'old', '', 'env', '', NOW)
        assert [e['name'] for e in r] == ['env']

    def test_unreadable_registry_is_empty(self):
        r, source = g.effective(None, False, 'old', '', 'env', '', NOW)
        assert r == [] and source == 'unreadable'


def load(saved=None, env=None):
    class Db:
        def configGetPrefix(self, prefixes):
            return dict(saved or {})
    return identity.load_settings(Db(), env=env or {})


class TestSettings:
    def test_old_lists_still_work_before_anything_is_saved(self):
        s = load({'_oidc_admin_groups': 'sf-admins', '_oidc_user_groups': 'sf-users'})
        assert s.registry_source == 'migrated'
        assert identity.role_for(['sf-admins'], s) == 'admin' and identity.role_for(['sf-users'], s) == 'user'
        assert identity.role_for(['x'], s) == 'denied'
        assert s.admin_groups == ['sf-admins'] and s.user_groups == ['sf-users']

    def test_old_empty_user_list_means_any_signed_in_account(self):
        s = load({'_oidc_admin_groups': 'sf-admins'})
        assert identity.role_for(['whatever'], s) == 'user' and identity.role_for([], s) == 'user'
        assert s.default_role == 'user' and s.default_role_setting == ''

    def test_env_seeds_do_not_lock_and_are_ignored_once_a_registry_is_stored(self):
        env = {'SF_OIDC_ADMIN_GROUPS': 'seed-admins', 'SF_OIDC_USER_GROUPS': 'seed-users'}
        s = load(env=env)
        assert identity.role_for(['seed-admins'], s) == 'admin' and identity.role_for(['seed-users'], s) == 'user'
        assert not s.from_env & {'_oidc_admin_groups', '_oidc_user_groups', '_oidc_groups'}
        stored = load({'_oidc_groups': g.dumps(reg(('mine', 'admin')))}, env)
        assert stored.admin_groups == ['mine'] and identity.role_for(['seed-admins'], stored) == 'user'  # default 'user': no user group registered

    def test_registry_replaces_old_lists_when_stored(self):
        s = load({'_oidc_groups': g.dumps(reg(('new', 'admin'))), '_oidc_admin_groups': 'old', '_oidc_user_groups': 'old-u'})
        assert s.registry_source == 'stored' and s.admin_groups == ['new'] and s.user_groups == []

    def test_default_role_env_overrides_and_is_locked(self):
        s = load({'_oidc_groups': g.dumps(reg(('a', 'admin'))), '_oidc_default_role': 'user'}, {'SF_OIDC_DEFAULT_ROLE': 'none'})
        assert s.default_role == 'none' and '_oidc_default_role' in s.from_env

    def test_damaged_registry_lets_nobody_in(self):
        s = load({'_oidc_groups': '{oops', '_oidc_admin_groups': 'old'})
        assert s.registry_source == 'unreadable' and identity.role_for(['old'], s) == 'denied' and identity.role_for([], s) == 'denied'

    def test_changes_are_visible_on_a_fresh_load_with_nothing_cached(self):
        before = load({'_oidc_groups': g.dumps(reg(('a', 'admin'), ('u', 'user')))})
        after = load({'_oidc_groups': g.dumps(reg(('a', 'admin')))})
        assert identity.role_for(['u'], before) == 'user' and identity.role_for(['u'], after) == 'user'  # default flips to user: no user group left
        assert before.default_role == 'none' and after.default_role == 'user'

    def test_denied_group_bookkeeping_is_bounded_and_throttled(self):
        text = g.note_denied('', ['a', 'b', 'bad,name'], NOW)
        assert g.denied_names(text) == {'a': NOW, 'b': NOW}
        assert g.note_denied(text, ['a'], NOW + 60) is None  # nothing new, refreshed at most daily
        assert g.denied_names(g.note_denied(text, ['a'], NOW + g.DENIED_REFRESH + 1))['a'] == NOW + g.DENIED_REFRESH + 1
        many = None
        for i in range(0, 300, 50):
            many = g.note_denied(many, [f'group-{j}' for j in range(i, i + 50)], NOW + i) or many
        assert len(g.denied_names(many)) == g.MAX_DENIED


class TestDexShapedClaims:
    def test_groups_as_array(self):
        assert oidc.extract_groups({'groups': ['spiderfoot', ' team a ', 'spiderfoot']}, 'groups') == ['spiderfoot', 'team a']

    def test_groups_missing_or_null_or_empty(self):
        for claims in ({}, {'groups': None}, {'groups': []}, {'groups': ''}, {'groups': {}}, {'groups': 5}, None):
            assert oidc.extract_groups(claims, 'groups') == []

    def test_groups_as_a_single_string(self):
        assert oidc.extract_groups({'groups': 'spiderfoot'}, 'groups') == ['spiderfoot']
        assert oidc.extract_groups({'groups': 'Team Alpha'}, 'groups') == ['Team Alpha']  # one name, not two
        assert oidc.extract_groups({'groups': 'a, b\nc'}, 'groups') == ['a', 'b', 'c']

    def test_junk_entries_are_dropped(self):
        claims = {'groups': ['ok', '', '  ', None, True, {'x': 1}, ['y'], 'bad\x00name', 'z' * 201, 42]}
        assert oidc.extract_groups(claims, 'groups') == ['42', 'ok']

    def test_custom_claim_name(self):
        assert oidc.extract_groups({'roles': ['r']}, 'roles') == ['r'] and oidc.extract_groups({'roles': ['r']}, 'groups') == []

    def test_profile_with_dex_claims(self):
        sub = 'CiQwOGE4Njg0Yi1kYjg4LTRiNzMtOTBhOS0zY2QxNjYxZjU0NjYSBWxvY2Fs'  # opaque, Dex-encoded
        p = oidc.profile({'sub': sub, 'preferred_username': 'alice', 'email': 'alice@example.test', 'name': 'Alice A'})
        assert p == {'subject': sub, 'username': 'alice', 'email': 'alice@example.test', 'display_name': 'Alice A'}

    def test_profile_fallbacks_never_show_the_opaque_subject_when_something_better_exists(self):
        assert oidc.profile({'sub': 'opaque', 'email': 'bob@example.test'})['username'] == 'bob@example.test'
        assert oidc.profile({'sub': 'opaque', 'name': 'Bob B'})['username'] == 'Bob B'
        only = oidc.profile({'sub': 'opaque'})
        assert only['username'] == 'opaque' and only['display_name'] == 'opaque' and only['email'] == ''
        weird = oidc.profile({'sub': 'opaque', 'preferred_username': ['list'], 'email': 7, 'name': 'N\x00ame'})
        assert weird['username'] == 'Name' and weird['email'] == ''

    def test_a_provider_cannot_claim_the_local_namespace(self):
        with pytest.raises(oidc.OidcError):
            oidc.profile({'sub': 'local:admin'})
