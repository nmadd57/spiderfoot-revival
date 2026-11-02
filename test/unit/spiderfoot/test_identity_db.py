"""Users, scan grants, scan owners and personal tokens in the database, and the migration of an existing database."""
import sqlite3
import time

import pytest

from spiderfoot import SpiderFootDb


def columns(path, table):
    conn = sqlite3.connect(path)
    try:
        return [r[1] for r in conn.execute(f'PRAGMA table_info({table})')]
    finally:
        conn.close()


def tables(path):
    conn = sqlite3.connect(path)
    try:
        return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()


class TestMigration:
    def make_old_database(self, path):
        """A database as an earlier version left it: no owner column and none of the identity tables."""
        SpiderFootDb({'__database': path}, init=True)
        conn = sqlite3.connect(path)
        for stmt in ("DROP INDEX IF EXISTS idx_scan_instance_owner", "ALTER TABLE tbl_scan_instance DROP COLUMN owner",
                     "DROP TABLE tbl_users", "DROP TABLE tbl_scan_acl", "DROP TABLE tbl_mcp_tokens"):
            conn.execute(stmt)
        now = int(time.time() * 1000)
        conn.execute("INSERT INTO tbl_scan_instance (guid, name, seed_target, created, started, ended, status) "
                     "VALUES ('OLD1', 'old scan', 'example.com', ?, ?, ?, 'FINISHED')", (now, now, now))
        conn.execute("INSERT INTO tbl_scan_config VALUES ('OLD1', 'GLOBAL', '_modulesenabled', 'sfp_x')")
        conn.execute("INSERT INTO tbl_config VALUES ('GLOBAL', '_mcp_token_hash', 'deadbeef')")
        conn.execute("INSERT INTO tbl_config VALUES ('GLOBAL', '_mcp_token_hint', 'sfmcp_ab12')")
        conn.execute("INSERT INTO tbl_config VALUES ('GLOBAL', '_mcp_allow_scan', '1')")
        conn.execute("INSERT INTO tbl_config VALUES ('sfp_x', 'api_key', 'kept')")
        conn.commit()
        conn.close()
        assert 'owner' not in columns(path, 'tbl_scan_instance') and 'tbl_users' not in tables(path)

    def test_existing_database_is_migrated_in_place(self, tmp_path):
        path = str(tmp_path / 'old.db')
        self.make_old_database(path)
        dbh = SpiderFootDb({'__database': path})
        assert 'owner' in columns(path, 'tbl_scan_instance')
        assert {'tbl_users', 'tbl_scan_acl', 'tbl_mcp_tokens'} <= tables(path)
        # data intact, scan is unowned
        row = dbh.scanInstanceGet('OLD1')
        assert row[0] == 'old scan' and row[1] == 'example.com' and row[5] == 'FINISHED'
        assert dbh.scanOwnerGet('OLD1') is None
        assert dbh.scanConfigGet('OLD1')['_modulesenabled'] == 'sfp_x'
        assert [r[0] for r in dbh.scanInstanceList()] == ['OLD1']
        cfg = dbh.configGet()
        assert cfg['_mcp_allow_scan'] == '1' and cfg['sfp_x:api_key'] == 'kept'
        # the retired shared token is gone
        assert '_mcp_token_hash' not in cfg and '_mcp_token_hint' not in cfg

    def test_migration_is_idempotent(self, tmp_path):
        path = str(tmp_path / 'old.db')
        self.make_old_database(path)
        SpiderFootDb({'__database': path})
        first = SpiderFootDb({'__database': path})
        first.scanOwnerSet('OLD1', 7)
        first.userUpsert('oidc|a', 'a')
        again = SpiderFootDb({'__database': path})
        assert again.scanOwnerGet('OLD1') == 7
        assert again.userGetBySubject('oidc|a')['username'] == 'a'
        assert columns(path, 'tbl_scan_instance').count('owner') == 1

    def test_new_database_has_everything(self, tmp_path):
        path = str(tmp_path / 'new.db')
        SpiderFootDb({'__database': path}, init=True)
        assert 'owner' in columns(path, 'tbl_scan_instance')
        assert {'tbl_users', 'tbl_scan_acl', 'tbl_mcp_tokens'} <= tables(path)

    def test_reset_to_defaults_keeps_sign_in_settings(self, tmp_path):
        dbh = SpiderFootDb({'__database': str(tmp_path / 'r.db')}, init=True)
        dbh.configSet({'_oidc_issuer': 'https://idp.test', '_auth_session_hours': '3', '_ai_enabled': '1', 'sfp_x:opt': '1'})
        dbh.configClear()
        cfg = dbh.configGet()
        assert cfg == {'_oidc_issuer': 'https://idp.test', '_auth_session_hours': '3'}


@pytest.fixture
def dbh(tmp_path):
    return SpiderFootDb({'__database': str(tmp_path / 'i.db')}, init=True)


class TestUsers:
    def test_upsert_creates_then_updates(self, dbh):
        a = dbh.userUpsert('oidc|1', 'ann', 'ann@x.test', 'Ann A', ['g1', 'g2', 'g1'], 'user')
        assert a['groups'] == ['g1', 'g2'] and a['last_login'] > 0 and a['created'] > 0
        b = dbh.userUpsert('oidc|1', 'ann2', 'ann@x.test', 'Ann B', ['g3'], 'admin')
        assert b['id'] == a['id'] and b['username'] == 'ann2' and b['groups'] == ['g3'] and b['role'] == 'admin'
        assert len(dbh.userList()) == 1

    def test_login_flag(self, dbh):
        u = dbh.userUpsert('oidc|1', 'a', login=False)
        assert u['last_login'] == 0
        assert dbh.userUpsert('oidc|1', 'a', login=True)['last_login'] > 0

    def test_subject_is_unique_and_role_checked(self, dbh):
        dbh.userUpsert('oidc|1', 'a')
        with pytest.raises(ValueError):
            dbh.userUpsert('oidc|2', 'b', role='root')
        assert len(dbh.userList()) == 1

    def test_groups_seen(self, dbh):
        dbh.userUpsert('oidc|1', 'a', groups=['Beta', 'alpha'])
        dbh.userUpsert('oidc|2', 'b', groups=['alpha', 'gamma'])
        assert dbh.userGroups() == ['alpha', 'Beta', 'gamma']

    def test_lookup_misses(self, dbh):
        assert dbh.userGet(99) is None and dbh.userGetBySubject('nope') is None


class TestGrants:
    def test_set_update_remove(self, dbh):
        dbh.aclSet('S1', 'group', 'team', 'view', 5)
        dbh.aclSet('S1', 'user', '7', 'edit', 5)
        assert {(g['principal_type'], g['principal'], g['level']) for g in dbh.aclList('S1')} == {('group', 'team', 'view'), ('user', '7', 'edit')}
        dbh.aclSet('S1', 'group', 'team', 'edit', 6)  # same principal: updated, not duplicated
        grants = {g['principal']: g for g in dbh.aclList('S1')}
        assert len(grants) == 2 and grants['team']['level'] == 'edit' and grants['team']['granted_by'] == 6
        assert dbh.aclRemove('S1', 'group', 'team') is True
        assert dbh.aclRemove('S1', 'group', 'team') is False
        assert [g['principal'] for g in dbh.aclList('S1')] == ['7']

    @pytest.mark.parametrize('args', [('S', 'team', 'x', 'view'), ('S', 'user', '1', 'owner'), ('S', 'user', '  ', 'view')])
    def test_rejects_bad_grants(self, dbh, args):
        with pytest.raises(ValueError):
            dbh.aclSet(*args)

    def test_for_principals_takes_highest(self, dbh):
        dbh.aclSet('A', 'user', '7', 'view')
        dbh.aclSet('A', 'group', 'g', 'edit')
        dbh.aclSet('B', 'group', 'other', 'edit')
        dbh.aclSet('C', 'user', '8', 'edit')
        assert dbh.aclForPrincipals(7, ['g']) == {'A': 'edit'}
        assert dbh.aclForPrincipals(7, []) == {'A': 'view'}
        assert dbh.aclForPrincipals(None, ['other']) == {'B': 'edit'}
        assert dbh.aclForPrincipals(None, []) == {}

    def test_deleting_a_scan_removes_its_grants(self, dbh):
        dbh.scanInstanceCreate('S9', 'n', 't', 3)
        dbh.aclSet('S9', 'group', 'g', 'view')
        dbh.scanInstanceDelete('S9')
        assert dbh.aclList('S9') == []

    def test_owner_set_and_map(self, dbh):
        dbh.scanInstanceCreate('X1', 'n', 't', 3)
        dbh.scanInstanceCreate('X2', 'n', 't')
        assert dbh.scanOwners() == {'X1': 3, 'X2': None}
        dbh.scanOwnerSet('X2', 4)
        assert dbh.scanOwnerGet('X2') == 4 and dbh.scanOwnerGet('nope') is None
        assert dbh.scanExists('X1') and not dbh.scanExists('nope')

    def test_scan_instance_create_stays_backward_compatible(self, dbh):
        dbh.scanInstanceCreate('OLDSIG', 'name', 'target')  # the three-argument form
        assert dbh.scanOwnerGet('OLDSIG') is None


class TestTokens:
    def test_lifecycle(self, dbh):
        tid = dbh.mcpTokenCreate(1, 'laptop', 'h' * 64, 'sfmcp_ab12', None)
        dbh.mcpTokenCreate(2, 'other', 'g' * 64, 'sfmcp_cd34', int(time.time()) + 5)
        assert [t['name'] for t in dbh.mcpTokenList(1)] == ['laptop']
        found = dbh.mcpTokenByHash('h' * 64)
        assert found['user_id'] == 1 and found['expires'] is None
        dbh.mcpTokenTouch(tid)
        assert dbh.mcpTokenList(1)[0]['last_used'] > 0
        assert dbh.mcpTokenRevoke(2, tid) is False  # not theirs
        assert dbh.mcpTokenRevoke(1, tid) is True
        assert dbh.mcpTokenByHash('h' * 64) is None

    def test_hash_is_unique(self, dbh):
        dbh.mcpTokenCreate(1, 'a', 'x' * 64, 'h')
        with pytest.raises(IOError):
            dbh.mcpTokenCreate(1, 'b', 'x' * 64, 'h')
