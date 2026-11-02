"""The access rules: who may view, edit and own a scan (pure functions plus the database-backed helpers)."""
import pytest

from spiderfoot import SpiderFootDb
from spiderfoot.services import access
from spiderfoot.services.access import EDIT, NONE, OWNER, VIEW, User

ADMIN = User(1, 'oidc|root', 'root', role='admin', groups=('sf-admins',))
OWNER_U = User(2, 'oidc|olivia', 'olivia', groups=('team-a',))
EDITOR = User(3, 'oidc|edith', 'edith', groups=('team-b',))
VIEWER = User(4, 'oidc|vic', 'vic', groups=('team-c',))
GROUP_EDIT = User(5, 'oidc|gail', 'gail', groups=('editors',))
GROUP_VIEW = User(6, 'oidc|gus', 'gus', groups=('readers', 'editors-no'))
STRANGER = User(7, 'oidc|sam', 'sam', groups=('other',))

GRANTS = [
    {'principal_type': 'user', 'principal': '3', 'level': 'edit'},
    {'principal_type': 'user', 'principal': '4', 'level': 'view'},
    {'principal_type': 'group', 'principal': 'editors', 'level': 'edit'},
    {'principal_type': 'group', 'principal': 'readers', 'level': 'view'},
]

# who -> level on a scan owned by OWNER_U with GRANTS
EXPECTED = {
    'admin': (ADMIN, OWNER), 'owner': (OWNER_U, OWNER), 'edit grantee': (EDITOR, EDIT), 'view grantee': (VIEWER, VIEW),
    'edit group': (GROUP_EDIT, EDIT), 'view group': (GROUP_VIEW, VIEW), 'no access': (STRANGER, NONE),
}


@pytest.mark.parametrize('who', EXPECTED)
def test_level_matrix(who):
    user, level = EXPECTED[who]
    assert access.effective_level(user, OWNER_U.id, GRANTS) == level


@pytest.mark.parametrize('who', EXPECTED)
@pytest.mark.parametrize('need', ['view', 'edit', 'owner'])
def test_actions_per_persona(who, need):
    user, level = EXPECTED[who]
    assert access.allows(access.effective_level(user, OWNER_U.id, GRANTS), need) == (level >= access.level_value(need))


def test_highest_grant_wins_between_user_and_group():
    user = User(8, 'oidc|multi', groups=('readers', 'editors'))
    grants = GRANTS + [{'principal_type': 'user', 'principal': '8', 'level': 'view'}]
    assert access.effective_level(user, 99, grants) == EDIT


def test_grants_never_exceed_edit():
    grants = [{'principal_type': 'user', 'principal': '7', 'level': 'owner'}]
    assert access.effective_level(STRANGER, 99, grants) == EDIT


def test_unowned_scans_admin_only_by_default():
    for user in (OWNER_U, EDITOR, STRANGER):
        assert access.effective_level(user, None, []) == NONE
    assert access.effective_level(ADMIN, None, []) == OWNER


def test_unowned_visible_setting_gives_everyone_view_only():
    for user in (OWNER_U, STRANGER):
        assert access.effective_level(user, None, [], unowned_visible=True) == VIEW
    # an explicit grant still wins
    assert access.effective_level(EDITOR, None, GRANTS, unowned_visible=True) == EDIT
    # the setting does not touch owned scans
    assert access.effective_level(STRANGER, 2, [], unowned_visible=True) == NONE


def test_no_user_has_no_access():
    assert access.effective_level(None, 2, GRANTS) == NONE


def test_user_without_id_cannot_match_owner_or_user_grants():
    local = User(None, 'local:admin', 'admin', role='user')
    assert access.effective_level(local, None, [{'principal_type': 'user', 'principal': 'None', 'level': 'edit'}]) == NONE


def test_denial_status_hides_scans_from_people_who_cannot_see_them():
    assert access.denial(NONE) == 404
    assert access.denial(VIEW) == 403
    assert access.denial(EDIT) == 403


@pytest.mark.parametrize('who,granted,expected', [
    ('owner', 'view', True), ('owner', 'edit', True), ('owner', 'owner', False), ('owner', 'admin', False),
    ('admin', 'edit', True), ('edit grantee', 'view', False), ('edit grantee', 'edit', False),
    ('view grantee', 'view', False), ('no access', 'view', False),
])
def test_can_grant(who, granted, expected):
    user, level = EXPECTED[who]
    assert access.can_grant(user, level, granted) is expected


def test_level_value_handles_bad_input():
    assert access.level_value('EDIT') == EDIT
    assert access.level_value('nonsense') == NONE
    assert access.level_value(None) == NONE
    assert access.level_value(99) == NONE
    assert not access.allows(OWNER, 'nonsense')


def test_user_helpers():
    assert User(1, 's', 'u', display_name='Ada').label == 'Ada'
    assert User(1, 's', 'u').label == 'u'
    assert User(1, 's', role='admin').is_admin and not User(1, 's').is_admin
    public = User(1, 's', 'u', email='e@x', groups=('g',)).public()
    assert public['groups'] == ['g'] and 'password' not in str(public)


@pytest.fixture
def dbh(tmp_path):
    handle = SpiderFootDb({'__database': str(tmp_path / 'a.db')}, init=True)
    for guid, owner in (('MINE', 2), ('SHARED', 9), ('GROUPED', 9), ('OTHERS', 9), ('LEGACY', None)):
        handle.scanInstanceCreate(guid, guid.lower(), 'example.com', owner)
    handle.aclSet('SHARED', 'user', '4', 'view')
    handle.aclSet('GROUPED', 'group', 'editors', 'edit')
    return handle


def test_scan_level_from_database(dbh):
    assert access.scan_level(OWNER_U, 'MINE', dbh) == OWNER
    assert access.scan_level(VIEWER, 'SHARED', dbh) == VIEW
    assert access.scan_level(GROUP_EDIT, 'GROUPED', dbh) == EDIT
    assert access.scan_level(STRANGER, 'OTHERS', dbh) == NONE
    assert access.scan_level(OWNER_U, 'LEGACY', dbh) == NONE
    assert access.scan_level(OWNER_U, 'LEGACY', dbh, unowned=True) == VIEW
    assert access.scan_level(ADMIN, 'LEGACY', dbh) == OWNER


def test_missing_scan(dbh):
    assert access.scan_level(OWNER_U, 'NOPE', dbh) == NONE
    assert access.scan_level(ADMIN, 'NOPE', dbh) == OWNER  # an administrator reaches the handler, which reports "not found"
    assert access.scan_level(OWNER_U, '', dbh) == NONE
    assert not access.can(OWNER_U, 'NOPE', 'view', dbh)


def test_visible_scans_and_list_filter(dbh):
    assert access.visible_scans(ADMIN, dbh) is None
    assert access.visible_scans(OWNER_U, dbh) == {'MINE'}
    assert access.visible_scans(VIEWER, dbh) == {'SHARED'}
    assert access.visible_scans(GROUP_EDIT, dbh) == {'GROUPED'}
    assert access.visible_scans(STRANGER, dbh) == set()
    assert access.visible_scans(STRANGER, dbh, unowned=True) == {'LEGACY'}
    rows = [('MINE', 'a'), ('SHARED', 'b'), ('OTHERS', 'c'), ('LEGACY', 'd')]
    assert access.filter_scan_list(VIEWER, rows, dbh) == [('SHARED', 'b')]
    assert access.filter_scan_list(ADMIN, rows, dbh) == rows
    assert access.filter_scan_list(None, rows, dbh) == []
    assert access.scan_levels(VIEWER, dbh) == {'SHARED': VIEW}


def test_relation_labels():
    assert access.relation(OWNER_U, 2, OWNER) == 'mine'
    assert access.relation(VIEWER, 2, VIEW) == 'shared'
    assert access.relation(ADMIN, 2, OWNER) == 'other'
    assert access.relation(STRANGER, 2, NONE) == 'other'
