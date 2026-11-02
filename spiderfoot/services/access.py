"""Who may see and change which scan.

Levels, lowest to highest: ``view`` < ``edit`` < ``owner``.

* admins hold ``owner`` on every scan
* the owner of a scan holds ``owner`` (full control, including sharing and deleting)
* a grant to the user, or to any group the user belongs to, gives ``view`` or ``edit`` (the highest wins)
* a scan without an owner (created before users existed) is only for admins, and visible (``view``) to
  everyone when the operator sets ``_auth_unowned_visible``

``edit`` covers stop, rerun, mark false positive and similar; it does not cover delete or changing who
a scan is shared with. The functions here are small and free of Flask so they can be tested exhaustively;
the ones taking a database handle only read from it.
"""

import typing
from dataclasses import dataclass, field

NONE, VIEW, EDIT, OWNER = 0, 1, 2, 3
LEVEL_NAMES = {NONE: 'none', VIEW: 'view', EDIT: 'edit', OWNER: 'owner'}
LEVEL_VALUES = {name: value for value, name in LEVEL_NAMES.items()}
GRANTABLE = ('view', 'edit')

ROLE_ADMIN = 'admin'
ROLE_USER = 'user'


@dataclass(frozen=True)
class User:
    """The signed-in person (or the synthetic administrator of an installation without sign-in).

    ``id`` is the row in ``tbl_users``; it is None for an administrator who has no row yet (authentication
    disabled, or a legacy passwd-file user who has not created anything).
    """
    id: typing.Optional[int]
    subject: str
    username: str = ''
    email: str = ''
    display_name: str = ''
    groups: tuple = field(default_factory=tuple)
    role: str = ROLE_USER
    local: bool = False  # passwd-file user or no-sign-in mode (not an OIDC account)

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    @property
    def label(self) -> str:
        return self.display_name or self.username or self.email or self.subject

    def public(self) -> dict:
        """What may be shown about the user (never a secret)."""
        return {'id': self.id, 'subject': self.subject, 'username': self.username, 'email': self.email,
                'name': self.label, 'role': self.role, 'groups': list(self.groups), 'local': self.local}


def level_value(level) -> int:
    """The number for a level name ('view', 'edit', 'owner'); numbers pass through; anything else is NONE."""
    if isinstance(level, int):
        return level if level in LEVEL_NAMES else NONE
    return LEVEL_VALUES.get(str(level or '').lower(), NONE)


def level_name(level: int) -> str:
    return LEVEL_NAMES.get(level, 'none')


def grant_level(user: User, grants: typing.Iterable[dict]) -> int:
    """The highest level the grants give this user, directly or through a group."""
    best = NONE
    groups = set(user.groups)
    for grant in grants or []:
        ptype, principal = grant.get('principal_type'), str(grant.get('principal'))
        if ptype == 'user' and user.id is not None and principal == str(user.id):
            best = max(best, level_value(grant.get('level')))
        elif ptype == 'group' and principal in groups:
            best = max(best, level_value(grant.get('level')))
    return min(best, EDIT)  # a grant never gives more than edit


def effective_level(user: typing.Optional[User], owner: typing.Optional[int], grants: typing.Iterable[dict],
                    unowned_visible: bool = False) -> int:
    """The level ``user`` holds on a scan with this owner and these grants."""
    if user is None:
        return NONE
    if user.is_admin:
        return OWNER
    if owner is not None and user.id is not None and owner == user.id:
        return OWNER
    level = grant_level(user, grants)
    if owner is None and unowned_visible:
        level = max(level, VIEW)
    return level


def allows(have: int, need) -> bool:
    return have >= level_value(need) > NONE


def denial(have: int) -> int:
    """HTTP status for a refused request: 404 when the user cannot even see the scan, else 403."""
    return 404 if have < VIEW else 403


def can_grant(user: User, scan_level: int, granted) -> bool:
    """May ``user`` (holding ``scan_level`` on the scan) give someone ``granted`` access?

    Only the owner (and admins) may share, and nobody can hand out more than they hold.
    """
    wanted = level_value(granted)
    return scan_level >= OWNER and NONE < wanted <= min(scan_level, EDIT) and granted in GRANTABLE


# --------------------------------------------------------------------------------------------
# Database-backed helpers (read only)

def unowned_visible(settings) -> bool:
    return str(getattr(settings, 'unowned_visible', settings)) in ('1', 'True', 'true')


def scan_level(user: typing.Optional[User], scan_id: str, dbh, unowned: bool = False) -> int:
    """The level ``user`` holds on one scan (NONE if the scan does not exist)."""
    if user is None or not scan_id:
        return NONE
    if not dbh.scanExists(scan_id):
        return NONE if not user.is_admin else OWNER
    if user.is_admin:
        return OWNER
    return effective_level(user, dbh.scanOwnerGet(scan_id), dbh.aclList(scan_id), unowned)


def can(user: typing.Optional[User], scan_id: str, need, dbh, unowned: bool = False) -> bool:
    return allows(scan_level(user, scan_id, dbh, unowned), need)


def scan_levels(user: typing.Optional[User], dbh, unowned: bool = False) -> typing.Optional[dict]:
    """{scan id: level} of every scan the user can see; None means "all of them" (administrators)."""
    if user is None:
        return {}
    if user.is_admin:
        return None
    grants = dbh.aclForPrincipals(user.id, user.groups)
    levels = {}
    for guid, owner in dbh.scanOwners().items():
        if owner is not None and user.id is not None and owner == user.id:
            levels[guid] = OWNER
            continue
        level = level_value(grants.get(guid))
        if owner is None and unowned:
            level = max(level, VIEW)
        if level >= VIEW:
            levels[guid] = level
    return levels


def visible_scans(user: typing.Optional[User], dbh, unowned: bool = False) -> typing.Optional[set]:
    """Ids of the scans the user can see; None means all of them."""
    levels = scan_levels(user, dbh, unowned)
    return None if levels is None else set(levels)


def filter_scan_list(user: typing.Optional[User], rows: typing.Iterable, dbh, unowned: bool = False, index: int = 0) -> list:
    """Keep the rows (lists or tuples whose item ``index`` is the scan id) the user can see."""
    rows = list(rows)
    visible = visible_scans(user, dbh, unowned)
    return rows if visible is None else [r for r in rows if r[index] in visible]


def relation(user: typing.Optional[User], owner: typing.Optional[int], level: int) -> str:
    """How a scan relates to the user, for list badges and filters: 'mine', 'shared' or 'other'."""
    if user is not None and owner is not None and user.id is not None and owner == user.id:
        return 'mine'
    if level >= VIEW and not (user is not None and user.is_admin):
        return 'shared'
    return 'other'
