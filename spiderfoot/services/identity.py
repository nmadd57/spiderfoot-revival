"""Sign-in configuration, roles and the current user.

Settings come from the environment first and from the database (Settings > Access) otherwise:

=================================  ============================  =====================================================
setting (database key)             environment                   meaning
=================================  ============================  =====================================================
``_oidc_enabled``                  ``SF_OIDC_ENABLED``           "0" switches SSO off even when it is configured
``_oidc_issuer``                   ``SF_OIDC_ISSUER``            issuer URL (discovery is read from it)
``_oidc_client_id``                ``SF_OIDC_CLIENT_ID``
``_oidc_client_secret``            ``SF_OIDC_CLIENT_SECRET``     never returned by any endpoint
``_oidc_scopes``                   ``SF_OIDC_SCOPES``            default ``openid profile email groups``
``_oidc_groups_claim``             ``SF_OIDC_GROUPS_CLAIM``      default ``groups``
``_oidc_admin_groups``             ``SF_OIDC_ADMIN_GROUPS``      comma list; members are administrators
``_oidc_user_groups``              ``SF_OIDC_USER_GROUPS``       comma list; empty = any signed-in account may use it
``_oidc_redirect_uri``             ``SF_OIDC_REDIRECT_URI``      default: built from the request
``_oidc_mcp_audience``             ``SF_OIDC_MCP_AUDIENCE``      audience of access tokens for the MCP server
``_auth_session_hours``            ``SF_AUTH_SESSION_HOURS``     default 12
``_auth_unowned_visible``          ``SF_AUTH_UNOWNED_VISIBLE``   "1": scans without an owner are visible to everyone
``_auth_trust_proxy``              ``SF_TRUST_PROXY``            honour X-Forwarded-* headers (a number = hops)
=================================  ============================  =====================================================

Without OIDC and without passwd-file users the application has no sign-in at all (legacy mode) and
everybody is an administrator. Passwd-file (HTTP Basic) users are administrators too.
"""

import os
import typing
from dataclasses import dataclass

from flask import g, has_request_context

from spiderfoot import SpiderFootDb
from spiderfoot.services import access
from spiderfoot.services.access import User

DEFAULT_SCOPES = 'openid profile email groups'
DEFAULT_GROUPS_CLAIM = 'groups'
DEFAULT_SESSION_HOURS = 12
MAX_SESSION_HOURS = 24 * 30

ROLE_DENIED = 'denied'

# database key -> (environment variable, default)
KEYS = {
    '_oidc_enabled': ('SF_OIDC_ENABLED', ''),
    '_oidc_issuer': ('SF_OIDC_ISSUER', ''),
    '_oidc_client_id': ('SF_OIDC_CLIENT_ID', ''),
    '_oidc_client_secret': ('SF_OIDC_CLIENT_SECRET', ''),
    '_oidc_scopes': ('SF_OIDC_SCOPES', DEFAULT_SCOPES),
    '_oidc_groups_claim': ('SF_OIDC_GROUPS_CLAIM', DEFAULT_GROUPS_CLAIM),
    '_oidc_admin_groups': ('SF_OIDC_ADMIN_GROUPS', ''),
    '_oidc_user_groups': ('SF_OIDC_USER_GROUPS', ''),
    '_oidc_redirect_uri': ('SF_OIDC_REDIRECT_URI', ''),
    '_oidc_mcp_audience': ('SF_OIDC_MCP_AUDIENCE', ''),
    '_auth_session_hours': ('SF_AUTH_SESSION_HOURS', str(DEFAULT_SESSION_HOURS)),
    '_auth_unowned_visible': ('SF_AUTH_UNOWNED_VISIBLE', '0'),
    '_auth_trust_proxy': ('SF_TRUST_PROXY', '0'),
}
SECRET_KEYS = ('_oidc_client_secret',)


def split_groups(text) -> list:
    """A comma (or newline) separated list of group names, without blanks or duplicates."""
    if isinstance(text, (list, tuple, set)):
        parts = [str(p) for p in text]
    else:
        parts = str(text or '').replace('\n', ',').split(',')
    seen, out = set(), []
    for part in parts:
        part = part.strip()
        if part and part not in seen:
            seen.add(part)
            out.append(part)
    return out


@dataclass(frozen=True)
class AuthSettings:
    values: dict
    from_env: frozenset

    def get(self, key: str) -> str:
        return str(self.values.get(key, KEYS[key][1]) or '')

    @property
    def issuer(self) -> str:
        return self.get('_oidc_issuer').strip().rstrip('/')

    @property
    def client_id(self) -> str:
        return self.get('_oidc_client_id').strip()

    @property
    def client_secret(self) -> str:
        return self.get('_oidc_client_secret')

    @property
    def scopes(self) -> str:
        return ' '.join(self.get('_oidc_scopes').split()) or DEFAULT_SCOPES

    @property
    def groups_claim(self) -> str:
        return self.get('_oidc_groups_claim').strip() or DEFAULT_GROUPS_CLAIM

    @property
    def admin_groups(self) -> list:
        return split_groups(self.get('_oidc_admin_groups'))

    @property
    def user_groups(self) -> list:
        return split_groups(self.get('_oidc_user_groups'))

    @property
    def redirect_uri(self) -> str:
        return self.get('_oidc_redirect_uri').strip()

    @property
    def mcp_audience(self) -> str:
        return self.get('_oidc_mcp_audience').strip() or self.client_id

    @property
    def session_hours(self) -> float:
        try:
            hours = float(self.get('_auth_session_hours'))
        except ValueError:
            hours = DEFAULT_SESSION_HOURS
        return min(max(hours, 0.1), MAX_SESSION_HOURS)

    @property
    def unowned_visible(self) -> bool:
        return self.get('_auth_unowned_visible') == '1'

    @property
    def trust_proxy(self) -> int:
        """Number of proxy hops whose X-Forwarded-* headers are trusted (0 = none)."""
        raw = self.get('_auth_trust_proxy').strip().lower()
        if raw in ('', '0', 'false', 'no', 'off'):
            return 0
        if raw.isdigit():
            return min(int(raw), 10)
        return 1

    @property
    def oidc_configured(self) -> bool:
        """SSO is on: issuer and client id are set and it has not been switched off."""
        return bool(self.issuer and self.client_id) and self.get('_oidc_enabled').lower() not in ('0', 'false', 'no', 'off')


def load_settings(dbh=None, env=None) -> AuthSettings:
    """Environment first, then the database; a database failure falls back to the environment alone."""
    env = os.environ if env is None else env
    values, from_env = {}, set()
    saved = {}
    try:
        saved = (dbh or SpiderFootDb(_current_config())).configGetPrefix(('_oidc_', '_auth_'))
    except Exception:  # nosec B110 - the environment alone still works
        saved = {}
    for key, (var, default) in KEYS.items():
        if env.get(var, '') != '':
            values[key] = env[var]
            from_env.add(key)
        elif key in saved and saved[key] != '':
            values[key] = saved[key]
        else:
            values[key] = default
    return AuthSettings(values, frozenset(from_env))


def _current_config() -> dict:
    from flask import current_app
    return current_app.config['SF_CONFIG']


def role_for(groups: typing.Iterable[str], settings: AuthSettings) -> str:
    """'admin' for members of an admin group, 'user' for members of a user group (or anybody when no user
    group is configured), otherwise 'denied'."""
    have = set(groups or [])
    if have & set(settings.admin_groups):
        return access.ROLE_ADMIN
    allowed = settings.user_groups
    if not allowed or have & set(allowed):
        return access.ROLE_USER
    return ROLE_DENIED


def user_from_row(row: dict, settings: AuthSettings) -> typing.Optional[User]:
    """The User for a tbl_users row with the role evaluated now; None when the account is denied."""
    if row['subject'].startswith('local:'):
        role = access.ROLE_ADMIN
    else:
        role = role_for(row['groups'], settings)
        if role == ROLE_DENIED:
            return None
    return User(id=row['id'], subject=row['subject'], username=row['username'], email=row['email'],
                display_name=row['display_name'], groups=tuple(row['groups']), role=role, local=row['subject'].startswith('local:'))


def local_user(name: str = '', user_id: typing.Optional[int] = None) -> User:
    """An administrator for passwd-file users (name given) and for installations without sign-in."""
    return User(id=user_id, subject=f'local:{name}' if name else 'local:admin', username=name or 'admin',
                display_name=name or 'Administrator', groups=(), role=access.ROLE_ADMIN, local=True)


def ensure_user_id(user: User, dbh=None) -> int:
    """The tbl_users id of ``user``, creating the row of a local administrator on first need."""
    if user.id is not None:
        return user.id
    dbh = dbh or SpiderFootDb(_current_config())
    row = dbh.userGetBySubject(user.subject) or dbh.userUpsert(
        user.subject, username=user.username, display_name=user.display_name, role=access.ROLE_ADMIN, login=False)
    return row['id']


# ---------------------------------------------------------------------- request scope


def request_db():
    """One database handle per request."""
    if not has_request_context():
        return SpiderFootDb(_current_config())
    if 'sf_db' not in g:
        g.sf_db = SpiderFootDb(_current_config())
    return g.sf_db


def request_settings() -> AuthSettings:
    if not has_request_context():
        return load_settings()
    if 'sf_auth_settings' not in g:
        try:
            dbh = request_db()
        except Exception:  # an unreadable database must not take the sign-in check down: environment settings still apply
            dbh = None
        g.sf_auth_settings = load_settings(dbh)
    return g.sf_auth_settings


def current_user() -> typing.Optional[User]:
    """The authenticated user of this request (None when nobody is signed in or outside a request)."""
    return g.get('sf_user') if has_request_context() else None


def current_user_id(create: bool = True) -> typing.Optional[int]:
    user = current_user()
    if user is None:
        return None
    return ensure_user_id(user, request_db()) if create else user.id
