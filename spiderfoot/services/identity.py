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
``_oidc_groups``                   (none)                        group registry, JSON (see ``services/groups.py``)
``_oidc_default_role``             ``SF_OIDC_DEFAULT_ROLE``      ``user`` / ``none`` for unlisted accounts; empty = automatic
(``_oidc_admin_groups`` / ``_oidc_user_groups`` and ``SF_OIDC_ADMIN_GROUPS`` / ``SF_OIDC_USER_GROUPS`` only seed the registry)
``_oidc_redirect_uri``             ``SF_OIDC_REDIRECT_URI``      default: built from the request
``_oidc_mcp_audience``             ``SF_OIDC_MCP_AUDIENCE``      audience of access tokens for the MCP server
``_auth_session_hours``            ``SF_AUTH_SESSION_HOURS``     default 12
``_auth_unowned_visible``          ``SF_AUTH_UNOWNED_VISIBLE``   "1": scans without an owner are visible to everyone
``_auth_trust_proxy``              ``SF_TRUST_PROXY``            honour X-Forwarded-* headers (a number = hops)
=================================  ============================  =====================================================

Without OIDC and without passwd-file users the application has no sign-in at all (legacy mode) and
everybody is an administrator. Passwd-file (HTTP Basic) users are administrators too.
"""

import functools
import logging
import os
import typing
from dataclasses import dataclass

from flask import g, has_request_context

from spiderfoot import SpiderFootDb
from spiderfoot.services import access, groups as groupreg
from spiderfoot.services.access import User

log = logging.getLogger('spiderfoot.auth')

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
    '_oidc_groups': ('', ''),
    '_oidc_default_role': ('SF_OIDC_DEFAULT_ROLE', ''),
    '_oidc_redirect_uri': ('SF_OIDC_REDIRECT_URI', ''),
    '_oidc_mcp_audience': ('SF_OIDC_MCP_AUDIENCE', ''),
    '_auth_session_hours': ('SF_AUTH_SESSION_HOURS', str(DEFAULT_SESSION_HOURS)),
    '_auth_unowned_visible': ('SF_AUTH_UNOWNED_VISIBLE', '0'),
    '_auth_trust_proxy': ('SF_TRUST_PROXY', '0'),
}
SECRET_KEYS = ('_oidc_client_secret',)


# The old group lists and the environment seeds only feed the registry when none is stored yet
LEGACY_KEYS = ('_oidc_admin_groups', '_oidc_user_groups')
SEED_ENV = {'_oidc_seed_admin_groups': 'SF_OIDC_ADMIN_GROUPS', '_oidc_seed_user_groups': 'SF_OIDC_USER_GROUPS'}
DENIED_KEY = '_oidc_denied_groups'


@dataclass(frozen=True)
class AuthSettings:
    values: dict
    from_env: frozenset

    def get(self, key: str) -> str:
        return str(self.values.get(key, KEYS[key][1] if key in KEYS else '') or '')

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

    @functools.cached_property
    def _registry_state(self) -> tuple:
        stored, readable = groupreg.parse(self.get('_oidc_groups'))
        registry, source = groupreg.effective(
            stored, readable, self.get('_oidc_admin_groups'), self.get('_oidc_user_groups'),
            self.get('_oidc_seed_admin_groups'), self.get('_oidc_seed_user_groups'))
        return registry, source, readable

    @property
    def registry(self) -> list:
        """The group registry in force: stored, or (until the first change is saved) built from the old lists and seeds."""
        return self._registry_state[0]

    @property
    def registry_source(self) -> str:
        """'stored', 'migrated' (nothing saved yet) or 'unreadable' (the saved value is damaged: nobody is let in)."""
        return self._registry_state[1]

    @property
    def admin_groups(self) -> list:
        return groupreg.names(self.registry, groupreg.ROLE_ADMIN)

    @property
    def user_groups(self) -> list:
        return groupreg.names(self.registry, groupreg.ROLE_USER)

    @property
    def default_role_setting(self) -> str:
        """'' (automatic), 'user' or 'none' as configured."""
        return groupreg.default_role_setting(self.get('_oidc_default_role'))

    @property
    def default_role(self) -> str:
        """'user' or 'none': what an account without a registered group is (the automatic mode resolved)."""
        return groupreg.effective_default(self.default_role_setting, self.registry, self._registry_state[2])

    def with_values(self, **changes) -> 'AuthSettings':
        return AuthSettings({**self.values, **changes}, self.from_env)

    def with_registry(self, registry: list) -> 'AuthSettings':
        return self.with_values(_oidc_groups=groupreg.dumps(registry))

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
        if var and env.get(var, '') != '':
            values[key] = env[var]
            from_env.add(key)
        elif key in saved and saved[key] != '':
            values[key] = saved[key]
        else:
            values[key] = default
    for key in LEGACY_KEYS + (DENIED_KEY,):
        values[key] = saved.get(key, '')
    for key, var in SEED_ENV.items():
        values[key] = env.get(var, '')
    return AuthSettings(values, frozenset(from_env))


def _current_config() -> dict:
    from flask import current_app
    return current_app.config['SF_CONFIG']


def role_for(groups: typing.Iterable[str], settings: AuthSettings) -> str:
    """'admin' for members of a registered admin group, 'user' for members of a registered user group, otherwise
    the default role for unlisted accounts ('user') or 'denied'."""
    return groupreg.resolve(groups, settings.registry, settings.default_role)


def save_registry(dbh, registry: list) -> None:
    dbh.configSet({'_oidc_groups': groupreg.dumps(registry)})


def ensure_registry_saved(dbh, settings: AuthSettings) -> bool:
    """Persist the registry built from the old lists / environment seeds the first time it is needed.
    Returns True when something was saved. An empty result is not saved (there is nothing to migrate)."""
    if settings.registry_source == 'migrated' and settings.registry:
        save_registry(dbh, settings.registry)
        log.info("Group registry created from the previous group settings (%d groups)", len(settings.registry))
        return True
    return False


def note_denied_groups(dbh, settings: AuthSettings, group_names) -> None:
    """Remember the groups of a refused account so the administrator can register them (best effort)."""
    try:
        text = groupreg.note_denied(settings.get(DENIED_KEY), group_names)
        if text is not None:
            dbh.configSet({DENIED_KEY: text})
    except Exception:  # nosec B110 - a bookkeeping failure must not change the sign-in outcome
        log.warning("Could not remember the groups of a refused sign-in")


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
