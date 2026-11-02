"""Settings, credentials and identity for the MCP server (agent access to scans).

The MCP server acts as a user. Two kinds of bearer credentials identify the user:

* a personal access token (``sfmcp_...``) that the user generates in Settings > Agent (MCP). Only its
  SHA-256 hash is stored (``tbl_mcp_tokens``). The token acts as its owner with the owner's *current*
  role and groups, so an account that loses its groups or is denied loses agent access at once.
* an OIDC access token (a JWT) from the configured issuer, validated like the login ID token: signature
  from the issuer's keys, issuer, audience (``_oidc_mcp_audience`` or the client id) and expiry. Groups
  come from the token's groups claim, or from the userinfo endpoint when the token has none.

Global settings, saved like other options (``dbh.configSet({key: value})``), as strings:

* ``_mcp_enabled``       "1" when agents may connect (default off)
* ``_mcp_allow_scan``    "1" lets agents start, stop and rerun scans (default on)
* ``_mcp_allow_delete``  "1" lets agents delete scans and their data (default off)
* ``_mcp_allow_active``  "1" lets agents start active/invasive modules, and then only with an explicit
                         confirmation in the tool call (default off)
* ``_mcp_allow_private`` "1" lets agents scan loopback, private-range and link-local targets (default off)

The operator's permissions are a ceiling for everyone; what a user may do with a particular scan is
decided by the same access rules as in the web interface (spiderfoot.services.access). No tool ever
returns API keys or other secrets. The retired shared token (``_mcp_token_hash`` and friends) is ignored
and removed from the database when it is next opened.

The MCP listener is a separate port, enabled by environment: ``SF_MCP_PORT`` (0 or unset = no listener)
and ``SF_MCP_HOST`` (default 0.0.0.0).
"""

import hashlib
import os
import secrets
import time

from spiderfoot.services import identity, oidc

TOKEN_PREFIX = 'sfmcp_'

ENABLED = '_mcp_enabled'
ALLOW_SCAN = '_mcp_allow_scan'
ALLOW_DELETE = '_mcp_allow_delete'
ALLOW_ACTIVE = '_mcp_allow_active'
ALLOW_PRIVATE = '_mcp_allow_private'

DEFAULTS = {
    ENABLED: '0',
    ALLOW_SCAN: '1',
    ALLOW_DELETE: '0',
    ALLOW_ACTIVE: '0',
    ALLOW_PRIVATE: '0',
}
PERMISSION_KEYS = (ALLOW_SCAN, ALLOW_DELETE, ALLOW_ACTIVE, ALLOW_PRIVATE)
TOUCH_INTERVAL = 60  # seconds between "last used" updates of a token


class McpAuthError(Exception):
    """A credential problem. ``status`` is the HTTP status (401 not authenticated, 403 not allowed)."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _flag(saved: dict, key: str) -> bool:
    return str((saved or {}).get(key, DEFAULTS.get(key, '0'))) == '1'


def enabled(saved: dict) -> bool:
    return _flag(saved, ENABLED)


def permissions(saved: dict) -> dict:
    """What an authenticated agent may do: {'scan', 'delete', 'active', 'private'} booleans."""
    return {
        'scan': _flag(saved, ALLOW_SCAN),
        'delete': _flag(saved, ALLOW_DELETE),
        'active': _flag(saved, ALLOW_ACTIVE),
        'private': _flag(saved, ALLOW_PRIVATE),
    }


def hash_token(token: str) -> str:
    return hashlib.sha256(str(token or '').encode('utf-8')).hexdigest()


def new_token():
    """Create an access token. Returns (token, hash, hint, created); only the hash and hint are stored."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, hash_token(token), token[:len(TOKEN_PREFIX) + 4], int(time.time())


def from_authorization_header(value: str):
    """The token from an ``Authorization: Bearer <token>`` header, or None."""
    parts = str(value or '').split(None, 1)
    if len(parts) == 2 and parts[0].lower() == 'bearer' and parts[1].strip():
        return parts[1].strip()
    return None


def listen_port() -> int:
    """Port of the MCP listener from ``SF_MCP_PORT`` (0 = not started)."""
    try:
        port = int(os.environ.get('SF_MCP_PORT', '0') or 0)
    except ValueError:
        return 0
    return port if 0 < port < 65536 else 0


def listen_host() -> str:
    return os.environ.get('SF_MCP_HOST', '') or '0.0.0.0'


def public_status(saved: dict) -> dict:
    """Non-secret state for the settings page."""
    return {
        'enabled': _flag(saved, ENABLED),
        'permissions': permissions(saved),
        'listening': listen_port() > 0,
        'port': listen_port(),
    }


# ---------------------------------------------------------------------------------------------
# identity of the caller

def _user_for_row(row, settings):
    user = identity.user_from_row(row, settings)
    if user is None:
        raise McpAuthError(403, 'account not allowed')
    return user


def authenticate(token: str, dbh, settings):
    """The :class:`~spiderfoot.services.access.User` a bearer token stands for; raises McpAuthError.

    Roles and groups are evaluated now, not when the token was issued.
    """
    if not token:
        raise McpAuthError(401, 'missing token')
    if token.startswith(TOKEN_PREFIX):
        row = dbh.mcpTokenByHash(hash_token(token))
        if not row:
            raise McpAuthError(401, 'unknown token')
        if row['expires'] and row['expires'] < time.time():
            raise McpAuthError(401, 'expired token')
        owner = dbh.userGet(row['user_id'])
        if not owner:
            raise McpAuthError(401, 'unknown token')
        user = _user_for_row(owner, settings)
        if time.time() - (row.get('last_used') or 0) > TOUCH_INTERVAL:
            dbh.mcpTokenTouch(row['id'])
        return user
    if settings.oidc_configured and oidc.looks_like_jwt(token):
        try:
            who = oidc.verify_bearer(settings, token)
        except oidc.OidcError as e:
            raise McpAuthError(401, e.code) from None
        role = identity.role_for(who['groups'], settings)
        if role == identity.ROLE_DENIED:
            existing = dbh.userGetBySubject(who['subject'])
            if existing:
                dbh.userUpsert(who['subject'], who['username'], who['email'], who['display_name'], who['groups'],
                               existing['role'], login=False)
            raise McpAuthError(403, 'account not allowed')
        row = dbh.userUpsert(who['subject'], who['username'], who['email'], who['display_name'], who['groups'], role,
                             login=False)
        return _user_for_row(row, settings)
    raise McpAuthError(401, 'unrecognised token')
