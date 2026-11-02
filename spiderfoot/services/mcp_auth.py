"""Settings and token handling for the MCP server (agent access to scans).

Everything the MCP server and its settings page share lives here so the two cannot drift:
the saved option names, the token format, and the permission model.

Options are stored like other global settings (``dbh.configSet({key: value})``, read back with
``dbh.configGet()``), as strings:

* ``_mcp_enabled``      "1" when agents may connect (default off)
* ``_mcp_token_hash``   SHA-256 hex digest of the access token (the token itself is never stored)
* ``_mcp_token_hint``   a short, non-secret prefix of the token for display (``sfmcp_ab12``)
* ``_mcp_token_created`` unix time the token was issued
* ``_mcp_allow_scan``   "1" lets agents start, stop and rerun scans (default on)
* ``_mcp_allow_delete`` "1" lets agents delete scans and their data (default off)
* ``_mcp_allow_active`` "1" lets agents start active/invasive modules, and then only with an explicit
                        confirmation in the tool call (default off)
* ``_mcp_allow_private`` "1" lets agents scan loopback, private-range and link-local targets (default off)

Reading data (modules, scans, events) is always allowed once the token is valid; no tool ever returns
API keys or other secrets.

The MCP listener is a separate port, enabled by environment: ``SF_MCP_PORT`` (0 or unset = no listener)
and ``SF_MCP_HOST`` (default 0.0.0.0).
"""

import hashlib
import hmac
import os
import secrets
import time

TOKEN_PREFIX = 'sfmcp_'

ENABLED = '_mcp_enabled'
TOKEN_HASH = '_mcp_token_hash'
TOKEN_HINT = '_mcp_token_hint'
TOKEN_CREATED = '_mcp_token_created'
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


def _flag(saved: dict, key: str) -> bool:
    return str((saved or {}).get(key, DEFAULTS.get(key, '0'))) == '1'


def enabled(saved: dict) -> bool:
    return _flag(saved, ENABLED) and bool((saved or {}).get(TOKEN_HASH))


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


def token_settings(token_hash: str, hint: str, created: int) -> dict:
    """The option updates that store a freshly created token."""
    return {TOKEN_HASH: token_hash, TOKEN_HINT: hint, TOKEN_CREATED: str(created)}


def revoked_settings() -> dict:
    """The option updates that revoke the token and switch the server off."""
    return {TOKEN_HASH: '', TOKEN_HINT: '', TOKEN_CREATED: '', ENABLED: '0'}


def verify(token: str, saved: dict) -> bool:
    """Constant-time check of a presented token against the stored hash."""
    stored = str((saved or {}).get(TOKEN_HASH) or '')
    if not stored or not token:
        return False
    return hmac.compare_digest(hash_token(token), stored)


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
        'hasToken': bool((saved or {}).get(TOKEN_HASH)),
        'tokenHint': (saved or {}).get(TOKEN_HINT, ''),
        'tokenCreated': int((saved or {}).get(TOKEN_CREATED) or 0),
        'permissions': permissions(saved),
        'listening': listen_port() > 0,
        'port': listen_port(),
    }
