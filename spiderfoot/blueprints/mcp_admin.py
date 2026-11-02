"""Admin API for the MCP server (agent access to scans), used by Settings > Agent (MCP).

The access token is shown exactly once, in the response that creates it. Only its SHA-256 hash and a
short hint are stored, and no endpoint returns the hash. Error responses are short fixed messages.
"""

import logging

from flask import Blueprint, jsonify, request

from spiderfoot.blueprints.api import get_db
from spiderfoot.services import mcp_auth

mcp_admin_bp = Blueprint('mcp_admin', __name__)

log = logging.getLogger(f"spiderfoot.{__name__}")

# JSON body field -> stored option name
_FIELDS = {
    'enabled': mcp_auth.ENABLED,
    'allow_scan': mcp_auth.ALLOW_SCAN,
    'allow_delete': mcp_auth.ALLOW_DELETE,
    'allow_active': mcp_auth.ALLOW_ACTIVE,
    'allow_private': mcp_auth.ALLOW_PRIVATE,
}


def _error(message, status=400):
    return jsonify({'error': message}), status


def _no_store(resp):
    resp.headers['Cache-Control'] = 'no-store, max-age=0'
    return resp


def _perm_summary(perms):
    return ' '.join(f"{k}={int(bool(v))}" for k, v in perms.items())


@mcp_admin_bp.route('/settings', methods=['GET'])
def get_settings():
    try:
        saved = get_db().configGet()
    except Exception:
        log.error("MCP settings: could not read configuration", exc_info=True)
        return _error('Could not read the settings.', 500)
    return _no_store(jsonify(mcp_auth.public_status(saved)))


@mcp_admin_bp.route('/settings', methods=['POST'])
def set_settings():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not body:
        return _error('Send a JSON object with the settings to change.')
    if any(k not in _FIELDS for k in body):
        return _error('Unknown setting.')
    if any(not isinstance(v, bool) for v in body.values()):
        return _error('Every setting must be true or false.')

    try:
        dbh = get_db()
        saved = dbh.configGet()
        if body.get('enabled') and not saved.get(mcp_auth.TOKEN_HASH):
            return _error('Generate a token before enabling the MCP server.')
        dbh.configSet({_FIELDS[k]: '1' if v else '0' for k, v in body.items()})
        saved = dbh.configGet()
    except Exception:
        log.error("MCP settings: could not save configuration", exc_info=True)
        return _error('Could not save the settings.', 500)

    status = mcp_auth.public_status(saved)
    if 'enabled' in body:
        log.info("MCP server %s", 'enabled' if status['enabled'] else 'disabled')
    if any(k != 'enabled' for k in body):
        log.info("MCP permissions changed: %s", _perm_summary(status['permissions']))
    return _no_store(jsonify(status))


@mcp_admin_bp.route('/token', methods=['POST'])
def create_token():
    """Create (or rotate) the access token. The old token stops working at once."""
    token, digest, hint, created = mcp_auth.new_token()
    try:
        get_db().configSet(mcp_auth.token_settings(digest, hint, created))
        saved = get_db().configGet()
    except Exception:
        log.error("MCP token: could not save configuration", exc_info=True)
        return _error('Could not save the token.', 500)
    log.info("MCP token rotated")
    out = mcp_auth.public_status(saved)
    out['token'] = token
    return _no_store(jsonify(out))


@mcp_admin_bp.route('/token/revoke', methods=['POST'])
def revoke_token():
    try:
        dbh = get_db()
        dbh.configSet(mcp_auth.revoked_settings())
        saved = dbh.configGet()
    except Exception:
        log.error("MCP token: could not revoke", exc_info=True)
        return _error('Could not revoke the token.', 500)
    log.info("MCP token revoked and server disabled")
    return _no_store(jsonify(mcp_auth.public_status(saved)))
