"""Settings > Agent (MCP): operator settings (administrators) and each user's personal access tokens.

A personal token is shown exactly once, in the response that creates it. Only its SHA-256 hash and a short
hint are stored, no endpoint returns the hash, and a user can only list and revoke their own tokens. Error
responses are short fixed messages.
"""

import logging
import re
import time

from flask import Blueprint, jsonify, request

from spiderfoot.services import identity, mcp_auth

mcp_admin_bp = Blueprint('mcp_admin', __name__)

log = logging.getLogger(f"spiderfoot.{__name__}")

MAX_TOKENS = 25
DEFAULT_DAYS = 90
NAME_CLEAN = re.compile(r'[\x00-\x1f\x7f]')

# JSON body field -> stored option name
_FIELDS = {
    'enabled': mcp_auth.ENABLED,
    'allow_scan': mcp_auth.ALLOW_SCAN,
    'allow_delete': mcp_auth.ALLOW_DELETE,
    'allow_active': mcp_auth.ALLOW_ACTIVE,
    'allow_private': mcp_auth.ALLOW_PRIVATE,
}


def _db():
    return identity.request_db()


def _error(message, status=400):
    return jsonify({'error': message}), status


def _no_store(resp):
    resp.headers['Cache-Control'] = 'no-store, max-age=0'
    return resp


def _perm_summary(perms):
    return ' '.join(f"{k}={int(bool(v))}" for k, v in perms.items())


def _status(saved):
    out = mcp_auth.public_status(saved)
    user = identity.current_user()
    out['isAdmin'] = bool(user and user.is_admin)
    out['sso'] = identity.request_settings().oidc_configured
    return out


@mcp_admin_bp.route('/settings', methods=['GET'])
def get_settings():
    try:
        saved = _db().configGet()
    except Exception:
        log.error("MCP settings: could not read configuration", exc_info=True)
        return _error('Could not read the settings.', 500)
    return _no_store(jsonify(_status(saved)))


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
        dbh = _db()
        dbh.configSet({_FIELDS[k]: '1' if v else '0' for k, v in body.items()})
        saved = dbh.configGet()
    except Exception:
        log.error("MCP settings: could not save configuration", exc_info=True)
        return _error('Could not save the settings.', 500)

    status = _status(saved)
    if 'enabled' in body:
        log.info("MCP server %s", 'enabled' if status['enabled'] else 'disabled')
    if any(k != 'enabled' for k in body):
        log.info("MCP permissions changed: %s", _perm_summary(status['permissions']))
    return _no_store(jsonify(status))


def _token_list(dbh, user_id):
    now = time.time()
    return [{**t, 'expired': bool(t['expires'] and t['expires'] < now)} for t in dbh.mcpTokenList(user_id)]


@mcp_admin_bp.route('/tokens', methods=['GET'])
def list_tokens():
    """The signed-in user's own tokens (name, hint, dates). Never the token or its hash."""
    try:
        tokens = _token_list(_db(), identity.current_user_id())
    except Exception:
        log.error("MCP token: could not list", exc_info=True)
        return _error('Could not read the tokens.', 500)
    return _no_store(jsonify({'tokens': tokens}))


@mcp_admin_bp.route('/tokens', methods=['POST'])
def create_token():
    """Create a personal access token. JSON body: {"name": "...", "days": 90 (0 = no expiry)}."""
    body = request.get_json(silent=True)
    body = body if isinstance(body, dict) else {}
    name = NAME_CLEAN.sub('', str(body.get('name') or '')).strip()[:60] or 'Agent'
    days = body.get('days', DEFAULT_DAYS)
    if isinstance(days, bool) or not isinstance(days, int) or not 0 <= days <= 3650:
        return _error('The lifetime must be a number of days (0 for no expiry).')
    try:
        dbh = _db()
        uid = identity.current_user_id()
        if len(dbh.mcpTokenList(uid)) >= MAX_TOKENS:
            return _error(f'You can have at most {MAX_TOKENS} tokens. Revoke one you no longer use.')
        token, digest, hint, created = mcp_auth.new_token()
        dbh.mcpTokenCreate(uid, name, digest, hint, created + days * 86400 if days else None)
    except Exception:
        log.error("MCP token: could not save", exc_info=True)
        return _error('Could not save the token.', 500)
    log.info("MCP token created by user id %s", uid)
    return _no_store(jsonify({'token': token, 'tokens': _token_list(dbh, uid)}))


@mcp_admin_bp.route('/tokens/<int:token_id>', methods=['DELETE'])
def revoke_token(token_id):
    try:
        dbh = _db()
        uid = identity.current_user_id()
        if not dbh.mcpTokenRevoke(uid, token_id):
            return _error('Token not found.', 404)
    except Exception:
        log.error("MCP token: could not revoke", exc_info=True)
        return _error('Could not revoke the token.', 500)
    log.info("MCP token revoked by user id %s", uid)
    return _no_store(jsonify({'tokens': _token_list(dbh, uid)}))
