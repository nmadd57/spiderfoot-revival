"""Sharing of scans, the user directory and the sign-in settings (Settings > Access).

Who may call what is declared in ``spiderfoot.services.route_policy`` and enforced before these views run;
the views repeat the checks that depend on the data (never grant more than you hold, keep an administrator
from locking themselves out).
"""

import logging
import re

from flask import Blueprint, jsonify, request

from spiderfoot.services import access, identity, oidc, session_auth

access_bp = Blueprint('access', __name__)
log = logging.getLogger(f"spiderfoot.{__name__}")

MASK = '********'
GROUP_RE = re.compile(r'^[^\x00-\x1f\x7f]{1,200}$')


def _db():
    return identity.request_db()


def _error(message, status=400):
    resp = jsonify({'error': message})
    resp.status_code = status
    return resp


def _no_store(resp):
    resp.headers['Cache-Control'] = 'no-store, max-age=0'
    return resp


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


# ------------------------------------------------------------------------------------ sharing

def sharing_view(scan_id: str, viewer: access.User, settings) -> dict:
    """What the Sharing panel shows. Only edit-level users and above see the grants (read only unless owner)."""
    dbh = _db()
    level = access.scan_level(viewer, scan_id, dbh, settings.unowned_visible)
    owner_id = dbh.scanOwnerGet(scan_id)
    users = {u['id']: u for u in dbh.userList()}
    owner = None
    if owner_id is not None:
        o = users.get(owner_id)
        owner = {'id': owner_id, 'name': (o['display_name'] or o['username']) if o else f'user {owner_id}',
                 'username': o['username'] if o else ''}
    grants = []
    if level >= access.EDIT:
        for g in dbh.aclList(scan_id):
            label = g['principal']
            if g['principal_type'] == 'user':
                u = users.get(int(g['principal'])) if str(g['principal']).isdigit() else None
                label = (u['display_name'] or u['username']) if u else f"user {g['principal']}"
            grants.append({'type': g['principal_type'], 'principal': g['principal'], 'name': label, 'level': g['level']})
    return {'scanId': scan_id, 'owner': owner, 'yourLevel': access.level_name(level), 'canManage': level >= access.OWNER,
            'canSeeGrants': level >= access.EDIT, 'grants': grants, 'unowned': owner_id is None}


@access_bp.route('/scan/<scan_id>/access', methods=['GET'])
def scan_access_list(scan_id):
    return _no_store(jsonify(sharing_view(scan_id, identity.current_user(), identity.request_settings())))


@access_bp.route('/scan/<scan_id>/access', methods=['POST'])
def scan_access_add(scan_id):
    user, settings, dbh = identity.current_user(), identity.request_settings(), _db()
    body = _body()
    ptype, principal, level = str(body.get('type', '')), str(body.get('principal', '')).strip(), str(body.get('level', ''))
    if ptype not in ('user', 'group'):
        return _error("Choose a user or a group.")
    if level not in access.GRANTABLE:
        return _error("The level must be 'view' or 'edit'.")
    have = access.scan_level(user, scan_id, dbh, settings.unowned_visible)
    if not dbh.scanExists(scan_id):
        return _error('Scan not found.', 404)
    if not access.can_grant(user, have, level):
        return _error('Only the owner of a scan can share it.', 403)
    if ptype == 'user':
        if not principal.isdigit() or not dbh.userGet(int(principal)):
            return _error('Unknown user.')
        principal = str(int(principal))
        if dbh.scanOwnerGet(scan_id) == int(principal):
            return _error('That user already owns the scan.')
    elif not GROUP_RE.match(principal):
        return _error('Enter a group name.')
    dbh.aclSet(scan_id, ptype, principal, level, identity.ensure_user_id(user, dbh))
    log.info("Scan %s shared with %s %s (%s) by user %s", scan_id, ptype, principal if ptype == 'user' else '<group>', level, user.id)
    return _no_store(jsonify(sharing_view(scan_id, user, settings)))


@access_bp.route('/scan/<scan_id>/access', methods=['DELETE'])
def scan_access_remove(scan_id):
    user, settings, dbh = identity.current_user(), identity.request_settings(), _db()
    body = _body()
    ptype = str(body.get('type') or request.args.get('type', ''))
    principal = str(body.get('principal') or request.args.get('principal', '')).strip()
    if ptype not in ('user', 'group') or not principal:
        return _error('Say which grant to remove.')
    if not dbh.aclRemove(scan_id, ptype, principal):
        return _error('That grant does not exist.', 404)
    log.info("Scan %s: %s grant removed by user %s", scan_id, ptype, user.id)
    return _no_store(jsonify(sharing_view(scan_id, user, settings)))


@access_bp.route('/scan/<scan_id>/owner', methods=['POST'])
def scan_owner_set(scan_id):
    """Administrators only: hand a scan (for example an unowned one) to a user."""
    dbh = _db()
    uid = _body().get('user_id')
    if not dbh.scanExists(scan_id):
        return _error('Scan not found.', 404)
    if not isinstance(uid, int) or isinstance(uid, bool) or not dbh.userGet(uid):
        return _error('Unknown user.')
    dbh.scanOwnerSet(scan_id, uid)
    log.info("Scan %s handed to user %s by user %s", scan_id, uid, identity.current_user().id)
    return _no_store(jsonify(sharing_view(scan_id, identity.current_user(), identity.request_settings())))


@access_bp.route('/users', methods=['GET'])
def user_picker():
    """People a scan can be shared with: id and names only (no e-mail addresses or groups)."""
    q = request.args.get('q', '').strip().lower()
    out = []
    for u in _db().userList():
        if u['subject'].startswith('local:'):
            continue
        name = u['display_name'] or u['username']
        if q and q not in f"{name} {u['username']}".lower():
            continue
        out.append({'id': u['id'], 'name': name, 'username': u['username']})
    return _no_store(jsonify(out[:200]))


@access_bp.route('/groups', methods=['GET'])
def group_picker():
    """Group names seen on signed-in users, for suggestions (any name may still be typed)."""
    return _no_store(jsonify(_db().userGroups()))


# ------------------------------------------------------------------------------------ settings

_LIST_KEYS = ('_oidc_admin_groups', '_oidc_user_groups')
_TEXT_KEYS = ('_oidc_issuer', '_oidc_client_id', '_oidc_scopes', '_oidc_groups_claim', '_oidc_redirect_uri',
              '_oidc_mcp_audience')
_ALL_KEYS = _TEXT_KEYS + _LIST_KEYS + ('_oidc_enabled', '_auth_session_hours', '_auth_unowned_visible', '_auth_trust_proxy')
_FIELD_NAMES = {k: k.lstrip('_') for k in _ALL_KEYS + identity.SECRET_KEYS}


def settings_view(settings, request_origin: str) -> dict:
    """The settings for the form. The client secret is never included, only whether one is set."""
    out = {'fields': {}, 'env': sorted(_FIELD_NAMES[k] for k in settings.from_env if k in _FIELD_NAMES)}
    for key in _ALL_KEYS:
        out['fields'][_FIELD_NAMES[key]] = settings.get(key)
    out['fields']['oidc_enabled'] = '0' if settings.get('_oidc_enabled').lower() in ('0', 'false', 'no', 'off') else '1'
    out['fields']['oidc_scopes'] = settings.scopes
    out['fields']['oidc_groups_claim'] = settings.groups_claim
    out['fields']['auth_session_hours'] = str(settings.session_hours).rstrip('0').rstrip('.')
    out['secretSet'] = bool(settings.client_secret)
    out['configured'] = settings.oidc_configured
    out['redirectUri'] = settings.redirect_uri or request_origin + '/auth/callback'
    out['legacyUsers'] = False
    return out


def _check_issuer(url: str):
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if not parts.hostname or not (parts.scheme == 'https' or (parts.scheme == 'http' and parts.hostname in oidc.LOOPBACK)):
        return 'The issuer URL must start with https:// (http:// only for localhost).'
    if parts.query or parts.fragment:
        return 'The issuer URL must not have a query string or fragment.'
    return ''


@access_bp.route('/access/settings', methods=['GET'])
def access_settings_get():
    from flask import current_app
    settings = identity.request_settings()
    out = settings_view(settings, session_auth.external_origin(settings))
    out['legacyUsers'] = bool(current_app.config.get('SF_USERS'))
    return _no_store(jsonify(out))


@access_bp.route('/access/settings', methods=['POST'])
def access_settings_set():
    user, dbh = identity.current_user(), _db()
    before = identity.request_settings()
    body = _body()
    if not body:
        return _error('Send a JSON object with the settings to change.')
    updates, ignored = {}, []
    by_name = {v: k for k, v in _FIELD_NAMES.items()}
    for name, value in body.items():
        key = by_name.get(name)
        if key is None and name not in ('clear_secret', 'acknowledge'):
            return _error('Unknown setting.')
        if key is None:
            continue
        if key in before.from_env:
            ignored.append(name)
            continue
        if key in identity.SECRET_KEYS:
            if value in ('', None, MASK):
                continue
            if not isinstance(value, str) or len(value) > 512:
                return _error('The client secret is not valid.')
            updates[key] = value
            continue
        if key in _LIST_KEYS and isinstance(value, list):
            value = ','.join(identity.split_groups(value))
        if isinstance(value, bool):
            value = '1' if value else '0'
        if not isinstance(value, (str, int, float)) or len(str(value)) > 2000:
            return _error('One of the values is not valid.')
        value = str(value).strip()
        if key == '_oidc_issuer' and value:
            problem = _check_issuer(value)
            if problem:
                return _error(problem)
        if key == '_oidc_scopes' and value and 'openid' not in value.split():
            return _error("The scopes must include 'openid'.")
        if key == '_auth_session_hours':
            try:
                hours = float(value)
            except ValueError:
                return _error('The session lifetime must be a number of hours.')
            if not 0.1 <= hours <= identity.MAX_SESSION_HOURS:
                return _error('The session lifetime must be between 0.1 and 720 hours.')
        if key in ('_oidc_enabled', '_auth_unowned_visible') and value not in ('0', '1'):
            return _error('That setting must be on or off.')
        updates[key] = value
    if body.get('clear_secret') is True and '_oidc_client_secret' not in before.from_env:
        updates['_oidc_client_secret'] = ''

    merged = dict(before.values)
    merged.update(updates)
    after = identity.AuthSettings(merged, before.from_env)

    # Never let a change shut every administrator out
    if after.oidc_configured:
        if not after.admin_groups:
            return _error('Enter at least one admin group, otherwise nobody could manage SpiderFoot after sign-in is enabled.')
        if not before.oidc_configured and body.get('acknowledge') is not True:
            return _error('Confirm that you understand everyone must sign in with SSO from now on.')
        if not user.local and identity.role_for(user.groups, after) != access.ROLE_ADMIN:
            return _error('This change would remove your own administrator access. Add one of your groups as an admin group.')
    if updates:
        dbh.configSet(updates)
        oidc.clear_cache()
        log.info("Access settings changed: %s", ', '.join(sorted(_FIELD_NAMES[k] for k in updates)))
    fresh = identity.load_settings(dbh)
    out = settings_view(fresh, session_auth.external_origin(fresh))
    out['ignored'] = ignored
    return _no_store(jsonify(out))


@access_bp.route('/access/test', methods=['POST'])
def access_test():
    """Fetch the discovery document and keys for the issuer on the form (or the saved one). No secrets in the answer."""
    saved = identity.request_settings()
    body = _body()
    values = dict(saved.values)
    issuer = str(body.get('oidc_issuer') or '').strip()
    if issuer and '_oidc_issuer' not in saved.from_env:
        problem = _check_issuer(issuer)
        if problem:
            return _no_store(jsonify({'ok': False, 'message': problem}))
        values['_oidc_issuer'] = issuer
    for field, key in (('oidc_scopes', '_oidc_scopes'), ('oidc_groups_claim', '_oidc_groups_claim')):
        if body.get(field) and key not in saved.from_env:
            values[key] = str(body[field])[:500]
    return _no_store(jsonify(oidc.test_connection(identity.AuthSettings(values, saved.from_env))))


@access_bp.route('/access/users', methods=['GET'])
def access_users():
    settings = identity.request_settings()
    out = []
    for u in _db().userList():
        row = identity.user_from_row(u, settings)
        out.append({'id': u['id'], 'name': u['display_name'] or u['username'], 'username': u['username'], 'email': u['email'],
                    'role': row.role if row else 'denied', 'groups': u['groups'], 'lastLogin': u['last_login'],
                    'local': u['subject'].startswith('local:')})
    return _no_store(jsonify(out))
