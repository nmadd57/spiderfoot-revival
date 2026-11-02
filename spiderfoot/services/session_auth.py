"""Per-request authentication: HTTP Basic (passwd file, unchanged), the sign-in session, or no sign-in at all.

``authenticate`` returns the :class:`~spiderfoot.services.access.User` of the request, or a response that
challenges the client (redirect to the login page for browsers, 401 JSON for API clients, the Basic
challenge for clients that can answer it).
"""

import base64
import logging
import time
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urlsplit

from flask import Response, jsonify, make_response, redirect, request, session
from flask.sessions import SecureCookieSessionInterface

from spiderfoot.services import identity
from spiderfoot.services.access import User

auth_log = logging.getLogger('spiderfoot.auth')

BASIC_CHALLENGE = {'WWW-Authenticate': 'Basic realm="SpiderFoot"'}


def safe_next(value) -> str:
    """A same-site path to return to after sign-in; anything else becomes '/'."""
    value = str(value or '')
    if not value or len(value) > 512 or not value.startswith('/'):
        return '/'
    for candidate in (value, unquote(value)):
        if candidate.startswith('//') or '\\' in candidate or any(ord(c) < 32 or ord(c) == 127 for c in candidate):
            return '/'
    parts = urlsplit(value)
    if parts.scheme or parts.netloc or parts.path.startswith('/auth/'):
        return '/'
    return value


def external_origin(settings) -> str:
    """scheme://host as the browser sees it (forwarded headers are honoured only when trusted)."""
    scheme, host = request.scheme, request.host
    hops = settings.trust_proxy
    if hops:
        def pick(header):
            parts = [p.strip() for p in request.headers.get(header, '').split(',') if p.strip()]
            return parts[-hops] if len(parts) >= hops else (parts[0] if parts else '')
        scheme = pick('X-Forwarded-Proto') or scheme
        host = pick('X-Forwarded-Host') or host
    if scheme not in ('http', 'https'):
        scheme = 'http'
    return f'{scheme}://{host}'


def is_secure(settings) -> bool:
    return external_origin(settings).startswith('https://')


def client_kind() -> str:
    """'navigate' (a browser loading a page), 'xhr' (a browser script or htmx) or 'api' (any other client)."""
    if request.headers.get('HX-Request'):
        return 'xhr'
    mode = request.headers.get('Sec-Fetch-Mode')
    if mode:
        return 'navigate' if (mode == 'navigate' and request.method == 'GET') else 'xhr'
    if request.method == 'GET' and 'text/html' in request.headers.get('Accept', ''):
        return 'navigate'
    return 'api'


def _current_path() -> str:
    return request.full_path.rstrip('?') if request.query_string else request.path


def challenge(settings, passwd_users) -> Response:
    """The response for a request that carries no valid credentials."""
    kind = client_kind()
    if settings.oidc_configured:
        login = '/auth/login?next=' + quote(safe_next(_current_path()), safe='/')
        if kind == 'navigate':
            return redirect(login)
        resp = jsonify({'error': 'Authentication required.', 'login': '/auth/login'})
        resp.status_code = 401
        if kind == 'xhr':
            resp.headers['HX-Redirect'] = '/auth/login'
        elif passwd_users:
            resp.headers.update(BASIC_CHALLENGE)
        return resp
    return Response('Authentication required.\n', 401, BASIC_CHALLENGE)


def _basic(app, passwd_users, settings):
    """Check an ``Authorization: Basic`` header against the passwd file: a User, or a 401 response."""
    from spiderfoot.app import _check_password, _hash_password
    header = request.headers.get('Authorization', '')
    try:
        decoded = base64.b64decode(header[6:]).decode('utf-8')
        username, password = decoded.split(':', 1)
    except Exception:
        return Response('Malformed credentials.\n', 401, BASIC_CHALLENGE)
    stored = passwd_users.get(username)
    if stored is None:
        _check_password(password, _hash_password("dummy"))  # no username enumeration through timing
        auth_log.warning(f"Failed login attempt for unknown user '{username}'")
        return Response('Invalid credentials.\n', 401, BASIC_CHALLENGE)
    if not _check_password(password, stored):
        auth_log.warning(f"Failed login attempt for user '{username}'")
        return Response('Invalid credentials.\n', 401, BASIC_CHALLENGE)
    return identity.local_user(username)


def session_user(settings, get_dbh):
    """The user of a valid sign-in session. Returns (User or None, reason) where reason is 'denied'/'expired'/''."""
    uid = session.get('uid')
    if not uid:
        return None, ''
    dbh = get_dbh()
    now = time.time()
    if now > float(session.get('exp', 0) or 0) or now - float(session.get('iat', 0) or 0) > settings.session_hours * 3600:
        session.clear()
        return None, 'expired'
    row = dbh.userGet(uid)
    if not row:
        session.clear()
        return None, 'expired'
    user = identity.user_from_row(row, settings)
    if user is None:
        auth_log.warning("Access refused for user id %s: no group grants access", row['id'])
        return None, 'denied'
    return user, ''


def authenticate(app):
    """The User of this request, or the response to send instead."""
    settings = identity.request_settings()
    passwd_users = app.config.get('SF_USERS')
    header = request.headers.get('Authorization', '')

    if header.startswith('Basic ') and passwd_users:
        return _basic(app, passwd_users, settings)

    if settings.oidc_configured or passwd_users:
        user, reason = session_user(settings, identity.request_db) if session.get('uid') else (None, '')
        if user is not None:
            return user
        if reason == 'denied':
            return 'denied'
        return challenge(settings, passwd_users)

    # No sign-in configured at all (legacy mode): everybody is an administrator
    return identity.local_user()


class SessionInterface(SecureCookieSessionInterface):
    """Signed cookie sessions with an absolute lifetime and a Secure flag that follows the request."""

    def get_expiration_time(self, app, session):
        exp = session.get('exp')
        if exp:
            return datetime.fromtimestamp(float(exp), tz=timezone.utc)
        return super().get_expiration_time(app, session)

    def get_cookie_secure(self, app):
        try:
            return is_secure(identity.request_settings())
        except Exception:
            return bool(request.is_secure)

    def should_set_cookie(self, app, session):
        return session.modified


def start_session(user: User, settings, csrf_token: str):
    """Begin a fresh signed-in session (the old one is discarded, so a pre-login cookie is worthless)."""
    session.clear()
    now = int(time.time())
    session['uid'] = user.id
    session['iat'] = now
    session['exp'] = now + int(settings.session_hours * 3600)
    session['csrf_token'] = csrf_token
    session.permanent = True


def denied_response(message='Your account is not allowed to use SpiderFoot.', page=False):
    from flask import render_template
    if not page and client_kind() != 'navigate':
        resp = jsonify({'error': message})
        resp.status_code = 403
        return resp
    resp = make_response(render_template('pages/error.html', page_id='', version='', status=403, message=message,
                                         signout=True), 403)
    return resp
