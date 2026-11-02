"""Sign-in routes: ``/auth/login``, ``/auth/callback``, ``/auth/logout`` and ``/auth/me``."""

import hashlib
import logging
import os

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session

from spiderfoot.services import identity, oidc, session_auth
from spiderfoot.services.access import ROLE_ADMIN

auth_bp = Blueprint('auth', __name__)
log = logging.getLogger('spiderfoot.auth')

# Fixed texts: nothing from the provider's responses is ever shown
ERRORS = {
    'failed': 'Sign-in failed. Please try again.',
    'expired': 'The sign-in took too long or your session ended. Please sign in again.',
    'unavailable': 'The identity provider could not be reached. Please try again later.',
}
SIGNED_OUT = 'You have been signed out.'


def _fresh_csrf() -> str:
    from spiderfoot.app import generate_csrf_token
    return generate_csrf_token(current_app.config['SECRET_KEY'], os.urandom(16).hex())


def _redirect_uri(settings) -> str:
    return settings.redirect_uri or session_auth.external_origin(settings) + '/auth/callback'


def _error_code(err: oidc.OidcError) -> str:
    if err.code in ('unreachable', 'http_error', 'issuer_mismatch', 'insecure_endpoint', 'bad_jwks', 'bad_response',
                    'response_too_large'):
        return 'unavailable'
    if err.code in ('no_transaction', 'expired', 'state_mismatch'):
        return 'expired'
    return 'failed'


@auth_bp.route('/auth/login')
def login():
    settings = identity.request_settings()
    nxt = session_auth.safe_next(request.args.get('next'))
    if settings.oidc_configured and request.args.get('start') == '1':
        try:
            url, tx = oidc.begin(settings, _redirect_uri(settings), nxt)
        except oidc.OidcError as e:
            log.warning("OIDC login could not start: %s", e.code)
            return redirect('/auth/login?error=' + _error_code(e))
        session['oidc_tx'] = tx
        return redirect(url)
    error = request.args.get('error')
    return render_template(
        'pages/login.html', page_id='', version='', sso=settings.oidc_configured, next=nxt,
        message=ERRORS.get(error, '') if error else (SIGNED_OUT if request.args.get('signed_out') else ''),
        failed=bool(error), legacy=bool(current_app.config.get('SF_USERS')))


@auth_bp.route('/auth/callback')
def callback():
    settings = identity.request_settings()
    if not settings.oidc_configured:
        return redirect('/auth/login')
    tx = session.pop('oidc_tx', None)
    try:
        who = oidc.finish(settings, tx, request.args)
    except oidc.OidcError as e:
        log.warning("OIDC login failed: %s", e.code)
        return redirect('/auth/login?error=' + _error_code(e))
    except Exception:
        log.exception("OIDC login failed unexpectedly")
        return redirect('/auth/login?error=failed')

    dbh = identity.request_db()
    role = identity.role_for(who['groups'], settings)
    if role == identity.ROLE_DENIED:
        log.warning("OIDC login denied: account %s is in none of the groups that may use SpiderFoot (groups: %s)",
                    hashlib.sha256(who['subject'].encode()).hexdigest()[:12], ','.join(who['groups'][:20]) or '-')
        existing = dbh.userGetBySubject(who['subject'])
        if existing:  # keep the stored groups current so tokens of this account stop working at once
            dbh.userUpsert(who['subject'], who['username'], who['email'], who['display_name'], who['groups'],
                           existing['role'], login=False)
        session.clear()
        return session_auth.denied_response('Your account is not in a group that may use SpiderFoot. '
                                            'Ask an administrator to add you.', page=True)
    row = dbh.userUpsert(who['subject'], who['username'], who['email'], who['display_name'], who['groups'], role)
    user = identity.user_from_row(row, settings)
    session_auth.start_session(user, settings, _fresh_csrf())
    log.info("OIDC login: user id %s signed in as %s", row['id'], role)
    return redirect(session_auth.safe_next((tx or {}).get('next')))


@auth_bp.route('/auth/logout', methods=['GET', 'POST'])
def logout():
    settings = identity.request_settings()
    session.clear()
    if settings.oidc_configured:
        url = oidc.logout_url(settings, '', session_auth.external_origin(settings) + '/auth/login?signed_out=1')
        if url:
            return redirect(url)
        return redirect('/auth/login?signed_out=1')
    if current_app.config.get('SF_USERS'):
        return redirect('/auth/login?signed_out=1')
    return redirect('/')


@auth_bp.route('/auth/me')
def me():
    user = identity.current_user()
    out = user.public()
    if not user.local:
        method = 'oidc'
    elif request.headers.get('Authorization', '').startswith('Basic '):
        method = 'basic'
    else:
        method = 'none'
    out.update({'authenticated': True, 'isAdmin': user.role == ROLE_ADMIN, 'auth': method,
                'sessionExpires': session.get('exp')})
    resp = jsonify(out)
    resp.headers['Cache-Control'] = 'no-store'
    return resp
