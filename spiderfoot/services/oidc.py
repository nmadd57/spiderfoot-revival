"""OpenID Connect: authorization code flow with PKCE, ID token validation and access token validation.

Signatures are checked with Authlib's JOSE implementation against the issuer's published keys (JWKS);
only asymmetric algorithms are accepted, so ``none`` and HMAC tokens are refused. The issuer, audience,
expiry and (for ID tokens) the nonce are checked on top. Nothing from the provider's responses is ever
shown to a user: callers get an :class:`OidcError` carrying a short fixed reason, the details go to the
log without secrets.
"""

import base64
import hashlib
import json
import logging
import re
import secrets
import threading
import time
from urllib.parse import quote_plus, urlencode, urlsplit

import requests
from authlib.jose import JsonWebKey, JsonWebToken
from authlib.jose.errors import JoseError

log = logging.getLogger('spiderfoot.auth')

TIMEOUT = 8
MAX_RESPONSE = 1024 * 1024
CACHE_SECONDS = 600
TX_SECONDS = 600
LEEWAY = 60
ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512']
LOOPBACK = ('localhost', '127.0.0.1', '::1')

_jwt = JsonWebToken(ALGORITHMS)
_cache = {}
_cache_lock = threading.Lock()
_userinfo_cache = {}


class OidcError(Exception):
    """A sign-in problem. ``code`` is a short machine-readable reason; the message is safe to show."""

    def __init__(self, code: str, message: str = ''):
        super().__init__(message or code)
        self.code = code


# ---------------------------------------------------------------------------------------------
# network (replaceable in tests)

def _limited(resp):
    if len(resp.content) > MAX_RESPONSE:
        raise OidcError('response_too_large', 'The identity provider sent too much data.')
    try:
        return resp.json()
    except ValueError:
        raise OidcError('bad_response', 'The identity provider sent an unreadable response.') from None


def http_get_json(url: str, headers=None) -> dict:
    try:
        resp = requests.get(url, headers=headers or {}, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as e:
        log.warning("OIDC request to %s failed: %s", _where(url), type(e).__name__)
        raise OidcError('unreachable', 'The identity provider could not be reached.') from None
    if resp.status_code != 200:
        log.warning("OIDC request to %s answered HTTP %s", _where(url), resp.status_code)
        raise OidcError('http_error', 'The identity provider refused the request.')
    return _limited(resp)


def http_post_form(url: str, data: dict, basic=None) -> dict:
    try:
        resp = requests.post(url, data=data, auth=basic, headers={'Accept': 'application/json'},
                             timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as e:
        log.warning("OIDC token request to %s failed: %s", _where(url), type(e).__name__)
        raise OidcError('unreachable', 'The identity provider could not be reached.') from None
    if resp.status_code != 200:
        log.warning("OIDC token endpoint %s answered HTTP %s", _where(url), resp.status_code)
        raise OidcError('token_refused', 'The identity provider refused the sign-in.')
    return _limited(resp)


def _where(url: str) -> str:
    parts = urlsplit(url)
    return f'{parts.scheme}://{parts.netloc}{parts.path}'


# ---------------------------------------------------------------------------------------------
# discovery and keys

def _check_url(url, what):
    parts = urlsplit(str(url or ''))
    if parts.scheme == 'https' or (parts.scheme == 'http' and (parts.hostname or '') in LOOPBACK):
        return str(url)
    raise OidcError('insecure_endpoint', f'The {what} must use https.')


def discovery(issuer: str, force: bool = False) -> dict:
    """The provider's discovery document (cached for ten minutes)."""
    issuer = issuer.rstrip('/')
    now = time.time()
    with _cache_lock:
        entry = _cache.get(issuer)
        if entry and not force and now - entry['at'] < CACHE_SECONDS and entry.get('doc'):
            return entry['doc']
    _check_url(issuer, 'issuer URL')
    doc = http_get_json(issuer + '/.well-known/openid-configuration')
    if not isinstance(doc, dict) or str(doc.get('issuer', '')).rstrip('/') != issuer:
        log.warning("OIDC discovery for %s returned a different issuer", _where(issuer))
        raise OidcError('issuer_mismatch', 'The identity provider reports a different issuer.')
    for key in ('authorization_endpoint', 'token_endpoint', 'jwks_uri'):
        _check_url(doc.get(key), key.replace('_', ' '))
    with _cache_lock:
        _cache[issuer] = {'doc': doc, 'at': now, 'jwks': None, 'jwks_at': 0}
    return doc


def jwks(issuer: str, doc: dict, force: bool = False) -> dict:
    issuer = issuer.rstrip('/')
    now = time.time()
    with _cache_lock:
        entry = _cache.get(issuer)
        if entry and not force and entry.get('jwks') and now - entry['jwks_at'] < CACHE_SECONDS:
            return entry['jwks']
    keys = http_get_json(_check_url(doc['jwks_uri'], 'JWKS URL'))
    if not isinstance(keys, dict) or not isinstance(keys.get('keys'), list):
        raise OidcError('bad_jwks', 'The identity provider published no signing keys.')
    with _cache_lock:
        entry = _cache.setdefault(issuer, {'doc': doc, 'at': now})
        entry['jwks'], entry['jwks_at'] = keys, now
    return keys


def clear_cache():
    with _cache_lock:
        _cache.clear()
        _userinfo_cache.clear()


# ---------------------------------------------------------------------------------------------
# tokens

def _b64json(part: str) -> dict:
    pad = '=' * (-len(part) % 4)
    try:
        value = json.loads(base64.urlsafe_b64decode(part + pad))
    except (ValueError, TypeError):
        raise OidcError('bad_token', 'The token is not valid.') from None
    if not isinstance(value, dict):
        raise OidcError('bad_token', 'The token is not valid.')
    return value


def looks_like_jwt(token: str) -> bool:
    return isinstance(token, str) and token.count('.') == 2 and len(token) < 16384


def _audiences(claims) -> list:
    aud = claims.get('aud')
    return [aud] if isinstance(aud, str) else [a for a in (aud or []) if isinstance(a, str)]


def decode_token(token: str, issuer: str, doc: dict, audiences: list, nonce=None, subject_required=True) -> dict:
    """Verify signature, issuer, audience and expiry (and the nonce when given); returns the claims."""
    if not looks_like_jwt(token):
        raise OidcError('bad_token', 'The token is not valid.')
    header = _b64json(token.split('.')[0])
    kid = header.get('kid')
    key_set = jwks(issuer, doc)
    if kid is not None and kid not in [k.get('kid') for k in key_set.get('keys', [])]:
        key_set = jwks(issuer, doc, force=True)  # keys rotate: look again once
    try:
        keys = JsonWebKey.import_key_set(key_set)
        claims = _jwt.decode(token, keys, claims_options={
            'iss': {'essential': True, 'value': doc['issuer']},
            'aud': {'essential': True},
            'exp': {'essential': True},
        })
        claims.validate(leeway=LEEWAY)
    except (JoseError, ValueError, KeyError, TypeError) as e:
        log.warning("OIDC token rejected: %s", type(e).__name__)
        raise OidcError('invalid_token', 'The token was not accepted.') from None
    present = set(_audiences(claims))
    if not present & set(a for a in audiences if a):
        log.warning("OIDC token rejected: audience mismatch")
        raise OidcError('invalid_token', 'The token was not accepted.')
    if nonce is not None and not (isinstance(claims.get('nonce'), str) and secrets.compare_digest(claims['nonce'], nonce)):
        log.warning("OIDC token rejected: nonce mismatch")
        raise OidcError('invalid_token', 'The token was not accepted.')
    if subject_required and not (isinstance(claims.get('sub'), str) and claims['sub']):
        raise OidcError('invalid_token', 'The token was not accepted.')
    return dict(claims)


MAX_CLAIM_GROUPS = 200
_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f]')


def extract_groups(claims: dict, claim: str) -> list:
    """Group names from a claim: a list (the normal case, Dex sends an array), a single string (one name, or
    several separated by commas or newlines) or nothing at all (Dex leaves the claim out when the user has no
    groups). Names are trimmed; blanks, control characters, non-text values and absurd lengths are dropped."""
    value = (claims or {}).get(claim)
    if isinstance(value, str):
        value = value.replace('\n', ',').split(',')
    if not isinstance(value, (list, tuple)):
        return []
    out = set()
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (str, int)):
            continue
        name = str(item).strip()
        if name and len(name) <= 200 and not _CONTROL.search(name):
            out.add(name)
    return sorted(out)[:MAX_CLAIM_GROUPS]


def _text(value, limit=200) -> str:
    """A claim value as clean text: only strings count (a list or object is not a name), no control characters."""
    if not isinstance(value, str):
        return ''
    return _CONTROL.sub('', value).strip()[:limit]


def profile(claims: dict) -> dict:
    """Subject and display fields from ID token (or userinfo) claims.

    Dex's ``sub`` is an opaque encoded string, so it is only the last resort for a display name:
    ``preferred_username``, then ``email``, then ``name`` are tried first.
    """
    sub = claims.get('sub')
    sub = sub.strip() if isinstance(sub, str) else ''
    if sub.startswith('local:'):
        # 'local:' is the namespace of passwd-file and no-sign-in administrators; a provider cannot claim it
        raise OidcError('invalid_token', 'The token was not accepted.')
    preferred, email, name = _text(claims.get('preferred_username')), _text(claims.get('email')), _text(claims.get('name'))
    username = preferred or email or name or sub[:200]
    return {'subject': sub, 'username': username, 'email': email,
            'display_name': name or preferred or email or username}


def userinfo(doc: dict, access_token: str, ttl: int = 60) -> dict:
    """Claims from the userinfo endpoint (cached briefly per token)."""
    endpoint = doc.get('userinfo_endpoint')
    if not endpoint:
        return {}
    key = hashlib.sha256(access_token.encode()).hexdigest()
    now = time.time()
    with _cache_lock:
        hit = _userinfo_cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    data = http_get_json(_check_url(endpoint, 'userinfo endpoint'), headers={'Authorization': 'Bearer ' + access_token})
    data = data if isinstance(data, dict) else {}
    with _cache_lock:
        if len(_userinfo_cache) > 500:
            _userinfo_cache.clear()
        _userinfo_cache[key] = (now, data)
    return data


# ---------------------------------------------------------------------------------------------
# authorization code flow with PKCE

def _challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()


def begin(settings, redirect_uri: str, next_url: str = '/') -> tuple:
    """Start a sign-in. Returns (authorization URL, transaction dict to keep in the session)."""
    doc = discovery(settings.issuer)
    tx = {'state': secrets.token_urlsafe(24), 'nonce': secrets.token_urlsafe(24), 'verifier': secrets.token_urlsafe(48),
          'next': next_url, 'redirect_uri': redirect_uri, 'at': int(time.time())}
    query = {
        'response_type': 'code', 'client_id': settings.client_id, 'redirect_uri': redirect_uri,
        'scope': settings.scopes, 'state': tx['state'], 'nonce': tx['nonce'],
        'code_challenge': _challenge(tx['verifier']), 'code_challenge_method': 'S256',
    }
    url = doc['authorization_endpoint']
    return url + ('&' if '?' in url else '?') + urlencode(query), tx


def finish(settings, tx: dict, params) -> dict:
    """Complete a sign-in from the callback parameters; returns the verified identity.

    Returns {'subject', 'username', 'email', 'display_name', 'groups'}. Raises OidcError otherwise.
    """
    if not isinstance(tx, dict) or not tx.get('state'):
        raise OidcError('no_transaction', 'The sign-in expired. Please try again.')
    if time.time() - int(tx.get('at', 0)) > TX_SECONDS:
        raise OidcError('expired', 'The sign-in took too long. Please try again.')
    state = str(params.get('state', ''))
    if not state or not secrets.compare_digest(state, tx['state']):
        raise OidcError('state_mismatch', 'The sign-in could not be verified. Please try again.')
    if params.get('error'):
        log.warning("OIDC provider returned an error at the callback: %s", str(params.get('error'))[:60])
        raise OidcError('provider_error', 'The identity provider did not sign you in.')
    code = str(params.get('code', ''))
    if not code:
        raise OidcError('no_code', 'The sign-in could not be completed.')

    doc = discovery(settings.issuer)
    form = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': tx['redirect_uri'],
            'client_id': settings.client_id, 'code_verifier': tx['verifier']}
    basic = None
    if settings.client_secret:
        methods = doc.get('token_endpoint_auth_methods_supported') or ['client_secret_basic']
        if 'client_secret_basic' in methods:
            basic = (quote_plus(settings.client_id), quote_plus(settings.client_secret))
            form.pop('client_id')
        else:
            form['client_secret'] = settings.client_secret
    token = http_post_form(_check_url(doc['token_endpoint'], 'token endpoint'), form, basic)
    id_token = token.get('id_token') if isinstance(token, dict) else None
    if not isinstance(id_token, str):
        raise OidcError('no_id_token', 'The identity provider sent no ID token.')

    claims = decode_token(id_token, settings.issuer, doc, [settings.client_id], nonce=tx['nonce'])
    if len(_audiences(claims)) > 1 and claims.get('azp') != settings.client_id:
        raise OidcError('invalid_token', 'The token was not accepted.')
    if settings.groups_claim not in claims and isinstance(token.get('access_token'), str):
        # The ID token carries no groups: ask the userinfo endpoint (only accepted for the same subject)
        try:
            extra = userinfo(doc, token['access_token'], ttl=0)
            if extra.get('sub') == claims.get('sub') and settings.groups_claim in extra:
                claims[settings.groups_claim] = extra[settings.groups_claim]
        except OidcError:
            pass  # sign in without groups
    who = profile(claims)
    who['groups'] = extract_groups(claims, settings.groups_claim)
    who['end_session_endpoint'] = doc.get('end_session_endpoint') or ''
    who['id_token'] = id_token
    return who


def logout_url(settings, id_token_hint: str, post_logout_uri: str) -> str:
    """The provider's end-session URL, or '' when it has none."""
    try:
        doc = discovery(settings.issuer)
    except OidcError:
        return ''
    endpoint = doc.get('end_session_endpoint')
    if not endpoint:
        return ''
    query = {'post_logout_redirect_uri': post_logout_uri, 'client_id': settings.client_id}
    if id_token_hint:
        query['id_token_hint'] = id_token_hint
    return endpoint + ('&' if '?' in endpoint else '?') + urlencode(query)


# ---------------------------------------------------------------------------------------------
# bearer tokens for the MCP server

def verify_bearer(settings, token: str) -> dict:
    """Validate an OIDC access token (a JWT) presented to the MCP server.

    Returns {'subject', 'username', 'email', 'display_name', 'groups'}. The groups come from the token's
    groups claim, or from the userinfo endpoint when the token has none.
    """
    if not settings.oidc_configured:
        raise OidcError('not_configured', 'Sign-in is not configured.')
    doc = discovery(settings.issuer)
    audiences = [settings.mcp_audience, settings.client_id]
    claims = decode_token(token, settings.issuer, doc, audiences)
    who = profile(claims)
    if settings.groups_claim in claims:
        who['groups'] = extract_groups(claims, settings.groups_claim)
    else:
        extra = {}
        try:
            extra = userinfo(doc, token)
        except OidcError:
            extra = {}
        who['groups'] = extract_groups(extra, settings.groups_claim) if extra.get('sub') == claims.get('sub') else []
    return who


# ---------------------------------------------------------------------------------------------
# settings page: connection test

def test_connection(settings) -> dict:
    """Fetch the discovery document and keys and report what was found. Contains no secrets."""
    if not settings.issuer:
        return {'ok': False, 'message': 'Enter the issuer URL first.'}
    try:
        doc = discovery(settings.issuer, force=True)
        key_set = jwks(settings.issuer, doc, force=True)
    except OidcError as e:
        return {'ok': False, 'message': str(e)}
    scopes = doc.get('scopes_supported')
    claims = doc.get('claims_supported')
    return {
        'ok': True,
        'message': 'The identity provider answered and published its signing keys.',
        'issuer': doc.get('issuer'),
        'authorization_endpoint': doc.get('authorization_endpoint'),
        'token_endpoint': doc.get('token_endpoint'),
        'userinfo_endpoint': doc.get('userinfo_endpoint') or '',
        'end_session_endpoint': doc.get('end_session_endpoint') or '',
        'jwks_uri': doc.get('jwks_uri'),
        'keys': len(key_set.get('keys', [])),
        'pkce': 'S256' in (doc.get('code_challenge_methods_supported') or []),
        'groups_scope': ('groups' in scopes) if isinstance(scopes, list) else None,
        'groups_claim': (settings.groups_claim in claims) if isinstance(claims, list) else None,
        'claims_supported': sorted({c for c in claims if isinstance(c, str)})[:60] if isinstance(claims, list) else None,
        'scopes_requested': settings.scopes,
    }
