"""Shared pieces for the sign-in / access tests: a fake OIDC provider (no network) and app helpers."""
import base64
import hashlib
import json
import time
import types
from urllib.parse import parse_qs, urlsplit

from authlib.jose import JsonWebKey, jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from spiderfoot import SpiderFootDb
from spiderfoot.app import create_app
from spiderfoot.services import oidc

ISSUER = 'https://idp.test'
CLIENT_ID = 'sf-client'
CLIENT_SECRET = 'client-secret-not-real-0123456789'

_KEYS = {}


def rsa_key(name='main'):
    """An RSA key pair (generated once per name per test run)."""
    if name not in _KEYS:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        _KEYS[name] = JsonWebKey.import_key(pem, {'kty': 'RSA', 'kid': f'kid-{name}', 'use': 'sig', 'alg': 'RS256'})
    return _KEYS[name]


class FakeIdp:
    """Stands in for the identity provider: discovery, keys, the token endpoint and userinfo, all in memory."""

    def __init__(self, issuer=ISSUER, client_id=CLIENT_ID, with_groups_in_token=True):
        self.issuer = issuer
        self.client_id = client_id
        self.pending = {}
        self.requests = []
        self.userinfo_claims = {}
        self.fail_token = False
        self.with_groups_in_token = with_groups_in_token
        self.discovery_doc = {
            'issuer': issuer,
            'authorization_endpoint': issuer + '/authorize',
            'token_endpoint': issuer + '/token',
            'userinfo_endpoint': issuer + '/userinfo',
            'jwks_uri': issuer + '/keys',
            'end_session_endpoint': issuer + '/logout',
            'scopes_supported': ['openid', 'profile', 'email', 'groups'],
            'claims_supported': ['sub', 'email', 'groups'],
            'code_challenge_methods_supported': ['S256'],
            'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'],
        }
        self.key_name = 'main'

    # -- tokens
    def claims(self, sub='user-1', groups=('sf-users',), **extra):
        now = int(time.time())
        claims = {'iss': self.issuer, 'aud': self.client_id, 'sub': sub, 'iat': now, 'exp': now + 600,
                  'preferred_username': sub, 'email': f'{sub}@example.test', 'name': sub.title()}
        if groups is not None and self.with_groups_in_token:
            claims['groups'] = list(groups)
        claims.update(extra)
        return {k: v for k, v in claims.items() if v is not None}

    def mint(self, claims=None, key_name=None, alg='RS256', kid=True, **claim_overrides):
        key = rsa_key(key_name or self.key_name)
        header = {'alg': alg, 'typ': 'JWT'}
        if kid:
            header['kid'] = key.as_dict()['kid']
        payload = dict(claims if claims is not None else self.claims())
        payload.update(claim_overrides)
        return jwt.encode(header, payload, key).decode()

    # -- authorize / token
    def issue_code(self, auth_url, user_claims=None, **id_token_overrides):
        """Act as the provider after the user logged in: returns the code and remembers what the token should contain."""
        q = {k: v[0] for k, v in parse_qs(urlsplit(auth_url).query).items()}
        assert q['response_type'] == 'code' and q['code_challenge_method'] == 'S256'
        code = base64.urlsafe_b64encode(hashlib.sha256(json.dumps(q, sort_keys=True).encode()).digest()).decode()[:20]
        self.pending[code] = {'q': q, 'claims': dict(user_claims if user_claims is not None else self.claims()),
                              'overrides': id_token_overrides}
        return code, q

    # -- network replacements
    def http_get_json(self, url, headers=None):
        self.requests.append(('GET', url))
        if url == self.issuer + '/.well-known/openid-configuration':
            return self.discovery_doc
        if url == self.discovery_doc['jwks_uri']:
            return {'keys': [rsa_key(self.key_name).as_dict(is_private=False)]}
        if url == self.discovery_doc['userinfo_endpoint']:
            token = (headers or {}).get('Authorization', '').replace('Bearer ', '')
            if not token:
                raise oidc.OidcError('http_error')
            return dict(self.userinfo_claims)
        raise oidc.OidcError('http_error')

    def http_post_form(self, url, data, basic=None):
        self.requests.append(('POST', url))
        if self.fail_token:
            raise oidc.OidcError('token_refused')
        assert url == self.discovery_doc['token_endpoint']
        entry = self.pending.pop(data['code'], None)
        if entry is None:
            raise oidc.OidcError('token_refused')
        q = entry['q']
        # PKCE: the verifier must hash to the challenge sent at /authorize
        digest = base64.urlsafe_b64encode(hashlib.sha256(data['code_verifier'].encode()).digest()).rstrip(b'=').decode()
        if digest != q['code_challenge'] or data['redirect_uri'] != q['redirect_uri']:
            raise oidc.OidcError('token_refused')
        if basic is not None:
            assert basic[0] == CLIENT_ID and basic[1] == CLIENT_SECRET
        else:
            assert data.get('client_secret') == CLIENT_SECRET
        claims = dict(entry['claims'])
        claims.setdefault('nonce', q['nonce'])
        claims.update(entry['overrides'])
        return {'id_token': self.mint(claims), 'access_token': 'opaque-access-token', 'token_type': 'Bearer'}

    def install(self, monkeypatch):
        monkeypatch.setattr(oidc, 'http_get_json', self.http_get_json)
        monkeypatch.setattr(oidc, 'http_post_form', self.http_post_form)
        oidc.clear_cache()


def make_app(tmp_path, modules=None, **config):
    path = str(tmp_path / 'sf.db')
    SpiderFootDb({'__database': path}, init=True)
    cfg = {'__database': path, '__modules__': modules or {}, '__correlationrules__': [], '_debug': '0', '_maxscans': 5}
    cfg.update(config)
    app = create_app(config=cfg)
    app.config['TESTING'] = True
    app.config['SF_USERS'] = {}
    return app


def db(app):
    return SpiderFootDb(app.config['SF_CONFIG'])


def configure_sso(app, admin_groups='sf-admins', user_groups='sf-users', **extra):
    values = {'_oidc_issuer': ISSUER, '_oidc_client_id': CLIENT_ID, '_oidc_client_secret': CLIENT_SECRET,
              '_oidc_admin_groups': admin_groups, '_oidc_user_groups': user_groups}
    values.update(extra)
    db(app).configSet(values)


def set_registry(app, admin=(), user=(), default_role=None, added_by='tests'):
    """Store a group registry the way the Groups card does (instead of the old two comma lists). ``app`` may also be the
    MCP test environment."""
    from spiderfoot.services import groups
    entries = groups.seed(list(admin), list(user), added_by, 1_700_000_000)
    values = {'_oidc_groups': groups.dumps(entries)}
    if default_role is not None:
        values['_oidc_default_role'] = default_role
    (app.db() if callable(getattr(app, 'db', None)) else db(app)).configSet(values)


def add_user(app, name, groups=(), subject=None):
    return db(app).userUpsert(subject or f'oidc|{name}', username=name, email=f'{name}@example.test',
                              display_name=name.title(), groups=list(groups), role='user', login=False)


def seed_scan(app, scan_id, owner=None, name='scan', target='example.com', status='FINISHED'):
    dbh = db(app)
    dbh.scanInstanceCreate(scan_id, f'{name} {scan_id}', target, owner)
    now = int(time.time() * 1000)
    dbh.scanInstanceSet(scan_id, started=now - 60000, ended=now - 1000, status=status)
    dbh.scanConfigSet(scan_id, {'_modulesenabled': 'sfp__stor_db,sfp_dnsresolve'})
    return scan_id


def sign_in(client, user_row, hours=1, csrf='csrf-test-token'):
    """Put a valid session cookie on the client (the fast route; the OIDC tests use the real flow)."""
    now = int(time.time())
    with client.session_transaction() as sess:
        sess.clear()
        sess['uid'] = user_row['id']
        sess['iat'] = now
        sess['exp'] = now + int(hours * 3600)
        sess['csrf_token'] = csrf
        sess.permanent = True
    client.environ_base['HTTP_X_CSRF_TOKEN'] = csrf
    return client


def fake_process_namespace(launched):
    """A stand-in for multiprocessing that registers the scan like the real worker would."""
    class Proc:
        def __init__(self, target=None, args=None, **kw):
            self.args = args
            self.daemon = False

        def start(self):
            queue, name, scan_id, tgt, ttype, modules, cfg = self.args
            launched.append({'scan_id': scan_id, 'cfg_owner': cfg.get('__scan_owner')})
            dbh = SpiderFootDb(cfg)
            dbh.scanInstanceCreate(scan_id, name, tgt, cfg.get('__scan_owner'))
            dbh.scanInstanceSet(scan_id, started=int(time.time() * 1000), status='RUNNING')
            dbh.scanConfigSet(scan_id, {'_modulesenabled': ','.join(modules)})
    return types.SimpleNamespace(Process=Proc)
