"""The HTTP side of the MCP server: ``POST /mcp`` (Streamable HTTP, JSON responses), ``GET /health`` and
``GET /.well-known/oauth-protected-resource`` (RFC 9728, when SSO is configured).

Every request to /mcp must carry ``Authorization: Bearer <token>``: a personal access token or an OIDC
access token (see spiderfoot.services.mcp_auth). The caller is a user and the tools apply that user's
access rules. Settings are read from the database on each request. Tokens and request headers are never
logged. Failed authentications are throttled per client address; ``X-Forwarded-For`` is used for that
only when ``SF_TRUST_PROXY`` (or the matching setting) says a proxy is in front.
"""

import collections
import json
import logging
import threading
import time
from urllib.parse import urlsplit

from werkzeug.wrappers import Request, Response

from spiderfoot.mcp import protocol
from spiderfoot.mcp.context import CallContext, McpContext
from spiderfoot.services import identity, mcp_auth

log = logging.getLogger('spiderfoot.mcp')

MAX_BODY = 256 * 1024
LOCAL_HOSTS = ('localhost', '127.0.0.1', '::1')


class FailureThrottle:
    """Counts failed authentications per client address in a sliding window."""

    def __init__(self, limit=10, window=60.0, clock=time.monotonic, max_clients=10000):
        self.limit = limit
        self.window = window
        self.clock = clock
        self.max_clients = max_clients
        self._failures = {}
        self._lock = threading.Lock()

    def _recent(self, client):
        now = self.clock()
        recent = self._failures.get(client)
        if recent is None:
            return None
        while recent and now - recent[0] > self.window:
            recent.popleft()
        if not recent:
            del self._failures[client]
            return None
        return recent

    def retry_after(self, client) -> int:
        """Seconds until the client may try again, 0 if it is not blocked."""
        with self._lock:
            recent = self._recent(client)
            if recent is None or len(recent) < self.limit:
                return 0
            return max(1, int(self.window - (self.clock() - recent[0])) + 1)

    def record_failure(self, client):
        with self._lock:
            if client not in self._failures and len(self._failures) >= self.max_clients:
                self._failures.clear()
            self._failures.setdefault(client, collections.deque()).append(self.clock())
            self._recent(client)


def _json(status, body, headers=None):
    resp = Response(json.dumps(body, separators=(',', ':'), ensure_ascii=False), status=status, mimetype='application/json')
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    for key, value in (headers or {}).items():
        resp.headers[key] = value
    return resp


def client_address(request, hops: int = 0) -> str:
    """The address failed logins are counted against; the Nth entry from the right of X-Forwarded-For when a proxy is trusted."""
    if hops:
        parts = [p.strip() for p in request.headers.get('X-Forwarded-For', '').split(',') if p.strip()]
        if len(parts) >= hops:
            return parts[-hops]
    return request.remote_addr or 'unknown'


def _origin(request, hops: int = 0) -> str:
    scheme, host = request.scheme, request.host
    if hops:
        def pick(header):
            parts = [p.strip() for p in request.headers.get(header, '').split(',') if p.strip()]
            return parts[-hops] if len(parts) >= hops else (parts[0] if parts else '')
        scheme, host = pick('X-Forwarded-Proto') or scheme, pick('X-Forwarded-Host') or host
    return f'{scheme if scheme in ("http", "https") else "http"}://{host}'


def _host_only(netloc: str) -> str:
    try:
        return (urlsplit('//' + netloc).hostname or '').lower()
    except ValueError:
        return ''


def origin_allowed(origin, host_header) -> bool:
    """DNS-rebinding guard: no Origin is fine; otherwise its host must be the request host or a local name."""
    if origin is None:
        return True
    try:
        host = (urlsplit(origin).hostname or '').lower()
    except ValueError:
        return False
    return bool(host) and (host in LOCAL_HOSTS or host == _host_only(host_header or ''))


class McpWsgiApp:
    def __init__(self, app, throttle=None):
        self.ctx = McpContext(app)
        self.throttle = throttle or FailureThrottle()

    def __call__(self, environ, start_response):
        request = Request(environ)
        try:
            response = self.dispatch(request)
        except Exception:
            log.exception('mcp request failed')
            response = _json(500, {'error': 'Internal error'})
        return response(environ, start_response)

    def dispatch(self, request):
        path = request.path.rstrip('/') or '/'
        if path == '/health':
            if request.method not in ('GET', 'HEAD'):
                return _json(405, {'error': 'Method not allowed'}, {'Allow': 'GET, HEAD'})
            return _json(200, {'ok': True})
        if path.startswith('/.well-known/oauth-protected-resource'):
            return self.protected_resource(request)
        if path != '/mcp':
            return _json(404, {'error': 'Not found'})

        if not origin_allowed(request.headers.get('Origin'), request.headers.get('Host')):
            return _json(403, {'error': 'Origin not allowed'})
        try:
            saved = self.ctx.saved()
        except Exception:
            log.exception('mcp could not read settings')
            return _json(503, {'error': 'Service unavailable'})
        if not mcp_auth.enabled(saved):
            return _json(403, {'error': 'MCP server is disabled'})

        with self.ctx.db() as dbh:
            auth = identity.load_settings(dbh)
            client = client_address(request, auth.trust_proxy)
            wait = self.throttle.retry_after(client)
            if wait:
                return _json(429, {'error': 'Too many failed attempts'}, {'Retry-After': str(wait)})
            token = mcp_auth.from_authorization_header(request.headers.get('Authorization'))
            try:
                user = mcp_auth.authenticate(token, dbh, auth)
            except mcp_auth.McpAuthError as e:
                if e.status == 403:
                    log.warning('mcp request refused: account not allowed client=%s', client)
                    return _json(403, {'error': 'This account is not allowed to use the MCP server'})
                self.throttle.record_failure(client)
                challenge = 'Bearer'
                if auth.oidc_configured:
                    challenge += f' resource_metadata="{_origin(request, auth.trust_proxy)}/.well-known/oauth-protected-resource"'
                return _json(401, {'error': 'Unauthorized'}, {'WWW-Authenticate': challenge})

        if request.method != 'POST':
            note = 'This server answers JSON-RPC requests sent with POST /mcp; it offers no server-sent event stream.'
            return _json(405, {'error': 'Method not allowed', 'note': note}, {'Allow': 'POST'})
        length = request.content_length
        if length is not None and length > MAX_BODY:
            return _json(413, {'error': 'Request body too large'})
        body = request.stream.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            return _json(413, {'error': 'Request body too large'})
        try:
            payload = json.loads(body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            return _json(400, protocol.rpc_error(None, protocol.PARSE_ERROR, 'Parse error'))

        status, reply = protocol.handle_payload(payload, CallContext(self.ctx, saved, f'{client} user={user.id}', user, auth))
        if reply is None:
            return Response(status=status)
        return _json(status, reply)

    def protected_resource(self, request):
        """OAuth protected resource metadata (RFC 9728): tells MCP clients which issuer to get tokens from."""
        if request.method not in ('GET', 'HEAD'):
            return _json(405, {'error': 'Method not allowed'}, {'Allow': 'GET, HEAD'})
        try:
            with self.ctx.db() as dbh:
                auth = identity.load_settings(dbh)
        except Exception:
            log.exception('mcp could not read settings')
            return _json(503, {'error': 'Service unavailable'})
        if not auth.oidc_configured:
            return _json(404, {'error': 'Not found'})
        return _json(200, {'resource': _origin(request, auth.trust_proxy) + '/mcp',
                           'authorization_servers': [auth.issuer],
                           'bearer_methods_supported': ['header'],
                           'resource_name': 'SpiderFoot MCP server'})
