"""Fixtures for the MCP server tests: a temp database, a small fake module set, a Flask app and a client."""
import json
import time
import types
from unittest import mock

import pytest

from spiderfoot import SpiderFootDb
from spiderfoot.app import create_app
from spiderfoot.event import SpiderFootEvent
from spiderfoot.services import mcp_auth

SECRET = 'sk-test-DO-NOT-LEAK-9f8e7d6c5b4a'
OTHER_SECRET = 'or-v1-another-secret-value-123456'


def fake_module(name, cats=('DNS',), flags=(), pricing='free', use_cases=('Footprint', 'Investigate', 'Passive'),
                provides=(), consumes=(), opts=None, optdescs=None):
    return {
        'name': name, 'descr': f'{name} long description', 'cats': list(cats), 'group': list(use_cases), 'labels': [],
        'pricing': pricing, 'broken': False, 'provides': list(provides), 'consumes': list(consumes),
        'meta': {'name': name, 'summary': f'{name} summary', 'flags': list(flags), 'pricing': pricing,
                 'useCases': list(use_cases), 'categories': list(cats)},
        'opts': dict(opts or {}), 'optdescs': dict(optdescs or {}),
    }


def fake_modules():
    return {
        'sfp_dnsresolve': fake_module('sfp_dnsresolve', pricing='local', provides=['IP_ADDRESS', 'DOMAIN_NAME'],
                                      consumes=['INTERNET_NAME', 'IP_ADDRESS'],
                                      opts={'validatereverse': True, 'maxnetblock': 24},
                                      optdescs={'validatereverse': 'Validate reverse lookups.'}),
        'sfp_countryname': fake_module('sfp_countryname', cats=('Real World',), pricing='local',
                                       provides=['COUNTRY_NAME'], consumes=['IP_ADDRESS', 'DOMAIN_NAME']),
        'sfp_crt': fake_module('sfp_crt', cats=('Passive DNS',), provides=['INTERNET_NAME'], consumes=['DOMAIN_NAME', 'INTERNET_NAME']),
        'sfp_mail': fake_module('sfp_mail', cats=('Leaks, Dumps and Breaches',), use_cases=('Investigate',),
                                provides=['EMAILADDR_COMPROMISED'], consumes=['EMAILADDR']),
        'sfp_keyed': fake_module('sfp_keyed', cats=('Search Engines',), flags=['apikey'], pricing='free_key',
                                 provides=['INTERNET_NAME'], consumes=['DOMAIN_NAME'],
                                 opts={'api_key': SECRET, 'limit': 10}, optdescs={'api_key': 'API key', 'limit': 'Result limit'}),
        'sfp_nokey': fake_module('sfp_nokey', cats=('Search Engines',), flags=['apikey'], pricing='free_key',
                                 provides=['INTERNET_NAME'], consumes=['DOMAIN_NAME'], opts={'api_key': ''}),
        'sfp_portscan_tcp': fake_module('sfp_portscan_tcp', cats=('Crawling and Scanning',), flags=['slow', 'invasive'],
                                        pricing='local', use_cases=('Footprint', 'Investigate'),
                                        provides=['TCP_PORT_OPEN'], consumes=['IP_ADDRESS']),
        'sfp_dnsbrute': fake_module('sfp_dnsbrute', pricing='local', use_cases=('Footprint',),
                                    provides=['INTERNET_NAME'], consumes=['DOMAIN_NAME']),
        'sfp_tool_nmap': fake_module('sfp_tool_nmap', cats=('Crawling and Scanning',), flags=['tool', 'slow', 'invasive'],
                                     pricing='local', use_cases=('Footprint', 'Investigate'),
                                     provides=['OPERATING_SYSTEM'], consumes=['IP_ADDRESS'], opts={'nmappath': ''}),
        'sfp_opsoff': fake_module('sfp_opsoff', provides=['INTERNET_NAME'], consumes=['DOMAIN_NAME']),
    }


class Env:
    """The pieces of one test environment."""

    def __init__(self, app, db_path, token):
        self.app = app
        self.db_path = db_path
        self.token = token
        self.launched = []

    def db(self):
        return SpiderFootDb({'__database': self.db_path})

    def configure(self, **settings):
        """Save MCP settings the way the Settings page does (names without the _mcp_ prefix)."""
        self.db().configSet({f'_mcp_{k}': str(v) for k, v in settings.items()})

    def seed_scan(self, scan_id='SCAN0001', target='example.com', name='demo scan', status='FINISHED', modules='sfp__stor_db,sfp_dnsresolve,sfp_crt',
                  seed_type='INTERNET_NAME'):
        dbh = self.db()
        dbh.scanInstanceCreate(scan_id, name, target)
        now = int(time.time() * 1000)
        dbh.scanInstanceSet(scan_id, started=now - 60000, ended=now - 1000 if status in ('FINISHED', 'ABORTED') else None, status=status)
        dbh.scanConfigSet(scan_id, {'_modulesenabled': modules})
        root = SpiderFootEvent('ROOT', target, '', None)
        seed = SpiderFootEvent(seed_type, target, 'SpiderFoot UI', root)
        dbh.scanEventStore(scan_id, root)
        dbh.scanEventStore(scan_id, seed)
        for i, host in enumerate(['www.example.com', 'mail.example.com', 'api.example.com']):
            dbh.scanEventStore(scan_id, SpiderFootEvent('INTERNET_NAME', host, 'sfp_crt', seed))
        ip = SpiderFootEvent('IP_ADDRESS', '93.184.216.34', 'sfp_dnsresolve', seed)
        dbh.scanEventStore(scan_id, ip)
        dbh.scanEventStore(scan_id, SpiderFootEvent('RAW_RIR_DATA', 'x' * 900 + f' leaked {SECRET} here', 'sfp_crt', seed))
        dbh.scanLogEvent(scan_id, 'STATUS', 'Scan started', 'sflib')
        dbh.scanLogEvent(scan_id, 'ERROR', f'request failed with key {SECRET}', 'sfp_crt')
        dbh.scanLogEvent(scan_id, 'DEBUG', 'details', 'sfp_dnsresolve')
        return scan_id

    def make_user(self, name, groups=(), role='user', subject=None):
        """A signed-in account (the role is computed from the groups at use, so ``role`` is informational)."""
        return self.db().userUpsert(subject or f'oidc|{name}', username=name, email=f'{name}@example.test', display_name=name.title(),
                                    groups=list(groups), role=role, login=False)

    def token_for(self, user_id, name='test', expires=None):
        token, digest, hint, _ = mcp_auth.new_token()
        self.db().mcpTokenCreate(user_id, name, digest, hint, expires)
        return token

    def rpc(self, method, params=None, rid=1):
        return {'jsonrpc': '2.0', 'id': rid, 'method': method, 'params': params or {}}

    def client(self):
        from werkzeug.test import Client
        from spiderfoot.mcp.wsgi import McpWsgiApp
        return Client(McpWsgiApp(self.app))

    def post(self, body, token='default', headers=None, client=None, raw=None):
        client = client or self.client()
        h = {'Content-Type': 'application/json'}
        if token == 'default':
            token = self.token
        if token:
            h['Authorization'] = 'Bearer ' + token
        h.update(headers or {})
        data = raw if raw is not None else json.dumps(body)
        return client.post('/mcp', data=data, headers=h)

    def call(self, tool, **arguments):
        """Run a tool through the real HTTP app; returns (is_error, structured-or-text)."""
        resp = self.post(self.rpc('tools/call', {'name': tool, 'arguments': arguments}))
        assert resp.status_code == 200, resp.get_data(as_text=True)
        result = resp.get_json()['result']
        return result['isError'], (result['content'][0]['text'] if result['isError'] else result['structuredContent'])


class FakeProcess:
    """Stands in for the scan worker: registers the scan in the database like a real start would."""

    def __init__(self, env):
        self.env = env

    def __call__(self, target=None, args=None, **kw):
        queue, name, scan_id, tgt, ttype, modules, cfg = args
        self.env.launched.append({'name': name, 'scan_id': scan_id, 'target': tgt, 'type': ttype, 'modules': list(modules)})
        env = self.env

        class Proc:
            daemon = False

            def start(self):
                dbh = env.db()
                dbh.scanInstanceCreate(scan_id, name, tgt)
                dbh.scanInstanceSet(scan_id, started=int(time.time() * 1000), status='RUNNING')
                dbh.scanConfigSet(scan_id, {'_modulesenabled': ','.join(modules)})
        return Proc()


@pytest.fixture
def env(tmp_path):
    db_path = str(tmp_path / 'mcp.db')
    SpiderFootDb({'__database': db_path}, init=True)
    config = {'__database': db_path, '__modules__': fake_modules(), '__correlationrules__': [], '_maxscans': 3,
              'sfp_keyed:api_key': SECRET, '_ai_openrouter_key': OTHER_SECRET}
    app = create_app(config=config)
    app.config['TESTING'] = True
    app.config['SF_USERS'] = {}
    e = Env(app, db_path, None)
    # The default caller is the synthetic administrator of an installation without sign-in
    e.admin = e.db().userUpsert('local:admin', username='admin', display_name='Administrator', role='admin', login=False)
    e.token = e.token_for(e.admin['id'])
    e.db().configSet({'sfp_keyed:api_key': SECRET, '_ai_openrouter_key': OTHER_SECRET, '_mcp_enabled': '1'})
    e.fake_process = FakeProcess(e)
    with mock.patch('spiderfoot.services.tools.tool_installed', return_value=False), \
            mock.patch('spiderfoot.mcp.guardrails.resolver', return_value=[]), \
            mock.patch('spiderfoot.blueprints.api.mp', types.SimpleNamespace(Process=e.fake_process)):
        yield e
