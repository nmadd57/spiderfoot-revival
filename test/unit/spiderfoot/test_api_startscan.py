# test/unit/spiderfoot/test_api_startscan.py
"""The /api/startscan route keeps its behaviour and response shape after sharing start_scan_core with the MCP server."""
import base64
import types
from unittest import mock

import pytest

from spiderfoot import SpiderFootDb
from spiderfoot.app import create_app
from spiderfoot.blueprints import api

MODULES = {
    'sfp_dnsresolve': {'name': 'DNS', 'descr': 'd', 'group': ['Footprint'], 'provides': ['IP_ADDRESS'], 'consumes': ['INTERNET_NAME'],
                       'meta': {'name': 'DNS', 'summary': 's', 'flags': [], 'pricing': 'local', 'useCases': ['Footprint'], 'categories': ['DNS']}, 'opts': {}},
    'sfp_countryname': {'name': 'Country', 'descr': 'd', 'group': ['Footprint'], 'provides': ['COUNTRY_NAME'], 'consumes': ['IP_ADDRESS'],
                        'meta': {'name': 'Country', 'summary': 's', 'flags': [], 'pricing': 'local', 'useCases': ['Footprint'], 'categories': ['Real World']}, 'opts': {}},
    'sfp_nokey': {'name': 'Keyed', 'descr': 'd', 'group': ['Footprint'], 'provides': [], 'consumes': ['INTERNET_NAME'],
                  'meta': {'name': 'Keyed', 'summary': 's', 'flags': ['apikey'], 'pricing': 'free_key', 'useCases': ['Footprint'], 'categories': ['DNS']},
                  'opts': {'api_key': ''}},
}


@pytest.fixture
def started(tmp_path):
    """An app on a real database plus a recorder standing in for the scan worker process."""
    db_path = str(tmp_path / 'scan.db')
    SpiderFootDb({'__database': db_path}, init=True)
    app = create_app(config={'__database': db_path, '__modules__': MODULES, '__correlationrules__': [], '_maxscans': 2})
    app.config['TESTING'] = True
    app.config['SF_USERS'] = {}
    launched = []

    def process(target=None, args=None, **kw):
        launched.append(args)

        class Proc:
            daemon = False

            def start(self):
                dbh = SpiderFootDb({'__database': db_path})
                dbh.scanInstanceCreate(args[2], args[1], args[3])
                dbh.scanInstanceSet(args[2], status='RUNNING')
        return Proc()

    with mock.patch.object(api, 'mp', types.SimpleNamespace(Process=process)):
        client = app.test_client()
        client.environ_base['HTTP_AUTHORIZATION'] = 'Basic ' + base64.b64encode(b'x:x').decode()
        yield client, launched, db_path


def post(client, **form):
    data = {'scanname': 'n', 'scantarget': 'example.com', 'modulelist': 'sfp_dnsresolve', 'typelist': '', 'usecase': ''}
    data.update(form)
    return client.post('/api/startscan', data=data)


class TestStartscanRoute:
    def test_success_shape(self, started):
        client, launched, db_path = started
        resp = post(client)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body[0] == 'SUCCESS' and len(body) == 2
        queue, name, scan_id, target, ttype, modules, cfg = launched[0]
        assert (name, scan_id, target, ttype) == ('n', body[1], 'example.com', 'INTERNET_NAME')
        assert modules == ['sfp__stor_db', 'sfp_dnsresolve']
        assert SpiderFootDb({'__database': db_path}).scanInstanceGet(body[1])[0] == 'n'

    def test_route_does_not_prefix_names(self, started):
        client, launched, _ = started
        post(client, scanname='plain name')
        assert launched[0][1] == 'plain name'

    @pytest.mark.parametrize('form,message', [
        ({'scanname': ''}, 'Incorrect usage: scan name was not specified.'),
        ({'scantarget': ''}, 'Incorrect usage: scan target was not specified.'),
        ({'modulelist': ''}, 'Incorrect usage: no modules specified for scan.'),
        ({'scantarget': '%%%'}, 'Unrecognised target type.'),
        ({'modulelist': 'sfp_nokey'}, 'Incorrect usage: no enabled modules specified for scan.'),
    ])
    def test_error_shape(self, started, form, message):
        client, launched, _ = started
        resp = post(client, **form)
        assert resp.status_code == 200
        assert resp.get_json() == ['ERROR', message]
        assert launched == []

    def test_usecase_and_disabled_and_auto_disabled_modules(self, started):
        client, launched, db_path = started
        SpiderFootDb({'__database': db_path}).configSet({'_disabled_modules': 'sfp_countryname'})
        assert post(client, modulelist='', usecase='Footprint').get_json()[0] == 'SUCCESS'
        assert launched[0][5] == ['sfp__stor_db', 'sfp_dnsresolve']

    def test_private_ip_strips_incompatible_modules(self, started):
        client, launched, _ = started
        assert post(client, scantarget='10.0.0.5', modulelist='sfp_dnsresolve,sfp_countryname').get_json()[0] == 'SUCCESS'
        assert launched[0][5] == ['sfp__stor_db', 'sfp_dnsresolve']
        assert post(client, scantarget='10.0.0.5', modulelist='sfp_countryname').get_json() == ['ERROR', 'No modules available for private IP targets.']

    def test_names_keep_their_characters(self, started):
        client, launched, _ = started
        assert post(client, scantarget='business:A&B Widgets LLC').get_json()[0] == 'SUCCESS'
        assert launched[0][3:5] == ('A&B Widgets LLC', 'COMPANY_NAME')

    def test_429_when_the_cap_is_reached_on_a_real_database(self, started):
        client, launched, db_path = started
        dbh = SpiderFootDb({'__database': db_path})
        for i in range(2):
            dbh.scanInstanceCreate(f'RUN{i}', 'x', 'example.com')
            dbh.scanInstanceSet(f'RUN{i}', status='RUNNING')
        resp = post(client)
        assert resp.status_code == 429
        assert 'Maximum concurrent scans (2) reached' in resp.get_json()['error']['message']
        assert launched == []

    def test_spawn_failure_is_generic(self, started):
        client, _, _ = started
        with mock.patch.object(api, 'mp', types.SimpleNamespace(Process=mock.Mock(side_effect=RuntimeError('secret-detail')))):
            body = post(client).get_json()
        assert body[0] == 'ERROR' and 'secret-detail' not in body[1] and 'failed to start' in body[1]


class TestNormalizeTarget:
    @pytest.mark.parametrize('raw,expected', [
        ('Example.com', ('example.com', 'INTERNET_NAME')), ('  example.com ', ('example.com', 'INTERNET_NAME')),
        ('John Smith', ('John Smith', 'HUMAN_NAME')), ('"jsmith"', ('jsmith', 'USERNAME')),
        ('business:Acme & Co LLC', ('Acme & Co LLC', 'COMPANY_NAME')), ('???', ('???', None)),
    ])
    def test_cases(self, raw, expected):
        assert api.normalize_target(api.clean_user_input([raw])[0]) == expected

    def test_known_type_skips_detection(self):
        assert api.normalize_target('jsmith', 'USERNAME') == ('jsmith', 'USERNAME')
