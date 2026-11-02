# test/unit/spiderfoot/test_api_no_exception_text.py
"""Exception text must stay in the server log and never reach the HTTP client."""
import base64
import json
import sqlite3
from unittest import mock

import pytest

from spiderfoot.app import create_app

SECRET = 'zq-internal-detail-9431'


@pytest.fixture
def client(tmp_path):
    from spiderfoot import SpiderFootDb
    path = str(tmp_path / 'x.db')
    SpiderFootDb({'__database': path}, init=True)
    app = create_app(config={'__database': path, '__modules__': {'sfp_dnsresolve': {'meta': {}, 'opts': {}}},
                             '__correlationrules__': [], '_debug': '0'})
    app.config['TESTING'] = True
    app.config['SF_USERS'] = {}
    c = app.test_client()
    c.environ_base['HTTP_AUTHORIZATION'] = 'Basic ' + base64.b64encode(b'x:x').decode()
    return c


class TestNoExceptionText:
    def test_usage_limits_value_error_is_generic(self, client):
        with mock.patch('spiderfoot.services.usage.normalize_limits', side_effect=ValueError(SECRET)):
            r = client.post('/api/usage/limits', json={'module': 'sfp_dnsresolve', 'limits': {'x': 1}})
        assert r.status_code == 400
        assert SECRET not in r.get_data(as_text=True)
        assert json.loads(r.data)[0] == 'ERROR'

    def test_vacuum_failure_is_generic(self, client):
        db = mock.Mock()
        db.vacuumDB.side_effect = RuntimeError(SECRET)
        with mock.patch('spiderfoot.blueprints.api.get_db', return_value=db):
            r = client.post('/api/vacuum')
        assert SECRET not in r.get_data(as_text=True)
        assert json.loads(r.data)[0] == 'ERROR'

    def test_savesettings_failure_is_generic(self, client):
        with mock.patch('spiderfoot.blueprints.api.get_db', side_effect=RuntimeError(SECRET)):
            r = client.post('/api/savesettings', data={'allopts': '{"a": "b"}'})
        assert SECRET not in r.get_data(as_text=True)
        assert json.loads(r.data)[0] == 'ERROR'

    def test_preset_create_failure_is_generic(self, client):
        db = mock.Mock()
        db.presetList.return_value = []
        db.presetCreate.side_effect = sqlite3.IntegrityError(SECRET)
        with mock.patch('spiderfoot.blueprints.api.get_db', return_value=db):
            r = client.post('/api/presets', json={'name': 'mine', 'modules': ['sfp_dnsresolve']})
        assert r.status_code == 400
        assert SECRET not in r.get_data(as_text=True)
        db.presetCreate.side_effect = RuntimeError(SECRET)
        with mock.patch('spiderfoot.blueprints.api.get_db', return_value=db):
            r = client.post('/api/presets', json={'name': 'mine', 'modules': ['sfp_dnsresolve']})
        assert r.status_code == 500
        assert SECRET not in r.get_data(as_text=True)
