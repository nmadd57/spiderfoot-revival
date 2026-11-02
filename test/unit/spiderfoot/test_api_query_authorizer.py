# test/unit/spiderfoot/test_api_query_authorizer.py
"""The /query SQL console is locked down by a SQLite authorizer, not only by text checks."""
import base64
import json
import sqlite3

import pytest

from spiderfoot.app import create_app
from spiderfoot.blueprints.api import query_authorizer


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / 'sf.db')
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE tbl_scan_instance (guid TEXT, name TEXT)")
    conn.execute("INSERT INTO tbl_scan_instance VALUES ('g1', 'first')")
    conn.execute("CREATE TABLE tbl_config (scope TEXT, opt TEXT, val TEXT)")
    conn.execute("INSERT INTO tbl_config VALUES ('GLOBAL', 'api_key', 'secret-value')")
    conn.commit()
    conn.close()
    return path


@pytest.fixture
def guarded(db_path):
    conn = sqlite3.connect(db_path)
    conn.set_authorizer(query_authorizer)
    yield conn
    conn.close()


class TestQueryAuthorizer:
    def test_plain_select_allowed(self, guarded):
        assert guarded.execute("SELECT name FROM tbl_scan_instance").fetchall() == [('first',)]

    def test_functions_and_recursive_cte_allowed(self, guarded):
        assert guarded.execute("SELECT upper('a'), length('abc')").fetchall() == [('A', 3)]
        rows = guarded.execute(
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 3) SELECT x FROM c").fetchall()
        assert rows == [(1,), (2,), (3,)]

    def test_tbl_config_read_denied(self, guarded):
        with pytest.raises(sqlite3.DatabaseError):
            guarded.execute("SELECT val FROM tbl_config").fetchall()
        with pytest.raises(sqlite3.DatabaseError):
            guarded.execute("SELECT * FROM TBL_CONFIG").fetchall()
        with pytest.raises(sqlite3.DatabaseError):
            guarded.execute("SELECT name FROM tbl_scan_instance WHERE guid IN (SELECT scope FROM tbl_config)").fetchall()

    @pytest.mark.parametrize('sql', [
        "ATTACH DATABASE ':memory:' AS other",
        "PRAGMA table_info(tbl_scan_instance)",
        "INSERT INTO tbl_scan_instance VALUES ('g2', 'second')",
        "UPDATE tbl_scan_instance SET name = 'x'",
        "DELETE FROM tbl_scan_instance",
        "DROP TABLE tbl_scan_instance",
        "CREATE TABLE t (a)",
        "SELECT load_extension('x')",
    ])
    def test_everything_else_denied(self, guarded, sql):
        with pytest.raises(sqlite3.DatabaseError):
            guarded.execute(sql).fetchall()
        assert guarded.execute("SELECT count(*) FROM tbl_scan_instance").fetchall() == [(1,)]


def _headers():
    creds = base64.b64encode(b'admin:pass').decode()
    return {'Authorization': f'Basic {creds}'}


@pytest.fixture
def client(db_path):
    app = create_app(config={'__database': db_path, '__modules__': {}})
    app.config['TESTING'] = True
    app.config['SF_USERS'] = {'admin': 'pass'}
    return app.test_client()


class TestQueryEndpointAuthorizer:
    def test_select_returns_rows(self, client):
        r = client.post('/api/query', data={'query': 'SELECT guid, name FROM tbl_scan_instance'}, headers=_headers())
        assert r.status_code == 200
        assert json.loads(r.data) == [{'guid': 'g1', 'name': 'first'}]

    def test_config_table_not_readable(self, client):
        r = client.post('/api/query', data={'query': 'SELECT val FROM tbl_config'}, headers=_headers())
        assert r.status_code == 400
        assert b'secret-value' not in r.data
