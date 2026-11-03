"""MCP: relevance in get_scan / get_scan_events, create_scan context, reassess_relevance and mark_event, with the usual access rules."""
from unittest import mock

from spiderfoot.services import relevance_job as job
from test.unit.services.relevance_fixture import TARGET, namesake_events


def load(env, scan_id='REL00001', owner=None):
    dbh = env.db()
    dbh.scanInstanceCreate(scan_id, 'mcp: namesakes', TARGET, owner)
    dbh.scanInstanceSet(scan_id, started=1000, ended=2000, status='FINISHED')
    dbh.scanConfigSet(scan_id, {'_modulesenabled': 'sfp__stor_db,sfp_crt'})
    for r in namesake_events():
        dbh.dbh.execute("INSERT INTO tbl_scan_results (scan_instance_id,hash,type,generated,confidence,visibility,risk,module,data,false_positive,source_event_hash)"
                        " VALUES (?,?,?,?,100,100,0,?,?,0,?)", (scan_id, r[0], r[1], r[5], r[2], r[3], r[4]))
    dbh.conn.commit()
    dbh.scanContextSet(scan_id, 'location: Massachusetts', True)
    job.assess_scan(dict(job.DEFAULTS, __database=env.db_path), scan_id, dbh=dbh, network=False)
    return scan_id


class TestReading:
    def test_get_scan_carries_the_relevance_summary(self, env):
        load(env)
        err, out = env.call('get_scan', scan_id='REL00001')
        rel = out['relevance']
        assert not err and rel['assessed'] and rel['counts']['unrelated'] > 10 and rel['method'] == 'heuristics'
        assert rel['pruneUnrelated'] is True and rel['hasContextHints'] is True and rel['status'] == 'done'

    def test_unassessed_scan(self, env):
        env.seed_scan('SCAN0001')
        err, out = env.call('get_scan', scan_id='SCAN0001')
        assert out['relevance']['assessed'] is False and out['relevance']['counts'] is None

    def test_events_hide_unrelated_by_default(self, env):
        load(env)
        err, out = env.call('get_scan_events', scan_id='REL00001', limit=300)
        assert not err and out['hiddenAsUnrelated'] > 10 and 'include_unrelated' in out['note']
        labels = {e['relevance']['label'] for e in out['events']}
        assert 'unrelated' not in labels and labels
        ev = out['events'][0]
        assert ev['eventId'] and set(ev['relevance']) == {'label', 'score', 'reasons', 'markedByUser'} and ev['relevance']['reasons']

    def test_include_unrelated_and_min_relevance(self, env):
        load(env)
        _, everything = env.call('get_scan_events', scan_id='REL00001', include_unrelated=True, limit=300)
        _, default = env.call('get_scan_events', scan_id='REL00001', limit=300)
        assert everything['total'] > default['total'] and 'hiddenAsUnrelated' not in everything
        _, strong = env.call('get_scan_events', scan_id='REL00001', min_relevance=0.6, limit=300)
        assert strong['total'] < default['total'] and all(e['relevance']['score'] >= 0.6 for e in strong['events'])
        err, out = env.call('get_scan_events', scan_id='REL00001', min_relevance=2)      # clamped to 1, like limit
        assert not err and out['total'] <= 1

    def test_scans_without_data_return_everything(self, env):
        env.seed_scan('SCAN0001')
        _, out = env.call('get_scan_events', scan_id='SCAN0001')
        assert out['total'] >= 5 and 'hiddenAsUnrelated' not in out and out['events'][0]['relevance'] is None


class TestWriting:
    def test_mark_event_and_lineage(self, env):
        load(env)
        with mock.patch.object(job, 'start_job', return_value=True) as sj:
            err, out = env.call('mark_event', scan_id='REL00001', event_id='bc_firm', verdict='not_related')
            assert not err and out['eventsChanged'] >= 9 and out['reassessing'] and sj.called
            err, out = env.call('mark_event', scan_id='REL00001', event_id='npi_lic', verdict='mine')
            assert not err and out['eventsChanged'] == 1
        assert env.db().overrideGet('REL00001')['npi_lic'] == 'mine' and env.db().overrideGet('REL00001')['firm_lei'] == 'not_related'
        _, ev = env.call('get_scan_events', scan_id='REL00001', event_type='PROFESSIONAL_LICENSE')
        mine = [e for e in ev['events'] if e['eventId'] == 'npi_lic'][0]
        assert mine['relevance']['label'] == 'confirmed' and mine['relevance']['markedByUser'] == 'mine'

    def test_clear(self, env):
        load(env)
        with mock.patch.object(job, 'start_job', return_value=False):
            env.call('mark_event', scan_id='REL00001', event_id='npi_lic', verdict='mine')
            err, out = env.call('mark_event', scan_id='REL00001', event_id='npi_lic', verdict='clear')
        assert not err and env.db().overrideGet('REL00001') == {}

    def test_unknown_event_and_scan(self, env):
        load(env)
        assert env.call('mark_event', scan_id='REL00001', event_id='nonexistent-event', verdict='mine')[0]
        assert env.call('mark_event', scan_id='NOSUCH01', event_id='nonexistent-event', verdict='mine')[0]
        assert env.call('mark_event', scan_id='REL00001', event_id='npi_lic', verdict='maybe')[0]

    def test_reassess(self, env):
        load(env)
        with mock.patch.object(job, 'start_job', return_value=True) as sj:
            err, out = env.call('reassess_relevance', scan_id='REL00001', context='born: 1985')
        assert not err and out['started'] and sj.called
        assert env.db().scanContextGet('REL00001')['context'] == 'born: 1985'

    def test_edit_level_is_needed(self, env):
        owner = env.make_user('olivia', ['sf-users'])
        viewer = env.make_user('vic', ['sf-users'])
        load(env, owner=owner['id'])
        env.db().aclSet('REL00001', 'user', str(viewer['id']), 'view')
        viewer_token = env.token_for(viewer['id'])
        resp = env.post(env.rpc('tools/call', {'name': 'mark_event', 'arguments': {'scan_id': 'REL00001', 'event_id': 'npi_lic', 'verdict': 'mine'}}), token=viewer_token)
        result = resp.get_json()['result']
        assert result['isError'] and 'edit' in result['content'][0]['text'] or 'not enough' in result['content'][0]['text']
        resp = env.post(env.rpc('tools/call', {'name': 'reassess_relevance', 'arguments': {'scan_id': 'REL00001'}}), token=viewer_token)
        assert resp.get_json()['result']['isError']
        # reading is fine for the viewer
        resp = env.post(env.rpc('tools/call', {'name': 'get_scan_events', 'arguments': {'scan_id': 'REL00001'}}), token=viewer_token)
        assert not resp.get_json()['result']['isError']

    def test_operator_permission_is_required(self, env):
        load(env)
        env.configure(allow_scan=0)
        err, text = env.call('mark_event', scan_id='REL00001', event_id='npi_lic', verdict='mine')
        assert err and 'not allowed' in text

    def test_create_scan_takes_context_and_prune(self, env):
        captured = {}
        from spiderfoot.blueprints import api
        real = api.start_scan_core

        def spy(*a, **kw):
            captured.update(kw)
            return real(*a, **kw)
        with mock.patch.object(api, 'start_scan_core', side_effect=spy):
            err, out = env.call('create_scan', target='"Marcus Elias Thornwood"', modules=['sfp_crt'],
                                context='location: Boston, MA', prune_unrelated=False)
        assert not err, out
        assert captured['context'] == 'location: Boston, MA' and captured['prune'] is False

    def test_secrets_never_appear(self, env):
        load(env)
        from test.unit.services.conftest import SECRET, OTHER_SECRET
        for tool, args in (('get_scan', {}), ('get_scan_events', {'limit': 300, 'include_unrelated': True})):
            err, out = env.call(tool, scan_id='REL00001', **args)
            assert SECRET not in str(out) and OTHER_SECRET not in str(out)
