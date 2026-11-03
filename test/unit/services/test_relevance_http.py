"""Relevance through the web layer: access rules, the results filter, counters, exports, search, marking, start parameters, settings."""
import csv
import io
import json
import types
from unittest import mock

import pytest

from spiderfoot import SpiderFootDb
from spiderfoot.blueprints import api
from spiderfoot.services import relevance_job as job
from test.unit import identity_helpers as h
from test.unit.services.conftest import fake_modules
from test.unit.services.relevance_fixture import TARGET, namesake_events

SCAN = 'REL00001'


def load_scan(app, scan_id=SCAN, owner=None, assess=True, context=''):
    h.seed_scan(app, scan_id, owner=owner, target=TARGET)
    dbh = h.db(app)
    for r in namesake_events():
        if r[1] == 'ROOT':
            dbh.dbh.execute("INSERT INTO tbl_scan_results (scan_instance_id,hash,type,generated,confidence,visibility,risk,module,data,false_positive,source_event_hash)"
                            " VALUES (?,?,?,?,100,100,0,?,?,0,?)", (scan_id, r[0], r[1], r[5], r[2], r[3], r[4]))
            continue
        dbh.dbh.execute("INSERT INTO tbl_scan_results (scan_instance_id,hash,type,generated,confidence,visibility,risk,module,data,false_positive,source_event_hash)"
                        " VALUES (?,?,?,?,100,100,0,?,?,0,?)", (scan_id, f'{scan_id}:{r[0]}' if False else r[0], r[1], r[5], r[2], r[3], r[4]))
    dbh.conn.commit()
    dbh.scanContextSet(scan_id, context, True)
    if assess:
        job.assess_scan(app.config['SF_CONFIG'], scan_id, dbh=dbh, network=False)
    return dbh


@pytest.fixture
def plain(tmp_path):
    app = h.make_app(tmp_path, modules=fake_modules(), **job.DEFAULTS)
    load_scan(app)
    c = app.test_client()
    c.environ_base['HTTP_AUTHORIZATION'] = 'Basic ' + __import__('base64').b64encode(b'x:x').decode()
    return app, c


@pytest.fixture
def world(tmp_path):
    app = h.make_app(tmp_path, modules=fake_modules())
    h.configure_sso(app)
    people = (('root', ['sf-admins']), ('olivia', ['sf-users']), ('edith', ['sf-users']), ('vic', ['sf-users']), ('sam', ['sf-users']))
    users = {n: h.add_user(app, n, g) for n, g in people}
    load_scan(app, owner=users['olivia']['id'])
    dbh = h.db(app)
    dbh.aclSet(SCAN, 'user', str(users['edith']['id']), 'edit')
    dbh.aclSet(SCAN, 'user', str(users['vic']['id']), 'view')
    return app, users


def as_user(app, users, name):
    return h.sign_in(app.test_client(), users[name])


class TestAccess:
    @pytest.mark.parametrize('who,status', [('olivia', 200), ('edith', 200), ('vic', 200), ('sam', 404), ('root', 200)])
    def test_reading_needs_view(self, world, who, status):
        app, users = world
        c = as_user(app, users, who)
        assert c.get(f'/api/relevance/status?id={SCAN}').status_code == status
        assert c.get(f'/frag/relevance-card?id={SCAN}').status_code == status

    @pytest.mark.parametrize('who,status', [('olivia', 200), ('edith', 200), ('vic', 403), ('sam', 404), ('root', 200)])
    def test_writing_needs_edit(self, world, who, status):
        app, users = world
        c = as_user(app, users, who)
        with mock.patch.object(job, 'start_job', return_value=True):
            assert c.post('/api/relevance/mark', data={'id': SCAN, 'hashes': 'npi_lic', 'verdict': 'mine'}).status_code == status
            assert c.post('/api/relevance/assess', data={'id': SCAN}).status_code == status

    def test_the_sample_test_is_for_administrators(self, world):
        app, users = world
        for who, status in (('olivia', 403), ('vic', 403), ('root', 200)):
            r = as_user(app, users, who).post('/api/relevance/test', json={'target': TARGET, 'candidate': 'Marcus Adrian Thornwood, MD'})
            assert r.status_code == status


class TestResultsFilter:
    def events(self, c, **params):
        q = '&'.join(f'{k}={v}' for k, v in params.items())
        r = c.get(f'/frag/events?id={SCAN}&dedup=0&{q}')
        assert r.status_code == 200
        return r.get_data(as_text=True)

    def test_default_hides_unrelated_and_says_so(self, plain):
        _, c = plain
        body = self.events(c)
        assert 'data-relevance="unrelated"' not in body and 'NPI 1000000001' not in body
        assert 'marcus.elias.thornwood' in body
        assert 'hidden as unrelated' in body and 'data-hidden-unrelated' in body

    def test_show_all_and_modes(self, plain):
        _, c = plain
        assert 'MARCUS ADRIAN THORNWOOD' in self.events(c, rel='all')
        only_unrelated = self.events(c, rel='unrelated')
        assert 'MARCUS ADRIAN THORNWOOD' in only_unrelated and 'marcus.elias.thornwood' not in only_unrelated
        strong = self.events(c, rel='strong')
        assert 'marcus.elias.thornwood' in strong and 'SkyFan0042' not in strong
        assert 'SkyFan0042' in self.events(c, rel='unclear')

    def test_groups_collapse_under_their_entity(self, plain):
        _, c = plain
        body = self.events(c)
        assert 'under' in body and 'Example Securities Llc' in body and 'hidden' in body
        first = c.get(f'/frag/events?id={SCAN}&under=bc_firm&rel=all').get_data(as_text=True)
        assert '9 Example Plaza' in first and 'Back to the list' in first and 'MARCUS ADRIAN' not in first

    def test_sort_by_relevance_and_badges(self, plain):
        _, c = plain
        body = self.events(c, rel='all', sort='relevance')
        assert body.index('data-relevance="confirmed"') < body.index('data-relevance="unclear"') < body.index('data-relevance="unrelated"')
        assert 'Different middle name' in body

    def test_scan_without_relevance_data_hides_nothing(self, tmp_path):
        app = h.make_app(tmp_path, modules=fake_modules())
        load_scan(app, assess=False)
        c = app.test_client()
        body = c.get(f'/frag/events?id={SCAN}&dedup=0').get_data(as_text=True)
        assert 'MARCUS ADRIAN THORNWOOD' in body and 'hidden as unrelated' not in body and 'data-relevance=' not in body

    def test_tab_counts_respect_the_filter(self, plain):
        _, c = plain
        hide = c.get(f'/frag/results-tab?id={SCAN}&tab=data').get_data(as_text=True)
        show = c.get(f'/frag/results-tab?id={SCAN}&tab=data&rel=all').get_data(as_text=True)
        assert 'Relevance: hide unrelated' in hide
        n_hide = int(hide.split('Infrastructure')[1].split('(')[1].split(')')[0]) if 'Infrastructure' in hide else 0
        n_show = int(show.split('Infrastructure')[1].split('(')[1].split(')')[0]) if 'Infrastructure' in show else 0
        assert n_show > n_hide

    def test_header_card(self, plain):
        _, c = plain
        card = c.get(f'/frag/relevance-card?id={SCAN}').get_data(as_text=True)
        assert 'data-rel-count="unrelated"' in card and 'data-rel-hidden-counter' in card and 'Re-assess' in card and 'heuristics' in card
        page = c.get(f'/scaninfo?id={SCAN}').get_data(as_text=True)
        assert 'relevance-card-slot' in page


class TestExportsAndSearch:
    def test_csv_has_relevance_columns_and_leaves_out_unrelated(self, plain):
        _, c = plain
        rows = list(csv.reader(io.StringIO(c.get(f'/api/scaneventresultexport?id={SCAN}&type=ALL').get_data(as_text=True))))
        assert rows[0][-2:] == ['Relevance', 'Relevance score']
        text = json.dumps(rows)
        assert 'MARCUS ADRIAN' not in text and 'marcus.elias.thornwood' in text
        rows = list(csv.reader(io.StringIO(c.get(f'/api/scaneventresultexport?id={SCAN}&type=ALL&include_unrelated=1').get_data(as_text=True))))
        assert any('MARCUS ADRIAN' in r[5] and r[-2] == 'unrelated' for r in rows[1:])

    def test_multi_csv_and_json(self, plain):
        _, c = plain
        csv_text = c.get(f'/api/scaneventresultexportmulti?ids={SCAN}').get_data(as_text=True)
        assert 'Relevance' in csv_text.splitlines()[0] and 'MARCUS ADRIAN' not in csv_text
        data = json.loads(c.get(f'/api/scanexportjsonmulti?ids={SCAN}').get_data(as_text=True))
        assert data and all('relevance' in r for r in data) and not any(r['relevance'] == 'unrelated' for r in data)
        everything = json.loads(c.get(f'/api/scanexportjsonmulti?ids={SCAN}&include_unrelated=true').get_data(as_text=True))
        assert len(everything) > len(data) and any(r['relevance'] == 'unrelated' for r in everything)

    def test_search_rows_end_with_label_and_score(self, plain):
        _, c = plain
        rows = c.get(f'/api/search?id={SCAN}&value=*thornwood*').get_json()
        assert rows and all(len(r) == 15 for r in rows) and not any(r[13] == 'unrelated' for r in rows)
        rows = c.get(f'/api/search?id={SCAN}&value=*thornwood*&include_unrelated=1').get_json()
        assert any(r[13] == 'unrelated' for r in rows)
        assert c.get(f'/api/scansearchresultexport?id={SCAN}&value=*thornwood*&include_unrelated=1').get_data(as_text=True).splitlines()[0].endswith('Relevance score')

    def test_event_list_json(self, plain):
        _, c = plain
        hidden = c.get(f'/api/scaneventresults?id={SCAN}').get_json()
        everything = c.get(f'/api/scaneventresults?id={SCAN}&include_unrelated=1').get_json()
        assert len(everything) > len(hidden) and all(len(r) == 13 for r in hidden)

    def test_ai_summary_only_gets_relevant_findings(self, plain):
        app, _ = plain
        from spiderfoot.blueprints.ai import _scan_payload
        from spiderfoot.services import ai_service
        with app.app_context():
            scan, type_counts, correlations, events, ended = _scan_payload(h.db(app), SCAN)
        text = ' '.join(e['data'] for e in events)
        assert 'MARCUS ADRIAN' not in text and 'marcus.elias.thornwood' in text and scan['excluded_unrelated'] > 10
        msgs, _ = ai_service.build_scan_prompt(scan, type_counts, correlations, events)
        assert 'further findings were judged' in msgs[1]['content'] and 'MARCUS ADRIAN' not in msgs[1]['content']


class TestMarking:
    def mark(self, c, **form):
        data = {'id': SCAN, 'scope': 'event'}
        data.update(form)
        with mock.patch.object(job, 'start_job', return_value=True) as sj:
            r = c.post('/api/relevance/mark', data=data)
        return r, sj

    def test_mine_pins_the_finding_and_reassesses(self, plain):
        app, c = plain
        r, sj = self.mark(c, hashes='npi_lic', verdict='mine')
        assert r.status_code == 200 and r.get_json()['reassessing'] and sj.called
        assert h.db(app).relevanceGet(SCAN)['npi_lic'][1] == 'confirmed'
        assert h.db(app).overrideGet(SCAN) == {'npi_lic': 'mine'}

    def test_not_related_applies_to_the_lineage(self, plain):
        app, c = plain
        r, _ = self.mark(c, hashes='fb_nameonly', verdict='not_related', scope='lineage')
        assert r.status_code == 200
        r, _ = self.mark(c, hashes='bc2_lic', verdict='not_related', scope='lineage')
        assert h.db(app).overrideGet(SCAN)['fb_nameonly'] == 'not_related'
        # a real entity with descendants
        r, _ = self.mark(c, hashes='acme', verdict='not_related', scope='lineage')
        ov = h.db(app).overrideGet(SCAN)
        assert {'acme', 'officer', 'officer_co', 'officer_addr', 'acme_addr', 'acme_wifi'} <= set(ov)
        job.assess_scan(app.config['SF_CONFIG'], SCAN, dbh=h.db(app), network=False)
        assert h.db(app).relevanceGet(SCAN)['acme'][1] == 'unrelated'

    def test_clear_removes_the_decision(self, plain):
        app, c = plain
        self.mark(c, hashes='npi_lic', verdict='mine')
        r, _ = self.mark(c, hashes='npi_lic', verdict='clear')
        assert r.get_json()['changed'] == 1 and h.db(app).overrideGet(SCAN) == {}

    @pytest.mark.parametrize('form', [{'verdict': 'maybe', 'hashes': 'npi_lic'}, {'verdict': 'mine', 'hashes': ''},
                                      {'verdict': 'mine', 'hashes': 'npi_lic', 'scope': 'galaxy'}])
    def test_bad_input(self, plain, form):
        _, c = plain
        r, _ = self.mark(c, **form)
        assert r.status_code == 400

    def test_foreign_hashes_are_ignored(self, plain):
        _, c = plain
        r, _ = self.mark(c, hashes='not-in-this-scan', verdict='mine')
        assert r.status_code == 404

    def test_status_and_assess(self, plain):
        _, c = plain
        st = c.get(f'/api/relevance/status?id={SCAN}').get_json()
        assert st['hasData'] and st['counts']['unrelated'] > 10 and st['run']['status'] == 'done' and st['prune'] is True
        with mock.patch.object(job, 'start_job', return_value=True):
            assert c.post('/api/relevance/assess', data={'id': SCAN, 'context': 'lives in Boston, MA'}).get_json()['started']
        assert c.get(f'/api/relevance/status?id={SCAN}').get_json()['context'] == 'lives in Boston, MA'
        assert c.post('/api/relevance/assess', data={'id': 'NOPE0000'}).status_code in (404, 409)


class TestStartParameters:
    @pytest.fixture
    def started(self, tmp_path):
        app = h.make_app(tmp_path, modules={'sfp_dnsresolve': fake_modules()['sfp_dnsresolve']})
        launched = []

        def process(target=None, args=None, **kw):
            launched.append(args)

            class Proc:
                daemon = False

                def start(self):
                    d = SpiderFootDb(args[6])
                    d.scanInstanceCreate(args[2], args[1], args[3])
                    d.scanInstanceSet(args[2], status='RUNNING')
            return Proc()
        with mock.patch.object(api, 'mp', types.SimpleNamespace(Process=process)):
            c = app.test_client()
            c.environ_base['HTTP_AUTHORIZATION'] = 'Basic ' + __import__('base64').b64encode(b'x:x').decode()
            yield c, launched, app

    def test_context_and_prune_reach_the_scan(self, started):
        c, launched, _ = started
        r = c.post('/api/startscan', data={'scanname': 'n', 'scantarget': 'Marcus Elias Thornwood', 'modulelist': 'sfp_dnsresolve',
                                           'context': 'location: Boston, MA\x00', 'prune': '0'})
        assert r.get_json()[0] == 'SUCCESS'
        cfg = launched[0][6]
        assert cfg['__scan_context'] == 'location: Boston, MA' and cfg['__scan_prune'] is False

    def test_defaults_when_omitted(self, started):
        c, launched, _ = started
        c.post('/api/startscan', data={'scanname': 'n', 'scantarget': 'example.com', 'modulelist': 'sfp_dnsresolve'})
        cfg = launched[0][6]
        assert cfg['__scan_context'] == '' and '__scan_prune' not in cfg

    def test_rerun_carries_the_context(self, started):
        c, launched, app = started
        r = c.post('/api/startscan', data={'scanname': 'n', 'scantarget': 'Marcus Elias Thornwood', 'modulelist': 'sfp_dnsresolve',
                                           'context': 'employer: Acme', 'prune': '1'})
        sid = r.get_json()[1]
        d = h.db(app)
        d.scanContextSet(sid, 'employer: Acme', True)
        d.scanConfigSet(sid, {'_modulesenabled': 'sfp__stor_db,sfp_dnsresolve'})
        c.post('/api/rerunscan', data={'id': sid})
        assert launched[-1][6]['__scan_context'] == 'employer: Acme' and launched[-1][6]['__scan_prune'] is True


class TestSettings:
    def test_keys_never_come_back(self, plain):
        app, c = plain
        r = c.post('/api/savesettings', data={'allopts': json.dumps({'_rel_embeddings_apikey': 'sk-rel-SECRET-999', '_rel_embeddings_url': 'http://emb.test/v1'})})
        assert r.get_json()[0] == 'SUCCESS'
        assert app.config['SF_CONFIG']['_rel_embeddings_apikey'] == 'sk-rel-SECRET-999'
        for url in ('/api/optsraw', '/frag/settings-section?section=relevance'):
            assert 'sk-rel-SECRET-999' not in c.get(url).get_data(as_text=True), url
        assert 'sk-rel-SECRET-999' not in c.get('/api/optsexport').get_data(as_text=True)
        # the masked placeholder keeps the stored key
        c.post('/api/savesettings', data={'allopts': json.dumps({'_rel_embeddings_apikey': '********', '_rel_embed_mid': '55'})})
        assert app.config['SF_CONFIG']['_rel_embeddings_apikey'] == 'sk-rel-SECRET-999' and app.config['SF_CONFIG']['_rel_embed_mid'] == 55

    @pytest.mark.parametrize('bad', [{'_rel_t_unrelated': 'lots'}, {'_rel_t_likely': '5', '_rel_t_unrelated': '50'}, {'_rel_embeddings_url': 'file:///etc/passwd'}])
    def test_invalid_values_are_refused(self, plain, bad):
        app, c = plain
        r = c.post('/api/savesettings', data={'allopts': json.dumps(bad)})
        assert r.get_json()[0] == 'ERROR'
        assert app.config['SF_CONFIG']['_rel_t_unrelated'] == 25

    def test_settings_section_renders_for_admins_only(self, world):
        app, users = world
        assert as_user(app, users, 'root').get('/frag/settings-section?section=relevance').status_code == 200
        assert as_user(app, users, 'olivia').get('/frag/settings-section?section=relevance').status_code == 403

    def test_pair_test_endpoint_without_endpoints(self, plain):
        _, c = plain
        r = c.post('/api/relevance/test', json={'target': 'Nicholas Thomas Thornwood', 'context': 'location: Massachusetts',
                                                'candidate': 'Nicholas Andrew Thornwood, MD, Missouri'})
        out = r.get_json()
        assert out['ok'] and out['final']['label'] == 'unrelated' and out['signals'][0]['stage'] == 'heuristics'

    def test_new_scan_page_has_the_hints_section(self, plain):
        _, c = plain
        page = c.get('/newscan').get_data(as_text=True)
        assert 'data-relevance-hints' in page and 'Help narrow the results' in page and 'Prune unrelated matches' in page


class TestRoutePolicyEntries:
    def test_levels(self):
        from spiderfoot.services import route_policy as rp
        assert rp.POLICIES['relevance.status'].level == 'view' and rp.POLICIES['frag.relevance_card'].level == 'view'
        assert rp.POLICIES['relevance.assess'].level == 'edit' and rp.POLICIES['relevance.mark'].level == 'edit'
        assert rp.POLICIES['relevance.test'].kind == 'admin'

    def test_every_relevance_route_is_listed(self, plain):
        from spiderfoot.services import route_policy as rp
        app, _ = plain
        endpoints = {r.endpoint for r in app.url_map.iter_rules() if r.endpoint.startswith('relevance.')}
        assert endpoints == {'relevance.status', 'relevance.assess', 'relevance.mark', 'relevance.test'}
        assert all(rp.table_policy(e) is not None for e in endpoints)


class TestBackgroundJob:
    def test_a_second_start_while_running_is_refused(self, plain):
        import threading
        app, _ = plain
        gate = threading.Event()
        with mock.patch.object(job, 'assess_scan', side_effect=lambda *a, **k: gate.wait(5)):
            cfg = app.config['SF_CONFIG']
            assert job.start_job(cfg, SCAN) is True
            assert job.is_running(SCAN) and job.start_job(cfg, SCAN) is False
            assert h.db(app).relevanceRunGet(SCAN)['status'] == 'queued'
            gate.set()
            for _ in range(50):
                if not job.is_running(SCAN):
                    break
                __import__('time').sleep(0.05)
        assert not job.is_running(SCAN)
