"""Reports through the web layer: routes, CSRF, the route policy, the access matrix, exports, sanitising, settings, start parameters."""
import base64
import json
import types
from unittest import mock

import pytest

from spiderfoot import SpiderFootDb
from spiderfoot.blueprints import api
from spiderfoot.services import report_job as rj
from test.unit import identity_helpers as h
from test.unit.services import report_helpers as rh
from test.unit.services.conftest import fake_modules

SCAN = 'INF00001'


def make(tmp_path, owner=None, generate=True, **cfg):
    app = h.make_app(tmp_path, modules=fake_modules(), **rh.ai_config(**cfg))
    dbh = h.db(app)
    rh.seed_infra(app.config['SF_CONFIG'], SCAN, owner=owner, dbh=dbh)
    if generate:
        row, _ = rj.request_report(app.config['SF_CONFIG'], dbh, SCAN)
        rj.generate(app.config['SF_CONFIG'], row['id'], dbh=dbh, llm=rh.FakeLLM())
    return app, dbh


@pytest.fixture
def plain(tmp_path):
    app, dbh = make(tmp_path)
    c = app.test_client()
    c.environ_base['HTTP_AUTHORIZATION'] = 'Basic ' + base64.b64encode(b'x:x').decode()
    return app, c, dbh


@pytest.fixture
def world(tmp_path):
    app = h.make_app(tmp_path, modules=fake_modules(), **rh.ai_config())
    h.configure_sso(app)
    users = {n: h.add_user(app, n, g) for n, g in (('root', ['sf-admins']), ('olivia', ['sf-users']), ('edith', ['sf-users']),
                                                   ('vic', ['sf-users']), ('sam', ['sf-users']))}
    dbh = h.db(app)
    rh.seed_infra(app.config['SF_CONFIG'], SCAN, owner=users['olivia']['id'], dbh=dbh)
    row, _ = rj.request_report(app.config['SF_CONFIG'], dbh, SCAN)
    rj.generate(app.config['SF_CONFIG'], row['id'], dbh=dbh, llm=rh.FakeLLM())
    dbh.aclSet(SCAN, 'user', str(users['edith']['id']), 'edit')
    dbh.aclSet(SCAN, 'user', str(users['vic']['id']), 'view')
    return app, users


def as_user(app, users, name):
    return h.sign_in(app.test_client(), users[name])


class TestRoutePolicy:
    def test_every_report_route_is_in_the_table(self, plain):
        from spiderfoot.services import route_policy
        app, _, _ = plain
        names = {r.endpoint for r in app.url_map.iter_rules() if r.endpoint.startswith(('report.', 'report_frag.'))}
        assert names == {'report.status', 'report.generate', 'report.delete', 'report.export', 'report_frag.view'}
        for n in names:
            assert route_policy.table_policy(n) is not None, n

    def test_levels(self):
        from spiderfoot.services import route_policy as rp
        for ep, level in (('report.status', 'view'), ('report.export', 'view'), ('report_frag.view', 'view'),
                          ('report.generate', 'edit'), ('report.delete', 'edit')):
            p = rp.table_policy(ep)
            assert p.kind == 'scan' and p.level == level and p.arg == 'id', ep


class TestAccessMatrix:
    @pytest.mark.parametrize('who,status', [('olivia', 200), ('edith', 200), ('vic', 200), ('sam', 404), ('root', 200)])
    def test_reading_needs_view(self, world, who, status):
        app, users = world
        c = as_user(app, users, who)
        assert c.get(f'/api/report/status?id={SCAN}').status_code == status
        assert c.get(f'/frag/report?id={SCAN}').status_code == status
        for fmt in ('md', 'html', 'json'):
            assert c.get(f'/api/report/export?id={SCAN}&format={fmt}').status_code == status

    @pytest.mark.parametrize('who,status', [('olivia', 202), ('edith', 202), ('vic', 403), ('sam', 404), ('root', 202)])
    def test_generating_needs_edit(self, world, who, status):
        app, users = world
        c = as_user(app, users, who)
        r = c.post('/api/report/generate', data={'id': SCAN})
        assert r.status_code == status, r.get_data(as_text=True)
        # a second request while one is queued answers 200 (already in progress)
        if status == 202:
            assert c.post('/api/report/generate', data={'id': SCAN}).status_code == 200

    @pytest.mark.parametrize('who,status', [('olivia', 200), ('edith', 200), ('vic', 403), ('sam', 404)])
    def test_deleting_a_version_needs_edit(self, world, who, status):
        app, users = world
        assert as_user(app, users, who).post('/api/report/delete', data={'id': SCAN, 'version': '1'}).status_code == status

    def test_a_viewer_sees_the_report_but_not_the_buttons(self, world):
        app, users = world
        viewer = as_user(app, users, 'vic').get(f'/frag/report?id={SCAN}').get_data(as_text=True)
        editor = as_user(app, users, 'edith').get(f'/frag/report?id={SCAN}').get_data(as_text=True)
        assert 'Executive summary' in viewer and 'Generate report' not in viewer and 'Regenerate report' not in viewer and 'Delete v1' not in viewer
        assert 'Regenerate report' in editor and 'Delete v1' in editor

    def test_the_refusals_are_not_json_in_the_fragment(self, world):
        app, users = world
        r = as_user(app, users, 'sam').get(f'/frag/report?id={SCAN}')
        assert r.status_code == 404 and r.mimetype == 'text/html'

    def test_csrf_is_required_for_writes(self, world):
        app, users = world
        c = as_user(app, users, 'olivia')
        c.environ_base.pop('HTTP_X_CSRF_TOKEN')
        assert c.post('/api/report/generate', data={'id': SCAN}).status_code == 403
        assert c.post('/api/report/delete', data={'id': SCAN, 'version': '1'}).status_code == 403
        assert c.get(f'/api/report/status?id={SCAN}').status_code == 200


class TestRoutes:
    def test_status(self, plain):
        _, c, _ = plain
        s = c.get(f'/api/report/status?id={SCAN}').get_json()
        assert s['latest']['version'] == 1 and s['latest']['mode'] == 'ai' and not s['running'] and s['aiReady'] is True
        assert 'markdown' not in json.dumps(s)

    def test_generate_queues_a_new_version(self, plain):
        app, c, dbh = plain
        r = c.post('/api/report/generate', data={'id': SCAN, 'model': 'backup'})
        assert r.status_code == 202 and r.get_json()['report']['version'] == 2
        row = dbh.reportList(SCAN)[0]
        assert row['status'] == 'queued' and row['model'] == 'backup' and row['trigger'] == 'manual'
        s = c.get(f'/api/report/status?id={SCAN}').get_json()
        assert s['running'] and s['active']['version'] == 2 and s['latest']['version'] == 1

    def test_unknown_model_and_running_scan(self, plain):
        app, c, dbh = plain
        assert c.post('/api/report/generate', data={'id': SCAN, 'model': 'gpt-expensive'}).status_code == 400
        dbh.scanInstanceSet(SCAN, status='RUNNING')
        r = c.post('/api/report/generate', data={'id': SCAN})
        assert r.status_code == 409 and 'still running' in r.get_json()['error']['message']

    def test_delete(self, plain):
        _, c, dbh = plain
        assert c.post('/api/report/delete', data={'id': SCAN}).status_code == 400
        assert c.post('/api/report/delete', data={'id': SCAN, 'version': '7'}).status_code == 404
        assert c.post('/api/report/delete', data={'id': SCAN, 'version': '1'}).status_code == 200
        assert dbh.reportList(SCAN) == []

    def test_tab_states(self, plain):
        app, c, dbh = plain
        body = c.get(f'/frag/report?id={SCAN}').get_data(as_text=True)
        assert 'id="report-body"' in body and 'AI-generated' in body and 'aria-label="Report contents"' in body
        assert '/api/report/export?id=INF00001&v=1&format=md' in body and 'Print / save as PDF' in body
        c.post('/api/report/generate', data={'id': SCAN})
        queued = c.get(f'/frag/report?id={SCAN}').get_data(as_text=True)
        assert 'Writing report v2' in queued and 'hx-trigger="every 3s"' in queued
        part = c.get(f'/frag/report?id={SCAN}&part=progress')
        assert part.status_code == 200 and 'Writing report v2' in part.get_data(as_text=True)
        dbh.reportUpdate(dbh.reportList(SCAN)[0]['id'], status='failed', message='boom')
        done = c.get(f'/frag/report?id={SCAN}&part=progress')
        assert done.get_data(as_text=True) == '' and done.headers['HX-Trigger'] == 'sf-report-changed'
        assert 'could not be written: boom' in c.get(f'/frag/report?id={SCAN}').get_data(as_text=True)

    def test_empty_state_and_version_picker(self, tmp_path):
        app, dbh = make(tmp_path, generate=False)
        c = app.test_client()
        c.environ_base['HTTP_AUTHORIZATION'] = 'Basic ' + base64.b64encode(b'x:x').decode()
        assert 'No report has been written' in c.get(f'/frag/report?id={SCAN}').get_data(as_text=True)
        cfg = app.config['SF_CONFIG']
        for _ in range(2):
            row, _created = rj.request_report(cfg, dbh, SCAN)
            rj.generate(cfg, row['id'], dbh=dbh, llm=rh.FakeLLM())
        body = c.get(f'/frag/report?id={SCAN}&v=1').get_data(as_text=True)
        assert 'id="report-version"' in body and body.count('<option value="') >= 2
        assert 'v1' in body and c.get(f'/frag/report?id={SCAN}&v=2').status_code == 200

    def test_no_ai_configured_is_explained(self, tmp_path):
        app, dbh = make(tmp_path, generate=False, _ai_enabled=False)
        c = app.test_client()
        c.environ_base['HTTP_AUTHORIZATION'] = 'Basic ' + base64.b64encode(b'x:x').decode()
        assert 'figures and lists only' in c.get(f'/frag/report?id={SCAN}').get_data(as_text=True)
        r = c.post('/api/report/generate', data={'id': SCAN})
        assert r.status_code == 202 and r.get_json()['aiReady'] is False


class TestExports:
    def test_markdown(self, plain):
        _, c, _ = plain
        r = c.get(f'/api/report/export?id={SCAN}&format=md')
        assert r.status_code == 200 and r.mimetype == 'text/markdown'
        assert 'attachment; filename="spiderfoot-report-INF00001-v1.md"' in r.headers['Content-Disposition']
        text = r.get_data(as_text=True)
        assert text.startswith('# Scan report: example.test') and '## Executive summary' in text and '## Appendix A' in text
        assert '](http://localhost/scaninfo?id=INF00001' in text

    def test_html_is_self_contained_and_escapes_event_data(self, plain):
        _, c, _ = plain
        r = c.get(f'/api/report/export?id={SCAN}&format=html')
        body = r.get_data(as_text=True)
        assert r.mimetype == 'text/html' and body.startswith('<!doctype html>')
        assert '<script' not in body and 'alert(1)' not in body.replace('&lt;script&gt;alert(1)&lt;/script&gt;', '')
        assert "default-src 'none'" in r.headers['Content-Security-Policy'] and r.headers['X-Content-Type-Options'] == 'nosniff'
        assert '@media print' in body and '<link' not in body
        inline = c.get(f'/api/report/export?id={SCAN}&format=html&inline=1')
        assert inline.headers['Content-Disposition'].startswith('inline')

    def test_the_tab_escapes_event_data_too(self, plain):
        _, c, dbh = plain
        # the hostile URL is in the cited findings; make sure it is cited by pointing a section at it
        row, _created = rj.request_report(plain[0].config['SF_CONFIG'], dbh, SCAN)
        rj.generate(plain[0].config['SF_CONFIG'], row['id'], dbh=dbh,
                    llm=rh.FakeLLM(lambda p, m: "Seen: " + ' '.join(f'[{i}]' for i in rh.offered_ids(p))))
        md = dbh.reportGet(SCAN)['markdown']
        assert 'other.test' in md and '&lt;' not in md.split('other.test', 1)[1][:5]      # the hostile URL is cited in the appendix, as text
        body = c.get(f'/frag/report?id={SCAN}').get_data(as_text=True)
        assert '<script>alert' not in body and '<script' not in body.split('id="report-body"', 1)[1].split('</article>')[0]

    def test_json_has_digests_and_citations(self, plain):
        _, c, _ = plain
        r = c.get(f'/api/report/export?id={SCAN}&format=json')
        data = r.get_json()
        assert r.mimetype == 'application/json' and data['version'] == 1 and data['digests']['scan']['target'] == 'example.test'
        assert data['citations']['events'] and data['usage']['calls'] > 0 and data['markdown'].startswith('# Scan report')
        assert set(data['sections']) >= {'summary', 'identity', 'next'}

    def test_versions_and_bad_requests(self, plain):
        app, c, dbh = plain
        assert c.get(f'/api/report/export?id={SCAN}&format=pdf').status_code == 400
        assert c.get(f'/api/report/export?id={SCAN}&format=md&v=9').status_code == 404
        c.post('/api/report/generate', data={'id': SCAN})
        assert c.get(f'/api/report/export?id={SCAN}&format=md').status_code == 200       # the queued version is not exported
        assert c.get(f'/api/report/export?id={SCAN}&format=md&v=2').status_code == 404

    def test_no_secret_in_any_export(self, tmp_path):
        secret = 'sk-live-HTTP-LEAK-1234567890abcdef'
        app = h.make_app(tmp_path, modules=fake_modules(), **rh.ai_config())
        app.config['SF_CONFIG']['__modules__'] = {'sfp_shodan': {'opts': {'api_key': secret}}}
        dbh = h.db(app)
        rh.seed_infra(app.config['SF_CONFIG'], SCAN, secret_in_event=secret, dbh=dbh)
        row, _ = rj.request_report(app.config['SF_CONFIG'], dbh, SCAN)
        rj.generate(app.config['SF_CONFIG'], row['id'], dbh=dbh, llm=rh.FakeLLM(lambda p, m: f"key {secret} " + ' '.join(f'[{i}]' for i in rh.offered_ids(p))))
        c = app.test_client()
        c.environ_base['HTTP_AUTHORIZATION'] = 'Basic ' + base64.b64encode(b'x:x').decode()
        for url in (f'/api/report/export?id={SCAN}&format={f}' for f in ('md', 'html', 'json')):
            body = c.get(url).get_data(as_text=True)
            assert secret not in body and rh.FAKE_KEY not in body, url
        assert secret not in c.get(f'/frag/report?id={SCAN}').get_data(as_text=True)
        assert rh.FAKE_KEY not in c.get(f'/api/report/status?id={SCAN}').get_data(as_text=True)


class TestPagesAndLists:
    def test_scan_page_has_the_tab_and_the_badge(self, plain):
        _, c, _ = plain
        page = c.get(f'/scaninfo?id={SCAN}').get_data(as_text=True)
        assert 'data-tab="report"' in page and 'Report ready' in page and 'js/report.js' in page

    def test_no_badge_without_a_report(self, tmp_path):
        app, _ = make(tmp_path, generate=False)
        c = app.test_client()
        c.environ_base['HTTP_AUTHORIZATION'] = 'Basic ' + base64.b64encode(b'x:x').decode()
        page = c.get(f'/scaninfo?id={SCAN}').get_data(as_text=True)
        assert 'data-tab="report"' in page and 'Report ready' not in page

    def test_scan_list_badge(self, plain):
        _, c, _ = plain
        assert 'Report ready' in c.get('/frag/scan-table').get_data(as_text=True)

    def test_data_tab_can_be_opened_on_a_finding(self, plain):
        _, c, _ = plain
        body = c.get(f'/frag/results-tab?id={SCAN}&tab=data&init_q=www.example.test&init_type=INTERNET_NAME').get_data(as_text=True)
        assert 'value="www.example.test"' in body and 'value="INTERNET_NAME" selected' in body
        evil = c.get(f'/frag/results-tab?id={SCAN}&tab=data&init_q=%22%3E%3Cscript%3E').get_data(as_text=True)
        assert '"><script>' not in evil

    def test_new_scan_checkbox(self, plain):
        _, c, _ = plain
        page = c.get('/newscan').get_data(as_text=True)
        assert 'data-report-option' in page and 'Write a report when finished' in page and 'reportDefault = true' in page

    def test_new_scan_default_off_without_ai(self, tmp_path):
        app = h.make_app(tmp_path, modules=fake_modules(), **rh.ai_config(_ai_enabled=False))
        c = app.test_client()
        c.environ_base['HTTP_AUTHORIZATION'] = 'Basic ' + base64.b64encode(b'x:x').decode()
        page = c.get('/newscan').get_data(as_text=True)
        assert 'reportDefault = false' in page and 'figures and lists only' in page


class TestStartParameter:
    @pytest.fixture
    def started(self, tmp_path):
        app = h.make_app(tmp_path, modules=fake_modules(), **rh.ai_config())
        launched = []

        def process(target=None, args=None, **kw):
            class Proc:
                daemon = False

                def start(self):
                    launched.append(args)
                    d = SpiderFootDb(args[6])
                    d.scanInstanceCreate(args[2], args[1], args[3])
                    d.scanInstanceSet(args[2], status='RUNNING')
            return Proc()
        with mock.patch.object(api, 'mp', types.SimpleNamespace(Process=process)):
            c = app.test_client()
            c.environ_base['HTTP_AUTHORIZATION'] = 'Basic ' + base64.b64encode(b'x:x').decode()
            yield c, launched, app

    @pytest.mark.parametrize('value,expect', [('1', True), ('0', False), ('true', True), ('no', False)])
    def test_report_reaches_the_scan(self, started, value, expect):
        c, launched, _ = started
        c.post('/api/startscan', data={'scanname': 'n', 'scantarget': 'example.com', 'modulelist': 'sfp_dnsresolve', 'report': value})
        assert launched[-1][6]['__scan_report'] is expect

    def test_omitted_means_the_settings_decide(self, started):
        c, launched, _ = started
        c.post('/api/startscan', data={'scanname': 'n', 'scantarget': 'example.com', 'modulelist': 'sfp_dnsresolve'})
        assert '__scan_report' not in launched[-1][6]

    def test_rerun_keeps_the_choice(self, started):
        c, launched, app = started
        sid = c.post('/api/startscan', data={'scanname': 'n', 'scantarget': 'example.com', 'modulelist': 'sfp_dnsresolve', 'report': '0'}).get_json()[1]
        d = h.db(app)
        d.reportPrefSet(sid, False)
        d.scanConfigSet(sid, {'_modulesenabled': 'sfp__stor_db,sfp_dnsresolve'})
        c.post('/api/rerunscan', data={'id': sid})
        assert launched[-1][6]['__scan_report'] is False

    def test_the_scanner_records_the_preference(self):
        import inspect
        import sfscan
        src = inspect.getsource(sfscan.SpiderFootScanner)
        assert "reportPrefSet(self.__scanId, bool(self.__config['__scan_report']))" in src and 'self.queueReport()' in src


class TestSettings:
    def test_save_and_read_back(self, plain):
        app, c, _ = plain
        r = c.post('/api/savesettings', data={'allopts': json.dumps({'_report_max_calls': '12', '_report_auto': '0', '_report_sections': 'summary,next'})})
        assert r.get_json()[0] == 'SUCCESS'
        cfg = app.config['SF_CONFIG']
        assert cfg['_report_max_calls'] == 12 and cfg['_report_auto'] in (False, '0', 0) and cfg['_report_sections'] == 'summary,next'

    @pytest.mark.parametrize('bad', [{'_report_max_calls': '0'}, {'_report_sections': 'nope'}, {'_report_concurrency': '9'}, {'_report_auto': 'maybe'}])
    def test_invalid_values_are_refused(self, plain, bad):
        app, c, _ = plain
        assert c.post('/api/savesettings', data={'allopts': json.dumps(bad)}).get_json()[0] == 'ERROR'
        assert app.config['SF_CONFIG']['_report_max_calls'] == 24

    def test_settings_section_is_for_administrators(self, world):
        app, users = world
        r = as_user(app, users, 'root').get('/frag/settings-section?section=reports')
        assert r.status_code == 200 and 'Write a report when a scan finishes' in r.get_data(as_text=True)
        assert as_user(app, users, 'olivia').get('/frag/settings-section?section=reports').status_code == 403
        assert as_user(app, users, 'olivia').post('/api/savesettings', data={'allopts': '{"_report_auto": "0"}'}).status_code == 403

    def test_the_settings_page_lists_the_section(self, plain):
        _, c, _ = plain
        assert 'hx-get="/frag/settings-section?section=reports"' in c.get('/opts').get_data(as_text=True)

    def test_the_section_never_shows_a_key(self, plain):
        _, c, _ = plain
        assert rh.FAKE_KEY not in c.get('/frag/settings-section?section=reports').get_data(as_text=True)
