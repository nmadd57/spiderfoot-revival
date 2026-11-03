"""MCP: get_scan_report, generate_scan_report and the report fields of get_scan / create_scan, with the usual access rules."""
from unittest import mock

import pytest

from spiderfoot.mcp import tools
from spiderfoot.services import report_job as rj
from test.unit.services import report_helpers as rh
from test.unit.services.conftest import OTHER_SECRET, SECRET
from test.unit.services.test_mcp_identity import call_as, owned_scan


def write_report(env, scan_id, llm=None):
    cfg = dict(env.app.config['SF_CONFIG'])
    cfg.update(rh.ai_config(__database=env.db_path))
    dbh = env.db()
    row, _ = rj.request_report(cfg, dbh, scan_id)
    return rj.generate(cfg, row['id'], dbh=dbh, llm=llm or rh.FakeLLM())


@pytest.fixture
def team(env):
    env.users = {n: env.make_user(n, ['sf-users']) for n in ('olivia', 'edith', 'vic', 'sam')}
    owned_scan(env, 'SCAN_A', env.users['olivia'])
    env.db().aclSet('SCAN_A', 'user', str(env.users['edith']['id']), 'edit')
    env.db().aclSet('SCAN_A', 'user', str(env.users['vic']['id']), 'view')
    env.tokens = {n: env.token_for(u['id']) for n, u in env.users.items()}
    return env


class TestReading:
    def test_no_report_yet(self, env):
        env.seed_scan('SCAN0001')
        err, out = env.call('get_scan_report', scan_id='SCAN0001')
        assert not err and out['status'] == 'none' and 'generate_scan_report' in out['note'] and 'markdown' not in out

    def test_a_finished_report(self, env):
        env.seed_scan('SCAN0001')
        write_report(env, 'SCAN0001')
        err, out = env.call('get_scan_report', scan_id='SCAN0001')
        assert not err and out['status'] == 'done' and out['version'] == 1 and out['mode'] == 'ai' and not out['truncated']
        assert out['markdown'].startswith('# Scan report: example.com') and '## Appendix A' in out['markdown'] and out['tokens'] > 0
        assert out['versions'] == [1] and out['partialScan'] is False

    def test_one_section(self, env):
        env.seed_scan('SCAN0001')
        write_report(env, 'SCAN0001')
        err, out = env.call('get_scan_report', scan_id='SCAN0001', section='risks')
        assert not err and out['markdown'].startswith('## Risks and notable items') and '## Recommended' not in out['markdown']
        err, out = env.call('get_scan_report', scan_id='SCAN0001', section='appendix')
        assert out['markdown'].startswith('## Appendix A')
        err, out = env.call('get_scan_report', scan_id='SCAN0001', section='bogus')
        assert err

    def test_long_reports_are_cut_with_an_indicator(self, env):
        env.seed_scan('SCAN0001')
        write_report(env, 'SCAN0001')
        with mock.patch.object(tools, 'REPORT_CHARS', 300):
            err, out = env.call('get_scan_report', scan_id='SCAN0001')
        assert not err and out['truncated'] is True and len(out['markdown']) == 300 and out['totalChars'] > 300 and 'section' in out['note']

    def test_in_progress_is_reported(self, env):
        env.seed_scan('SCAN0001')
        write_report(env, 'SCAN0001')
        rj.request_report(env.app.config['SF_CONFIG'], env.db(), 'SCAN0001')
        err, out = env.call('get_scan_report', scan_id='SCAN0001')
        assert out['status'] == 'done' and out['inProgress']['status'] == 'queued' and out['inProgress']['version'] == 2
        assert env.call('get_scan', scan_id='SCAN0001')[1]['report'] == {
            'status': 'queued', 'latestVersion': 1, 'inProgress': True, 'sectionsDone': 0, 'sectionsTotal': 0}

    def test_get_scan_without_a_report(self, env):
        env.seed_scan('SCAN0001')
        assert env.call('get_scan', scan_id='SCAN0001')[1]['report'] == {'status': 'none'}

    def test_unknown_scan(self, env):
        err, text = env.call('get_scan_report', scan_id='NOPE')
        assert err and 'does not exist' in text

    def test_secrets_never_appear(self, env):
        env.seed_scan('SCAN0001')
        write_report(env, 'SCAN0001', rh.FakeLLM(lambda p, m: f"The key {SECRET} and {OTHER_SECRET} were in the data [E1]."))
        for section in (None, 'appendix', 'summary'):
            args = {'section': section} if section else {}
            err, out = env.call('get_scan_report', scan_id='SCAN0001', **args)
            assert SECRET not in str(out) and OTHER_SECRET not in str(out)


class TestAccess:
    def test_view_reads_edit_generates(self, team):
        write_report(team, 'SCAN_A')
        for who in ('olivia', 'edith', 'vic'):
            err, out = call_as(team, who, 'get_scan_report', scan_id='SCAN_A')
            assert not err and out['status'] == 'done', who
        err, out = call_as(team, 'vic', 'generate_scan_report', scan_id='SCAN_A')
        assert err and 'not enough' in out
        err, out = call_as(team, 'edith', 'generate_scan_report', scan_id='SCAN_A')
        assert not err and out['status'] == 'queued' and out['started'] is True and out['version'] == 2

    def test_outsiders_do_not_see_the_scan(self, team):
        write_report(team, 'SCAN_A')
        for tool in ('get_scan_report', 'generate_scan_report'):
            err, text = call_as(team, 'sam', tool, scan_id='SCAN_A')
            assert err and 'does not exist' in text, tool

    def test_the_operator_can_forbid_it(self, env):
        env.seed_scan('SCAN0001')
        env.configure(allow_scan=0)
        err, text = env.call('generate_scan_report', scan_id='SCAN0001')
        assert err and 'not allowed' in text
        assert not env.call('get_scan_report', scan_id='SCAN0001')[0]        # reading stays possible


class TestGenerating:
    def test_returns_at_once_and_is_idempotent(self, env):
        env.seed_scan('SCAN0001')
        err, out = env.call('generate_scan_report', scan_id='SCAN0001')
        assert not err and out['status'] == 'queued' and out['started'] and 'get_scan_report' in out['next']
        err, again = env.call('generate_scan_report', scan_id='SCAN0001')
        assert not err and again['alreadyInProgress'] and again['version'] == out['version']
        assert len(env.db().reportList('SCAN0001')) == 1
        assert env.db().reportList('SCAN0001')[0]['trigger'] == 'mcp'

    def test_running_scan_and_unknown_model(self, env):
        env.seed_scan('SCAN0001', status='RUNNING')
        err, text = env.call('generate_scan_report', scan_id='SCAN0001')
        assert err and 'still running' in text
        env.seed_scan('SCAN0002')
        err, text = env.call('generate_scan_report', scan_id='SCAN0002', model='something-else')
        assert err and 'not one of the models' in text

    def test_create_scan_takes_report(self, env):
        captured = {}
        from spiderfoot.blueprints import api
        real = api.start_scan_core

        def spy(*a, **kw):
            captured.update(kw)
            return real(*a, **kw)
        with mock.patch.object(api, 'start_scan_core', side_effect=spy):
            err, out = env.call('create_scan', target='example.com', modules=['sfp_crt'], report=True)
        assert not err, out
        assert captured['report'] is True
        with mock.patch.object(api, 'start_scan_core', side_effect=spy):
            env.call('create_scan', target='example.org', modules=['sfp_crt'])
        assert captured['report'] is None
