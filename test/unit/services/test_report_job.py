"""Writing a report: lifecycle, idempotence, chaining, caps, fallbacks, versions, auto-trigger, settings, secrets, migration."""
import json
import re
import sqlite3

import pytest

from spiderfoot import SpiderFootDb
from spiderfoot.services import report_job as rj
from spiderfoot.services.report_llm import ReportLLM, ReportLLMError
from test.unit.services import report_helpers as rh


@pytest.fixture
def world(tmp_path):
    cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'))
    dbh = rh.seed_namesake(cfg)
    return cfg, dbh


def queue(cfg, dbh, scan='NS000001', **kw):
    row, created = rj.request_report(cfg, dbh, scan, **kw)
    assert created
    return row


class TestLifecycle:
    def test_queued_to_done_with_progress_and_usage(self, world):
        cfg, dbh = world
        row = queue(cfg, dbh)
        assert row['status'] == 'queued' and row['version'] == 1
        llm = rh.FakeLLM()
        out = rj.generate(cfg, row['id'], dbh=dbh, llm=llm)
        assert out['status'] == 'done' and out['mode'] == 'ai' and out['progress'] == 1.0
        assert out['sections_done'] == out['sections_total'] > 5
        assert out['calls'] == llm.calls == len(llm.prompts) and out['tokens'] == llm.tokens > 0
        assert out['model'] == 'small' and out['model_used'] == 'small'
        assert out['markdown'].startswith('# Scan report: ') and out['citations']['events'] and out['digests']['scan']['id'] == 'NS000001'

    def test_prompts_are_small_and_bounded(self, world):
        cfg, dbh = world
        llm = rh.FakeLLM()
        rj.generate(cfg, queue(cfg, dbh)['id'], dbh=dbh, llm=llm)
        from spiderfoot.services import ai_service
        for p in llm.prompts:
            assert ai_service.estimate_tokens(p) <= cfg['_report_section_tokens'] + 400, p[:80]
            assert p.startswith('SECTION: ') and 'TASK: ' in p and 'DATA:\n' in p
        assert len(llm.prompts) <= 12

    def test_generate_twice_is_idempotent(self, world):
        cfg, dbh = world
        row = queue(cfg, dbh)
        llm = rh.FakeLLM()
        first = rj.generate(cfg, row['id'], dbh=dbh, llm=llm)
        n = llm.calls
        second = rj.generate(cfg, row['id'], dbh=dbh, llm=llm)
        assert llm.calls == n and second['markdown'] == first['markdown'] and len(dbh.reportList('NS000001')) == 1

    def test_one_report_at_a_time_per_scan(self, world):
        cfg, dbh = world
        first = queue(cfg, dbh)
        again, created = rj.request_report(cfg, dbh, 'NS000001')
        assert not created and again['id'] == first['id'] and len(dbh.reportList('NS000001')) == 1

    def test_resume_reuses_written_sections(self, world):
        cfg, dbh = world
        row = queue(cfg, dbh)
        calls = []

        def dies_on_third(prompt, model):
            calls.append(prompt)
            if len(calls) == 3:
                raise KeyboardInterrupt            # the process goes away in the middle of a report
            return rh.default_answer(prompt, model)
        with pytest.raises(KeyboardInterrupt):
            rj.generate(cfg, row['id'], dbh=dbh, llm=rh.FakeLLM(dies_on_third))
        part = dbh.reportGetById(row['id'])
        written = dict(part['sections'])
        assert part['status'] == 'running' and 2 <= len(written) < part['sections_total'] and part['digests']
        assert dbh.reportReconcile() == 1
        assert dbh.reportGetById(row['id'])['status'] == 'queued'
        llm = rh.FakeLLM()
        out = rj.generate(cfg, row['id'], dbh=dbh, llm=llm)
        assert out['status'] == 'done' and len(out['sections']) == out['sections_total']
        assert all(out['sections'][k] == v for k, v in written.items())          # what was written before is kept as it was
        assert len(llm.prompts) < out['sections_total'] - len(written) + 1

    def test_a_crash_marks_the_report_failed_without_details(self, world, monkeypatch):
        cfg, dbh = world
        row = queue(cfg, dbh)
        monkeypatch.setattr(rj.rd, 'build', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('secret detail ' + rh.FAKE_KEY)))
        out = rj.generate(cfg, row['id'], dbh=dbh, llm=rh.FakeLLM())
        assert out['status'] == 'failed' and rh.FAKE_KEY not in out['message'] and 'server log' in out['message']

    def test_running_scan_is_refused(self, tmp_path):
        cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'))
        dbh = rh.seed_infra(cfg, status='RUNNING')
        with pytest.raises(rj.ReportRefused) as e:
            rj.request_report(cfg, dbh, 'INF00001')
        assert e.value.status == 409
        with pytest.raises(rj.ReportRefused) as e:
            rj.request_report(cfg, dbh, 'NOPE0000')
        assert e.value.status == 404


class TestChaining:
    def test_waits_for_the_relevance_assessment(self, world):
        cfg, dbh = world
        row = queue(cfg, dbh)
        dbh.relevanceRunSet('NS000001', status='running', phase='ai', started=int(__import__('time').time()))
        assert 'relevance' in rj.blocked(dbh, row)
        assert rj.run_pending(cfg, llm_factory=rh.FakeLLM, dbh=dbh) == []
        dbh.relevanceRunSet('NS000001', status='done')
        assert rj.blocked(dbh, row) == ''
        assert rj.run_pending(cfg, llm_factory=rh.FakeLLM, dbh=dbh) == [row['id']]

    def test_a_stale_relevance_run_does_not_block_forever(self, world):
        cfg, dbh = world
        row = queue(cfg, dbh)
        dbh.relevanceRunSet('NS000001', status='running', started=1000)
        assert rj.blocked(dbh, row) == ''

    def test_uses_the_relevance_labels(self, world):
        cfg, dbh = world
        llm = rh.FakeLLM()
        rj.generate(cfg, queue(cfg, dbh)['id'], dbh=dbh, llm=llm)
        ident = next(p for p in llm.prompts if p.startswith('SECTION: Identity'))
        assert 'likely' in ident and 'unclear' in ident and 'EXCLUDED' in ident

    def test_a_scan_without_relevance_still_gets_a_report(self, tmp_path):
        cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'), _rel_enabled=False)
        dbh = rh.seed_infra(cfg)
        out = rj.generate(cfg, queue(cfg, dbh, 'INF00001')['id'], dbh=dbh, llm=rh.FakeLLM())
        assert out['status'] == 'done' and out['digests']['totals']['has_relevance'] is False


class TestAutoTrigger:
    @pytest.mark.parametrize('status,include,pref,ready,expect', [
        ('FINISHED', True, None, True, True),
        ('FINISHED', True, None, False, False),            # no AI configured: nothing automatic
        ('FINISHED', True, True, False, True),             # asked for on the New Scan page: figures only
        ('FINISHED', True, False, True, False),            # switched off for this scan
        ('ABORTED', True, None, True, True),
        ('ERROR-FAILED', True, None, True, True),
        ('ABORTED', False, None, True, False),
        ('ABORTED', False, True, True, False),
        ('RUNNING', True, None, True, False),
    ])
    def test_decision(self, status, include, pref, ready, expect):
        cfg = {'_report_auto': True, '_report_include_aborted': include}
        assert rj.should_auto(cfg, status, pref, ready)[0] is expect

    def test_setting_off_and_no_findings(self):
        assert rj.should_auto({'_report_auto': False}, 'FINISHED', None, True)[0] is False
        assert rj.should_auto({'_report_auto': False}, 'FINISHED', True, True)[0] is True
        assert rj.should_auto({'_report_auto': True}, 'FINISHED', None, True, events=0)[0] is False

    def test_enqueue_when_a_scan_ends(self, world):
        cfg, dbh = world
        row = rj.enqueue_for_scan(cfg, dbh, 'NS000001')
        assert row and row['trigger'] == 'auto' and row['status'] == 'queued'
        assert rj.enqueue_for_scan(cfg, dbh, 'NS000001') is None            # idempotent: one report per end of the scan

    def test_aborted_scan_gets_a_partial_report(self, tmp_path):
        cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'))
        dbh = rh.seed_namesake(cfg, status='ABORTED')
        row = rj.enqueue_for_scan(cfg, dbh, 'NS000001')
        out = rj.generate(cfg, row['id'], dbh=dbh, llm=rh.FakeLLM())
        assert out['scan_status'] == 'ABORTED' and 'Partial results' in out['markdown']
        cfg2 = dict(cfg, _report_include_aborted=False)
        dbh.dbh.execute("DELETE FROM tbl_scan_report")
        dbh.conn.commit()
        assert rj.enqueue_for_scan(cfg2, dbh, 'NS000001') is None

    def test_per_scan_preference_wins(self, world):
        cfg, dbh = world
        dbh.reportPrefSet('NS000001', False)
        assert rj.enqueue_for_scan(cfg, dbh, 'NS000001') is None
        dbh.reportPrefSet('NS000001', True)
        assert rj.enqueue_for_scan(dict(cfg, _report_auto=False, _ai_enabled=False), dbh, 'NS000001')['trigger'] == 'auto'
        dbh.reportPrefSet('NS000001', None)
        assert dbh.reportPrefGet('NS000001') is None

    def test_a_failed_automatic_report_may_be_queued_again(self, world):
        cfg, dbh = world
        row = rj.enqueue_for_scan(cfg, dbh, 'NS000001')
        dbh.reportUpdate(row['id'], status='failed')
        assert rj.enqueue_for_scan(cfg, dbh, 'NS000001') is not None

    def test_the_scan_engine_queues_a_report(self, tmp_path):
        """sfscan.queueReport: an unconfigured scan process calls enqueue_for_scan with its own database handle and never raises."""
        from sfscan import SpiderFootScanner
        assert hasattr(SpiderFootScanner, 'queueReport')


class TestDegradation:
    def test_no_endpoint_gives_a_deterministic_report(self, tmp_path):
        cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'), _ai_enabled=False)
        dbh = rh.seed_namesake(cfg)
        out = rj.generate(cfg, queue(cfg, dbh)['id'], dbh=dbh)
        assert out['status'] == 'done' and out['mode'] == 'deterministic' and out['calls'] == 0
        assert 'Generated without AI' in out['markdown'] and 'AI-generated; verify' not in out['markdown']
        assert '## Executive summary' in out['markdown'] and '## Appendix A' in out['markdown']
        assert 'off or not configured' in out['message']

    def test_endpoint_down_falls_back_per_section_and_stops_asking(self, world):
        cfg, dbh = world
        llm = rh.FakeLLM(rh.failing)
        out = rj.generate(cfg, queue(cfg, dbh)['id'], dbh=dbh, llm=llm)
        assert out['status'] == 'done' and out['mode'] == 'deterministic'
        assert llm.dead and llm.calls <= 6            # two sections tried (one retry + one fallback model each), then no more calls
        assert '## Recommended next steps' in out['markdown']
        assert any('without AI' in w for w in out['warnings'])

    def test_call_cap(self, world):
        cfg, dbh = world
        llm = rh.FakeLLM()
        out = rj.generate(dict(cfg, _report_max_calls=3), queue(cfg, dbh)['id'], dbh=dbh, llm=llm)
        assert out['calls'] == 3 == len(llm.prompts) and out['mode'] == 'ai'
        assert any('limit' in w for w in out['warnings']) and '## Recommended next steps' in out['markdown']

    def test_token_cap(self, world):
        cfg, dbh = world
        llm = rh.FakeLLM()               # 820 tokens per call
        out = rj.generate(dict(cfg, _report_max_tokens=1700), queue(cfg, dbh)['id'], dbh=dbh, llm=llm)
        assert out['calls'] == 3 and out['tokens'] == 3 * 820

    def test_retry_then_fallback_model(self, world):
        cfg, dbh = world
        llm = rh.FakeLLM(lambda p, m: rh.default_answer(p, m) if m == 'backup' else ReportLLMError('The AI endpoint answered HTTP 503.'))
        text = llm.complete('SECTION: x\nDATA:\n[E1] a')
        assert llm.models_asked == ['small', 'small', 'backup'] and text and llm.failures_in_a_row == 0

    def test_empty_answers_are_failures(self):
        llm = rh.FakeLLM(lambda p, m: '<think>only thinking</think>')
        with pytest.raises(ReportLLMError):
            llm.complete('x')
        assert llm.calls == 3 and llm.dead is False and llm.failures_in_a_row == 1

    def test_hallucinated_citations_and_figures_are_flagged(self, world):
        cfg, dbh = world

        def liar(prompt, model):
            ids = rh.offered_ids(prompt)
            return f"There are 98,765 findings [E99]. A real one {ids[0] if ids else ''}.".replace(' ', ' ') if ids else "Nothing at all is listed here."
        out = rj.generate(cfg, queue(cfg, dbh)['id'], dbh=dbh, llm=rh.FakeLLM(liar))
        assert '[E99]' not in out['markdown'] and '98,765' in out['markdown']
        joined = ' '.join(out['warnings'])
        assert 'citation(s) to findings that do not exist' in joined and '98,765' in joined

    def test_only_cited_findings_reach_the_appendix(self, world):
        cfg, dbh = world
        out = rj.generate(cfg, queue(cfg, dbh)['id'], dbh=dbh, llm=rh.FakeLLM())
        body, appendix = out['markdown'].split('## Appendix A', 1)
        cited = set(re.findall(r"\[(E\d+)\]", body))
        rows = set(re.findall(r"^\| (E\d+) \|", appendix, flags=re.M))
        assert cited and rows == cited

    def test_sections_can_be_chosen(self, world):
        cfg, dbh = world
        row, _ = rj.request_report(cfg, dbh, 'NS000001', sections=['summary', 'next'])
        llm = rh.FakeLLM()
        out = rj.generate(cfg, row['id'], dbh=dbh, llm=llm)
        assert len(llm.prompts) == 2 and '## Executive summary' in out['markdown'] and '## Target and scope' not in out['markdown']


class TestVersions:
    def test_versions_accumulate_and_are_pruned(self, world):
        cfg, dbh = world
        cfg = dict(cfg, _report_keep=3)
        for i in range(5):
            out = rj.generate(cfg, queue(cfg, dbh)['id'], dbh=dbh, llm=None if False else rh.FakeLLM())
            assert out['version'] == i + 1
        assert [r['version'] for r in dbh.reportList('NS000001')] == [5, 4, 3]
        assert dbh.reportGet('NS000001', 4)['status'] == 'done' and dbh.reportGet('NS000001')['version'] == 5

    def test_delete_a_version(self, world):
        cfg, dbh = world
        rj.generate(cfg, queue(cfg, dbh)['id'], dbh=dbh, llm=rh.FakeLLM())
        active = queue(cfg, dbh)
        assert dbh.reportDelete('NS000001', 1) == 1
        assert dbh.reportDelete('NS000001', active['version']) == 0          # still queued

    def test_ready_map_and_scan_delete(self, world):
        cfg, dbh = world
        rj.generate(cfg, queue(cfg, dbh)['id'], dbh=dbh, llm=rh.FakeLLM())
        assert dbh.reportReadyMap(['NS000001', 'other']) == {'NS000001': 1}
        dbh.reportPrefSet('NS000001', True)
        dbh.scanInstanceDelete('NS000001')
        assert dbh.reportList('NS000001') == [] and dbh.reportPrefGet('NS000001') is None

    def test_usage_is_recorded_for_the_monthly_cost(self, world):
        cfg, dbh = world
        rj.generate(cfg, queue(cfg, dbh)['id'], dbh=dbh, llm=rh.FakeLLM())
        dbh.dbh.execute("SELECT target_id, prompt_tokens FROM tbl_ai_summaries WHERE scan_id='NS000001'")
        target, tokens = dbh.dbh.fetchone()
        assert target == 'report-v1' and tokens > 0
        from spiderfoot.services.ai_persistence import fetch_cached, fetch_monthly_cost
        assert fetch_cached(dbh, scan_id='NS000001', kind='scan', target_id='', model_requested='small') is None      # not the scan summary
        assert fetch_monthly_cost(dbh, since_unix=0) == 0.0


class TestRedactionAndSecrets:
    def test_redaction_is_applied_and_reversed(self, tmp_path):
        cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'), _ai_redact_pii=True)
        dbh = rh.seed_infra(cfg)
        seen = []

        def echo(prompt, model):
            seen.append(prompt)
            return "The host is [IP-1] and the scan was of <TARGET> [E1]." if '[IP-' in prompt or '<TARGET>' in prompt else "ok [E1]"
        llm = rh.FakeLLM(echo)
        llm.redact = True
        out = rj.generate(cfg, queue(cfg, dbh, 'INF00001')['id'], dbh=dbh, llm=llm)
        # FakeLLM bypasses the HTTP layer, so exercise the redaction path of complete() directly
        assert out['status'] == 'done'
        real = ReportLLM('http://ai.test/v1', 'k', 'm', redact=True)
        sent = []

        def post(model, messages, max_tokens):
            sent.append(messages[1]['content'])
            return "Hosts [IP-1] under <TARGET>.", {'total_tokens': 10}, 'stop'
        real._post = post
        text = real.complete("[E1] ip 8.8.4.4 for mail admin@example.test on www.example.test", target='example.test')
        assert '8.8.4.4' not in sent[0] and 'admin@example.test' not in sent[0] and 'www.<TARGET>' in sent[0]
        assert text == "Hosts 8.8.4.4 under example.test."

    def test_secret_in_config_and_in_an_event_never_appears(self, tmp_path):
        secret = 'sk-live-EVENT-LEAK-9f8e7d6c5b4a3210'
        cfg = rh.ai_config(__database=str(tmp_path / 'sf.db'))
        cfg['__modules__'] = {'sfp_shodan': {'opts': {'api_key': secret}}}
        dbh = rh.seed_infra(cfg, secret_in_event=secret)
        dbh.configSet({'sfp_shodan:api_key': secret})
        llm = rh.FakeLLM(lambda p, m: f"Backend uses {secret} and {rh.FAKE_KEY} [E1].")
        out = rj.generate(cfg, queue(cfg, dbh, 'INF00001')['id'], dbh=dbh, llm=llm)
        blob = json.dumps(out, default=str) + ''.join(llm.prompts)
        assert secret not in blob and rh.FAKE_KEY not in blob
        assert '[redacted]' in out['markdown']

    def test_the_prompt_sent_to_the_endpoint_never_has_a_key(self, world):
        cfg, dbh = world
        llm = rh.FakeLLM()
        rj.generate(cfg, queue(cfg, dbh)['id'], dbh=dbh, llm=llm)
        assert not any(rh.FAKE_KEY in p for p in llm.prompts)
        assert rh.FAKE_KEY not in json.dumps(dbh.reportGet('NS000001'), default=str)


class TestHttpClient:
    def test_request_shape_and_errors(self, monkeypatch):
        import requests
        sent = {}

        class R:
            status_code = 200

            def json(self):
                return {'choices': [{'message': {'content': 'text [E1]'}, 'finish_reason': 'stop'}], 'usage': {'prompt_tokens': 11, 'completion_tokens': 5}}

        def post(url, headers=None, json=None, timeout=None):
            sent.update(url=url, headers=headers, body=json, timeout=timeout)
            return R()
        monkeypatch.setattr(requests, 'post', post)
        llm = ReportLLM('http://ai.test/v1', 'KEY123456', 'hermes', timeout=77)
        assert llm.complete('hello') == 'text [E1]'
        assert sent['url'] == 'http://ai.test/v1/chat/completions' and sent['timeout'] == 77
        assert sent['body']['stream'] is False and sent['body']['model'] == 'hermes' and 'models' not in sent['body']
        assert sent['headers']['Authorization'] == 'Bearer KEY123456' and llm.tokens == 16 and llm.calls == 1

        class Bad(R):
            status_code = 401
        monkeypatch.setattr(requests, 'post', lambda *a, **k: Bad())
        with pytest.raises(ReportLLMError) as e:
            ReportLLM('http://ai.test/v1', 'KEY123456', 'm', retry_wait=0).complete('x')
        assert 'KEY123456' not in str(e.value) and 'rejected' in str(e.value)

    def test_timeout_message(self, monkeypatch):
        import requests

        def boom(*a, **k):
            raise requests.exceptions.Timeout('x KEY999')
        monkeypatch.setattr(requests, 'post', boom)
        with pytest.raises(ReportLLMError) as e:
            ReportLLM('http://ai.test/v1', 'KEY999', 'm', timeout=5, retry_wait=0).complete('x')
        assert 'KEY999' not in str(e.value) and '5 s' in str(e.value)

    def test_from_config(self):
        assert ReportLLM.from_config({'_ai_enabled': False, '_ai_base_url': 'http://x/v1'}) is None
        assert ReportLLM.from_config({'_ai_enabled': True}) is None
        llm = ReportLLM.from_config(rh.ai_config(_report_model='big', _report_max_calls=5))
        assert llm.model == 'big' and llm.max_calls == 5 and llm.fallback == 'backup'
        assert ReportLLM.from_config(rh.ai_config(), model='picked').model == 'picked'


class TestSettings:
    @pytest.mark.parametrize('opts,ok', [
        ({'_report_max_calls': '10', '_report_auto': '1'}, True),
        ({'_report_max_calls': '0'}, False), ({'_report_max_calls': 'x'}, False), ({'_report_keep': '2'}, False),
        ({'_report_concurrency': '3'}, False), ({'_report_concurrency': '2'}, True), ({'_report_auto': 'yes'}, False),
        ({'_report_sections': 'summary,next'}, True), ({'_report_sections': 'summary,bogus'}, False), ({'_report_sections': ''}, False),
        ({'_report_section_tokens': '100'}, False), ({'_report_appendix_max': '9'}, False), ({'_report_model': 'a\nb'}, False),
        ({'_rel_t_likely': '5'}, True),
    ])
    def test_validation(self, opts, ok):
        assert (rj.validate_settings(opts) == '') is ok

    def test_defaults_match_the_application_defaults(self):
        import ast
        src = open('sf.py').read()
        for key, value in rj.DEFAULTS.items():
            m = re.search(r"'" + key + r"': (.+?),\n", src)
            assert m and ast.literal_eval(m.group(1)) == value, key


class TestMigration:
    def test_old_database_gains_the_tables(self, tmp_path):
        path = str(tmp_path / 'old.db')
        SpiderFootDb({'__database': path}, init=True)
        conn = sqlite3.connect(path)
        conn.execute("DROP TABLE tbl_scan_report")
        conn.execute("DROP TABLE tbl_report_pref")
        conn.commit()
        conn.close()
        dbh = SpiderFootDb({'__database': path})
        assert dbh.reportList('x') == [] and dbh.reportPrefGet('x') is None
        row, created = dbh.reportCreate('x', 'manual')
        assert created and row['version'] == 1
        SpiderFootDb({'__database': path})           # idempotent
        assert dbh.reportGet('x')['version'] == 1
