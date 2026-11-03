"""Embeddings client + cache, AI adjudication parsing and the staged job, with mocked HTTP (no network)."""
import json
from unittest import mock

import pytest

from spiderfoot import SpiderFootDb
from spiderfoot.services import relevance_embed as re_
from spiderfoot.services import relevance_job as job
from spiderfoot.services import relevance_llm as rl
from test.unit.services.relevance_fixture import TARGET, namesake_events

KEY = 'sk-relevance-SECRET-12345'


class Resp:
    def __init__(self, status=200, body=None, text=''):
        self.status_code, self._body, self.text = status, body, text

    def json(self):
        if self._body is None:
            raise ValueError('no json')
        return self._body


def vec_for(text):
    """A deterministic fake embedding: texts that mention Boston point one way, everything else the other."""
    return [1.0, 0.1, 0.0] if 'boston' in text.lower() else [0.1, 1.0, 0.0]


def embeddings_post(calls):
    def post(url, headers=None, json=None, timeout=None):
        calls.append({'url': url, 'headers': headers, 'n': len(json['input']), 'model': json.get('model')})
        return Resp(200, {'data': [{'index': i, 'embedding': vec_for(t)} for i, t in enumerate(json['input'])]})
    return post


@pytest.fixture
def dbh(tmp_path):
    path = str(tmp_path / 'sf.db')
    d = SpiderFootDb({'__database': path}, init=True)
    yield d
    d.close()


def routed(chat_resp, calls=None):
    """One replacement for requests.post that answers /embeddings and /chat/completions (both modules share `requests`)."""
    emb = embeddings_post(calls if calls is not None else [])

    def post(url, headers=None, json=None, timeout=None):
        if url.endswith('/embeddings'):
            return emb(url, headers=headers, json=json, timeout=timeout)
        return chat_resp(url, headers, json) if callable(chat_resp) else chat_resp
    return post


class TestEmbeddingClient:
    def test_batches_of_64_headers_and_model(self):
        calls = []
        client = re_.EmbeddingClient('http://emb.test/v1', 'm1', KEY)
        with mock.patch('spiderfoot.services.relevance_embed.requests.post', side_effect=embeddings_post(calls)):
            vecs = client.embed([f't{i}' for i in range(130)])
        assert len(vecs) == 130 and [c['n'] for c in calls] == [64, 64, 2]
        assert calls[0]['url'] == 'http://emb.test/v1/embeddings' and calls[0]['model'] == 'm1'
        assert calls[0]['headers']['Authorization'] == 'Bearer ' + KEY

    def test_cache_makes_reruns_free_and_bounds_new_texts(self, dbh):
        calls = []
        client = re_.EmbeddingClient('http://emb.test/v1', 'm1')
        with mock.patch('spiderfoot.services.relevance_embed.requests.post', side_effect=embeddings_post(calls)):
            out, stats = re_.embed_cached(client, dbh, ['a', 'b', 'c', 'boston'], max_new=3)
            assert stats['sent'] == 3 and stats['skipped'] == 1 and len(out) == 3
            out, stats = re_.embed_cached(client, dbh, ['a', 'b', 'c', 'boston'], max_new=10)
            assert stats['cached'] == 3 and stats['sent'] == 1
            before = len(calls)
            out, stats = re_.embed_cached(client, dbh, ['a', 'b', 'c', 'boston'], max_new=10)
            assert len(calls) == before and stats['sent'] == 0 and len(out) == 4

    def test_cache_is_keyed_by_model(self, dbh):
        with mock.patch('spiderfoot.services.relevance_embed.requests.post', side_effect=embeddings_post([])):
            re_.embed_cached(re_.EmbeddingClient('http://emb.test/v1', 'm1'), dbh, ['x'])
            _, stats = re_.embed_cached(re_.EmbeddingClient('http://emb.test/v1', 'm2'), dbh, ['x'])
        assert stats['sent'] == 1

    @pytest.mark.parametrize('resp', [Resp(500), Resp(401), Resp(200, {'data': []}), Resp(200, {'nope': 1}), Resp(200, text='<html>')])
    def test_failures_are_reported_without_the_key(self, resp, dbh):
        client = re_.EmbeddingClient('http://emb.test/v1', 'm', KEY)
        with mock.patch('spiderfoot.services.relevance_embed.requests.post', return_value=resp):
            out, stats = re_.embed_cached(client, dbh, ['a'])
        assert out == {} and stats['error'] and KEY not in stats['error']

    def test_network_error_message_has_no_key(self, dbh):
        import requests
        client = re_.EmbeddingClient('http://emb.test/v1', 'm', KEY)
        with mock.patch('spiderfoot.services.relevance_embed.requests.post', side_effect=requests.exceptions.ConnectTimeout(f'timeout {KEY}')):
            _, stats = re_.embed_cached(client, dbh, ['a'])
        assert 'ConnectTimeout' in stats['error'] and KEY not in stats['error']

    def test_blocked_url_is_refused(self):
        with pytest.raises(re_.EmbeddingError):
            re_.EmbeddingClient('http://169.254.169.254/v1', 'm').embed(['a'])

    def test_config_resolution(self):
        cfg = {'__modules__': {'sfp_searxng': {'opts': {'embeddings_url': 'http://web.test/v1', 'embeddings_model': 'web-model', 'embeddings_apikey': 'k1'}}}}
        assert re_.resolve_config(cfg)['source'] == 'web search'
        cfg.update({'_rel_embeddings_url': 'http://own.test/v1', '_rel_embeddings_apikey': 'k2'})
        c = re_.resolve_config(cfg)
        assert c['url'] == 'http://own.test/v1' and c['model'] == 'web-model' and c['key'] == 'k2'
        assert re_.EmbeddingClient.from_config({}) is None
        assert re_.EmbeddingClient.from_config(dict(cfg, _rel_use_embeddings=False)) is None

    def test_similarity_delta_bounds(self):
        assert re_.similarity_delta(1.0) == 0.20 and re_.similarity_delta(0.0) == -0.10 and re_.similarity_delta(0.5) == 0.0


class TestAdjudicationParsing:
    def test_clean_reply(self):
        out = rl.parse_response('{"results":[{"id":"1","verdict":"same","confidence":0.9,"reason":"same city"},'
                                '{"id":"2","verdict":"different","confidence":0.8,"reason":"other middle name"}]}', ['1', '2'])
        assert out == {'1': ('same', 0.9, 'same city'), '2': ('different', 0.8, 'other middle name')}

    def test_fences_think_tags_and_prose(self):
        text = '<think>hmm</think> Sure!\n```json\n{"results":[{"id":1,"verdict":"Same","confidence":"0.7","reason":"x"}]}\n```\nDone.'
        assert rl.parse_response(text, ['1'])['1'][:2] == ('same', 0.7)

    def test_garbage_and_wrong_shapes(self):
        for text in ('', 'I cannot help with that', '{', '[1,2,3]', '{"results": "no"}', 'null', '{"id": "1"}'):
            assert rl.parse_response(text, ['1']) == {}

    def test_unknown_ids_bad_verdicts_and_duplicates_are_ignored(self):
        text = '[{"id":"99","verdict":"same"},{"id":"1","verdict":"maybe"},{"id":"2","verdict":"same","confidence":5},{"id":"2","verdict":"different"}]'
        out = rl.parse_response(text, ['1', '2'])
        assert list(out) == ['2'] and out['2'] == ('same', 1.0, '')

    def test_reason_is_cleaned_and_clipped(self):
        out = rl.parse_response(json.dumps({'results': [{'id': '1', 'verdict': 'unknown', 'confidence': 0.2, 'reason': 'a\x00b\n' + 'z' * 500}]}), ['1'])
        assert len(out['1'][2]) <= 140 and '\x00' not in out['1'][2] and '\n' not in out['1'][2]

    def test_nan_confidence(self):
        out = rl.parse_response('[{"id":"1","verdict":"same","confidence":NaN}]', ['1'])
        assert out['1'][1] == 0.5


def chat_ok(content):
    return Resp(200, {'choices': [{'message': {'content': content}}], 'usage': {'total_tokens': 123}})


class TestAdjudicator:
    def items(self, n):
        return [{'id': str(i), 'type': 'social media', 'text': f'item {i}'} for i in range(1, n + 1)]

    def test_batches_and_caps_calls(self):
        posts = []

        def post(url, headers=None, json=None, timeout=None):
            posts.append({'url': url, 'json': json, 'headers': headers})
            ids = [c['id'] for c in __import__('json').loads(json['messages'][1]['content'].split('CANDIDATES (JSON): ')[1].split('\n')[0])]
            return chat_ok(__import__('json').dumps({'results': [{'id': i, 'verdict': 'same', 'confidence': 0.9, 'reason': 'ok'} for i in ids]}))
        adj = rl.Adjudicator('http://ai.test/v1', KEY, 'hermes', max_calls=2, max_tokens=100000, batch_size=5)
        with mock.patch('spiderfoot.services.relevance_llm.requests.post', side_effect=post):
            out = adj.judge('Person: X', self.items(23))
        assert len(posts) == 2 and len(out) == 10 and adj.calls == 2 and adj.tokens == 246
        assert posts[0]['url'] == 'http://ai.test/v1/chat/completions' and posts[0]['json']['model'] == 'hermes'
        assert posts[0]['json']['stream'] is False and posts[0]['headers']['Authorization'] == 'Bearer ' + KEY

    def test_token_cap_stops_further_calls(self):
        adj = rl.Adjudicator('http://ai.test/v1', '', 'm', max_calls=10, max_tokens=100, batch_size=2)
        with mock.patch('spiderfoot.services.relevance_llm.requests.post', return_value=chat_ok('{"results":[]}')):
            adj.judge('p', self.items(10))
        assert adj.calls == 1

    def test_failure_is_tolerated_and_stops(self):
        adj = rl.Adjudicator('http://ai.test/v1', KEY, 'm', batch_size=2)
        with mock.patch('spiderfoot.services.relevance_llm.requests.post', return_value=Resp(500)):
            assert adj.judge('p', self.items(6)) == {}
        assert adj.calls == 1 and adj.errors and KEY not in adj.errors[0]

    def test_garbage_reply_yields_nothing(self):
        adj = rl.Adjudicator('http://ai.test/v1', '', 'm')
        with mock.patch('spiderfoot.services.relevance_llm.requests.post', return_value=chat_ok('Sorry, as a language model...')):
            assert adj.judge('p', self.items(3)) == {}

    def test_redaction_is_applied_when_asked(self):
        seen = []

        def post(url, headers=None, json=None, timeout=None):
            seen.append(json['messages'][1]['content'])
            return chat_ok('{"results":[]}')
        adj = rl.Adjudicator('http://ai.test/v1', '', 'm', redact=True)
        with mock.patch('spiderfoot.services.relevance_llm.requests.post', side_effect=post):
            adj.judge('p', [{'id': '1', 'type': 'email', 'text': 'jane@example.com at 8.8.8.8'}])
        assert 'jane@example.com' not in seen[0] and '8.8.8.8' not in seen[0]

    def test_from_config(self):
        assert rl.Adjudicator.from_config({}) is None
        assert rl.Adjudicator.from_config({'_ai_enabled': True}) is None            # no endpoint
        assert rl.Adjudicator.from_config({'_ai_enabled': True, '_ai_base_url': 'http://a.test/v1', '_rel_use_ai': False}) is None
        a = rl.Adjudicator.from_config({'_ai_enabled': True, '_ai_base_url': 'http://a.test/v1', '_ai_default_model': 'm', '_rel_max_llm_calls': 3})
        assert a.model == 'm' and a.max_calls == 3

    def test_prompt_is_compact_and_strict(self):
        msgs = rl.build_messages('Person: X', self.items(2))
        assert len(msgs[0]['content']) < 1200 and 'JSON only' in msgs[0]['content'] and 'CANDIDATES (JSON)' in msgs[1]['content']


class TestStagedJob:
    def seed(self, dbh, context=''):
        dbh.scanInstanceCreate('S1', 'x', TARGET)
        for r in namesake_events():
            if r[1] == 'ROOT':
                continue
            dbh.dbh.execute("INSERT INTO tbl_scan_results (scan_instance_id,hash,type,generated,confidence,visibility,risk,module,data,false_positive,source_event_hash)"
                            " VALUES (?,?,?,?,100,100,0,?,?,0,?)", ('S1', r[0], r[1], r[5], r[2], r[3], r[4]))
        dbh.conn.commit()
        dbh.scanContextSet('S1', context, True)

    def test_heuristics_only_stores_scores_and_status(self, dbh):
        self.seed(dbh)
        s = job.assess_scan({}, 'S1', dbh=dbh, network=False)
        assert s['method'] == 'heuristics' and s['counts']['unrelated'] > 10
        stored = dbh.relevanceGet('S1')
        assert stored['npi_lic'][1] == 'unrelated' and stored['seed'][1] == 'confirmed'
        run = dbh.relevanceRunGet('S1')
        assert run['status'] == 'done' and run['method'] == 'heuristics' and run['counts']['unrelated'] == s['counts']['unrelated']

    def test_rerun_is_idempotent(self, dbh):
        self.seed(dbh)
        job.assess_scan({}, 'S1', dbh=dbh, network=False)
        first = dbh.relevanceGet('S1')
        job.assess_scan({}, 'S1', dbh=dbh, network=False)
        assert dbh.relevanceGet('S1') == {k: v for k, v in first.items()} and len(first) == len(namesake_events()) - 1

    def test_overrides_are_used_by_the_reassessment(self, dbh):
        self.seed(dbh)
        dbh.overrideSet('S1', ['npi_lic'], 'mine')
        dbh.overrideSet('S1', ['user_exact'], 'not_related')
        job.assess_scan({}, 'S1', dbh=dbh, network=False)
        got = dbh.relevanceGet('S1')
        assert got['npi_lic'][1] == 'confirmed' and got['user_exact'][1] == 'unrelated' and got['acct_exact'][1] == 'unrelated'

    def test_not_scorable_scan_is_skipped(self, dbh):
        dbh.scanInstanceCreate('S2', 'x', 'example.com')
        dbh.dbh.execute("INSERT INTO tbl_scan_results (scan_instance_id,hash,type,generated,confidence,visibility,risk,module,data,false_positive,source_event_hash)"
                        " VALUES ('S2','a','INTERNET_NAME',1,100,100,0,'SpiderFoot UI','example.com',0,'ROOT')")
        dbh.conn.commit()
        s = job.assess_scan({}, 'S2', dbh=dbh, network=False)
        assert s['skipped'] and dbh.relevanceGet('S2') == {}
        assert dbh.relevanceRunGet('S2')['status'] == 'skipped'

    def test_embeddings_need_context_beyond_the_name(self, dbh):
        self.seed(dbh)
        calls = []
        with mock.patch('spiderfoot.services.relevance_embed.requests.post', side_effect=embeddings_post(calls)):
            s = job.assess_scan({}, 'S1', dbh=dbh, network=False, embed_client=re_.EmbeddingClient('http://emb.test/v1', 'm'))
        assert calls == [] and any('context hints' in n for n in s['notes'])

    def test_embeddings_adjust_borderline_findings_and_are_cached(self, dbh):
        self.seed(dbh, 'lives in Boston, MA')
        rows = [('mA', 'LINKED_URL_EXTERNAL', 'sfp_searxng', 'https://prof.test/in/marcus-thornwood', 'seed', 99.0, 0)]
        for r in rows:
            dbh.dbh.execute("INSERT INTO tbl_scan_results (scan_instance_id,hash,type,generated,confidence,visibility,risk,module,data,false_positive,source_event_hash)"
                            " VALUES ('S1',?,?,?,100,100,0,?,?,0,?)", (r[0], r[1], r[5], r[2], r[3], r[4]))
        dbh.conn.commit()
        calls = []
        client = re_.EmbeddingClient('http://emb.test/v1', 'm')
        base = job.assess_scan({}, 'S1', dbh=dbh, network=False)
        base_score = dbh.relevanceGet('S1')['mA'][0]
        with mock.patch('spiderfoot.services.relevance_embed.requests.post', side_effect=embeddings_post(calls)):
            s = job.assess_scan({}, 'S1', dbh=dbh, network=False, embed_client=client)
            assert s['method'] == 'heuristics+embeddings' and s['embedded'] > 0
            n = len(calls)
            s2 = job.assess_scan({}, 'S1', dbh=dbh, network=False, embed_client=client)
            assert len(calls) == n and s2['embedded'] == 0                 # all from the cache
        assert dbh.relevanceGet('S1')['mA'][0] != base_score and base['counts']
        assert any('Context similarity' in r for r in dbh.relevanceGet('S1')['mA'][2])

    def test_ai_verdicts_move_borderline_findings(self, dbh):
        self.seed(dbh)

        def post(url, headers=None, json=None, timeout=None):
            payload = __import__('json').loads(json['messages'][1]['content'].split('CANDIDATES (JSON): ')[1].split('\n')[0])
            return chat_ok(__import__('json').dumps({'results': [
                {'id': c['id'], 'verdict': 'different' if 'facebook.com SkyFan' in c['text'] else 'unknown', 'confidence': 0.9, 'reason': 'unrelated hobby'}
                for c in payload]}))
        adj = rl.Adjudicator('http://ai.test/v1', KEY, 'm', max_calls=3)
        with mock.patch('spiderfoot.services.relevance_llm.requests.post', side_effect=post):
            s = job.assess_scan({}, 'S1', dbh=dbh, network=False, adjudicator=adj)
        got = dbh.relevanceGet('S1')
        assert s['calls'] == 1 and got['fb_nothing'][1] == 'unrelated' and 'AI:' in ' '.join(got['fb_nothing'][2])
        assert got['fb_nameonly'][1] == 'unclear'
        run = dbh.relevanceRunGet('S1')
        assert run['calls'] == 1 and run['tokens'] > 0 and 'ai' in run['method']

    def test_ai_failure_keeps_heuristic_scores(self, dbh):
        self.seed(dbh)
        base = job.assess_scan({}, 'S1', dbh=dbh, network=False)['counts']
        adj = rl.Adjudicator('http://ai.test/v1', KEY, 'm')
        with mock.patch('spiderfoot.services.relevance_llm.requests.post', return_value=Resp(503)):
            s = job.assess_scan({}, 'S1', dbh=dbh, network=False, adjudicator=adj)
        assert s['counts'] == base and s['method'] == 'heuristics' and dbh.relevanceRunGet('S1')['status'] == 'done'

    def test_no_secret_reaches_stored_state(self, dbh):
        self.seed(dbh, 'lives in Boston, MA')
        client = re_.EmbeddingClient('http://emb.test/v1', 'm', KEY)
        adj = rl.Adjudicator('http://ai.test/v1', KEY, 'm')
        with mock.patch('requests.post', side_effect=routed(Resp(500))):
            s = job.assess_scan({}, 'S1', dbh=dbh, network=False, embed_client=client, adjudicator=adj)
        dump = json.dumps({k: v for k, v in s.items() if not k.startswith('_')}, default=str) + json.dumps(dbh.relevanceRunGet('S1')) \
            + json.dumps(dbh.relevanceGet('S1'))
        assert KEY not in dump

    def test_pair_test_runs_the_real_pipeline(self):
        cfg = {'_ai_enabled': True, '_ai_base_url': 'http://ai.test/v1', '_ai_default_model': 'm'}
        client = re_.EmbeddingClient('http://emb.test/v1', 'm', KEY)
        adj = rl.Adjudicator('http://ai.test/v1', KEY, 'm')
        with mock.patch('requests.post', side_effect=routed(chat_ok('{"results":[{"id":"1","verdict":"different","confidence":0.9,"reason":"other middle name"}]}'))):
            out = job.test_pair(cfg, 'Nicholas Thomas Thornwood', 'location: Massachusetts', 'Nicholas Andrew Thornwood, MD, Missouri',
                                embed_client=client, adjudicator=adj)
        stages = {s['stage']: s for s in out['signals']}
        assert out['ok'] and stages['heuristics']['label'] == 'unrelated' and 'similarity' in stages['embeddings'] and stages['ai']['verdict'] == 'different'
        assert out['final']['label'] == 'unrelated' and KEY not in json.dumps(out)

    def test_pair_test_without_endpoints_degrades(self):
        out = job.test_pair({}, 'Nicholas Thomas Thornwood', '', 'Nicholas Andrew Thornwood, MD')
        assert out['ok'] and all('skipped' in s for s in out['signals'][1:]) and out['final']['label'] == 'unrelated'
        assert not job.test_pair({}, '', '', 'x')['ok']


class TestSettingsValidation:
    @pytest.mark.parametrize('opts', [{'_rel_t_unrelated': 'abc'}, {'_rel_t_unrelated': '99'}, {'_rel_max_llm_calls': '-1'}, {'_rel_enabled': 'yes'},
                                      {'_rel_embeddings_url': 'ftp://x'}, {'_rel_embeddings_url': 'http://169.254.169.254/v1'},
                                      {'_rel_t_unrelated': '70', '_rel_t_likely': '60', '_rel_t_confirmed': '90'}])
    def test_rejected(self, opts):
        assert job.validate_settings(opts, {})

    def test_accepted(self):
        assert job.validate_settings({'_rel_t_unrelated': '30', '_rel_t_likely': '60', '_rel_t_confirmed': '85', '_rel_enabled': '1',
                                      '_rel_embeddings_url': 'http://192.168.1.2:8642/v1', '_rel_max_llm_tokens': '1000'}, {}) == ''
        assert job.validate_settings({}, {}) == ''
