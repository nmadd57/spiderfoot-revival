"""Relevance tables: migration of an old database, scores, overrides, run status, the embedding cache, scan deletion."""
import sqlite3

import pytest

from spiderfoot import SpiderFootDb, SpiderFootEvent

TABLES = ('tbl_event_relevance', 'tbl_scan_context', 'tbl_relevance_override', 'tbl_relevance_run', 'tbl_embedding_cache')


@pytest.fixture
def dbh(tmp_path):
    d = SpiderFootDb({'__database': str(tmp_path / 'r.db')}, init=True)
    yield d
    d.close()


def tables(path):
    c = sqlite3.connect(path)
    try:
        return {r[0] for r in c.execute("select name from sqlite_master where type='table'")}
    finally:
        c.close()


class TestMigration:
    def test_an_old_database_gains_the_tables_and_keeps_its_data(self, tmp_path):
        path = str(tmp_path / 'old.db')
        d = SpiderFootDb({'__database': path}, init=True)
        d.scanInstanceCreate('OLD1', 'old scan', 'jane doe')
        root = SpiderFootEvent('ROOT', 'jane doe', '', None)
        d.scanEventStore('OLD1', root)
        d.close()
        c = sqlite3.connect(path)
        for t in TABLES:
            c.execute(f'DROP TABLE {t}')
        c.commit()
        c.close()
        assert not set(TABLES) & tables(path)
        d2 = SpiderFootDb({'__database': path})
        assert set(TABLES) <= tables(path)
        assert d2.scanInstanceGet('OLD1')[0] == 'old scan' and len(d2.scanResultEvent('OLD1')) == 1
        assert d2.scanContextGet('OLD1') == {'context': '', 'prune': False, 'exists': False}
        assert d2.relevanceGet('OLD1') == {} and d2.relevanceRunGet('OLD1')['status'] == 'none'
        d2.close()

    def test_migration_is_idempotent(self, tmp_path):
        path = str(tmp_path / 'i.db')
        for _ in range(3):
            SpiderFootDb({'__database': path}, init=True).close()
        assert set(TABLES) <= tables(path)


class TestScores:
    def test_store_get_replace_and_counts(self, dbh):
        dbh.relevanceStore('S', [('a', 0.9, 'confirmed', ['x'], 'seed'), ('b', 0.1, 'unrelated', ['y', 'z'], 'heuristics')])
        got = dbh.relevanceGet('S')
        assert got['a'] == (0.9, 'confirmed', ['x'], 'seed') and got['b'][2] == ['y', 'z']
        dbh.relevanceStore('S', [('b', 0.5, 'likely', ['w'], 'heuristics')])
        assert dbh.relevanceGet('S')['b'][1] == 'likely'
        assert dbh.relevanceCounts('S') == {'confirmed': 1, 'likely': 1, 'unclear': 0, 'unrelated': 0}
        assert set(dbh.relevanceGet('S', labels=['likely'])) == {'b'}
        dbh.relevanceDelete('S')
        assert dbh.relevanceGet('S') == {}

    def test_scores_are_per_scan(self, dbh):
        dbh.relevanceStore('S1', [('a', 0.9, 'confirmed', [], 'x')])
        assert dbh.relevanceGet('S2') == {}

    def test_deleting_a_scan_removes_its_relevance_but_not_the_cache(self, dbh):
        dbh.scanInstanceCreate('S', 'n', 't')
        dbh.relevanceStore('S', [('a', 0.9, 'confirmed', [], 'x')])
        dbh.scanContextSet('S', 'lives in Boston', True)
        dbh.overrideSet('S', ['a'], 'mine')
        dbh.relevanceRunSet('S', status='done')
        dbh.embeddingCachePut('m', {'h': [0.1, 0.2]})
        dbh.scanInstanceDelete('S')
        assert dbh.relevanceGet('S') == {} and dbh.overrideGet('S') == {} and dbh.scanContextGet('S')['exists'] is False
        assert dbh.relevanceRunGet('S')['status'] == 'none'
        assert dbh.embeddingCacheGet('m', ['h']) == {'h': pytest.approx([0.1, 0.2], rel=1e-6)}

    def test_filtering_in_the_event_query(self, dbh):
        dbh.scanInstanceCreate('S', 'n', 't')
        root = SpiderFootEvent('ROOT', 't', '', None)
        seed = SpiderFootEvent('HUMAN_NAME', 'Jane Doe', 'SpiderFoot UI', root)
        keep = SpiderFootEvent('HUMAN_NAME', 'Jane Q Doe', 'm', seed)
        drop = SpiderFootEvent('HUMAN_NAME', 'Joan Doe', 'm', seed)
        for e in (root, seed, keep, drop):
            dbh.scanEventStore('S', e)
        dbh.relevanceStore('S', [(drop.hash, 0.0, 'unrelated', [], 'x'), (keep.hash, 0.8, 'likely', [], 'x')])
        names = lambda rows: {r[1] for r in rows if r[4] != 'ROOT'}  # noqa: E731
        assert names(dbh.scanResultEvent('S')) == {'Jane Doe', 'Jane Q Doe', 'Joan Doe'}
        assert names(dbh.scanResultEvent('S', hideLabels=['unrelated'])) == {'Jane Doe', 'Jane Q Doe'}
        assert names(dbh.scanResultEvent('S', hashes=[keep.hash])) == {'Jane Q Doe'}
        rows = dbh.scanResultEvent('S', sourceLimit=4)
        assert all(len(r[2]) <= 4 for r in rows)
        assert [r[0] for r in dbh.relevanceUnrelatedRows('S')] == [drop.hash]
        assert dbh.relevanceCountsByType('S')['HUMAN_NAME'] == {'unrelated': 1, 'likely': 1}


class TestOverridesAndRuns:
    def test_override_roundtrip(self, dbh):
        assert dbh.overrideSet('S', ['a', 'b'], 'mine', 7) == 2
        dbh.overrideSet('S', ['b'], 'not_related')
        assert dbh.overrideGet('S') == {'a': 'mine', 'b': 'not_related'}
        assert dbh.overrideClear('S', ['a']) == 1 and dbh.overrideGet('S') == {'b': 'not_related'}
        with pytest.raises(ValueError):
            dbh.overrideSet('S', ['a'], 'maybe')

    def test_scan_context(self, dbh):
        dbh.scanContextSet('S', 'x' * 5000, False)
        got = dbh.scanContextGet('S')
        assert len(got['context']) == 4000 and got['prune'] is False and got['exists']
        dbh.scanContextSet('S', 'new', True)
        assert dbh.scanContextGet('S')['context'] == 'new'

    def test_run_status_and_restart_reconciliation(self, dbh):
        dbh.relevanceRunSet('S', status='running', phase='ai', progress=0.5, counts={'unrelated': 3})
        run = dbh.relevanceRunGet('S')
        assert run['status'] == 'running' and run['counts'] == {'unrelated': 3}
        assert dbh.relevanceRunsReconcile() == 1
        assert dbh.relevanceRunGet('S')['status'] == 'failed'

    def test_unknown_run_fields_are_ignored(self, dbh):
        dbh.relevanceRunSet('S', bogus=1, status='done')
        assert dbh.relevanceRunGet('S')['status'] == 'done'


class TestEmbeddingCache:
    def test_roundtrip_and_prune(self, dbh):
        dbh.embeddingCachePut('m', {f'h{i}': [float(i), 1.0] for i in range(10)})
        got = dbh.embeddingCacheGet('m', [f'h{i}' for i in range(12)])
        assert len(got) == 10 and got['h3'] == [3.0, 1.0]
        assert dbh.embeddingCacheGet('other', ['h3']) == {}
        dbh.embeddingCachePrune(keep=4)
        assert len(dbh.embeddingCacheGet('m', [f'h{i}' for i in range(10)])) == 4
