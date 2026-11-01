import datetime
import os
import tempfile
import unittest

from spiderfoot.services import usage

D = datetime.date


class TestLimits(unittest.TestCase):
    def test_normalize_defaults(self):
        lim = usage.normalize_limits({})
        self.assertEqual((lim['per_second'], lim['per_day'], lim['total']), (0, 0, 0))
        self.assertTrue(lim['enforce'])

    def test_normalize_rejects_bad_input(self):
        for bad in ({'per_day': 'x'}, {'total': -1}, {'reset_date': '31/12/2026'}, {'reset_every': 'hourly'}):
            with self.assertRaises(ValueError):
                usage.normalize_limits(bad)

    def test_advance(self):
        self.assertEqual(usage.advance(D(2026, 1, 31), 'monthly'), D(2026, 2, 28))
        self.assertEqual(usage.advance(D(2026, 12, 15), 'monthly'), D(2027, 1, 15))
        self.assertEqual(usage.advance(D(2028, 2, 29), 'yearly'), D(2029, 2, 28))
        self.assertEqual(usage.advance(D(2026, 1, 1), 'weekly'), D(2026, 1, 8))

    def test_roll_period(self):
        lim = usage.normalize_limits({'total': 10, 'reset_date': '2026-03-01', 'reset_every': 'monthly',
                                      'period_start': '2026-02-01'})
        self.assertEqual(usage.roll_period(lim, D(2026, 2, 20))['period_start'], '2026-02-01')
        r = usage.roll_period(lim, D(2026, 5, 2))
        self.assertEqual((r['period_start'], r['reset_date']), ('2026-05-01', '2026-06-01'))

    def test_roll_period_one_off(self):
        lim = usage.normalize_limits({'total': 10, 'reset_date': '2026-03-01', 'period_start': '2026-02-01'})
        r = usage.roll_period(lim, D(2026, 3, 2))
        self.assertEqual((r['period_start'], r['reset_date']), ('2026-03-01', ''))

    def test_headers(self):
        self.assertEqual(usage.parse_ratelimit_headers({'x-ratelimit-limit': '100', 'x-ratelimit-remaining': '42'}),
                         {'limit': 100, 'remaining': 42, 'reset': None})
        self.assertIsNone(usage.parse_ratelimit_headers({'content-type': 'x'}))
        self.assertIsNone(usage.parse_ratelimit_headers(None))


class TestTracker(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.dir.name, 't.db')
        conn = usage.connect(self.db)
        conn.execute("CREATE TABLE tbl_config (scope TEXT, opt TEXT, val TEXT, PRIMARY KEY (scope, opt))")
        conn.commit()
        conn.close()

    def tearDown(self):
        self.dir.cleanup()

    def _limits(self, mod, lim):
        import json
        conn = usage.connect(self.db)
        conn.execute("REPLACE INTO tbl_config VALUES ('GLOBAL', ?, ?)", (usage.LIMITS_KEY, json.dumps({mod: lim})))
        conn.commit()
        conn.close()

    def test_counts_and_flush(self):
        t = usage.Tracker(self.db)
        for _ in range(3):
            self.assertTrue(t.before('sfp_a')[0])
        t.after('sfp_a', {'code': '500', 'headers': {'x-ratelimit-remaining': '5'}})
        t.after('sfp_a', {'code': '429', 'headers': None})
        t.flush()
        conn = usage.connect(self.db)
        day = usage.today_utc().isoformat()
        self.assertEqual(usage.summarize(conn)['sfp_a'][day], (3, 1, 1, 0))
        self.assertEqual(usage.load_ratelimits(conn)['sfp_a']['remaining'], 5)

    def test_daily_limit_blocks(self):
        self._limits('sfp_a', usage.normalize_limits({'per_day': 2}))
        t = usage.Tracker(self.db)
        self.assertTrue(t.before('sfp_a')[0])
        self.assertTrue(t.before('sfp_a')[0])
        ok, why = t.before('sfp_a')
        self.assertFalse(ok)
        self.assertIn('daily', why)

    def test_total_limit_respects_period_start(self):
        t0 = usage.Tracker(self.db)
        t0.before('sfp_a')
        t0.flush()
        self._limits('sfp_a', usage.normalize_limits({'total': 1, 'period_start': usage.today_utc().isoformat()}))
        t = usage.Tracker(self.db)
        self.assertFalse(t.before('sfp_a')[0])
        future = (usage.today_utc() + datetime.timedelta(days=1)).isoformat()
        self._limits('sfp_a', usage.normalize_limits({'total': 1, 'period_start': future}))
        t2 = usage.Tracker(self.db)
        self.assertTrue(t2.before('sfp_a')[0])

    def test_enforce_off_never_blocks(self):
        self._limits('sfp_a', usage.normalize_limits({'per_day': 1, 'enforce': False}))
        t = usage.Tracker(self.db)
        for _ in range(3):
            self.assertTrue(t.before('sfp_a')[0])

    def test_per_second_spaces_calls(self):
        import time
        self._limits('sfp_a', usage.normalize_limits({'per_second': 20}))
        t = usage.Tracker(self.db)
        start = time.monotonic()
        for _ in range(4):
            t.before('sfp_a')
        self.assertGreaterEqual(time.monotonic() - start, 0.14)


class TestHttpHook(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.dir.name, 'h.db')
        conn = usage.connect(self.db)
        conn.execute("CREATE TABLE tbl_config (scope TEXT, opt TEXT, val TEXT, PRIMARY KEY (scope, opt))")
        conn.commit()
        conn.close()
        from unittest import mock
        import logging
        from spiderfoot.net.http import SpiderFootHttp
        self.http = SpiderFootHttp({'__database': self.db}, logging.getLogger('t'))
        self.fetch = mock.patch.object(SpiderFootHttp, '_fetchUrl',
                                       return_value={'code': '200', 'headers': {}, 'content': 'x', 'realurl': 'u'}).start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(self.dir.cleanup)
        self.addCleanup(usage.set_module, None)

    def test_untracked_without_module(self):
        usage.set_module(None)
        self.http.fetchUrl('http://example.com')
        self.assertEqual(self.fetch.call_count, 1)
        usage.get_tracker(self.db).flush()
        self.assertEqual(usage.summarize(usage.connect(self.db)), {})

    def test_counted_and_blocked(self):
        import json
        conn = usage.connect(self.db)
        conn.execute("REPLACE INTO tbl_config VALUES ('GLOBAL', ?, ?)",
                     (usage.LIMITS_KEY, json.dumps({'sfp_x': usage.normalize_limits({'per_day': 2})})))
        conn.commit()
        conn.close()
        usage.set_module('sfp_x')
        results = [self.http.fetchUrl('http://example.com') for _ in range(3)]
        self.assertEqual([r['code'] for r in results], ['200', '200', None])
        self.assertIn('daily limit', results[2]['status'])
        self.assertEqual(self.fetch.call_count, 2)
