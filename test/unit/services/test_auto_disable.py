import datetime
import json
import os
import tempfile
import time
import unittest

from spiderfoot.services import auto_disable, usage

TODAY = datetime.date(2026, 11, 1)


class TestOverLimit(unittest.TestCase):
    def test_daily(self):
        days = {TODAY.isoformat(): (5, 0, 0, 0)}
        self.assertIn('daily', auto_disable.over_limit({'per_day': 5}, days, TODAY))
        self.assertEqual(auto_disable.over_limit({'per_day': 6}, days, TODAY), '')

    def test_total_uses_period_start(self):
        days = {'2026-10-01': (50, 0, 0, 0), '2026-11-01': (3, 0, 0, 0)}
        self.assertEqual(auto_disable.over_limit({'total': 10, 'period_start': '2026-10-15'}, days, TODAY), '')
        self.assertIn('period', auto_disable.over_limit({'total': 10, 'period_start': '2026-10-01'}, days, TODAY))

    def test_not_enforced(self):
        days = {TODAY.isoformat(): (50, 0, 0, 0)}
        self.assertEqual(auto_disable.over_limit({'per_day': 5, 'enforce': False}, days, TODAY), '')

    def test_period_rolls_over(self):
        days = {'2026-10-20': (50, 0, 0, 0)}
        lim = {'total': 10, 'reset_date': '2026-11-01', 'reset_every': 'monthly', 'period_start': '2026-10-01'}
        self.assertEqual(auto_disable.over_limit(lim, days, TODAY), '')


class TestQuota(unittest.TestCase):
    def test_exhausted_only_when_recent_and_known(self):
        now = time.time()
        self.assertTrue(auto_disable.quota_exhausted({'ok': True, 'remaining': 0, 'at': now}))
        self.assertFalse(auto_disable.quota_exhausted({'ok': True, 'remaining': 3, 'at': now}))
        self.assertFalse(auto_disable.quota_exhausted({'ok': True, 'remaining': 0, 'at': now - 2 * 86400}))
        self.assertFalse(auto_disable.quota_exhausted({'ok': True, 'remaining': None, 'at': now}))
        self.assertFalse(auto_disable.quota_exhausted({'ok': False, 'remaining': 0, 'at': now}))
        self.assertFalse(auto_disable.quota_exhausted(None))


class TestCompute(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.dir.name, 'a.db')
        conn = usage.connect(self.db)
        conn.execute("CREATE TABLE tbl_config (scope TEXT, opt TEXT, val TEXT, PRIMARY KEY (scope, opt))")
        today = usage.today_utc().isoformat()
        conn.execute("INSERT INTO tbl_module_usage (module, day, calls) VALUES ('sfp_busy', ?, 9)", (today,))
        conn.execute("REPLACE INTO tbl_config VALUES ('GLOBAL', ?, ?)",
                     (usage.LIMITS_KEY, json.dumps({'sfp_busy': usage.normalize_limits({'per_day': 5})})))
        conn.commit()
        conn.close()
        self.addCleanup(self.dir.cleanup)
        self.keyinfo = {'sfp_nokey': (True, False), 'sfp_haskey': (True, True), 'sfp_free': (False, False),
                        'sfp_busy': (False, False), 'sfp_vendor': (True, True)}
        self.cfg = {auto_disable.QUOTA_CACHE_KEY: json.dumps(
            {'sfp_vendor': {'ok': True, 'remaining': 0, 'at': int(time.time())}})}

    def test_reasons(self):
        r = auto_disable.compute(self.db, self.cfg, self.keyinfo)
        self.assertEqual(r['sfp_nokey'], 'no API key')
        self.assertIn('daily', r['sfp_busy'])
        self.assertEqual(r['sfp_vendor'], 'vendor quota used up')
        self.assertNotIn('sfp_haskey', r)
        self.assertNotIn('sfp_free', r)

    def test_can_be_switched_off(self):
        cfg = dict(self.cfg, **{auto_disable.KEY: '0'})
        self.assertEqual(auto_disable.compute(self.db, cfg, self.keyinfo), {})
        self.assertFalse(auto_disable.enabled(cfg))
        self.assertTrue(auto_disable.enabled({}))
