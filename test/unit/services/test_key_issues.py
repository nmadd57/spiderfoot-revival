import os
import tempfile
import time
import unittest

from spiderfoot.services import usage


class TestClassify(unittest.TestCase):
    def test_http_codes(self):
        self.assertEqual(usage.classify(code=401)[0], 'rejected')
        self.assertEqual(usage.classify(code=403)[0], 'rejected')
        self.assertEqual(usage.classify(code=402)[0], 'quota')
        self.assertEqual(usage.classify(code=429)[0], 'rate')
        self.assertIsNone(usage.classify(code=404))
        self.assertIsNone(usage.classify(code=200))

    def test_messages(self):
        cases = {
            'Greynoise API key seems to have been rejected or you have exceeded usage limits.': 'quota',
            "API error: {'code': 101, 'type': 'invalid_access_key'}": 'rejected',
            'Error querying Whoxy: Zero Account Balance': 'quota',
            'ZoomEye: this plan has no search credits left (HTTP 402 credits_insufficient)': 'quota',
            'Hunter.io rate limit exceeded.': 'rate',
            'LeakCheck API: plan limit reached or inactive.': 'quota',
            'Invalid AbstractAPI API key.': 'rejected',
            'Unauthorized. Invalid AbstractAPI API key.': 'rejected',
        }
        for msg, kind in cases.items():
            hit = usage.classify(msg)
            self.assertIsNotNone(hit, msg)
            self.assertEqual(hit[0], kind, msg)

    def test_not_key_problems(self):
        for msg in ('You enabled sfp_fofa but did not set an API key and email!',
                    'Unable to fetch CommonCrawl index.',
                    'Error processing JSON response from DuckDuckGo: Expecting value',
                    'No information available for that IP.', ''):
            self.assertIsNone(usage.classify(msg), msg)


class TestStore(unittest.TestCase):
    def test_record_expire_clear(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, 'x.db')
            t = usage.get_tracker(db)
            t.issue('sfp_a', 'quota', 'out of credits')
            t.issue('sfp_a', 'quota', 'out of credits')
            t.flush()
            conn = usage.connect(db)
            try:
                got = usage.load_issues(conn)
                self.assertEqual(got['sfp_a']['kind'], 'quota')
                self.assertEqual(got['sfp_a']['hits'], 2)
                self.assertEqual(usage.load_issues(conn, now=time.time() + usage.ISSUE_TTL + 60), {})
                usage.clear_issues(conn, ['sfp_a'])
                self.assertEqual(usage.load_issues(conn), {})
            finally:
                conn.close()

    def test_after_records_http_failure(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, 'x.db')
            t = usage.get_tracker(db)
            t.after('sfp_b', {'code': '401', 'headers': {}})
            t.flush()
            conn = usage.connect(db)
            try:
                self.assertEqual(usage.load_issues(conn)['sfp_b']['kind'], 'rejected')
            finally:
                conn.close()
