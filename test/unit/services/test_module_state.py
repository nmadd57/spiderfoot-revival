import unittest

from spiderfoot.services import module_state


class FakeDb:
    def __init__(self):
        self.cfg = {}

    def configGet(self):
        return dict(self.cfg)

    def configSet(self, m):
        self.cfg.update(m)


class TestModuleState(unittest.TestCase):
    def test_roundtrip(self):
        db = FakeDb()
        self.assertEqual(module_state.get_disabled(db), set())
        module_state.set_disabled(db, {"sfp_b", "sfp_a"})
        self.assertEqual(db.cfg[module_state.KEY], "sfp_a,sfp_b")
        self.assertEqual(module_state.get_disabled(db), {"sfp_a", "sfp_b"})
        module_state.set_disabled(db, set())
        self.assertEqual(module_state.get_disabled(db), set())

    def test_parse_ignores_blanks(self):
        self.assertEqual(module_state.parse(" a, ,b,"), {"a", "b"})
        self.assertEqual(module_state.parse(None), set())
