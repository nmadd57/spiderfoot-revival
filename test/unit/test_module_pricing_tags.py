import glob
import importlib
import os
import unittest

VALID = {"free", "free_key", "paid", "local"}
MODEL_TO_TAG = {
    "FREE_NOAUTH_UNLIMITED": {"free"},
    "FREE_NOAUTH_LIMITED": {"free", "free_key"},
    "FREE_AUTH_UNLIMITED": {"free", "free_key"},
    "FREE_AUTH_LIMITED": {"free", "free_key"},
    "COMMERCIAL_ONLY": {"paid"},
    "PRIVATE_ONLY": {"paid"},
}


def _modules():
    root = os.path.join(os.path.dirname(__file__), "..", "..", "modules")
    for f in sorted(glob.glob(os.path.join(root, "sfp_*.py"))):
        name = os.path.basename(f)[:-3]
        yield name, importlib.import_module(f"modules.{name}")


class TestModulePricingTags(unittest.TestCase):
    def test_every_module_has_valid_pricing_tag(self):
        for name, mod in _modules():
            meta = getattr(getattr(mod, name), "meta", None) or {}
            self.assertIn(meta.get("pricing"), VALID, name)

    def test_pricing_consistent_with_data_source_model(self):
        for name, mod in _modules():
            meta = getattr(getattr(mod, name), "meta", None) or {}
            model = (meta.get("dataSource") or {}).get("model")
            if model:
                self.assertIn(meta["pricing"], MODEL_TO_TAG[model], name)

    def test_asdict_exposes_pricing(self):
        from modules.sfp_hostio import sfp_hostio
        self.assertEqual(sfp_hostio().asdict()["pricing"], "free_key")


if __name__ == "__main__":
    unittest.main()
