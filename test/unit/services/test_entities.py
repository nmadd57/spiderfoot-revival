from spiderfoot.services import entities as en
from spiderfoot.services import relevance as rv
from spiderfoot.services import relevance_profile as rp


def _type(v):
    return 'EMAILADDR' if '@' in v else ('HUMAN_NAME' if ' ' in v and not v[0].isdigit() else None)


def test_plan_splits_name_and_address():
    for text in ("Jane Roe\n1 Elm St Springfield MA", "Jane Roe, 1 Elm St, Springfield, MA 01103"):
        p = en.plan(text, _type)
        assert not p.error and p.primary[0] == 'HUMAN_NAME' and len(p.others) == 1
        assert p.others[0][0] == 'PHYSICAL_ADDRESS'
    assert en.plan("1 Elm St Springfield MA", _type).error


def test_address_and_name_are_correlated():
    p = en.plan("Jane Roe\n1 Elm St Springfield MA", _type)
    prof = rp.TargetProfile("Jane Roe", "HUMAN_NAME", "\n".join(p.context_lines))
    ev = [("r", "ROOT", "", "Jane Roe", "", 0, 0), ("s1", "HUMAN_NAME", "SpiderFoot UI", "Jane Roe", "r", 0, 0),
          ("s2", "PHYSICAL_ADDRESS", "SpiderFoot UI", "1 Elm St Springfield MA", "r", 0, 0),
          ("a", "HUMAN_NAME", "sfp_x", "Jane Roe", "s2", 0, 0),
          ("b", "RAW_RIR_DATA", "sfp_x", "Jane Roe, 9 Oak Ave, Tulsa, OK", "s1", 0, 0)]
    res = rv.Assessment(ev, prof).run()
    assert res["a"].label == "confirmed" and res["b"].score < 0.4
