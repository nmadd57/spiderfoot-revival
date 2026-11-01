"""Shared harness for the federal-records module tests."""
import json

from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget

TLDS = "// ===BEGIN ICANN DOMAINS===\ncom\nus\n// ===END ICANN DOMAINS===\n"


def run(testcase, cls, target, routes, opts=None):
    """Run cls.handleEvent on a COMPANY_NAME target with fetchUrl answered from routes.

    routes: list of (substring, code, body); the first substring found in the URL wins.
    Returns (events, calls).
    """
    sf = SpiderFoot(testcase.default_options)
    module = cls()
    module.setup(sf, {**testcase.default_options, '_internettlds': TLDS, **(opts or {})})
    module.setTarget(SpiderFootTarget(target, 'COMPANY_NAME'))
    calls = []

    def fetch(url, **kwargs):
        calls.append((url, kwargs))
        for key, code, body in routes:
            if key in url:
                return {'code': code, 'content': body if isinstance(body, str) else json.dumps(body)}
        return {'code': '404', 'content': None}

    sf.fetchUrl = fetch
    events = []
    module.notifyListeners = events.append
    root = SpiderFootEvent('ROOT', target, '', '')
    module.handleEvent(SpiderFootEvent('COMPANY_NAME', target, 'SpiderFoot UI', root))
    return events, calls


def by_type(events):
    out = {}
    for e in events:
        out.setdefault(e.eventType, []).append(e.data)
    return out
