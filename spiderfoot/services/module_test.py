"""Run one module against a small sample and report what happened.

Used by the Test button on Settings -> Modules. The module is set up exactly as a
scan would set it up (same options, keys and proxy), fed one sample event it
watches, and its output, errors and HTTP status codes are collected. Nothing is
stored: events are discarded, and no scan or scan log is created.

Safety:

* modules flagged ``invasive`` (port scanners, crawlers...) are only run when the
  caller supplies a target, so a test never probes a third party by itself;
* ``sfp_tool_*`` modules are not run against anything: the test starts the binary
  with a version/help flag and reports what it printed;
* HTTP calls are made through the normal client, so they count against, and are
  limited by, the module's usage limits. A test typically costs one to three calls.
"""

import logging
import os
import shutil
import subprocess
import threading
import time
from copy import deepcopy
from urllib.parse import urlparse

from spiderfoot.services import usage

TIMEOUT = 60

# Preference order of sample events: (event type, data, target type, target value).
SAMPLES = [
    ('DOMAIN_NAME', 'example.com', 'INTERNET_NAME', 'example.com'),
    ('IP_ADDRESS', '8.8.8.8', 'IP_ADDRESS', '8.8.8.8'),
    ('INTERNET_NAME', 'www.example.com', 'INTERNET_NAME', 'example.com'),
    ('EMAILADDR', 'test@example.com', 'EMAILADDR', 'test@example.com'),
    ('NETBLOCK_OWNER', '8.8.8.0/24', 'NETBLOCK_OWNER', '8.8.8.0/24'),
    ('BGP_AS_OWNER', '15169', 'BGP_AS_OWNER', '15169'),
    ('USERNAME', 'testuser', 'USERNAME', 'testuser'),
    ('HUMAN_NAME', 'John Smith', 'HUMAN_NAME', 'John Smith'),
    ('PHONE_NUMBER', '+14155550100', 'PHONE_NUMBER', '+14155550100'),
    ('COMPANY_NAME', 'Example Inc', 'COMPANY_NAME', 'Example Inc'),
    ('IPV6_ADDRESS', '2001:4860:4860::8888', 'IPV6_ADDRESS', '2001:4860:4860::8888'),
    ('BITCOIN_ADDRESS', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'BITCOIN_ADDRESS', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'),
    ('LINKED_URL_INTERNAL', 'https://example.com/', 'INTERNET_NAME', 'example.com'),
    ('AFFILIATE_INTERNET_NAME', 'example.org', 'INTERNET_NAME', 'example.com'),
    ('CO_HOSTED_SITE', 'example.org', 'INTERNET_NAME', 'example.com'),
]

# Tool modules: (binary file name, version/help arguments, interpreter or None).
TOOL_CMDS = {
    'bbot': ('bbot', ['--version'], None),
    'nmap': ('nmap', ['--version'], None),
    'nbtscan': ('nbtscan', ['-h'], None),
    'onesixtyone': ('onesixtyone', [], None),
    'nuclei': ('nuclei', ['-version'], None),
    'trufflehog': ('trufflehog', ['--version'], None),
    'retirejs': ('retire', ['--version'], None),
    'snallygaster': ('snallygaster', ['--help'], None),
    'testsslsh': ('testssl.sh', ['--version'], None),
    'wafw00f': ('wafw00f', ['--version'], None),
    'whatweb': ('whatweb', ['--version'], 'ruby'),
    'cmseek': ('cmseek.py', ['--help'], 'python3'),
    'dnstwist': ('dnstwist', ['--help'], None),
}


def pick_sample(watched, target=None):
    """Choose (event type, data, target type, target value) a module can be fed.

    ``target`` is a user-supplied scan target; without one a harmless public sample is used.
    """
    from spiderfoot import SpiderFootHelpers

    watched = list(watched or [])
    wildcard = '*' in watched
    if target:
        ttype = SpiderFootHelpers.targetTypeFromString(target)
        if not ttype:
            return None
        cands = [ttype]
        if ttype == 'INTERNET_NAME':
            cands = ['DOMAIN_NAME', 'INTERNET_NAME'] if target.count('.') == 1 else ['INTERNET_NAME', 'DOMAIN_NAME']
        for etype in cands:
            if etype in watched or wildcard:
                return etype, target, ttype, target
        return None
    for etype, data, ttype, tval in SAMPLES:
        if etype in watched or wildcard:
            return etype, data, ttype, tval
    return None


def _redact(url: str) -> dict:
    """host + path only: query strings routinely carry API keys."""
    try:
        u = urlparse(url or '')
        return {'host': u.netloc, 'path': u.path[:80]}
    except Exception:
        return {'host': '', 'path': ''}


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.errors, self.warnings = [], []

    def emit(self, record):
        try:
            msg = record.getMessage()
        except Exception:
            return
        (self.errors if record.levelno >= logging.ERROR else self.warnings).append(msg[:300])


def _result(status, summary, **extra):
    out = {'status': status, 'summary': summary, 'ms': 0, 'events': [], 'eventCount': 0,
           'errors': [], 'notes': [], 'warnings': [], 'requests': [], 'target': '', 'eventType': '', 'keyProblem': None}
    out.update(extra)
    return out


def test_tool(name, opts, saved):
    """Start the module's binary with a version/help flag and report what it prints."""
    from spiderfoot.services import tools

    key = name[len('sfp_tool_'):]
    key = 'bbot' if key.startswith('bbot') else key
    spec = TOOL_CMDS.get(key)
    if not tools.tool_installed(name, opts, saved):
        return _result('fail', 'The tool is not installed (or its path setting points at nothing).')
    if not spec:
        return _result('pass', 'The tool is installed. This module has no safe self-test, so it was not started.')
    binary, args, interp = spec
    opt = tools._tool_opt(opts)
    val = str(saved.get(f'{name}:{opt}', '') or opts.get(opt, '') or '').strip() if opt else ''
    if val and val.endswith('/'):
        exe = os.path.join(val, binary)
    elif val:
        exe = val
    else:
        exe = shutil.which(binary) or binary
    cmd = ([interp] if interp else []) + [exe] + args
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        text = ((p.stdout or '') + (p.stderr or '')).strip()
    except subprocess.TimeoutExpired:
        return _result('fail', 'The tool did not answer within 30 seconds.', ms=int((time.time() - t0) * 1000))
    except OSError as e:
        return _result('fail', f'The tool could not be started: {e}')
    line = next((ln.strip() for ln in text.splitlines() if ln.strip() and 'INF' not in ln[:8]), '')
    ms = int((time.time() - t0) * 1000)
    if not text:
        return _result('fail', 'The tool started but printed nothing.', ms=ms)
    return _result('pass', 'The tool starts and responds. (Tool modules are not run against a target by the test.)',
                   ms=ms, events=[{'type': 'TOOL_OUTPUT', 'data': line[:160]}], eventCount=0)


def run_module(name, config, sf_factory, target=None, saved=None, db=None):
    """Run module ``name`` on a sample and return a result dict.

    ``config`` is the app config (with ``__modules__``). ``sf_factory(config)`` builds the
    SpiderFoot helper object used by modules.
    """
    saved = saved or {}
    mod_cfg = (config.get('__modules__') or {}).get(name)
    if not mod_cfg:
        return _result('skip', 'Unknown module.')
    meta = mod_cfg.get('meta') or {}
    opts = mod_cfg.get('opts') or {}
    flags = meta.get('flags') or []

    if name.startswith('sfp_tool_'):
        return test_tool(name, opts, saved)

    # needs-a-key / needs-an-instance checks, using the same rule as auto-disable
    keyopts = [k for k in opts if any(t in k.lower() for t in ('api_key', 'apikey', 'api_id', 'accesstoken'))]
    if keyopts and 'apikey' in flags:
        if not any(str(saved.get(f'{name}:{k}', '') or opts.get(k, '')).strip() for k in keyopts):
            return _result('skip', 'No API key is set for this module.')
    if 'instance_url' in opts and not str(saved.get(f'{name}:instance_url', '') or opts.get('instance_url', '')).strip():
        return _result('skip', 'No instance URL is set for this module.')

    try:
        module = __import__('modules.' + name, globals(), locals(), [name])
        mod = getattr(module, name)()
        mod.__name__ = name
        # setup() merges the global config into ``self.opts``, which is a class-level dict shared with
        # the app's module registry: work on a private copy so a test never changes real settings.
        mod.opts = deepcopy(type(mod).opts)
    except Exception as e:
        return _result('fail', f'The module could not be loaded: {e}')

    sample = pick_sample(mod.watchedEvents(), target)
    if not sample:
        if target:
            return _result('skip', 'This module does not accept that kind of target. It watches: '
                           + ', '.join(mod.watchedEvents()[:8]))
        return _result('skip', 'No sample input is available for this module (it watches: '
                       + ', '.join(mod.watchedEvents()[:8]) + ').')
    if 'invasive' in flags and not target:
        return _result('skip', 'This module probes the target actively (invasive). Enter a target you are allowed to scan to test it.')
    etype, edata, ttype, tval = sample

    from spiderfoot import SpiderFootEvent, SpiderFootTarget, SpiderFootThreadPool

    modopts = deepcopy(opts)
    for opt in list(config.keys()):
        modopts[opt] = deepcopy(config[opt])

    capture = _Capture()
    events, requests_seen = [], []
    outcome = {'done': False, 'exc': None}
    pool = SpiderFootThreadPool(threads=2, name='moduleTestPool')

    try:
        sf = sf_factory(config)
        orig_fetch = sf.fetchUrl

        def fetch(url, *a, **kw):
            res = orig_fetch(url, *a, **kw)
            row = _redact(url)
            row['code'] = (res or {}).get('code')
            if len(requests_seen) < 12:
                requests_seen.append(row)
            return res
        sf.fetchUrl = fetch

        mod.clearListeners()
        mod.setScanId('')
        mod.setSharedThreadPool(pool)
        if db is not None:
            mod.setDbh(db)
        mod.setup(sf, modopts)
        mod.setTarget(SpiderFootTarget(tval, ttype))
        mod.notifyListeners = lambda e: events.append(e)
        mod.checkForStop = lambda: False
    except Exception as e:
        pool.shutdown(wait=False)
        return _result('fail', f'The module failed to initialise: {e}')

    mod.log.addHandler(capture)
    pool.start()
    root = SpiderFootEvent('ROOT', tval, '', None)
    evt = SpiderFootEvent(etype, edata, 'test', root)

    def work():
        usage.set_module(name)
        try:
            mod.handleEvent(evt)
        except Exception as e:  # noqa: BLE001 - report whatever the module raised
            outcome['exc'] = f'{type(e).__name__}: {e}'
        finally:
            usage.set_module(None)
            outcome['done'] = True

    t0 = time.time()
    th = threading.Thread(target=work, name=f'moduletest-{name}', daemon=True)
    th.start()
    th.join(TIMEOUT)
    ms = int((time.time() - t0) * 1000)
    mod.log.removeHandler(capture)
    try:
        pool.shutdown(wait=False)
    except Exception:
        pass

    errors = list(capture.errors)
    if outcome['exc']:
        errors.append(outcome['exc'])
    problem = None
    for r in requests_seen:
        problem = usage.classify(code=r.get('code'))
        if problem:
            break
    if not problem:
        for msg in errors:
            problem = usage.classify(msg)
            if problem:
                break

    ev = [{'type': e.eventType, 'data': str(e.data)[:140]} for e in events if e.eventType != 'ROOT']
    base = dict(ms=ms, events=ev[:15], eventCount=len(ev), errors=errors[:6], warnings=capture.warnings[:4],
                requests=requests_seen, target=edata, eventType=etype)
    if not outcome['done']:
        return _result('fail', f'The module did not finish within {TIMEOUT} seconds.', **base)
    if problem:
        kind, detail = problem
        label = {'rejected': 'the key was rejected', 'quota': 'the key is out of quota or credits', 'rate': 'the vendor rate limited the request'}[kind]
        return _result('fail', f'The service answered but {label}: {detail}', keyProblem={'kind': kind, 'detail': detail}, **base)
    if outcome['exc']:
        return _result('fail', outcome['exc'], **base)
    if errors:
        # Messages that do not concern the API key (no results, odd replies) are shown as notes,
        # not as a failed test: only key or account problems fail a module.
        base['notes'], base['errors'] = errors[:6], []
        return _result('warn', f'Completed, but the module logged: {errors[0]}', **base)
    if ev:
        return _result('pass', f'Produced {len(ev)} event{"s" if len(ev) != 1 else ""} for {edata}.', **base)
    return _result('pass', f'Ran without errors but found nothing for the sample {edata}. '
                   'That is normal for many modules; try your own target below.', **base)
