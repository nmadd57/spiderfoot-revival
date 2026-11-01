"""Automatic disabling of modules that cannot do useful work.

A module is auto-disabled (hidden from New Scan, stripped from API-started
scans) when, in this order of precedence:

* ``no API key``    - it needs an API key and none is configured;
* ``over limit``    - a limit the user set in Settings > API Usage is reached
                      (calls/day or total calls for the period);
* ``quota used up`` - the vendor itself reported 0 remaining within the last day.

Auto-disabling is computed on demand, never stored, so a module comes back as
soon as a key is added, the period resets or the quota refreshes. It can be
switched off with the ``_auto_disable`` config key ("0").
"""

import json
import time

from spiderfoot.services import usage

KEY = '_auto_disable'
QUOTA_CACHE_KEY = '_module_quota_cache'
QUOTA_MAX_AGE = 86400


def enabled(saved_config: dict) -> bool:
    return str(saved_config.get(KEY, '1')) != '0'


def over_limit(limits: dict, days: dict, today) -> str:
    """Reason a module's user-set limits are exhausted, or ''."""
    lim = usage.roll_period(usage.normalize_limits(limits), today)
    if not lim.get('enforce', True):
        return ''
    if lim['per_day'] and days.get(today.isoformat(), (0,))[0] >= lim['per_day']:
        return f"daily limit of {lim['per_day']} calls reached"
    start = lim.get('period_start') or ''
    if lim['total'] and sum(v[0] for d, v in days.items() if not start or d >= start) >= lim['total']:
        return f"limit of {lim['total']} calls for this period reached"
    return ''


def quota_exhausted(quota: dict, now=None) -> bool:
    """True if a recent vendor check reported nothing left."""
    if not quota or not quota.get('ok') or quota.get('remaining') is None:
        return False
    if (now or time.time()) - (quota.get('at') or 0) > QUOTA_MAX_AGE:
        return False
    return quota['remaining'] <= 0


def compute(db_path: str, saved_config: dict, keyinfo: dict) -> dict:
    """Return {module: reason} for every module that should be auto-disabled.

    ``keyinfo`` maps module name -> (needs_key, key_configured), optionally with a
    third element giving the reason to report when it is not configured (default
    'no API key'; self-hosted modules use 'no instance URL').
    """
    if not enabled(saved_config):
        return {}

    today = usage.today_utc()
    try:
        conn = usage.connect(db_path)
        try:
            limits = usage.load_limits(conn)
            stored = usage.summarize(conn)
        finally:
            conn.close()
    except Exception:
        limits, stored = {}, {}
    try:
        quotas = json.loads(saved_config.get(QUOTA_CACHE_KEY) or '{}')
    except (ValueError, TypeError):
        quotas = {}

    out = {}
    for name, info in keyinfo.items():
        needs_key, configured = info[0], info[1]
        if needs_key and not configured:
            out[name] = info[2] if len(info) > 2 else 'no API key'
            continue
        if name in limits:
            why = over_limit(limits[name], stored.get(name, {}), today)
            if why:
                out[name] = why
                continue
        if quota_exhausted(quotas.get(name)):
            out[name] = 'vendor quota used up'
    return out
