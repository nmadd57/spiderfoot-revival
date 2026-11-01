"""Per-module vendor quota checks and API key validation helpers.

Each provider performs one cheap account/usage request and parses the answer
into a uniform result dict. Keys are only ever sent to the vendor, never
logged or returned.
"""
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, NamedTuple, Optional
from urllib.parse import quote, urlencode

import requests

TIMEOUT = 15


class Provider(NamedTuple):
    opts: List[str]
    check: Callable[[Dict[str, str]], dict]


def _result(ok: bool = False, valid: Optional[bool] = None, message: str = '',
            used: Optional[int] = None, limit: Optional[int] = None,
            remaining: Optional[int] = None, unit: str = 'requests',
            resets: Optional[str] = None, plan: Optional[str] = None) -> dict:
    """Build a result dict, deriving the third of used/limit/remaining."""
    if limit is not None and used is not None and remaining is None:
        remaining = max(limit - used, 0)
    elif limit is not None and remaining is not None and used is None:
        used = max(limit - remaining, 0)
    elif used is not None and remaining is not None and limit is None:
        limit = used + remaining
    return {
        'ok': ok, 'valid': valid, 'message': message, 'used': used,
        'limit': limit, 'remaining': remaining, 'unit': unit,
        'resets': resets, 'plan': plan,
    }


def _int(v: Any) -> Optional[int]:
    if v is None or isinstance(v, bool):
        return None
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _str(v: Any) -> Optional[str]:
    if v is None or v == '':
        return None
    return str(v)


def _get(d: Any, *path: str) -> Any:
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


# ---------------------------------------------------------------- parsers

def _parse_shodan(j: dict) -> dict:
    limits = j.get('usage_limits') or {}
    remaining = _int(j.get('query_credits'))
    limit = _int(limits.get('query_credits'))
    plan = _str(j.get('plan'))
    return _result(True, True, 'Shodan query credits', remaining=remaining,
                   limit=limit, unit='query credits', plan=plan)


def _parse_virustotal(j: dict) -> dict:
    d = _get(j, 'data', 'api_requests_daily', 'user') or {}
    used, allowed = _int(d.get('used')), _int(d.get('allowed'))
    return _result(True, True, 'VirusTotal daily API requests', used=used,
                   limit=allowed, unit='requests/day', resets='daily')


def _parse_hunter(j: dict) -> dict:
    data = j.get('data') or {}
    req = data.get('requests') or {}
    s = req.get('searches') or {}
    return _result(True, True, 'Hunter searches', used=_int(s.get('used')),
                   limit=_int(s.get('available')), unit='searches',
                   resets=_str(data.get('reset_date')),
                   plan=_str(data.get('plan_name')))


def _parse_fullhunt(j: dict) -> dict:
    c = j.get('user_credits') or {}
    used, limit = _int(c.get('credits_usage')), _int(c.get('total_credits_per_month'))
    remaining = _int(c.get('remaining_credits'))
    if limit is not None and remaining is not None and remaining > limit:
        limit = None  # vendor figures are inconsistent; derive from used + remaining
    return _result(True, True, 'FullHunt credits', used=used, limit=limit,
                   remaining=remaining, unit='credits')


def _parse_whoisxmlapi(j: dict) -> dict:
    products = j.get('data')
    if not isinstance(products, list):
        return _result(True, True, 'WhoisXML API key accepted', unit='credits')
    credits = [_int(p.get('credits')) for p in products if isinstance(p, dict)]
    credits = [c for c in credits if c is not None]
    return _result(True, True,
                   'WhoisXML API credits summed over %d product(s)' % len(credits),
                   remaining=sum(credits) if credits else None, unit='credits')


def _parse_hybrid_analysis(j: dict) -> dict:
    ok = bool(j.get('api_key'))
    return _result(ok, True if ok else None, 'Hybrid Analysis key accepted'
                   if ok else 'Unexpected response', unit='requests',
                   plan=_str(j.get('auth_level_name')))


def _parse_netlas(j: dict) -> dict:
    plan = j.get('plan') or {}
    key = j.get('api_key') or {}
    return _result(True, True, 'Netlas coin allowance (usage not exposed by the API)',
                   limit=_int(plan.get('coins')), unit='coins',
                   resets=_str(key.get('next_time_coins_will_be_updated')),
                   plan=_str(plan.get('name')))


def _parse_abuseipdb(headers: Dict[str, str]) -> dict:
    h = {str(k).lower(): v for k, v in headers.items()}
    resets = None
    ts = _int(h.get('x-ratelimit-reset'))
    if ts:
        resets = datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    return _result(True, True, 'AbuseIPDB daily checks (this check used one request)',
                   limit=_int(h.get('x-ratelimit-limit')),
                   remaining=_int(h.get('x-ratelimit-remaining')),
                   unit='requests/day', resets=resets)


def _parse_zoomeye(j: dict) -> dict:
    sub = (j.get('data') or {}).get('subscription') or {}
    if j.get('code') not in (None, 60000):
        return _result(False, None, 'ZoomEye: ' + (_str(j.get('message')) or 'request failed'))
    plan = _str(sub.get('plan'))
    return _result(True, True, 'ZoomEye key accepted. Searching also needs search credits, which the Free plan lacks',
                   remaining=_int(sub.get('points')), unit='points',
                   resets=_str(sub.get('end_date')), plan=plan)


def _parse_greynoise(j: dict) -> dict:
    return _result(True, True, 'GreyNoise key accepted (no usage counters exposed)',
                   unit='requests', resets=_str(j.get('expiration')),
                   plan=_str(j.get('plan')) or _str(j.get('offering')))


def _parse_ipinfo(j: dict) -> dict:
    r = j.get('requests') or {}
    if not r:
        return _result(True, True, 'IPinfo key accepted (no usage block)',
                       unit='requests/month')
    return _result(True, True, 'IPinfo monthly requests', used=_int(r.get('month')),
                   limit=_int(r.get('limit')), remaining=_int(r.get('remaining')),
                   unit='requests/month')


def _parse_alienvault(j: dict) -> dict:
    return _result(True, True, 'AlienVault OTX key accepted (no quota counters)',
                   unit='requests')


def _parse_govfiles(j: dict) -> dict:
    if 'balance' not in j:
        return _result(False, None, 'unexpected response format')
    extra = ' (overage allowed)' if j.get('overage_enabled') else ''
    return _result(True, True, 'GovFiles credit balance' + extra,
                   remaining=_int(j.get('balance')), unit='credits')


# ---------------------------------------------------------------- fetchers

def _http(url: str, headers: Optional[Dict[str, str]] = None) -> requests.Response:
    return requests.get(url, headers=headers or {}, timeout=TIMEOUT)


def _fetch_zoomeye(v):
    return requests.post('https://api.zoomeye.ai/v2/userinfo', headers={'API-KEY': v['api_key']},
                         json={}, timeout=TIMEOUT)


def _fetch_shodan(v):
    return _http('https://api.shodan.io/api-info?' + urlencode({'key': v['api_key']}))


def _fetch_virustotal(v):
    return _http('https://www.virustotal.com/api/v3/users/%s/overall_quotas'
                 % quote(v['api_key'], safe=''), {'x-apikey': v['api_key']})


def _fetch_hunter(v):
    return _http('https://api.hunter.io/v2/account?' + urlencode({'api_key': v['api_key']}))


def _fetch_fullhunt(v):
    return _http('https://fullhunt.io/api/v1/auth/status', {'X-API-KEY': v['api_key']})


def _fetch_whoisxmlapi(v):
    return _http('https://user.whoisxmlapi.com/user-service/account-balance?'
                 + urlencode({'apiKey': v['api_key']}))


def _fetch_hybrid_analysis(v):
    return _http('https://www.hybrid-analysis.com/api/v2/key/current',
                 {'api-key': v['api_key'], 'user-agent': 'Falcon Sandbox'})


def _fetch_netlas(v):
    return _http('https://app.netlas.io/api/users/current/',
                 {'Authorization': 'Bearer ' + v['api_key']})


def _fetch_abuseipdb(v):
    return _http('https://api.abuseipdb.com/api/v2/check?ipAddress=127.0.0.1',
                 {'Key': v['api_key'], 'Accept': 'application/json'})


def _fetch_greynoise(v):
    return _http('https://api.greynoise.io/ping', {'key': v['api_key']})


def _fetch_ipinfo(v):
    return _http('https://ipinfo.io/me?' + urlencode({'token': v['api_key']}))


def _fetch_alienvault(v):
    return _http('https://otx.alienvault.com/api/v1/user/me',
                 {'X-OTX-API-KEY': v['api_key']})


def _fetch_govfiles(v):
    return _http('https://api.govfiles.dev/v2/credits', {'X-API-Key': v['api_key']})


def _runner(fetch: Callable, parse: Callable, use_headers: bool = False) -> Callable:
    def run(values: Dict[str, str]) -> dict:
        try:
            resp = fetch(values)
        except Exception as e:  # never include str(e): it may contain the URL/key
            return _result(False, None, 'network error (%s)' % type(e).__name__)
        status = resp.status_code
        if status in (401, 403):
            return _result(False, False, 'API key rejected (HTTP %d)' % status)
        if status == 429:
            return _result(False, None, 'rate limited')
        if status != 200:
            return _result(False, None, 'unexpected HTTP status %d' % status)
        try:
            if use_headers:
                return parse(resp.headers)
            data = resp.json()
            if not isinstance(data, dict):
                return _result(False, None, 'unexpected response format')
            return parse(data)
        except Exception:
            return _result(False, None, 'could not parse vendor response')
    return run


# Checkers that spend one of the vendor's own API calls, so they are never run automatically.
COSTS_CALL = {'sfp_abuseipdb'}

PROVIDERS: Dict[str, Provider] = {
    'sfp_shodan': Provider(['api_key'], _runner(_fetch_shodan, _parse_shodan)),
    'sfp_virustotal': Provider(['api_key'], _runner(_fetch_virustotal, _parse_virustotal)),
    'sfp_hunter': Provider(['api_key'], _runner(_fetch_hunter, _parse_hunter)),
    'sfp_fullhunt': Provider(['api_key'], _runner(_fetch_fullhunt, _parse_fullhunt)),
    'sfp_whoisxmlapi': Provider(['api_key'], _runner(_fetch_whoisxmlapi, _parse_whoisxmlapi)),
    'sfp_hybrid_analysis': Provider(['api_key'], _runner(_fetch_hybrid_analysis, _parse_hybrid_analysis)),
    'sfp_netlas': Provider(['api_key'], _runner(_fetch_netlas, _parse_netlas)),
    'sfp_abuseipdb': Provider(['api_key'], _runner(_fetch_abuseipdb, _parse_abuseipdb, True)),
    'sfp_greynoise': Provider(['api_key'], _runner(_fetch_greynoise, _parse_greynoise)),
    'sfp_ipinfo': Provider(['api_key'], _runner(_fetch_ipinfo, _parse_ipinfo)),
    'sfp_zoomeye': Provider(['api_key'], _runner(_fetch_zoomeye, _parse_zoomeye)),
    'sfp_alienvault': Provider(['api_key'], _runner(_fetch_alienvault, _parse_alienvault)),
    'sfp_govfiles': Provider(['api_key'], _runner(_fetch_govfiles, _parse_govfiles)),
}


def check(module: str, values: Dict[str, str]) -> dict:
    """Run the quota/key checker for a module. Never raises."""
    try:
        prov = PROVIDERS.get(module)
        if prov is None:
            return _result(False, None, 'No quota checker for this module')
        values = values or {}
        for o in prov.opts:
            if not str(values.get(o) or '').strip():
                return _result(False, None, 'Missing required option: %s' % o)
        return prov.check({o: str(values[o]).strip() for o in prov.opts})
    except Exception as e:
        return _result(False, None, 'checker error (%s)' % type(e).__name__)
