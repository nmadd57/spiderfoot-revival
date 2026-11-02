"""Web search through the user's SearXNG instance.

The Google Custom Search JSON API is closed to new customers and ends on
2027-01-01, and Microsoft retired the Bing Search API in August 2025, so those modules
were removed. Modules that search the web (``sfp_pastebin``, ``sfp_onioncity``,
``sfp_socialprofiles``) call ``SpiderFoot.webSearch``, which calls :func:`search` here when
a SearXNG instance is set up on the ``sfp_searxng`` module (Settings -> Modules -> SearXNG).

The instance URL, auth header, TLS verification and query defaults are read from the
``sfp_searxng`` module's own settings, so there is one place to configure it.
"""

import json
import re
import urllib.parse

MODULE = 'sfp_searxng'


def parse_header(value) -> dict:
    """'Name: value' -> {'Name': 'value'}; empty or malformed -> {}."""
    name, sep, val = str(value or '').partition(':')
    if not sep or not name.strip() or not val.strip():
        return {}
    return {name.strip(): val.strip()}


_LOGIN = re.compile(r'oauth2|sign[ _-]?in|log[ _-]?in|single sign|sso|authelia|authentik|keycloak|pocket ?id', re.I)


def login_page(content) -> bool:
    """True if a reply body looks like a sign-in page from an SSO/auth proxy rather than SearXNG."""
    return bool(content) and bool(_LOGIN.search(str(content)[:4000]))


SSO_HINT = ("The URL is behind a login (SSO) proxy, which answers API calls with a sign-in page. Point the SearXNG "
            "module at an address that skips the login, such as the instance's own port on your LAN, or have "
            "the proxy skip authentication for this host.")


def config(sf) -> dict:
    """The SearXNG module's settings if an instance URL is set, else ``{}``."""
    try:
        opts = ((sf.opts or {}).get('__modules__') or {}).get(MODULE, {}).get('opts') or {}
    except AttributeError:
        return {}
    url = str(opts.get('instance_url') or '').strip().rstrip('/')
    if not url:
        return {}
    if '://' not in url:
        url = 'http://' + url
    return {**opts, 'instance_url': url}


def available(sf) -> bool:
    return bool(config(sf))


def search(sf, query: str, pages: int = 0, timeout: int = 0):
    """Run ``query`` on the configured instance.

    Returns ``{"urls": [...], "webSearchUrl": str, "results": [...]}`` (URLs de-duplicated,
    in rank order), or None when no instance is set up, the instance cannot be used, or there
    were no results. Problems are reported once through ``sf.error``.
    """
    cfg = config(sf)
    if not cfg or not query:
        return None
    base = cfg['instance_url']
    pages = max(1, int(pages or cfg.get('pages') or 1))
    timeout = max(30, int(timeout or 0))
    headers = {'Accept': 'application/json', **parse_header(cfg.get('auth_header'))}
    useragent = (sf.opts or {}).get('_useragent') or 'SpiderFoot'

    seen, results = set(), []
    for pageno in range(1, pages + 1):
        params = {'q': query, 'format': 'json', 'pageno': pageno}
        for opt in ('categories', 'engines', 'language', 'time_range'):
            val = str(cfg.get(opt) or '').strip()
            if val:
                params[opt] = val
        params['safesearch'] = int(cfg.get('safesearch') or 0)
        res = sf.fetchUrl(f"{base}/search?" + urllib.parse.urlencode(params), timeout=timeout, headers=headers,
                          useragent=useragent, verify=bool(cfg.get('verify_ssl', True)))
        code = str(res.get('code'))
        if code in ('401', '403', '407') and login_page(res.get('content')):
            sf.error(f"SearXNG at {base} answered HTTP {code} with a sign-in page. {SSO_HINT}")
            return None
        if code == '403':
            sf.error("SearXNG returned HTTP 403: JSON output is disabled (add 'json' to search.formats in settings.yml) "
                     "or a proxy in front of the instance blocked the request.")
            return None
        if code in ('401', '407'):
            sf.error(f"SearXNG instance requires authentication (HTTP {code}); set the auth header on the SearXNG module.")
            return None
        if code == '429':
            sf.error("SearXNG rate limited the request (HTTP 429). Allow this client's IP in the instance's limiter settings.")
            return None
        if code == 'None':
            sf.error(f"Could not reach the SearXNG instance at {base}: {res.get('status')}")
            return None
        if code != '200' or not res.get('content'):
            break
        try:
            data = json.loads(res['content'])
        except ValueError:
            if login_page(res.get('content')):
                sf.error(f"SearXNG at {base} returned a sign-in page instead of JSON. {SSO_HINT}")
            else:
                sf.error("SearXNG did not return JSON: check the instance URL and that no bot-protection page "
                         "sits in front of it.")
            return None
        page = [r for r in (data.get('results') or []) if isinstance(r, dict) and r.get('url')]
        new = [r for r in page if r['url'] not in seen]
        if not new:
            break
        for r in new:
            seen.add(r['url'])
            results.append(r)
    if not results:
        return None
    return {
        'urls': [r['url'] for r in results],
        'webSearchUrl': f"{base}/search?" + urllib.parse.urlencode({'q': query}),
        'results': [{'url': r['url'], 'title': r.get('title') or '', 'content': str(r.get('content') or '')[:300]}
                    for r in results],
    }
