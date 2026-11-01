# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_searxng
# Purpose:      Search a self-hosted SearXNG metasearch instance: site: searches
#               for hosts/URLs on the target, and exact-phrase searches for
#               names, emails, usernames and phone numbers.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


def parse_header(value: str):
    """'Name: value' -> {'Name': 'value'}; empty or malformed -> {}."""
    name, sep, val = str(value or "").partition(":")
    if not sep or not name.strip() or not val.strip():
        return {}
    return {name.strip(): val.strip()}


class sfp_searxng(SpiderFootPlugin):

    meta = {
        'name': "SearXNG (self-hosted)",
        'summary': "Search your own SearXNG metasearch instance: site: searches for URLs and hosts on the "
                   "target, and exact-phrase searches for names, businesses, emails, usernames and phone numbers.",
        'flags': [],
        'pricing': 'local',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        # Shown on the module's card in Settings > API Keys (there is no other editor for module options)
        'connectionOpts': ['instance_url', 'auth_header', 'verify_ssl', 'engines'],
        'dataSource': {
            'website': "https://docs.searxng.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://docs.searxng.org/dev/search_api.html",
                "https://docs.searxng.org/admin/settings/settings_search.html",
            ],
            'favIcon': "https://docs.searxng.org/_static/searxng-wordmark.svg",
            'description': "SearXNG is a self-hosted metasearch engine that queries many search engines at once "
                           "and merges the results. This module uses its JSON API, which must be enabled by "
                           "listing 'json' under search.formats in the instance's settings.yml.",
        }
    }

    opts = {
        'instance_url': '',
        'auth_header': '',
        'verify_ssl': True,
        'categories': 'general',
        'engines': '',
        'language': 'all',
        'safesearch': 0,
        'time_range': '',
        'pages': 2,
        'site_search': True,
        'phrase_search': True,
    }

    optdescs = {
        'instance_url': "Base URL of your SearXNG instance, e.g. http://searxng:8080 or https://searx.example.com.",
        'auth_header': "Optional header sent with every request, as 'Name: value' (e.g. 'Authorization: Basic ...' "
                       "for an instance behind a reverse proxy that requires auth).",
        'verify_ssl': "Verify the instance's TLS certificate (turn off for self-signed certificates).",
        'categories': "Comma-separated SearXNG categories to search (e.g. general,it,news).",
        'engines': "Comma-separated engines to use instead of the instance's defaults (e.g. google,bing,duckduckgo).",
        'language': "Search language code, or 'all'.",
        'safesearch': "Safe search level: 0 (off), 1 (moderate), 2 (strict).",
        'time_range': "Restrict results to the last 'day', 'month' or 'year'; empty for any time.",
        'pages': "Number of result pages to fetch per query.",
        'site_search': "Run site:<host> searches for domains and hostnames to find URLs and subdomains.",
        'phrase_search': "Run exact-phrase searches for names, businesses, emails, usernames and phone numbers.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.opts = dict(self.opts)  # per-instance copy; don't mutate the class defaults
        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["INTERNET_NAME", "DOMAIN_NAME", "COMPANY_NAME", "HUMAN_NAME", "EMAILADDR", "USERNAME",
                "PHONE_NUMBER"]

    def producedEvents(self):
        return ["LINKED_URL_INTERNAL", "LINKED_URL_EXTERNAL", "INTERNET_NAME", "RAW_RIR_DATA"]

    # ------------------------------------------------------------------ HTTP

    def baseUrl(self) -> str:
        url = str(self.opts.get('instance_url') or '').strip().rstrip("/")
        if url and "://" not in url:
            url = "http://" + url
        return url

    def search(self, query: str, pageno: int = 1):
        """One page of SearXNG JSON results, or None on error."""
        params = {'q': query, 'format': "json", 'pageno': pageno}
        for opt in ('categories', 'engines', 'language', 'time_range'):
            val = str(self.opts.get(opt) or '').strip()
            if val:
                params[opt] = val
        params['safesearch'] = int(self.opts.get('safesearch') or 0)

        res = self.sf.fetchUrl(
            f"{self.baseUrl()}/search?" + urllib.parse.urlencode(params),
            timeout=max(30, int(self.opts.get('_fetchtimeout') or 0)),
            headers={'Accept': "application/json", **parse_header(self.opts.get('auth_header'))},
            useragent=self.opts['_useragent'],
            verify=bool(self.opts.get('verify_ssl', True)),
        )
        code = str(res.get('code'))
        if code == "403":
            self.error("SearXNG refused JSON output (HTTP 403). Add 'json' to search.formats in the "
                       "instance's settings.yml.")
            self.errorState = True
            return None
        if code in ("401", "407"):
            self.error(f"SearXNG instance requires authentication (HTTP {code}); set the auth header option.")
            self.errorState = True
            return None
        if code == "429":
            self.error("SearXNG rate limited the request (HTTP 429); disable the limiter for this client.")
            return None
        if code == "None":
            self.error(f"Could not reach the SearXNG instance at {self.baseUrl()}: {res.get('status')}")
            self.errorState = True
            return None
        if code != "200" or not res.get('content'):
            self.debug(f"SearXNG returned HTTP {code} for {query}")
            return None
        try:
            data = json.loads(res['content'])
        except Exception:
            # An HTML page usually means a login page from a reverse proxy in front of SearXNG
            self.error("SearXNG did not return JSON; check the instance URL and any proxy authentication.")
            self.errorState = True
            return None
        return data if isinstance(data, dict) else None

    def searchAll(self, query: str) -> list:
        """Results from every configured page, de-duplicated by URL."""
        seen, out = set(), []
        unresponsive = set()
        for pageno in range(1, max(1, int(self.opts.get('pages') or 1)) + 1):
            if self.checkForStop() or self.errorState:
                break
            data = self.search(query, pageno)
            if not data:
                break
            for eng in data.get('unresponsive_engines') or []:
                unresponsive.add(str(eng[0] if isinstance(eng, (list, tuple)) and eng else eng))
            page = [r for r in data.get('results') or [] if isinstance(r, dict) and r.get('url')]
            new = [r for r in page if r['url'] not in seen]
            if not new:
                break
            for r in new:
                seen.add(r['url'])
                out.append(r)
        if unresponsive:
            self.debug(f"SearXNG engines that did not respond for {query}: {', '.join(sorted(unresponsive))}")
        return out

    # ------------------------------------------------------------- emitting

    def _emit(self, etype: str, data: str, source):
        key = f"{etype}:{data}"
        if key in self.results:
            return
        self.results[key] = True
        self.notifyListeners(SpiderFootEvent(etype, data, self.__name__, source))

    @staticmethod
    def summary(query: str, results: list) -> str:
        return json.dumps({
            'source': "SearXNG",
            'query': query,
            'results': [{
                'title': r.get('title'),
                'url': r.get('url'),
                'snippet': str(r.get('content') or '')[:300] or None,
                'engines': sorted(r.get('engines') or ([r['engine']] if r.get('engine') else [])),
                'published': r.get('publishedDate'),
            } for r in results],
        }, ensure_ascii=False, default=str)

    def siteSearch(self, host: str, event):
        results = self.searchAll(f"site:{host}")
        internal = []
        for r in results:
            url = r['url']
            fqdn = (self.sf.urlFQDN(url) or "").lower()
            if fqdn != host and not fqdn.endswith("." + host):
                continue
            internal.append(r)
            self._emit("LINKED_URL_INTERNAL", url, event)
            if fqdn != host and self.getTarget().matches(fqdn, includeChildren=True):
                self._emit("INTERNET_NAME", fqdn, event)
        if internal:
            self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", self.summary(f"site:{host}", internal),
                                                 self.__name__, event))

    def phraseSearch(self, phrase: str, event):
        query = '"' + phrase.replace('"', '') + '"'
        results = self.searchAll(query)
        if not results:
            return
        for r in results:
            url = r['url']
            fqdn = (self.sf.urlFQDN(url) or "").lower()
            if fqdn and self.getTarget().matches(fqdn, includeChildren=True):
                self._emit("LINKED_URL_INTERNAL", url, event)
            else:
                self._emit("LINKED_URL_EXTERNAL", url, event)
        self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", self.summary(query, results), self.__name__, event))

    # ---------------------------------------------------------------- event

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return
        if not self.baseUrl():
            self.error("You enabled sfp_searxng but did not set the SearXNG instance URL.")
            self.errorState = True
            return

        site = eventName in ("INTERNET_NAME", "DOMAIN_NAME")
        # The target domain arrives as both INTERNET_NAME and DOMAIN_NAME; search it once
        key = f"site:{eventData.lower().rstrip('.')}" if site else f"phrase:{eventData.lower()}"
        if key in self.results:
            self.debug(f"Skipping {eventData}, already searched.")
            return
        self.results[key] = True

        self.debug(f"Received event, {eventName}, from {event.module}")

        if site:
            if self.opts.get('site_search'):
                self.siteSearch(eventData.lower().rstrip("."), event)
        elif self.opts.get('phrase_search'):
            self.phraseSearch(eventData, event)

# End of sfp_searxng class
