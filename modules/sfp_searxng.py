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
import math
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
        'connectionOpts': ['instance_url', 'auth_header', 'verify_ssl', 'engines',
                           'embeddings_url', 'embeddings_model', 'embeddings_apikey', 'min_similarity'],
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
                           "listing 'json' under search.formats in the instance's settings.yml. Optionally, an "
                           "OpenAI-compatible embeddings API (llama.cpp, llama-swap, Ollama, vLLM, LocalAI, OpenAI) "
                           "ranks phrase-search results by how relevant they are to the target.",
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
        'embeddings_url': '',
        'embeddings_model': '',
        'embeddings_apikey': '',
        'min_similarity': 0,
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
        'embeddings_url': "Optional OpenAI-compatible embeddings API base URL (e.g. http://llama-swap:8080/v1 or "
                          "https://api.openai.com/v1) used to rank phrase-search results by relevance to the "
                          "target. Empty disables ranking.",
        'embeddings_model': "Embedding model name for the embeddings API (e.g. nomic-embed-text-v1.5, "
                            "text-embedding-3-small).",
        'embeddings_apikey': "API key for the embeddings API, if it needs one (sent as a Bearer token).",
        'min_similarity': "Drop phrase-search results whose similarity to the search (0-100, cosine x 100) is "
                          "below this. 0 keeps every result and only ranks them. Good values depend on the model; "
                          "check the similarity scores in the raw results first.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.embeddingsFailed = False
        self.siteSearched = set()
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
            self.error("SearXNG returned HTTP 403: JSON output is disabled (add 'json' to search.formats in "
                       "settings.yml) or a proxy in front of the instance blocked the request.")
            self.errorState = True
            return None
        if code in ("401", "407"):
            self.error(f"SearXNG instance requires authentication (HTTP {code}); set the auth header option.")
            self.errorState = True
            return None
        if code == "429":
            self.error("SearXNG rate limited the request (HTTP 429). Public instances block API clients; on your "
                       "own instance, disable the limiter or allow this client's IP (pass_ip in limiter.toml).")
            self.errorState = True
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
            # An HTML page usually means a reverse-proxy login page or a bot-protection challenge
            self.error("SearXNG did not return JSON: check the instance URL, any proxy authentication, and "
                       "that no bot-protection page (e.g. Anubis) sits in front of it.")
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

    # ----------------------------------------------------------- embeddings

    def embeddingsEndpoint(self) -> str:
        url = str(self.opts.get('embeddings_url') or '').strip().rstrip("/")
        if not url:
            return ""
        if "://" not in url:
            url = "http://" + url
        return url if url.endswith("/embeddings") else url + "/embeddings"

    def embed(self, texts: list):
        """Embedding vectors for texts via an OpenAI-compatible /embeddings API, or None."""
        vectors = []
        headers = {'Content-Type': "application/json", 'Accept': "application/json"}
        if str(self.opts.get('embeddings_apikey') or '').strip():
            headers['Authorization'] = "Bearer " + str(self.opts['embeddings_apikey']).strip()
        for start in range(0, len(texts), 32):
            batch = texts[start:start + 32]
            body = {'input': batch}
            if str(self.opts.get('embeddings_model') or '').strip():
                body['model'] = str(self.opts['embeddings_model']).strip()
            res = self.sf.fetchUrl(self.embeddingsEndpoint(), postData=json.dumps(body), headers=headers,
                                   timeout=max(60, int(self.opts.get('_fetchtimeout') or 0)),
                                   useragent=self.opts['_useragent'], noLog=True)
            try:
                data = json.loads(res.get('content') or "") if str(res.get('code')) == "200" else None
                rows = sorted(data['data'], key=lambda d: d.get('index', 0))
                got = [r['embedding'] for r in rows]
                if len(got) != len(batch) or not all(isinstance(v, list) and v for v in got):
                    raise ValueError("wrong number of embeddings")
            except Exception:
                detail = str(res.get('content') or res.get('status') or '')[:200]
                self.error(f"Embeddings API at {self.embeddingsEndpoint()} failed (HTTP {res.get('code')}): "
                           f"{detail}. Results will not be ranked.")
                self.embeddingsFailed = True
                return None
            vectors.extend(got)
        return vectors

    @staticmethod
    def cosine(a: list, b: list) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        return dot / (na * nb) if na and nb else 0.0

    def searchContext(self, phrase: str) -> str:
        """What a relevant result should be about: the phrase, plus the scan target if different."""
        try:
            target = str(self.getTarget().targetValue or '')
        except Exception:
            target = ''
        if target and target.lower() not in phrase.lower() and phrase.lower() not in target.lower():
            return f"{phrase} ({target})"
        return phrase

    def rank(self, phrase: str, results: list):
        """Sort results by similarity to the search context; returns (kept, dropped, context)."""
        if not self.embeddingsEndpoint() or self.embeddingsFailed or not results:
            return results, [], None
        context = self.searchContext(phrase)
        texts = [context] + [f"{r.get('title') or ''}. {str(r.get('content') or '')[:1000]}".strip()
                             for r in results]
        vectors = self.embed(texts)
        if not vectors:
            return results, [], None
        for r, vec in zip(results, vectors[1:]):
            r['similarity'] = round(100 * self.cosine(vectors[0], vec), 1)
        results = sorted(results, key=lambda r: r['similarity'], reverse=True)
        floor = max(0, min(100, int(self.opts.get('min_similarity') or 0)))
        kept = [r for r in results if r['similarity'] >= floor]
        return kept, [r for r in results if r['similarity'] < floor], context

    def isTargetHost(self, fqdn: str) -> bool:
        """Whether a host belongs to the scan target.

        SpiderFootTarget.matches() is True for anything when the target is a name
        (person, business, username, phone), so only trust it for host-like targets.
        """
        target = self.getTarget()
        host_types = ("INTERNET_NAME", "EMAILADDR", "IP_ADDRESS", "IPV6_ADDRESS", "NETBLOCK_OWNER", "NETBLOCKV6_OWNER")
        if not fqdn or target.targetType not in host_types:
            return False
        return target.matches(fqdn, includeChildren=True)

    # ------------------------------------------------------------- emitting

    def _emit(self, etype: str, data: str, source):
        key = f"{etype}:{data}"
        if key in self.results:
            return
        self.results[key] = True
        self.notifyListeners(SpiderFootEvent(etype, data, self.__name__, source))

    @staticmethod
    def summary(query: str, results: list, context: str = None, dropped: int = 0) -> str:
        data = {
            'source': "SearXNG",
            'query': query,
            'results': [{
                'title': r.get('title'),
                'url': r.get('url'),
                'snippet': str(r.get('content') or '')[:300] or None,
                'engines': sorted(r.get('engines') or ([r['engine']] if r.get('engine') else [])),
                'published': r.get('publishedDate'),
                **({'similarity': r['similarity']} if 'similarity' in r else {}),
            } for r in results],
        }
        if context:
            data['ranked_against'] = context
            data['dropped_below_min_similarity'] = dropped
        return json.dumps(data, ensure_ascii=False, default=str)

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
        results, dropped, context = self.rank(phrase.replace('"', ''), results)
        if dropped:
            best = max(r['similarity'] for r in dropped)
            self.info(f"SearXNG: dropped {len(dropped)} of {len(dropped) + len(results)} results for {query} "
                      f"below min_similarity {self.opts.get('min_similarity')} (best dropped: {best})")
        if not results:
            return
        for r in results:
            url = r['url']
            fqdn = (self.sf.urlFQDN(url) or "").lower()
            if self.isTargetHost(fqdn):
                self._emit("LINKED_URL_INTERNAL", url, event)
            else:
                self._emit("LINKED_URL_EXTERNAL", url, event)
        self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", self.summary(query, results, context, len(dropped)),
                                             self.__name__, event))

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
            if not self.opts.get('site_search'):
                return
            host = eventData.lower().rstrip(".")
            # site:example.com already covers its subdomains, including the ones this
            # module just reported, so don't search them again (that would also recurse)
            if event.module == self.__name__ or any(host.endswith("." + h) for h in self.siteSearched):
                self.debug(f"Skipping site:{host}, covered by an earlier site: search.")
                return
            self.siteSearched.add(host)
            self.siteSearch(host, event)
        elif self.opts.get('phrase_search'):
            self.phraseSearch(eventData, event)

# End of sfp_searxng class
