# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_vane
# Purpose:      Ask a self-hosted Vane (formerly Perplexica) AI answering engine
#               for a cited summary of the scan target.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


def parse_header(value: str):
    """'Name: value' -> {'Name': 'value'}; empty or malformed -> {}."""
    name, sep, val = str(value or "").partition(":")
    if not sep or not name.strip() or not val.strip():
        return {}
    return {name.strip(): val.strip()}


# What to ask Vane about each kind of target
QUESTIONS = {
    'COMPANY_NAME': (
        'Give an OSINT profile of the organisation "{v}": what it does, headquarters and other locations, '
        'founders and key executives, parent company and subsidiaries, official website and domains, and any '
        'notable lawsuits, data breaches, regulatory actions or sanctions. Cite a source for every fact.'),
    'HUMAN_NAME': (
        'Give an OSINT profile of the person "{v}": who they are, current and past employers and roles, '
        'locations, public social media or professional profiles, and any notable news. If several people share '
        'this name, list them separately. Cite a source for every fact.'),
    'DOMAIN_NAME': (
        'Who owns and operates the domain {v}? Describe the organisation behind it, what the site is used for, '
        'related domains and brands, and any reported security incidents, phishing or malware associated with '
        'it. Cite a source for every fact.'),
    'USERNAME': (
        'What is publicly known about the online username "{v}": which platforms it appears on, who appears to '
        'use it, and any notable activity. Cite a source for every fact.'),
    'EMAILADDR': (
        'What is publicly known about the email address {v}: who or what organisation uses it and where it '
        'appears publicly. Cite a source for every fact.'),
}


class sfp_vane(SpiderFootPlugin):

    meta = {
        'name': "Vane AI Search (self-hosted)",
        'summary': "Ask your own Vane (formerly Perplexica) instance for a cited, AI-written profile of the scan "
                   "target, and collect the web sources it used.",
        'flags': ["slow"],
        'pricing': 'local',
        'useCases': ["Investigate", "Passive"],
        'categories': ["Search Engines"],
        # Shown on the module's card in Settings > API Keys (there is no other editor for module options)
        'connectionOpts': ['instance_url', 'auth_header', 'verify_ssl', 'chat_provider', 'chat_model',
                           'embedding_provider', 'embedding_model', 'optimization_mode'],
        'dataSource': {
            'website': "https://github.com/ItzCrazyKns/Vane",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://github.com/ItzCrazyKns/Vane/blob/master/docs/API/SEARCH.md",
            ],
            'description': "Vane is a self-hosted AI answering engine: it searches the web through SearXNG and has "
                           "an LLM (local, e.g. Ollama, or a cloud provider) write an answer citing its sources. "
                           "Answers are LLM-generated and can be wrong; check the cited sources.",
        }
    }

    opts = {
        'instance_url': '',
        'auth_header': '',
        'verify_ssl': True,
        'chat_provider': '',
        'chat_model': '',
        'embedding_provider': '',
        'embedding_model': '',
        'optimization_mode': 'balanced',
        'sources': 'web',
        'target_only': True,
        'timeout': 300,
    }

    optdescs = {
        'instance_url': "Base URL of your Vane instance, e.g. http://vane:3000 or https://vane.example.com.",
        'auth_header': "Optional header sent with every request, as 'Name: value', for an instance behind an "
                       "authenticating reverse proxy.",
        'verify_ssl': "Verify the instance's TLS certificate (turn off for self-signed certificates).",
        'chat_provider': "Chat model provider: its name or ID as listed by Vane's /api/providers. "
                         "Empty uses the first provider that has a chat model.",
        'chat_model': "Chat model key (e.g. llama3.1:8b, gpt-4o-mini). Empty uses the provider's first chat model.",
        'embedding_provider': "Embedding model provider name or ID. Empty uses the first provider with an "
                              "embedding model.",
        'embedding_model': "Embedding model key (e.g. nomic-embed-text-v1.5). Empty uses the provider's first "
                           "embedding model.",
        'optimization_mode': "Vane optimisation mode: speed, balanced or quality.",
        'sources': "Comma-separated Vane search sources: web, academic, discussions.",
        'target_only': "Only ask about the scan target itself, not every name or domain other modules find "
                       "(each question runs an LLM and can take minutes).",
        'timeout': "Seconds to wait for an answer.",
    }

    results = None
    errorState = False
    models = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.models = None
        self.opts = dict(self.opts)  # per-instance copy; don't mutate the class defaults
        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return list(QUESTIONS.keys())

    def producedEvents(self):
        return ["DESCRIPTION_ABSTRACT", "LINKED_URL_EXTERNAL", "LINKED_URL_INTERNAL", "RAW_RIR_DATA"]

    # ------------------------------------------------------------------ HTTP

    def baseUrl(self) -> str:
        url = str(self.opts.get('instance_url') or '').strip().rstrip("/")
        if url and "://" not in url:
            url = "http://" + url
        return url

    def _call(self, path: str, body: dict = None, timeout: int = 30):
        res = self.sf.fetchUrl(
            self.baseUrl() + path,
            postData=json.dumps(body) if body is not None else None,
            timeout=timeout,
            headers={'Content-Type': "application/json", 'Accept': "application/json",
                     **parse_header(self.opts.get('auth_header'))},
            useragent=self.opts['_useragent'],
            verify=bool(self.opts.get('verify_ssl', True)),
        )
        code = str(res.get('code'))
        if code == "None":
            self.error(f"Could not reach the Vane instance at {self.baseUrl()}: {res.get('status')}")
            self.errorState = True
            return None
        if code in ("401", "403", "407"):
            self.error(f"Vane instance refused the request (HTTP {code}); check the auth header option.")
            self.errorState = True
            return None
        try:
            data = json.loads(res.get('content') or "")
        except Exception:
            self.error(f"Vane did not return JSON from {path} (HTTP {code}); check the instance URL.")
            self.errorState = True
            return None
        if code != "200":
            detail = data.get('message') if isinstance(data, dict) else None
            self.error(f"Vane {path} failed (HTTP {code}): {detail or 'no details'}")
            return None
        return data

    @staticmethod
    def _pick(providers: list, kind: str, want_provider: str, want_model: str):
        """Choose (providerId, modelKey) for kind 'chatModels' or 'embeddingModels'."""
        want_provider = (want_provider or "").strip().lower()
        want_model = (want_model or "").strip()
        for p in providers:
            if want_provider and want_provider not in (str(p.get('id', '')).lower(), str(p.get('name', '')).lower()):
                continue
            keys = [m.get('key') for m in p.get(kind) or [] if isinstance(m, dict) and m.get('key')]
            if want_model:
                if want_model in keys:
                    return p.get('id'), want_model
                continue
            if keys:
                return p.get('id'), keys[0]
        return None

    def resolveModels(self):
        """Look up the chat and embedding models to use, once per scan."""
        if self.models is not None:
            return self.models or None
        data = self._call("/api/providers")
        providers = (data or {}).get('providers') or []
        chat = self._pick(providers, 'chatModels', self.opts.get('chat_provider'), self.opts.get('chat_model'))
        emb = self._pick(providers, 'embeddingModels', self.opts.get('embedding_provider'),
                         self.opts.get('embedding_model'))
        if data is not None and (not chat or not emb):
            available = {p.get('name'): {'chat': [m.get('key') for m in p.get('chatModels') or []],
                                         'embedding': [m.get('key') for m in p.get('embeddingModels') or []]}
                         for p in providers}
            self.error(f"Vane has no matching {'chat' if not chat else 'embedding'} model for the configured "
                       f"provider/model options. Available: {json.dumps(available)}")
            self.errorState = True
        self.models = (chat, emb) if chat and emb else ()
        return self.models or None

    def ask(self, question: str):
        models = self.resolveModels()
        if not models:
            return None
        (chat_pid, chat_key), (emb_pid, emb_key) = models
        mode = str(self.opts.get('optimization_mode') or 'balanced').strip().lower()
        sources = [s.strip().lower() for s in str(self.opts.get('sources') or 'web').split(",") if s.strip()]
        return self._call("/api/search", {
            'chatModel': {'providerId': chat_pid, 'key': chat_key},
            'embeddingModel': {'providerId': emb_pid, 'key': emb_key},
            'optimizationMode': mode if mode in ("speed", "balanced", "quality") else "balanced",
            'sources': [s for s in sources if s in ("web", "academic", "discussions")] or ["web"],
            'query': question,
            'history': [],
            'stream': False,
        }, timeout=max(60, int(self.opts.get('timeout') or 300)))

    # ---------------------------------------------------------------- event

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return
        if not self.baseUrl():
            self.error("You enabled sfp_vane but did not set the Vane instance URL.")
            self.errorState = True
            return
        if self.opts.get('target_only') and event.module != "SpiderFoot UI":
            self.debug(f"Skipping {eventData} from {event.module}: only the scan target is sent to Vane.")
            return

        key = f"{eventName}:{eventData.lower()}"
        if key in self.results:
            return
        self.results[key] = True

        self.debug(f"Received event, {eventName}, from {event.module}")

        question = QUESTIONS[eventName].format(v=eventData)
        answer = self.ask(question)
        if not answer or self.checkForStop():
            return

        message = str(answer.get('message') or '').strip()
        sources = []
        for src in answer.get('sources') or []:
            meta = (src or {}).get('metadata') or {}
            url = str(meta.get('url') or '').strip()
            if url.startswith(("http://", "https://")) and url not in [s['url'] for s in sources]:
                sources.append({'title': meta.get('title'), 'url': url})

        if not message:
            self.info(f"Vane returned no answer for {eventData}")
            return

        refs = "\n".join(f"[{i}] {s['title'] or ''} {s['url']}".strip() for i, s in enumerate(sources, 1))
        text = f"Vane AI summary (LLM-generated; verify against the sources):\n\n{message}"
        if refs:
            text += f"\n\nSources:\n{refs}"
        self.notifyListeners(SpiderFootEvent("DESCRIPTION_ABSTRACT", text, self.__name__, event))
        self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", json.dumps({
            'source': "Vane",
            'question': question,
            'answer': message,
            'sources': sources,
        }, ensure_ascii=False), self.__name__, event))

        for s in sources:
            fqdn = (self.sf.urlFQDN(s['url']) or "").lower()
            etype = "LINKED_URL_INTERNAL" if fqdn and self.getTarget().matches(fqdn, includeChildren=True) \
                else "LINKED_URL_EXTERNAL"
            if f"{etype}:{s['url']}" not in self.results:
                self.results[f"{etype}:{s['url']}"] = True
                self.notifyListeners(SpiderFootEvent(etype, s['url'], self.__name__, event))

# End of sfp_vane class
