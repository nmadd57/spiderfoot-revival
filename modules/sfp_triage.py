# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_triage
# Purpose:      Find malware sandbox reports (Hatching Triage / tria.ge) that
#               reference the target's IPs and domains.
# -------------------------------------------------------------------------------

import json
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_triage(SpiderFootPlugin):

    meta = {
        'name': "Tria.ge",
        'summary': "Search Hatching Triage (tria.ge) malware sandbox reports for ones that contacted the target's IPs or domains.",
        'flags': ["apikey"],
        'pricing': 'free_key',
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://tria.ge/",
            'model': "FREE_AUTH_LIMITED",
            'references': ["https://tria.ge/docs/cloud-api/"],
            'apiKeyInstructions': [
                "Visit https://tria.ge/ and sign up for a free account",
                "Open Account > API",
                "Copy your API key",
            ],
            'description': "Triage is a malware analysis sandbox. The free public cloud lets researchers "
                           "search reports by network indicators (domain, IP) and read their scores.",
        }
    }

    opts = {
        'api_key': '',
        'minscore': 7,
        'maxsamples': 5,
        'checkaffiliates': True,
        'delay': 1.0,
    }

    optdescs = {
        'api_key': "Tria.ge API key.",
        'minscore': "Minimum sandbox score (1-10) a report needs to be reported as malicious.",
        'maxsamples': "Maximum number of matching reports to score per indicator.",
        'checkaffiliates': "Also check affiliate IP addresses and domains?",
        'delay': "Seconds to wait between API requests.",
    }

    # event type -> (search field, malicious event produced)
    EVENT_MAP = {
        'IP_ADDRESS': ('ip', 'MALICIOUS_IPADDR'),
        'INTERNET_NAME': ('domain', 'MALICIOUS_INTERNET_NAME'),
        'DOMAIN_NAME': ('domain', 'MALICIOUS_INTERNET_NAME'),
        'AFFILIATE_IPADDR': ('ip', 'MALICIOUS_AFFILIATE_IPADDR'),
        'AFFILIATE_INTERNET_NAME': ('domain', 'MALICIOUS_AFFILIATE_INTERNET_NAME'),
        'AFFILIATE_DOMAIN_NAME': ('domain', 'MALICIOUS_AFFILIATE_INTERNET_NAME'),
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return list(self.EVENT_MAP)

    def producedEvents(self):
        return [
            "MALICIOUS_IPADDR", "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "RAW_RIR_DATA",
        ]

    def get(self, path: str):
        res = self.sf.fetchUrl(
            "https://tria.ge/api/v0/" + path,
            headers={'Authorization': f"Bearer {self.opts['api_key']}"},
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )
        time.sleep(self.opts['delay'])

        if not res:
            return None
        if res['code'] in ("401", "403"):
            self.error("Tria.ge rejected the API key")
            self.errorState = True
            return None
        if res['code'] == "429":
            self.error("Tria.ge rate limit reached")
            self.errorState = True
            return None
        if res['code'] != "200" or not res['content']:
            return None
        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Could not parse Tria.ge response: {e}")
            return None

    @staticmethod
    def sampleIds(search) -> list:
        """Sample IDs from a /search response."""
        return [str(s['id']) for s in (search or {}).get('data') or [] if s.get('id')]

    @staticmethod
    def sampleScore(summary) -> int:
        return int((summary or {}).get('score') or 0)

    def handleEvent(self, event):
        if self.errorState or event.data in self.results:
            return
        self.results[event.data] = True

        if event.eventType not in self.EVENT_MAP:
            return
        if event.eventType.startswith('AFFILIATE_') and not self.opts['checkaffiliates']:
            return

        if not self.opts['api_key']:
            self.error("You enabled sfp_triage but did not set an API key!")
            self.errorState = True
            return

        field, malicious_type = self.EVENT_MAP[event.eventType]
        query = urllib.parse.quote(f"{field}:{event.data}")
        ids = self.sampleIds(self.get(f"search?query={query}"))[:int(self.opts['maxsamples'])]
        if not ids:
            return

        hits = []
        for sid in ids:
            if self.checkForStop() or self.errorState:
                return
            score = self.sampleScore(self.get(f"samples/{sid}/summary"))
            if score >= int(self.opts['minscore']):
                hits.append((sid, score))

        if not hits:
            return

        self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", json.dumps(hits), self.__name__, event))
        lines = [f"Tria.ge [{event.data}] - {len(hits)} malicious sandbox report(s)"]
        lines += [f"  - score {score}/10: https://tria.ge/{sid}" for sid, score in hits]
        lines.append(f"<SFURL>https://tria.ge/s?q={query}</SFURL>")
        self.notifyListeners(SpiderFootEvent(malicious_type, "\n".join(lines), self.__name__, event))

# End of sfp_triage class
