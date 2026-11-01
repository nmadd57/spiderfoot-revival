# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_recordedfuture
# Purpose:      Query Recorded Future's Connect API for IP/domain risk scores.
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_recordedfuture(SpiderFootPlugin):

    meta = {
        'name': "Recorded Future",
        'summary': "Look up IP addresses and domains in Recorded Future and flag those with a high risk score.",
        'flags': ["apikey"],
        'pricing': 'paid',
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.recordedfuture.com/",
            'model': "COMMERCIAL_ONLY",
            'references': ["https://support.recordedfuture.com/hc/en-us/articles/115000894448-Connect-API-Overview"],
            'apiKeyInstructions': [
                "Sign in to the Recorded Future portal (a commercial licence with Connect API access is required)",
                "Open User Settings > API Access",
                "Generate an API token",
            ],
            'description': "Recorded Future is a commercial threat intelligence platform. "
                           "The Connect API returns a 0-99 risk score and the evidence rules behind it.",
        }
    }

    opts = {
        'api_key': '',
        'minscore': 65,
        'checkaffiliates': True,
        'delay': 0.5,
    }

    optdescs = {
        'api_key': "Recorded Future Connect API token.",
        'minscore': "Minimum risk score (0-99) to report as malicious. 25 = suspicious, 65 = malicious, 90 = very malicious.",
        'checkaffiliates': "Also check affiliate IP addresses and domains?",
        'delay': "Seconds to wait between API requests.",
    }

    # event type -> (API entity kind, malicious event produced)
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

    def query(self, kind: str, entity: str):
        res = self.sf.fetchUrl(
            f"https://api.recordedfuture.com/v2/{kind}/{entity}?fields=risk",
            headers={'X-RFToken': self.opts['api_key'], 'Accept': 'application/json'},
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )
        time.sleep(self.opts['delay'])

        if not res:
            return None
        if res['code'] in ("401", "403"):
            self.error("Recorded Future rejected the API token (or it lacks Connect API access)")
            self.errorState = True
            return None
        if res['code'] == "429":
            self.error("Recorded Future API quota exceeded")
            self.errorState = True
            return None
        if res['code'] == "404" or not res['content']:
            return None
        if res['code'] != "200":
            self.debug(f"Unexpected response from Recorded Future: HTTP {res['code']}")
            return None
        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Could not parse Recorded Future response: {e}")
            return None

    @staticmethod
    def parseRisk(data) -> dict:
        """Extract score, label and evidence strings from a Connect API response."""
        risk = ((data or {}).get('data') or {}).get('risk') or {}
        evidence = [
            f"{e.get('rule', '?')}: {e.get('evidenceString', '')}".strip()
            for e in risk.get('evidenceDetails') or []
        ]
        return {
            'score': int(risk.get('score') or 0),
            'label': risk.get('criticalityLabel') or '',
            'evidence': evidence,
        }

    def handleEvent(self, event):
        if self.errorState or event.data in self.results:
            return
        self.results[event.data] = True

        if event.eventType not in self.EVENT_MAP:
            return
        if event.eventType.startswith('AFFILIATE_') and not self.opts['checkaffiliates']:
            return

        if not self.opts['api_key']:
            self.error("You enabled sfp_recordedfuture but did not set an API token!")
            self.errorState = True
            return

        kind, malicious_type = self.EVENT_MAP[event.eventType]
        data = self.query(kind, event.data)
        if not data:
            return

        risk = self.parseRisk(data)
        if risk['score'] < int(self.opts['minscore']):
            return

        self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event))

        lines = [f"Recorded Future [{event.data}] - risk {risk['score']}/99 {risk['label']}".rstrip()]
        lines += [f"  - {e}" for e in risk['evidence'][:10]]
        lines.append(f"<SFURL>https://app.recordedfuture.com/live/sc/entity/{kind}:{event.data}</SFURL>")
        self.notifyListeners(SpiderFootEvent(malicious_type, "\n".join(lines), self.__name__, event))

# End of sfp_recordedfuture class
