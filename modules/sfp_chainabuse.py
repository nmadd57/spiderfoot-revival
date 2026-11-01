# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_chainabuse
# Purpose:      Check Bitcoin/Ethereum addresses against Chainabuse scam reports.
# -------------------------------------------------------------------------------

import base64
import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_chainabuse(SpiderFootPlugin):

    meta = {
        'name': "Chainabuse",
        'summary': "Check cryptocurrency addresses for scam/abuse reports on Chainabuse.",
        'flags': ["apikey"],
        'pricing': 'free_key',
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.chainabuse.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': ["https://docs.chainabuse.com/docs/api"],
            'apiKeyInstructions': [
                "Visit https://www.chainabuse.com/",
                "Sign in and open the API section of your account",
                "Create an API key",
                "The API key will be listed there",
            ],
            'description': "Chainabuse is a public database of crypto scam and abuse reports. "
                           "A free API key is required.",
        }
    }

    opts = {
        'api_key': '',
        'minreports': 1,
    }

    optdescs = {
        'api_key': "Chainabuse API key.",
        'minreports': "Minimum number of reports before an address is flagged as malicious.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["BITCOIN_ADDRESS", "ETHEREUM_ADDRESS"]

    def producedEvents(self):
        return ["MALICIOUS_BITCOIN_ADDRESS", "RAW_RIR_DATA"]

    def queryAddress(self, address: str):
        key = self.opts['api_key']
        token = base64.b64encode(f"{key}:{key}".encode()).decode()
        res = self.sf.fetchUrl(
            f"https://api.chainabuse.com/v0/reports?address={address}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
            headers={'Authorization': f"Basic {token}", 'Accept': 'application/json'},
        )

        if not res:
            return None
        if res['code'] in ("401", "403"):
            self.error("Invalid Chainabuse API key")
            self.errorState = True
            return None
        if res['code'] == "429":
            self.error("Chainabuse rate limit reached")
            self.errorState = True
            return None
        if res['code'] != "200" or not res['content']:
            return None
        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Could not parse Chainabuse response: {e}")
            return None

    @staticmethod
    def reportList(data) -> list:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get('reports') or []
        return []

    def handleEvent(self, event):
        if self.errorState or event.data in self.results:
            return
        self.results[event.data] = True

        if not self.opts['api_key']:
            self.error("You enabled sfp_chainabuse but did not set an API key!")
            self.errorState = True
            return

        data = self.queryAddress(event.data)
        reports = self.reportList(data)
        if len(reports) < int(self.opts['minreports']):
            return

        self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", json.dumps(reports), self.__name__, event))
        cats = sorted({str(r.get('scamCategory') or r.get('category') or 'unknown') for r in reports})
        text = (f"Chainabuse [{event.data}] - {len(reports)} report(s): {', '.join(cats)}\n"
                f"<SFURL>https://www.chainabuse.com/address/{event.data}</SFURL>")
        self.notifyListeners(SpiderFootEvent("MALICIOUS_BITCOIN_ADDRESS", text, self.__name__, event))

# End of sfp_chainabuse class
