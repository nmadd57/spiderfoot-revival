# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_crt_org
# Purpose:      Find domains an organisation has obtained certificates for, via crt.sh.
# -------------------------------------------------------------------------------

import json
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_crt_org(SpiderFootPlugin):

    meta = {
        'name': "Certificate Transparency (Organisation)",
        'summary': "Find domains a company has had certificates issued to, by searching crt.sh on the organisation name.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://crt.sh/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': ["https://crt.sh/", "https://github.com/crtsh"],
            'description': "crt.sh can search certificates by the Organization (O=) subject field, which "
                           "reveals domains owned by a company that no domain-based search would find.",
        }
    }

    opts = {
        'maxdomains': 200,
    }

    optdescs = {
        'maxdomains': "Maximum number of domains to report per organisation.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["COMPANY_NAME"]

    def producedEvents(self):
        return ["AFFILIATE_DOMAIN_NAME", "AFFILIATE_INTERNET_NAME", "RAW_RIR_DATA"]

    @staticmethod
    def extractNames(data) -> set:
        names = set()
        for cert in data or []:
            for n in str(cert.get('name_value', '')).split("\n"):
                n = n.strip().lower().replace("*.", "")
                if n and "@" not in n and " " not in n:
                    names.add(n)
        return names

    def handleEvent(self, event):
        if self.errorState or event.data in self.results:
            return
        self.results[event.data] = True

        url = "https://crt.sh/?" + urllib.parse.urlencode({'O': event.data, 'output': 'json'})
        res = self.sf.fetchUrl(url, timeout=60, useragent=self.opts['_useragent'])
        time.sleep(0.5)

        if not res or res.get('code') != "200":
            self.error(f"crt.sh organisation search failed (HTTP {res.get('code') if res else 'none'})")
            self.errorState = True
            return
        if not res.get('content'):
            return

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Could not parse crt.sh response: {e}")
            return
        if not data:
            return

        self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", str(data)[:20000], self.__name__, event))

        count = 0
        for name in sorted(self.extractNames(data)):
            if count >= int(self.opts['maxdomains']):
                break
            if name in self.results or not self.sf.validHost(name, self.opts['_internettlds']):
                continue
            self.results[name] = True
            count += 1

            self.notifyListeners(SpiderFootEvent("AFFILIATE_INTERNET_NAME", name, self.__name__, event))
            if self.sf.isDomain(name, self.opts['_internettlds']):
                self.notifyListeners(SpiderFootEvent("AFFILIATE_DOMAIN_NAME", name, self.__name__, event))

# End of sfp_crt_org class
