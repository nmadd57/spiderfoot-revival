# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_rapiddns
# Purpose:      Identify subdomains of a domain using RapidDNS.
# -------------------------------------------------------------------------------

import re
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_rapiddns(SpiderFootPlugin):

    meta = {
        'name': "RapidDNS",
        'summary': "Obtain subdomains of a domain from RapidDNS (no API key).",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Passive DNS"],
        'dataSource': {
            'website': "https://rapiddns.io/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': ["https://rapiddns.io/"],
            'description': "RapidDNS is a free DNS query tool that lists known subdomains and same-IP hosts. "
                           "There is no official API, so results are parsed from the HTML page.",
        }
    }

    opts = {
        'verify': True,
        'delay': 1.0,
    }

    optdescs = {
        'verify': "Verify discovered subdomains resolve.",
        'delay': "Seconds to wait between requests.",
    }

    results = None
    errorState = False

    HOST_RE = re.compile(r"<td>([A-Za-z0-9_.-]+)</td>")

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    def producedEvents(self):
        return ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED", "DOMAIN_NAME"]

    @classmethod
    def parseHosts(cls, html: str, domain: str) -> set:
        domain = domain.lower()
        hosts = set()
        for h in cls.HOST_RE.findall(html or ""):
            h = h.lower().strip(".")
            if h == domain or h.endswith("." + domain):
                hosts.add(h)
        return hosts

    def handleEvent(self, event):
        if self.errorState or event.data in self.results:
            return
        self.results[event.data] = True

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        res = self.sf.fetchUrl(
            f"https://rapiddns.io/subdomain/{event.data}?full=1",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )
        time.sleep(self.opts['delay'])

        if not res or res.get('code') != "200" or not res.get('content'):
            self.error(f"Unable to retrieve results from RapidDNS (HTTP {res.get('code') if res else 'none'})")
            self.errorState = True
            return

        for host in sorted(self.parseHosts(res['content'], event.data)):
            if host == event.data.lower() or host in self.results:
                continue
            self.results[host] = True

            if not self.sf.validHost(host, self.opts['_internettlds']):
                continue

            etype = "INTERNET_NAME"
            if self.opts['verify'] and not self.sf.resolveHost(host) and not self.sf.resolveHost6(host):
                etype = "INTERNET_NAME_UNRESOLVED"

            self.notifyListeners(SpiderFootEvent(etype, host, self.__name__, event))

            if self.sf.isDomain(host, self.opts['_internettlds']):
                self.notifyListeners(SpiderFootEvent("DOMAIN_NAME", host, self.__name__, event))

# End of sfp_rapiddns class
