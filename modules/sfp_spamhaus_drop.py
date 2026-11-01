# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_spamhaus_drop
# Purpose:      Check if an IP address or netblock is on the Spamhaus DROP list.
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork, IPSet

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_spamhaus_drop(SpiderFootPlugin):

    meta = {
        'name': "Spamhaus DROP",
        'summary': "Check if an IP address or netblock falls within the Spamhaus DROP list of hijacked or criminal-controlled netblocks.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.spamhaus.org/drop/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': ["https://www.spamhaus.org/drop/drop_v4.json"],
            'description': "The Spamhaus Don't Route Or Peer list contains netblocks that are hijacked or leased by professional spam or cyber-crime operations.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True,
    }

    optdescs = {
        'checkaffiliates': "Apply checks to affiliate IP addresses?",
        'cacheperiod': "Hours to cache list data before re-fetching.",
        'checknetblocks': "Report if any listed ranges overlap owned netblocks?",
        'checksubnets': "Check if any listed ranges overlap the same subnet of the target?",
    }

    URL = "https://www.spamhaus.org/drop/drop_v4.json"

    results = None
    errorState = False
    blocklist = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.blocklist = None

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "NETBLOCK_MEMBER", "NETBLOCK_OWNER"]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR", "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET", "BLACKLISTED_NETBLOCK",
            "MALICIOUS_IPADDR", "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_SUBNET", "MALICIOUS_NETBLOCK",
        ]

    @staticmethod
    def parseList(content: str) -> IPSet:
        """Parse the downloaded list into an IPSet."""
        import json
        nets = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                nets.append(IPNetwork(json.loads(line)['cidr']))
            except Exception:
                continue
        return IPSet(nets)

    def loadList(self):
        if self.blocklist is not None:
            return self.blocklist

        cid = "sfmal_spamhaus_drop"
        content = self.sf.cacheGet(cid, self.opts.get('cacheperiod', 0))

        if content is None:
            res = self.sf.fetchUrl(self.URL, timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])
            if not res or res.get('code') != "200" or not res.get('content'):
                self.error(f"Unable to fetch {self.URL}")
                self.errorState = True
                return None
            content = res['content']
            self.sf.cachePut(cid, content)

        self.blocklist = self.parseList(content)
        return self.blocklist

    def query(self, qry, targetType):
        blocklist = self.loadList()
        if blocklist is None:
            return None

        try:
            if targetType == "ip":
                hit = IPAddress(qry) in blocklist
            else:
                hit = bool(IPSet([IPNetwork(qry)]) & blocklist)
        except Exception as e:
            self.debug(f"Could not evaluate {qry}: {e}")
            return None

        return self.URL if hit else None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results or self.errorState:
            return
        self.results[eventData] = True

        if eventName == 'IP_ADDRESS':
            targetType, malicious_type, blacklist_type = 'ip', "MALICIOUS_IPADDR", "BLACKLISTED_IPADDR"
        elif eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            targetType, malicious_type, blacklist_type = 'ip', "MALICIOUS_AFFILIATE_IPADDR", "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts.get('checknetblocks', False):
                return
            targetType, malicious_type, blacklist_type = 'netblock', "MALICIOUS_NETBLOCK", "BLACKLISTED_NETBLOCK"
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts.get('checksubnets', False):
                return
            targetType, malicious_type, blacklist_type = 'netblock', "MALICIOUS_SUBNET", "BLACKLISTED_SUBNET"
        else:
            return

        url = self.query(eventData, targetType)
        if not url:
            return

        text = f"Spamhaus DROP [{eventData}]\n<SFURL>{url}</SFURL>"

        for etype in (malicious_type, blacklist_type):
            evt = SpiderFootEvent(etype, text, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_spamhaus_drop class
