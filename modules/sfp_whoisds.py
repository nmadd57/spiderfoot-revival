# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_whoisds
# Purpose:      Find newly registered domains that resemble the target (lookalikes).
# -------------------------------------------------------------------------------

import base64
import datetime
import io
import zipfile

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_whoisds(SpiderFootPlugin):

    meta = {
        'name': "WhoisDS Newly Registered Domains",
        'summary': "Search recently registered domains (WhoisDS daily feed) for lookalikes of the target's name.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://whoisds.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': ["https://whoisds.com/newly-registered-domains"],
            'description': "WhoisDS publishes a free daily list of newly registered domain names, useful for "
                           "spotting typosquatting and brand impersonation shortly after registration.",
        }
    }

    opts = {
        'days': 3,
        'minlength': 4,
        'cacheperiod': 12,
    }

    optdescs = {
        'days': "How many days of daily feeds to search (1 = today's/yesterday's most recent).",
        'minlength': "Minimum length of the target's name label to match on (shorter names give too many false positives).",
        'cacheperiod': "Hours to cache each daily feed before re-fetching.",
    }

    results = None
    errorState = False
    domains = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.domains = None

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    def producedEvents(self):
        return ["SIMILARDOMAIN"]

    @staticmethod
    def feedUrl(day: datetime.date) -> str:
        token = base64.b64encode(f"{day.isoformat()}.zip".encode()).decode()
        return f"https://whoisds.com//whois-database/newly-registered-domains/{token}/nrd"

    @staticmethod
    def parseZip(blob: bytes) -> list:
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            out = []
            for name in z.namelist():
                out.extend(z.read(name).decode('utf-8', errors='ignore').split())
            return [d.strip().lower() for d in out if d.strip()]

    @staticmethod
    def lookalikes(label: str, own: str, domains) -> list:
        return sorted(d for d in domains if d != own and label in d.rsplit('.', 1)[0])

    def loadDomains(self):
        if self.domains is not None:
            return self.domains

        found = set()
        today = datetime.datetime.utcnow().date()
        for back in range(0, int(self.opts['days']) + 1):
            if self.checkForStop():
                break
            day = today - datetime.timedelta(days=back)
            cid = f"sfwds_{day.isoformat()}"
            cached = self.sf.cacheGet(cid, self.opts.get('cacheperiod', 0))
            if cached is not None:
                found.update(cached.split())
                continue
            try:
                r = self.sf.getSession().get(self.feedUrl(day), timeout=self.opts['_fetchtimeout'],
                                             headers={'User-Agent': self.opts['_useragent']})
                if r.status_code != 200:
                    self.debug(f"No WhoisDS feed for {day} (HTTP {r.status_code})")
                    continue
                items = self.parseZip(r.content)
            except Exception as e:
                self.debug(f"Could not load WhoisDS feed for {day}: {e}")
                continue
            self.sf.cachePut(cid, "\n".join(items))
            found.update(items)

        if not found:
            self.error("Unable to load any WhoisDS newly-registered-domain feed")
            self.errorState = True
        self.domains = found
        return found

    def handleEvent(self, event):
        if self.errorState or event.data in self.results:
            return
        self.results[event.data] = True

        own = event.data.lower()
        label = own.rsplit('.', 1)[0].split('.')[-1]
        if len(label) < int(self.opts['minlength']):
            self.debug(f"Skipping {own}: name too short to match reliably")
            return

        domains = self.loadDomains()
        for d in self.lookalikes(label, own, domains):
            evt = SpiderFootEvent("SIMILARDOMAIN", d, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_whoisds class
