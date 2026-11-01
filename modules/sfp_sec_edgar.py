# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_sec_edgar
# Purpose:      Look up US companies that file with the SEC via EDGAR.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


class sfp_sec_edgar(SpiderFootPlugin):

    meta = {
        'name': "SEC EDGAR",
        'summary': "Look up companies that file with the US Securities and Exchange Commission: "
                   "addresses, phone, tickers, EIN, state of incorporation and former names.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://www.sec.gov/edgar/search/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://www.sec.gov/search-filings/edgar-application-programming-interfaces",
                "https://www.sec.gov/os/accessing-edgar-data",
            ],
            'favIcon': "https://www.sec.gov/favicon.ico",
            'description': "EDGAR is the SEC's database of filings by public companies, funds and other "
                           "registrants. Its free JSON APIs give each filer's business and mailing address, "
                           "phone, tickers, industry (SIC), EIN, state of incorporation and former names. "
                           "The SEC limits clients to 10 requests per second and asks for a User-Agent "
                           "that includes a contact email.",
        }
    }

    opts = {
        'contact_email': '',
        'exact_match': True,
        'max_results': 3,
    }

    optdescs = {
        'contact_email': "Contact email sent in the User-Agent, as the SEC's fair-access policy asks "
                         "(e.g. you@example.com). Requests without one may be blocked.",
        'exact_match': "Only report filers whose name matches the target once legal-form words "
                       "(Inc, Corp, LLC...) and punctuation are ignored. Turn off to report the closest "
                       "matches as well.",
        'max_results': "Maximum number of EDGAR filers to report per company name.",
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
        return ["COMPANY_NAME"]

    def producedEvents(self):
        return ["COMPANY_NAME", "PHYSICAL_ADDRESS", "PHONE_NUMBER", "AFFILIATE_INTERNET_NAME",
                "RAW_RIR_DATA"]

    def _useragent(self) -> str:
        email = str(self.opts.get('contact_email') or '').strip()
        return f"SpiderFoot-Revival OSINT {email}".strip() if email else "SpiderFoot-Revival OSINT"

    def _get(self, url: str):
        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self._useragent())
        code = str(res.get('code'))
        if code in ("403", "429"):
            self.error(f"SEC EDGAR refused the request (HTTP {code}). Set a contact email in the "
                       "module options, and keep under 10 requests per second.")
            self.errorState = True
            return None
        if code != "200" or not res.get('content'):
            self.debug(f"No EDGAR data from {url} (HTTP {code})")
            return None
        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error parsing EDGAR JSON: {e}")
            return None

    def searchEntities(self, name: str) -> list:
        """Search EDGAR filer names.

        Returns:
            list: (cik, entity name) tuples, best match first
        """
        data = self._get("https://efts.sec.gov/LATEST/search-index?"
                         + urllib.parse.urlencode({'keysTyped': name}))
        hits = ((data or {}).get('hits') or {}).get('hits') or []
        out = []
        for h in hits:
            cik = str(h.get('_id') or '')
            entity = str((h.get('_source') or {}).get('entity') or '')
            if not cik.isdigit() or not entity:
                continue
            # "ACME UNITED CORP (ACU)" / "SMITH JOHN (CIK 0001234567)" -> drop the parenthetical
            entity = re.sub(r"\s*\((?:CIK\s*)?[^()]*\)\s*$", "", entity).strip()
            out.append((cik, entity))
        return out

    def submissions(self, cik: str):
        return self._get(f"https://data.sec.gov/submissions/CIK{int(cik):010d}.json")

    @staticmethod
    def formatAddress(addr: dict):
        if not addr or not addr.get('street1'):
            return None
        parts = [addr.get('street1'), addr.get('street2'), addr.get('city'),
                 " ".join(p for p in [addr.get('stateOrCountryDescription') or addr.get('stateOrCountry'),
                                      addr.get('zipCode')] if p)]
        return ", ".join(p.strip() for p in parts if p and p.strip())

    def handleEvent(self, event):
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return
        self.results[eventData] = True

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        wanted = SpiderFootHelpers.normalizeCompanyName(eventData)
        if not wanted:
            return

        # Search on the core name: EDGAR matches every word, so "Corporation" would miss "CORP"
        matches = self.searchEntities(wanted)
        if self.errorState:
            return
        if self.opts['exact_match']:
            matches = [m for m in matches if SpiderFootHelpers.normalizeCompanyName(m[1]) == wanted]
        matches = matches[:max(1, int(self.opts['max_results']))]

        if not matches:
            self.debug(f"No EDGAR filer matches {eventData}")
            return

        for cik, _entity in matches:
            if self.checkForStop() or self.errorState:
                return
            if cik in self.results:
                continue
            self.results[cik] = True

            sub = self.submissions(cik)
            if not sub:
                continue

            record = {k: v for k, v in sub.items() if k != 'filings'}
            record['source'] = "SEC EDGAR"
            record['url'] = f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={int(cik):010d}"
            recent = ((sub.get('filings') or {}).get('recent') or {})
            if recent.get('filingDate'):
                record['latestFilingDate'] = recent['filingDate'][0]
                record['latestFilingForm'] = (recent.get('form') or [None])[0]

            raw = SpiderFootEvent("RAW_RIR_DATA", json.dumps(record, ensure_ascii=False), self.__name__, event)
            self.notifyListeners(raw)

            name = sub.get('name')
            if name and SpiderFootHelpers.normalizeCompanyName(name) != wanted:
                self.notifyListeners(SpiderFootEvent("COMPANY_NAME", name, self.__name__, event))

            addresses = set()
            for kind in ('business', 'mailing'):
                addr = self.formatAddress((sub.get('addresses') or {}).get(kind))
                if addr:
                    addresses.add(addr)
            for addr in addresses:
                self.notifyListeners(SpiderFootEvent("PHYSICAL_ADDRESS", addr, self.__name__, event))

            phone = re.sub(r"[^\d+]", "", str(sub.get('phone') or ''))
            if len(phone) == 10 and not phone.startswith('+'):
                phone = "+1" + phone
            if len(phone) >= 8:
                self.notifyListeners(SpiderFootEvent("PHONE_NUMBER", phone, self.__name__, event))

            for site in (sub.get('website'), sub.get('investorWebsite')):
                host = urllib.parse.urlparse(site if site and "://" in site else f"http://{site}").hostname if site else None
                if host and self.sf.validHost(host, self.opts.get('_internettlds')):
                    self.notifyListeners(SpiderFootEvent("AFFILIATE_INTERNET_NAME", host.lower(),
                                                         self.__name__, event))

# End of sfp_sec_edgar class
