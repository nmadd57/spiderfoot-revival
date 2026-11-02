# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_secedgar
# Purpose:      Link people to the public companies they appear in filings for,
#               and list a company's SEC registration details and recent filings.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import threading
import time
import urllib.parse
from collections import Counter

from spiderfoot import SpiderFootEvent, SpiderFootPlugin
from spiderfoot.services import people

_throttle = threading.Lock()
_last = [0.0]


def _wait(delay: float) -> None:
    """SEC fair access allows 10 requests a second; stay well under it across all threads."""
    with _throttle:
        gap = delay - (time.time() - _last[0])
        if gap > 0:
            time.sleep(gap)
        _last[0] = time.time()


class sfp_secedgar(SpiderFootPlugin):

    meta = {
        'name': "SEC EDGAR",
        'summary': "From a person's name, find the public companies they file or are named in (insider, "
                   "ownership and proxy filings); from a company name, get its SEC registration, address and "
                   "recent filings.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://www.sec.gov/edgar",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://www.sec.gov/search-filings/edgar-application-programming-interfaces",
                "https://www.sec.gov/search-filings/edgar-search-assistance/accessing-edgar-data",
                "https://www.sec.gov/os/webmaster-faq#developers",
            ],
            'favIcon': "https://www.sec.gov/favicon.ico",
            'logo': "https://www.sec.gov/files/sec-logo.png",
            'description': "EDGAR is the SEC's database of company filings. Insider ownership forms (3, 4, 5), "
                           "beneficial ownership schedules (13D/13G), proxy statements and annual reports name "
                           "directors, officers and large shareholders, which links individuals to companies. "
                           "Free, no key; the SEC asks clients to identify themselves and stay under 10 requests "
                           "a second.",
        }
    }

    opts = {
        'contact': "",
        'person_forms': "3,4,5,SC 13D,SC 13G,DEF 14A,S-1,10-K,8-K,D",
        'filing_forms': "10-K,10-Q,8-K,S-1,DEF 14A,SC 13D,SC 13G,20-F,6-K,D",
        'max_companies': 5,
        'max_filings': 8,
        'delay': 0.2,
    }

    optdescs = {
        'contact': "Your contact email, added to the User-Agent as the SEC's fair access policy asks (optional).",
        'person_forms': "Filing forms to search for a person's name (comma separated).",
        'filing_forms': "Filing forms to list for a company (comma separated).",
        'max_companies': "Most companies to report for one person's name (common names match many).",
        'max_filings': "Most filings to report per company.",
        'delay': "Seconds between requests to the SEC (they allow 10 per second).",
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
        return ['HUMAN_NAME', 'COMPANY_NAME']

    def producedEvents(self):
        return ['COMPANY_NAME', 'COMPANY_FILING', 'PHYSICAL_ADDRESS', 'PHONE_NUMBER', 'RAW_RIR_DATA']

    # ------------------------------------------------------------------ HTTP

    def userAgent(self) -> str:
        # the SEC's firewall rejects User-Agents that contain a URL; an email address is what it asks for
        ua = "SpiderFoot-Revival (osint scanner)"
        contact = str(self.opts.get('contact') or '').strip()
        return f"{ua} {contact}" if contact else ua

    def getJson(self, url: str, params: dict = None):
        if params:
            url += '?' + urllib.parse.urlencode(params)
        _wait(float(self.opts.get('delay') or 0))
        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.userAgent(),
                               headers={'Accept': 'application/json'})
        code = str(res.get('code'))
        if code in ('403', '429'):
            self.error(f"The SEC refused the request (HTTP {code}). It blocks clients that do not identify themselves or "
                       "that go over 10 requests a second: set your contact email in this module's settings.")
            self.errorState = True
            return None
        if not res.get('content') or code != '200':
            return None
        try:
            return json.loads(res['content'])
        except ValueError:
            return None

    def fullText(self, phrase: str):
        return self.getJson("https://efts.sec.gov/LATEST/search-index",
                            {'q': f'"{phrase}"', 'forms': self.opts['person_forms']})

    def submissions(self, cik) -> dict:
        data = self.getJson(f"https://data.sec.gov/submissions/CIK{int(cik):010d}.json")
        return data if isinstance(data, dict) else None

    @staticmethod
    def cleanName(display: str) -> str:
        """'APPLE INC  (AAPL)  (CIK 0000320193)' -> 'APPLE INC'."""
        return re.sub(r'\s*\((?:CIK \d+|[A-Z.,\- ]{1,30})\)', '', str(display or '')).strip()

    @staticmethod
    def filingUrl(cik, accession: str, document: str = '') -> str:
        base = f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/{accession.replace('-', '')}"
        return f"{base}/{document}" if document else base

    # ------------------------------------------------------------- handlers

    def handleEvent(self, event):
        if self.errorState:
            return
        if event.module == self.__name__:
            return  # our own companies were already looked up when they were found
        if event.data in self.results:
            return
        self.results[event.data] = True
        self.debug(f"Received event, {event.eventType}, from {event.module}")

        if event.eventType == 'HUMAN_NAME':
            self.handlePerson(event)
        elif event.eventType == 'COMPANY_NAME':
            self.handleCompany(event)

    def handlePerson(self, event):
        parts = people.split_name(event.data)
        if not parts:
            self.debug(f"Not searching for the single-word name {event.data}")
            return
        first, last, tokens = parts

        phrases = [f"{first} {last}", f"{last} {first}"]
        if len(tokens) > 2:
            phrases.append(' '.join(tokens))

        seen_hits, found = set(), {}
        for phrase in dict.fromkeys(phrases):
            data = self.fullText(phrase)
            if not data:
                continue
            for hit in (data.get('hits') or {}).get('hits') or []:
                src = hit.get('_source') or {}
                if hit.get('_id') in seen_hits:
                    continue
                seen_hits.add(hit.get('_id'))
                names, ciks = src.get('display_names') or [], src.get('ciks') or []
                for disp, cik in zip(names, ciks):
                    if people.name_in_text(first, last, self.cleanName(disp)):
                        continue  # the person's own filer record
                    row = found.setdefault(cik, {'name': self.cleanName(disp), 'forms': Counter(), 'hits': []})
                    row['forms'][src.get('form') or '?'] += 1
                    doc = (hit.get('_id') or ':').split(':', 1)
                    row['hits'].append((src.get('file_date') or '', src.get('form') or '', src.get('adsh') or doc[0],
                                        doc[1] if len(doc) > 1 else ''))

        ranked = sorted(found.items(), key=lambda kv: (-sum(kv[1]['forms'].values()), kv[1]['name']))
        emitted = 0
        for cik, row in ranked:
            if emitted >= int(self.opts['max_companies']) or self.checkForStop():
                break
            sub = self.submissions(cik)
            if self.errorState:
                return
            # individuals and trusts share the registry; only operating companies are businesses
            if not sub or sub.get('entityType') != 'operating':
                continue
            emitted += 1
            self.emitPersonLink(event, first, last, cik, sub, row)

    def emitPersonLink(self, event, first, last, cik, sub, row):
        company = sub.get('name') or row['name']
        if f"co:{cik}" not in self.results:
            self.results[f"co:{cik}"] = True
            self.notifyListeners(SpiderFootEvent('COMPANY_NAME', company, self.__name__, event))
            self.emitCompanyDetails(event, cik, sub, filings=True)

        dates = sorted(h[0] for h in row['hits'] if h[0])
        evidence = {'person': f"{first} {last}", 'company': company, 'cik': str(cik).zfill(10),
                    'appearsIn': dict(row['forms']), 'firstSeen': dates[0] if dates else '',
                    'lastSeen': dates[-1] if dates else '',
                    'note': "Matched on name only: confirm this is the same person before relying on it."}
        self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', json.dumps(evidence), self.__name__, event))
        for date, form, adsh, doc in sorted(row['hits'], reverse=True)[:int(self.opts['max_filings'])]:
            self.notifyListeners(SpiderFootEvent(
                'COMPANY_FILING', f"{company} · Form {form} · {date} · {self.filingUrl(cik, adsh, doc)}",
                self.__name__, event))

    def handleCompany(self, event):
        name = event.data
        data = self.getJson("https://efts.sec.gov/LATEST/search-index", {'keysTyped': name})
        if not data:
            return
        matches = []
        for hit in (data.get('hits') or {}).get('hits') or []:
            ent = ((hit.get('_source') or {}).get('entity')) or ''
            if people.same_company(self.cleanName(ent), name):
                matches.append(hit.get('_id'))
        for cik in matches[:3]:
            if f"co:{cik}" in self.results or self.checkForStop():
                continue
            self.results[f"co:{cik}"] = True
            sub = self.submissions(cik)
            if not sub:
                continue
            self.emitCompanyDetails(event, cik, sub, filings=True)

    def emitCompanyDetails(self, event, cik, sub, filings=None):
        company = sub.get('name') or ''
        summary = {k: sub.get(k) for k in ('name', 'cik', 'entityType', 'sic', 'sicDescription', 'tickers', 'exchanges',
                                           'stateOfIncorporation', 'fiscalYearEnd', 'ein', 'formerNames', 'category')}
        self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', json.dumps(summary), self.__name__, event))

        biz = ((sub.get('addresses') or {}).get('business')) or {}
        addr = ', '.join(str(biz[k]) for k in ('street1', 'street2', 'city', 'stateOrCountry', 'zipCode') if biz.get(k))
        if addr:
            self.notifyListeners(SpiderFootEvent('PHYSICAL_ADDRESS', addr, self.__name__, event))
        if sub.get('phone'):
            self.notifyListeners(SpiderFootEvent('PHONE_NUMBER', str(sub['phone']), self.__name__, event))

        if filings is None:
            return
        wanted = {f.strip().upper() for f in str(self.opts['filing_forms']).split(',') if f.strip()}
        recent = ((sub.get('filings') or {}).get('recent')) or {}
        forms, dates = recent.get('form') or [], recent.get('filingDate') or []
        accs, docs = recent.get('accessionNumber') or [], recent.get('primaryDocument') or []
        count = 0
        for i, form in enumerate(forms):
            if wanted and str(form).upper() not in wanted:
                continue
            if count >= int(self.opts['max_filings']):
                break
            count += 1
            self.notifyListeners(SpiderFootEvent(
                'COMPANY_FILING', f"{company} · Form {form} · {dates[i]} · {self.filingUrl(cik, accs[i], docs[i] if i < len(docs) else '')}",
                self.__name__, event))

# End of sfp_secedgar class
