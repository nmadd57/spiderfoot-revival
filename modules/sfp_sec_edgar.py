# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_sec_edgar
# Purpose:      Look up US companies that file with the SEC via EDGAR, and find the
#               public companies a person appears in filings for.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import threading
import time
import urllib.parse
from collections import Counter

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin
from spiderfoot.services import people

_throttle = threading.Lock()
_last = [0.0]


def _wait(delay: float) -> None:
    """SEC fair access allows 10 requests a second; stay under it across all threads."""
    with _throttle:
        gap = delay - (time.time() - _last[0])
        if gap > 0:
            time.sleep(gap)
        _last[0] = time.time()


class sfp_sec_edgar(SpiderFootPlugin):

    meta = {
        'name': "SEC EDGAR",
        'summary': "Look up companies that file with the US Securities and Exchange Commission (address, phone, "
                   "tickers, EIN, state of incorporation, former names, recent filings, parent company), and "
                   "from a person's name find the public companies they file or are named in.",
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
                           "Insider ownership forms (3, 4, 5), beneficial ownership schedules (13D/13G), "
                           "proxy statements and annual reports name directors, officers and large "
                           "shareholders, which links individuals to companies. The SEC limits clients to "
                           "10 requests per second and asks for a User-Agent that includes a contact email.",
        }
    }

    opts = {
        'contact_email': '',
        'exact_match': True,
        'max_results': 3,
        'parent_search': True,
        'recent_filings': 10,
        'filing_forms': "10-K,10-Q,8-K,S-1,DEF 14A,SC 13D,SC 13G,20-F,6-K,D",
        'person_search': True,
        'person_forms': "3,4,5,SC 13D,SC 13G,DEF 14A,S-1,10-K,8-K,D",
        'max_companies': 5,
        'delay': 0.15,
    }

    optdescs = {
        'contact_email': "Contact email sent in the User-Agent, as the SEC's fair-access policy asks "
                         "(e.g. you@example.com). Requests without one may be blocked.",
        'exact_match': "Only report filers whose name matches the target once legal-form words "
                       "(Inc, Corp, LLC...) and punctuation are ignored. Turn off to report the closest "
                       "matches as well.",
        'max_results': "Maximum number of EDGAR filers to report per company name.",
        'parent_search': "Find public companies that list the business as a subsidiary (Exhibit 21 of "
                         "their 10-K), and report them as affiliates.",
        'recent_filings': "Number of recent filings to list in each filer's record (0 to skip), and the most "
                          "COMPANY_FILING events to report per company.",
        'filing_forms': "Filing forms reported as COMPANY_FILING events for a company (comma separated, empty "
                        "for every form).",
        'person_search': "Search a person's name in SEC filings and report the public companies they appear in. "
                         "These are name matches, so common names find unrelated people.",
        'person_forms': "Filing forms searched for a person's name (comma separated).",
        'max_companies': "Most companies to report for one person's name.",
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
        return ["COMPANY_NAME", "HUMAN_NAME"]

    def producedEvents(self):
        return ["COMPANY_NAME", "COMPANY_FILING", "PHYSICAL_ADDRESS", "PHONE_NUMBER", "AFFILIATE_INTERNET_NAME",
                "AFFILIATE_COMPANY_NAME", "RAW_RIR_DATA"]

    def _useragent(self) -> str:
        email = str(self.opts.get('contact_email') or '').strip()
        return f"SpiderFoot-Revival OSINT {email}".strip() if email else "SpiderFoot-Revival OSINT"

    def _get(self, url: str):
        # The SEC's edge sometimes resets a connection (TLS EOF) under bursts of requests; one retry
        # after a short pause gets through.
        for attempt in (1, 2):
            _wait(float(self.opts.get('delay') or 0))
            res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self._useragent())
            if str(res.get('code')) == 'None' and attempt == 1:
                time.sleep(1.0)
                continue
            break
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

    def parentFilers(self, name: str, own_ciks: set) -> list:
        """Public companies whose Exhibit 21 (list of subsidiaries) names the business.

        Returns:
            list: dicts with parent name, CIK, filing date and exhibit URL, newest first
        """
        data = self._get("https://efts.sec.gov/LATEST/search-index?"
                         + urllib.parse.urlencode({'q': f'"{name}"', 'forms': "10-K"}))
        parents = {}
        for h in ((data or {}).get('hits') or {}).get('hits') or []:
            src = h.get('_source') or {}
            if not str(src.get('file_type') or '').upper().startswith("EX-21"):
                continue
            ciks = [str(c).lstrip("0") for c in src.get('ciks') or []]
            names = src.get('display_names') or []
            if not ciks or not names or ciks[0] in own_ciks:
                continue
            adsh, _, filename = str(h.get('_id') or '').partition(":")
            entry = {
                'parent': re.sub(r"\s*\((?:CIK\s*)?[^()]*\)", "", names[0]).strip(),
                'cik': ciks[0],
                'filed': src.get('file_date'),
                'exhibit': (f"https://www.sec.gov/Archives/edgar/data/{ciks[0]}/{adsh.replace('-', '')}/{filename}"
                            if adsh and filename else None),
            }
            if ciks[0] not in parents or str(entry['filed']) > str(parents[ciks[0]]['filed']):
                parents[ciks[0]] = entry
        return sorted(parents.values(), key=lambda e: str(e['filed']), reverse=True)

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

    @staticmethod
    def cleanName(display: str) -> str:
        """'APPLE INC  (AAPL)  (CIK 0000320193)' -> 'APPLE INC'."""
        return re.sub(r'\s*\((?:CIK \d+|[A-Z.,\- ]{1,30})\)', '', str(display or '')).strip()

    @staticmethod
    def filingUrl(cik, accession: str, document: str = '') -> str:
        base = f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/{accession.replace('-', '')}"
        return f"{base}/{document}" if document else base

    def handleEvent(self, event):
        eventData = event.data

        if self.errorState:
            return
        if event.module == self.__name__:
            return  # the companies this module reports were already looked up when they were found

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return
        self.results[eventData] = True

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        if event.eventType == "HUMAN_NAME":
            if self.opts.get('person_search'):
                self.handlePerson(event)
            return
        self.handleCompany(event)

    # ------------------------------------------------------------ companies

    def handleCompany(self, event):
        eventData = event.data
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

        for cik, _entity in matches:
            if self.checkForStop() or self.errorState:
                return
            if cik in self.results:
                continue
            self.results[cik] = True

            sub = self.submissions(cik)
            if not sub:
                continue
            self.emitFiler(event, cik, sub, wanted)

        if self.opts.get('parent_search') and not self.errorState and not self.checkForStop():
            own = {str(c).lstrip("0") for c, _e in matches}
            name = SpiderFootHelpers.stripTargetPrefix(eventData).strip().strip('"')
            for parent in self.parentFilers(name, own)[:3]:
                if f"parent:{parent['cik']}" in self.results:
                    continue
                self.results[f"parent:{parent['cik']}"] = True
                record = {'source': "SEC EDGAR Exhibit 21 (subsidiaries)", 'subsidiary': name, **parent}
                self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", json.dumps(record, ensure_ascii=False),
                                                     self.__name__, event))
                if SpiderFootHelpers.normalizeCompanyName(parent['parent']) != wanted:
                    self.notifyListeners(SpiderFootEvent("AFFILIATE_COMPANY_NAME", parent['parent'],
                                                         self.__name__, event))

    def emitFiler(self, event, cik, sub, wanted=None):
        """Report one filer: record, official name, addresses, phone, websites and recent filings.

        ``wanted`` is the normalised name that was searched. The official name is reported as a
        company only when it differs from it; a filer found from a person's name has no ``wanted``
        and is always reported.
        """
        record = {k: v for k, v in sub.items() if k != 'filings'}
        record['source'] = "SEC EDGAR"
        record['url'] = f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={int(cik):010d}"
        recent = ((sub.get('filings') or {}).get('recent') or {})
        if recent.get('filingDate'):
            record['latestFilingDate'] = recent['filingDate'][0]
            record['latestFilingForm'] = (recent.get('form') or [None])[0]
        limit = int(self.opts.get('recent_filings') or 0)
        filings = []
        for i in range(min(limit, len(recent.get('filingDate') or []))):
            acc = (recent.get('accessionNumber') or [''] * (i + 1))[i]
            doc = (recent.get('primaryDocument') or [''] * (i + 1))[i]
            filings.append({
                'date': recent['filingDate'][i],
                'form': (recent.get('form') or [None] * (i + 1))[i],
                'description': (recent.get('primaryDocDescription') or [None] * (i + 1))[i] or None,
                'url': (f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/{acc.replace('-', '')}/{doc}"
                        if acc and doc else None),
            })
        if filings:
            record['recentFilings'] = filings

        raw = SpiderFootEvent("RAW_RIR_DATA", json.dumps(record, ensure_ascii=False), self.__name__, event)
        self.notifyListeners(raw)

        name = sub.get('name')
        if name and (wanted is None or SpiderFootHelpers.normalizeCompanyName(name) != wanted):
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

        # recent filings as entities, limited to the forms people usually want (empty list = every form)
        wanted_forms = {f.strip().upper() for f in str(self.opts.get('filing_forms') or '').split(',') if f.strip()}
        forms, dates = recent.get('form') or [], recent.get('filingDate') or []
        accs, docs = recent.get('accessionNumber') or [], recent.get('primaryDocument') or []
        company = name or ''
        count = 0
        for i, form in enumerate(forms):
            if count >= limit:
                break
            if wanted_forms and str(form).upper() not in wanted_forms:
                continue
            if i >= len(dates) or i >= len(accs):
                break
            count += 1
            self.notifyListeners(SpiderFootEvent(
                "COMPANY_FILING",
                f"{company} · Form {form} · {dates[i]} · {self.filingUrl(cik, accs[i], docs[i] if i < len(docs) else '')}",
                self.__name__, event))

    # -------------------------------------------------------------- people

    def fullText(self, phrase: str):
        return self._get("https://efts.sec.gov/LATEST/search-index?"
                         + urllib.parse.urlencode({'q': f'"{phrase}"', 'forms': self.opts['person_forms']}))

    def handlePerson(self, event):
        """Report the public companies a person's name appears in (insider, ownership and proxy filings)."""
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
            if self.errorState:
                return
            for hit in ((data or {}).get('hits') or {}).get('hits') or []:
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
            if cik not in self.results:
                self.results[cik] = True
                self.emitFiler(event, cik, sub)

            company = sub.get('name') or row['name']
            dates = sorted(h[0] for h in row['hits'] if h[0])
            evidence = {'source': "SEC EDGAR full-text search", 'person': f"{first} {last}", 'company': company,
                        'cik': str(cik).zfill(10), 'appearsIn': dict(row['forms']),
                        'firstSeen': dates[0] if dates else '', 'lastSeen': dates[-1] if dates else '',
                        'note': "Matched on name only: confirm this is the same person before relying on it."}
            self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", json.dumps(evidence), self.__name__, event))
            for date, form, adsh, doc in sorted(row['hits'], reverse=True)[:int(self.opts['recent_filings'] or 0)]:
                self.notifyListeners(SpiderFootEvent(
                    "COMPANY_FILING", f"{company} · Form {form} · {date} · {self.filingUrl(cik, adsh, doc)}",
                    self.__name__, event))

# End of sfp_sec_edgar class
