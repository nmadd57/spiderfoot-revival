# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_brokercheck
# Purpose:      Securities and investment adviser registrations from FINRA
#               BrokerCheck and the SEC's Investment Adviser Public Disclosure.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import threading
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin
from spiderfoot.services import people

_throttle = threading.Lock()
_last = [0.0]


def _wait(delay: float) -> None:
    with _throttle:
        gap = delay - (time.time() - _last[0])
        if gap > 0:
            time.sleep(gap)
        _last[0] = time.time()


class sfp_brokercheck(SpiderFootPlugin):

    meta = {
        'name': "BrokerCheck and IAPD (securities licences)",
        'summary': "Look up people and firms registered as securities brokers or investment advisers with FINRA "
                   "BrokerCheck and the SEC's IAPD: CRD number, registration status, current employer firms and "
                   "whether there are disclosures.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://brokercheck.finra.org/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://brokercheck.finra.org/",
                "https://adviserinfo.sec.gov/",
            ],
            'favIcon': "https://brokercheck.finra.org/favicon.ico",
            'logo': "https://brokercheck.finra.org/favicon.ico",
            'description': "FINRA BrokerCheck lists every registered securities broker and brokerage firm; the SEC's "
                           "Investment Adviser Public Disclosure (IAPD) lists investment adviser representatives and "
                           "firms. Both show registration status, employment history and disclosures. Free, no key. "
                           "The sites have no documented API: this module uses the JSON the public search pages use.",
        }
    }

    opts = {
        'max_results': 10,
        'delay': 0.5,
        'use_finra': True,
        'use_iapd': True,
    }

    optdescs = {
        'max_results': "Most records to report per name and per source.",
        'delay': "Seconds between requests.",
        'use_finra': "Search FINRA BrokerCheck (brokers and brokerage firms)?",
        'use_iapd': "Search the SEC's IAPD (investment advisers and adviser firms)?",
    }

    SOURCES = {
        'FINRA BrokerCheck': ("https://api.brokercheck.finra.org/search/", "https://brokercheck.finra.org/{kind}/summary/{crd}", 'use_finra'),
        'SEC IAPD': ("https://api.adviserinfo.sec.gov/search/", "https://adviserinfo.sec.gov/{kind}/summary/{crd}", 'use_iapd'),
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
        return ['PROFESSIONAL_LICENSE', 'COMPANY_NAME', 'PHYSICAL_ADDRESS', 'RAW_RIR_DATA']

    def search(self, base: str, kind: str, query: str):
        params = {'query': query, 'nrows': max(1, min(int(self.opts['max_results']), 50)), 'start': 0, 'wt': 'json'}
        _wait(float(self.opts.get('delay') or 0))
        res = self.sf.fetchUrl(f"{base}{kind}?{urllib.parse.urlencode(params)}", timeout=self.opts['_fetchtimeout'],
                               useragent="Mozilla/5.0 (compatible; SpiderFoot-Revival)")
        if str(res.get('code')) in ('403', '429'):
            self.error(f"{base.split('/')[2]} refused the request (HTTP {res['code']}); try again later.")
            self.errorState = True
            return []
        if not res.get('content'):
            return []
        try:
            hits = (json.loads(res['content']).get('hits') or {}).get('hits') or []
        except (ValueError, AttributeError):
            return []
        return [h.get('_source') or {} for h in hits]

    def handleEvent(self, event):
        if self.errorState or event.module == self.__name__:
            return
        if event.data in self.results:
            return
        self.results[event.data] = True
        self.debug(f"Received event, {event.eventType}, from {event.module}")
        for source, (base, link, opt) in self.SOURCES.items():
            if not self.opts.get(opt) or self.errorState or self.checkForStop():
                continue
            if event.eventType == 'HUMAN_NAME':
                self.handlePerson(event, source, base, link)
            else:
                self.handleFirm(event, source, base, link)

    def handlePerson(self, event, source, base, link):
        parts = people.split_name(event.data)
        if not parts:
            return
        first, last, _tokens = parts
        for rec in self.search(base, 'individual', f"{first} {last}"):
            names = [f"{rec.get('ind_firstname', '')} {rec.get('ind_lastname', '')}"] + list(rec.get('ind_other_names') or [])
            if not people.same_person(names[0], first, last, names[1:]):
                continue
            crd = rec.get('ind_source_id')
            who = ' '.join(x for x in (rec.get('ind_firstname'), rec.get('ind_middlename'), rec.get('ind_lastname')) if x).title()
            self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', json.dumps(rec), self.__name__, event))

            roles = []
            if str(rec.get('ind_bc_scope')) in ('Active', 'InActive'):
                roles.append(f"broker ({rec['ind_bc_scope'].lower()})")
            if str(rec.get('ind_ia_scope')) in ('Active', 'InActive'):
                roles.append(f"investment adviser representative ({rec['ind_ia_scope'].lower()})")
            disclosures = 'Y' in (str(rec.get('ind_bc_disclosure_fl')), str(rec.get('ind_ia_disclosure_fl')))
            jobs = (rec.get('ind_current_employments') or []) + (rec.get('ind_ia_current_employments') or [])
            firms = list(dict.fromkeys(j.get('firm_name', '').strip() for j in jobs if j.get('firm_name')))
            text = (f"{who} · {source} CRD {crd} · {', '.join(roles) or 'not currently registered'}"
                    f"{' · current firm: ' + '; '.join(firms) if firms else ''}"
                    f"{' · HAS DISCLOSURES (complaints, regulatory or criminal events)' if disclosures else ''}"
                    f" · {link.format(kind='individual', crd=crd)}")
            self.notifyListeners(SpiderFootEvent('PROFESSIONAL_LICENSE', text, self.__name__, event))

            for firm in firms:
                self.notifyListeners(SpiderFootEvent('COMPANY_NAME', firm.title() if firm.isupper() else firm, self.__name__, event))
            for j in jobs[:3]:
                loc = ', '.join(x for x in (j.get('branch_city'), j.get('branch_state'), j.get('branch_zip')) if x)
                if loc:
                    self.notifyListeners(SpiderFootEvent('PHYSICAL_ADDRESS', loc, self.__name__, event))

    def handleFirm(self, event, source, base, link):
        name = event.data.strip()
        if len(name) < 3:
            return
        for rec in self.search(base, 'firm', name):
            names = [rec.get('firm_name') or ''] + list(rec.get('firm_other_names') or []) + [rec.get('ia_firm_name') or '']
            if not any(people.same_company(n, name) for n in names if n):
                continue
            crd = rec.get('firm_source_id')
            self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', json.dumps(rec), self.__name__, event))
            ids = []
            if rec.get('firm_bd_full_sec_number'):
                ids.append(f"broker-dealer SEC {rec['firm_bd_full_sec_number']} ({str(rec.get('firm_scope', '')).lower()})")
            if rec.get('firm_ia_full_sec_number'):
                ids.append(f"investment adviser SEC {rec['firm_ia_full_sec_number']} ({str(rec.get('firm_ia_scope', '')).lower()})")
            disclosures = 'Y' in (str(rec.get('firm_disclosure_fl')), str(rec.get('firm_ia_disclosure_fl')))
            branches = rec.get('firm_branches_count')
            text = (f"{rec.get('firm_name')} · {source} firm CRD {crd} · {'; '.join(ids) or 'registered firm'}"
                    f"{' · ' + str(branches) + ' branches' if branches else ''}"
                    f"{' · HAS DISCLOSURES' if disclosures else ''} · {link.format(kind='firm', crd=crd)}")
            self.notifyListeners(SpiderFootEvent('PROFESSIONAL_LICENSE', text, self.__name__, event))
            for key in ('firm_address_details', 'firm_ia_address_details'):
                try:
                    office = (json.loads(rec.get(key) or '{}').get('officeAddress')) or {}
                except ValueError:
                    office = {}
                addr = ', '.join(str(office[k]) for k in ('street1', 'street2', 'city', 'state', 'postalCode') if office.get(k))
                if addr:
                    self.notifyListeners(SpiderFootEvent('PHYSICAL_ADDRESS', addr, self.__name__, event))
                    break

# End of sfp_brokercheck class
