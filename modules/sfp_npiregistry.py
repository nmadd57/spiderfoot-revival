# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_npiregistry
# Purpose:      Healthcare professional and organisation licences from the US
#               National Provider Identifier (NPPES) registry.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin
from spiderfoot.services import people


class sfp_npiregistry(SpiderFootPlugin):

    meta = {
        'name': "NPI Registry (healthcare licences)",
        'summary': "Look up US healthcare professionals and organisations in the NPPES NPI registry: specialty, "
                   "state licence numbers, practice address and phone, and an organisation's authorised official.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://npiregistry.cms.hhs.gov/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://npiregistry.cms.hhs.gov/api-page",
                "https://www.cms.gov/regulations-and-guidance/administrative-simplification/nationalprovidentstand",
            ],
            'favIcon': "https://npiregistry.cms.hhs.gov/favicon.ico",
            'logo': "https://npiregistry.cms.hhs.gov/favicon.ico",
            'description': "The National Plan and Provider Enumeration System (NPPES) assigns an NPI to every US "
                           "healthcare provider, individual or organisation, and publishes the record: name, "
                           "credential, taxonomy (specialty), state licence number, practice location and phone. "
                           "Free, no key. Records are self-reported by providers.",
        }
    }

    opts = {
        'max_results': 10,
        'state': "",
        'wildcard_orgs': False,
    }

    optdescs = {
        'max_results': "Most records to report per name (common names match many people).",
        'state': "Only report providers in this state (two-letter code, optional); narrows common names.",
        'wildcard_orgs': "Also match organisations whose name only starts with the company name?",
    }

    results = None
    errorState = False

    API = "https://npiregistry.cms.hhs.gov/api/"

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.opts = dict(self.opts)  # per-instance copy; don't mutate the class defaults
        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ['HUMAN_NAME', 'COMPANY_NAME']

    def producedEvents(self):
        return ['PROFESSIONAL_LICENSE', 'PHYSICAL_ADDRESS', 'PHONE_NUMBER', 'HUMAN_NAME', 'RAW_RIR_DATA']

    def query(self, params: dict):
        params = {'version': '2.1', 'limit': max(1, min(int(self.opts['max_results']), 50)), **params}
        if str(self.opts.get('state') or '').strip():
            params['state'] = str(self.opts['state']).strip().upper()
        res = self.sf.fetchUrl(self.API + '?' + urllib.parse.urlencode(params), timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts.get('_useragent') or 'SpiderFoot')
        if str(res.get('code')) in ('403', '429'):
            self.error(f"The NPI registry refused the request (HTTP {res['code']}); try again later.")
            self.errorState = True
            return None
        if not res.get('content'):
            return None
        try:
            data = json.loads(res['content'])
        except ValueError:
            return None
        if not isinstance(data, dict) or data.get('Errors'):
            self.debug(f"NPI registry returned errors: {str((data or {}).get('Errors'))[:200]}")
            return None
        return data.get('results') or []

    @staticmethod
    def address(rec: dict, purpose='LOCATION') -> dict:
        for a in rec.get('addresses') or []:
            if a.get('address_purpose') == purpose:
                return a
        return (rec.get('addresses') or [{}])[0]

    @staticmethod
    def formatAddress(a: dict) -> str:
        parts = [a.get('address_1'), a.get('address_2'), a.get('city'), a.get('state'), (a.get('postal_code') or '')[:5]]
        return ', '.join(str(p).strip() for p in parts if p and str(p).strip())

    def handleEvent(self, event):
        if self.errorState or event.module == self.__name__:
            return
        if event.data in self.results:
            return
        self.results[event.data] = True
        self.debug(f"Received event, {event.eventType}, from {event.module}")

        if event.eventType == 'HUMAN_NAME':
            self.handlePerson(event)
        else:
            self.handleOrganisation(event)

    def handlePerson(self, event):
        parts = people.split_name(event.data)
        if not parts:
            return
        first, last, _tokens = parts
        recs = self.query({'first_name': first, 'last_name': last, 'enumeration_type': 'NPI-1'})
        for rec in recs or []:
            basic = rec.get('basic') or {}
            if not people.same_person(f"{basic.get('first_name', '')} {basic.get('last_name', '')}", first, last,
                                      [f"{o.get('first_name', '')} {o.get('last_name', '')}" for o in rec.get('other_names') or []]):
                continue
            who = ' '.join(x for x in (basic.get('first_name'), basic.get('middle_name'), basic.get('last_name')) if x)
            credential = (basic.get('credential') or '').strip()
            npi = rec.get('number')
            self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', json.dumps(rec), self.__name__, event))
            self.emitLicenses(event, f"{who}{', ' + credential if credential else ''}", rec)
            loc = self.address(rec)
            addr = self.formatAddress(loc)
            if addr:
                self.notifyListeners(SpiderFootEvent('PHYSICAL_ADDRESS', addr, self.__name__, event))
            if loc.get('telephone_number'):
                self.notifyListeners(SpiderFootEvent('PHONE_NUMBER', loc['telephone_number'], self.__name__, event))
            self.debug(f"NPI {npi}: {who}")

    def handleOrganisation(self, event):
        name = event.data.strip()
        if len(name) < 3:
            return
        recs = self.query({'organization_name': name + ('*' if self.opts.get('wildcard_orgs') else ''),
                           'enumeration_type': 'NPI-2'})
        for rec in recs or []:
            basic = rec.get('basic') or {}
            org = basic.get('organization_name') or ''
            if not (people.same_company(org, name) or (self.opts.get('wildcard_orgs') and people.company_key(org).startswith(people.company_key(name)))):
                continue
            self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', json.dumps(rec), self.__name__, event))
            self.emitLicenses(event, org, rec)
            official = ' '.join(x for x in (basic.get('authorized_official_first_name'),
                                            basic.get('authorized_official_last_name')) if x)
            if official and f"official:{official}" not in self.results:
                self.results[f"official:{official}"] = True
                title = basic.get('authorized_official_title_or_position') or 'authorised official'
                self.notifyListeners(SpiderFootEvent('HUMAN_NAME', official, self.__name__, event))
                self.notifyListeners(SpiderFootEvent(
                    'RAW_RIR_DATA', json.dumps({'organisation': org, 'npi': rec.get('number'), 'authorizedOfficial': official,
                                                'title': title}), self.__name__, event))
            loc = self.address(rec)
            addr = self.formatAddress(loc)
            if addr:
                self.notifyListeners(SpiderFootEvent('PHYSICAL_ADDRESS', addr, self.__name__, event))
            if loc.get('telephone_number'):
                self.notifyListeners(SpiderFootEvent('PHONE_NUMBER', loc['telephone_number'], self.__name__, event))

    def emitLicenses(self, event, label, rec):
        npi = rec.get('number')
        kind = 'organisation' if rec.get('enumeration_type') == 'NPI-2' else 'individual'
        link = f"https://npiregistry.cms.hhs.gov/provider-view/{npi}"
        taxonomies = rec.get('taxonomies') or []
        emitted = False
        for t in taxonomies:
            lic = (t.get('license') or '').strip()
            if not lic:
                continue
            emitted = True
            text = (f"{label} · {t.get('desc') or t.get('code')} · state licence {lic}"
                    f"{' (' + t['state'] + ')' if t.get('state') else ''} · NPI {npi} ({kind}) · {link}")
            self.notifyListeners(SpiderFootEvent('PROFESSIONAL_LICENSE', re.sub(r'\s+', ' ', text), self.__name__, event))
        if not emitted:
            specialty = ', '.join(t.get('desc') or t.get('code') or '' for t in taxonomies[:2]) or 'healthcare provider'
            self.notifyListeners(SpiderFootEvent(
                'PROFESSIONAL_LICENSE', f"{label} · {specialty} · NPI {npi} ({kind}) · no state licence listed · {link}",
                self.__name__, event))

# End of sfp_npiregistry class
