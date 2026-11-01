# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_openfda
# Purpose:      Look up a business in FDA records via openFDA: drug, device and
#               food recalls, and medical device establishment registrations.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin

# endpoint -> (label, firm field, sort field)
RECALLS = {
    'drug/enforcement': ("Drug recall", "recalling_firm", "report_date"),
    'device/enforcement': ("Medical device recall", "recalling_firm", "report_date"),
    'food/enforcement': ("Food recall", "recalling_firm", "report_date"),
}


def _join_addr(*parts) -> str:
    """Join address parts, skipping blanks and the "N/A" placeholders FDA data uses."""
    clean = [str(p).strip() for p in parts if p and str(p).strip() and str(p).strip().upper() not in ("N/A", "NA")]
    return ", ".join(clean)


class sfp_openfda(SpiderFootPlugin):

    meta = {
        'name': "openFDA",
        'summary': "Look up a business in FDA records: drug, medical device and food recalls (enforcement "
                   "reports) and registered medical device establishments with their addresses and US agents.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://open.fda.gov/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://open.fda.gov/apis/",
                "https://open.fda.gov/apis/authentication/",
                "https://open.fda.gov/apis/device/registrationlisting/",
            ],
            'favIcon': "https://open.fda.gov/favicon.ico",
            'description': "openFDA publishes FDA enforcement reports (recalls of drugs, devices and food, with "
                           "the recalling firm, reason, classification and distribution) and the medical "
                           "device establishment registration database. Without a key the limit is 1,000 "
                           "requests a day per IP; a free key raises it to 120,000.",
        }
    }

    opts = {
        'openfda_apikey': '',
        'recalls': True,
        'registrations': True,
        'max_items': 10,
    }

    optdescs = {
        'openfda_apikey': "Optional openFDA API key (free, https://open.fda.gov/apis/authentication/).",
        'recalls': "Search drug, device and food recalls by recalling firm.",
        'registrations': "Search medical device establishment registrations by company name.",
        'max_items': "Maximum number of recalls (per product type) and establishments to report.",
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
        return ["RAW_RIR_DATA", "PHYSICAL_ADDRESS", "HUMAN_NAME", "EMAILADDR"]

    def query(self, endpoint: str, search: str, sort: str = None, limit: int = 100):
        params = {'search': search, 'limit': str(limit)}
        if sort:
            params['sort'] = f"{sort}:desc"
        if self.opts.get('openfda_apikey'):
            params['api_key'] = self.opts['openfda_apikey']
        res = self.sf.fetchUrl(f"https://api.fda.gov/{endpoint}.json?" + urllib.parse.urlencode(params),
                               timeout=max(30, int(self.opts.get('_fetchtimeout') or 0)),
                               useragent=self.opts['_useragent'])
        code = str(res.get('code'))
        if code == "404":  # openFDA answers "no matches" with a 404
            return []
        if code == "429":
            self.error("openFDA rate limit reached; add a free API key.")
            self.errorState = True
            return []
        if code != "200" or not res.get('content'):
            self.debug(f"openFDA {endpoint} returned HTTP {code}")
            return []
        try:
            return json.loads(res['content']).get('results') or []
        except Exception as e:
            self.debug(f"Error parsing openFDA JSON: {e}")
            return []

    def _emit(self, etype: str, data, source):
        data = str(data or "").strip()
        if not data or f"{etype}:{data.lower()}" in self.results:
            return
        self.results[f"{etype}:{data.lower()}"] = True
        self.notifyListeners(SpiderFootEvent(etype, data, self.__name__, source))

    def recalls(self, core: str, wanted: str, event):
        limit = max(1, int(self.opts.get('max_items') or 10))
        for endpoint, (label, field, sort) in RECALLS.items():
            if self.checkForStop() or self.errorState:
                return
            rows = [r for r in self.query(endpoint, f'{field}:"{core}"', sort)
                    if SpiderFootHelpers.normalizeCompanyName(r.get(field)) == wanted]
            if not rows:
                continue
            classes = {}
            for r in rows:
                classes[r.get('classification')] = classes.get(r.get('classification'), 0) + 1
            items = [{
                'recall_number': r.get('recall_number'),
                'date': r.get('report_date') or r.get('recall_initiation_date'),
                'classification': r.get('classification'),
                'status': r.get('status'),
                'product': str(r.get('product_description') or '')[:300],
                'reason': str(r.get('reason_for_recall') or '')[:300],
                'distribution': str(r.get('distribution_pattern') or '')[:200],
            } for r in rows[:limit]]
            self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", json.dumps({
                'source': f"openFDA {label.lower()}s",
                'firm': rows[0].get(field),
                'recalls_found': len(rows),
                'by_classification': classes,
                'recent': items,
                'url': "https://www.accessdata.fda.gov/scripts/ires/index.cfm",
            }, ensure_ascii=False), self.__name__, event))
            for r in rows[:limit]:
                if r.get('address_1'):
                    addr = _join_addr(r.get('address_1'), r.get('address_2'), r.get('city'),
                                      " ".join(str(x) for x in [r.get('state'), r.get('postal_code')] if x))
                    self._emit("PHYSICAL_ADDRESS", addr, event)

    def registrations(self, core: str, wanted: str, event):
        limit = max(1, int(self.opts.get('max_items') or 10))
        seen = 0
        for r in self.query("device/registrationlisting", f'registration.name:"{core}"'):
            reg = r.get('registration') or {}
            if SpiderFootHelpers.normalizeCompanyName(reg.get('name')) != wanted:
                continue
            num = reg.get('registration_number')
            if not num or f"reg:{num}" in self.results:
                continue
            self.results[f"reg:{num}"] = True
            seen += 1
            if seen > limit:
                break
            addr = _join_addr(
                reg.get('address_line_1'), reg.get('address_line_2'), reg.get('city'),
                " ".join(str(x) for x in [reg.get('state_code'), reg.get('zip_code') or reg.get('postal_code')] if x),
                reg.get('iso_country_code') if reg.get('iso_country_code') not in (None, "", "US") else None)
            agent = reg.get('us_agent') or {}
            owner = reg.get('owner_operator') or {}
            self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", json.dumps({
                'source': "openFDA medical device establishment registration",
                'name': reg.get('name'),
                'registration_number': num,
                'fei_number': reg.get('fei_number'),
                'establishment_types': r.get('establishment_type'),
                'registration_expires': reg.get('reg_expiry_date_year'),
                'address': addr,
                'owner_operator': owner.get('firm_name'),
                'us_agent': agent.get('name'),
                'us_agent_business': agent.get('business_name'),
                'products': [p.get('openfda', {}).get('device_name') or p.get('product_code')
                             for p in (r.get('products') or [])[:10]],
                'url': f"https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfRL/rl.cfm?rid={num}",
            }, ensure_ascii=False, default=str), self.__name__, event))
            self._emit("PHYSICAL_ADDRESS", addr if reg.get('address_line_1') else None, event)
            for person in (agent.get('name'), (owner.get('contact_address') or {}).get('name')):
                if person and len(str(person).split()) >= 2 and not SpiderFootHelpers.looksLikeCompanyName(person):
                    self._emit("HUMAN_NAME", str(person).title() if str(person).isupper() else person, event)
            email = str(agent.get('email_address') or '').strip().lower()
            if SpiderFootHelpers.validEmail(email) and \
                    email.split("@")[-1] not in SpiderFootHelpers.REGISTERED_AGENT_EMAIL_DOMAINS:
                self._emit("EMAILADDR", email, event)

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
        if not wanted or f"core:{wanted}" in self.results:
            return
        self.results[f"core:{wanted}"] = True
        core = " ".join(re.findall(r"[^\W_]+", wanted))

        if self.opts.get('recalls'):
            self.recalls(core, wanted, event)
        if self.opts.get('registrations') and not self.errorState and not self.checkForStop():
            self.registrations(core, wanted, event)

# End of sfp_openfda class
