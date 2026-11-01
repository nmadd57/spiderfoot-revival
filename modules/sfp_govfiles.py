# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_govfiles
# Purpose:      Search US state business registries (all 50 states + DC) through
#               the GovFiles corporate entity API.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin

NEW_ENGLAND = "us_ct,us_ma,us_me,us_nh,us_ri,us_vt"

STATE_NAMES = {
    'us_ak': "Alaska", 'us_al': "Alabama", 'us_ar': "Arkansas", 'us_az': "Arizona", 'us_ca': "California",
    'us_co': "Colorado", 'us_ct': "Connecticut", 'us_dc': "District of Columbia", 'us_de': "Delaware",
    'us_fl': "Florida", 'us_ga': "Georgia", 'us_hi': "Hawaii", 'us_ia': "Iowa", 'us_id': "Idaho",
    'us_il': "Illinois", 'us_in': "Indiana", 'us_ks': "Kansas", 'us_ky': "Kentucky", 'us_la': "Louisiana",
    'us_ma': "Massachusetts", 'us_md': "Maryland", 'us_me': "Maine", 'us_mi': "Michigan", 'us_mn': "Minnesota",
    'us_mo': "Missouri", 'us_ms': "Mississippi", 'us_mt': "Montana", 'us_nc': "North Carolina",
    'us_nd': "North Dakota", 'us_ne': "Nebraska", 'us_nh': "New Hampshire", 'us_nj': "New Jersey",
    'us_nm': "New Mexico", 'us_nv': "Nevada", 'us_ny': "New York", 'us_oh': "Ohio", 'us_ok': "Oklahoma",
    'us_or': "Oregon", 'us_pa': "Pennsylvania", 'us_ri': "Rhode Island", 'us_sc': "South Carolina",
    'us_sd': "South Dakota", 'us_tn': "Tennessee", 'us_tx': "Texas", 'us_ut': "Utah", 'us_va': "Virginia",
    'us_vt': "Vermont", 'us_wa': "Washington", 'us_wi': "Wisconsin", 'us_wv': "West Virginia",
    'us_wy': "Wyoming",
}

# Roles that make a company party an affiliate rather than a service provider
_AFFILIATE_ROLES = {"manager", "member", "owner", "shareholder", "governor", "officer"}


def _fmt_addr(a):
    if not isinstance(a, dict):
        return None
    street = ", ".join(p.strip() for p in [a.get('street_address'), a.get('street_address_2')] if p and p.strip())
    if street:
        tail = " ".join(p for p in [a.get('region'), a.get('postal_code')] if p)
        parts = [street, a.get('locality'), tail]
        if a.get('country_code') and a['country_code'].upper() not in ("US", "USA"):
            parts.append(a.get('country'))
        return ", ".join(p.strip() for p in parts if p and p.strip())
    raw = re.sub(r"\s+", " ", str(a.get('raw') or "")).strip(" ,")
    return raw or None


class sfp_govfiles(SpiderFootPlugin):

    meta = {
        'name': "GovFiles",
        'summary': "Search state business registries (all 50 states and DC, including Massachusetts and "
                   "New Hampshire) for a company: status, formation, addresses, officers, agents and filings.",
        'flags': ["apikey"],
        'pricing': 'free_key',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://govfiles.dev/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.govfiles.dev/",
                "https://docs.govfiles.dev/guides/company-schema",
                "https://docs.govfiles.dev/guides/jurisdictions",
            ],
            'apiKeyInstructions': [
                "Visit https://govfiles.dev/",
                "Sign up for a free account (includes 1,000 free credits)",
                "Copy the API key from your dashboard",
            ],
            'description': "GovFiles ingests the business entity records each US state publishes and serves "
                           "them from one API: legal name, status, legal form, formation date, registered, "
                           "headquarters and mailing addresses, officers, members, registered agents, "
                           "alternative and previous names, and filings. Each returned search result costs one "
                           "credit (about $0.01); searches with no results are free.",
        }
    }

    opts = {
        'api_key': '',
        'jurisdictions': NEW_ENGLAND,
        'max_results': 10,
        'exact_match': True,
        'other_names': False,
    }

    optdescs = {
        'api_key': "GovFiles API key.",
        'jurisdictions': "Comma-separated state codes to search (e.g. us_ma,us_nh), or 'all'. Default is the "
                         "six New England states. Every returned result costs a credit, so keep this narrow.",
        'max_results': "Maximum results to request per search (each returned result costs one credit).",
        'exact_match': "Only report entities whose name matches the target once legal-form words (Inc, LLC, "
                       "Corp...) and punctuation are ignored.",
        'other_names': "Report the entity's DBAs, trade names and previous names as new company names to "
                       "search (each triggers further lookups and credits).",
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
        return ["RAW_RIR_DATA", "PHYSICAL_ADDRESS", "HUMAN_NAME", "PHONE_NUMBER", "AFFILIATE_COMPANY_NAME",
                "AFFILIATE_INTERNET_NAME", "COMPANY_NAME"]

    def jurisdictions(self) -> str:
        val = str(self.opts.get('jurisdictions') or '').strip().lower()
        if not val or val == "all":
            return "all"
        codes = [c.strip() for c in val.split(",") if c.strip()]
        codes = [c if c.startswith("us_") else f"us_{c}" for c in codes]
        return ",".join(c for c in codes if re.fullmatch(r"us_[a-z]{2}", c)) or "all"

    def search(self, name: str):
        body = {
            'q': f'"{name}"',
            'match_alternative_names': True,
            'match_previous_names': True,
            'jurisdictions': self.jurisdictions(),
            'status': "any",
            'order_by': "relevance",
            'limit': max(1, min(100, int(self.opts.get('max_results') or 10))),
            'page': 1,
        }
        res = self.sf.fetchUrl(
            "https://api.govfiles.dev/v2/companies/search",
            postData=json.dumps(body),
            headers={'X-API-Key': self.opts['api_key'], 'Content-Type': "application/json",
                     'Accept': "application/json"},
            timeout=max(30, int(self.opts.get('_fetchtimeout') or 0)),
            useragent=self.opts['_useragent'],
        )
        code = str(res.get('code'))
        if code == "401":
            self.error("GovFiles rejected the API key.")
            self.errorState = True
            return None
        if code == "402":
            self.error("GovFiles account is out of credits.")
            self.errorState = True
            return None
        if code == "429":
            self.error("GovFiles rate limit reached.")
            return None
        if code != "200" or not res.get('content'):
            self.debug(f"GovFiles search returned HTTP {code}: {str(res.get('content'))[:200]}")
            return None
        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error parsing GovFiles JSON: {e}")
            return None

    def _emit(self, etype: str, data, source):
        data = str(data or "").strip()
        if not data:
            return
        key = f"{etype}:{data.lower()}"
        if key in self.results:
            return
        self.results[key] = True
        self.notifyListeners(SpiderFootEvent(etype, data, self.__name__, source))

    def report(self, company: dict, event, wanted: str):
        jur = company.get('jurisdiction_code') or ''
        state = STATE_NAMES.get(jur, jur.upper())
        parties = company.get('parties') or []
        addresses = company.get('addresses') or {}

        people, affiliates, agents = [], [], []
        for p in parties:
            roles = [r.get('kind') for r in p.get('roles') or [] if isinstance(r, dict)]
            titles = [r.get('title') or r.get('kind') for r in p.get('roles') or [] if isinstance(r, dict)]
            label = f"{p.get('name')} ({', '.join(t for t in titles if t)})" if titles else p.get('name')
            if "registered_agent" in roles:
                agents.append(label)
            if p.get('type') == "person":
                people.append(label)
            elif p.get('type') == "company" and set(roles) & _AFFILIATE_ROLES:
                affiliates.append(p.get('name'))

        record = {
            'source': f"{state} business registry (via GovFiles)",
            'state': state,
            'jurisdiction_code': jur,
            'entity_number': company.get('entity_number'),
            'name': company.get('legal_name'),
            'status': company.get('status_raw') or company.get('status'),
            'legal_form': company.get('legal_form_raw') or company.get('legal_form'),
            'domicile': company.get('domicile'),
            'formed_on': company.get('formed_on'),
            'dissolved_on': company.get('dissolved_on'),
            'addresses': {k: _fmt_addr(v) for k, v in addresses.items() if _fmt_addr(v)},
            'registered_agents': agents,
            'people': people,
            'other_names': [f"{n.get('name')} ({n.get('kind')})" for n in company.get('names') or []
                            if isinstance(n, dict) and n.get('name')],
            'filings': [{k: f.get(k) for k in ('filed_on', 'title', 'url') if f.get(k)}
                        for f in (company.get('filings') or [])[:20] if isinstance(f, dict)],
            'relationships': company.get('relationships') or None,
            'industry_codes': company.get('industry_codes') or None,
            'identifiers': company.get('identifiers') or None,
            'contact': company.get('contact') or None,
            'url': company.get('entity_url') or company.get('search_url'),
            'as_of': company.get('as_of'),
        }
        self.notifyListeners(SpiderFootEvent(
            "RAW_RIR_DATA", json.dumps({k: v for k, v in record.items() if v}, ensure_ascii=False, default=str),
            self.__name__, event))

        # Registered office is usually the agent's; only use it when there are no other addresses
        own = [_fmt_addr(addresses.get(k)) for k in ('headquarters', 'mailing')]
        own = [a for a in own if a] or ([_fmt_addr(addresses.get('registered'))] if not agents else [])
        for addr in own:
            self._emit("PHYSICAL_ADDRESS", addr, event)

        for p in parties:
            if p.get('type') == "person":
                name = re.sub(r"\s+", " ", str(p.get('name') or "")).strip()
                if len(name.split()) >= 2:
                    self._emit("HUMAN_NAME", name.title() if name.isupper() else name, event)
        for name in affiliates:
            if name and SpiderFootHelpers.normalizeCompanyName(name) != wanted:
                self._emit("AFFILIATE_COMPANY_NAME", name, event)
        for rel in company.get('relationships') or []:
            other = rel.get('entity') if isinstance(rel, dict) else None
            if isinstance(other, dict) and other.get('name'):
                if SpiderFootHelpers.normalizeCompanyName(other['name']) != wanted:
                    self._emit("AFFILIATE_COMPANY_NAME", other['name'], event)

        contact = company.get('contact') or {}
        phone = re.sub(r"[^\d+]", "", str(contact.get('phone') or ""))
        if len(phone) == 10:
            phone = "+1" + phone
        elif len(phone) == 11 and phone.startswith("1"):
            phone = "+" + phone
        if len(phone) >= 11:
            self._emit("PHONE_NUMBER", phone, event)
        for site in contact.get('websites') or []:
            site = str(site or "").strip()
            host = urllib.parse.urlparse(site if "://" in site else f"http://{site}").hostname if site else None
            if host and self.sf.validHost(host, self.opts.get('_internettlds')):
                self._emit("AFFILIATE_INTERNET_NAME", host.lower(), event)

        if self.opts.get('other_names'):
            for n in company.get('names') or []:
                name = n.get('name') if isinstance(n, dict) else None
                if name and SpiderFootHelpers.normalizeCompanyName(name) != wanted:
                    self._emit("COMPANY_NAME", name, event)

    def handleEvent(self, event):
        eventData = event.data

        if self.errorState:
            return
        if not self.opts.get('api_key'):
            self.error("You enabled sfp_govfiles but did not set an API key!")
            self.errorState = True
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

        # Quoted phrase on the core name: "Acme Widgets" also finds "ACME WIDGETS, INC."
        core = " ".join(re.findall(r"[^\W_]+", wanted))
        data = self.search(core)
        if not data:
            return

        reported = 0
        for result in data.get('results') or []:
            company = (result or {}).get('company') or {}
            name = company.get('legal_name')
            if not name:
                continue
            if self.opts['exact_match']:
                match = (result.get('match') or {}).get('matched_value') or name
                if wanted not in (SpiderFootHelpers.normalizeCompanyName(name),
                                  SpiderFootHelpers.normalizeCompanyName(match)):
                    continue
            key = f"entity:{company.get('jurisdiction_code')}:{company.get('entity_number') or name}"
            if key in self.results:
                continue
            self.results[key] = True
            self.report(company, event, wanted)
            reported += 1

        summary = data.get('summary') or {}
        self.info(f"GovFiles: {reported} matching entities for {eventData} "
                  f"({summary.get('total_matches', 0)} matches in {', '.join(summary.get('jurisdictions_searched') or []) or 'all states'})")

# End of sfp_govfiles class
