# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_fcc
# Purpose:      Look up a business in US Federal Communications Commission
#               records: Form 499 telecom filers, equipment authorization
#               grantees, the Intermediate Provider Registry and ECFS filings.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse
import xml.etree.ElementTree as ET

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


def _text(el, path: str) -> str:
    found = el.find(path) if el is not None else None
    return (found.text or "").strip() if found is not None and found.text else ""


def _xml_addr(el):
    if el is None:
        return None
    lines = [(a.text or "").strip() for a in el.findall('address_line') if a.text and a.text.strip()]
    if not lines:
        return None
    tail = " ".join(p for p in [_text(el, 'state'), _text(el, 'zip_code')] if p)
    return ", ".join(p for p in lines + [_text(el, 'city'), tail] if p)


def _us_phone(value) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10 or digits == "0" * 10:
        return ""
    return "+1" + digits


class sfp_fcc(SpiderFootPlugin):

    meta = {
        'name': "FCC Filings",
        'summary': "Look up a business in FCC records: Form 499 telecom filer registrations (officers, HQ, "
                   "FRN), equipment authorization grantees, the Intermediate Provider Registry and recent "
                   "ECFS docket filings.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://www.fcc.gov/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://apps.fcc.gov/cgb/form499/499a.cfm",
                "https://opendata.fcc.gov/d/3b3k-34jp",
                "https://opendata.fcc.gov/d/a6ec-cry4",
                "https://www.fcc.gov/ecfs/public-api-docs.html",
                "https://api.data.gov/signup/",
            ],
            'favIcon': "https://www.fcc.gov/themes/custom/fcc/favicon.ico",
            'description': "The Federal Communications Commission publishes the Form 499 Filer Database "
                           "(every telecom provider that contributes to the Universal Service Fund, with "
                           "officers, headquarters and FCC Registration Number), the equipment authorization "
                           "grantee register (companies that certify radio devices), the Intermediate "
                           "Provider Registry and the Electronic Comment Filing System (ECFS). ECFS needs a "
                           "free api.data.gov key; without one the shared DEMO_KEY is used, which is heavily "
                           "rate limited.",
        }
    }

    opts = {
        'form499': True,
        'grantees': True,
        'intermediate_providers': True,
        'ecfs': True,
        'ecfs_apikey': '',
        'max_filings': 10,
        'affiliates': True,
        'timeout': 30,
    }

    optdescs = {
        'form499': "Search the Form 499 Filer Database (telecom service providers).",
        'grantees': "Search FCC equipment authorization grantees (companies with FCC IDs).",
        'intermediate_providers': "Search the Intermediate Provider Registry (call routing providers).",
        'ecfs': "List recent filings the business made in FCC dockets (ECFS).",
        'ecfs_apikey': "api.data.gov API key for ECFS (free, https://api.data.gov/signup/). "
                       "Leave empty to use the rate-limited DEMO_KEY.",
        'max_filings': "Maximum number of ECFS filings to report.",
        'affiliates': "Report Form 499 filers whose holding company is the target as affiliates.",
        'timeout': "Seconds to wait for each FCC request.",
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
        return ["RAW_RIR_DATA", "PHYSICAL_ADDRESS", "PHONE_NUMBER", "HUMAN_NAME", "EMAILADDR",
                "AFFILIATE_COMPANY_NAME"]

    # ------------------------------------------------------------------ HTTP

    def _get(self, url: str, headers: dict = None):
        res = self.sf.fetchUrl(url, timeout=int(self.opts.get('timeout') or 30), headers=headers or {},
                               useragent=self.opts['_useragent'])
        code = str(res.get('code'))
        if code == "429":
            self.error(f"FCC rate limit hit for {urllib.parse.urlparse(url).netloc}")
            return None
        if code != "200" or not res.get('content'):
            self.debug(f"FCC request returned HTTP {code}: {url}")
            return None
        return res['content']

    def _json(self, url: str):
        content = self._get(url, {'Accept': 'application/json'})
        if not content:
            return None
        try:
            return json.loads(content)
        except Exception as e:
            self.debug(f"Error parsing FCC JSON: {e}")
            return None

    def _socrata(self, dataset: str, field: str, pattern: str, limit: int = 50) -> list:
        params = urllib.parse.urlencode({'$where': f"upper({field}) like '{pattern}'", '$limit': str(limit)})
        data = self._json(f"https://opendata.fcc.gov/resource/{dataset}.json?{params}")
        return data if isinstance(data, list) else []

    # --------------------------------------------------------------- emitting

    def _emit(self, etype: str, data: str, source):
        if not data:
            return
        key = f"{etype}:{data.lower()}"
        if key in self.results:
            return
        self.results[key] = True
        self.notifyListeners(SpiderFootEvent(etype, data, self.__name__, source))

    def _emit_person(self, name: str, source):
        name = re.sub(r"\s+", " ", str(name or "")).strip()
        if not name or len(name.split()) < 2 or SpiderFootHelpers.looksLikeCompanyName(name):
            return
        if name.lower() in ("none", "n/a", "contact contact"):
            return
        self._emit("HUMAN_NAME", name.title() if name.isupper() else name, source)

    def _emit_email(self, email: str, source):
        email = str(email or "").strip().lower()
        if not SpiderFootHelpers.validEmail(email):
            return
        if email.split("@")[-1] in SpiderFootHelpers.REGISTERED_AGENT_EMAIL_DOMAINS:
            return
        self._emit("EMAILADDR", email, source)

    def _emit_raw(self, record: dict, source):
        self.notifyListeners(SpiderFootEvent(
            "RAW_RIR_DATA", json.dumps(record, ensure_ascii=False, default=str), self.__name__, source))

    # ---------------------------------------------------------------- sources

    def form499(self, name: str, wanted: str, event):
        params = urllib.parse.urlencode({
            'FilerID': '', 'frn': '', 'operational': '', 'comm_type': 'Any Type',
            'LegalName': name, 'state': 'Any State', 'R1': 'and', 'XML': 'TRUE',
        })
        content = self._get(f"https://apps.fcc.gov/cgb/form499/499results.cfm?{params}")
        if not content:
            return
        try:
            root = ET.fromstring(content.encode('latin-1', errors='replace') if isinstance(content, str)
                                 else content)
        except ET.ParseError as e:
            self.debug(f"Error parsing Form 499 XML: {e}")
            return

        for filer in root.findall('Filer'):
            info = filer.find('Filer_ID_Info')
            legal = _text(info, 'Legal_Name')
            # Legal name only: resellers often put a carrier's brand ("AT&T") in their DBA
            if legal and SpiderFootHelpers.normalizeCompanyName(legal) == wanted:
                self._report499(filer, info, event)
            elif (self.opts['affiliates'] and legal
                  and SpiderFootHelpers.normalizeCompanyName(_text(info, 'holding_company')) == wanted):
                self._emit("AFFILIATE_COMPANY_NAME", legal, event)

    def _report499(self, filer, info, event):
        fid = _text(filer, 'Form_499_ID')
        if f"499:{fid}" in self.results:
            return
        self.results[f"499:{fid}"] = True

        reg = filer.find('FCC_Registration_information')
        officers = {
            'Chief Executive Officer': _text(reg, 'Chief_Executive_Officer'),
            'Chairman or Senior Officer': _text(reg, 'Chairman_or_Senior_Officer'),
            'President or Senior Officer': _text(reg, 'President_or_Senior_Officer'),
        }
        hq = _xml_addr(info.find('hq_address'))
        phone = _us_phone(_text(info, 'Customer_Inquiries_telephone'))
        agent = filer.find('Agent_for_Service_Of_Process')
        record = {
            'source': "FCC Form 499 Filer Database",
            'form_499_id': fid,
            'url': f"https://apps.fcc.gov/cgb/form499/499detail.cfm?FilerNum={fid}",
            'legal_name': _text(info, 'Legal_Name'),
            'doing_business_as': _text(info, 'doing_business_as') or None,
            'holding_company': _text(info, 'holding_company') or None,
            'frn': _text(info, 'FRN') or None,
            'communications_type': _text(info, 'Principal_Communications_Type') or None,
            'usf_contributor': _text(info, 'USF_Contributor') or None,
            'start_date': _text(info, 'start_date') or None,
            'end_date': _text(info, 'end_date') or None,
            'end_reason': _text(info, 'end_reason_desc') or None,
            'registration_current_as_of': _text(info, 'Registration_Current_as_of') or None,
            'hq_address': hq,
            'customer_inquiries_phone': phone or None,
            'officers': {k: v for k, v in officers.items() if v},
            'dc_agent': _text(agent, 'dc_agent') or None,
            'alternate_agent': _text(agent, 'alternate_agent') or None,
            'states': [s.text for s in filer.findall('jurisdiction_state') if s.text],
        }
        self._emit_raw({k: v for k, v in record.items() if v}, event)
        self._emit("PHYSICAL_ADDRESS", hq, event)
        self._emit("PHONE_NUMBER", phone, event)
        for person in officers.values():
            self._emit_person(person, event)
        self._emit_email(_text(agent, 'alternate_agent_email'), event)

    def grantees(self, pattern: str, wanted: str, event):
        for rec in self._socrata("3b3k-34jp", "grantee_name", pattern):
            if SpiderFootHelpers.normalizeCompanyName(rec.get('grantee_name')) != wanted:
                continue
            code = rec.get('grantee_code')
            if f"grantee:{code}" in self.results:
                continue
            self.results[f"grantee:{code}"] = True
            parts = [rec.get('mailing_address'), rec.get('city'),
                     " ".join(p for p in [rec.get('state'), rec.get('zip_code')] if p and p != "N/A"),
                     rec.get('country')]
            addr = ", ".join(p.strip() for p in parts if p and p.strip() and p.strip() != "N/A")
            self._emit_raw({
                'source': "FCC equipment authorization grantee",
                'grantee_code': code,
                'url': "https://apps.fcc.gov/oetcf/eas/reports/GenericSearch.cfm",  # search by grantee code
                'grantee_name': rec.get('grantee_name'),
                'address': addr,
                'contact': rec.get('contact_name'),
                'registered': rec.get('date_received'),
            }, event)
            self._emit("PHYSICAL_ADDRESS", addr if rec.get('mailing_address') else None, event)
            self._emit_person(rec.get('contact_name'), event)

    def intermediate_providers(self, pattern: str, wanted: str, event):
        for rec in self._socrata("a6ec-cry4", "business_name", pattern):
            if SpiderFootHelpers.normalizeCompanyName(rec.get('business_name')) != wanted:
                continue
            key = f"ipr:{rec.get('business_name')}:{rec.get('business_address')}"
            if key in self.results:
                continue
            self.results[key] = True
            self._emit_raw({'source': "FCC Intermediate Provider Registry",
                            'url': "https://opendata.fcc.gov/d/a6ec-cry4",
                            **{k: v for k, v in rec.items() if v and v != "None"}}, event)
            addr = str(rec.get('business_address') or '').replace(",", ", ").replace("  ", " ").strip()
            self._emit("PHYSICAL_ADDRESS", addr or None, event)
            for prefix in ('regulatory_contact', 'rural_call_completion_contact'):
                self._emit_person(rec.get(f"{prefix}_name"), event)
                self._emit_email(rec.get(f"{prefix}_email"), event)
                self._emit("PHONE_NUMBER", _us_phone(rec.get(f"{prefix}_telephone")), event)

    def ecfs(self, name: str, wanted: str, event):
        key = str(self.opts.get('ecfs_apikey') or '').strip() or "DEMO_KEY"
        limit = max(1, int(self.opts.get('max_filings') or 10))
        params = urllib.parse.urlencode({
            'api_key': key, 'filers.name': name, 'limit': str(min(100, limit * 3)),
            'sort': 'date_disseminated,DESC',
        })
        data = self._json(f"https://publicapi.fcc.gov/ecfs/filings?{params}")
        filings = []
        for f in (data or {}).get('filing') or []:
            filers = [x.get('name') for x in f.get('filers') or [] if x.get('name')]
            if not any(SpiderFootHelpers.normalizeCompanyName(x) == wanted for x in filers):
                continue
            sid = f.get('id_submission')
            filings.append({
                'id': sid,
                'date': str(f.get('date_disseminated') or f.get('date_received') or '')[:10],
                'type': (f.get('submissiontype') or {}).get('description'),
                'proceedings': [f"{p.get('name')}: {p.get('description_display') or p.get('description')}"
                                for p in f.get('proceedings') or []],
                'filers': filers,
                'authors': [x.get('name') for x in f.get('authors') or [] if x.get('name')],
                'url': f"https://www.fcc.gov/ecfs/search/search-filings/filing/{sid}",
            })
            if len(filings) >= limit:
                break
        if filings:
            self._emit_raw({'source': "FCC ECFS filings", 'filer': event.data,
                            'search': "https://www.fcc.gov/ecfs/search/search-filings?q="
                                      + urllib.parse.quote(f'filers.name:("{name}")'),
                            'filings': filings}, event)

    # ------------------------------------------------------------------ event

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
        words = re.findall(r"[^\W_]+", wanted)
        if not words:
            return
        if f"core:{wanted}" in self.results:
            return
        self.results[f"core:{wanted}"] = True
        pattern = "%".join(words) + "%"
        # Name searches use the core name so "Acme Corp" finds "ACME CORPORATION".
        # Form 499 does a plain substring match, so for names with inner punctuation
        # ("AT&T", "Yahoo!") search on the first word and filter the results here.
        core = " ".join(words)
        first = re.match(r"[^\W_]+", eventData.strip())
        search499 = core if re.fullmatch(r"[\w\s.,]+", eventData.strip()) or not first else first.group(0)

        steps = [
            ('form499', lambda: self.form499(search499, wanted, event)),
            ('grantees', lambda: self.grantees(pattern, wanted, event)),
            ('intermediate_providers', lambda: self.intermediate_providers(pattern, wanted, event)),
            ('ecfs', lambda: self.ecfs(core, wanted, event)),
        ]
        for opt, step in steps:
            if self.checkForStop():
                return
            if self.opts.get(opt):
                step()

# End of sfp_fcc class
