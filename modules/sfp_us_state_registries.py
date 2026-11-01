# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_us_state_registries
# Purpose:      Search US state business registries that publish their entity
#               records as open data (Socrata SODA APIs).
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


def _join(*parts) -> str:
    return " ".join(str(p).strip() for p in parts if p and str(p).strip())


def _addr(rec: dict, street: list, city: str, state: str, zipcode: str):
    line = ", ".join(str(rec.get(f)).strip() for f in street if rec.get(f) and str(rec.get(f)).strip())
    if not line or _EMPTY_RX.match(line):
        return None
    return ", ".join(p for p in [line, str(rec.get(city) or '').strip(),
                                 _join(rec.get(state), rec.get(zipcode))] if p)


def _ny(rec: dict) -> dict:
    people = []
    if rec.get('chairman_name'):
        people.append(("Chairman/CEO", rec['chairman_name']))
    process = ("Service of process", _addr(rec, ['dos_process_address_1', 'dos_process_address_2'],
                                           'dos_process_city', 'dos_process_state', 'dos_process_zip'))
    pname = rec.get('dos_process_name') or ''
    own_process = (not pname
                   or SpiderFootHelpers.normalizeCompanyName(pname)
                   == SpiderFootHelpers.normalizeCompanyName(rec.get('current_entity_name'))
                   or not SpiderFootHelpers.looksLikeCompanyName(pname))
    return {
        'id': rec.get('dos_id'),
        'name': rec.get('current_entity_name'),
        'status': "Active",
        'type': rec.get('entity_type'),
        'formed': rec.get('initial_dos_filing_date'),
        'jurisdiction': rec.get('jurisdiction'),
        'addresses': [
            ("Location", _addr(rec, ['location_address_1', 'location_address_2'], 'location_city',
                               'location_state', 'location_zip')),
        ] + ([process] if own_process else []),
        'agent_addresses': [] if own_process else [process],
        'process_name': pname or None,
        'people': people,
        'agent': rec.get('registered_agent_name'),
        'url': "https://apps.dos.ny.gov/publicInquiry/",
    }


def _co(rec: dict) -> dict:
    people = []
    agent = rec.get('agentorganizationname')
    person = _join(rec.get('agentfirstname'), rec.get('agentmiddlename'), rec.get('agentlastname'),
                   rec.get('agentsuffix'))
    if rec.get('agentfirstname') and rec.get('agentlastname'):
        people.append(("Registered agent", person))
    agent = agent or person
    eid = rec.get('entityid')
    return {
        'id': eid,
        'name': rec.get('entityname'),
        'status': rec.get('entitystatus'),
        'type': rec.get('entitytype'),
        'formed': rec.get('entityformdate'),
        'jurisdiction': rec.get('jurisdictonofformation'),
        'addresses': [
            ("Principal office", _addr(rec, ['principaladdress1', 'principaladdress2'], 'principalcity',
                                       'principalstate', 'principalzipcode')),
            ("Mailing", _addr(rec, ['mailingaddress1', 'mailingaddress2'], 'mailingcity',
                              'mailingstate', 'mailingzipcode')),
        ],
        'people': people,
        'agent': agent,
        'url': ("https://www.coloradosos.gov/biz/BusinessEntityDetail.do?"
                f"quitButtonDestination=BusinessEntityResults&masterFileId={eid}") if eid else None,
    }


def _ct(rec: dict) -> dict:
    mailing = re.sub(r"\s*,[\s,]*", ", ", str(rec.get('mailing_address') or '')).strip(" ,")
    mailing = re.sub(r", United States(?=,|$)", "", mailing)
    mailing = re.sub(r", ([A-Z]{2}), (\d{5}(?:-\d{4})?)$", r", \1 \2", mailing)
    return {
        'id': rec.get('accountnumber'),
        'name': rec.get('name'),
        'status': _join(rec.get('status'), f"({rec['sub_status']})" if rec.get('sub_status') else None),
        'type': rec.get('business_type'),
        'formed': rec.get('date_registration'),
        'jurisdiction': rec.get('state_or_territory_formation') or rec.get('formation_place'),
        'industry': rec.get('naics_code'),
        'addresses': [
            ("Principal office", _addr(rec, ['billingstreet', 'billing_unit'], 'billingcity',
                                       'billingstate', 'billingpostalcode')),
            ("Mailing", None if not mailing or _EMPTY_RX.match(mailing) else mailing),
        ],
        'people': [],
        'emails': [rec['business_email_address']] if rec.get('business_email_address') else [],
        'url': "https://service.ct.gov/business/s/onlinebusinesssearch",
    }


def _or(rows: list) -> dict:
    """Oregon publishes one row per associated name (agent, address...)."""
    first = rows[0]
    addresses, people, agent = [], [], None
    for r in rows:
        kind = str(r.get('associated_name_type') or '').title()
        addr = _addr(r, ['address', 'address_continued'], 'city', 'state', 'zip')
        person = _join(r.get('first_name'), r.get('middle_name'), r.get('last_name'), r.get('suffix'))
        if kind in ("Principal Place Of Business", "Mailing Address"):
            addresses.append((kind, addr))
        elif r.get('first_name') and r.get('last_name'):
            people.append((kind, person))
        if kind == "Registered Agent":
            agent = person or r.get('entity_of_record_name')
    return {
        'id': first.get('registry_number'),
        'name': first.get('business_name'),
        'status': "Active",
        'type': first.get('entity_type'),
        'formed': first.get('registry_date'),
        'jurisdiction': first.get('jurisdiction'),
        'addresses': addresses,
        'people': people,
        'agent': agent,
        'url': (first.get('business_details') or {}).get('url'),
    }


def _tx(rec: dict) -> dict:
    return {
        'id': rec.get('taxpayer_number'),
        'sos_file_number': rec.get('secretary_of_state_sos_or_coa_file_number'),
        'name': rec.get('taxpayer_name'),
        'status': "Active franchise taxpayer",
        'type': rec.get('taxpayer_organizational_type'),
        'formed': rec.get('sos_charter_date') or rec.get('responsibility_beginning_date'),
        'addresses': [
            ("Taxpayer", _addr(rec, ['taxpayer_address'], 'taxpayer_city', 'taxpayer_state', 'taxpayer_zip')),
        ],
        'people': [],
        'url': "https://comptroller.texas.gov/taxes/franchise/account-status/search",
    }


# state option -> dataset definition
REGISTRIES = {
    'state_ny': {'state': "New York", 'host': "data.ny.gov", 'dataset': "n9v6-gdp6",
                 'name_field': "current_entity_name", 'parse': _ny,
                 'note': "active corporations and LLCs"},
    'state_co': {'state': "Colorado", 'host': "data.colorado.gov", 'dataset': "4ykn-tg5h",
                 'name_field': "entityname", 'parse': _co, 'note': "all entities, including dissolved"},
    'state_ct': {'state': "Connecticut", 'host': "data.ct.gov", 'dataset': "n7gp-d28j",
                 'name_field': "name", 'parse': _ct, 'note': "all entities"},
    'state_or': {'state': "Oregon", 'host': "data.oregon.gov", 'dataset': "tckn-sxa6",
                 'name_field': "business_name", 'parse': _or, 'group_by': "registry_number",
                 'note': "active businesses"},
    'state_tx': {'state': "Texas", 'host': "data.texas.gov", 'dataset': "9cir-efmm",
                 'name_field': "taxpayer_name", 'parse': _tx, 'note': "active franchise taxpayers"},
}

# Placeholder text some registries put in empty fields
_EMPTY_RX = re.compile(r"^(?:no information provided|none|n/?a|unknown)[\s,]*$", re.IGNORECASE)

# Colorado appends the end state to the name: "ACME INC, Dissolved May 1, 2001"
_STATUS_TAIL_RX = re.compile(r",?\s+(?:Dissolved|Delinquent|Withdrawn|Expired|Converted|Merged|Consolidated|"
                             r"Revoked|Cancell?ed)\b.*$", re.IGNORECASE)


class sfp_us_state_registries(SpiderFootPlugin):

    meta = {
        'name': "US State Business Registries",
        'summary': "Search state business entity registries (New York, Colorado, Connecticut, Oregon, Texas) "
                   "for a company: status, entity type, formation date, addresses, registered agent and officers.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://dev.socrata.com/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://data.ny.gov/d/n9v6-gdp6",
                "https://data.colorado.gov/d/4ykn-tg5h",
                "https://data.ct.gov/d/n7gp-d28j",
                "https://data.oregon.gov/d/tckn-sxa6",
                "https://data.texas.gov/d/9cir-efmm",
                "https://dev.socrata.com/docs/app-tokens.html",
            ],
            'description': "Several US states publish their Secretary of State / Comptroller business entity "
                           "records on Socrata open-data portals with a free query API. No account is needed; "
                           "an optional Socrata app token raises the rate limit. States whose registries are "
                           "only available through a search website (e.g. Massachusetts, Delaware) are not covered.",
        }
    }

    opts = {
        'state_ny': True,
        'state_co': True,
        'state_ct': True,
        'state_or': True,
        'state_tx': True,
        'exact_match': True,
        'max_per_state': 10,
        'socrata_app_token': '',
        'timeout': 30,
    }

    optdescs = {
        'state_ny': "Search New York (Department of State, " + REGISTRIES['state_ny']['note'] + ").",
        'state_co': "Search Colorado (Secretary of State, " + REGISTRIES['state_co']['note'] + ").",
        'state_ct': "Search Connecticut (Secretary of the State, " + REGISTRIES['state_ct']['note'] + ").",
        'state_or': "Search Oregon (Secretary of State, " + REGISTRIES['state_or']['note'] + ").",
        'state_tx': "Search Texas (Comptroller, " + REGISTRIES['state_tx']['note'] + ").",
        'exact_match': "Only report entities whose name matches the target once legal-form words "
                       "(Inc, LLC, Corp...) and punctuation are ignored. Turn off to report every entity "
                       "whose name starts with the target.",
        'max_per_state': "Maximum number of entities to report per state.",
        'socrata_app_token': "Optional Socrata app token (free, from any Socrata portal) to raise the rate limit.",
        'timeout': "Seconds to wait for each state's API.",
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
        return ["PHYSICAL_ADDRESS", "HUMAN_NAME", "EMAILADDR", "RAW_RIR_DATA"]

    @staticmethod
    def likePattern(name: str):
        """SoQL LIKE pattern matching the name regardless of punctuation.

        "Acme Widgets, Inc." -> "ACME%WIDGETS%". Only letters and digits are
        kept, so the pattern needs no escaping.
        """
        words = re.findall(r"[^\W_]+", (name or "").upper())
        suffixes = {s.replace(".", "").upper() for s in SpiderFootHelpers.COMPANY_SUFFIXES}
        while len(words) > 1 and words[-1] in suffixes:
            words.pop()
        if len(words) > 1 and words[0] == "THE":
            words.pop(0)
        if not words:
            return None
        return "%".join(words) + "%"

    @staticmethod
    def cleanName(name: str) -> str:
        return _STATUS_TAIL_RX.sub("", str(name or "")).strip()

    def query(self, reg: dict, pattern: str, limit: int):
        params = {
            '$where': f"upper({reg['name_field']}) like '{pattern}'",
            '$limit': str(limit),
        }
        headers = {'Accept': 'application/json'}
        if self.opts.get('socrata_app_token'):
            headers['X-App-Token'] = self.opts['socrata_app_token']
        url = f"https://{reg['host']}/resource/{reg['dataset']}.json?" + urllib.parse.urlencode(params)
        res = self.sf.fetchUrl(url, timeout=int(self.opts.get('timeout') or 30), headers=headers,
                               useragent=self.opts['_useragent'])
        code = str(res.get('code'))
        if code == "429":
            self.error(f"{reg['state']} registry is rate limiting requests; add a Socrata app token.")
            return None
        if code != "200" or not res.get('content'):
            self.debug(f"{reg['state']} registry returned HTTP {code}")
            return None
        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error parsing {reg['state']} registry JSON: {e}")
            return None
        return data if isinstance(data, list) else None

    def entities(self, reg: dict, rows: list) -> list:
        key = reg.get('group_by')
        if not key:
            return [(reg['parse'](r), r) for r in rows]
        grouped = {}
        for r in rows:
            grouped.setdefault(r.get(key), []).append(r)
        return [(reg['parse'](g), g) for g in grouped.values()]

    def handleEvent(self, event):
        eventData = event.data

        if self.errorState:
            return
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return
        self.results[eventData] = True

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        pattern = self.likePattern(eventData)
        wanted = SpiderFootHelpers.normalizeCompanyName(eventData)
        if not pattern or not wanted:
            return

        maxn = max(1, int(self.opts.get('max_per_state') or 10))

        for opt, reg in REGISTRIES.items():
            if not self.opts.get(opt):
                continue
            if self.checkForStop():
                return

            # Oregon has several rows per entity; over-fetch so grouping still fills maxn.
            rows = self.query(reg, pattern, maxn * (8 if reg.get('group_by') else 5))
            if not rows:
                continue

            reported = 0
            for ent, raw in self.entities(reg, rows):
                if reported >= maxn:
                    break
                name = self.cleanName(ent.get('name'))
                if not name:
                    continue
                if self.opts['exact_match'] and SpiderFootHelpers.normalizeCompanyName(name) != wanted:
                    continue

                dedupe = f"{opt}:{ent.get('id') or name}"
                if dedupe in self.results:
                    continue
                self.results[dedupe] = True
                reported += 1

                summary = {
                    'source': f"{reg['state']} business registry",
                    'state': reg['state'],
                    **{k: v for k, v in ent.items() if v and k not in ('addresses', 'agent_addresses', 'people')},
                    'name': ent.get('name'),
                    'addresses': {k: v for k, v in ent.get('addresses', []) + ent.get('agent_addresses', []) if v},
                    'people': [f"{role}: {who}" for role, who in ent.get('people', [])],
                    'record': raw,
                }
                self.notifyListeners(SpiderFootEvent(
                    "RAW_RIR_DATA", json.dumps(summary, ensure_ascii=False, default=str), self.__name__, event))

                for addr in {a for _k, a in ent.get('addresses', []) if a}:
                    self.notifyListeners(SpiderFootEvent("PHYSICAL_ADDRESS", addr, self.__name__, event))

                for who in {w for _r, w in ent.get('people', []) if w}:
                    if SpiderFootHelpers.looksLikeCompanyName(who):
                        continue
                    self.notifyListeners(SpiderFootEvent("HUMAN_NAME", who.title(), self.__name__, event))

                for email in ent.get('emails', []):
                    if email.split("@")[-1].lower() in SpiderFootHelpers.REGISTERED_AGENT_EMAIL_DOMAINS:
                        continue
                    if SpiderFootHelpers.validEmail(email):
                        self.notifyListeners(SpiderFootEvent("EMAILADDR", email.lower(), self.__name__, event))

            if reported:
                self.info(f"Found {reported} {reg['state']} registry record(s) for {eventData}")

# End of sfp_us_state_registries class
