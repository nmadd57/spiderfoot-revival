# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_dol_enforcement
# Purpose:      Look up a business in US Department of Labor enforcement data:
#               OSHA inspections/violations and Wage and Hour Division cases.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin

API = "https://apiprod.dol.gov/v4/get"

INSPECTION_TYPES = {
    'A': "Accident", 'B': "Complaint", 'C': "Referral", 'D': "Monitoring", 'E': "Variance",
    'F': "Follow-up", 'G': "Unprogrammed related", 'H': "Planned", 'I': "Unprogrammed other",
    'J': "Programmed related", 'K': "Programmed other", 'L': "Other", 'M': "Fatality/catastrophe",
}
INSPECTION_SCOPES = {'A': "Complete", 'B': "Partial", 'C': "Records only", 'D': "No inspection"}
# WHD violation counters (<prefix>_violtn_cnt) by the law they fall under
WHD_LAWS = {
    'flsa': "FLSA (minimum wage/overtime)", 'flsa_cl': "FLSA child labor", 'fmla': "FMLA",
    'sca': "Service Contract Act", 'dbra': "Davis-Bacon", 'cwhssa': "Contract Work Hours",
    'mspa': "Migrant and Seasonal Worker Protection", 'h1a': "H-1A", 'h1b': "H-1B", 'h2a': "H-2A",
    'h2b': "H-2B", 'eppa': "Polygraph Protection", 'ccpa': "Wage garnishment (CCPA)",
    'crew': "Crewmember", 'pca': "Public Contracts", 'sraw': "Agricultural worker housing",
    'osha': "Field sanitation/housing (OSHA)", 'ca': "Child labor (other)", 'eev': "E-Verify",
}
VIOLATION_TYPES = {'S': "Serious", 'W': "Willful", 'R': "Repeat", 'O': "Other-than-serious",
                   'U': "Unclassified"}


def _addr(street, city, state, zipcode):
    street = str(street or "").strip()
    if not street:
        return None
    zipcode = str(zipcode or "").strip()
    tail = " ".join(p for p in [str(state or "").strip(), "" if zipcode in ("", "00000") else zipcode] if p)
    return ", ".join(p for p in [street, str(city or "").strip(), tail] if p)


class sfp_dol_enforcement(SpiderFootPlugin):

    meta = {
        'name': "DOL Enforcement (OSHA, Wage & Hour)",
        'summary': "Look up a business in Department of Labor enforcement records: OSHA inspections, "
                   "citations and penalties, and Wage and Hour Division cases (back wages, penalties).",
        'flags': ["apikey"],
        'pricing': 'free_key',
        'useCases': ["Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://dataportal.dol.gov/",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://dataportal.dol.gov/",
                "https://dataportal.dol.gov/registration",
                "https://dataportal.dol.gov/api-keys",
            ],
            'apiKeyInstructions': [
                "Visit https://dataportal.dol.gov/registration and sign in with Login.gov",
                "Complete the registration",
                "Create a key at https://dataportal.dol.gov/api-keys",
            ],
            'favIcon': "https://www.dol.gov/themes/opa_theme/img/favicon.ico",
            'description': "The Department of Labor's Open Data Portal publishes OSHA's inspection and "
                           "violation records (every federal and state-plan workplace inspection since the "
                           "1970s, with citations and penalties) and the Wage and Hour Division's compliance "
                           "actions (minimum wage, overtime, child labor, FMLA, H-1B), with back wages owed "
                           "and civil money penalties.",
        }
    }

    opts = {
        'api_key': '',
        'osha': True,
        'whd': True,
        'max_inspections': 25,
        'max_cases': 25,
        'name_match': "prefix",
    }

    optdescs = {
        'api_key': "DOL Open Data Portal API key.",
        'osha': "Search OSHA inspections, and the violations and penalties from them.",
        'whd': "Search Wage and Hour Division enforcement cases.",
        'max_inspections': "Maximum number of OSHA inspections to report (most recent first).",
        'max_cases': "Maximum number of Wage and Hour cases to report.",
        'name_match': "How establishment names must match the target: 'exact' (same name once legal-form "
                      "words are ignored) or 'prefix' (site names such as 'ACME CORP - PLANT 2' too).",
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
        return ["RAW_RIR_DATA", "PHYSICAL_ADDRESS"]

    # ------------------------------------------------------------------ HTTP

    def query(self, dataset: str, filter_object: dict, **params) -> list:
        """Query a DOL v4 dataset. The key only works as the X-API-KEY query parameter."""
        qs = {'X-API-KEY': self.opts['api_key'], 'filter_object': json.dumps(filter_object), **params}
        url = f"{API}/{dataset}/json?" + urllib.parse.urlencode(qs)
        for attempt in range(3):
            res = self.sf.fetchUrl(url, timeout=max(60, int(self.opts.get('_fetchtimeout') or 0)),
                                   useragent=self.opts['_useragent'])
            code = str(res.get('code'))
            if code == "429" and attempt < 2:
                # The API gateway allows short bursts only; back off and retry
                time.sleep(2 * (attempt + 1))
                continue
            break
        if code in ("401", "403"):
            self.error("The DOL API rejected the API key.")
            self.errorState = True
            return []
        if code == "204":  # no matching rows
            return []
        if code != "200" or not res.get('content') or not str(res['content']).strip():
            self.debug(f"DOL {dataset} returned HTTP {code}")
            if code == "429":
                self.error("The DOL API is rate limiting requests.")
            return []
        try:
            return json.loads(res['content']).get('data') or []
        except Exception as e:
            self.debug(f"Error parsing DOL JSON: {e}")
            return []

    @staticmethod
    def namePatterns(wanted: str) -> list:
        """LIKE patterns for a name: the API's LIKE is case-sensitive, so try both cases."""
        words = re.findall(r"[^\W_]+", wanted)
        if not words:
            return []
        upper = "%".join(w.upper() for w in words) + "%"
        title = "%".join(w.capitalize() for w in words) + "%"
        return sorted({upper, title})

    def nameMatches(self, name: str, wanted: str) -> bool:
        return SpiderFootHelpers.facilityNameMatches(name, wanted, prefix=self.opts.get('name_match') != "exact")

    def _emit_addr(self, addr, event):
        if addr and f"addr:{addr.lower()}" not in self.results:
            self.results[f"addr:{addr.lower()}"] = True
            self.notifyListeners(SpiderFootEvent("PHYSICAL_ADDRESS", addr, self.__name__, event))

    # ------------------------------------------------------------------ OSHA

    def osha(self, wanted: str, event):
        patterns = self.namePatterns(wanted)
        rows = self.query("OSHA/inspection",
                          {'or': [{'field': "estab_name", 'operator': "like", 'value': p} for p in patterns]},
                          limit=500, sort_by="open_date", sort="desc")
        inspections = [r for r in rows if self.nameMatches(r.get('estab_name'), wanted)]
        matched = len(inspections)
        inspections = inspections[:max(1, int(self.opts.get('max_inspections') or 25))]
        if not inspections or self.errorState:
            return

        violations = {}
        ids = [r['activity_nr'] for r in inspections if r.get('activity_nr')]
        if ids and not self.checkForStop():
            for v in self.query("OSHA/violation", {'field': "activity_nr", 'operator': "in", 'value': ids},
                                limit=5000):
                if v.get('delete_flag') == "X":
                    continue
                violations.setdefault(v.get('activity_nr'), []).append(v)

        listed = []
        totals = {'violations': 0, 'initial_penalties': 0.0, 'current_penalties': 0.0, 'by_type': {}}
        for r in inspections:
            vs = violations.get(r.get('activity_nr'), [])
            by_type = {}
            for v in vs:
                label = VIOLATION_TYPES.get(v.get('viol_type'), v.get('viol_type') or "Unknown")
                by_type[label] = by_type.get(label, 0) + 1
                totals['by_type'][label] = totals['by_type'].get(label, 0) + 1
            initial = round(sum(float(v.get('initial_penalty') or 0) for v in vs), 2)
            current = round(sum(float(v.get('current_penalty') or 0) for v in vs), 2)
            totals['violations'] += len(vs)
            totals['initial_penalties'] += initial
            totals['current_penalties'] += current
            site = _addr(r.get('site_address'), r.get('site_city'), r.get('site_state'), r.get('site_zip'))
            listed.append({
                'activity_nr': r.get('activity_nr'),
                'establishment': r.get('estab_name'),
                'address': site,
                'opened': str(r.get('open_date') or '')[:10] or None,
                'closed': str(r.get('close_case_date') or '')[:10] or None,
                'type': INSPECTION_TYPES.get(r.get('insp_type'), r.get('insp_type')),
                'scope': INSPECTION_SCOPES.get(r.get('insp_scope'), r.get('insp_scope')),
                'safety_or_health': {'S': "Safety", 'H': "Health"}.get(r.get('safety_hlth')),
                'employees_at_site': r.get('nr_in_estab'),
                'naics': r.get('naics_code') if r.get('naics_code') not in (None, "000000") else None,
                'violations': len(vs),
                'violations_by_type': by_type or None,
                'initial_penalty': initial or None,
                'current_penalty': current or None,
                'url': f"https://www.osha.gov/ords/imis/establishment.inspection_detail?id={r.get('activity_nr')}",
            })
            self._emit_addr(site, event)

        totals['initial_penalties'] = round(totals['initial_penalties'], 2)
        totals['current_penalties'] = round(totals['current_penalties'], 2)
        record = {
            'source': "OSHA inspections (Department of Labor)",
            'business': event.data,
            'inspections_found': f"{matched}+" if len(rows) >= 500 else matched,
            'inspections_listed': len(listed),
            'violations_in_listed': totals['violations'],
            'violations_by_type': totals['by_type'],
            'initial_penalties_in_listed': totals['initial_penalties'],
            'current_penalties_in_listed': totals['current_penalties'],
            'most_recent': listed[0]['opened'],
            'oldest_listed': listed[-1]['opened'],
            'list': [{k: v for k, v in i.items() if v not in (None, "")} for i in listed],
        }
        self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", json.dumps(record, ensure_ascii=False, default=str),
                                             self.__name__, event))

    # ------------------------------------------------------------------- WHD

    def whd(self, wanted: str, event):
        patterns = self.namePatterns(wanted)
        rows = self.query("WHD/enforcement",
                          {'or': [{'field': f, 'operator': "like", 'value': p}
                                  for f in ("legal_name", "trade_nm") for p in patterns]},
                          limit=500, sort_by="findings_end_date", sort="desc")
        cases = [r for r in rows if self.nameMatches(r.get('legal_name'), wanted)
                 or self.nameMatches(r.get('trade_nm'), wanted)]
        matched = len(cases)
        cases = cases[:max(1, int(self.opts.get('max_cases') or 25))]
        if not cases:
            return

        listed = []
        for r in cases:
            addr = _addr(r.get('street_addr_1_txt'), r.get('cty_nm'), r.get('st_cd'), r.get('zip_cd'))
            acts = {label: r[f"{key}_violtn_cnt"] for key, label in WHD_LAWS.items()
                    if r.get(f"{key}_violtn_cnt")}
            listed.append({
                'case_id': r.get('case_id'),
                'legal_name': r.get('legal_name'),
                'trade_name': r.get('trade_nm'),
                'address': addr,
                'industry': r.get('naics_code_description'),
                'findings_from': str(r.get('findings_start_date') or '')[:10] or None,
                'findings_to': str(r.get('findings_end_date') or '')[:10] or None,
                'violations': r.get('case_violtn_cnt'),
                'violations_by_law': acts or None,
                'employees_with_violations': r.get('ee_violtd_cnt'),
                'back_wages': r.get('bw_atp_amt'),
                'employees_owed_back_wages': r.get('ee_atp_cnt'),
                'civil_money_penalties': r.get('cmp_assd'),
                'repeat_violator': r.get('flsa_repeat_violator') if r.get('flsa_repeat_violator') not in
                (None, "N/A", "N") else None,
            })
            self._emit_addr(addr, event)

        record = {
            'source': "Wage and Hour Division cases (Department of Labor)",
            'business': event.data,
            'cases_found': f"{matched}+" if len(rows) >= 500 else matched,
            'cases_listed': len(listed),
            'violations_in_listed': sum(int(c.get('violations') or 0) for c in listed),
            'back_wages_in_listed': round(sum(float(c.get('back_wages') or 0) for c in listed), 2),
            'civil_money_penalties_in_listed': round(sum(float(c.get('civil_money_penalties') or 0)
                                                         for c in listed), 2),
            'list': [{k: v for k, v in c.items() if v not in (None, "", 0, 0.0)} for c in listed],
        }
        self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", json.dumps(record, ensure_ascii=False, default=str),
                                             self.__name__, event))

    # ----------------------------------------------------------------- event

    def handleEvent(self, event):
        eventData = event.data

        if self.errorState:
            return
        if not self.opts.get('api_key'):
            self.error("You enabled sfp_dol_enforcement but did not set an API key!")
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

        if self.opts.get('osha'):
            self.osha(wanted, event)
        if self.opts.get('whd') and not self.errorState and not self.checkForStop():
            self.whd(wanted, event)

# End of sfp_dol_enforcement class
