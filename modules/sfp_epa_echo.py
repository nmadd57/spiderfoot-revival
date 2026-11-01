# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_epa_echo
# Purpose:      Find a business's EPA-regulated facilities and their
#               environmental compliance history via EPA ECHO.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin

# ECHO facility fields worth keeping in the raw record
_FIELDS = {
    'RegistryID': 'registry_id', 'FacName': 'name', 'FacSICDescs': 'sic', 'FacNAICSCodes': 'naics',
    'FacComplianceStatus': 'compliance_status', 'CAAComplianceStatus': 'clean_air_act',
    'CWAComplianceStatus': 'clean_water_act', 'RCRAComplianceStatus': 'hazardous_waste_rcra',
    'SDWAComplianceStatus': 'safe_drinking_water_act', 'FacSNCFlg': 'significant_violator',
    'FacQtrsWithNC': 'quarters_in_noncompliance', 'FacInspectionCount': 'inspections_5yr',
    'FacDateLastInspection': 'last_inspection', 'FacFormalActionCount': 'formal_actions_5yr',
    'FacTotalPenalties': 'penalties_5yr', 'FacDateLastPenalty': 'last_penalty',
    'CWAPermitTypes': 'water_permits', 'RCRAPermitTypes': 'waste_permits', 'TRIIDs': 'toxics_release_ids',
    'GHGFlag': 'greenhouse_gas_reporter',
}


class sfp_epa_echo(SpiderFootPlugin):

    meta = {
        'name': "EPA ECHO",
        'summary': "Find a business's EPA-regulated facilities (air, water, hazardous waste, drinking water) "
                   "with their addresses, inspections, violations and penalties.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://echo.epa.gov/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://echo.epa.gov/tools/web-services",
                "https://echo.epa.gov/tools/web-services/facility-search-all-data",
            ],
            'favIcon': "https://echo.epa.gov/favicon.ico",
            'description': "Enforcement and Compliance History Online (ECHO) is the EPA's public database of "
                           "regulated facilities. For each facility it gives the location, permits under the "
                           "Clean Air Act, Clean Water Act and RCRA, compliance status, inspections, "
                           "enforcement actions and penalties over the last five years.",
        }
    }

    opts = {
        'max_facilities': 25,
        'name_match': "prefix",
    }

    optdescs = {
        'max_facilities': "Maximum number of facilities to report.",
        'name_match': "How facility names must match the target: 'exact' (same name once legal-form words "
                      "are ignored) or 'prefix' (facility name starts with the target, e.g. "
                      "'ACME CORP - PLANT 2').",
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

    def _json(self, service: str, params: dict):
        url = f"https://echodata.epa.gov/echo/echo_rest_services.{service}?" + urllib.parse.urlencode(
            {'output': "JSON", **params})
        res = self.sf.fetchUrl(url, timeout=max(30, int(self.opts.get('_fetchtimeout') or 0)),
                               useragent=self.opts['_useragent'])
        if str(res.get('code')) != "200" or not res.get('content'):
            self.debug(f"EPA ECHO returned HTTP {res.get('code')}")
            return None
        try:
            return (json.loads(res['content']) or {}).get('Results') or {}
        except Exception as e:
            self.debug(f"Error parsing EPA ECHO JSON: {e}")
            return None

    def facilities(self, name: str) -> list:
        query = self._json("get_facilities", {'p_fn': name})
        qid = (query or {}).get('QueryID')
        if not qid:
            if query and query.get('Error'):
                self.debug(f"EPA ECHO error: {query['Error']}")
            return []
        page = self._json("get_qid", {'qid': qid, 'pageno': 1})
        return [f for f in (page or {}).get('Facilities') or [] if isinstance(f, dict)]

    @staticmethod
    def cleanName(name: str) -> str:
        # ECHO prefixes some names with a program ID: "136430 - ACME UNITED CORPORATION"
        return re.sub(r"^\s*[\w-]*\d[\w-]*\s+-\s+", "", str(name or "")).strip()

    def nameMatches(self, facility: str, wanted: str) -> bool:
        norm = SpiderFootHelpers.normalizeCompanyName(self.cleanName(facility))
        if norm == wanted:
            return True
        if self.opts.get('name_match') == "exact":
            return False
        if not norm.startswith(wanted + " "):
            return False
        # "ACME CORP - PLANT 2" is a facility of Acme; "ACME HOLDINGS" is a different company
        rest = norm[len(wanted):].split()
        suffixes = {s.replace(".", "").upper() for s in SpiderFootHelpers.COMPANY_SUFFIXES}
        return not rest or rest[0] in suffixes or "-" in self.cleanName(facility)

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

        reported = 0
        for fac in self.facilities(" ".join(re.findall(r"[^\W_]+", wanted))):
            if reported >= max(1, int(self.opts.get('max_facilities') or 25)):
                break
            if not self.nameMatches(fac.get('FacName'), wanted):
                continue
            rid = fac.get('RegistryID')
            if not rid or f"fac:{rid}" in self.results:
                continue
            self.results[f"fac:{rid}"] = True
            reported += 1

            address = ", ".join(p for p in [
                str(fac.get('FacStreet') or '').strip(), str(fac.get('FacCity') or '').strip(),
                " ".join(p for p in [fac.get('FacState'), fac.get('FacZip')] if p)] if p)
            record = {'source': "EPA ECHO regulated facility",
                      'url': f"https://echo.epa.gov/detailed-facility-report?fid={rid}",
                      'address': address}
            for key, label in _FIELDS.items():
                val = fac.get(key)
                if val not in (None, "", "0", "$0", "N"):
                    record[label] = val
            self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", json.dumps(record, ensure_ascii=False),
                                                 self.__name__, event))
            if fac.get('FacStreet') and f"addr:{address.lower()}" not in self.results:
                self.results[f"addr:{address.lower()}"] = True
                self.notifyListeners(SpiderFootEvent("PHYSICAL_ADDRESS", address, self.__name__, event))

# End of sfp_epa_echo class
