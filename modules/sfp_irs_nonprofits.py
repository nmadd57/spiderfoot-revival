# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_irs_nonprofits
# Purpose:      Look up tax-exempt organisations (IRS Form 990 filers) by name
#               via ProPublica's Nonprofit Explorer API.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


class sfp_irs_nonprofits(SpiderFootPlugin):

    meta = {
        'name': "IRS Nonprofits (990)",
        'summary': "Look up tax-exempt organisations by name: EIN, IRS subsection, NTEE category, address, "
                   "ruling date, revenue and assets, and links to recent Form 990 filings.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://projects.propublica.org/nonprofits/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://projects.propublica.org/nonprofits/api",
                "https://www.irs.gov/charities-non-profits/exempt-organizations-business-master-file-extract-eo-bmf",
            ],
            'favIcon': "https://projects.propublica.org/favicon.ico",
            'description': "ProPublica's Nonprofit Explorer republishes the IRS Exempt Organizations Business "
                           "Master File and the Form 990 returns the IRS releases: every tax-exempt "
                           "organisation's EIN, address, classification, and its filed revenue, expenses and "
                           "assets by year.",
        }
    }

    opts = {
        'max_results': 5,
        'filings': 3,
    }

    optdescs = {
        'max_results': "Maximum number of organisations to report.",
        'filings': "Number of recent Form 990 filings to summarise per organisation.",
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
        return ["RAW_RIR_DATA", "PHYSICAL_ADDRESS", "HUMAN_NAME"]

    def _json(self, url: str):
        res = self.sf.fetchUrl(url, timeout=max(30, int(self.opts.get('_fetchtimeout') or 0)),
                               useragent=self.opts['_useragent'])
        if str(res.get('code')) != "200" or not res.get('content'):
            self.debug(f"Nonprofit Explorer returned HTTP {res.get('code')} for {url}")
            return None
        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error parsing Nonprofit Explorer JSON: {e}")
            return None

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
        data = self._json("https://projects.propublica.org/nonprofits/api/v2/search.json?"
                          + urllib.parse.urlencode({'q': f'"{core}"'}))
        orgs = [o for o in (data or {}).get('organizations') or []
                if isinstance(o, dict) and wanted in (SpiderFootHelpers.normalizeCompanyName(o.get('name')),
                                                      SpiderFootHelpers.normalizeCompanyName(o.get('sub_name')))]

        for org in orgs[:max(1, int(self.opts.get('max_results') or 5))]:
            if self.checkForStop():
                return
            ein = org.get('ein')
            if not ein or f"ein:{ein}" in self.results:
                continue
            self.results[f"ein:{ein}"] = True
            detail = self._json(f"https://projects.propublica.org/nonprofits/api/v2/organizations/{int(ein)}.json") or {}
            o = detail.get('organization') or org

            address = ", ".join(str(p).strip() for p in [
                o.get('address'), o.get('city'), " ".join(str(x) for x in [o.get('state'), o.get('zipcode')] if x)]
                if p and str(p).strip())
            filings = [{
                'tax_year': f.get('tax_prd_yr'),
                'revenue': f.get('totrevenue'),
                'expenses': f.get('totfuncexpns'),
                'assets': f.get('totassetsend'),
                'officer_compensation': f.get('compnsatncurrofcr'),
                'pdf': f.get('pdf_url'),
            } for f in (detail.get('filings_with_data') or [])[:max(0, int(self.opts.get('filings') or 0))]]
            record = {
                'source': "IRS exempt organisation (ProPublica Nonprofit Explorer)",
                'name': o.get('name'),
                'ein': org.get('strein') or ein,
                'subsection': f"501(c)({o.get('subsection_code')})" if o.get('subsection_code') else None,
                'ntee_code': o.get('ntee_code'),
                'ruling_date': o.get('ruling_date'),
                'address': address or None,
                'care_of': o.get('careofname'),
                'revenue': o.get('revenue_amount'),
                'income': o.get('income_amount'),
                'assets': o.get('asset_amount'),
                'filings': filings or None,
                'url': f"https://projects.propublica.org/nonprofits/organizations/{int(ein)}",
            }
            self.notifyListeners(SpiderFootEvent(
                "RAW_RIR_DATA", json.dumps({k: v for k, v in record.items() if v not in (None, "")},
                                           ensure_ascii=False, default=str), self.__name__, event))
            if o.get('address') and f"addr:{address.lower()}" not in self.results:
                self.results[f"addr:{address.lower()}"] = True
                self.notifyListeners(SpiderFootEvent("PHYSICAL_ADDRESS", address, self.__name__, event))

            # "% KAREN G FINE" -> the person mail is addressed to (usually an officer)
            care = re.sub(r"^\s*(?:%|C/O)\s*", "", str(o.get('careofname') or ''), flags=re.IGNORECASE).strip()
            if len(care.split()) >= 2 and not SpiderFootHelpers.looksLikeCompanyName(care) and \
                    f"person:{care.lower()}" not in self.results:
                self.results[f"person:{care.lower()}"] = True
                self.notifyListeners(SpiderFootEvent("HUMAN_NAME", care.title() if care.isupper() else care,
                                                     self.__name__, event))

# End of sfp_irs_nonprofits class
