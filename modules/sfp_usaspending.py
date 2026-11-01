# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_usaspending
# Purpose:      Look up a business as a recipient of US federal contracts,
#               grants and loans on USAspending.gov.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


class sfp_usaspending(SpiderFootPlugin):

    meta = {
        'name': "USAspending",
        'summary': "Look up a business as a recipient of federal contracts, grants and loans: UEI/DUNS, "
                   "parent company, address, business types and total award amounts.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://www.usaspending.gov/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://api.usaspending.gov/docs/endpoints",
                "https://github.com/fedspendingtransparency/usaspending-api/blob/master/usaspending_api/"
                "api_contracts/contracts/v2/recipient.md",
            ],
            'favIcon': "https://www.usaspending.gov/img/favicon.ico",
            'description': "USAspending.gov is the official source of US federal spending data, run by the "
                           "Treasury. Each award recipient has a profile with its Unique Entity ID (UEI), legacy "
                           "DUNS, parent organisation, registered address, business type designations and the "
                           "total value of its federal transactions.",
        }
    }

    opts = {
        'max_recipients': 5,
        'exact_match': True,
    }

    optdescs = {
        'max_recipients': "Maximum number of recipient profiles to report (largest by award amount first). "
                          "A company often has one profile per registered location.",
        'exact_match': "Only report recipients whose name matches the target once legal-form words "
                       "(Inc, Corp, LLC...) and punctuation are ignored.",
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
        return ["RAW_RIR_DATA", "PHYSICAL_ADDRESS", "AFFILIATE_COMPANY_NAME"]

    def _call(self, url: str, body: dict = None):
        res = self.sf.fetchUrl(
            url, timeout=max(30, int(self.opts.get('_fetchtimeout') or 0)),
            postData=json.dumps(body) if body is not None else None,
            headers={'Content-Type': "application/json", 'Accept': "application/json"},
            useragent=self.opts['_useragent'])
        code = str(res.get('code'))
        if code != "200" or not res.get('content'):
            self.debug(f"USAspending returned HTTP {code} for {url}")
            if code == "429":
                self.error("USAspending is rate limiting requests.")
            return None
        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error parsing USAspending JSON: {e}")
            return None

    def search(self, name: str) -> list:
        data = self._call("https://api.usaspending.gov/api/v2/recipient/",
                          {'keyword': name, 'award_type': "all", 'limit': 50, 'page': 1,
                           'order': "desc", 'sort': "amount"})
        return [r for r in (data or {}).get('results') or [] if isinstance(r, dict)]

    def profile(self, recipient_id: str):
        if not re.fullmatch(r"[0-9a-f-]+-[CPR]", recipient_id or ""):
            return None
        return self._call(f"https://api.usaspending.gov/api/v2/recipient/{recipient_id}/")

    @staticmethod
    def formatAddress(loc: dict):
        if not isinstance(loc, dict) or not loc.get('address_line1'):
            return None
        street = ", ".join(loc[k].strip() for k in ('address_line1', 'address_line2', 'address_line3')
                           if loc.get(k) and str(loc[k]).strip())
        zipcode = "-".join(z for z in [loc.get('zip'), loc.get('zip4')] if z)
        parts = [street, loc.get('city_name'), " ".join(p for p in [loc.get('state_code'), zipcode] if p)]
        if loc.get('country_code') not in (None, "USA"):
            parts.append(loc.get('country_name'))
        return ", ".join(p for p in parts if p)

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

        recipients = self.search(" ".join(re.findall(r"[^\W_]+", wanted)))
        if self.opts['exact_match']:
            recipients = [r for r in recipients if SpiderFootHelpers.normalizeCompanyName(r.get('name')) == wanted]
        # Prefer the child/recipient-level profiles; parent rollups repeat the same company
        recipients.sort(key=lambda r: (r.get('recipient_level') == "P", -(r.get('amount') or 0)))

        reported = 0
        for rec in recipients:
            if reported >= max(1, int(self.opts.get('max_recipients') or 5)) or self.checkForStop():
                break
            rid = rec.get('id')
            if not rid or f"rid:{rid}" in self.results:
                continue
            self.results[f"rid:{rid}"] = True
            prof = self.profile(rid) or {}
            reported += 1

            address = self.formatAddress(prof.get('location'))
            parents = sorted({p.get('parent_name') for p in prof.get('parents') or []
                              if isinstance(p, dict) and p.get('parent_name')})
            record = {
                'source': "USAspending.gov federal award recipient",
                'name': prof.get('name') or rec.get('name'),
                'uei': prof.get('uei') or rec.get('uei'),
                'duns': prof.get('duns') or rec.get('duns'),
                'recipient_level': {'P': "parent", 'C': "child", 'R': "recipient"}.get(rec.get('recipient_level')),
                'alternate_names': prof.get('alternate_names') or None,
                'parent': prof.get('parent_name'),
                'parent_uei': prof.get('parent_uei'),
                'parents': parents or None,
                'business_types': prof.get('business_types') or None,
                'address': address,
                'total_award_amount': prof.get('total_transaction_amount', rec.get('amount')),
                'total_transactions': prof.get('total_transactions'),
                'total_loan_face_value': prof.get('total_face_value_loan_amount') or None,
                'url': f"https://www.usaspending.gov/recipient/{rid}/latest",
            }
            self.notifyListeners(SpiderFootEvent(
                "RAW_RIR_DATA", json.dumps({k: v for k, v in record.items() if v not in (None, [], "")},
                                           ensure_ascii=False, default=str), self.__name__, event))

            if address and f"addr:{address.lower()}" not in self.results:
                self.results[f"addr:{address.lower()}"] = True
                self.notifyListeners(SpiderFootEvent("PHYSICAL_ADDRESS", address, self.__name__, event))

            for parent in parents:
                if SpiderFootHelpers.normalizeCompanyName(parent) == wanted:
                    continue
                if f"parent:{parent.lower()}" in self.results:
                    continue
                self.results[f"parent:{parent.lower()}"] = True
                self.notifyListeners(SpiderFootEvent("AFFILIATE_COMPANY_NAME", parent, self.__name__, event))

# End of sfp_usaspending class
