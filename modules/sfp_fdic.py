# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_fdic
# Purpose:      Look up FDIC-insured banks and savings institutions by name
#               using the FDIC BankFind Suite API.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin

FIELDS = ("NAME,CERT,ACTIVE,ADDRESS,CITY,STALP,ZIP,WEBADDR,ESTYMD,ENDEFYMD,INSDATE,ASSET,DEP,OFFICES,"
          "REGAGNT,CHARTER_CLASS,FED_RSSD,NAMEHCR,RSSDHCR,CHANGEC1,REPDTE")

# Bank legal forms that normalizeCompanyName() doesn't know about
_BANK_TAIL_RX = re.compile(r"\s+(?:NATIONAL ASSOCIATION|N A|NA|FSB|SSB)$")


def _bank_name(name: str) -> str:
    return _BANK_TAIL_RX.sub("", SpiderFootHelpers.normalizeCompanyName(name)).strip()


class sfp_fdic(SpiderFootPlugin):

    meta = {
        'name': "FDIC BankFind",
        'summary': "Look up FDIC-insured banks by name: FDIC certificate, status, regulator, holding company, "
                   "headquarters, website, assets, deposits and branch count.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://banks.data.fdic.gov/bankfind-suite/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': ["https://banks.data.fdic.gov/docs/", "https://api.fdic.gov/banks/docs/"],
            'favIcon': "https://www.fdic.gov/themes/custom/fdic/favicon.ico",
            'description': "The FDIC's BankFind Suite lists every FDIC-insured institution, current and "
                           "historical, with its certificate number, primary regulator, holding company, "
                           "headquarters, website, financials and branch offices.",
        }
    }

    opts = {
        'inactive': True,
    }

    optdescs = {
        'inactive': "Also report closed, merged or acquired institutions.",
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
        return ["RAW_RIR_DATA", "PHYSICAL_ADDRESS", "AFFILIATE_COMPANY_NAME", "AFFILIATE_INTERNET_NAME"]

    def search(self, name: str) -> list:
        params = {'search': f'NAME:"{name}"', 'fields': FIELDS, 'limit': 25, 'sort_by': "ASSET",
                  'sort_order': "DESC"}
        if not self.opts.get('inactive'):
            params['filters'] = "ACTIVE:1"
        res = self.sf.fetchUrl("https://api.fdic.gov/banks/institutions?" + urllib.parse.urlencode(params),
                               timeout=max(30, int(self.opts.get('_fetchtimeout') or 0)),
                               headers={'Accept': "application/json"}, useragent=self.opts['_useragent'])
        if str(res.get('code')) != "200" or not res.get('content'):
            self.debug(f"FDIC returned HTTP {res.get('code')}")
            return []
        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error parsing FDIC JSON: {e}")
            return []
        return [d.get('data') for d in data.get('data') or [] if isinstance(d, dict) and d.get('data')]

    def handleEvent(self, event):
        eventData = event.data

        if self.errorState:
            return
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return
        self.results[eventData] = True

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        wanted = _bank_name(eventData)
        if not wanted or f"core:{wanted}" in self.results:
            return
        self.results[f"core:{wanted}"] = True

        for bank in self.search(" ".join(re.findall(r"[^\W_]+", wanted))):
            if _bank_name(bank.get('NAME')) != wanted:
                continue
            cert = bank.get('CERT')
            if f"cert:{cert}" in self.results:
                continue
            self.results[f"cert:{cert}"] = True

            address = ", ".join(str(p).strip() for p in [
                bank.get('ADDRESS'), bank.get('CITY'),
                " ".join(str(x) for x in [bank.get('STALP'), bank.get('ZIP')] if x)] if p)
            record = {
                'source': "FDIC BankFind",
                'name': bank.get('NAME'),
                'fdic_cert': cert,
                'active': bool(bank.get('ACTIVE')),
                'established': bank.get('ESTYMD'),
                'insured_since': bank.get('INSDATE'),
                'closed_or_merged': bank.get('ENDEFYMD') if not bank.get('ACTIVE') else None,
                'regulator': bank.get('REGAGNT'),
                'charter_class': bank.get('CHARTER_CLASS'),
                'holding_company': bank.get('NAMEHCR') or None,
                'fed_rssd': bank.get('FED_RSSD'),
                'total_assets_thousands': bank.get('ASSET'),
                'total_deposits_thousands': bank.get('DEP'),
                'offices': bank.get('OFFICES'),
                'website': bank.get('WEBADDR') or None,
                'address': address,
                'report_date': bank.get('REPDTE'),
                'url': f"https://banks.data.fdic.gov/bankfind-suite/bankfind/details/{cert}",
            }
            self.notifyListeners(SpiderFootEvent(
                "RAW_RIR_DATA", json.dumps({k: v for k, v in record.items() if v not in (None, "")},
                                           ensure_ascii=False, default=str), self.__name__, event))
            if bank.get('ADDRESS'):
                self.notifyListeners(SpiderFootEvent("PHYSICAL_ADDRESS", address, self.__name__, event))
            holder = bank.get('NAMEHCR')
            if holder and _bank_name(holder) != wanted and f"hc:{holder}" not in self.results:
                self.results[f"hc:{holder}"] = True
                self.notifyListeners(SpiderFootEvent("AFFILIATE_COMPANY_NAME", holder, self.__name__, event))
            site = str(bank.get('WEBADDR') or '').strip()
            host = urllib.parse.urlparse(site if "://" in site else f"http://{site}").hostname if site else None
            if bank.get('ACTIVE') and host and self.sf.validHost(host, self.opts.get('_internettlds')):
                self.notifyListeners(SpiderFootEvent("AFFILIATE_INTERNET_NAME", host.lower(), self.__name__, event))

# End of sfp_fdic class
