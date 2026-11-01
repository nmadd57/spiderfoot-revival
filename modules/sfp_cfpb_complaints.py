# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_cfpb_complaints
# Purpose:      Summarise consumer complaints filed against a business with the
#               Consumer Financial Protection Bureau.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin

API = "https://www.consumerfinance.gov/data-research/consumer-complaints/search/api/v1/"


def _buckets(aggs: dict, name: str, top: int = 5) -> list:
    """Top buckets of a CFPB aggregation, e.g. [("Mortgage", 49913), ...]."""
    agg = (aggs or {}).get(name) or {}
    inner = agg.get(name) or agg
    return [(b.get('key'), b.get('doc_count')) for b in (inner.get('buckets') or [])[:top] if b.get('key')]


class sfp_cfpb_complaints(SpiderFootPlugin):

    meta = {
        'name': "CFPB Consumer Complaints",
        'summary': "Summarise consumer complaints filed against a financial company with the Consumer "
                   "Financial Protection Bureau: totals, top products and issues, company responses.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.consumerfinance.gov/data-research/consumer-complaints/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': ["https://cfpb.github.io/api/ccdb/api.html"],
            'favIcon': "https://www.consumerfinance.gov/static/img/favicon.ico",
            'description': "The CFPB's Consumer Complaint Database holds complaints about financial products "
                           "and services (banks, lenders, credit bureaus, debt collectors, money transfer and "
                           "crypto firms) that were sent to the company for a response. Narratives are "
                           "anonymised; this module only reports aggregate counts.",
        }
    }

    opts = {
        'recent': 5,
    }

    optdescs = {
        'recent': "Number of most recent complaints (product, issue, date, response) to list.",
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
        return ["RAW_RIR_DATA"]

    def query(self, params: dict):
        res = self.sf.fetchUrl(API + "?" + urllib.parse.urlencode(params),
                               timeout=max(30, int(self.opts.get('_fetchtimeout') or 0)),
                               headers={'Accept': "application/json"}, useragent=self.opts['_useragent'])
        if str(res.get('code')) != "200" or not res.get('content'):
            self.debug(f"CFPB returned HTTP {res.get('code')}")
            return None
        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error parsing CFPB JSON: {e}")
            return None

    def companies(self, name: str) -> list:
        """Company names, as the CFPB records them, that a phrase search turns up."""
        data = self.query({'search_term': f'"{name}"', 'field': "company", 'size': 0})
        return _buckets((data or {}).get('aggregations'), "company", top=25)

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
        for company, _count in self.companies(core):
            if SpiderFootHelpers.normalizeCompanyName(company) != wanted or self.checkForStop():
                continue
            if f"company:{company}" in self.results:
                continue
            self.results[f"company:{company}"] = True

            data = self.query({'company': company, 'size': max(0, int(self.opts.get('recent') or 0)),
                               'sort': "created_date_desc"})
            if not data:
                continue
            total = ((data.get('hits') or {}).get('total') or {})
            total = total.get('value') if isinstance(total, dict) else total
            aggs = data.get('aggregations') or {}
            timely = dict(_buckets(aggs, "timely"))
            recent = []
            for hit in (data.get('hits') or {}).get('hits') or []:
                src = hit.get('_source') or {}
                recent.append({
                    'date': str(src.get('date_received') or '')[:10],
                    'product': src.get('product'),
                    'issue': src.get('issue'),
                    'state': src.get('state'),
                    'response': src.get('company_response'),
                    'url': f"https://www.consumerfinance.gov/data-research/consumer-complaints/search/detail/"
                           f"{src.get('complaint_id')}" if src.get('complaint_id') else None,
                })
            record = {
                'source': "CFPB Consumer Complaint Database",
                'company': company,
                'total_complaints': total,
                'top_products': _buckets(aggs, "product"),
                'top_issues': _buckets(aggs, "issue"),
                'company_responses': _buckets(aggs, "company_response"),
                'timely_response_rate': (round(100.0 * timely.get("Yes", 0) / sum(timely.values()), 1)
                                         if timely else None),
                'top_states': _buckets(aggs, "state"),
                'recent': recent,
                'url': "https://www.consumerfinance.gov/data-research/consumer-complaints/search/?"
                       + urllib.parse.urlencode({'company': company}),
            }
            self.notifyListeners(SpiderFootEvent(
                "RAW_RIR_DATA", json.dumps({k: v for k, v in record.items() if v not in (None, [])},
                                           ensure_ascii=False), self.__name__, event))

# End of sfp_cfpb_complaints class
