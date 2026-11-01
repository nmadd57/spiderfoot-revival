# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_zoomeye
# Purpose:      Query ZoomEye for internet-connected device and web application data.
#
# Author:       SpiderFoot Revival Project
#
# Created:      2026-04-08
# Copyright:    (c) SpiderFoot Revival Project
# Licence:      MIT
# -------------------------------------------------------------------------------

import base64
import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_zoomeye(SpiderFootPlugin):

    meta = {
        "name": "ZoomEye",
        "summary": "Query ZoomEye for internet-connected devices, open ports, services, and web applications associated with the target.",
        "flags": ["apikey"],
        "pricing": "paid",
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Search Engines"],
        "dataSource": {
            "website": "https://www.zoomeye.ai/",
            "model": "COMMERCIAL_ONLY",
            "references": [
                "https://www.zoomeye.ai/doc",
                "https://api.zoomeye.ai/v2/search",
            ],
            "apiKeyInstructions": [
                "Visit https://www.zoomeye.ai/ and sign up",
                "Search needs a plan with search credits: the Free plan returns HTTP 402 credits_insufficient",
                "The API key is in your account profile",
            ],
            "favIcon": "https://www.zoomeye.ai/favicon.ico",
            "logo": "https://www.zoomeye.ai/logo.png",
            "description": "ZoomEye is a cyberspace search engine by Knownsec that indexes "
            "internet-connected devices and web applications. It provides host, port, service, "
            "banner, and SSL certificate data. API access requires a paid plan.",
        },
    }

    opts = {
        "api_key": "",
        "max_pages": 3,
        "pagesize": 20,
        "request_delay": 1.0,
    }

    optdescs = {
        "api_key": "ZoomEye API key.",
        "max_pages": "Maximum number of search result pages to retrieve.",
        "pagesize": "Results per page (the plan's credits are charged per result).",
        "request_delay": "Delay between API requests in seconds.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME", "IP_ADDRESS"]

    def producedEvents(self):
        return [
            "TCP_PORT_OPEN",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "OPERATING_SYSTEM",
            "WEBSERVER_BANNER",
            "RAW_RIR_DATA",
        ]

    API = "https://api.zoomeye.ai/v2/search"

    @staticmethod
    def buildQuery(eventName, eventData):
        """ZoomEye v2 query for an event: ip="x", domain="x" or hostname="x"."""
        if eventName == "IP_ADDRESS":
            return f'ip="{eventData}"'
        if eventName == "DOMAIN_NAME":
            return f'domain="{eventData}"'
        return f'hostname="{eventData}"'

    def queryHost(self, query, page=1):
        """Query the ZoomEye v2 search API (POST, JSON body, base64 query)."""
        body = json.dumps({
            "qbase64": base64.b64encode(query.encode()).decode(),
            "page": page,
            "pagesize": self.opts["pagesize"],
        })
        headers = {"API-KEY": self.opts["api_key"], "Content-Type": "application/json"}

        res = self.sf.fetchUrl(
            self.API,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
            headers=headers,
            postData=body,
        )

        time.sleep(self.opts["request_delay"])

        if not res or not res.get("code"):
            return None

        if res["code"] == "402":
            self.error("ZoomEye: this plan has no search credits left (HTTP 402 credits_insufficient).")
            self.errorState = True
            return None

        if res["code"] in ["401", "403"]:
            self.error("ZoomEye API key is invalid, or the request was blocked.")
            self.errorState = True
            return None

        if res["code"] == "429":
            self.error("ZoomEye rate limit hit.")
            self.errorState = True
            return None

        if res["code"] != "200" or not res.get("content"):
            self.debug(f"Unexpected response code {res['code']} from ZoomEye")
            return None

        try:
            data = json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing ZoomEye response: {e}")
            return None

        # v2 reports failures in the body: {"code": 50000, "error": "...", "message": "..."}
        if data.get("code") not in (None, 60000) and not data.get("data"):
            self.debug(f"ZoomEye returned code {data.get('code')}: {data.get('message')}")
            return None

        return data

    @staticmethod
    def _text(value):
        """Flatten a v2 field that may be a string, list or {'name': ...} object."""
        if isinstance(value, dict):
            value = value.get("name") or value.get("value")
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value if v)
        return str(value).strip() if value else ""

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if not self.opts["api_key"]:
            self.error("You enabled sfp_zoomeye but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        query = self.buildQuery(eventName, eventData)

        for page in range(1, self.opts["max_pages"] + 1):
            if self.checkForStop() or self.errorState:
                return

            data = self.queryHost(query, page)
            if not data:
                break

            matches = data.get("data") or []
            if not matches:
                break

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
            self.notifyListeners(e)

            for match in matches:
                ip = self._text(match.get("ip"))
                port = self._text(match.get("port"))

                if ip and port:
                    port_str = f"{ip}:{port}"
                    if port_str not in self.results:
                        self.results[port_str] = True
                        e = SpiderFootEvent("TCP_PORT_OPEN", port_str, self.__name__, event)
                        self.notifyListeners(e)

                for hostname in {self._text(match.get("hostname")), self._text(match.get("domain"))}:
                    if not hostname or hostname in self.results:
                        continue
                    self.results[hostname] = True
                    if self.getTarget().matches(hostname):
                        e = SpiderFootEvent("INTERNET_NAME", hostname, self.__name__, event)
                    else:
                        e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", hostname, self.__name__, event)
                    self.notifyListeners(e)

                os_name = self._text(match.get("os"))
                if os_name:
                    e = SpiderFootEvent("OPERATING_SYSTEM", os_name, self.__name__, event)
                    self.notifyListeners(e)

                banner = self._text(match.get("banner"))
                if banner and len(banner) < 500:
                    e = SpiderFootEvent("WEBSERVER_BANNER", banner, self.__name__, event)
                    self.notifyListeners(e)

            if len(matches) < int(self.opts["pagesize"]):
                break


# End of sfp_zoomeye class
