# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_censys
# Purpose:     Query the Censys Platform API (v3). The legacy Search v2 API was
#              decommissioned on 2026-09-30.
#
# Author:      Steve Micallef
#
# Created:     01/02/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time
import urllib.parse
from datetime import datetime, timezone

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_censys(SpiderFootPlugin):

    meta = {
        'name': "Censys",
        'summary': "Obtain host information from Censys.io.",
        'flags': ["apikey"],
        'pricing': 'free_key',
        'useCases': ["Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://platform.censys.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.censys.com/reference/get-started",
                "https://docs.censys.com/reference/v3-globaldata-asset-host",
                "https://docs.censys.com/docs/platform-api-transition-guide",
            ],
            'apiKeyInstructions': [
                "Visit https://platform.censys.io/ and register a free account",
                "Open Account Management > Personal Access Tokens",
                "Create a token and copy it into the API key field",
                "Optionally set your Organization ID (needed to use an organization's credits instead of the free allowance)"
            ],
            'favIcon': "https://censys.io/assets/favicon.png",
            'logo': "https://censys.io/assets/logo.png",
            'description': "Discover exposures and other common entry points for attackers.\n"
            "Censys scans the entire internet constantly, including obscure ports. "
            "We use a combination of banner grabs and deep protocol handshakes "
            "to provide industry-leading visibility and an accurate depiction of what is live on the internet.",
        }
    }

    opts = {
        "censys_api_key": "",
        "censys_organization_id": "",
        'delay': 3,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
        "age_limit_days": 90,
    }

    optdescs = {
        "censys_api_key": "Censys Platform Personal Access Token.",
        "censys_organization_id": "Optional Censys organization ID (UUID) to bill requests to. Leave empty to use the free allowance.",
        'delay': 'Delay between requests, in seconds.',
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6netblock': "If looking up owned netblocks, the maximum IPv6 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
        ]

    def producedEvents(self):
        return [
            "BGP_AS_MEMBER",
            "UDP_PORT_OPEN",
            "TCP_PORT_OPEN",
            "TCP_PORT_OPEN_BANNER",
            "OPERATING_SYSTEM",
            "SOFTWARE_USED",
            "WEBSERVER_HTTPHEADERS",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "GEOINFO",
            "RAW_RIR_DATA"
        ]

    def queryHosts(self, qry):
        headers = {
            'Authorization': f"Bearer {self.opts['censys_api_key']}",
            'Accept': "application/vnd.censys.api.v3.host.v1+json",
        }
        if self.opts.get('censys_organization_id'):
            headers['X-Organization-ID'] = self.opts['censys_organization_id']

        res = self.sf.fetchUrl(
            f"https://api.platform.censys.io/v3/global/asset/host/{urllib.parse.quote(qry, safe=':')}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
            headers=headers
        )

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    @staticmethod
    def parseTime(value: str) -> int:
        """RFC 3339 timestamp (e.g. 2026-10-01T12:00:00Z) to a unix timestamp."""
        return int(datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc).timestamp())

    @staticmethod
    def flattenHeaders(headers) -> dict:
        """Platform headers are {name: {"headers": [values]}}; return {name: "value"}."""
        out = {}
        for name, val in (headers or {}).items():
            if isinstance(val, dict):
                val = val.get('headers', val.get('value'))
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            if val not in (None, ''):
                out[name] = str(val)
        return out

    def parseApiResponse(self, res: dict):
        if not res:
            self.error("No response from Censys.io.")
            return None

        if res['code'] == "400":
            self.error("Invalid request.")
            return None

        if res['code'] == "404":
            self.info('Censys.io returned no results')
            return None

        if res['code'] in ("401", "403"):
            self.error("Censys rejected the request: invalid Personal Access Token, or no permission/credits for this data.")
            self.errorState = True
            return None

        if res['code'] == "402":
            self.error("Censys: out of credits.")
            self.errorState = True
            return None

        if res['code'] == "429":
            self.error("Request rate limit exceeded.")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error(f"Unexpected HTTP response code {res['code']} from Censys API.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.info('Censys.io returned no results')
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from Censys.io: {e}")
            return None

        if not isinstance(data, dict):
            return None

        return data

    def handleEvent(self, event):
        if self.errorState:
            return

        eventName = event.eventType

        self.debug(f"Received event, {eventName}, from {event.module}")

        if self.opts['censys_api_key'] == "":
            self.error(f"You enabled {self.__class__.__name__} but did not set a Personal Access Token!")
            self.errorState = True
            return

        eventData = event.data

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts['netblocklookup']:
                return

            if eventName == 'NETBLOCKV6_OWNER':
                max_netblock = self.opts['maxv6netblock']
            else:
                max_netblock = self.opts['maxnetblock']

            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

        qrylist = list()
        if eventName.startswith("NETBLOCK"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        for addr in qrylist:
            if self.checkForStop():
                return

            data = self.queryHosts(addr)

            if not data:
                continue

            rec = (data.get("result") or {}).get("resource")

            if not rec:
                self.info(f"Censys.io returned no results for {addr}")
                continue

            self.debug(f"Found results for {addr} in Censys.io")

            # For netblocks, we need to create the associated IP address event first.
            if eventName == 'NETBLOCK_OWNER':
                pevent = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            elif eventName == 'NETBLOCKV6_OWNER':
                pevent = SpiderFootEvent("IPV6_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            else:
                pevent = event

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(rec), self.__name__, pevent)
            self.notifyListeners(e)

            try:
                # Hosts have no single timestamp; use the newest service scan_time (RFC 3339).
                scans = [x.get('scan_time') for x in (rec.get('services') or []) if x.get('scan_time')]
                if scans and self.opts['age_limit_days'] > 0:
                    newest = max(self.parseTime(t) for t in scans)
                    age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                    if newest < age_limit_ts:
                        self.debug(f"Record found but too old ({newest}), skipping.")
                        continue
            except Exception as e:
                self.error(f"Error encountered processing scan_time records for {addr}: {e}")

            try:
                location = rec.get('location')
                if location:
                    geoinfo = ', '.join(
                        [
                            _f for _f in [
                                location.get('city'),
                                location.get('province'),
                                location.get('postal_code'),
                                location.get('country'),
                                location.get('continent'),
                            ] if _f
                        ]
                    )
                    if geoinfo:
                        e = SpiderFootEvent("GEOINFO", geoinfo, self.__name__, pevent)
                        self.notifyListeners(e)
            except Exception as e:
                self.error(f"Error encountered processing location record for {addr}: {e}")

            try:
                services = rec.get('services')
                if services:
                    softwares = list()
                    tcp_banners = list()
                    for service in services:
                        port = service.get('port')

                        if port:
                            transport_protocol = str(service.get('transport_protocol') or '').upper()
                            banner = service.get('banner')

                            if transport_protocol == "UDP":
                                evt = SpiderFootEvent("UDP_PORT_OPEN", f"{addr}:{port}", self.__name__, pevent)
                                self.notifyListeners(evt)
                            elif transport_protocol == "TCP":
                                evt = SpiderFootEvent("TCP_PORT_OPEN", f"{addr}:{port}", self.__name__, pevent)
                                self.notifyListeners(evt)
                                if banner:
                                    tcp_banners.append(banner)

                        software = service.get('software', list())
                        if software:
                            for sw in software:
                                s = ' '.join(
                                    filter(
                                        None,
                                        [
                                            sw.get('vendor'),
                                            sw.get('product'),
                                            sw.get('version')
                                        ]
                                    )
                                )
                                if s:
                                    softwares.append(s)

                        for endpoint in service.get('endpoints') or []:
                            headers = self.flattenHeaders(((endpoint or {}).get('http') or {}).get('headers'))
                            if headers:
                                e = SpiderFootEvent(
                                    "WEBSERVER_HTTPHEADERS",
                                    json.dumps(headers, ensure_ascii=False),
                                    self.__name__,
                                    pevent
                                )
                                e.actualSource = addr
                                self.notifyListeners(e)

                    for software in set(softwares):
                        evt = SpiderFootEvent("SOFTWARE_USED", software, self.__name__, pevent)
                        self.notifyListeners(evt)

                    for banner in set(tcp_banners):
                        evt = SpiderFootEvent("TCP_PORT_OPEN_BANNER", str(banner), self.__name__, pevent)
                        self.notifyListeners(evt)
            except Exception as e:
                self.error(f"Error encountered processing services record for {addr}: {e}")

            try:
                autonomous_system = rec.get('autonomous_system')
                if autonomous_system:
                    asn = autonomous_system.get('asn')
                    if asn:
                        e = SpiderFootEvent("BGP_AS_MEMBER", str(asn), self.__name__, pevent)
                        self.notifyListeners(e)

                    bgp_prefix = autonomous_system.get('bgp_prefix')
                    if bgp_prefix and self.sf.validIpNetwork(bgp_prefix):
                        if ':' in bgp_prefix:
                            e = SpiderFootEvent("NETBLOCKV6_MEMBER", str(bgp_prefix), self.__name__, pevent)
                        else:
                            e = SpiderFootEvent("NETBLOCK_MEMBER", str(bgp_prefix), self.__name__, pevent)
                        self.notifyListeners(e)
            except Exception as e:
                self.error(f"Error encountered processing autonomous_system record for {addr}: {e}")

            try:
                operating_system = rec.get('operating_system')
                if operating_system:
                    os = ' '.join(
                        filter(
                            None,
                            [
                                operating_system.get('vendor'),
                                operating_system.get('product'),
                                operating_system.get('version'),
                                operating_system.get('edition')
                            ]
                        )
                    )

                    if os:
                        e = SpiderFootEvent("OPERATING_SYSTEM", os, self.__name__, pevent)
                        self.notifyListeners(e)
            except Exception as e:
                self.error(f"Error encountered processing operating_system record for {addr}: {e}")

# End of sfp_censys class
