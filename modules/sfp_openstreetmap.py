# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_openstreetmap
# Purpose:      SpiderFoot plug-in to geocode addresses and reverse-geocode
#               coordinates with OpenStreetMap's Nominatim. A free, key-less
#               replacement for the Google Maps geocoding module.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-27
# Copyright:   (c) bcoles 2018
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re
import threading
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

# Nominatim's usage policy allows at most one request per second per client, across
# every thread of this process.
_throttle = threading.Lock()
_last_call = [0.0]


def _wait(delay: float) -> None:
    with _throttle:
        gap = delay - (time.time() - _last_call[0])
        if gap > 0:
            time.sleep(gap)
        _last_call[0] = time.time()


class sfp_openstreetmap(SpiderFootPlugin):

    meta = {
        'name': "OpenStreetMap",
        'summary': "Geocodes physical addresses to coordinates, and reverse-geocodes coordinates to an address, "
                   "with OpenStreetMap's Nominatim. Free, no key; a replacement for the Google Maps module.",
        'flags': [],
        'pricing': 'free',
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://nominatim.org/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://nominatim.org/release-docs/latest/api/Search/",
                "https://nominatim.org/release-docs/latest/api/Reverse/",
                "https://operations.osmfoundation.org/policies/nominatim/"
            ],
            'favIcon': "https://www.openstreetmap.org/assets/osm_logo-b7061f13a03615f787a7e0e56a0db5252eb2a217ab063183e78526a8cc10989b.svg",
            'logo': "https://www.openstreetmap.org/assets/osm_logo-b7061f13a03615f787a7e0e56a0db5252eb2a217ab063183e78526a8cc10989b.svg",
            'description': "OpenStreetMap powers map data on thousands of web sites, mobile apps, and hardware devices. "
                           "Nominatim is its geocoder; the public server allows one request per second, or point this "
                           "module at your own Nominatim instance.",
        }
    }

    opts = {
        'nominatim_url': "https://nominatim.openstreetmap.org",
        'reverse': True,
        'delay': 1.0,
    }

    optdescs = {
        'nominatim_url': "Nominatim server to use. The public server is rate limited to one request per second; "
                         "set your own instance here for heavy use.",
        'reverse': "Also turn coordinates found by other modules into a street address?",
        'delay': "Seconds to wait between requests (1 or more for the public server; 0 is fine for your own).",
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.opts = dict(self.opts)  # per-instance copy; don't mutate the class defaults
        self._mergeOpts(userOpts)

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['PHYSICAL_ADDRESS', 'PHYSICAL_COORDINATES']

    # What events this module produces
    def producedEvents(self):
        return ['PHYSICAL_COORDINATES', 'PHYSICAL_ADDRESS']

    def baseUrl(self) -> str:
        url = str(self.opts.get('nominatim_url') or '').strip().rstrip('/')
        if url and '://' not in url:
            url = 'https://' + url
        return url or "https://nominatim.openstreetmap.org"

    def _get(self, path: str, params: dict):
        _wait(float(self.opts.get('delay') or 0))
        res = self.sf.fetchUrl(f"{self.baseUrl()}/{path}?" + urllib.parse.urlencode(params),
                               timeout=self.opts['_fetchtimeout'],
                               # the usage policy asks for an identifying User-Agent, not a browser one
                               useragent='SpiderFoot-Revival (+https://github.com/boredchilada/spiderfoot-revival)')
        if str(res.get('code')) in ('403', '429'):
            self.error(f"Nominatim refused the request (HTTP {res['code']}). The public server allows one request per "
                       "second and blocks heavy use; wait, raise the delay, or set your own Nominatim URL.")
            return None
        if res.get('content') is None:
            return None
        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
        return None

    # Search for address
    # https://operations.osmfoundation.org/policies/nominatim/
    def query(self, qry):
        data = self._get('search', {
            'q': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'format': 'json',
            'polygon': '0',
            'addressdetails': '0',
        })
        return data if isinstance(data, list) else None

    def reverse(self, lat, lon):
        data = self._get('reverse', {'lat': lat, 'lon': lon, 'format': 'jsonv2', 'zoom': 18, 'addressdetails': '0'})
        return data if isinstance(data, dict) and data.get('display_name') else None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # never feed our own output back in
        if srcModuleName == self.__name__:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'PHYSICAL_COORDINATES':
            self.handleCoordinates(event)
            return

        address = eventData

        # Skip post office boxes
        if address.lower().startswith('po box'):
            self.debug("Skipping PO BOX address")
            return

        rx1 = re.compile(r'^(c/o|care of|attn:|attention:)\s+[0-9a-z\s\.]', flags=re.IGNORECASE)
        # Remove address prefixes for delivery instructions
        address = re.sub(rx1, r'', address)

        rx2 = re.compile(r'^(Level|Floor|Suite|Room)\s+[0-9a-z]+,', flags=re.IGNORECASE)
        # Remove address prefixes known to return no results (floor, level, suite, etc).
        address = re.sub(rx2, r'', address)

        # Search for address
        data = self.query(address)

        if not data:
            self.debug("Found no results for " + eventData)
            return

        self.info("Found " + str(len(data)) + " matches for " + eventData)

        for location in data:
            try:
                lat = location.get('lat')
                lon = location.get('lon')
            except Exception as e:
                self.debug("Failed to get lat/lon: " + str(e))
                continue

            if not lat or not lon:
                continue

            coords = str(lat) + "," + str(lon)
            self.debug("Found coordinates: " + coords)

            evt = SpiderFootEvent("PHYSICAL_COORDINATES", coords, self.__name__, event)
            self.notifyListeners(evt)

    def handleCoordinates(self, event):
        if not self.opts.get('reverse'):
            return
        m = re.match(r'^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$', event.data)
        if not m:
            self.debug(f"Not a lat,lon pair: {event.data}")
            return
        lat, lon = float(m.group(1)), float(m.group(2))
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return

        place = self.reverse(m.group(1), m.group(2))
        if not place:
            self.debug(f"No address found for {event.data}")
            return

        self.notifyListeners(SpiderFootEvent("PHYSICAL_ADDRESS", place['display_name'], self.__name__, event))

# End of sfp_openstreetmap class
