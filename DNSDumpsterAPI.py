#!/usr/bin/env python3
"""
Official DNSDumpster.com API client.
Example curl: 
  curl -H "X-API-Key: your_api_key" \
       "https://api.dnsdumpster.com/domain/example.com?page=2&map=1"
"""

import time
import requests

class DNSDumpsterAPI:
    BASE_URL = 'https://api.dnsdumpster.com'

    def __init__(self, api_key, rate_limit_seconds=2, verbose=False):
        """
        :param api_key: your X-API-Key from dnsdumpster.com
        :param rate_limit_seconds: min delay between calls (API allows 1 req/2s)
        :param verbose: print debug info
        """
        self.api_key = api_key
        self.rate_limit = rate_limit_seconds
        self.verbose = verbose
        self._last_call = 0
        self.session = requests.Session()

    def _throttle(self):
        elapsed = time.time() - self._last_call
        if elapsed < self.rate_limit:
            to_wait = self.rate_limit - elapsed
            if self.verbose:
                print(f"[verbose] Throttling for {to_wait:.2f}s to respect rate limit")
            time.sleep(to_wait)

    def _headers(self):
        return {
            'X-API-Key': self.api_key,
            'Accept':    'application/json'
        }

    def search(self, domain, page=None, include_map=False):
        """
        :param domain: the domain to look up
        :param page:    int page number (>1) if you have Plus membership
        :param include_map: bool, include base64-encoded map image
        :returns: JSON-decoded dict with keys: 'a','cname','mx','ns','txt', etc.
        :raises: RuntimeError on 429 or HTTPError on other bad status
        """
        self._throttle()
        url = f"{self.BASE_URL}/domain/{domain}"
        params = {}
        if page is not None:
            params['page'] = page
        if include_map:
            params['map'] = 1

        if self.verbose:
            print(f"[verbose] GET {url} params={params} headers={self._headers()}")

        resp = self.session.get(url,
                                 headers=self._headers(),
                                 params=params)
        self._last_call = time.time()

        if resp.status_code == 429:
            raise RuntimeError("Rate limit exceeded (1 request per 2 seconds)")
        resp.raise_for_status()

        data = resp.json()
        if 'error' in data:
            # e.g. {"error":"Rate limit exceeded"} or other API errors
            raise RuntimeError("API error: " + data['error'])
        return data
