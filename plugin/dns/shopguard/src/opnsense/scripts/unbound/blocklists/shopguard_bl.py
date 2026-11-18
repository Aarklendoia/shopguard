"""
    Copyright (C) 2026 Édouard Biton
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

    ShopGuard domains for Unbound's blocklist (Services -> Unbound DNS -> Blocklist).

    Loaded by OPNsense's blocklist script (scripts/unbound/blocklists.py, "configctl
    unbound dnsbl") with the other sources. The domains come from
    /var/db/shopguard/blocklist.json, written by shopguard.py in Block mode; it is empty
    in Observe mode. Each domain is blocked with its subdomains (www.), answering
    NXDOMAIN, for every client.
"""

import os
import syslog

import ujson

from . import BaseBlocklistHandler

BLOCKLIST = os.environ.get('SHOPGUARD_BLOCKLIST', '/var/db/shopguard/blocklist.json')
POLICY_ID = 'shopguard'
BLOCK_MAX = 100000


class ShopGuardBlocklistHandler(BaseBlocklistHandler):
    def __init__(self):
        super().__init__('/dev/null')
        # after the core lists: on a domain in both, the core policy answers
        self.priority = 60

    def _domains(self):
        try:
            with open(BLOCKLIST) as f:
                data = ujson.load(f)
        except (OSError, ValueError):
            return []
        domains = data.get('domains') if isinstance(data, dict) else None
        if not isinstance(domains, list):
            return []
        return [d for d in domains[:BLOCK_MAX] if isinstance(d, str) and self.domain_pattern.match(d)]

    def get_policies(self):
        if not self._domains():
            return []
        return [{
            'source_nets': [],
            'address': '0.0.0.0',
            'rcode': 'NXDOMAIN',
            'description': 'ShopGuard',
            'id': POLICY_ID,
            'passlist': '',
        }]

    def blocklists_iter(self):
        domains = self._domains()
        for domain in domains:
            yield domain.lower(), POLICY_ID, {'bl': 'ShopGuard', 'wildcard': True}
        if domains:
            syslog.syslog(syslog.LOG_NOTICE, 'blocklist: ShopGuard (block: %d wildcard: %d)' % (
                len(domains), len(domains)))
