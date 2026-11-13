#!/usr/local/bin/python3

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

    ShopGuard backend, called by configd (actions_shopguard.conf).

        shopguard.py status     worker reachability, as JSON

    Only domain names are ever sent to the worker, never client addresses.
"""

import json
import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

CONFIG = os.environ.get('SHOPGUARD_CONFIG', '/conf/config.xml')
TIMEOUT = 10


def settings(path=CONFIG):
    """ShopGuard settings from the OPNsense configuration."""
    root = ET.parse(path).getroot()
    node = root.find('./OPNsense/shopguard/general')
    get = (lambda k, d='': (node.findtext(k) or d).strip()) if node is not None else (lambda k, d='': d)
    return {
        'enabled': get('enabled', '0') == '1',
        'worker_url': get('worker_url').rstrip('/'),
        'token': get('token'),
        'mode': get('mode', 'observe'),
        'threshold': int(get('threshold', '70') or 70),
    }


def call(cfg, path, payload=None):
    """JSON request to the worker API."""
    req = urllib.request.Request(cfg['worker_url'] + path, method='POST' if payload is not None else 'GET')
    req.add_header('Authorization', 'Bearer ' + cfg['token'])
    req.add_header('Accept', 'application/json')
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        req.add_header('Content-Type', 'application/json')
    with urllib.request.urlopen(req, data=data, timeout=TIMEOUT) as resp:
        return json.load(resp)


def status(cfg):
    if not cfg['worker_url']:
        return {'status': 'error', 'message': 'No worker URL configured.'}
    try:
        s = call(cfg, '/v1/status')
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {'status': 'error', 'message': 'The worker refused the token.'}
        return {'status': 'error', 'message': 'Worker error: HTTP %d.' % e.code}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {'status': 'error', 'message': 'Worker unreachable: %s' % getattr(e, 'reason', e)}
    return {'status': 'ok', 'version': s.get('version', '?'), 'pending': s.get('pending', 0)}


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ''
    if cmd == 'status':
        try:
            cfg = settings()
        except (OSError, ET.ParseError) as e:
            print(json.dumps({'status': 'error', 'message': 'Cannot read the configuration: %s' % e}))
            return 1
        print(json.dumps(status(cfg)))
        return 0
    print('usage: shopguard.py status', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
