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

        shopguard.py status     worker reachability and last collection, as JSON
        shopguard.py collect    send the worker the new domains resolved by Unbound (cron)
        shopguard.py verdicts <min_score> <offset> <limit> [search]
                                one page of verdicts, highest score first, as JSON

    Only domain names are ever sent to the worker, never client addresses.

    Source of the domains: the query database of Reporting -> Unbound DNS
    (/var/unbound/data/unbound.duckdb, kept 7 days by OPNsense). It exists when Unbound
    statistics are enabled; no query log is needed. Only the `domain` column is read.
"""

import fcntl
import ipaddress
import json
import os
import re
import sys
import syslog
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

CONFIG = os.environ.get('SHOPGUARD_CONFIG', '/conf/config.xml')
STATE_DIR = os.environ.get('SHOPGUARD_STATE', '/var/db/shopguard')
UNBOUND_DB = '/var/unbound/data/unbound.duckdb'
# created by OPNsense when Unbound statistics are enabled; the logger only runs then
UNBOUND_STATS = '/var/unbound/data/stats'
SITE_PYTHON = '/usr/local/opnsense/site-python'
TIMEOUT = 10
# most domains the worker accepts in one request
BATCH = 5000
# names remembered as sent; past that, the oldest are forgotten (and may be sent again)
SENT_MAX = 100000
# send a name again after this long: the worker evicts domains it has not seen for long
RESEND_AFTER = 30 * 86400
# re-read this much before the last query time already processed (same-second queries)
OVERLAP = 60
# suffixes of names that are not public websites
LOCAL_SUFFIXES = ('.arpa', '.local', '.lan', '.home', '.internal', '.localdomain', '.intranet', '.corp')
LABEL = re.compile(r'^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$')
# search in the verdict list: part of a domain name
SEARCH = re.compile(r'^[a-z0-9_.-]{0,253}$')
MAX_PAGE = 1000


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


def local_domain(path=CONFIG):
    """Domain of the router (System -> Settings -> General): names under it are LAN hosts."""
    try:
        return (ET.parse(path).getroot().findtext('./system/domain') or '').strip().lower().strip('.')
    except (OSError, ET.ParseError):
        return ''


def public_name(name, local=''):
    """`name` normalized if it can be a public website, else None."""
    name = name.strip().lower().rstrip('.')
    if not name or len(name) > 253 or '.' not in name:
        return None
    if name.endswith(LOCAL_SUFFIXES):
        return None
    if local and (name == local or name.endswith('.' + local)):
        return None
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        pass
    if not all(LABEL.match(label) for label in name.split('.')):
        return None
    return name


def unbound_names(since):
    """Names Unbound resolved since `since`, and the newest query time seen.

    Read-only, through the lock OPNsense uses between its logger and readers. Kept:
    queries passed (action 0, not blocked by a blocklist) with an answer (rcode 0
    NOERROR), not answered from local-data (source 2: host overrides of the LAN).
    """
    if not os.path.exists(UNBOUND_STATS) or not os.path.exists(UNBOUND_DB):
        raise LookupError('Unbound statistics are disabled: enable them in Reporting -> Unbound DNS, '
                          'Settings tab. ShopGuard reads the domains from there.')
    if SITE_PYTHON not in sys.path:
        sys.path.append(SITE_PYTHON)
    from duckdb_helper import DbConnection
    with DbConnection(UNBOUND_DB, read_only=True) as db:
        if db is None or db.connection is None or not db.table_exists('query'):
            return set(), since
        rows = db.connection.execute(
            'SELECT domain, max(time) FROM query '
            'WHERE time >= ? AND action = 0 AND rcode = 0 AND source <> 2 GROUP BY domain',
            [since],
        ).fetchall()
    newest = max((int(t) for _, t in rows if t is not None), default=since)
    return {d for d, _ in rows if d}, newest


def load_json(path, default):
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, type(default)) else default
    except (OSError, ValueError):
        return default


def save_json(path, data):
    """Atomic write: a crash leaves the old file or the new one, never half of one."""
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, separators=(',', ':'))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


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


def verdicts(cfg, min_score=0, offset=0, limit=50, search=''):
    """One page of verdicts: {'status', 'total', 'rows'}.

    Workers before 0.3 return every verdict without X-Total-Count: the page is cut here.
    """
    if not cfg['worker_url']:
        return {'status': 'error', 'message': 'No worker URL configured.', 'total': 0, 'rows': []}
    min_score = max(0, min(100, int(min_score)))
    offset = max(0, int(offset))
    limit = max(1, min(MAX_PAGE, int(limit)))
    search = search.strip().lower()
    if not SEARCH.match(search):
        return {'status': 'error', 'message': 'Search for part of a domain name.', 'total': 0, 'rows': []}
    query = urllib.parse.urlencode({'min_score': min_score, 'q': search, 'offset': offset, 'limit': limit})
    req = urllib.request.Request(cfg['worker_url'] + '/v1/verdicts?' + query)
    req.add_header('Authorization', 'Bearer ' + cfg['token'])
    req.add_header('Accept', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            rows = json.load(resp)
            total = resp.headers.get('X-Total-Count')
    except urllib.error.HTTPError as e:
        message = 'The worker refused the token.' if e.code == 401 else 'Worker error: HTTP %d.' % e.code
        return {'status': 'error', 'message': message, 'total': 0, 'rows': []}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {'status': 'error', 'message': 'Worker unreachable: %s' % getattr(e, 'reason', e),
                'total': 0, 'rows': []}
    if not isinstance(rows, list):
        return {'status': 'error', 'message': 'Unexpected answer from the worker.', 'total': 0, 'rows': []}
    if total is None:
        # older worker: no paging, no search
        rows = [r for r in rows if search in str(r.get('domain', '')) and int(r.get('score', 0)) >= min_score]
        total = len(rows)
        rows = rows[offset:offset + limit]
    keep = ('domain', 'score', 'checked_at', 'signals')
    return {'status': 'ok', 'total': int(total), 'rows': [{k: r.get(k) for k in keep} for r in rows]}


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


def collect(cfg, source=unbound_names, state_dir=STATE_DIR, local='', now=None):
    """Sends the worker the names resolved since the last run that it was not sent yet."""
    now = int(now if now is not None else time.time())
    if not cfg['enabled']:
        return {'status': 'disabled'}
    if not cfg['worker_url'] or not cfg['token']:
        return {'status': 'error', 'message': 'Set the worker URL and token first.'}
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    lock = open(os.path.join(state_dir, 'collect.lock'), 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.close()
        return {'status': 'busy'}
    try:
        return _collect(cfg, source, state_dir, local, now)
    finally:
        lock.close()


def _collect(cfg, source, state_dir, local, now):
    state_path = os.path.join(state_dir, 'state.json')
    sent_path = os.path.join(state_dir, 'sent.json')
    state = load_json(state_path, {})
    sent = load_json(sent_path, {})
    since = int(state.get('since', 0))

    def finish(result):
        state['last'] = dict(result, time=now)
        save_json(state_path, state)
        if result['status'] != 'ok':
            syslog.syslog(syslog.LOG_ERR, 'shopguard collect: %s' % result['message'])
        return result

    try:
        names, newest = source(max(0, since - OVERLAP))
    except LookupError as e:
        return finish({'status': 'error', 'message': str(e)})
    except Exception as e:  # duckdb errors have no common base we can import here
        return finish({'status': 'error', 'message': 'Cannot read the Unbound database: %s' % e})

    sent = {n: t for n, t in sent.items() if isinstance(t, int) and now - t < RESEND_AFTER}
    new = sorted({p for p in (public_name(n, local) for n in names) if p and p not in sent})
    queued = ignored = 0
    complete = True
    for i in range(0, len(new), BATCH):
        batch = new[i:i + BATCH]
        try:
            r = call(cfg, '/v1/domains', {'domains': batch})
        except urllib.error.HTTPError as e:
            complete = False
            error = 'The worker refused the token.' if e.code == 401 else 'Worker error: HTTP %d.' % e.code
            break
        except (urllib.error.URLError, OSError, ValueError) as e:
            complete = False
            error = 'Worker unreachable: %s' % getattr(e, 'reason', e)
            break
        queued += int(r.get('queued', 0))
        ignored += int(r.get('ignored', 0))
        if int(r.get('deferred', 0)) > 0:
            # the answer only gives counts: the whole batch goes again next time (the worker
            # ignores the names it already has), and the newer batches with it
            complete = False
            error = None
            break
        for n in batch:
            sent[n] = now

    if len(sent) > SENT_MAX:
        sent = dict(sorted(sent.items(), key=lambda kv: kv[1])[-SENT_MAX:])
    save_json(sent_path, sent)
    if complete:
        state['since'] = max(since, int(newest))
    result = {'status': 'ok', 'read': len(names), 'new': len(new), 'queued': queued,
              'ignored': ignored, 'complete': complete}
    if not complete and error:
        result = {'status': 'error', 'message': error, 'new': len(new), 'queued': queued}
    return finish(result)


def last_collect(state_dir=STATE_DIR):
    return load_json(os.path.join(state_dir, 'state.json'), {}).get('last')


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ''
    if cmd not in ('status', 'collect', 'verdicts'):
        print('usage: shopguard.py status|collect|verdicts', file=sys.stderr)
        return 2
    try:
        cfg = settings()
    except (OSError, ET.ParseError) as e:
        print(json.dumps({'status': 'error', 'message': 'Cannot read the configuration: %s' % e}))
        return 1
    if cmd == 'verdicts':
        try:
            nums = [int(a) for a in argv[2:5]]
        except ValueError:
            nums = []
        if len(nums) != 3:
            print(json.dumps({'status': 'error', 'message': 'usage: verdicts <min_score> <offset> <limit> [search]',
                              'total': 0, 'rows': []}))
            return 2
        out = verdicts(cfg, *nums, search=argv[5] if len(argv) > 5 else '')
        print(json.dumps(out))
        return 0 if out['status'] == 'ok' else 1
    if cmd == 'status':
        out = status(cfg)
        out['collect'] = last_collect()
        print(json.dumps(out))
        return 0
    out = collect(cfg, local=local_domain())
    print(json.dumps(out))
    return 0 if out['status'] in ('ok', 'disabled', 'busy') else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
