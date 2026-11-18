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
        shopguard.py collect    send the worker the new domains resolved by Unbound
        shopguard.py blocklist  in Block mode, the domains scoring at least the threshold
                                for Unbound (blocklist.json, read by shopguard_bl.py),
                                given to Unbound in the background
        shopguard.py apply      give Unbound the blocklist when it changed: rebuild its
                                blocklists, flush the changed domains from its cache
        shopguard.py update     collect, then blocklist and apply (cron, every 5 minutes)
        shopguard.py feedback <domain> <fake|legit|none>
                                the user's decision on a domain (worker 0.9+), then
                                the blocklist right away (applied in the background)
        shopguard.py labels     every domain with a decision, as JSON
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
import subprocess
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
# read by the Unbound blocklist handler (scripts/unbound/blocklists/shopguard_bl.py)
BLOCKLIST = 'blocklist.json'
# what Unbound was last given: the difference is applied (and its cache flushed)
APPLIED = 'applied.json'
# most domains blocked: a broken or hostile worker cannot inflate Unbound's memory
BLOCK_MAX = 100000
DNSBL_RELOAD = ['/usr/local/sbin/configctl', 'unbound', 'dnsbl']
# Unbound answers from its cache without asking the blocklist module: the cached answers of
# a domain newly blocked (or unblocked) are flushed, with its subdomains
UNBOUND_FLUSH = ['/usr/local/sbin/unbound-control', '-c', '/var/unbound/unbound.conf', 'flush_zone']
# most domains flushed in one run (one unbound-control call each)
FLUSH_MAX = 500
# Unbound's blocklist module reads a new list at most once a minute, on a query: the
# domains are flushed again this long after the reload, in a detached process
FLUSH_AGAIN_AFTER = 75


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
    keep = ('domain', 'score', 'checked_at', 'signals', 'feedback')
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


def effective_score(row):
    """The user's feedback (worker 0.9+) overrides the computed score."""
    label = (row.get('feedback') or {}).get('label') if isinstance(row.get('feedback'), dict) else None
    if label == 'fake':
        return 100
    if label == 'legit':
        return 0
    try:
        return int(row.get('score', 0))
    except (TypeError, ValueError):
        return 0


def blocked_domains(cfg):
    """Domains to block: verdicts scoring at least the threshold, as a sorted list.

    Raises OSError (or URLError) when the worker does not answer in full: the previous list
    is kept rather than unblocking everything.
    """
    domains = set()
    offset = 0
    while True:
        page = verdicts(cfg, cfg['threshold'], offset, MAX_PAGE)
        if page['status'] != 'ok':
            raise OSError(page['message'])
        for r in page['rows']:
            name = public_name(str(r.get('domain', '')))
            if name and effective_score(r) >= cfg['threshold']:
                domains.add(name)
        offset += len(page['rows'])
        if not page['rows'] or offset >= page['total'] or len(domains) >= BLOCK_MAX:
            break
    return sorted(domains)[:BLOCK_MAX]


def blocklist(cfg, state_dir=STATE_DIR, now=None, apply=None):
    """Writes the domains Unbound must block; when they differ from what Unbound has,
    `apply` (default: `apply_later`, in the background) gives them to Unbound.

    Observe mode, or ShopGuard disabled: the list is emptied (nothing blocked).
    """
    now = int(now if now is not None else time.time())
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    path = os.path.join(state_dir, BLOCKLIST)
    old = load_json(path, {})
    blocking = cfg['enabled'] and cfg['mode'] == 'block'
    if not blocking:
        domains = []
    else:
        if not cfg['worker_url'] or not cfg['token']:
            return {'status': 'error', 'message': 'Set the worker URL and token first.'}
        try:
            domains = blocked_domains(cfg)
        except (OSError, ValueError) as e:
            message = 'Blocklist not updated, the previous one stays: %s' % getattr(e, 'reason', e)
            syslog.syslog(syslog.LOG_ERR, 'shopguard blocklist: %s' % message)
            return {'status': 'error', 'message': message, 'blocked': len(old.get('domains', []))}
    changed = domains != old.get('domains', [])
    if changed or not os.path.exists(path):
        # read by Unbound's blocklist script, which runs as root like this one
        save_json(path, {'domains': domains, 'threshold': cfg['threshold'], 'time': now})
    pending = domains != applied_domains(state_dir)
    if pending:
        (apply or apply_later)(state_dir)
    return {'status': 'ok', 'blocked': len(domains), 'changed': changed, 'pending': pending,
            'mode': 'block' if blocking else ('observe' if cfg['enabled'] else 'disabled')}


def applied_domains(state_dir=STATE_DIR):
    """The domains Unbound was last given (none before the first time)."""
    return load_json(os.path.join(state_dir, APPLIED), {}).get('domains', [])


def apply_later(state_dir=STATE_DIR):
    """`apply_now` in a detached process: rebuilding Unbound's blocklists takes tens of
    seconds with big lists, the page answers at once."""
    try:
        subprocess.Popen(['/usr/sbin/daemon', '-f', os.path.abspath(__file__), 'apply'],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as e:
        syslog.syslog(syslog.LOG_ERR, 'shopguard apply: %s' % e)


def apply_now(state_dir=STATE_DIR, reload=None, flush=None, now=None):
    """Gives Unbound the current blocklist: rebuilds its blocklists, then flushes the cached
    answers of the domains added or removed. One run at a time; a list changed during a
    rebuild is applied by the same run. Returns how many rebuilds were done."""
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    with open(os.path.join(state_dir, 'apply.lock'), 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        rebuilds = 0
        while rebuilds < 5:
            target = load_json(os.path.join(state_dir, BLOCKLIST), {}).get('domains', [])
            applied = applied_domains(state_dir)
            if target == applied:
                break
            (reload or reload_unbound)()
            rebuilds += 1
            diff = sorted(set(target) ^ set(applied))[:FLUSH_MAX]
            if diff:
                (flush or flush_unbound)(diff)
            save_json(os.path.join(state_dir, APPLIED),
                      {'domains': target, 'time': int(now if now is not None else time.time())})
            syslog.syslog(syslog.LOG_NOTICE, 'shopguard blocklist: %d domains blocked' % len(target))
        return rebuilds


def flush_unbound(names):
    """Drops the cached answers of `names` and their subdomains, now and once more when the
    blocklist module has read the new list (a query in between caches the answer again)."""
    for name in names:
        try:
            subprocess.run(UNBOUND_FLUSH + [name], check=False, timeout=10,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            return
    # names are checked public domain names (public_name), passed as arguments, not code
    script = 'sleep %d; for d in "$@"; do %s "$d"; done' % (FLUSH_AGAIN_AFTER, ' '.join(UNBOUND_FLUSH))
    try:
        subprocess.Popen(['/usr/sbin/daemon', '-f', '/bin/sh', '-c', script, 'shopguard-flush'] + list(names),
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass


def reload_unbound():
    """Unbound rebuilds its blocklists from all sources, ShopGuard's included."""
    subprocess.run(DNSBL_RELOAD, check=False, timeout=600,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


LABELS = ('fake', 'legit', 'none')


def worker_error(e):
    """Message for a failed worker call."""
    if isinstance(e, urllib.error.HTTPError):
        if e.code == 401:
            return 'The worker refused the token.'
        if e.code in (404, 405):
            return 'The worker is too old for decisions: update it to 0.9 or later.'
        return 'Worker error: HTTP %d.' % e.code
    return 'Worker unreachable: %s' % getattr(e, 'reason', e)


def feedback(cfg, domain, label, state_dir=STATE_DIR, apply=None):
    """Sends the user's decision on `domain` (fake, legit, or none to forget it), then
    updates the blocklist so that it applies at once."""
    name = public_name(domain)
    if not name:
        return {'status': 'error', 'message': 'Not a public domain name.'}
    if label not in LABELS:
        return {'status': 'error', 'message': 'The decision is fake, legit or none.'}
    if not cfg['worker_url'] or not cfg['token']:
        return {'status': 'error', 'message': 'Set the worker URL and token first.'}
    try:
        r = call(cfg, '/v1/feedback', {'domain': name, 'label': None if label == 'none' else label})
    except urllib.error.HTTPError as e:
        if e.code == 400:
            return {'status': 'error', 'message': 'Not a public domain name.'}
        return {'status': 'error', 'message': worker_error(e)}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {'status': 'error', 'message': worker_error(e)}
    b = blocklist(cfg, state_dir, apply=apply) if cfg['enabled'] else {'status': 'ok', 'blocked': 0}
    out = {'status': 'ok', 'domain': r.get('domain', name), 'label': r.get('label'),
           'queued': bool(r.get('queued')), 'blocked': b.get('blocked', 0), 'pending': bool(b.get('pending'))}
    if b['status'] != 'ok':
        out['message'] = b['message']
    return out


def labels(cfg):
    """Every domain with a decision: {'status', 'rows': [{domain, label, at, score}]}."""
    if not cfg['worker_url'] or not cfg['token']:
        return {'status': 'error', 'message': 'Set the worker URL and token first.', 'rows': []}
    try:
        rows = call(cfg, '/v1/feedback')
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {'status': 'error', 'message': worker_error(e), 'rows': []}
    if not isinstance(rows, list):
        return {'status': 'error', 'message': 'Unexpected answer from the worker.', 'rows': []}
    out = []
    for r in rows:
        fb = r.get('feedback') if isinstance(r, dict) else None
        name = public_name(str(r.get('domain', ''))) if isinstance(r, dict) else None
        if not name or not isinstance(fb, dict) or fb.get('label') not in ('fake', 'legit'):
            continue
        out.append({'domain': name, 'label': fb['label'], 'at': int(fb.get('at') or 0),
                    'score': int(r.get('score') or 0), 'checked_at': int(r.get('checked_at') or 0)})
    return {'status': 'ok', 'rows': out}


def blocked_count(state_dir=STATE_DIR):
    return len(load_json(os.path.join(state_dir, BLOCKLIST), {}).get('domains', []))


def last_collect(state_dir=STATE_DIR):
    return load_json(os.path.join(state_dir, 'state.json'), {}).get('last')


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ''
    if cmd not in ('status', 'collect', 'blocklist', 'apply', 'update', 'verdicts', 'feedback', 'labels'):
        print('usage: shopguard.py status|collect|blocklist|apply|update|verdicts|feedback|labels', file=sys.stderr)
        return 2
    if cmd == 'apply':
        print(json.dumps({'status': 'ok', 'rebuilds': apply_now()}))
        return 0
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
        out['mode'] = cfg['mode'] if cfg['enabled'] else 'disabled'
        out['blocked'] = blocked_count()
        # not given to Unbound yet: a rebuild is running or waits for the cron
        out['applying'] = load_json(os.path.join(STATE_DIR, BLOCKLIST), {}).get('domains', []) != applied_domains()
        print(json.dumps(out))
        return 0
    if cmd == 'feedback':
        if len(argv) != 4:
            print(json.dumps({'status': 'error', 'message': 'usage: feedback <domain> <fake|legit|none>'}))
            return 2
        out = feedback(cfg, argv[2], argv[3])
        print(json.dumps(out))
        return 0 if out['status'] == 'ok' else 1
    if cmd == 'labels':
        out = labels(cfg)
        print(json.dumps(out))
        return 0 if out['status'] == 'ok' else 1
    if cmd == 'blocklist':
        out = blocklist(cfg)
        print(json.dumps(out))
        return 0 if out['status'] == 'ok' else 1
    out = collect(cfg, local=local_domain())
    if cmd == 'update':
        # the cron job: applied here, and catches up with a background run that failed
        out = {'collect': out, 'blocklist': blocklist(cfg, apply=apply_now)}
        print(json.dumps(out))
        return 0 if out['blocklist']['status'] == 'ok' and \
            out['collect']['status'] in ('ok', 'disabled', 'busy') else 1
    print(json.dumps(out))
    return 0 if out['status'] in ('ok', 'disabled', 'busy') else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
