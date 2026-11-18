"""
Backend tests, against a fake worker on loopback.

    python3 -I plugin/tests/test_shopguard.py plugin/dns/shopguard/src/opnsense/scripts/OPNsense/ShopGuard/shopguard.py
"""

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = '0123456789abcdef0123456789abcdef'


def load(path):
    spec = importlib.util.spec_from_file_location('shopguard', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeWorker(BaseHTTPRequestHandler):
    # domains received, and how many of the next ones to defer (queue full)
    received = []
    defer = 0
    # domain -> label, as POST /v1/feedback leaves them
    labels = {}

    def answer(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == '/v1/feedback' and self.headers.get('Authorization') != 'Bearer ' + TOKEN:
            return self.answer({}, 401)
        if self.path == '/v1/feedback':
            req = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if req['domain'].endswith('.invalid'):
                return self.answer({}, 400)
            if req['label'] is None:
                FakeWorker.labels.pop(req['domain'], None)
            else:
                FakeWorker.labels[req['domain']] = req['label']
            return self.answer({'domain': req['domain'], 'label': req['label'], 'queued': False})
        if self.headers.get('Authorization') != 'Bearer ' + TOKEN or self.path != '/v1/domains':
            self.send_response(401 if self.path == '/v1/domains' else 404)
            self.end_headers()
            return
        domains = json.loads(self.rfile.read(int(self.headers['Content-Length'])))['domains']
        assert len(domains) <= 5000
        if FakeWorker.defer:
            FakeWorker.defer -= 1
            answer = {'queued': 0, 'ignored': 0, 'deferred': len(domains)}
        else:
            new = [d for d in domains if d not in FakeWorker.received]
            FakeWorker.received.extend(new)
            answer = {'queued': len(new), 'ignored': len(domains) - len(new), 'deferred': 0}
        body = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.headers.get('Authorization') != 'Bearer ' + TOKEN:
            self.send_response(401)
            self.end_headers()
            return
        if self.path == '/v1/feedback':
            return self.answer([{'domain': d, 'score': 12, 'checked_at': 5, 'signals': [],
                                 'feedback': {'label': label, 'at': 7}}
                                for d, label in sorted(FakeWorker.labels.items())] +
                               [{'domain': 'nolabel.fr', 'score': 1}, 'garbage'])
        if self.path.startswith('/v1/verdicts'):
            rows = [{'domain': 'fake-shop.fr', 'score': 85, 'checked_at': 1, 'signals': [], 'extra': 1},
                    {'domain': 'shop.example.com', 'score': 40, 'checked_at': 2, 'signals': []},
                    {'domain': 'apple.com', 'score': 0, 'checked_at': 3, 'signals': []}]
            body = json.dumps(rows).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == '/v1/status':
            body = json.dumps({'version': '0.1.0', 'pending': 3, 'threshold': 70}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


CONFIG = '''<?xml version="1.0"?>
<opnsense><OPNsense><shopguard><general>
  <enabled>1</enabled><worker_url>%s/</worker_url><token>%s</token>
  <mode>observe</mode><threshold>80</threshold>
</general></shopguard></OPNsense></opnsense>'''


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(('127.0.0.1', 0), FakeWorker)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = 'http://127.0.0.1:%d' % cls.srv.server_port

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def cfg(self, url, token=TOKEN):
        with tempfile.NamedTemporaryFile('w', suffix='.xml', delete=False) as f:
            f.write(CONFIG % (url, token))
        return sg.settings(f.name)

    def test_settings(self):
        c = self.cfg(self.url)
        self.assertEqual(c['worker_url'], self.url)  # trailing slash removed
        self.assertEqual((c['enabled'], c['mode'], c['threshold']), (True, 'observe', 80))

    def test_missing_section(self):
        with tempfile.NamedTemporaryFile('w', suffix='.xml', delete=False) as f:
            f.write('<opnsense/>')
        c = sg.settings(f.name)
        self.assertEqual((c['enabled'], c['worker_url'], c['threshold']), (False, '', 70))

    def test_status_ok(self):
        self.assertEqual(sg.status(self.cfg(self.url)), {'status': 'ok', 'version': '0.1.0', 'pending': 3})

    def test_status_bad_token(self):
        s = sg.status(self.cfg(self.url, 'x' * 32))
        self.assertEqual(s['status'], 'error')
        self.assertIn('token', s['message'])

    def test_verdicts_from_a_worker_without_paging(self):
        v = sg.verdicts(self.cfg(self.url), min_score=1, offset=0, limit=1, search='SHOP')
        self.assertEqual((v['status'], v['total']), ('ok', 2))
        self.assertEqual(v['rows'], [{'domain': 'fake-shop.fr', 'score': 85, 'checked_at': 1, 'signals': [],
                                     'feedback': None}])
        self.assertEqual(sg.verdicts(self.cfg(self.url), 0, 2, 50)['rows'][0]['domain'], 'apple.com')

    def test_verdicts_rejects_odd_search_and_bad_token(self):
        self.assertEqual(sg.verdicts(self.cfg(self.url), search="x' OR 1")['status'], 'error')
        self.assertIn('token', sg.verdicts(self.cfg(self.url, 'x' * 32))['message'])

    def test_status_unreachable(self):
        s = sg.status(self.cfg('http://127.0.0.1:9'))
        self.assertEqual(s['status'], 'error')
        self.assertIn('unreachable', s['message'])

    def test_messages_keep_their_template(self):
        s = sg.templated(sg.status(self.cfg(self.url, 'x' * 32)))
        self.assertEqual(s['message_t'], ['The worker refused the token.', []])
        s = sg.templated(sg.status(self.cfg('http://127.0.0.1:9')))
        self.assertEqual(s['message_t'][0], 'Worker unreachable: %s')
        self.assertEqual(s['message_t'][0] % tuple(s['message_t'][1]), s['message'])
        # nested (update), and plain strings get no template
        out = sg.templated({'collect': {'message': sg.M('Worker error: HTTP %d.', 502)},
                            'blocklist': {'message': 'plain'}})
        self.assertEqual(out['collect']['message_t'], ['Worker error: HTTP %d.', [502]])
        self.assertNotIn('message_t', out['blocklist'])
        self.assertEqual(json.loads(json.dumps(out))['collect']['message'], 'Worker error: HTTP 502.')


class Collect(unittest.TestCase):
    """Collection with a fake Unbound source and the fake worker."""

    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(('127.0.0.1', 0), FakeWorker)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = 'http://127.0.0.1:%d' % cls.srv.server_port

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        FakeWorker.received = []
        FakeWorker.defer = 0
        self.state = tempfile.mkdtemp()
        self.cfg = {'enabled': True, 'worker_url': self.url, 'token': TOKEN, 'mode': 'observe', 'threshold': 70}
        self.calls = []

    def source(self, names, newest):
        def read(since):
            self.calls.append(since)
            return set(names), newest
        return read

    def run_collect(self, names, newest=1000, now=2000, **kw):
        return sg.collect(self.cfg, self.source(names, newest), self.state, now=now, **kw)

    def test_public_names(self):
        p = sg.public_name
        self.assertEqual(p('WWW.Shop.Example.COM.'), 'www.shop.example.com')
        for bad in ['', 'localhost', 'nas.lan', 'printer.local', 'router.home', '1.2.0.192.in-addr.arpa',
                    '192.0.2.1', 'bad..example.com', '-x.example.com', 'spa ce.example.com', 'x' * 300 + '.com']:
            self.assertIsNone(p(bad), bad)
        self.assertIsNone(p('nas.maison.example.org', 'maison.example.org'))
        self.assertEqual(p('shop.example.org', 'maison.example.org'), 'shop.example.org')

    def test_sends_only_new_public_names(self):
        r = self.run_collect(['a.fr', 'www.b.com', 'nas.lan', 'a.fr.'])
        self.assertEqual((r['status'], r['queued'], r['complete']), ('ok', 2, True))
        self.assertEqual(sorted(FakeWorker.received), ['a.fr', 'www.b.com'])
        # next run: from the newest query time (minus the overlap), nothing new to send
        r = self.run_collect(['a.fr', 'c.de'], newest=1500, now=2300)
        self.assertEqual(self.calls, [0, 1000 - sg.OVERLAP])
        self.assertEqual(r['new'], 1)
        self.assertEqual(FakeWorker.received, ['a.fr', 'www.b.com', 'c.de'])
        self.assertEqual(sg.last_collect(self.state)['time'], 2300)

    def test_batches_and_deferred(self):
        names = ['d%d.example.com' % i for i in range(12000)]
        FakeWorker.defer = 0
        r = self.run_collect(names)
        self.assertEqual((r['queued'], r['complete']), (12000, True))
        # a full queue: nothing is marked as sent, the time does not move
        FakeWorker.received = []
        self.state = tempfile.mkdtemp()
        FakeWorker.defer = 1
        r = self.run_collect(names[:10], newest=1000)
        self.assertEqual((r['status'], r['complete']), ('ok', False))
        self.assertEqual(sg.load_json(os.path.join(self.state, 'sent.json'), {}), {})
        r = self.run_collect(names[:10], newest=1100)
        self.assertEqual((r['queued'], r['complete']), (10, True))
        self.assertEqual(self.calls[-2:], [0, 0])

    def test_worker_down_keeps_position(self):
        self.cfg['worker_url'] = 'http://127.0.0.1:9'
        r = self.run_collect(['a.fr'])
        self.assertEqual(r['status'], 'error')
        self.assertIn('unreachable', r['message'])
        self.assertNotIn('since', sg.load_json(os.path.join(self.state, 'state.json'), {}))
        self.assertEqual(sg.last_collect(self.state)['status'], 'error')

    def test_names_sent_long_ago_are_sent_again(self):
        self.run_collect(['a.fr'], now=1000)
        FakeWorker.received = []
        self.run_collect(['a.fr'], now=1000 + sg.RESEND_AFTER)
        self.assertEqual(FakeWorker.received, ['a.fr'])

    def test_disabled_and_unavailable_source(self):
        self.cfg['enabled'] = False
        self.assertEqual(sg.collect(self.cfg, self.source([], 0), self.state)['status'], 'disabled')
        self.cfg['enabled'] = True

        def missing(since):
            raise LookupError('Unbound statistics are disabled')
        r = sg.collect(self.cfg, missing, self.state)
        self.assertEqual(r['status'], 'error')
        self.assertIn('statistics', r['message'])

        def missing_m(since):
            raise LookupError(sg.M('Cannot read the Unbound database: %s', 'locked'))
        sg.collect(self.cfg, missing_m, self.state)
        # saved for the status page with its template
        last = sg.last_collect(self.state)
        self.assertEqual(last['message_t'], ['Cannot read the Unbound database: %s', ['locked']])


class Blocklist(unittest.TestCase):
    """Domains written for Unbound, from the fake worker (no paging: the old-worker path),
    and given to Unbound (applied synchronously here, in the background on the router)."""

    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(('127.0.0.1', 0), FakeWorker)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = 'http://127.0.0.1:%d' % cls.srv.server_port

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.state = tempfile.mkdtemp()
        self.cfg = {'enabled': True, 'worker_url': self.url, 'token': TOKEN, 'mode': 'block', 'threshold': 80}
        self.reloads = 0
        self.flushed = []
        self.applies = 0

    def reload(self):
        self.reloads += 1

    def apply(self, state_dir):
        self.applies += 1
        sg.apply_now(state_dir, reload=self.reload, flush=self.flushed.append, now=1000)

    def run_blocklist(self, apply=None):
        return sg.blocklist(self.cfg, self.state, now=1000, apply=apply or self.apply)

    def written(self):
        return sg.load_json(os.path.join(self.state, sg.BLOCKLIST), {}).get('domains')

    def test_block_mode(self):
        r = self.run_blocklist()
        self.assertEqual((r['status'], r['blocked'], r['changed'], r['pending']), ('ok', 1, True, True))
        self.assertEqual(self.written(), ['fake-shop.fr'])
        self.assertEqual((self.reloads, self.flushed), (1, [['fake-shop.fr']]))
        self.assertEqual(sg.applied_domains(self.state), ['fake-shop.fr'])
        # unchanged and applied: nothing to do
        r = self.run_blocklist()
        self.assertEqual((r['changed'], r['pending'], self.applies), (False, False, 1))
        # a lower threshold blocks more: only the new domain is flushed
        self.cfg['threshold'] = 40
        self.assertEqual(self.run_blocklist()['blocked'], 2)
        self.assertEqual(self.written(), ['fake-shop.fr', 'shop.example.com'])
        self.assertEqual(self.flushed[-1], ['shop.example.com'])
        self.assertEqual(sg.blocked_count(self.state), 2)

    def test_background_run_that_did_not_happen_is_caught_up(self):
        # the detached process did not run (or failed): still pending, applied next time
        r = self.run_blocklist(apply=lambda state_dir: None)
        self.assertTrue(r['pending'])
        self.assertEqual(sg.applied_domains(self.state), [])
        r = self.run_blocklist()
        self.assertEqual((r['changed'], r['pending'], self.reloads), (False, True, 1))
        self.assertEqual(sg.applied_domains(self.state), ['fake-shop.fr'])

    def test_list_changed_during_a_rebuild(self):
        sg.save_json(os.path.join(self.state, sg.BLOCKLIST), {'domains': ['a.fr']})

        def slow_reload():
            self.reloads += 1
            if self.reloads == 1:
                # a decision while Unbound rebuilds
                sg.save_json(os.path.join(self.state, sg.BLOCKLIST), {'domains': ['a.fr', 'b.fr']})
        n = sg.apply_now(self.state, reload=slow_reload, flush=self.flushed.append)
        self.assertEqual(n, 2)
        self.assertEqual(sg.applied_domains(self.state), ['a.fr', 'b.fr'])
        self.assertEqual(self.flushed, [['a.fr'], ['b.fr']])
        self.assertEqual(sg.apply_now(self.state, reload=slow_reload, flush=self.flushed.append), 0)

    def test_feedback_overrides_the_score(self):
        e = sg.effective_score
        self.assertEqual(e({'score': 40, 'feedback': {'label': 'fake', 'at': 1}}), 100)
        self.assertEqual(e({'score': 90, 'feedback': {'label': 'legit', 'at': 1}}), 0)
        self.assertEqual(e({'score': 90, 'feedback': None}), 90)
        self.assertEqual(e({'score': 'x', 'feedback': 'odd'}), 0)

    def test_observe_mode_and_disabled_unblock(self):
        self.run_blocklist()
        self.cfg['mode'] = 'observe'
        r = self.run_blocklist()
        self.assertEqual((r['blocked'], r['changed'], r['mode']), (0, True, 'observe'))
        self.assertEqual((self.written(), self.reloads), ([], 2))
        # unblocked: flushed too (a cached NXDOMAIN)
        self.assertEqual(self.flushed[-1], ['fake-shop.fr'])
        self.cfg['mode'] = 'block'
        self.run_blocklist()
        self.cfg['enabled'] = False
        r = self.run_blocklist()
        self.assertEqual((r['blocked'], r['mode']), (0, 'disabled'))
        # never blocking, nothing to apply
        fresh = tempfile.mkdtemp()
        r = sg.blocklist(self.cfg, fresh, apply=self.apply)
        self.assertEqual((r['changed'], r['pending']), (False, False))

    def test_worker_down_keeps_the_list(self):
        self.run_blocklist()
        self.cfg['worker_url'] = 'http://127.0.0.1:9'
        r = self.run_blocklist()
        self.assertEqual((r['status'], r['blocked']), ('error', 1))
        self.assertIn('previous', r['message'])
        self.assertEqual(sg.templated(r)['message_t'][0], 'Blocklist not updated, the previous one stays: %s')
        self.assertEqual((self.written(), self.reloads), (['fake-shop.fr'], 1))
        self.cfg['token'] = 'x' * 32
        self.cfg['worker_url'] = self.url
        self.assertEqual(self.run_blocklist()['status'], 'error')
        self.assertEqual(self.written(), ['fake-shop.fr'])


class Decisions(unittest.TestCase):
    """Feedback on a domain, and the list of decisions."""

    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(('127.0.0.1', 0), FakeWorker)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = 'http://127.0.0.1:%d' % cls.srv.server_port

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        FakeWorker.labels = {}
        self.state = tempfile.mkdtemp()
        self.cfg = {'enabled': True, 'worker_url': self.url, 'token': TOKEN, 'mode': 'block', 'threshold': 80}
        self.reloads = 0

    def reload(self):
        self.reloads += 1

    def apply(self, state_dir):
        sg.apply_now(state_dir, reload=self.reload, flush=lambda names: None)

    def test_decide_list_forget(self):
        r = sg.feedback(self.cfg, 'WWW.Fake.Example.', 'fake', self.state, self.apply)
        self.assertEqual((r['status'], r['domain'], r['label']), ('ok', 'www.fake.example', 'fake'))
        # the blocklist was updated at once
        self.assertEqual(self.reloads, 1)
        sg.feedback(self.cfg, 'real.fr', 'legit', self.state, self.apply)
        rows = sg.labels(self.cfg)['rows']
        self.assertEqual([(x['domain'], x['label'], x['at']) for x in rows],
                         [('real.fr', 'legit', 7), ('www.fake.example', 'fake', 7)])
        sg.feedback(self.cfg, 'real.fr', 'none', self.state, self.apply)
        self.assertEqual(FakeWorker.labels, {'www.fake.example': 'fake'})

    def test_refused(self):
        for domain, label in (('nas.lan', 'fake'), ('a.fr', 'maybe'), ('x.invalid', 'fake')):
            r = sg.feedback(self.cfg, domain, label, self.state, self.apply)
            self.assertEqual(r['status'], 'error', domain)
        self.assertEqual(self.reloads, 0)
        self.cfg['token'] = 'x' * 32
        self.assertIn('token', sg.feedback(self.cfg, 'a.fr', 'fake', self.state, self.apply)['message'])
        self.assertIn('token', sg.labels(self.cfg)['message'])
        self.cfg['worker_url'] = 'http://127.0.0.1:9'
        self.assertIn('unreachable', sg.labels(self.cfg)['message'])


class Handler(unittest.TestCase):
    """The Unbound blocklist handler, loaded as OPNsense loads it (a module of the
    `blocklists` package, next to the core's BaseBlocklistHandler)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        pkg = os.path.join(self.dir, 'blocklists')
        os.mkdir(pkg)
        with open(os.path.join(pkg, '__init__.py'), 'w') as f:
            f.write(BASE)
        shutil.copy(HANDLER, pkg)
        self.list = os.path.join(self.dir, 'blocklist.json')
        os.environ['SHOPGUARD_BLOCKLIST'] = self.list
        sys.modules.setdefault('ujson', json)
        sys.path.insert(0, self.dir)
        for m in ('blocklists', 'blocklists.shopguard_bl'):
            sys.modules.pop(m, None)
        self.mod = importlib.import_module('blocklists.shopguard_bl')

    def tearDown(self):
        sys.path.remove(self.dir)
        del os.environ['SHOPGUARD_BLOCKLIST']

    def write(self, data):
        with open(self.list, 'w') as f:
            f.write(data if isinstance(data, str) else json.dumps(data))

    def test_domains_and_policy(self):
        self.write({'domains': ['fake-shop.fr', 'Bad Name', 42, 'autre.shop']})
        h = self.mod.ShopGuardBlocklistHandler()
        self.assertEqual(list(h.blocklists_iter()), [
            ('fake-shop.fr', 'shopguard', {'bl': 'ShopGuard', 'wildcard': True}),
            ('autre.shop', 'shopguard', {'bl': 'ShopGuard', 'wildcard': True}),
        ])
        p = h.get_policies()
        self.assertEqual((p[0]['id'], p[0]['rcode'], p[0]['source_nets']), ('shopguard', 'NXDOMAIN', []))

    def test_nothing_to_block(self):
        for data in ({'domains': []}, '{broken', {'domains': 'x.fr'}, ['x.fr']):
            self.write(data)
            h = self.mod.ShopGuardBlocklistHandler()
            self.assertEqual((h.get_policies(), list(h.blocklists_iter())), ([], []), data)
        os.remove(self.list)
        self.assertEqual(self.mod.ShopGuardBlocklistHandler().get_policies(), [])


# what the handler needs from OPNsense's scripts/unbound/blocklists/__init__.py
BASE = '''
import re


class BaseBlocklistHandler:
    def __init__(self, config=None):
        self.config = config
        self.priority = 0
        self.domain_pattern = re.compile(
            r'^(\\*\\.){,1}(([\\da-zA-Z_])([_\\w-]{,62})\\.){,127}(([\\da-zA-Z])[_\\w-]{,61})'
            r'?([\\da-zA-Z]\\.((xn\\-\\-[a-zA-Z\\d]+)|([a-zA-Z\\d]{2,})))$'
        )
'''


if __name__ == '__main__':
    sg = load(sys.argv.pop(1))
    # scripts/OPNsense/ShopGuard/shopguard.py -> scripts/unbound/blocklists/shopguard_bl.py
    HANDLER = os.path.join(os.path.dirname(os.path.abspath(sg.__file__)),
                           '..', '..', 'unbound', 'blocklists', 'shopguard_bl.py')
    unittest.main()
