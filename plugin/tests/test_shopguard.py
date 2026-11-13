"""
Backend tests, against a fake worker on loopback.

    python3 -I plugin/tests/test_shopguard.py plugin/dns/shopguard/src/opnsense/scripts/OPNsense/ShopGuard/shopguard.py
"""

import importlib.util
import json
import os
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

    def do_POST(self):
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
        self.assertEqual(v['rows'], [{'domain': 'fake-shop.fr', 'score': 85, 'checked_at': 1, 'signals': []}])
        self.assertEqual(sg.verdicts(self.cfg(self.url), 0, 2, 50)['rows'][0]['domain'], 'apple.com')

    def test_verdicts_rejects_odd_search_and_bad_token(self):
        self.assertEqual(sg.verdicts(self.cfg(self.url), search="x' OR 1")['status'], 'error')
        self.assertIn('token', sg.verdicts(self.cfg(self.url, 'x' * 32))['message'])

    def test_status_unreachable(self):
        s = sg.status(self.cfg('http://127.0.0.1:9'))
        self.assertEqual(s['status'], 'error')
        self.assertIn('unreachable', s['message'])


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


if __name__ == '__main__':
    sg = load(sys.argv.pop(1))
    unittest.main()
