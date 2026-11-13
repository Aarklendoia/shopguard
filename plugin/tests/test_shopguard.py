"""
Backend tests, against a fake worker on loopback.

    python3 -I plugin/tests/test_shopguard.py plugin/dns/shopguard/src/opnsense/scripts/OPNsense/ShopGuard/shopguard.py
"""

import importlib.util
import json
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
    def do_GET(self):
        if self.headers.get('Authorization') != 'Bearer ' + TOKEN:
            self.send_response(401)
            self.end_headers()
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

    def test_status_unreachable(self):
        s = sg.status(self.cfg('http://127.0.0.1:9'))
        self.assertEqual(s['status'], 'error')
        self.assertIn('unreachable', s['message'])


if __name__ == '__main__':
    sg = load(sys.argv.pop(1))
    unittest.main()
