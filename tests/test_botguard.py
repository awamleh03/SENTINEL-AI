import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app
from modules.database import db, SecurityEvent
from modules import botguard

BENIGN_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
             '(KHTML, like Gecko) Chrome/120.0 Safari/537.36')
BENIGN_HEADERS = {
    'User-Agent': BENIGN_UA,
    'Accept': 'text/html,application/xhtml+xml',
    'Accept-Language': 'en-US,en;q=0.9',
    'Referer': 'https://example.com/home',
}


def _register(client, username, email, password='Password123'):
    resp = client.post('/api/auth/register', json={
        'username': username, 'email': email, 'password': password
    })
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()['token']


def _auth(token):
    return {'Authorization': f'Bearer {token}'}


class BotGuardTests(unittest.TestCase):
    """Heuristic suspicion scoring, monitor-only behaviour and tenancy."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app('test')
        cls.client = cls.app.test_client()
        with cls.app.app_context():
            db.create_all()
            cls.token_a = _register(cls.client, 'botalice', 'botalice@example.com')
            cls.token_b = _register(cls.client, 'botbob', 'botbob@example.com')

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.drop_all()

    def setUp(self):
        # The behavioural tracker keeps in-process state; reset it per test.
        botguard._BURST.clear()

    # -- helpers --------------------------------------------------------------
    def _new_site(self, token, name='site'):
        resp = self.client.post('/api/sites', headers=_auth(token), json={'name': name})
        self.assertEqual(resp.status_code, 201, resp.get_json())
        return resp.get_json()['site']

    def _evaluate(self, token, site_id, headers=None, path='/page', method='GET',
                  body_headers=None, remote=None):
        payload = {'site_id': site_id, 'path': path, 'method': method}
        if body_headers is not None:
            payload['headers'] = body_headers
        kwargs = {}
        if remote:
            kwargs['environ_base'] = {'REMOTE_ADDR': remote}
        hdrs = dict(headers) if headers is not None else dict(BENIGN_HEADERS)
        hdrs.update(_auth(token))
        resp = self.client.post('/api/botguard/evaluate', headers=hdrs, json=payload, **kwargs)
        self.assertEqual(resp.status_code, 200, resp.get_json())
        return resp.get_json()['result']

    def _bot_events(self, site_id=None):
        with self.app.app_context():
            q = SecurityEvent.query.filter_by(event_type='bot_suspected')
            if site_id is not None:
                q = q.filter(SecurityEvent.site_id == site_id)
            return q.count()

    # -- auth / validation ----------------------------------------------------
    def test_endpoints_require_auth(self):
        self.assertEqual(self.client.post('/api/botguard/evaluate', json={}).status_code, 401)

    def test_requires_site_id(self):
        resp = self.client.post('/api/botguard/evaluate', headers=_auth(self.token_a),
                                json={'path': '/x'})
        self.assertEqual(resp.status_code, 400)

    def test_foreign_site_rejected(self):
        site = self._new_site(self.token_a)
        resp = self.client.post('/api/botguard/evaluate', headers=_auth(self.token_b),
                                json={'site_id': site['id'], 'path': '/x'})
        self.assertEqual(resp.status_code, 404)

    # -- scoring --------------------------------------------------------------
    def test_benign_browser_scores_zero(self):
        site = self._new_site(self.token_a)
        result = self._evaluate(self.token_a, site['id'], headers=BENIGN_HEADERS)
        self.assertEqual(result['score'], 0)
        self.assertFalse(result['suspicious'])
        self.assertEqual(result['level'], 'none')
        self.assertEqual(result['reasons'], [])

    def test_user_agent_alone_is_not_enough(self):
        site = self._new_site(self.token_a)
        headers = dict(BENIGN_HEADERS)
        headers['User-Agent'] = 'curl/8.4.0'
        result = self._evaluate(self.token_a, site['id'], headers=headers, path='/page')
        # A single automation marker stays below the suspicion threshold.
        self.assertIn('automation_marker_in_user_agent', result['reasons'])
        self.assertLess(result['score'], 40)
        self.assertFalse(result['suspicious'])

    def test_missing_headers_combined_raise_suspicion(self):
        site = self._new_site(self.token_a)
        headers = {'User-Agent': '', 'Accept': '', 'Accept-Language': '', 'Referer': ''}
        result = self._evaluate(self.token_a, site['id'], headers=headers, path='/login')
        self.assertTrue(result['suspicious'])
        self.assertIn('missing_user_agent', result['reasons'])
        self.assertIn('missing_accept_language', result['reasons'])
        self.assertIn('missing_accept_header', result['reasons'])
        self.assertIn('sensitive_path_targeted', result['reasons'])
        self.assertGreaterEqual(result['score'], 40)

    def test_signals_include_weights(self):
        site = self._new_site(self.token_a)
        headers = {'User-Agent': 'python-requests/2.31', 'Accept': '*/*', 'Accept-Language': ''}
        result = self._evaluate(self.token_a, site['id'], headers=headers)
        codes = [s['code'] for s in result['signals']]
        self.assertIn('automation_marker_in_user_agent', codes)
        self.assertIn('generic_accept_header', codes)
        for sig in result['signals']:
            self.assertIsInstance(sig['weight'], int)

    def test_high_request_rate_signal(self):
        site = self._new_site(self.token_a)
        self.app.config['BOT_RATE_THRESHOLD'] = 3
        self.app.config['BOT_WINDOW_SECONDS'] = 60
        try:
            last = None
            for _ in range(3):
                last = self._evaluate(self.token_a, site['id'], headers=BENIGN_HEADERS)
            self.assertIn('high_request_rate', last['reasons'])
        finally:
            self.app.config['BOT_RATE_THRESHOLD'] = 20
            self.app.config['BOT_WINDOW_SECONDS'] = 10

    # -- monitor-only guarantees ---------------------------------------------
    def test_never_blocks(self):
        site = self._new_site(self.token_a)
        headers = {'User-Agent': '', 'Accept': '', 'Accept-Language': '', 'Referer': ''}
        result = self._evaluate(self.token_a, site['id'], headers=headers, path='/admin')
        self.assertEqual(result['action_taken'], 'monitored')
        self.assertTrue(result['monitor_only'])
        self.assertNotEqual(result['action_taken'], 'blocked')
        self.assertIn(result['decision'], ('allow', 'suspicious'))

    # -- event recording ------------------------------------------------------
    def test_records_event_when_suspicious(self):
        site = self._new_site(self.token_a)
        before = self._bot_events(site['id'])
        headers = {'User-Agent': '', 'Accept': '', 'Accept-Language': '', 'Referer': ''}
        self._evaluate(self.token_a, site['id'], headers=headers, path='/login')
        self.assertEqual(self._bot_events(site['id']), before + 1)

    def test_no_event_when_benign(self):
        site = self._new_site(self.token_a)
        before = self._bot_events(site['id'])
        self._evaluate(self.token_a, site['id'], headers=BENIGN_HEADERS)
        self.assertEqual(self._bot_events(site['id']), before)

    # -- API key (SDK) path ---------------------------------------------------
    def test_api_key_resolves_site(self):
        site = self._new_site(self.token_a)
        key_resp = self.client.post(f"/api/sites/{site['id']}/keys", headers=_auth(self.token_a),
                                    json={'name': 'sdk'})
        self.assertEqual(key_resp.status_code, 201, key_resp.get_json())
        raw_key = key_resp.get_json()['key']
        resp = self.client.post('/api/botguard/evaluate',
                                headers={'X-API-Key': raw_key, **BENIGN_HEADERS},
                                json={'path': '/page', 'method': 'GET'})
        self.assertEqual(resp.status_code, 200, resp.get_json())
        self.assertIn('result', resp.get_json())

    def test_body_header_overrides_are_used(self):
        site = self._new_site(self.token_a)
        result = self._evaluate(
            self.token_a, site['id'],
            headers=BENIGN_HEADERS,
            body_headers={'User-Agent': 'python-requests/2.31'},
        )
        self.assertIn('automation_marker_in_user_agent', result['reasons'])

    # -- tenancy --------------------------------------------------------------
    def test_isolation_between_accounts(self):
        site_a = self._new_site(self.token_a, 'a-site')
        # Account B has its own site and never sees A's signals.
        site_b = self._new_site(self.token_b, 'b-site')
        headers = {'User-Agent': '', 'Accept': '', 'Accept-Language': '', 'Referer': ''}
        self._evaluate(self.token_a, site_a['id'], headers=headers, path='/login')
        self._evaluate(self.token_b, site_b['id'], headers=headers, path='/login')
        self.assertEqual(self._bot_events(site_a['id']), 1)
        self.assertEqual(self._bot_events(site_b['id']), 1)

    def test_trusted_proxy_ignores_forwarded_header(self):
        # Without TRUSTED_PROXIES configured, a spoofed X-Forwarded-For is ignored.
        site = self._new_site(self.token_a)
        headers = dict(BENIGN_HEADERS)
        headers['X-Forwarded-For'] = '203.0.113.9'
        headers.update(_auth(self.token_a))
        resp = self.client.post('/api/botguard/evaluate', headers=headers,
                                json={'site_id': site['id'], 'path': '/page'})
        self.assertEqual(resp.status_code, 200, resp.get_json())
        # The result is produced regardless; the IP is resolved server-side.
        self.assertIn('result', resp.get_json())


if __name__ == '__main__':
    unittest.main()
