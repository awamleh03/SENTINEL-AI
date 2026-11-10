import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app
from modules.database import db, User, SecurityEvent, sanitize_details
from modules.events import get_client_ip


def _register(client, username, email, password='Password123'):
    resp = client.post('/api/auth/register', json={
        'username': username,
        'email': email,
        'password': password
    })
    assert resp.status_code == 201, f'registration failed: {resp.get_json()}'
    return resp.get_json()['token']


def _auth(token):
    return {'Authorization': f'Bearer {token}'}


class SecurityEventTests(unittest.TestCase):
    """Security event log: recording, filters, isolation, retention."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app('test')
        cls.client = cls.app.test_client()
        with cls.app.app_context():
            db.create_all()
            cls.token_a = _register(cls.client, 'alice', 'alice@example.com')
            cls.token_b = _register(cls.client, 'bob', 'bob@example.com')

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.drop_all()

    def _create_site(self, token, name, domain='shop.example.com'):
        resp = self.client.post('/api/sites', json={'name': name, 'domain': domain},
                                headers=_auth(token))
        self.assertEqual(resp.status_code, 201)
        return resp.get_json()['site']

    def _create_key(self, token, site_id):
        resp = self.client.post(f'/api/sites/{site_id}/keys', json={'name': 'prod'},
                                headers=_auth(token))
        self.assertEqual(resp.status_code, 201)
        return resp.get_json()['key']

    # --- access control -----------------------------------------------------
    def test_list_events_requires_auth(self):
        resp = self.client.get('/api/events')
        self.assertEqual(resp.status_code, 401)

    def test_get_event_requires_auth(self):
        resp = self.client.get('/api/events/1')
        self.assertEqual(resp.status_code, 401)

    # --- real producer: apikey-info writes an attributable event ------------
    def test_apikey_info_records_event(self):
        site = self._create_site(self.token_a, 'Prod')
        raw = self._create_key(self.token_a, site['id'])
        self.client.get('/api/apikey-info', headers={'X-API-Key': raw})

        resp = self.client.get('/api/events', headers=_auth(self.token_a))
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertGreaterEqual(body['total'], 1)
        ev = body['events'][0]
        self.assertEqual(ev['event_type'], 'apikey_validation')
        self.assertEqual(ev['decision'], 'allow')
        self.assertEqual(ev['action_taken'], 'allowed')
        self.assertEqual(ev['site_id'], site['id'])

    def test_inactive_site_records_deny_event(self):
        site = self._create_site(self.token_a, 'InactiveProd')
        raw = self._create_key(self.token_a, site['id'])
        # deactivate the site
        resp = self.client.patch(f"/api/sites/{site['id']}", json={'is_active': False},
                                 headers=_auth(self.token_a))
        self.assertEqual(resp.status_code, 200)

        info = self.client.get('/api/apikey-info', headers={'X-API-Key': raw})
        self.assertEqual(info.status_code, 403)

        resp = self.client.get('/api/events', headers=_auth(self.token_a),
                               query_string={'site_id': site['id'], 'decision': 'deny'})
        self.assertEqual(resp.status_code, 200)
        events = resp.get_json()['events']
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0]['threat_type'], 'inactive_site')

    # --- filters ------------------------------------------------------------
    def test_filter_by_event_type(self):
        resp = self.client.get('/api/events', headers=_auth(self.token_a),
                               query_string={'event_type': 'apikey_validation'})
        self.assertEqual(resp.status_code, 200)
        for ev in resp.get_json()['events']:
            self.assertEqual(ev['event_type'], 'apikey_validation')

    def test_filter_by_path_substring(self):
        resp = self.client.get('/api/events', headers=_auth(self.token_a),
                               query_string={'path': 'apikey'})
        self.assertEqual(resp.status_code, 200)
        for ev in resp.get_json()['events']:
            self.assertIn('apikey', (ev['path'] or ''))

    def test_pagination_shape(self):
        resp = self.client.get('/api/events', headers=_auth(self.token_a),
                               query_string={'page': 1, 'per_page': 1})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertIn('page', body)
        self.assertIn('per_page', body)
        self.assertIn('pages', body)
        self.assertLessEqual(len(body['events']), 1)

    # --- isolation ----------------------------------------------------------
    def test_events_are_isolated_between_accounts(self):
        # Alice's own site + activity.
        site_a = self._create_site(self.token_a, 'AliceShop', domain='alice.example.com')
        raw_a = self._create_key(self.token_a, site_a['id'])
        self.client.get('/api/apikey-info', headers={'X-API-Key': raw_a})

        # Bob has his own site + key activity.
        site_b = self._create_site(self.token_b, 'BobShop', domain='bob.example.com')
        raw_b = self._create_key(self.token_b, site_b['id'])
        self.client.get('/api/apikey-info', headers={'X-API-Key': raw_b})

        a_site_ids = {ev['site_id'] for ev in
                      self.client.get('/api/events', headers=_auth(self.token_a)).get_json()['events']}
        b_site_ids = {ev['site_id'] for ev in
                      self.client.get('/api/events', headers=_auth(self.token_b)).get_json()['events']}

        # Alice never sees Bob's site, and vice versa.
        self.assertNotIn(site_b['id'], a_site_ids)
        self.assertNotIn(site_a['id'], b_site_ids)
        self.assertIn(site_a['id'], a_site_ids)
        self.assertIn(site_b['id'], b_site_ids)

    def test_cannot_read_other_accounts_event_by_id(self):
        site_b = self._create_site(self.token_b, 'BobShop2', domain='bob2.example.com')
        raw_b = self._create_key(self.token_b, site_b['id'])
        self.client.get('/api/apikey-info', headers={'X-API-Key': raw_b})
        b_ev = self.client.get('/api/events', headers=_auth(self.token_b)).get_json()['events'][0]

        resp = self.client.get(f"/api/events/{b_ev['id']}", headers=_auth(self.token_a))
        self.assertEqual(resp.status_code, 404)

    # --- retention purge (admin only) --------------------------------------
    def test_purge_requires_admin(self):
        resp = self.client.post('/api/events/purge', headers=_auth(self.token_a))
        self.assertEqual(resp.status_code, 403)

    def test_purge_as_admin(self):
        with self.app.app_context():
            user = User.query.filter_by(username='alice').first()
            user.is_admin = True
            db.session.commit()
        try:
            resp = self.client.post('/api/events/purge', json={'retention_days': 3650},
                                    headers=_auth(self.token_a))
            self.assertEqual(resp.status_code, 200)
            self.assertIn('deleted', resp.get_json())
        finally:
            with self.app.app_context():
                user = User.query.filter_by(username='alice').first()
                user.is_admin = False
                db.session.commit()

    # --- sensitive data is never stored ------------------------------------
    def test_sanitize_details_redacts_secrets(self):
        sanitized = sanitize_details({
            'username': 'alice',
            'password': 'hunter2',
            'nested': {'token': 'abc', 'note': 'ok'},
            'items': [{'api_key': 'sk-123'}]
        })
        self.assertEqual(sanitized['username'], 'alice')
        self.assertEqual(sanitized['password'], '[redacted]')
        self.assertEqual(sanitized['nested']['token'], '[redacted]')
        self.assertEqual(sanitized['nested']['note'], 'ok')
        self.assertEqual(sanitized['items'][0]['api_key'], '[redacted]')


class ClientIpTests(unittest.TestCase):
    """Trusted-proxy handling: X-Forwarded-For is not blindly trusted."""

    def setUp(self):
        self.app = create_app('test')

    def test_untrusted_peer_ignores_forwarded_header(self):
        self.app.config['TRUSTED_PROXIES'] = []
        with self.app.test_request_context(
            '/', environ_base={'REMOTE_ADDR': '1.2.3.4'},
            headers={'X-Forwarded-For': '9.9.9.9'}
        ):
            self.assertEqual(get_client_ip(), '1.2.3.4')

    def test_trusted_peer_honors_forwarded_header(self):
        self.app.config['TRUSTED_PROXIES'] = ['10.0.0.1']
        self.app.config['TRUSTED_PROXY_HOPS'] = 1
        with self.app.test_request_context(
            '/', environ_base={'REMOTE_ADDR': '10.0.0.1'},
            headers={'X-Forwarded-For': '9.9.9.9'}
        ):
            self.assertEqual(get_client_ip(), '9.9.9.9')

    def test_spoofed_header_from_untrusted_peer_is_ignored(self):
        self.app.config['TRUSTED_PROXIES'] = ['10.0.0.1']
        self.app.config['TRUSTED_PROXY_HOPS'] = 1
        with self.app.test_request_context(
            '/', environ_base={'REMOTE_ADDR': '203.0.113.7'},
            headers={'X-Forwarded-For': '9.9.9.9'}
        ):
            self.assertEqual(get_client_ip(), '203.0.113.7')


if __name__ == '__main__':
    unittest.main()
