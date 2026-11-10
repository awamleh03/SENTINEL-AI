import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app
from modules.database import db, User, Scan, Alert


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


class IsolationTests(unittest.TestCase):
    """Server-side isolation between two accounts."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app('test')
        cls.client = cls.app.test_client()

        with cls.app.app_context():
            db.create_all()
            cls.token_a = _register(cls.client, 'alice', 'alice@example.com')
            cls.token_b = _register(cls.client, 'bob', 'bob@example.com')

            alice = User.query.filter_by(username='alice').first()
            cls.alice_id = alice.id

            site = cls.client.post('/api/sites', json={'name': 'Alice Site', 'domain': 'a.test'},
                                   headers=_auth(cls.token_a)).get_json()['site']
            cls.alice_site_id = site['id']

            key = cls.client.post(f"/api/sites/{cls.alice_site_id}/keys", json={'name': 'k'},
                                  headers=_auth(cls.token_a)).get_json()
            cls.alice_key_id = key['api_key']['id']

            # Directly seed a scan and an alert owned by Alice.
            scan = Scan(user_id=alice.id, site_id=cls.alice_site_id, module='docguard',
                        target='a.test', risk_score=55.0, details='{}')
            alert = Alert(user_id=alice.id, site_id=cls.alice_site_id, source='docguard',
                          severity='high', title='Alice alert', message='x')
            db.session.add_all([scan, alert])
            db.session.commit()
            cls.alice_scan_id = scan.id
            cls.alice_alert_id = alert.id

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.drop_all()

    # --- Sites isolation ---
    def test_bob_cannot_see_alice_sites(self):
        resp = self.client.get('/api/sites', headers=_auth(self.token_b))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['total'], 0)

    def test_bob_cannot_get_alice_site(self):
        resp = self.client.get(f'/api/sites/{self.alice_site_id}', headers=_auth(self.token_b))
        self.assertEqual(resp.status_code, 404)

    def test_bob_cannot_list_alice_keys(self):
        resp = self.client.get(f'/api/sites/{self.alice_site_id}/keys', headers=_auth(self.token_b))
        self.assertEqual(resp.status_code, 404)

    def test_bob_cannot_revoke_alice_key(self):
        resp = self.client.post(f'/api/keys/{self.alice_key_id}/revoke', headers=_auth(self.token_b))
        self.assertEqual(resp.status_code, 404)

    def test_bob_cannot_delete_alice_site(self):
        resp = self.client.delete(f'/api/sites/{self.alice_site_id}', headers=_auth(self.token_b))
        self.assertEqual(resp.status_code, 404)

    # --- Scans isolation ---
    def test_bob_scans_empty_alice_has_data(self):
        bob = self.client.get('/api/scans', headers=_auth(self.token_b)).get_json()
        alice = self.client.get('/api/scans', headers=_auth(self.token_a)).get_json()
        self.assertEqual(bob['total'], 0)
        self.assertGreaterEqual(alice['total'], 1)

    def test_bob_cannot_get_alice_scan(self):
        resp = self.client.get(f'/api/scans/{self.alice_scan_id}', headers=_auth(self.token_b))
        self.assertEqual(resp.status_code, 404)

    # --- Alerts isolation ---
    def test_bob_alerts_empty_alice_has_data(self):
        bob = self.client.get('/api/alerts', headers=_auth(self.token_b)).get_json()
        alice = self.client.get('/api/alerts', headers=_auth(self.token_a)).get_json()
        self.assertEqual(bob['total'], 0)
        self.assertGreaterEqual(alice['total'], 1)

    def test_bob_cannot_read_alice_alert(self):
        resp = self.client.post(f'/api/alerts/{self.alice_alert_id}/read', headers=_auth(self.token_b))
        self.assertEqual(resp.status_code, 404)

    # --- Dashboard summary isolation ---
    def test_summary_scoped_per_account(self):
        bob = self.client.get('/api/dashboard/summary', headers=_auth(self.token_b)).get_json()
        alice = self.client.get('/api/dashboard/summary', headers=_auth(self.token_a)).get_json()
        self.assertEqual(bob['scans']['total'], 0)
        self.assertGreaterEqual(alice['scans']['total'], 1)

    # --- Unauthenticated access is rejected ---
    def test_unauthenticated_reads_rejected(self):
        for path in ('/api/scans', '/api/alerts', '/api/dashboard/summary', '/api/sites'):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 401, f'{path} should require auth')


if __name__ == '__main__':
    unittest.main()
