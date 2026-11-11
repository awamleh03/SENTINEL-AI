"""Additional BotGuard checks for phase 4.2 dashboard Alert creation.

Append these methods to tests/test_botguard.py inside BotGuardTests, or run this
module alongside the existing suite. Existing monitor-only guarantees remain
unchanged and must still pass.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app
from modules.database import db, Alert
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


class BotGuardAlertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app('test')
        cls.client = cls.app.test_client()
        with cls.app.app_context():
            db.create_all()
            cls.token = _register(cls.client, 'botalert', 'botalert@example.com')

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.drop_all()

    def setUp(self):
        botguard._BURST.clear()
        botguard._ALERT_DEDUP.clear()
        with self.app.app_context():
            Alert.query.delete()
            db.session.commit()

    def _site(self):
        resp = self.client.post('/api/sites', headers=_auth(self.token), json={'name': 's'})
        self.assertEqual(resp.status_code, 201, resp.get_json())
        return resp.get_json()['site']

    def test_suspicious_creates_dashboard_alert(self):
        site = self._site()
        headers = {'User-Agent': '', 'Accept': '', 'Accept-Language': '', 'Referer': ''}
        headers.update(_auth(self.token))
        resp = self.client.post('/api/botguard/evaluate', headers=headers, json={
            'site_id': site['id'], 'path': '/login', 'method': 'GET'
        })
        self.assertEqual(resp.status_code, 200)
        result = resp.get_json()['result']
        self.assertTrue(result['suspicious'])
        self.assertEqual(result['action_taken'], 'monitored')
        with self.app.app_context():
            alerts = Alert.query.filter_by(source='botguard', site_id=site['id']).all()
            self.assertGreaterEqual(len(alerts), 1)
            self.assertIn(alerts[0].severity, ('medium', 'high'))

    def test_benign_does_not_create_alert(self):
        site = self._site()
        headers = dict(BENIGN_HEADERS)
        headers.update(_auth(self.token))
        resp = self.client.post('/api/botguard/evaluate', headers=headers, json={
            'site_id': site['id'], 'path': '/page', 'method': 'GET'
        })
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.get_json()['result']['suspicious'])
        with self.app.app_context():
            self.assertEqual(Alert.query.filter_by(source='botguard').count(), 0)

    def test_alert_dedup_within_window(self):
        site = self._site()
        headers = {'User-Agent': '', 'Accept': '', 'Accept-Language': '', 'Referer': ''}
        headers.update(_auth(self.token))
        for _ in range(3):
            self.client.post('/api/botguard/evaluate', headers=headers, json={
                'site_id': site['id'], 'path': '/login', 'method': 'GET'
            })
        with self.app.app_context():
            # Multiple security events may exist, but dashboard alerts are deduped.
            self.assertEqual(Alert.query.filter_by(source='botguard', site_id=site['id']).count(), 1)


if __name__ == '__main__':
    unittest.main()
