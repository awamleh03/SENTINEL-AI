"""Authorisation tests: who may call what, and who is turned away.

This file is deliberately separate from test_isolation.py. Isolation proves that
one account never SEES another account's data; authorisation proves the gate
itself: requests without valid credentials are rejected, non-admins cannot reach
admin-only endpoints, and a caller cannot reach into another account's
resources even when it guesses a valid id.

Nothing here proves the project is free of every access-control flaw; it covers
the specific paths exercised below.
"""

import datetime
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import jwt

from backend.app import create_app
from modules.database import db, User, Scan, Alert


def _register(client, username, email, password='Password123'):
    resp = client.post('/api/auth/register', json={
        'username': username,
        'email': email,
        'password': password,
    })
    assert resp.status_code == 201, f'registration failed: {resp.get_json()}'
    return resp.get_json()['token']


def _auth(token):
    return {'Authorization': f'Bearer {token}'}


# Endpoints that must reject an anonymous caller (each uses @token_required).
PROTECTED_GETS = (
    '/api/auth/me',
    '/api/sites',
    '/api/scans',
    '/api/alerts',
    '/api/events',
    '/api/policies',
    '/api/ratelimit/rules',
    '/api/acl/rules',
    '/api/notifications/channels',
    '/api/dashboard/summary',
)


class AuthorizationTests(unittest.TestCase):
    """Credential and role enforcement across the API surface."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app('test')
        cls.client = cls.app.test_client()
        cls.jwt_secret = cls.app.config['JWT_SECRET_KEY']

        with cls.app.app_context():
            db.create_all()

            # Two ordinary accounts plus one elevated account.
            cls.token_a = _register(cls.client, 'alice', 'alice@example.com')
            cls.token_b = _register(cls.client, 'bob', 'bob@example.com')
            cls.token_admin = _register(cls.client, 'root', 'root@example.com')

            root = User.query.filter_by(username='root').first()
            root.is_admin = True
            db.session.commit()

            alice = User.query.filter_by(username='alice').first()
            cls.alice_id = alice.id
            cls.bob_id = User.query.filter_by(username='bob').first().id

            # --- Alice owns a representative resource of every kind ---
            site = cls.client.post(
                '/api/sites', json={'name': 'Alice Site', 'domain': 'a.test'},
                headers=_auth(cls.token_a)
            ).get_json()['site']
            cls.alice_site_id = site['id']

            key = cls.client.post(
                f"/api/sites/{cls.alice_site_id}/keys", json={'name': 'k'},
                headers=_auth(cls.token_a)
            ).get_json()
            cls.alice_key_id = key['api_key']['id']

            policy = cls.client.post(
                '/api/policies', json={'name': 'Alice Policy', 'site_id': cls.alice_site_id},
                headers=_auth(cls.token_a)
            ).get_json()['policy']
            cls.alice_policy_id = policy['id']

            rule = cls.client.post(
                f"/api/policies/{cls.alice_policy_id}/rules",
                json={'label': 'r', 'path_pattern': '/x', 'action': 'monitor'},
                headers=_auth(cls.token_a)
            ).get_json()['rule']
            cls.alice_policy_rule_id = rule['id']

            rl = cls.client.post(
                '/api/ratelimit/rules',
                json={'name': 'rl', 'limit_count': 10, 'window_seconds': 60,
                      'site_id': cls.alice_site_id},
                headers=_auth(cls.token_a)
            ).get_json()['rule']
            cls.alice_rl_rule_id = rl['id']

            acl = cls.client.post(
                '/api/acl/rules',
                json={'list_type': 'allow', 'match_type': 'path', 'value': '/x',
                      'site_id': cls.alice_site_id},
                headers=_auth(cls.token_a)
            ).get_json()['rule']
            cls.alice_acl_rule_id = acl['id']

            channel = cls.client.post(
                '/api/notifications/channels',
                json={'channel_type': 'email', 'name': 'Alice Mail',
                      'config': {'to_address': 'alice@example.com'}},
                headers=_auth(cls.token_a)
            ).get_json()['channel']
            cls.alice_channel_id = channel['id']

            # Seed a scan and an alert directly (no public create endpoint).
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

    # --- 1. missing / malformed / invalid credentials -> 401 ----------------

    def test_anonymous_get_requires_authentication(self):
        for path in PROTECTED_GETS:
            with self.subTest(path=path):
                resp = self.client.get(path)
                self.assertEqual(resp.status_code, 401, f'{path} must require auth')

    def test_missing_authorization_header_is_401(self):
        resp = self.client.get('/api/sites')
        self.assertEqual(resp.status_code, 401)
        self.assertIn('error', resp.get_json())

    def test_wrong_authorization_scheme_is_401(self):
        resp = self.client.get('/api/sites', headers={'Authorization': 'Token abc'})
        self.assertEqual(resp.status_code, 401)

    def test_bearer_without_token_is_401(self):
        resp = self.client.get('/api/sites', headers={'Authorization': 'Bearer'})
        self.assertEqual(resp.status_code, 401)

    def test_malformed_bearer_token_is_401(self):
        for bad in ('Bearer not-a-jwt', 'Bearer a.b.c', 'Bearer   '):
            with self.subTest(value=bad):
                resp = self.client.get('/api/sites', headers={'Authorization': bad})
                self.assertEqual(resp.status_code, 401)

    def test_token_signed_with_wrong_secret_is_401(self):
        forged = jwt.encode(
            {'user_id': self.alice_id, 'username': 'alice', 'is_admin': True,
             'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            'a-different-secret', algorithm='HS256',
        )
        resp = self.client.get('/api/sites', headers=_auth(forged))
        self.assertEqual(resp.status_code, 401)

    def test_expired_token_is_401(self):
        expired = jwt.encode(
            {'user_id': self.alice_id, 'username': 'alice', 'is_admin': False,
             'exp': datetime.datetime.utcnow() - datetime.timedelta(minutes=1),
             'iat': datetime.datetime.utcnow() - datetime.timedelta(hours=2)},
            self.jwt_secret, algorithm='HS256',
        )
        resp = self.client.get('/api/sites', headers=_auth(expired))
        self.assertEqual(resp.status_code, 401)

    def test_valid_token_is_accepted(self):
        # Positive control: the same route accepts a legitimate credential.
        resp = self.client.get('/api/sites', headers=_auth(self.token_a))
        self.assertEqual(resp.status_code, 200)

    def test_token_of_deactivated_user_is_401(self):
        with self.app.app_context():
            admin = User.query.filter_by(username='root').first()
            admin.is_admin = True
            db.session.commit()

        token = _register(self.client, 'carol', 'carol@example.com')
        with self.app.app_context():
            carol = User.query.filter_by(username='carol').first()
            carol.is_active = False
            db.session.commit()

        resp = self.client.get('/api/sites', headers=_auth(token))
        self.assertEqual(resp.status_code, 401)

    def test_protected_write_requires_authentication(self):
        resp = self.client.post('/api/sites', json={'name': 'x', 'domain': 'x.test'})
        self.assertEqual(resp.status_code, 401)

    # --- 2. admin-only endpoints -> 403 for non-admins ----------------------

    def test_admin_endpoints_reject_ordinary_user(self):
        for method, path in (('GET', '/api/auth/users'),
                             ('POST', '/api/events/purge')):
            with self.subTest(path=path):
                resp = self.client.open(path, method=method, headers=_auth(self.token_a))
                self.assertEqual(resp.status_code, 403, f'{path} is admin-only')

    def test_admin_endpoints_reject_anonymous_user(self):
        for method, path in (('GET', '/api/auth/users'),
                             ('POST', '/api/events/purge')):
            with self.subTest(path=path):
                resp = self.client.open(path, method=method)
                self.assertEqual(resp.status_code, 401, f'{path} must require auth')

    def test_admin_can_reach_admin_endpoints(self):
        resp = self.client.get('/api/auth/users', headers=_auth(self.token_admin))
        self.assertEqual(resp.status_code, 200)
        self.assertIn('users', resp.get_json())

        resp = self.client.post('/api/events/purge', json={'retention_days': 30},
                                headers=_auth(self.token_admin))
        self.assertEqual(resp.status_code, 200)

    def test_admin_flag_in_token_alone_does_not_grant_access(self):
        # A token minted for an ordinary user cannot fake the admin flag: the
        # server re-reads is_admin from the database on every request.
        forged = jwt.encode(
            {'user_id': self.bob_id, 'username': 'bob', 'is_admin': True,
             'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            self.jwt_secret, algorithm='HS256',
        )
        resp = self.client.get('/api/auth/users', headers=_auth(forged))
        self.assertEqual(resp.status_code, 403)

    # --- 3. cross-account access -> 404 (anti-enumeration) ------------------

    def test_bob_cannot_reach_alice_site(self):
        self.assertEqual(
            self.client.get(f'/api/sites/{self.alice_site_id}', headers=_auth(self.token_b)).status_code,
            404)
        self.assertEqual(
            self.client.patch(f'/api/sites/{self.alice_site_id}', json={'name': 'x'},
                              headers=_auth(self.token_b)).status_code,
            404)
        self.assertEqual(
            self.client.delete(f'/api/sites/{self.alice_site_id}', headers=_auth(self.token_b)).status_code,
            404)

    def test_bob_cannot_reach_alice_keys(self):
        self.assertEqual(
            self.client.get(f'/api/sites/{self.alice_site_id}/keys', headers=_auth(self.token_b)).status_code,
            404)
        self.assertEqual(
            self.client.post(f'/api/keys/{self.alice_key_id}/revoke', headers=_auth(self.token_b)).status_code,
            404)
        self.assertEqual(
            self.client.post(f'/api/keys/{self.alice_key_id}/rotate', headers=_auth(self.token_b)).status_code,
            404)

    def test_bob_cannot_reach_alice_scan_or_alert(self):
        self.assertEqual(
            self.client.get(f'/api/scans/{self.alice_scan_id}', headers=_auth(self.token_b)).status_code,
            404)
        self.assertEqual(
            self.client.post(f'/api/alerts/{self.alice_alert_id}/read', headers=_auth(self.token_b)).status_code,
            404)

    def test_bob_cannot_reach_alice_policy(self):
        self.assertEqual(
            self.client.get(f'/api/policies/{self.alice_policy_id}', headers=_auth(self.token_b)).status_code,
            404)
        self.assertEqual(
            self.client.patch(f'/api/policies/{self.alice_policy_id}', json={'name': 'x'},
                              headers=_auth(self.token_b)).status_code,
            404)
        self.assertEqual(
            self.client.delete(f'/api/policies/{self.alice_policy_id}', headers=_auth(self.token_b)).status_code,
            404)
        self.assertEqual(
            self.client.patch(f'/api/policies/rules/{self.alice_policy_rule_id}', json={'label': 'x'},
                              headers=_auth(self.token_b)).status_code,
            404)

    def test_bob_cannot_reach_alice_ratelimit_rule(self):
        self.assertEqual(
            self.client.get(f'/api/ratelimit/rules/{self.alice_rl_rule_id}', headers=_auth(self.token_b)).status_code,
            404)
        self.assertEqual(
            self.client.delete(f'/api/ratelimit/rules/{self.alice_rl_rule_id}', headers=_auth(self.token_b)).status_code,
            404)

    def test_bob_cannot_reach_alice_acl_rule(self):
        self.assertEqual(
            self.client.get(f'/api/acl/rules/{self.alice_acl_rule_id}', headers=_auth(self.token_b)).status_code,
            404)
        self.assertEqual(
            self.client.patch(f'/api/acl/rules/{self.alice_acl_rule_id}', json={'value': '/y'},
                              headers=_auth(self.token_b)).status_code,
            404)
        self.assertEqual(
            self.client.delete(f'/api/acl/rules/{self.alice_acl_rule_id}', headers=_auth(self.token_b)).status_code,
            404)

    def test_bob_cannot_reach_alice_notification_channel(self):
        self.assertEqual(
            self.client.get(f'/api/notifications/channels/{self.alice_channel_id}', headers=_auth(self.token_b)).status_code,
            404)
        self.assertEqual(
            self.client.delete(f'/api/notifications/channels/{self.alice_channel_id}', headers=_auth(self.token_b)).status_code,
            404)

    def test_bob_cannot_narrow_a_scope_to_alice_site(self):
        # Passing another account's site_id as a filter must not leak its data.
        for path in ('/api/policies', '/api/ratelimit/rules', '/api/acl/rules'):
            with self.subTest(path=path):
                resp = self.client.get(f'{path}?site_id={self.alice_site_id}', headers=_auth(self.token_b))
                self.assertEqual(resp.status_code, 404)

    def test_bob_cannot_create_resources_under_alice_site(self):
        cases = (
            ('/api/policies', {'name': 'x', 'site_id': self.alice_site_id}),
            ('/api/ratelimit/rules', {'name': 'x', 'limit_count': 5, 'window_seconds': 60,
                                      'site_id': self.alice_site_id}),
            ('/api/acl/rules', {'list_type': 'block', 'match_type': 'path', 'value': '/x',
                                'site_id': self.alice_site_id}),
        )
        for path, payload in cases:
            with self.subTest(path=path):
                resp = self.client.post(path, json=payload, headers=_auth(self.token_b))
                self.assertEqual(resp.status_code, 404)

    def test_owner_can_still_reach_its_own_resources(self):
        # Positive control mirroring the cross-account checks above.
        self.assertEqual(
            self.client.get(f'/api/sites/{self.alice_site_id}', headers=_auth(self.token_a)).status_code,
            200)
        self.assertEqual(
            self.client.get(f'/api/policies/{self.alice_policy_id}', headers=_auth(self.token_a)).status_code,
            200)
        self.assertEqual(
            self.client.get(f'/api/acl/rules/{self.alice_acl_rule_id}', headers=_auth(self.token_a)).status_code,
            200)


if __name__ == '__main__':
    unittest.main()
