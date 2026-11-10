import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app
from modules.database import db


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


class TenancyTests(unittest.TestCase):
    """Sites + API key lifecycle for a single account."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app('test')
        cls.client = cls.app.test_client()
        with cls.app.app_context():
            db.create_all()
            cls.token = _register(cls.client, 'alice', 'alice@example.com')

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.drop_all()

    def _create_site(self, name='Shop', domain='shop.example.com'):
        resp = self.client.post('/api/sites', json={'name': name, 'domain': domain},
                                headers=_auth(self.token))
        self.assertEqual(resp.status_code, 201)
        return resp.get_json()['site']

    def test_create_and_list_site(self):
        site = self._create_site(name='Listed')
        resp = self.client.get('/api/sites', headers=_auth(self.token))
        self.assertEqual(resp.status_code, 200)
        ids = [s['id'] for s in resp.get_json()['sites']]
        self.assertIn(site['id'], ids)

    def test_create_site_requires_name(self):
        resp = self.client.post('/api/sites', json={'domain': 'x.com'}, headers=_auth(self.token))
        self.assertEqual(resp.status_code, 400)

    def test_create_site_requires_auth(self):
        resp = self.client.post('/api/sites', json={'name': 'NoAuth'})
        self.assertEqual(resp.status_code, 401)

    def test_update_site(self):
        site = self._create_site(name='Old')
        resp = self.client.patch(f"/api/sites/{site['id']}", json={'name': 'New'},
                                 headers=_auth(self.token))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['site']['name'], 'New')

    def test_delete_site(self):
        site = self._create_site(name='Doomed')
        resp = self.client.delete(f"/api/sites/{site['id']}", headers=_auth(self.token))
        self.assertEqual(resp.status_code, 200)
        resp2 = self.client.get(f"/api/sites/{site['id']}", headers=_auth(self.token))
        self.assertEqual(resp2.status_code, 404)

    def test_key_creation_returns_secret_once_only(self):
        site = self._create_site(name='Keys')
        resp = self.client.post(f"/api/sites/{site['id']}/keys", json={'name': 'prod'},
                                headers=_auth(self.token))
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertIn('key', data)
        self.assertTrue(data['key'].startswith('snt_'))
        # secret is never part of the persisted representation
        self.assertNotIn('key_hash', data['api_key'])
        self.assertNotIn('key', data['api_key'])

    def test_list_keys_never_exposes_secret(self):
        site = self._create_site(name='KeysList')
        self.client.post(f"/api/sites/{site['id']}/keys", json={'name': 'prod'},
                         headers=_auth(self.token))
        resp = self.client.get(f"/api/sites/{site['id']}/keys", headers=_auth(self.token))
        self.assertEqual(resp.status_code, 200)
        keys = resp.get_json()['keys']
        self.assertGreaterEqual(len(keys), 1)
        for k in keys:
            self.assertNotIn('key_hash', k)
            self.assertTrue(k['key_prefix'].startswith('snt_'))

    def test_apikey_info_valid(self):
        site = self._create_site(name='Info')
        raw = self.client.post(f"/api/sites/{site['id']}/keys", json={'name': 'prod'},
                               headers=_auth(self.token)).get_json()['key']
        resp = self.client.get('/api/apikey-info', headers={'X-API-Key': raw})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body['valid'])
        self.assertEqual(body['site']['id'], site['id'])

    def test_revoke_key(self):
        site = self._create_site(name='Revoke')
        created = self.client.post(f"/api/sites/{site['id']}/keys", json={'name': 'prod'},
                                   headers=_auth(self.token)).get_json()
        raw, key_id = created['key'], created['api_key']['id']

        resp = self.client.post(f'/api/keys/{key_id}/revoke', headers=_auth(self.token))
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.get_json()['api_key']['is_active'])

        # revoked key must no longer authenticate
        info = self.client.get('/api/apikey-info', headers={'X-API-Key': raw})
        self.assertEqual(info.status_code, 401)

    def test_rotate_key(self):
        site = self._create_site(name='Rotate')
        created = self.client.post(f"/api/sites/{site['id']}/keys", json={'name': 'prod'},
                                   headers=_auth(self.token)).get_json()
        old_raw, old_id = created['key'], created['api_key']['id']

        resp = self.client.post(f'/api/keys/{old_id}/rotate', headers=_auth(self.token))
        self.assertEqual(resp.status_code, 201)
        body = resp.get_json()
        new_raw = body['key']
        self.assertEqual(body['revoked_key_id'], old_id)
        self.assertEqual(body['api_key']['rotated_from_id'], old_id)

        # old key revoked, new key valid
        self.assertEqual(self.client.get('/api/apikey-info', headers={'X-API-Key': old_raw}).status_code, 401)
        self.assertEqual(self.client.get('/api/apikey-info', headers={'X-API-Key': new_raw}).status_code, 200)


if __name__ == '__main__':
    unittest.main()
