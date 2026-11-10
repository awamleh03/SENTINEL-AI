import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app
from modules.database import db, SecurityEvent, RateLimitRule, RateLimitCounter


def _register(client, username, email, password='Password123'):
    resp = client.post('/api/auth/register', json={
        'username': username, 'email': email, 'password': password
    })
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()['token']


def _auth(token):
    return {'Authorization': f'Bearer {token}'}


class RateLimitTests(unittest.TestCase):
    """Rule CRUD, window counting, scopes, modes and per-site isolation."""

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

    # -- helpers --------------------------------------------------------------
    def _new_site(self, token, name='site'):
        resp = self.client.post('/api/sites', headers=_auth(token), json={'name': name})
        self.assertEqual(resp.status_code, 201, resp.get_json())
        return resp.get_json()['site']

    def _make_rule(self, token, site_id, name='r', scope='ip', limit=2, window=60,
                   action='monitor', priority=100):
        resp = self.client.post('/api/ratelimit/rules', headers=_auth(token), json={
            'site_id': site_id, 'name': name, 'scope': scope, 'limit_count': limit,
            'window_seconds': window, 'action': action, 'priority': priority
        })
        self.assertEqual(resp.status_code, 201, resp.get_json())
        return resp.get_json()['rule']

    def _check(self, token, site_id, path='/x', remote=None, forwarded=None):
        kwargs = {}
        if remote or forwarded:
            env = {}
            if remote:
                env['REMOTE_ADDR'] = remote
            if forwarded:
                env['HTTP_X_FORWARDED_FOR'] = forwarded
            kwargs['environ_base'] = env
        resp = self.client.post('/api/ratelimit/check', headers=_auth(token),
                                json={'site_id': site_id, 'path': path}, **kwargs)
        self.assertEqual(resp.status_code, 200, resp.get_json())
        return resp.get_json()['result']

    # -- auth / validation ----------------------------------------------------
    def test_endpoints_require_auth(self):
        self.assertEqual(self.client.get('/api/ratelimit/rules').status_code, 401)
        self.assertEqual(self.client.post('/api/ratelimit/rules', json={}).status_code, 401)
        self.assertEqual(self.client.post('/api/ratelimit/check', json={'path': '/x'}).status_code, 401)

    def test_create_rule_defaults(self):
        site = self._new_site(self.token_a)
        rule = self._make_rule(self.token_a, site['id'], 'defaults', scope='ip', limit=5, window=30)
        self.assertEqual(rule['scope'], 'ip')
        self.assertEqual(rule['limit_count'], 5)
        self.assertEqual(rule['window_seconds'], 30)
        self.assertEqual(rule['action'], 'monitor')
        self.assertTrue(rule['is_enabled'])

    def test_create_rule_rejects_foreign_site(self):
        site = self._new_site(self.token_a)
        resp = self.client.post('/api/ratelimit/rules', headers=_auth(self.token_b),
                                json={'site_id': site['id'], 'name': 'leak',
                                      'limit_count': 1, 'window_seconds': 60})
        self.assertEqual(resp.status_code, 404)

    def test_create_rule_requires_site_id(self):
        resp = self.client.post('/api/ratelimit/rules', headers=_auth(self.token_a),
                                json={'name': 'x', 'limit_count': 1, 'window_seconds': 60})
        self.assertEqual(resp.status_code, 400)

    def test_invalid_scope_and_limits_rejected(self):
        site = self._new_site(self.token_a)
        bad_scope = self.client.post('/api/ratelimit/rules', headers=_auth(self.token_a),
                                     json={'site_id': site['id'], 'name': 'x', 'scope': 'cookie',
                                           'limit_count': 1, 'window_seconds': 60})
        self.assertEqual(bad_scope.status_code, 400)
        bad_limit = self.client.post('/api/ratelimit/rules', headers=_auth(self.token_a),
                                     json={'site_id': site['id'], 'name': 'x',
                                           'limit_count': 0, 'window_seconds': 60})
        self.assertEqual(bad_limit.status_code, 400)
        bad_window = self.client.post('/api/ratelimit/rules', headers=_auth(self.token_a),
                                      json={'site_id': site['id'], 'name': 'x',
                                            'limit_count': 1, 'window_seconds': 0})
        self.assertEqual(bad_window.status_code, 400)

    # -- counting semantics ---------------------------------------------------
    def test_under_limit_allows(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], 'under', limit=3, window=60)
        result = self._check(self.token_a, site['id'])
        self.assertTrue(result['allowed'])
        self.assertFalse(result['limited'])
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['remaining'], 2)
        self.assertEqual(result['action_taken'], 'allowed')

    def test_no_rule_allows(self):
        site = self._new_site(self.token_a)
        result = self._check(self.token_a, site['id'])
        self.assertTrue(result['allowed'])
        self.assertFalse(result['limited'])
        self.assertEqual(result['reason'], 'no_matching_rule')

    def test_monitor_mode_records_but_allows(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], 'mon', limit=1, window=60, action='monitor')
        self.assertTrue(self._check(self.token_a, site['id'])['allowed'])
        second = self._check(self.token_a, site['id'])
        self.assertTrue(second['limited'])
        self.assertTrue(second['allowed'])            # monitor never enforces
        self.assertEqual(second['decision'], 'block')  # detection verdict
        self.assertEqual(second['action_taken'], 'monitored')
        self.assertGreaterEqual(second['retry_after'], 1)
        with self.app.app_context():
            event = SecurityEvent.query.filter_by(event_type='rate_limit').order_by(
                SecurityEvent.id.desc()).first()
            self.assertIsNotNone(event)
            self.assertEqual(event.site_id, site['id'])
            self.assertEqual(event.action_taken, 'monitored')

    def test_block_mode_denies(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], 'blk', limit=1, window=60, action='block')
        self.assertTrue(self._check(self.token_a, site['id'])['allowed'])
        second = self._check(self.token_a, site['id'])
        self.assertTrue(second['limited'])
        self.assertFalse(second['allowed'])
        self.assertEqual(second['action_taken'], 'blocked')
        self.assertEqual(second['reason'], 'rule_block')

    def test_window_resets(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], 'reset', limit=1, window=1, action='block')
        self.assertTrue(self._check(self.token_a, site['id'])['allowed'])
        self.assertFalse(self._check(self.token_a, site['id'])['allowed'])
        time.sleep(1.1)
        after = self._check(self.token_a, site['id'])
        self.assertFalse(after['limited'])
        self.assertTrue(after['allowed'])
        self.assertEqual(after['count'], 1)

    def test_rules_are_isolated_between_sites(self):
        site_a = self._new_site(self.token_a, 'a')
        site_b = self._new_site(self.token_a, 'b')
        self._make_rule(self.token_a, site_a['id'], 'a', limit=1, window=60, action='block')
        # Site B has no rule, so it is never limited by site A's counter.
        self.assertTrue(self._check(self.token_a, site_a['id'])['allowed'])
        self.assertFalse(self._check(self.token_a, site_a['id'])['allowed'])
        b_result = self._check(self.token_a, site_b['id'])
        self.assertTrue(b_result['allowed'])
        self.assertEqual(b_result['reason'], 'no_matching_rule')

    def test_priority_picks_highest(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], 'low', limit=1, window=60,
                        action='block', priority=10)
        high = self._make_rule(self.token_a, site['id'], 'high', limit=100, window=60,
                               action='block', priority=900)
        result = self._check(self.token_a, site['id'])
        self.assertEqual(result['rule_id'], high['id'])
        self.assertEqual(result['limit'], 100)

    def test_disabled_rule_is_ignored(self):
        site = self._new_site(self.token_a)
        rule = self._make_rule(self.token_a, site['id'], 'off', limit=1, window=60, action='block')
        self.client.patch(f"/api/ratelimit/rules/{rule['id']}", headers=_auth(self.token_a),
                          json={'is_enabled': False})
        result = self._check(self.token_a, site['id'])
        self.assertEqual(result['reason'], 'no_matching_rule')

    # -- scope: API key -------------------------------------------------------
    def test_api_key_scope(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], 'key', scope='api_key', limit=1, window=60)
        key = self.client.post(f"/api/sites/{site['id']}/keys",
                               headers=_auth(self.token_a), json={'name': 'sdk'}).get_json()['key']
        h = {'X-API-Key': key}
        first = self.client.post('/api/ratelimit/check', headers=h, json={'path': '/sdk'})
        self.assertEqual(first.status_code, 200, first.get_json())
        self.assertTrue(first.get_json()['result']['allowed'])
        second = self.client.post('/api/ratelimit/check', headers=h, json={'path': '/sdk'})
        self.assertTrue(second.get_json()['result']['limited'])
        self.assertEqual(second.get_json()['result']['scope'], 'api_key')

    # -- trusted proxy IP handling -------------------------------------------
    def test_untrusted_peer_ignores_forwarded_header(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], 'ip', limit=1, window=60, action='block')
        # Different X-Forwarded-For values, but an untrusted peer: both requests
        # collapse onto remote_addr 1.2.3.4 -> the second is blocked.
        r1 = self._check(self.token_a, site['id'], remote='1.2.3.4', forwarded='9.9.9.9')
        r2 = self._check(self.token_a, site['id'], remote='1.2.3.4', forwarded='8.8.8.8')
        self.assertFalse(r1['limited'])
        self.assertTrue(r2['limited'])

    def test_trusted_peer_honors_forwarded_header(self):
        old = self.app.config.get('TRUSTED_PROXIES')
        old_hops = self.app.config.get('TRUSTED_PROXY_HOPS')
        self.app.config['TRUSTED_PROXIES'] = ['1.2.3.4']
        self.app.config['TRUSTED_PROXY_HOPS'] = 1
        try:
            site = self._new_site(self.token_a)
            self._make_rule(self.token_a, site['id'], 'ip', limit=1, window=60, action='block')
            # Trusted peer: the client is taken from X-Forwarded-For, so two
            # distinct clients are counted independently (neither is blocked).
            r1 = self._check(self.token_a, site['id'], remote='1.2.3.4', forwarded='9.9.9.9')
            r2 = self._check(self.token_a, site['id'], remote='1.2.3.4', forwarded='8.8.8.8')
            self.assertFalse(r1['limited'])
            self.assertFalse(r2['limited'])
        finally:
            self.app.config['TRUSTED_PROXIES'] = old
            self.app.config['TRUSTED_PROXY_HOPS'] = old_hops

    # -- isolation + lifecycle ------------------------------------------------
    def test_isolation_between_accounts(self):
        site = self._new_site(self.token_a)
        rule = self._make_rule(self.token_a, site['id'], 'private', limit=1, window=60)
        self.assertEqual(self.client.get(f"/api/ratelimit/rules/{rule['id']}",
                                         headers=_auth(self.token_b)).status_code, 404)
        self.assertEqual(self.client.patch(f"/api/ratelimit/rules/{rule['id']}", headers=_auth(self.token_b),
                                           json={'limit_count': 999}).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/ratelimit/rules/{rule['id']}",
                                            headers=_auth(self.token_b)).status_code, 404)
        bob_listing = self.client.get('/api/ratelimit/rules', headers=_auth(self.token_b)).get_json()
        self.assertFalse(any(r['id'] == rule['id'] for r in bob_listing['rules']))

    def test_list_is_filterable_and_scoped(self):
        site = self._new_site(self.token_a)
        rule = self._make_rule(self.token_a, site['id'], 'scoped', limit=2, window=60)
        listing = self.client.get(f"/api/ratelimit/rules?site_id={site['id']}",
                                  headers=_auth(self.token_a)).get_json()
        self.assertTrue(any(r['id'] == rule['id'] for r in listing['rules']))
        # Filtering by a foreign site must 404.
        self.assertEqual(self.client.get(f"/api/ratelimit/rules?site_id={site['id']}",
                                         headers=_auth(self.token_b)).status_code, 404)

    def test_delete_rule(self):
        site = self._new_site(self.token_a)
        rule = self._make_rule(self.token_a, site['id'], 'del', limit=1, window=60)
        self.assertEqual(self.client.delete(f"/api/ratelimit/rules/{rule['id']}",
                                            headers=_auth(self.token_a)).status_code, 200)
        with self.app.app_context():
            self.assertIsNone(RateLimitRule.query.get(rule['id']))

    def test_site_id_is_immutable(self):
        site_a = self._new_site(self.token_a, 'imm-a')
        site_b = self._new_site(self.token_a, 'imm-b')
        rule = self._make_rule(self.token_a, site_a['id'], 'immutable', limit=1, window=60)
        self.client.patch(f"/api/ratelimit/rules/{rule['id']}", headers=_auth(self.token_a),
                          json={'site_id': site_b['id'], 'limit_count': 42})
        with self.app.app_context():
            updated = RateLimitRule.query.get(rule['id'])
            self.assertEqual(updated.site_id, site_a['id'])
            self.assertEqual(updated.limit_count, 42)

    def test_counters_store_no_raw_identity(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], 'hash', limit=5, window=60)
        self._check(self.token_a, site['id'], remote='5.6.7.8')
        with self.app.app_context():
            counter = RateLimitCounter.query.filter_by(site_id=site['id']).first()
            self.assertIsNotNone(counter)
            # The stored key is a 64-char SHA-256 digest, never the raw IP.
            self.assertEqual(len(counter.key_hash), 64)
            self.assertNotIn('5.6.7.8', counter.key_hash)


if __name__ == '__main__':
    unittest.main()
