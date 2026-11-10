import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app
from modules.database import db, SecurityEvent, Policy, PolicyRule


def _register(client, username, email, password='Password123'):
    resp = client.post('/api/auth/register', json={
        'username': username, 'email': email, 'password': password
    })
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()['token']


def _auth(token):
    return {'Authorization': f'Bearer {token}'}


class PolicyTests(unittest.TestCase):
    """CRUD, validation, priority, modes, isolation and the evaluate endpoint."""

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
    # Each test builds its own site so policies from other tests can never
    # interfere with evaluation on the same site.
    def _new_site(self, token, name='site'):
        resp = self.client.post('/api/sites', headers=_auth(token), json={'name': name})
        self.assertEqual(resp.status_code, 201, resp.get_json())
        return resp.get_json()['site']

    def _make_policy(self, token, site_id, name='p', mode='monitor'):
        resp = self.client.post('/api/policies', headers=_auth(token),
                                json={'site_id': site_id, 'name': name, 'mode': mode})
        self.assertEqual(resp.status_code, 201, resp.get_json())
        return resp.get_json()['policy']

    def _make_rule(self, token, policy_id, pattern='/login', action='block',
                   match_type='prefix', priority=100):
        resp = self.client.post(f"/api/policies/{policy_id}/rules", headers=_auth(token), json={
            'label': f'rule {pattern}', 'match_type': match_type,
            'path_pattern': pattern, 'action': action, 'priority': priority
        })
        self.assertEqual(resp.status_code, 201, resp.get_json())
        return resp.get_json()['rule']

    def _evaluate(self, token, site_id, path):
        resp = self.client.post('/api/policies/evaluate', headers=_auth(token),
                                json={'site_id': site_id, 'path': path})
        self.assertEqual(resp.status_code, 200, resp.get_json())
        return resp.get_json()['result']

    def _event_count(self):
        with self.app.app_context():
            return SecurityEvent.query.filter_by(event_type='policy_evaluation').count()

    # -- auth / validation ----------------------------------------------------
    def test_endpoints_require_auth(self):
        self.assertEqual(self.client.get('/api/policies').status_code, 401)
        self.assertEqual(self.client.post('/api/policies', json={}).status_code, 401)
        self.assertEqual(self.client.post('/api/policies/evaluate',
                                          json={'path': '/x'}).status_code, 401)

    def test_create_policy_defaults_to_monitor(self):
        site = self._new_site(self.token_a)
        policy = self._make_policy(self.token_a, site['id'], 'defaults')
        self.assertEqual(policy['mode'], 'monitor')
        self.assertTrue(policy['is_enabled'])

    def test_create_policy_rejects_foreign_site(self):
        site = self._new_site(self.token_a)
        # Bob may never create a policy on Alice's site.
        resp = self.client.post('/api/policies', headers=_auth(self.token_b),
                                json={'site_id': site['id'], 'name': 'leak'})
        self.assertEqual(resp.status_code, 404)

    def test_create_policy_requires_site_id(self):
        resp = self.client.post('/api/policies', headers=_auth(self.token_a),
                                json={'name': 'no-site'})
        self.assertEqual(resp.status_code, 400)

    def test_invalid_mode_rejected(self):
        site = self._new_site(self.token_a)
        resp = self.client.post('/api/policies', headers=_auth(self.token_a),
                                json={'site_id': site['id'], 'name': 'x', 'mode': 'destroy'})
        self.assertEqual(resp.status_code, 400)

    def test_rule_validation(self):
        site = self._new_site(self.token_a)
        policy = self._make_policy(self.token_a, site['id'], 'v')
        bad_type = self.client.post(f"/api/policies/{policy['id']}/rules", headers=_auth(self.token_a),
                                    json={'label': 'r', 'match_type': 'regex', 'path_pattern': '/x'})
        self.assertEqual(bad_type.status_code, 400)
        bad_action = self.client.post(f"/api/policies/{policy['id']}/rules", headers=_auth(self.token_a),
                                      json={'label': 'r', 'path_pattern': '/x', 'action': 'nuke'})
        self.assertEqual(bad_action.status_code, 400)
        missing = self.client.post(f"/api/policies/{policy['id']}/rules", headers=_auth(self.token_a),
                                   json={'label': 'r'})
        self.assertEqual(missing.status_code, 400)

    # -- evaluation semantics -------------------------------------------------
    def test_monitor_mode_downgrades_block(self):
        site = self._new_site(self.token_a)
        policy = self._make_policy(self.token_a, site['id'], 'mon', mode='monitor')
        self._make_rule(self.token_a, policy['id'], '/login', action='block')
        result = self._evaluate(self.token_a, site['id'], '/login')
        self.assertTrue(result['matched'])
        self.assertEqual(result['decision'], 'block')          # detection verdict
        self.assertEqual(result['action_taken'], 'monitored')  # enforced action
        self.assertEqual(result['effective'], 'monitor')
        self.assertEqual(result['reason'], 'policy_monitor_mode')

    def test_block_mode_enforces_block(self):
        site = self._new_site(self.token_a)
        policy = self._make_policy(self.token_a, site['id'], 'blk', mode='block')
        self._make_rule(self.token_a, policy['id'], '/checkout', action='block')
        result = self._evaluate(self.token_a, site['id'], '/checkout/pay')
        self.assertEqual(result['decision'], 'block')
        self.assertEqual(result['action_taken'], 'blocked')
        self.assertEqual(result['effective'], 'block')

    def test_priority_picks_highest(self):
        site = self._new_site(self.token_a)
        policy = self._make_policy(self.token_a, site['id'], 'prio')
        self._make_rule(self.token_a, policy['id'], '/admin', action='monitor', priority=10)
        high = self._make_rule(self.token_a, policy['id'], '/admin', action='allow', priority=900)
        result = self._evaluate(self.token_a, site['id'], '/admin/x')
        self.assertEqual(result['rule_id'], high['id'])
        self.assertEqual(result['effective'], 'allow')

    def test_match_types(self):
        site = self._new_site(self.token_a)
        policy = self._make_policy(self.token_a, site['id'], 'mt')
        self._make_rule(self.token_a, policy['id'], '/exact', action='block',
                        match_type='exact', priority=500)
        self.assertTrue(self._evaluate(self.token_a, site['id'], '/exact')['matched'])
        self.assertFalse(self._evaluate(self.token_a, site['id'], '/exact/sub')['matched'])

        self._make_rule(self.token_a, policy['id'], 'token=', action='monitor',
                        match_type='contains', priority=400)
        self.assertTrue(self._evaluate(self.token_a, site['id'], '/x?token=abc')['matched'])

    def test_no_match_allows_and_records_nothing(self):
        site = self._new_site(self.token_a)
        before = self._event_count()
        result = self._evaluate(self.token_a, site['id'], '/totally-unmatched')
        self.assertFalse(result['matched'])
        self.assertEqual(result['effective'], 'allow')
        self.assertEqual(self._event_count(), before)

    def test_match_records_event_with_rule_id(self):
        site = self._new_site(self.token_a)
        policy = self._make_policy(self.token_a, site['id'], 'evt')
        rule = self._make_rule(self.token_a, policy['id'], '/log-me', action='monitor', priority=700)
        self._evaluate(self.token_a, site['id'], '/log-me')
        with self.app.app_context():
            event = SecurityEvent.query.filter_by(event_type='policy_evaluation').order_by(
                SecurityEvent.id.desc()).first()
            self.assertIsNotNone(event)
            self.assertEqual(event.rule_id, str(rule['id']))
            self.assertEqual(event.site_id, site['id'])

    def test_evaluate_via_api_key(self):
        site = self._new_site(self.token_a)
        policy = self._make_policy(self.token_a, site['id'], 'apikey')
        self._make_rule(self.token_a, policy['id'], '/sdk-path', action='block')
        key = self.client.post(f"/api/sites/{site['id']}/keys",
                               headers=_auth(self.token_a), json={'name': 'sdk'}).get_json()['key']
        resp = self.client.post('/api/policies/evaluate', headers={'X-API-Key': key},
                                json={'path': '/sdk-path/x'})
        self.assertEqual(resp.status_code, 200, resp.get_json())
        result = resp.get_json()['result']
        self.assertTrue(result['matched'])
        self.assertEqual(result['site_id'], site['id'])

    def test_disabled_policy_is_ignored(self):
        site = self._new_site(self.token_a)
        policy = self._make_policy(self.token_a, site['id'], 'disabled')
        self._make_rule(self.token_a, policy['id'], '/off', action='block')
        self.client.patch(f"/api/policies/{policy['id']}", headers=_auth(self.token_a),
                          json={'is_enabled': False})
        self.assertFalse(self._evaluate(self.token_a, site['id'], '/off')['matched'])

    # -- isolation + cascade ---------------------------------------------------
    def test_isolation_between_accounts(self):
        site = self._new_site(self.token_a)
        policy = self._make_policy(self.token_a, site['id'], 'private')
        rule = self._make_rule(self.token_a, policy['id'], '/p', action='monitor')
        self.assertEqual(self.client.get(f"/api/policies/{policy['id']}", headers=_auth(self.token_b)).status_code, 404)
        self.assertEqual(self.client.patch(f"/api/policies/{policy['id']}", headers=_auth(self.token_b),
                                           json={'name': 'hijack'}).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/policies/{policy['id']}", headers=_auth(self.token_b)).status_code, 404)
        self.assertEqual(self.client.patch(f"/api/policies/rules/{rule['id']}", headers=_auth(self.token_b),
                                           json={'action': 'allow'}).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/policies/rules/{rule['id']}", headers=_auth(self.token_b)).status_code, 404)

    def test_list_is_scoped_and_filterable(self):
        site = self._new_site(self.token_a)
        policy = self._make_policy(self.token_a, site['id'], 'scoped')
        listing = self.client.get('/api/policies', headers=_auth(self.token_a)).get_json()
        self.assertTrue(any(p['id'] == policy['id'] for p in listing['policies']))
        # Bob's list must never contain Alice's policy.
        bob_listing = self.client.get('/api/policies', headers=_auth(self.token_b)).get_json()
        self.assertFalse(any(p['id'] == policy['id'] for p in bob_listing['policies']))
        # Filtering by a foreign site must 404.
        self.assertEqual(self.client.get(f"/api/policies?site_id={site['id']}",
                                         headers=_auth(self.token_b)).status_code, 404)

    def test_delete_policy_cascades_rules(self):
        site = self._new_site(self.token_a)
        policy = self._make_policy(self.token_a, site['id'], 'cascade')
        rule = self._make_rule(self.token_a, policy['id'], '/c', action='monitor')
        self.assertEqual(self.client.delete(f"/api/policies/{policy['id']}",
                                            headers=_auth(self.token_a)).status_code, 200)
        with self.app.app_context():
            self.assertIsNone(Policy.query.get(policy['id']))
            self.assertIsNone(PolicyRule.query.get(rule['id']))

    def test_site_id_is_immutable(self):
        site_a = self._new_site(self.token_a, 'imm-a')
        site_b = self._new_site(self.token_a, 'imm-b')
        policy = self._make_policy(self.token_a, site_a['id'], 'immutable')
        # Attempting to move the policy to another site is silently ignored.
        self.client.patch(f"/api/policies/{policy['id']}", headers=_auth(self.token_a),
                          json={'site_id': site_b['id'], 'name': 'renamed'})
        with self.app.app_context():
            self.assertEqual(Policy.query.get(policy['id']).site_id, site_a['id'])


if __name__ == '__main__':
    unittest.main()
