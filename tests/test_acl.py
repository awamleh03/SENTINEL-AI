import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app
from modules.database import db, SecurityEvent, AccessListRule


def _register(client, username, email, password='Password123'):
    resp = client.post('/api/auth/register', json={
        'username': username, 'email': email, 'password': password
    })
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()['token']


def _auth(token):
    return {'Authorization': f'Bearer {token}'}


class AccessListTests(unittest.TestCase):
    """Rule CRUD, matching semantics, precedence, scopes and isolation."""

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

    def _make_rule(self, token, site_id, list_type='block', match_type='ip', value='1.2.3.4',
                   scope=None, mode='monitor', priority=100, description=None, is_active=True):
        payload = {
            'site_id': site_id, 'list_type': list_type, 'match_type': match_type,
            'value': value, 'mode': mode, 'priority': priority, 'is_active': is_active,
        }
        if scope is not None:
            payload['scope'] = scope
        if description is not None:
            payload['description'] = description
        resp = self.client.post('/api/acl/rules', headers=_auth(token), json=payload)
        self.assertEqual(resp.status_code, 201, resp.get_json())
        return resp.get_json()['rule']

    def _check(self, token, site_id, ip=None, path=None):
        body = {'site_id': site_id}
        if ip is not None:
            body['ip'] = ip
        if path is not None:
            body['path'] = path
        resp = self.client.post('/api/acl/check', headers=_auth(token), json=body)
        self.assertEqual(resp.status_code, 200, resp.get_json())
        return resp.get_json()['result']

    # -- auth / validation ----------------------------------------------------
    def test_endpoints_require_auth(self):
        self.assertEqual(self.client.get('/api/acl/rules').status_code, 401)
        self.assertEqual(self.client.post('/api/acl/rules', json={}).status_code, 401)
        self.assertEqual(self.client.post('/api/acl/check', json={'site_id': 1}).status_code, 401)

    def test_create_rule_defaults(self):
        site = self._new_site(self.token_a)
        rule = self._make_rule(self.token_a, site['id'], list_type='block',
                               match_type='ip', value='10.0.0.1')
        self.assertEqual(rule['list_type'], 'block')
        self.assertEqual(rule['match_type'], 'ip')
        self.assertEqual(rule['mode'], 'monitor')      # never blocks by default
        self.assertEqual(rule['scope'], [])            # exempts nothing by default
        self.assertEqual(rule['priority'], 100)
        self.assertTrue(rule['is_active'])
        self.assertEqual(rule['created_by_user_id'], rule['user_id'])

    def test_create_rule_rejects_foreign_site(self):
        site = self._new_site(self.token_a)
        resp = self.client.post('/api/acl/rules', headers=_auth(self.token_b), json={
            'site_id': site['id'], 'list_type': 'block', 'match_type': 'ip', 'value': '1.2.3.4'
        })
        self.assertEqual(resp.status_code, 404)

    def test_create_rule_requires_site_id(self):
        resp = self.client.post('/api/acl/rules', headers=_auth(self.token_a), json={
            'list_type': 'block', 'match_type': 'ip', 'value': '1.2.3.4'
        })
        self.assertEqual(resp.status_code, 400)

    def test_invalid_fields_rejected(self):
        site = self._new_site(self.token_a)
        bad_list = self.client.post('/api/acl/rules', headers=_auth(self.token_a), json={
            'site_id': site['id'], 'list_type': 'deny', 'match_type': 'ip', 'value': '1.2.3.4'
        })
        self.assertEqual(bad_list.status_code, 400)
        bad_match = self.client.post('/api/acl/rules', headers=_auth(self.token_a), json={
            'site_id': site['id'], 'list_type': 'block', 'match_type': 'host', 'value': 'x'
        })
        self.assertEqual(bad_match.status_code, 400)
        bad_ip = self.client.post('/api/acl/rules', headers=_auth(self.token_a), json={
            'site_id': site['id'], 'list_type': 'block', 'match_type': 'ip', 'value': 'not-an-ip'
        })
        self.assertEqual(bad_ip.status_code, 400)
        bad_cidr = self.client.post('/api/acl/rules', headers=_auth(self.token_a), json={
            'site_id': site['id'], 'list_type': 'block', 'match_type': 'cidr', 'value': '10.0.0.0/99'
        })
        self.assertEqual(bad_cidr.status_code, 400)

    def test_invalid_scope_rejected(self):
        site = self._new_site(self.token_a)
        resp = self.client.post('/api/acl/rules', headers=_auth(self.token_a), json={
            'site_id': site['id'], 'list_type': 'allow', 'match_type': 'ip',
            'value': '1.2.3.4', 'scope': ['everything']
        })
        self.assertEqual(resp.status_code, 400)

    # -- matching semantics ---------------------------------------------------
    def test_ip_block_enforced_in_block_mode(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], list_type='block', match_type='ip',
                        value='9.9.9.9', mode='block')
        result = self._check(self.token_a, site['id'], ip='9.9.9.9')
        self.assertTrue(result['matched'])
        self.assertEqual(result['decision'], 'block')
        self.assertEqual(result['action_taken'], 'blocked')
        self.assertTrue(result['enforced'])

    def test_block_monitor_mode_is_not_enforced(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], list_type='block', match_type='ip',
                        value='9.9.9.9', mode='monitor')
        result = self._check(self.token_a, site['id'], ip='9.9.9.9')
        self.assertEqual(result['decision'], 'block')       # detection verdict
        self.assertEqual(result['action_taken'], 'monitored')  # not enforced
        self.assertFalse(result['enforced'])

    def test_cidr_match(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], list_type='block', match_type='cidr',
                        value='10.0.0.0/8', mode='block')
        inside = self._check(self.token_a, site['id'], ip='10.5.6.7')
        outside = self._check(self.token_a, site['id'], ip='11.5.6.7')
        self.assertTrue(inside['matched'])
        self.assertFalse(outside['matched'])

    def test_path_prefix_match(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], list_type='allow', match_type='path',
                        value='/checkout', scope=['ratelimit'])
        result = self._check(self.token_a, site['id'], ip='1.2.3.4', path='/checkout/pay')
        self.assertTrue(result['matched'])
        self.assertEqual(result['list_type'], 'allow')

    def test_no_match_allows(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], list_type='block', match_type='ip',
                        value='9.9.9.9', mode='block')
        result = self._check(self.token_a, site['id'], ip='1.1.1.1')
        self.assertFalse(result['matched'])
        self.assertEqual(result['reason'], 'no_matching_rule')
        self.assertEqual(result['action_taken'], 'allowed')

    # -- precedence + scopes --------------------------------------------------
    def test_deny_takes_precedence_over_allow(self):
        site = self._new_site(self.token_a)
        # An allow rule with a very high priority still cannot override a deny.
        self._make_rule(self.token_a, site['id'], list_type='allow', match_type='ip',
                        value='9.9.9.9', scope=['policies'], priority=1000)
        self._make_rule(self.token_a, site['id'], list_type='block', match_type='ip',
                        value='9.9.9.9', mode='block', priority=1)
        result = self._check(self.token_a, site['id'], ip='9.9.9.9')
        self.assertEqual(result['list_type'], 'block')
        self.assertEqual(result['action_taken'], 'blocked')

    def test_allow_returns_only_explicit_scopes(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], list_type='allow', match_type='ip',
                        value='9.9.9.9', scope=['ratelimit', 'botguard'])
        result = self._check(self.token_a, site['id'], ip='9.9.9.9')
        self.assertEqual(result['bypass_scopes'], ['ratelimit', 'botguard'])
        self.assertNotIn('policies', result['bypass_scopes'])

    def test_allow_default_scope_bypasses_nothing(self):
        site = self._new_site(self.token_a)
        rule = self._make_rule(self.token_a, site['id'], list_type='allow', match_type='ip',
                               value='9.9.9.9')
        self.assertEqual(rule['scope'], [])
        result = self._check(self.token_a, site['id'], ip='9.9.9.9')
        self.assertEqual(result['bypass_scopes'], [])

    def test_priority_orders_within_block(self):
        site = self._new_site(self.token_a)
        low = self._make_rule(self.token_a, site['id'], list_type='block', match_type='ip',
                              value='9.9.9.9', mode='monitor', priority=10)
        high = self._make_rule(self.token_a, site['id'], list_type='block', match_type='ip',
                               value='9.9.9.9', mode='block', priority=900)
        result = self._check(self.token_a, site['id'], ip='9.9.9.9')
        self.assertEqual(result['rule_id'], high['id'])
        self.assertTrue(result['enforced'])

    # -- lifecycle + audit ----------------------------------------------------
    def test_site_id_is_immutable(self):
        site_a = self._new_site(self.token_a, 'imm-a')
        site_b = self._new_site(self.token_a, 'imm-b')
        rule = self._make_rule(self.token_a, site_a['id'], list_type='block',
                               match_type='ip', value='9.9.9.9')
        self.client.patch(f"/api/acl/rules/{rule['id']}", headers=_auth(self.token_a),
                          json={'site_id': site_b['id'], 'priority': 42})
        with self.app.app_context():
            updated = AccessListRule.query.get(rule['id'])
            self.assertEqual(updated.site_id, site_a['id'])
            self.assertEqual(updated.priority, 42)

    def test_disabled_rule_is_ignored(self):
        site = self._new_site(self.token_a)
        rule = self._make_rule(self.token_a, site['id'], list_type='block',
                               match_type='ip', value='9.9.9.9', mode='block')
        self.client.patch(f"/api/acl/rules/{rule['id']}", headers=_auth(self.token_a),
                          json={'is_active': False})
        result = self._check(self.token_a, site['id'], ip='9.9.9.9')
        self.assertEqual(result['reason'], 'no_matching_rule')

    def test_changes_are_audited_with_actor(self):
        site = self._new_site(self.token_a)
        rule = self._make_rule(self.token_a, site['id'], list_type='block',
                               match_type='ip', value='9.9.9.9')
        self.client.patch(f"/api/acl/rules/{rule['id']}", headers=_auth(self.token_a),
                          json={'mode': 'block'})
        self.client.delete(f"/api/acl/rules/{rule['id']}", headers=_auth(self.token_a))
        with self.app.app_context():
            events = SecurityEvent.query.filter_by(event_type='acl_changed').order_by(
                SecurityEvent.id.asc()).all()
            actions = [e.decision for e in events]
            self.assertIn('create', actions)
            self.assertIn('update', actions)
            self.assertIn('delete', actions)
            import json
            for e in events:
                details = json.loads(e.details)
                self.assertEqual(details['actor_username'], 'alice')
            # Deleting audits a snapshot of the removed rule.
            del_event = [e for e in events if e.decision == 'delete'][0]
            self.assertIsNotNone(json.loads(del_event.details)['before'])

    def test_block_match_records_event(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], list_type='block', match_type='ip',
                        value='9.9.9.9', mode='block')
        self._check(self.token_a, site['id'], ip='9.9.9.9')
        with self.app.app_context():
            event = SecurityEvent.query.filter_by(event_type='acl_block').order_by(
                SecurityEvent.id.desc()).first()
            self.assertIsNotNone(event)
            self.assertEqual(event.site_id, site['id'])
            self.assertEqual(event.action_taken, 'blocked')

    def test_allow_match_records_no_event(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], list_type='allow', match_type='ip',
                        value='9.9.9.9', scope=['policies'])
        self._check(self.token_a, site['id'], ip='9.9.9.9')
        with self.app.app_context():
            self.assertIsNone(SecurityEvent.query.filter_by(event_type='acl_block').first())

    # -- isolation ------------------------------------------------------------
    def test_isolation_between_accounts(self):
        site = self._new_site(self.token_a)
        rule = self._make_rule(self.token_a, site['id'], list_type='block',
                               match_type='ip', value='9.9.9.9')
        self.assertEqual(self.client.get(f"/api/acl/rules/{rule['id']}",
                                         headers=_auth(self.token_b)).status_code, 404)
        self.assertEqual(self.client.patch(f"/api/acl/rules/{rule['id']}", headers=_auth(self.token_b),
                                           json={'priority': 5}).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/acl/rules/{rule['id']}",
                                            headers=_auth(self.token_b)).status_code, 404)
        listing = self.client.get('/api/acl/rules', headers=_auth(self.token_b)).get_json()
        self.assertFalse(any(r['id'] == rule['id'] for r in listing['rules']))

    def test_rules_are_isolated_between_sites(self):
        site_a = self._new_site(self.token_a, 'a')
        site_b = self._new_site(self.token_a, 'b')
        self._make_rule(self.token_a, site_a['id'], list_type='block',
                        match_type='ip', value='9.9.9.9', mode='block')
        a_result = self._check(self.token_a, site_a['id'], ip='9.9.9.9')
        b_result = self._check(self.token_a, site_b['id'], ip='9.9.9.9')
        self.assertTrue(a_result['matched'])
        self.assertFalse(b_result['matched'])  # site B has no rule

    def test_list_is_filterable(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], list_type='block', match_type='ip', value='9.9.9.9')
        self._make_rule(self.token_a, site['id'], list_type='allow', match_type='ip', value='8.8.8.8')
        only_block = self.client.get(f"/api/acl/rules?site_id={site['id']}&list_type=block",
                                     headers=_auth(self.token_a)).get_json()
        self.assertTrue(all(r['list_type'] == 'block' for r in only_block['rules']))
        # Filtering by a foreign site must 404.
        self.assertEqual(self.client.get(f"/api/acl/rules?site_id={site['id']}",
                                         headers=_auth(self.token_b)).status_code, 404)

    # -- SDK auth -------------------------------------------------------------
    def test_check_via_api_key(self):
        site = self._new_site(self.token_a)
        self._make_rule(self.token_a, site['id'], list_type='block', match_type='ip',
                        value='9.9.9.9', mode='block')
        key = self.client.post(f"/api/sites/{site['id']}/keys",
                               headers=_auth(self.token_a), json={'name': 'sdk'}).get_json()['key']
        resp = self.client.post('/api/acl/check', headers={'X-API-Key': key},
                                json={'ip': '9.9.9.9'})
        self.assertEqual(resp.status_code, 200, resp.get_json())
        result = resp.get_json()['result']
        self.assertTrue(result['matched'])
        self.assertEqual(result['action_taken'], 'blocked')


if __name__ == '__main__':
    unittest.main()
