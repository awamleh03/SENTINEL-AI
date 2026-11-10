import os
import sys
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app
from modules.database import (
    db, SecurityEvent, NotificationChannel, NotificationLog, NotificationAggregate
)
from modules.notifications import dispatch_event, notify_event


def _register(client, username, email, password='Password123'):
    resp = client.post('/api/auth/register', json={
        'username': username, 'email': email, 'password': password
    })
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()['token']


def _auth(token):
    return {'Authorization': f'Bearer {token}'}


class NotificationChannelTests(unittest.TestCase):
    """Channel CRUD, secret non-exposure, verification gating and isolation."""

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

    def _email_channel(self, token, name='ops email'):
        resp = self.client.post('/api/notifications/channels', headers=_auth(token), json={
            'channel_type': 'email', 'name': name,
            'config': {'to_address': 'ops@example.com'}
        })
        self.assertEqual(resp.status_code, 201, resp.get_json())
        return resp.get_json()['channel']

    def test_list_requires_auth(self):
        self.assertEqual(self.client.get('/api/notifications/channels').status_code, 401)

    def test_create_requires_valid_type(self):
        resp = self.client.post('/api/notifications/channels', headers=_auth(self.token_a),
                                json={'channel_type': 'pigeon', 'name': 'x', 'config': {}})
        self.assertEqual(resp.status_code, 400)

    def test_create_requires_required_fields(self):
        resp = self.client.post('/api/notifications/channels', headers=_auth(self.token_a),
                                json={'channel_type': 'telegram', 'name': 'tg', 'config': {'chat_id': '1'}})
        self.assertEqual(resp.status_code, 400)

    def test_new_channel_is_unverified_and_disabled(self):
        ch = self._email_channel(self.token_a)
        self.assertFalse(ch['is_verified'])
        self.assertFalse(ch['is_enabled'])

    def test_cannot_enable_before_verified(self):
        ch = self._email_channel(self.token_a, 'gated')
        resp = self.client.patch(f"/api/notifications/channels/{ch['id']}",
                                 headers=_auth(self.token_a), json={'is_enabled': True})
        self.assertEqual(resp.status_code, 400)

    def test_test_then_enable(self):
        ch = self._email_channel(self.token_a, 'lifecycle')
        t = self.client.post(f"/api/notifications/channels/{ch['id']}/test", headers=_auth(self.token_a))
        self.assertEqual(t.status_code, 200)
        self.assertTrue(t.get_json()['channel']['is_verified'])

        e = self.client.patch(f"/api/notifications/channels/{ch['id']}",
                              headers=_auth(self.token_a), json={'is_enabled': True})
        self.assertEqual(e.status_code, 200)
        self.assertTrue(e.get_json()['channel']['is_enabled'])

    def test_secret_is_never_returned(self):
        resp = self.client.post('/api/notifications/channels', headers=_auth(self.token_a), json={
            'channel_type': 'slack', 'name': 'dev slack',
            'config': {'webhook_url': 'https://hooks.slack.com/services/TOP-SECRET-TOKEN'}
        })
        self.assertEqual(resp.status_code, 201)
        ch = resp.get_json()['channel']
        # The secret value must not appear anywhere in the serialized channel.
        self.assertNotIn('TOP-SECRET-TOKEN', json.dumps(ch))
        self.assertTrue(ch['has_secret']['webhook_url'])

        got = self.client.get(f"/api/notifications/channels/{ch['id']}", headers=_auth(self.token_a))
        self.assertNotIn('TOP-SECRET-TOKEN', json.dumps(got.get_json()))

    def test_config_change_resets_verification(self):
        ch = self._email_channel(self.token_a, 'reset-me')
        self.client.post(f"/api/notifications/channels/{ch['id']}/test", headers=_auth(self.token_a))
        resp = self.client.patch(f"/api/notifications/channels/{ch['id']}", headers=_auth(self.token_a),
                                 json={'config': {'smtp_host': 'smtp.example.com'}})
        self.assertFalse(resp.get_json()['channel']['is_verified'])

    def test_isolation_between_accounts(self):
        ch = self._email_channel(self.token_a, 'private')
        self.assertEqual(
            self.client.get(f"/api/notifications/channels/{ch['id']}", headers=_auth(self.token_b)).status_code, 404)
        self.assertEqual(
            self.client.patch(f"/api/notifications/channels/{ch['id']}", headers=_auth(self.token_b),
                              json={'name': 'hijack'}).status_code, 404)
        self.assertEqual(
            self.client.delete(f"/api/notifications/channels/{ch['id']}", headers=_auth(self.token_b)).status_code, 404)


class DispatchTests(unittest.TestCase):
    """Delivery log, severity filtering and aggregation (dry-run, no real send)."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app('test')
        cls.client = cls.app.test_client()
        with cls.app.app_context():
            db.create_all()
            cls.token = cls.client.post('/api/auth/register', json={
                'username': 'carol', 'email': 'carol@example.com', 'password': 'Password123'
            }).get_json()['token']

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.drop_all()

    def setUp(self):
        self.assertTrue(self.app.config.get('NOTIFY_DRY_RUN'))
        with self.app.app_context():
            NotificationAggregate.query.delete()
            NotificationLog.query.delete()
            NotificationChannel.query.delete()
            db.session.commit()

    def _make_channel(self, min_severity='medium'):
        with self.app.app_context():
            user_id = db.session.execute(db.text('SELECT id FROM users LIMIT 1')).scalar()
            ch = NotificationChannel(user_id=user_id, channel_type='email', name='c',
                                     config=json.dumps({'to_address': 'ops@example.com'}),
                                     min_severity=min_severity, is_enabled=True, is_verified=True)
            db.session.add(ch)
            db.session.commit()
            return ch.id

    def _new_event(self, threat_type='bruteforce', path='/login', decision='deny'):
        """Create a SecurityEvent bound to the current session (call in context)."""
        user_id = db.session.execute(db.text('SELECT id FROM users LIMIT 1')).scalar()
        ev = SecurityEvent(user_id=user_id, event_type='request', threat_type=threat_type,
                           path=path, decision=decision, action_taken='monitored')
        db.session.add(ev)
        db.session.commit()
        return ev

    def test_dispatch_sends_and_logs(self):
        self._make_channel()
        with self.app.app_context():
            ev = self._new_event()
            results = dispatch_event(self.app, ev)
            self.assertEqual(results[0][1], 'sent')
            logs = NotificationLog.query.all()
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0].status, 'sent')

    def test_aggregation_suppresses_repeats(self):
        self._make_channel()
        with self.app.app_context():
            ch = NotificationChannel.query.first()
            self.assertEqual(notify_event(self.app, ch, self._new_event()), 'sent')
            self.assertEqual(notify_event(self.app, ch, self._new_event()), 'aggregated')
            statuses = sorted(l.status for l in NotificationLog.query.all())
            self.assertEqual(statuses, ['aggregated', 'sent'])

    def test_min_severity_filters_low(self):
        self._make_channel(min_severity='high')
        with self.app.app_context():
            ev = self._new_event(threat_type=None, decision='allow')  # severity 'low'
            self.assertEqual(dispatch_event(self.app, ev), [])
            self.assertEqual(NotificationLog.query.count(), 0)

    def test_unverified_channel_is_skipped(self):
        with self.app.app_context():
            user_id = db.session.execute(db.text('SELECT id FROM users LIMIT 1')).scalar()
            db.session.add(NotificationChannel(
                user_id=user_id, channel_type='email', name='unverified',
                config=json.dumps({'to_address': 'x@example.com'}),
                min_severity='low', is_enabled=True, is_verified=False))
            db.session.commit()
            ev = self._new_event()
            self.assertEqual(dispatch_event(self.app, ev), [])

    def test_log_endpoint_pagination(self):
        resp = self.client.get('/api/notifications/log', headers=_auth(self.token),
                               query_string={'page': 1, 'per_page': 10})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        for key in ('logs', 'total', 'page', 'per_page', 'pages'):
            self.assertIn(key, body)


class AutoDispatchTests(unittest.TestCase):
    """Recording a security event must fan out to channels automatically.

    These tests exercise the wiring between `record_security_event` and
    `dispatch_event`. `NOTIFY_DRY_RUN` is on, so no real message is ever sent.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = create_app('test')
        cls.client = cls.app.test_client()
        with cls.app.app_context():
            db.create_all()
            cls.token = cls.client.post('/api/auth/register', json={
                'username': 'dave', 'email': 'dave@example.com', 'password': 'Password123'
            }).get_json()['token']

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.drop_all()

    def setUp(self):
        self.assertTrue(self.app.config.get('NOTIFY_DRY_RUN'))
        with self.app.app_context():
            NotificationAggregate.query.delete()
            NotificationLog.query.delete()
            NotificationChannel.query.delete()
            SecurityEvent.query.delete()
            db.session.commit()

    def _user_id(self):
        return db.session.execute(db.text('SELECT id FROM users LIMIT 1')).scalar()

    def _channel(self, min_severity='low', is_verified=True, is_enabled=True):
        with self.app.app_context():
            ch = NotificationChannel(
                user_id=self._user_id(), channel_type='email', name='auto',
                config=json.dumps({'to_address': 'ops@example.com'}),
                min_severity=min_severity, is_enabled=is_enabled, is_verified=is_verified)
            db.session.add(ch)
            db.session.commit()
            return ch.id

    def test_recording_event_triggers_dispatch(self):
        from modules.database import record_security_event
        self._channel()
        with self.app.app_context():
            user_id = self._user_id()
        event_id = record_security_event(
            self.app, 'request', user_id=user_id, threat_type='bruteforce',
            path='/login', decision='deny')
        self.assertIsNotNone(event_id)
        with self.app.app_context():
            logs = NotificationLog.query.all()
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0].status, 'sent')
            self.assertEqual(logs[0].event_id, event_id)

    def test_unverified_channel_is_not_dispatched(self):
        from modules.database import record_security_event
        self._channel(is_verified=False)
        with self.app.app_context():
            user_id = self._user_id()
        record_security_event(self.app, 'request', user_id=user_id,
                              threat_type='bruteforce', decision='deny')
        with self.app.app_context():
            self.assertEqual(NotificationLog.query.count(), 0)

    def test_repeated_events_are_aggregated_not_flooded(self):
        from modules.database import record_security_event
        self._channel()
        with self.app.app_context():
            user_id = self._user_id()
        for _ in range(3):
            record_security_event(self.app, 'request', user_id=user_id,
                                  threat_type='bruteforce', path='/login', decision='deny')
        with self.app.app_context():
            statuses = sorted(l.status for l in NotificationLog.query.all())
            # First one is sent, the two within the dedup window are aggregated.
            self.assertEqual(statuses, ['aggregated', 'aggregated', 'sent'])

    def test_dispatch_can_be_disabled(self):
        from modules.database import record_security_event
        self._channel()
        with self.app.app_context():
            user_id = self._user_id()
        self.app.config['NOTIFY_DISPATCH_ON_EVENT'] = False
        try:
            event_id = record_security_event(self.app, 'request', user_id=user_id,
                                             threat_type='bruteforce', decision='deny')
            self.assertIsNotNone(event_id)
            with self.app.app_context():
                self.assertEqual(NotificationLog.query.count(), 0)
        finally:
            self.app.config['NOTIFY_DISPATCH_ON_EVENT'] = True

    def test_dispatch_failure_does_not_break_recording(self):
        import modules.notifications as notif
        from modules.database import record_security_event
        self._channel()
        with self.app.app_context():
            user_id = self._user_id()

        original = notif.dispatch_event

        def _boom(app, event):
            raise RuntimeError('boom')

        notif.dispatch_event = _boom
        try:
            event_id = record_security_event(self.app, 'request', user_id=user_id,
                                             threat_type='bruteforce', decision='deny')
        finally:
            notif.dispatch_event = original

        # The event itself must still be persisted despite the dispatch failure.
        self.assertIsNotNone(event_id)
        with self.app.app_context():
            self.assertIsNotNone(db.session.get(SecurityEvent, event_id))
            self.assertEqual(NotificationLog.query.count(), 0)


if __name__ == '__main__':
    unittest.main()
