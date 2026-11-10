import os
import sys
import hashlib
import datetime
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app
from modules.database import db, User, PasswordResetToken


def _register(client, username, email, password='Password123'):
    resp = client.post('/api/auth/register', json={
        'username': username, 'email': email, 'password': password
    })
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()['token']


def _hash(raw):
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


class PasswordResetTests(unittest.TestCase):
    """Self-service password reset: enumeration safety and token lifecycle."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app('test')
        cls.client = cls.app.test_client()
        with cls.app.app_context():
            db.create_all()
            _register(cls.client, 'erin', 'erin@example.com')

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.drop_all()

    def setUp(self):
        self.assertTrue(self.app.config.get('NOTIFY_DRY_RUN'),
                        'tests must never send real email')
        with self.app.app_context():
            PasswordResetToken.query.delete()
            db.session.commit()

    # --- helpers -----------------------------------------------------------
    def _user_id(self, email='erin@example.com'):
        with self.app.app_context():
            return User.query.filter_by(email=email).first().id

    def _seed_token(self, raw='known-raw-token', expired=False, used=False,
                    user_id=None):
        now = datetime.datetime.utcnow()
        expires = now - datetime.timedelta(minutes=1) if expired \
            else now + datetime.timedelta(minutes=30)
        with self.app.app_context():
            row = PasswordResetToken(
                user_id=user_id if user_id is not None else self._user_id(),
                token_hash=_hash(raw),
                expires_at=expires,
                used_at=now if used else None,
            )
            db.session.add(row)
            db.session.commit()
            return row.id

    def _forgot(self, email):
        return self.client.post('/api/auth/forgot-password', json={'email': email})

    def _reset(self, token, new_password):
        return self.client.post('/api/auth/reset-password',
                                json={'token': token, 'new_password': new_password})

    # --- forgot-password ---------------------------------------------------
    def test_forgot_unknown_email_is_generic(self):
        resp = self._forgot('nobody@example.com')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('message', resp.get_json())
        with self.app.app_context():
            self.assertEqual(PasswordResetToken.query.count(), 0)

    def test_forgot_response_does_not_leak_registration(self):
        known = self._forgot('erin@example.com').get_json()
        unknown = self._forgot('nobody@example.com').get_json()
        self.assertEqual(known, unknown, 'response must not reveal registration')

    def test_forgot_creates_hashed_single_use_token(self):
        resp = self._forgot('erin@example.com')
        self.assertEqual(resp.status_code, 200)
        with self.app.app_context():
            rows = PasswordResetToken.query.all()
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertIsNone(row.used_at)
            self.assertGreater(row.expires_at, datetime.datetime.utcnow())
            self.assertEqual(len(row.token_hash), 64)
            self.assertNotIn('token_hash', row.to_dict())

    def test_forgot_empty_email_stays_generic(self):
        resp = self.client.post('/api/auth/forgot-password', json={'email': ''})
        self.assertEqual(resp.status_code, 200)
        with self.app.app_context():
            self.assertEqual(PasswordResetToken.query.count(), 0)

    def test_forgot_inactive_user_creates_no_token(self):
        with self.app.app_context():
            user = User.query.filter_by(email='erin@example.com').first()
            user.is_active = False
            db.session.commit()
        try:
            resp = self._forgot('erin@example.com')
            self.assertEqual(resp.status_code, 200)
            with self.app.app_context():
                self.assertEqual(PasswordResetToken.query.count(), 0)
        finally:
            with self.app.app_context():
                user = User.query.filter_by(email='erin@example.com').first()
                user.is_active = True
                db.session.commit()

    # --- reset-password ----------------------------------------------------
    def test_reset_with_valid_token_changes_password(self):
        raw = 'valid-token-123'
        self._seed_token(raw=raw)
        resp = self._reset(raw, 'NewPassword1')
        self.assertEqual(resp.status_code, 200)

        # Old password must no longer work; the new one must.
        old = self.client.post('/api/auth/login', json={
            'username': 'erin', 'password': 'Password123'})
        self.assertEqual(old.status_code, 401)
        new = self.client.post('/api/auth/login', json={
            'username': 'erin', 'password': 'NewPassword1'})
        self.assertEqual(new.status_code, 200)

    def test_token_is_single_use(self):
        raw = 'one-shot-token'
        self._seed_token(raw=raw)
        self.assertEqual(self._reset(raw, 'NewPassword1').status_code, 200)
        second = self._reset(raw, 'AnotherPass1')
        self.assertEqual(second.status_code, 400)
        with self.app.app_context():
            row = PasswordResetToken.query.filter_by(token_hash=_hash(raw)).first()
            self.assertIsNotNone(row.used_at, 'token must be marked used')

    def test_expired_token_is_rejected(self):
        raw = 'expired-token'
        self._seed_token(raw=raw, expired=True)
        resp = self._reset(raw, 'NewPassword1')
        self.assertEqual(resp.status_code, 400)

    def test_unknown_token_is_rejected(self):
        resp = self._reset('does-not-exist', 'NewPassword1')
        self.assertEqual(resp.status_code, 400)

    def test_weak_password_is_rejected(self):
        raw = 'weak-pass-token'
        self._seed_token(raw=raw)
        resp = self._reset(raw, 'weak')
        self.assertEqual(resp.status_code, 400)
        self.assertIn('at least 8', ' '.join(resp.get_json().get('details', [])))
        # A rejected attempt must not consume the token.
        with self.app.app_context():
            row = PasswordResetToken.query.filter_by(token_hash=_hash(raw)).first()
            self.assertIsNone(row.used_at)

    def test_missing_token_is_rejected(self):
        resp = self._reset('', 'NewPassword1')
        self.assertEqual(resp.status_code, 400)

    def test_raw_token_is_never_stored(self):
        raw = 'raw-token-must-not-persist'
        self._seed_token(raw=raw)
        with self.app.app_context():
            self.assertIsNone(
                PasswordResetToken.query.filter_by(token_hash=raw).first(),
                'the raw token must never be stored as-is')
            row = PasswordResetToken.query.filter_by(token_hash=_hash(raw)).first()
            self.assertIsNotNone(row)
            self.assertNotEqual(row.token_hash, raw)


if __name__ == '__main__':
    unittest.main()
