import os
import sys
import json
import unittest
from io import BytesIO

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app
from modules.database import db, User
from modules.docguard import (
    analyze_text,
    find_suspicious_urls,
    find_credit_cards,
    find_dangerous_keywords,
    _luhn_check,
    extract_text_from_pdf
)


class DocGuardUnitTests(unittest.TestCase):
    """Test DocGuard core algorithms without Flask app."""

    def test_luhn_valid_cards(self):
        valid_numbers = [
            '4532015112830366',
            '4916338506082832',
            '5425233430109903',
            '6011053819785308',
            '378734493671000',
        ]
        for num in valid_numbers:
            self.assertTrue(_luhn_check(num), f'Luhn check should pass for {num}')

    def test_luhn_invalid_cards(self):
        invalid = [
            '1234567890123456',
            '0000000000000000',
            '1111111111111111',
            '4532015112830367',
        ]
        for num in invalid:
            self.assertFalse(_luhn_check(num), f'Luhn check should fail for {num}')

    def test_luhn_rejects_short(self):
        self.assertFalse(_luhn_check('1234'))
        self.assertFalse(_luhn_check(''))

    def test_suspicious_urls_http_non_secure(self):
        text = 'Visit http://example.com/login now.'
        urls = find_suspicious_urls(text)
        self.assertGreaterEqual(len(urls), 1)
        self.assertTrue(any('http' in u['url'].lower() for u in urls))

    def test_suspicious_urls_short_link(self):
        text = 'Click here: https://bit.ly/abc123'
        urls = find_suspicious_urls(text)
        self.assertTrue(any('bit.ly' in u['url'].lower() for u in urls))

    def test_suspicious_urls_contains_at(self):
        text = 'Go to https://evil.com@legit.com'
        urls = find_suspicious_urls(text)
        self.assertTrue(any('@' in u['url'] for u in urls))

    def test_credit_card_detects_valid(self):
        text = 'My card is 4532015112830366, please use carefully.'
        cards = find_credit_cards(text)
        self.assertGreaterEqual(len(cards), 1)
        self.assertTrue(cards[0]['card_number_masked'].startswith('4532'))
        self.assertEqual(cards[0]['risk'], 95)

    def test_credit_card_ignores_plain_numbers(self):
        text = 'Invoice #1234567890123456 paid in full.'
        cards = find_credit_cards(text)
        self.assertEqual(len(cards), 0)

    def test_credit_card_masks_middle(self):
        text = 'Card: 4532015112830366'
        cards = find_credit_cards(text)
        mask = cards[0]['card_number_masked']
        self.assertEqual(mask.count('*'), 8)
        self.assertTrue(mask.startswith('4532'))
        self.assertTrue(mask.endswith('0366'))

    def test_dangerous_keywords_english(self):
        text = 'This document contains the password for accessing our bank account.'
        kws = find_dangerous_keywords(text)
        self.assertTrue(any(k['keyword'] == 'password' for k in kws))
        self.assertTrue(any(k['keyword'] == 'bank' for k in kws))
        self.assertTrue(all(k['language'] == 'en' for k in kws))

    def test_dangerous_keywords_arabic(self):
        text = 'هذا المستند يحتوي على كلمة مرور للحساب البنكي.'
        kws = find_dangerous_keywords(text)
        self.assertTrue(any(k['language'] == 'ar' for k in kws))

    def test_analyze_text_cleansafe(self):
        text = 'Hello World. This is a normal document with no issues.'
        result = analyze_text(text, filename='clean.txt')
        self.assertIn('risk_score', result)
        self.assertIn('risk_level', result)
        self.assertLess(result['risk_score'], 15)
        self.assertEqual(result['filename'], 'clean.txt')

    def test_analyze_text_risk_levels(self):
        result = analyze_text('', filename='empty.txt')
        self.assertIn(result['risk_level'], {'low', 'medium', 'high', 'critical'})
        dangerous = 'ransom password credit card 4532015112830366 click here ' * 20
        r2 = analyze_text(dangerous, filename='bad.txt')
        self.assertGreaterEqual(r2['risk_score'], 30)

    def test_analyze_text_issue_counts(self):
        text = (
            'Visit http://evil.com and https://bit.ly/xyz now. '
            'Enter password and credit card 4532015112830366.'
        )
        result = analyze_text(text, filename='bad.txt')
        self.assertGreaterEqual(result['issues_found'], 3)


class DocGuardFlaskTests(unittest.TestCase):
    """Test DocGuard REST endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app('test')
        cls.client = cls.app.test_client()
        with cls.app.app_context():
            db.create_all()

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.drop_all()

    def test_scan_text_endpoint(self):
        resp = self.client.post('/api/docguard/scan', json={
            'text': 'This is a clean text with no issues.',
            'filename': 'test.txt'
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('risk_score', data)
        self.assertIn('risk_level', data)
        self.assertIn('issues', data)

    def test_scan_text_missing(self):
        resp = self.client.post('/api/docguard/scan', json={})
        self.assertEqual(resp.status_code, 400)

    def test_scan_text_known_phish(self):
        resp = self.client.post('/api/docguard/scan', json={
            'text': (
                'URGENT: Click http://paypal-login.xyz to verify your account now! '
                'Enter password and credit card 4532015112830366 to avoid account closure.'
            ),
            'filename': 'phish.txt'
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertGreaterEqual(data['risk_score'], 40)
        self.assertGreaterEqual(data['issues_found'], 2)

    def test_scan_txt_file_upload(self):
        data = {
            'file': (BytesIO(b'hello world, clean document.'), 'hello.txt')
        }
        resp = self.client.post('/api/docguard/scan', data=data, content_type='multipart/form-data')
        self.assertEqual(resp.status_code, 200)
        j = resp.get_json()
        self.assertIn('risk_score', j)

    def test_scan_unsupported_file_rejected(self):
        data = {'file': (BytesIO(b'xxx'), 'picture.png')}
        resp = self.client.post('/api/docguard/scan', data=data, content_type='multipart/form-data')
        self.assertEqual(resp.status_code, 400)

    def test_analyze_text_endpoint_get_not_allowed(self):
        resp = self.client.get('/api/docguard/analyze-text')
        self.assertEqual(resp.status_code, 405)


if __name__ == '__main__':
    unittest.main()
