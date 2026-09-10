import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app
from modules.database import db
from modules.mailguard import (
    classify_email,
    _match_keywords,
    _analyze_links,
    _analyze_headers,
    SPAM_KEYWORDS_EN,
    PHISHING_KEYWORDS_EN
)


class MailGuardUnitTests(unittest.TestCase):

    def test_classify_clean_email(self):
        r = classify_email(
            sender='john.doe@company.com',
            subject='Meeting notes from last week',
            body=(
                'Hi team, following up on yesterday\'s meeting. Please review the attached notes '
                'and let me know your feedback. Thanks, regards, John'
            )
        )
        self.assertIn(r['classification'], {'Safe', 'Spam'})
        self.assertIsInstance(r['risk_score'], float)
        self.assertLessEqual(r['risk_score'], 100)
        self.assertGreaterEqual(r['risk_score'], 0)
        self.assertIn(r['risk_level'], {'low', 'medium', 'high', 'critical'})

    def test_classify_obvious_spam(self):
        body = (
            'Congratulations!!! You have won the lottery! Claim your million dollar prize now. '
            'Click here to receive your free money. Act now, limited time exclusive offer!!! '
            'Guaranteed 100% free cash prize for you, our lucky winner.'
        )
        r = classify_email(sender='luckywinner@lottery-claim.co', subject='YOU ARE A WINNER!!!', body=body)
        self.assertIn(r['classification'], {'Spam', 'Urgent', 'Phishing'})
        self.assertGreaterEqual(r['risk_score'], 30)
        self.assertGreaterEqual(len(r['hits'].get('spam_hits', [])), 2)

    def test_classify_phishing_verify_account(self):
        body = (
            'Dear Customer, We noticed unusual activity on your account. '
            'Verify your identity immediately by clicking this link: http://verify-paypal-account.xyz/login '
            'Failure to comply within 24 hours will result in account suspension. '
            'This is an official security alert.'
        )
        r = classify_email(
            sender='support@secure-paypal-login.co',
            subject='URGENT: Verify your account before it is closed',
            body=body
        )
        self.assertIn(r['classification'], {'Phishing', 'Urgent', 'Spam'})
        self.assertGreaterEqual(r['category_scores']['phishing_score'], 25)
        self.assertGreaterEqual(len(r['hits'].get('phishing_hits', [])), 2)

    def test_classify_urgent_business(self):
        body = (
            'Hey, this is the CEO. I need you to send me the Q3 numbers right away. This is time-sensitive '
            '— board meeting in 24 hours, critical decision, act now without delay. Do not share this with anyone, '
            'it is a confidential quick favor between us.'
        )
        r = classify_email(sender='ceo@company.com', subject='Quick question', body=body)
        self.assertIsInstance(r['urgent_score'] if 'urgent_score' in r.get('category_scores', {})
                              else r['category_scores'].get('urgent_score', 0), float)
        self.assertGreaterEqual(r['category_scores']['urgent_score'], 15)

    def test_classify_arabic_phishing(self):
        body = (
            'عميلنا العزيز، لاحظنا نشاط غير معتاد على حسابك البنكي. قم بتأكيد هويتك فوراً عبر الرابط التالي: '
            'http://تحقق-الحساب-البنكي.example/ '
            'عدم الامتثال خلال 24 ساعة يؤدي إلى إيقاف الحساب. هذا إشعار أمني رسمي.'
        )
        r = classify_email(sender='الدعم@الأمان-البنكي.example', subject='عاجل جداً: تحقق من حسابك', body=body)
        self.assertGreaterEqual(r['risk_score'], 25)
        phish_hits_ar = [h for h in r['hits'].get('phishing_hits', []) if True]
        self.assertGreaterEqual(len(r['hits'].get('phishing_hits', [])), 1)

    def test_match_keywords_count(self):
        text = 'Free money. Win a prize today with our exclusive free offer!'
        score, hits = _match_keywords(text, SPAM_KEYWORDS_EN)
        self.assertGreaterEqual(score, 10)
        self.assertTrue(any(h['keyword'] == 'free' for h in hits))

    def test_analyze_links_catches_http(self):
        body = 'Download from http://suspicious.example/file.exe now'
        score, issues = _analyze_links(body)
        self.assertGreaterEqual(score, 3)

    def test_analyze_links_catches_shortener(self):
        body = 'Click https://bit.ly/xyz for the document'
        score, issues = _analyze_links(body)
        self.assertGreaterEqual(score, 6)
        self.assertTrue(any('Shortened' in i.get('issue', '') for i in issues))

    def test_analyze_links_mismatched_href(self):
        body = '<a href="http://evil.xyz">http://yourbank.com</a>'
        score, issues = _analyze_links(body)
        self.assertGreaterEqual(score, 10)
        self.assertTrue(any('differs' in i.get('issue', '') for i in issues))

    def test_analyze_headers_all_caps_subject(self):
        score, notes = _analyze_headers('info@legit.com', 'ACT NOW OR LOSE OUT', 'text/plain')
        self.assertGreaterEqual(score, 5)

    def test_risk_score_bounds(self):
        for body in ['', 'clean', 'a' * 100, ('phishing ' * 50 + 'credit card ' * 30)]:
            r = classify_email(body=body)
            self.assertGreaterEqual(r['risk_score'], 0)
            self.assertLessEqual(r['risk_score'], 100)

    def test_attachments_detection(self):
        body = 'Please review the report.docx and invoice.pdf I attached.'
        r = classify_email(body=body)
        self.assertGreaterEqual(r['attachments_detected'], 2)


class MailGuardFlaskTests(unittest.TestCase):

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

    def test_classify_endpoint_requires_body_or_subject(self):
        resp = self.client.post('/api/mailguard/classify', json={})
        self.assertEqual(resp.status_code, 400)

    def test_classify_endpoint_success(self):
        resp = self.client.post('/api/mailguard/classify', json={
            'sender': 'team@company.com',
            'subject': 'Weekly status update',
            'body': 'Hi team, here is our weekly update report. Meeting scheduled for Tuesday. Regards.'
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('classification', data)
        self.assertIn('risk_score', data)
        self.assertIn('scan_id', data)

    def test_classify_endpoint_known_phish(self):
        resp = self.client.post('/api/mailguard/classify', json={
            'sender': 'noreply@bank-security-alert.xyz',
            'subject': 'Immediate action required: account suspended',
            'body': (
                'Dear Customer, your account has been compromised. Click http://verify-account.xyz '
                'to reset your password within 24 hours or your account will be terminated.'
            )
        })
        data = resp.get_json()
        self.assertGreaterEqual(data['risk_score'], 30)

    def test_batch_endpoint(self):
        emails = [
            {'sender': 'clean@example.com', 'subject': 'hi', 'body': 'Hello, how are you?'},
            {'sender': 'spam@lotto.xyz', 'subject': 'WIN', 'body': 'Free money free prize win today!!!'}
        ]
        resp = self.client.post('/api/mailguard/batch', json={'emails': emails})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['total'], 2)
        self.assertEqual(len(data['results']), 2)
        self.assertIn('summary', data)

    def test_batch_endpoint_more_than_100_rejected(self):
        emails = [{'body': str(i)} for i in range(101)]
        resp = self.client.post('/api/mailguard/batch', json={'emails': emails})
        self.assertEqual(resp.status_code, 400)


if __name__ == '__main__':
    unittest.main()
