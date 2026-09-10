import os
import sys
import unittest
import time
from collections import deque

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app
from modules.database import db
from modules.sysguard import (
    _detect_anomaly,
    get_system_status
)


class SysGuardUnitTests(unittest.TestCase):

    def test_detect_anomaly_insufficient_data(self):
        anomaly, avg, sd, meta = _detect_anomaly([], 80.0)
        self.assertFalse(anomaly)
        self.assertEqual(meta, 'insufficient_data')

    def test_detect_anomaly_no_variance(self):
        values = [10.0] * 15
        anomaly, avg, sd, meta = _detect_anomaly(values, 10.0)
        self.assertFalse(anomaly)
        self.assertEqual(avg, 10.0)
        self.assertEqual(sd, 0.0)

    def test_detect_anomaly_mild_fluctuations(self):
        values = [20.0] * 40 + [22.0, 18.0, 21.0]
        anomaly, avg, sd, meta = _detect_anomaly(values, 22.0)
        self.assertFalse(anomaly)
        self.assertAlmostEqual(avg, 20.0, delta=1.0)

    def test_detect_anomaly_spike_detected(self):
        values = [10.0] * 50
        anomaly, avg, sd, meta = _detect_anomaly(values, 90.0)
        self.assertTrue(anomaly)
        self.assertIsInstance(meta, float)
        self.assertGreater(meta, 1.0)

    def test_detect_anomaly_threshold_sensitive(self):
        values = list(range(30, 50)) + list(range(40, 60))
        # extreme outlier
        anomaly, _, _, _ = _detect_anomaly(values, 10_000.0, threshold_std=1.0)
        self.assertTrue(anomaly)

    def test_get_system_status_structure(self):
        result = get_system_status()
        # If psutil is not installed available will be False but dict still valid
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
        self.assertIn('available', result)
        self.assertIn('cpu', result)
        self.assertIn('memory', result)
        self.assertIn('disk', result)
        self.assertIn('network', result)
        self.assertIn('anomalies', result)
        self.assertIn('alerts', result)
        self.assertIn('risk_score', result)
        self.assertIn('risk_level', result)
        self.assertIsInstance(result['anomalies'], list)
        self.assertIsInstance(result['alerts'], list)

    def test_get_system_status_risk_bounds(self):
        result = get_system_status()
        self.assertGreaterEqual(result['risk_score'], 0)
        self.assertLessEqual(result['risk_score'], 100)
        self.assertIn(result['risk_level'], {'low', 'medium', 'high', 'critical'})

    def test_get_system_status_cpu_has_baseline_after_second_call(self):
        # first call seeds history, second should include baseline
        get_system_status()
        r = get_system_status()
        self.assertIn('baseline', r.get('cpu', {}))
        self.assertIn('baseline', r.get('memory', {}))

    def test_anomaly_types_dicts_have_expected_keys(self):
        # Fill history with stable values then inject spike to force anomalies
        from modules.sysguard import _HISTORY
        for key in ('cpu', 'memory', 'disk', 'network_io'):
            _HISTORY[key].clear()
            for _ in range(30):
                _HISTORY[key].append(10.0)
            _HISTORY['timestamps'].append(time.time())
        r = get_system_status()
        for a in r['anomalies']:
            self.assertIn('type', a)
            self.assertIn('value', a)
            self.assertIn('message', a)


class SysGuardFlaskTests(unittest.TestCase):

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

    def test_status_endpoint_returns_200(self):
        resp = self.client.get('/api/sysguard/status')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('available', data)
        self.assertIn('risk_score', data)

    def test_history_endpoint_returns_counts(self):
        # prime history
        self.client.get('/api/sysguard/status')
        resp = self.client.get('/api/sysguard/history')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        for key in ('cpu', 'memory', 'disk', 'network_KBps', 'timestamps'):
            self.assertIn(key, data)
            self.assertIsInstance(data[key], list)
        self.assertIn('count', data)
        self.assertGreaterEqual(data['count'], 0)

    def test_processes_endpoint(self):
        resp = self.client.get('/api/sysguard/processes?limit=5')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('total', data)
        self.assertIn('processes', data)
        self.assertLessEqual(len(data['processes']), 5)
        for p in data['processes']:
            self.assertIn('pid', p)
            self.assertIn('name', p)
            self.assertIn('cpu_percent', p)
            self.assertIn('memory_percent', p)


if __name__ == '__main__':
    unittest.main()
