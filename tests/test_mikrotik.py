import io
import json
import os
from pathlib import Path
import ssl
import unittest
import urllib.error
from unittest.mock import patch

import monitor


class MikroTikTests(unittest.TestCase):
    def setUp(self):
        self.item = {'type': 'mikrotik', 'url': 'https://router', 'cafile': str(Path(__file__).resolve().parent.parent / 'test-ca.crt')}
        self.resource = {'cpu-load': '10', 'free-memory': '50', 'total-memory': '100',
                         'free-hdd-space': '90', 'total-hdd-space': '100',
                         'uptime': '1d', 'version': '7', 'board-name': 'router'}
        self.env = patch.dict(os.environ, MIKROTIK_USERNAME='monitor', MIKROTIK_PASSWORD='secret')
        self.env.start()
        self.addCleanup(self.env.stop)
        self.context = patch('checks.mikrotik.ssl.create_default_context')
        self.tls = self.context.start()
        self.addCleanup(self.context.stop)
        self.opener_patch = patch('checks.mikrotik.urllib.request.build_opener')
        self.opener = self.opener_patch.start().return_value
        self.addCleanup(self.opener_patch.stop)

    def respond(self, data=None):
        self.opener.open.return_value = io.StringIO(json.dumps(self.resource if data is None else data))

    def test_healthy_ca_and_request(self):
        self.respond()
        ok, details = monitor.execute(self.item, 3)
        self.assertTrue(ok)
        self.assertIn('Memory 50.0%', details)
        self.assertIn('uptime: 1d', details)
        self.tls.assert_called_once_with(cafile=str(Path(__file__).resolve().parent.parent / 'test-ca.crt'))
        request = self.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, 'https://router/rest/system/resource')
        self.assertEqual(request.get_header('Authorization'), 'Basic bW9uaXRvcjpzZWNyZXQ=')
        self.assertEqual(self.opener.open.call_args.kwargs['timeout'], 3)

    def test_each_resource_warning(self):
        for key, value in [('cpu-load', '81'), ('free-memory', '14'), ('free-hdd-space', '9')]:
            with self.subTest(key=key):
                data = dict(self.resource, **{key: value})
                self.respond([data])
                result = monitor.check_device({'name': 'router', 'checks': [self.item]}, 2)
                self.assertTrue(result['ok'])
                self.assertTrue(result['checks'][0]['warning'])

    def test_resource_report_separate_from_checks(self):
        self.respond()
        result = monitor.check_device({'name': 'router', 'checks': [self.item]}, 2)
        report = monitor.format_report([result], 'now')
        self.assertIn('    Resources:', report)
        self.assertIn('            CPU 10.0%', report)
        self.assertNotIn('OK   mikrotik:', report)
        self.assertNotIn('WARN', report)

    def test_resource_warning_in_checks(self):
        self.respond(dict(self.resource, **{'cpu-load': '81'}))
        result = monitor.check_device({'name': 'router', 'checks': [self.item]}, 2)
        report = monitor.format_report([result], 'now')
        self.assertIn('WARN mikrotik: cpu 81.0% exceeds 80%', report)
        self.assertIn('    Resources:', report)
        self.assertIn('            CPU 81.0%', report)

    def test_resource_failure_in_checks(self):
        self.opener.open.side_effect = urllib.error.HTTPError('https://router', 401, 'Unauthorized', {}, None)
        result = monitor.check_device({'name': 'router', 'checks': [self.item]}, 2)
        report = monitor.format_report([result], 'now')
        self.assertIn('FAIL mikrotik: MikroTik REST HTTP 401', report)
        self.assertNotIn('    Resources:', report)

    def test_threshold_boundary_and_override(self):
        self.respond()
        ok, details = monitor.execute(dict(self.item, cpu_warn_percent=10), 2)
        self.assertTrue(ok)
        self.assertFalse(details.startswith('WARNING:'))
        self.respond()
        self.assertTrue(monitor.execute(dict(self.item, cpu_warn_percent=9), 2)[1].startswith('WARNING:'))

    def test_invalid_resource_fails(self):
        for data in [{}, [], dict(self.resource, **{'total-memory': '0'}), dict(self.resource, **{'cpu-load': 'NaN'})]:
            with self.subTest(data=data):
                self.respond(data)
                self.assertFalse(monitor.execute(self.item, 2)[0])

    def test_api_errors_fail(self):
        for error in [ssl.SSLError('certificate invalid'), urllib.error.HTTPError('https://router', 401, 'Unauthorized', {}, None)]:
            with self.subTest(error=error):
                self.opener.open.side_effect = error
                self.assertFalse(monitor.execute(self.item, 2)[0])

    def test_configuration_rejected(self):
        for override in [{'url': 'http://router'}, {'cpu_warn_percent': 101}, {'disk_warn_percent': float('nan')}]:
            with self.subTest(override=override):
                result = monitor.check_device({'name': 'router', 'checks': [dict(self.item, **override)]}, 2)
                self.assertFalse(result['ok'])
        self.tls.assert_not_called()

    def test_default_ca(self):
        self.respond()
        item = dict(self.item)
        del item['cafile']
        monitor.execute(item, 2)
        self.tls.assert_called_once_with(cafile=str(Path(__file__).resolve().parent.parent / 'cert_export_homelab-ca.crt'))

    def test_relative_ca(self):
        self.respond()
        monitor.execute(dict(self.item, cafile='certs/custom.crt'), 2)
        self.tls.assert_called_once_with(
            cafile=str(Path(__file__).resolve().parent.parent / 'certs/custom.crt'))

    def test_missing_credentials(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(monitor.check_device({'name': 'router', 'checks': [self.item]}, 2)['ok'])
        self.opener.open.assert_not_called()


if __name__ == '__main__':
    unittest.main()
