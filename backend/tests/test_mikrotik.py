# File: test_mikrotik.py
# Last updated: 2026-11-06
# Description: Test MikroTik resource and router ping checks, TLS, and error handling.

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

    def test_router_ping_request_and_report(self):
        item = dict(self.item, type='mikrotik_ping', host='1.1.1.1', count=3)
        self.respond([{'seq': '0', 'time': '10ms'}, {'seq': '1', 'status': 'timeout'},
                      {'seq': '2', 'time': '12ms'}])
        result = monitor.check_device({'name': 'router', 'checks': [item]}, 10)
        self.assertTrue(result['ok'])
        self.assertFalse(result['checks'][0]['resource'])
        self.assertIn('Router ping to 1.1.1.1: 2/3 replies', monitor.format_report([result], 'now'))
        request = self.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, 'https://router/rest/ping')
        self.assertEqual(request.get_method(), 'POST')
        self.assertEqual(json.loads(request.data), {'address': '1.1.1.1', 'count': '3', 'interval': '200ms'})
        self.assertEqual(request.get_header('Content-type'), 'application/json')
        self.assertEqual(request.get_header('Authorization'), 'Basic bW9uaXRvcjpzZWNyZXQ=')
        self.tls.assert_called_once_with(cafile=self.item['cafile'])
        self.assertEqual(self.opener.open.call_args.kwargs['timeout'], 10)

    def test_router_ping_no_replies_and_malformed_response(self):
        item = dict(self.item, type='mikrotik_ping', host='8.8.8.8')
        self.respond([{'seq': str(i), 'status': 'timeout'} for i in range(3)])
        self.assertEqual(monitor.execute(item, 10), (False, 'Router ping to 8.8.8.8: 0/3 replies'))
        for response in [[], {}, [{'seq': '0'}], ['invalid']]:
            with self.subTest(response=response):
                self.respond(response)
                self.assertFalse(monitor.execute(item, 10)[0])

    def test_router_ping_configuration(self):
        item = dict(self.item, type='mikrotik_ping', host='1.1.1.1')
        for override in [{'count': 0}, {'count': 11}, {'count': True}, {'count': 1.5},
                         {'host': []}, {'url': 'http://router'}, {'url': 'https://user:secret@router'}]:
            with self.subTest(override=override):
                self.assertFalse(monitor.check_device({'name': 'router', 'checks': [dict(item, **override)]}, 10)['ok'])
        self.opener.open.assert_not_called()
        self.respond([{'seq': '0', 'time': '1ms'}])
        self.assertTrue(monitor.execute(dict(item, url='https://router/rest/', count=1), 10)[0])
        self.assertEqual(self.opener.open.call_args.args[0].full_url, 'https://router/rest/ping')

    def test_router_ping_api_and_tls_errors(self):
        item = dict(self.item, type='mikrotik_ping', host='1.1.1.1')
        for error in [ssl.SSLError('secret'), TimeoutError('secret'),
                      urllib.error.HTTPError('https://router', 403, 'secret', {}, None)]:
            with self.subTest(error=error):
                self.opener.open.side_effect = error
                ok, details = monitor.execute(item, 10)
                self.assertFalse(ok)
                self.assertNotIn('secret', details)



if __name__ == '__main__':
    unittest.main()
