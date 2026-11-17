# File: test_omada.py
# Last updated: 2026-11-16
# Change: Test Omada authentication, queries, TLS, and safe failures.
# Description: Exercise the OpenAPI integration with mocked HTTP responses and no live credentials.

import io
import json
import ssl
import unittest
from unittest.mock import patch, Mock
from urllib.error import HTTPError

from checks import execute
from checks.omada import OmadaClient, NoRedirect, omada


class OmadaTests(unittest.TestCase):
    def setUp(self):
        env = {'OMADA_URL': 'https://controller.example:8043',
               'OMADA_CONTROLLER_ID': 'controller-id', 'OMADA_CLIENT_ID': 'app-id',
               'OMADA_CLIENT_SECRET': 'private-secret', 'OMADA_SITE_ID': 'site/id'}
        self.env = patch.dict('os.environ', env, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.patch = patch('checks.omada.urllib.request.build_opener')
        self.builder = self.patch.start()
        self.opener = self.builder.return_value
        self.addCleanup(self.patch.stop)

    def responses(self, *bodies):
        responses = []
        for body in bodies:
            response = Mock()
            response.__enter__ = Mock(return_value=io.StringIO(json.dumps(body)))
            response.__exit__ = Mock(return_value=False)
            responses.append(response)
        self.opener.open.side_effect = responses

    def test_authentication_and_sites(self):
        self.responses({'errorCode': 0, 'result': {'accessToken': 'AT-test'}},
                       {'errorCode': 0, 'result': {'totalRows': 1, 'data': [{'name': 'Home'}]}})
        ok, details = execute({'type': 'omada'}, 3)
        self.assertTrue(ok)
        self.assertIn('1 sites; sample: Home', details)
        auth, query = [call.args[0] for call in self.opener.open.call_args_list]
        self.assertEqual(auth.method if hasattr(auth, 'method') else auth.get_method(), 'POST')
        self.assertEqual(json.loads(auth.data), {'omadacId': 'controller-id',
                                               'client_id': 'app-id', 'client_secret': 'private-secret'})
        self.assertIn('grant_type=client_credentials', auth.full_url)
        self.assertEqual(query.get_method(), 'GET')
        self.assertEqual(query.get_header('Authorization'), 'AccessToken=AT-test')
        self.assertTrue(query.full_url.endswith('/controller-id/sites?page=1&pageSize=100'))
        self.assertEqual(self.opener.open.call_args.kwargs['timeout'], 3)

    def test_devices_and_clients_escape_site_id(self):
        for resource in ('devices', 'clients'):
            with self.subTest(resource=resource):
                self.responses({'errorCode': 0, 'result': {'accessToken': 'AT-test'}},
                               {'errorCode': 0, 'result': {'totalRows': 0, 'data': []}})
                self.assertTrue(omada({'resource': resource}, 3)[0])
                url = self.opener.open.call_args.args[0].full_url
                self.assertIn(f'/sites/site%2Fid/{resource}?page=1&pageSize=100', url)

    def test_api_rejection_does_not_leak_secrets(self):
        self.responses({'errorCode': -1, 'msg': 'private-secret AT-test'})
        ok, details = omada({}, 3)
        self.assertFalse(ok)
        self.assertNotIn('private-secret', details)
        self.assertNotIn('AT-test', details)

    def test_missing_credentials_skip_network(self):
        with patch.dict('os.environ', {'OMADA_CLIENT_SECRET': ''}):
            self.assertFalse(omada({}, 3)[0])
        self.opener.open.assert_not_called()

    def test_tls_verified_by_default(self):
        OmadaClient({}, 3)
        # Inspect the HTTPS handler supplied to the opener, not a real socket.
        https = self.builder.call_args.args[0]
        self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(https._context.check_hostname)
        OmadaClient({'verify_tls': False}, 3)
        https = self.builder.call_args.args[0]
        self.assertEqual(https._context.verify_mode, ssl.CERT_NONE)

    def test_rejects_unsafe_urls(self):
        for url in ('http://controller.example', 'https://user:secret@controller.example',
                    'https://controller.example/path', 'https://controller.example?x=1'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                OmadaClient({'url': url}, 3)

    def test_http_failure_safe_message(self):
        self.opener.open.side_effect = HTTPError('https://controller.example', 403, 'secret', {}, None)
        self.assertEqual(omada({}, 3), (False, 'Omada OpenAPI HTTP 403; check API address and app permissions'))

    def test_malformed_response_fails(self):
        for body in ({'errorCode': 0, 'result': {}}, {'errorCode': 0, 'result': []}):
            self.responses(body)
            self.assertFalse(omada({}, 3)[0])

    def test_redirects_are_blocked(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.example'))

    def test_resource_report_exposes_selected_fields_only(self):
        from monitor import check_device, format_report
        self.responses({'errorCode': 0, 'result': {'accessToken': 'AT-test'}},
                       {'errorCode': 0, 'result': {'totalRows': 120, 'data': [
                           {'name': 'AP', 'ip': '192.168.1.2', 'cpuUtil': 8,
                            'memUtil': 63, 'status': 1, 'sn': 'private-serial',
                            'unexpectedSecret': 'private-secret'}]}})
        result = check_device({'name': 'Controller', 'checks': [
            {'type': 'omada', 'resource': 'devices', 'resources': True}]}, 3)
        report = format_report([result], 'now')
        self.assertTrue(result['ok'])
        self.assertIn('120 devices; showing 1', report)
        self.assertIn('CPU: 8', report)
        self.assertIn('Memory: 63', report)
        self.assertNotIn('private-', str(result))

    def test_resource_failure_is_reported_as_failed_check(self):
        from monitor import check_device
        self.opener.open.side_effect = HTTPError('https://controller.example', 403, 'secret', {}, None)
        result = check_device({'name': 'Controller', 'checks': [
            {'type': 'omada', 'resource': 'clients', 'resources': True}]}, 3)
        self.assertFalse(result['ok'])
        self.assertIn('HTTP 403', result['checks'][0]['details'])


if __name__ == '__main__':
    unittest.main()
