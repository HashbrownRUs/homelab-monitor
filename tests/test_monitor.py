import unittest
from unittest.mock import patch, Mock
import monitor

class PingTests(unittest.TestCase):
    @patch('checks.ping.subprocess.run')
    @patch('checks.ping.platform.system', return_value='Windows')
    def test_windows(self, system, run):
        run.return_value = Mock(returncode=0)
        self.assertEqual(monitor.ping('127.0.0.1', 2), (True, 'ICMP reply'))
        self.assertEqual(run.call_args.args[0], ['ping', '-n', '1', '-w', '2000', '127.0.0.1'])

    @patch('checks.ping.subprocess.run')
    @patch('checks.ping.platform.system', return_value='Linux')
    def test_linux(self, system, run):
        run.return_value = Mock(returncode=1)
        self.assertEqual(monitor.ping('127.0.0.1', 2), (False, 'No ICMP reply'))
        self.assertEqual(run.call_args.args[0], ['ping', '-n', '-c', '1', '-W', '2', '127.0.0.1'])

    @patch('checks.ping.platform.system', return_value='Darwin')
    def test_unsupported(self, system):
        self.assertFalse(monitor.ping('localhost', 1)[0])

class WebPolicyTests(unittest.TestCase):
    @patch('checks.tcp')
    def test_tcp_web_ports(self, tcp):
        for plain, secure in [(True, True), (False, True), (True, False), (False, False)]:
            with self.subTest(plain=plain, secure=secure):
                tcp.reset_mock()
                tcp.side_effect = [(plain, 'plain'), (secure, 'secure')]
                ok, details = monitor.execute({'type': 'tcp', 'host': 'router', 'port': 80}, 2)
                self.assertEqual(ok, plain or secure)
                self.assertEqual(tcp.call_args_list[1].args, ('router', 443, 2))
                self.assertEqual(details.startswith('WARNING:'), plain != secure)

    @patch('checks.http')
    def test_http_fallback_and_report(self, http):
        http.side_effect = [(False, 'refused'), (True, 'HTTP 200')]
        result = monitor.check_device({'name': 'router', 'checks': [
            {'type': 'http', 'url': 'http://router:80/admin?q=1', 'verify_tls': False}
        ]}, 2)
        self.assertTrue(result['ok'])
        self.assertTrue(result['checks'][0]['warning'])
        self.assertIn('WARN', monitor.format_report([result], 'now'))
        self.assertEqual(http.call_args_list[1].args, ('https://router:443/admin?q=1', 2, False))

    @patch('checks.http', return_value=(False, 'HTTP 500'))
    def test_custom_http_port_remains_failure(self, http):
        self.assertFalse(monitor.execute({'type': 'http', 'url': 'http://router:8080'}, 2)[0])
        http.assert_called_once()

    @patch('checks.tcp', return_value=(False, 'refused'))
    def test_explicit_https_failure(self, tcp):
        self.assertFalse(monitor.execute({'type': 'tcp', 'host': 'router', 'port': 443}, 2)[0])
        tcp.assert_called_once()


if __name__ == '__main__':
    unittest.main()
