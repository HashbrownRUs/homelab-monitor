import unittest
from unittest.mock import patch, Mock
import monitor

class PingTests(unittest.TestCase):
    @patch('monitor.subprocess.run')
    @patch('monitor.platform.system', return_value='Windows')
    def test_windows(self, system, run):
        run.return_value = Mock(returncode=0)
        self.assertEqual(monitor.ping('127.0.0.1', 2), (True, 'ICMP reply'))
        self.assertEqual(run.call_args.args[0], ['ping', '-n', '1', '-w', '2000', '127.0.0.1'])

    @patch('monitor.subprocess.run')
    @patch('monitor.platform.system', return_value='Linux')
    def test_linux(self, system, run):
        run.return_value = Mock(returncode=1)
        self.assertEqual(monitor.ping('127.0.0.1', 2), (False, 'No ICMP reply'))
        self.assertEqual(run.call_args.args[0], ['ping', '-n', '-c', '1', '-W', '2', '127.0.0.1'])

    @patch('monitor.platform.system', return_value='Darwin')
    def test_unsupported(self, system):
        self.assertFalse(monitor.ping('localhost', 1)[0])

if __name__ == '__main__':
    unittest.main()
