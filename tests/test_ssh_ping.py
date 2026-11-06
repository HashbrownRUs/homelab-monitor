# File: test_ssh_ping.py
# Last updated: 2026-11-07
# Description: Test SSH ping commands, reply detection, credentials, and input validation.

import os
import unittest
from unittest.mock import Mock, patch

import paramiko
from checks import execute


class SSHPingTests(unittest.TestCase):
    def setUp(self):
        self.item = {'type': 'ssh_ping', 'ssh_host': '192.168.88.254',
                     'ssh_user': 'monitor', 'host': '1.1.1.1', 'count': 4}

    @patch.dict(os.environ, {'MONITORING_SERVER_SSH_PASSWORD': 'test-secret'})
    @patch('checks.ssh_ping.paramiko.SSHClient')
    def test_remote_command_and_reply_detection(self, factory):
        client = factory.return_value
        stdout = Mock()
        client.exec_command.return_value = (Mock(), stdout, Mock())
        stdout.channel.recv_exit_status.return_value = 0
        for output, expected in [(b'Reply from 1.1.1.1: bytes=32 time=5ms TTL=57', True),
                                 (b'Reply from 192.168.88.1: Destination host unreachable.', False)]:
            stdout.read.return_value = output
            self.assertEqual(execute(self.item, 10)[0], expected)
        client.exec_command.assert_called_with('ping -n 4 1.1.1.1', timeout=30)
        self.assertEqual(client.connect.call_args.kwargs['password'], 'test-secret')
        client.load_system_host_keys.assert_called()
        client.close.assert_called()

    @patch.dict(os.environ, {}, clear=True)
    @patch('checks.ssh_ping.paramiko.SSHClient')
    def test_missing_password(self, factory):
        self.assertFalse(execute(self.item, 10)[0])
        factory.assert_not_called()

    @patch.dict(os.environ, {'MONITORING_SERVER_SSH_PASSWORD': 'test-secret'})
    @patch('checks.ssh_ping.paramiko.SSHClient')
    def test_auth_failure_does_not_expose_secret(self, factory):
        factory.return_value.connect.side_effect = paramiko.AuthenticationException('test-secret')
        ok, details = execute(self.item, 10)
        self.assertFalse(ok)
        self.assertNotIn('test-secret', details)
        factory.return_value.close.assert_called_once()

    def test_reject_shell_input(self):
        self.item['host'] = '1.1.1.1 & whoami'
        with self.assertRaises(ValueError):
            execute(self.item, 10)
