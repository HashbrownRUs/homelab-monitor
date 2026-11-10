# File: test_snmp.py
# Last updated: 2026-11-11
# Change: Verify MD5 authentication and NAS protocol failures without network access.
# Description: Exercise SNMPv3 readings, cleanup, and monitor failure reporting.

import importlib
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import monitor

snmp = importlib.import_module('checks.snmp')


class SnmpTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {
            'ASUSTOR_SNMP_HOST': 'nas', 'ASUSTOR_SNMP_USERNAME': 'monitor',
            'ASUSTOR_SNMP_PASSWORD': 'secret-password', 'ASUSTOR_SNMP_PORT': '161',
        })
        env.start()
        self.addCleanup(env.stop)

    def run_check(self, responses):
        value = MagicMock()
        value.prettyPrint.return_value = 'NAS reading'
        responses = [(None, 0, 0, [(None, value)])] * 3 if responses is None else responses
        with patch('pysnmp.hlapi.v3arch.asyncio.SnmpEngine') as engine, \
                patch('pysnmp.hlapi.v3arch.asyncio.UsmUserData') as credentials, \
                patch('pysnmp.hlapi.v3arch.asyncio.UdpTransportTarget.create', new_callable=AsyncMock) as target, \
                patch('pysnmp.hlapi.v3arch.asyncio.get_cmd', new_callable=AsyncMock, side_effect=responses) as request:
            result = monitor.check_device({'name': 'NAS', 'checks': [{'type': 'snmp'}]}, 3)
            engine.return_value.close_dispatcher.assert_called_once()
            from pysnmp.hlapi.v3arch.asyncio import USM_AUTH_HMAC96_MD5
            credentials.assert_called_once_with(
                userName='monitor', authKey='secret-password',
                authProtocol=USM_AUTH_HMAC96_MD5)
            for call in request.await_args_list:
                self.assertIs(call.args[1], credentials.return_value)
            target.assert_awaited_once_with(('nas', 161), timeout=3, retries=1)
            return result, request.await_count

    def test_success(self):
        result, count = self.run_check(None)
        self.assertTrue(result['ok'])
        self.assertEqual(count, 3)
        for name in snmp.OIDS:
            self.assertIn(name, result['checks'][0]['details'])

    def test_request_failure_and_no_secret(self):
        result, count = self.run_check([('secret-password', 0, 0, [])] * 3)
        self.assertFalse(result['ok'])
        self.assertEqual(count, 3)
        self.assertNotIn('secret-password', result['checks'][0]['details'])

    def test_missing_oid(self):
        from pysnmp.proto.rfc1905 import NoSuchInstance
        result, _ = self.run_check([(None, 0, 0, [(None, NoSuchInstance())])] * 3)
        self.assertFalse(result['ok'])
        self.assertIn('OID unavailable', result['checks'][0]['details'])

    def test_exception_closes_engine(self):
        result, _ = self.run_check(RuntimeError('secret-password'))
        self.assertFalse(result['ok'])
        self.assertNotIn('secret-password', result['checks'][0]['details'])

    def test_missing_credentials(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(snmp.snmp({}, 3)[0])

    def test_invalid_port(self):
        result = monitor.check_device({'name': 'NAS', 'checks': [{'type': 'snmp', 'port': 0}]}, 3)
        self.assertFalse(result['ok'])


if __name__ == '__main__':
    unittest.main()
