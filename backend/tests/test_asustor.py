# File: test_asustor.py
# Last updated: 2026-11-11
# Change: Test dynamic NAS discovery, missing telemetry, health and counter calculations.
# Description: Verify ASUSTOR monitoring and reporting without contacting devices.

import asyncio
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from checks import asustor as nas
import monitor

V = nas.VENDOR
IF = '1.3.6.1.2.1.2.2.1'
IFX = '1.3.6.1.2.1.31.1.1.1'


def fixture():
    # Synthetic values, not the user's NAS data.
    return {'connected': True, 'endpoint': 'nas:161', 'timestamp': 1000, 'branches': {}, 'data': {
        nas.IDENTITY[0]: 'Test NAS', nas.IDENTITY[1]: 50000, nas.IDENTITY[2]: 'test-nas',
        V + '.1.2.0': 'test-adm', V + '.2.1.0': 'TestModel', '1.3.6.1.2.1.25.1.1.0': 80000,
        V + '.2.3.1.2.0': 20, V + '.2.3.1.2.1': 40,
        V + '.2.6.1.4.1': 60, V + '.2.5.1.2.1': 45, V + '.2.5.1.3.1': -2147483648,
        V + '.2.4.1.2.1': 1100, V + '.1.7.0': 'The ADM is latest version',
        V + '.4.1.1.2.1': 'Disk0', V + '.4.1.1.5.1': 'Good',
        V + '.4.1.1.6.1': 'Healthy', V + '.4.1.1.7.1': 35, V + '.4.1.1.8.1': 1000,
        V + '.4.1.1.2.7': 'Disk6', V + '.4.1.1.5.7': 'Good',
        V + '.4.1.1.6.7': 'Healthy', V + '.4.1.1.7.7': 37, V + '.4.1.1.8.7': 2000,
        V + '.5.1.1.2.4': 'Volume4', V + '.5.1.1.3.4': 'raid1',
        V + '.5.1.1.4.4': 'healthy', V + '.5.1.1.6.4': 1000, V + '.5.1.1.7.4': 250,
        IF + '.2.2': 'eth0', IF + '.7.2': 1, IF + '.8.2': 1, IF + '.5.2': 1000000000,
        IFX + '.1.2': 'eth0', IFX + '.15.2': 1000, IFX + '.19.2': 0,
        IFX + '.6.2': 10000000000000001, IFX + '.10.2': 20000,
        IF + '.10.2': 10000, IF + '.16.2': 20000,
        IF + '.13.2': 0, IF + '.14.2': 0, IF + '.19.2': 0, IF + '.20.2': 0,
    }}


def metrics(result):
    return {row['name']: row for row in result['resources']}


def statuses(result):
    return {row['name']: row['status'] for row in result['checks']}


class EvaluationTests(unittest.TestCase):
    def test_dynamic_rows_units_and_source_priority(self):
        s = fixture()
        s['data']['1.3.6.1.2.1.25.3.3.1.2.10'] = 99
        result = nas.evaluate(s, {})
        m = metrics(result)
        self.assertEqual(m['CPU']['value'], 30)
        self.assertEqual(m['RAM']['value'], 40)
        self.assertEqual(m['Volume 4 usage']['value'], 75)
        self.assertEqual(m['Volume 4 usage']['free'], 250)
        self.assertEqual(m['Disk 7 capacity']['unit'], 'GB (MIB-reported)')
        self.assertEqual(m['Disk 1 SMART']['value'], 'Healthy')
        self.assertEqual(m['NAS uptime']['value'], 800)
        self.assertEqual(m['SNMP agent uptime']['value'], 500)
        self.assertEqual(m['Interface eth0 link speed']['value'], 1000000000)
        self.assertEqual(len([r for r in result['resources'] if r['name'] == 'CPU']), 1)

    def test_missing_values_are_never_healthy_defaults(self):
        s = fixture()
        s['data'] = {nas.IDENTITY[2]: 'test-nas'}
        result = nas.evaluate(s, {})
        for name in ('CPU', 'RAM', 'Volume capacity', 'Disk I/O statistics'):
            self.assertIsNone(metrics(result)[name]['value'])
            self.assertEqual(metrics(result)[name]['status'], 'UNAVAILABLE')
        self.assertEqual(statuses(result)['CPU utilisation'], 'UNAVAILABLE')
        self.assertEqual(statuses(result)['Disk health'], 'UNAVAILABLE')
        self.assertEqual(statuses(result)['Malware/ransomware detection'], 'UNSUPPORTED')
        for check in result['checks']:
            if check['status'] in ('UNAVAILABLE', 'UNSUPPORTED', 'N/A'):
                self.assertIsNone(check['ok'])

    def test_sentinel_temperature_and_phantom_ups(self):
        s = fixture()
        s['data'].update({V + '.6.1.1.2.1': '', V + '.6.1.1.3.1': '',
                          V + '.6.1.1.7.1': 'OB', V + '.6.1.1.8.1': 0, V + '.6.1.1.9.1': 0})
        result = nas.evaluate(s, {})
        self.assertIsNone(metrics(result)['System temperature']['value'])
        self.assertEqual(statuses(result)['UPS 1 health'], 'N/A')
        self.assertNotIn('UPS 1 battery', metrics(result))

    def test_disk_failure_raid_degradation_and_thresholds(self):
        s = fixture()
        s['data'].update({V + '.4.1.1.5.7': 'Failed', V + '.5.1.1.4.4': 'degraded',
                          V + '.2.5.1.2.1': 90, V + '.5.1.1.7.4': 10,
                          V + '.2.6.1.4.1': 1, V + '.2.4.1.2.1': 0})
        result = nas.evaluate(s, {})
        st = statuses(result)
        self.assertEqual(st['Disk 7 health'], 'FAIL')
        self.assertEqual(st['Volume 4 health'], 'FAIL')
        for name in ('CPU temperature', 'Volume 4 storage usage', 'RAM utilisation', 'Fan 1 speed'):
            self.assertEqual(st[name], 'WARN')

    def test_unknown_status_not_passed(self):
        s = fixture()
        s['data'][V + '.4.1.1.5.1'] = 'not documented'
        self.assertEqual(statuses(nas.evaluate(s, {}))['Disk 1 health'], 'UNAVAILABLE')

    def test_threshold_boundary_and_invalid_configuration(self):
        s = fixture()
        self.assertEqual(statuses(nas.evaluate(s, {'cpu_warn_percent': 30}))['CPU utilisation'], 'OK')
        self.assertEqual(statuses(nas.evaluate(s, {'cpu_warn_percent': 29}))['CPU utilisation'], 'WARN')
        for value in (float('nan'), float('inf'), -1, 101):
            with self.subTest(value=value), self.assertRaises(ValueError):
                nas.evaluate(s, {'cpu_warn_percent': value})

    def test_standard_fallbacks_and_allocation_units(self):
        s = fixture()
        for oid in list(s['data']):
            if oid.startswith((V + '.2.3.', V + '.2.6.', V + '.5.')):
                del s['data'][oid]
        root = '1.3.6.1.2.1.25.2.3.1'
        s['data'].update({'1.3.6.1.2.1.25.3.3.1.2.99': 22,
                          '1.3.6.1.4.1.2021.4.5.0': 1000, '1.3.6.1.4.1.2021.4.6.0': 400,
                          root + '.2.10': '1.3.6.1.2.1.25.2.1.4', root + '.3.10': '/volume1',
                          root + '.4.10': 4096, root + '.5.10': 1000, root + '.6.10': 250,
                          root + '.2.11': '1.3.6.1.2.1.25.2.1.4', root + '.3.11': '/volume1/share',
                          root + '.4.11': 4096, root + '.5.11': 1000, root + '.6.11': 250})
        result = nas.evaluate(s, {})
        m = metrics(result)
        self.assertEqual(m['CPU']['value'], 22)
        self.assertEqual(m['RAM']['value'], 60)
        self.assertEqual(m['Storage /volume1 usage']['value'], 25)
        self.assertEqual(m['Storage /volume1 usage']['total'], 4096000)
        self.assertNotIn('Storage /volume1/share usage', m)
        self.assertEqual(statuses(result)['RAID/volume health'], 'UNAVAILABLE')

    def test_ram_host_resources_and_cpu_idle_fallback(self):
        s = fixture()
        for oid in list(s['data']):
            if oid.startswith((V + '.2.3.', V + '.2.6.')):
                del s['data'][oid]
        root = '1.3.6.1.2.1.25.2.3.1'
        s['data'].update({'1.3.6.1.4.1.2021.11.11.0': 75,
                          root + '.2.1': '1.3.6.1.2.1.25.2.1.2', root + '.5.1': 1000, root + '.6.1': 250})
        m = metrics(nas.evaluate(s, {}))
        self.assertEqual(m['CPU']['value'], 25)
        self.assertEqual(m['RAM']['value'], 25)

    def test_identified_ups_battery_and_runtime(self):
        s = fixture()
        s['data'].update({V + '.6.1.1.3.2': 'Test UPS', V + '.6.1.1.7.2': 'OB LB',
                          V + '.6.1.1.8.2': 120, V + '.6.1.1.9.2': 10})
        result = nas.evaluate(s, {})
        self.assertEqual(statuses(result)['UPS 2 power'], 'FAIL')
        self.assertEqual(statuses(result)['UPS 2 battery'], 'WARN')
        self.assertEqual(metrics(result)['UPS 2 runtime']['value'], 120)

    def test_required_interface_vs_disabled_interface(self):
        s = fixture()
        s['data'][IF + '.8.2'] = 2
        self.assertEqual(statuses(nas.evaluate(s, {'required_interfaces': ['eth0']}))['Interface eth0 connection'], 'FAIL')
        s['data'][IF + '.7.2'] = 2
        self.assertEqual(statuses(nas.evaluate(s, {}))['Interface eth0 connection'], 'N/A')
        self.assertEqual(statuses(nas.evaluate(s, {'required_interfaces': ['missing']}))['Interface missing connection'], 'FAIL')

    def test_disk_io_counters_and_unknown_update_status(self):
        s = fixture()
        root = '1.3.6.1.4.1.2021.13.15.1.1'
        s['data'].update({root + '.2.3': 'sdc', root + '.12.3': 2**60 + 1, root + '.3.3': 99,
                          V + '.1.7.0': 'unrecognized'})
        result = nas.evaluate(s, {})
        self.assertEqual(metrics(result)['Disk I/O sdc bytes read']['value'], 2**60 + 1)
        self.assertEqual(statuses(result)['ADM update availability'], 'UNAVAILABLE')

    def test_invalid_volume_counters_do_not_report_zero_or_healthy(self):
        s = fixture()
        for total, free in [(0, 0), (100, 101), (-1, 50)]:
            with self.subTest(total=total, free=free):
                s['data'][V + '.5.1.1.6.4'] = total
                s['data'][V + '.5.1.1.7.4'] = free
                result = nas.evaluate(s, {})
                self.assertIsNone(metrics(result)['Volume 4 usage']['value'])
                self.assertEqual(statuses(result)['Volume 4 storage usage'], 'UNAVAILABLE')

    def test_volume_fallback_replaces_missing_capacity_without_duplication(self):
        s = fixture()
        del s['data'][V + '.5.1.1.6.4']
        root = '1.3.6.1.2.1.25.2.3.1'
        s['data'].update({root + '.2.40': '1.3.6.1.2.1.25.2.1.4', root + '.3.40': '/volume4',
                          root + '.4.40': 1024, root + '.5.40': 1000, root + '.6.40': 300})
        result = nas.evaluate(s, {})
        self.assertEqual(metrics(result)['Volume 4 usage']['value'], 30)
        self.assertEqual(sum(r['name'] == 'Volume 4 usage' for r in result['resources']), 1)
        self.assertEqual(statuses(result)['Volume 4 health'], 'OK')


class CounterTests(unittest.TestCase):
    def setUp(self):
        self.old = fixture()
        self.new = copy.deepcopy(self.old)
        self.new['timestamp'] += 10
        self.new['data'][nas.IDENTITY[1]] += 1000
        self.new['data']['1.3.6.1.2.1.25.1.1.0'] += 1000
        self.new['data'][IFX + '.6.2'] += 21000000

    def test_exact_64_bit_delta_and_mb_units(self):
        m = metrics(nas.evaluate(self.new, {}, self.old))
        self.assertEqual(m['Interface eth0 RX rate']['value'], 2100000)
        self.assertEqual(m['Interface eth0 RX rate']['display'], '2.100 MB/s')
        self.assertEqual(statuses(nas.evaluate(self.new, {}, self.old))['Interface eth0 errors/drops'], 'OK')

    def test_reset_discontinuity_changed_identity_and_time(self):
        changes = [(nas.IDENTITY[1], 1), (IFX + '.19.2', 100), (IFX + '.1.2', 'renamed'),
                   (IFX + '.6.2', 1)]
        for oid, value in changes:
            with self.subTest(oid=oid):
                s = copy.deepcopy(self.new)
                s['data'][oid] = value
                self.assertIsNone(metrics(nas.evaluate(s, {}, self.old))['Interface ' + ('renamed' if oid == IFX + '.1.2' else 'eth0') + ' RX rate']['value'])
        self.new['timestamp'] = 1
        self.assertIsNone(metrics(nas.evaluate(self.new, {}, self.old))['Interface eth0 RX rate']['value'])

    def test_32_bit_wrap_and_ambiguous_long_interval(self):
        for s in (self.old, self.new):
            del s['data'][IFX + '.6.2']
            s['data'][IFX + '.15.2'] = 100
        self.old['data'][IF + '.10.2'] = 2**32 - 100
        self.new['data'][IF + '.10.2'] = 100
        self.assertEqual(metrics(nas.evaluate(self.new, {}, self.old))['Interface eth0 RX rate']['value'], 20)
        self.new['timestamp'] += 1000
        self.assertIsNone(metrics(nas.evaluate(self.new, {}, self.old))['Interface eth0 RX rate']['value'])

    def test_increasing_errors_warn_without_using_historical_total(self):
        self.old['data'][IF + '.14.2'] = 200
        self.new['data'][IF + '.14.2'] = 200
        self.new['timestamp'] += 300
        self.new['data'][nas.IDENTITY[1]] += 30000
        self.new['data']['1.3.6.1.2.1.25.1.1.0'] += 30000
        self.assertEqual(statuses(nas.evaluate(self.new, {}, self.old))['Interface eth0 errors/drops'], 'OK')
        self.new['data'][IF + '.14.2'] = 201
        self.assertEqual(statuses(nas.evaluate(self.new, {}, self.old))['Interface eth0 errors/drops'], 'WARN')

    def test_restart_between_polls_even_if_current_uptime_is_higher(self):
        self.new['timestamp'] += 3000
        self.assertIsNone(metrics(nas.evaluate(self.new, {}, self.old))['Interface eth0 RX rate']['value'])

    def test_branch_timestamps_used_instead_of_whole_poll_time(self):
        self.old['branches']['interface_counters'] = {'timestamp': 995}
        self.new['branches']['interface_counters'] = {'timestamp': 1000}
        self.assertEqual(metrics(nas.evaluate(self.new, {}, self.old))['Interface eth0 RX rate']['value'], 4200000)

    def test_counter32_fallback_without_ifx_and_no_baseline(self):
        for s in (self.old, self.new):
            s['data'] = {k: v for k, v in s['data'].items() if not k.startswith(IFX + '.')}
            s['data'][IF + '.5.2'] = 100000000
        self.new['data'][IF + '.10.2'] += 10000
        result = nas.evaluate(self.new, {}, self.old)
        self.assertEqual(metrics(result)['Interface eth0 RX rate']['value'], 1000)
        result = nas.evaluate(self.new, {})
        self.assertIsNone(metrics(result)['Interface eth0 RX rate']['value'])


class CollectionTests(unittest.TestCase):
    @patch.dict(os.environ, {'ASUSTOR_SNMP_HOST': 'nas', 'ASUSTOR_SNMP_USERNAME': 'monitor',
                            'ASUSTOR_SNMP_PASSWORD': 'secret-password'})
    def test_bounded_read_only_discovery_no_such_object_and_cleanup(self):
        from pysnmp.proto.rfc1902 import Integer, OctetString, ObjectName
        from pysnmp.proto.rfc1905 import NoSuchObject
        from pysnmp.hlapi.v3arch.asyncio import USM_AUTH_HMAC96_MD5, USM_PRIV_NONE
        async def walk(*args, **kwargs):
            self.assertFalse(kwargs['lexicographicMode'])
            yield None, 0, 0, [(ObjectName(V + '.2.1.0'), OctetString('TestModel')),
                               (ObjectName(V + '.2.2.0'), NoSuchObject()),
                               (ObjectName('1.3.6.1.4.1.99999.1.0'), Integer(99))]
        with patch('pysnmp.hlapi.v3arch.asyncio.SnmpEngine') as engine, \
                patch('pysnmp.hlapi.v3arch.asyncio.UsmUserData') as auth, \
                patch('pysnmp.hlapi.v3arch.asyncio.UdpTransportTarget.create', new_callable=AsyncMock), \
                patch('pysnmp.hlapi.v3arch.asyncio.get_cmd', new_callable=AsyncMock,
                      return_value=(None, 0, 0, [(ObjectName(nas.IDENTITY[2]), OctetString('test'))])), \
                patch('pysnmp.hlapi.v3arch.asyncio.bulk_walk_cmd', side_effect=walk), \
                patch.dict(nas.BRANCHES, {'hardware': V + '.2'}, clear=True):
            result = asyncio.run(nas.collect({}, 3))
            self.assertTrue(result['connected'])
            self.assertEqual(result['branches']['hardware']['count'], 1)
            self.assertNotIn(V + '.2.2.0', result['data'])
            self.assertNotIn('1.3.6.1.4.1.99999.1.0', result['data'])
            auth.assert_called_once_with(userName='monitor', authKey='secret-password',
                                         authProtocol=USM_AUTH_HMAC96_MD5, privProtocol=USM_PRIV_NONE)
            engine.return_value.close_dispatcher.assert_called_once()

    @patch.dict(os.environ, {'ASUSTOR_SNMP_HOST': 'nas', 'ASUSTOR_SNMP_USERNAME': 'monitor',
                            'ASUSTOR_SNMP_PASSWORD': 'secret-password'})
    def test_auth_failure_stops_discovery(self):
        with patch('pysnmp.hlapi.v3arch.asyncio.SnmpEngine') as engine, \
                patch('pysnmp.hlapi.v3arch.asyncio.UdpTransportTarget.create', new_callable=AsyncMock), \
                patch('pysnmp.hlapi.v3arch.asyncio.get_cmd', new_callable=AsyncMock,
                      return_value=('Wrong SNMP PDU digest secret-password', 0, 0, [])), \
                patch('pysnmp.hlapi.v3arch.asyncio.bulk_walk_cmd') as walk:
            result = asyncio.run(nas.collect({}, 3))
            self.assertFalse(result['connected'])
            self.assertIn('authentication', result['error'])
            self.assertNotIn('secret-password', str(result))
            walk.assert_not_called()
            engine.return_value.close_dispatcher.assert_called_once()

    @patch.dict(os.environ, {'ASUSTOR_SNMP_HOST': 'nas', 'ASUSTOR_SNMP_USERNAME': 'monitor',
                            'ASUSTOR_SNMP_PASSWORD': 'secret-password'})
    def test_branch_timeout_preserves_connection_and_marks_incomplete(self):
        from pysnmp.proto.rfc1902 import OctetString, ObjectName
        async def timeout_walk(*args, **kwargs):
            raise TimeoutError
            yield  # Make this an async generator without performing network I/O.
        with patch('pysnmp.hlapi.v3arch.asyncio.SnmpEngine'), \
                patch('pysnmp.hlapi.v3arch.asyncio.UdpTransportTarget.create', new_callable=AsyncMock), \
                patch('pysnmp.hlapi.v3arch.asyncio.get_cmd', new_callable=AsyncMock,
                      return_value=(None, 0, 0, [(ObjectName(nas.IDENTITY[2]), OctetString('test'))])), \
                patch('pysnmp.hlapi.v3arch.asyncio.bulk_walk_cmd', side_effect=timeout_walk), \
                patch.dict(nas.BRANCHES, {'disks': V + '.4'}, clear=True):
            snapshot = asyncio.run(nas.collect({}, 3))
        self.assertTrue(snapshot['connected'])
        self.assertEqual(snapshot['branches']['disks']['status'], 'UNAVAILABLE')
        self.assertEqual(statuses(nas.evaluate(snapshot, {}))['disks discovery'], 'WARN')

    def test_cache_round_trip_keeps_only_counter_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.json'
            self.assertIsNone(nas.load_baseline(path))
            nas.save_baseline(path, fixture())
            baseline = nas.load_baseline(path)
            self.assertIn(IFX + '.6.2', baseline['data'])
            self.assertNotIn(V + '.1.2.0', baseline['data'])
            self.assertNotIn(nas.IDENTITY[2], baseline['data'])
            path.write_text('{broken')
            self.assertIsNone(nas.load_baseline(path))


class IntegrationTests(unittest.TestCase):
    def test_dispatch_report_unknown_status_and_logs(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch('checks.asustor.asustor', return_value=nas.evaluate(fixture(), {})):
            result = monitor.check_device({'name': 'NAS', 'checks': [{'type': 'snmp', 'resources': True}]}, 3)
            self.assertTrue(result['ok'])
            text = monitor.format_report([result], 'test-time')
            self.assertIn('    Resources:', text)
            self.assertIn('UNSUPPORTED Malware/ransomware', text)
            self.assertNotIn('OK   Malware', text)
            self.assertIn('UNAVAILABLE System temperature', text)
            monitor.save_report(text, Path(directory))
            monitor.save_report('next report', Path(directory))
            self.assertEqual((Path(directory) / 'latest.log').read_text(), 'next report\n')
            history = (Path(directory) / 'history.log').read_text()
            self.assertIn('test-time', history)
            self.assertIn('next report', history)
            json.dumps(result, allow_nan=False)

    def test_disk_failure_propagates_to_device_and_report(self):
        s = fixture()
        s['data'][V + '.4.1.1.5.7'] = 'Failed'
        with patch('checks.asustor.asustor', return_value=nas.evaluate(s, {})):
            result = monitor.check_device({'name': 'NAS', 'checks': [{'type': 'snmp', 'resources': True}]}, 3)
        self.assertFalse(result['ok'])
        self.assertIn('FAIL Disk 7 health', monitor.format_report([result], 'now'))

    def test_main_json_logging_and_failure_recovery_notifications(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config = base / 'config.json'
            state = base / 'state.json'
            config.write_text(json.dumps({'devices': [{'name': 'NAS', 'checks': [{'type': 'snmp', 'resources': True}]}],
                                           'log_directory': str(base)}))
            with patch('sys.argv', ['monitor.py', '--config', str(config), '--state', str(state), '--json']), \
                    patch('monitor.load_dotenv'), \
                    patch.dict(os.environ, {'HOMELAB_WEBHOOK_URL': 'https://example.invalid/hook'}), \
                    patch('monitor.send_webhook') as notify, \
                    patch('checks.asustor.asustor') as poll, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                s = fixture()
                poll.return_value = nas.evaluate(s, {})
                self.assertEqual(monitor.main(), 0)
                self.assertEqual(notify.call_count, 1)
                payload = json.loads(output.getvalue())
                self.assertIn('resources', payload['devices'][0])
                output.seek(0)
                output.truncate()
                self.assertEqual(monitor.main(), 0)
                self.assertEqual(notify.call_count, 1)
                s['data'][V + '.4.1.1.5.7'] = 'Failed'
                poll.return_value = nas.evaluate(s, {})
                self.assertEqual(monitor.main(), 1)
                self.assertEqual(notify.call_count, 2)
                poll.return_value = nas.evaluate(fixture(), {})
                self.assertEqual(monitor.main(), 0)
                self.assertEqual(notify.call_count, 3)
            self.assertIn('OK   Disk 7 health', (base / 'latest.log').read_text())
            history = (base / 'history.log').read_text()
            self.assertIn('FAIL Disk 7 health', history)
            self.assertEqual(history.count('Home Lab Status'), 4)

    def test_counter_cache_write_failure_does_not_hide_resources(self):
        with patch('checks.asustor.cache_path', return_value=Path('unused.json')), \
                patch('checks.asustor.load_baseline', return_value=None), \
                patch('checks.asustor.collect', new_callable=AsyncMock, return_value=fixture()), \
                patch('checks.asustor.save_baseline', side_effect=OSError):
            result = nas.asustor({}, 3)
        self.assertEqual(metrics(result)['CPU']['value'], 30)
        self.assertEqual(statuses(result)['SNMP counter cache'], 'WARN')


if __name__ == '__main__':
    unittest.main()
