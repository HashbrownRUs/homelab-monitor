# File: asustor.py
# Last updated: 2026-11-11
# Change: Discover read-only ASUSTOR and standard SNMP resources.
# Description: Collect SNMPv3 MD5 snapshots and evaluate NAS health without assuming missing data is healthy.

import asyncio
import hashlib
import json
import math
import os
from pathlib import Path
import time
import tempfile

BASE = Path(__file__).resolve().parent.parent
VENDOR = '1.3.6.1.4.1.44738'
BRANCHES = {
    'system': VENDOR + '.1', 'hardware': VENDOR + '.2',
    'vendor_network': VENDOR + '.3', 'disks': VENDOR + '.4',
    'volumes': VENDOR + '.5', 'ups': VENDOR + '.6',
    'host_system': '1.3.6.1.2.1.25.1',
    'host_storage': '1.3.6.1.2.1.25.2.3',
    'host_devices': '1.3.6.1.2.1.25.3.2',
    'host_cpu': '1.3.6.1.2.1.25.3.3',
    'interfaces': '1.3.6.1.2.1.2.2',
    'interface_counters': '1.3.6.1.2.1.31.1.1',
    'memory': '1.3.6.1.4.1.2021.4',
    'load': '1.3.6.1.4.1.2021.10',
    'cpu_stats': '1.3.6.1.4.1.2021.11',
    'disk_io': '1.3.6.1.4.1.2021.13.15',
}
IDENTITY = ['1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.3.0', '1.3.6.1.2.1.1.5.0']


def connection(item):
    host = item.get('host') or os.getenv('ASUSTOR_SNMP_HOST')
    username = os.getenv(item.get('username_env', 'ASUSTOR_SNMP_USERNAME'))
    password = os.getenv(item.get('password_env', 'ASUSTOR_SNMP_PASSWORD'))
    if not host or not username or not password:
        raise ValueError('Set ASUSTOR_SNMP_HOST, ASUSTOR_SNMP_USERNAME and ASUSTOR_SNMP_PASSWORD')
    port = int(item.get('port', os.getenv('ASUSTOR_SNMP_PORT', '161')))
    if not 1 <= port <= 65535:
        raise ValueError('SNMP port must be between 1 and 65535')
    return host, port, username, password


def error_hint(error):
    text = str(error).lower()
    if any(word in text for word in ('digest', 'auth', 'user', 'security')):
        return 'SNMPv3 authentication failed; verify username, MD5 password and authNoPriv access'
    if 'timeout' in text or 'timed out' in text:
        return 'SNMP request timed out; verify NAS connectivity and UDP 161 access'
    return 'SNMP request failed; verify connectivity and read-only SNMP access'


async def collect(item, timeout):
    """Discover actual instances. GET/GETBULK only; numeric OIDs need no MIB compiler."""
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, UsmUserData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, USM_AUTH_HMAC96_MD5, USM_PRIV_NONE,
        get_cmd, bulk_walk_cmd,
    )
    from pysnmp.proto.rfc1905 import NoSuchObject, NoSuchInstance, EndOfMibView
    from pysnmp.proto.rfc1902 import OctetString, ObjectIdentifier

    host, port, username, password = connection(item)
    engine = SnmpEngine()
    data, branches = {}, {}
    missing = (NoSuchObject, NoSuchInstance, EndOfMibView)

    def store_values(values):
        count = 0
        for oid, value in values:
            if isinstance(value, missing):
                continue
            key = str(oid)
            if isinstance(value, ObjectIdentifier):
                data[key] = str(value)
            elif isinstance(value, OctetString):
                data[key] = value.prettyPrint()
            else:
                try:
                    data[key] = int(value)
                except (ValueError, TypeError):
                    data[key] = value.prettyPrint()
            count += 1
        return count

    try:
        auth = UsmUserData(userName=username, authKey=password,
                           authProtocol=USM_AUTH_HMAC96_MD5, privProtocol=USM_PRIV_NONE)
        target = await UdpTransportTarget.create((host, port), timeout=timeout, retries=1)
        context = ContextData()
        error, status, _, values = await get_cmd(
            engine, auth, target, context,
            *(ObjectType(ObjectIdentity(oid)) for oid in IDENTITY), lookupMib=False)
        if error or status:
            return {'connected': False, 'error': error_hint(error or status), 'data': {}, 'branches': {}}
        if not store_values(values):
            return {'connected': False, 'error': 'SNMP identity OIDs unavailable; check read permissions',
                    'data': {}, 'branches': {}}
        budget = float(item.get('poll_budget_seconds', 60))
        if not math.isfinite(budget) or budget <= 0:
            raise ValueError('poll_budget_seconds must be positive and finite')
        deadline = time.monotonic() + budget
        for name, root in BRANCHES.items():
            count = 0
            calls = 0
            issue = None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                branches[name] = {'status': 'UNAVAILABLE', 'reason': 'Poll time budget exhausted', 'count': 0}
                continue
            try:
                async with asyncio.timeout(min(remaining, max(5, timeout * 3))):
                    async for error, status, _, values in bulk_walk_cmd(
                        engine, auth, target, context, 0, 25, ObjectType(ObjectIdentity(root)),
                        lexicographicMode=False, lookupMib=False, maxCalls=100,
                    ):
                        calls += 1
                        if error or status:
                            issue = error_hint(error or status)
                            break
                        inside = [(oid, value) for oid, value in values if str(oid).startswith(root + '.')]
                        count += store_values(inside)
                        if count >= 2000:
                            issue = 'Walk limit reached; branch is incomplete'
                            break
                    else:
                        if calls >= 100:
                            issue = 'Walk limit reached; branch is incomplete'
            except TimeoutError:
                issue = 'Branch discovery timed out'
            branches[name] = {'status': 'UNAVAILABLE' if issue or not count else 'SUPPORTED',
                              'reason': issue or ('' if count else 'No readable instances; absent or restricted by SNMP view'),
                              'count': count, 'timestamp': time.time()}
        return {'connected': True, 'data': data, 'branches': branches, 'timestamp': time.time(),
                'endpoint': f'{host}:{port}'}
    finally:
        engine.close_dispatcher()


def number(value, minimum=None, maximum=None):
    """Reject missing, nonnumeric, sentinel and nonfinite values."""
    try:
        if value is None or isinstance(value, bool):
            return None
        result = float(value)
        if not math.isfinite(result):
            return None
        if (minimum is not None and result < minimum) or (maximum is not None and result > maximum):
            return None
        return result
    except (ValueError, TypeError, OverflowError):
        return None


def counter(value, bits=64):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    try:
        result = int(value)
        return result if 0 <= result < 2 ** bits else None
    except ValueError:
        return None


def table(data, root):
    """Group column.instance OIDs by their complete instance suffix."""
    rows = {}
    for oid, value in data.items():
        if oid.startswith(root + '.'):
            suffix = oid[len(root) + 1:].split('.')
            if len(suffix) >= 2:
                rows.setdefault('.'.join(suffix[1:]), {})[int(suffix[0])] = value
    return dict(sorted(rows.items(), key=lambda row: tuple(map(int, row[0].split('.')))))


def duration(seconds):
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f'{days}d {hours}h {minutes}m {seconds}s'


def threshold(item, name, default, maximum=100):
    value = number(item.get(name, default), 0, maximum)
    if value is None:
        raise ValueError(f'{name} must be finite and between 0 and {maximum}')
    return value


def validate_options(item):
    for name, default, maximum in [
        ('cpu_warn_percent', 80, 100), ('memory_warn_percent', 85, 100),
        ('disk_warn_percent', 90, 100), ('cpu_temp_warn_c', 80, 150),
        ('disk_temp_warn_c', 50, 150), ('system_temp_warn_c', 60, 150),
        ('ups_battery_warn_percent', 20, 100), ('ups_runtime_warn_seconds', 300, 86400),
    ]:
        threshold(item, name, default, maximum)
    budget = number(item.get('poll_budget_seconds', 60), 0)
    if budget is None or budget == 0:
        raise ValueError('poll_budget_seconds must be positive and finite')
    interfaces = item.get('required_interfaces', [])
    if not isinstance(interfaces, list) or any(not isinstance(v, str) or not v.strip() for v in interfaces):
        raise ValueError('required_interfaces must be a list of nonempty interface names')


def counter_rate(current, previous, oid, bits, speed_bps=None, discontinuity=None, identity=None,
                 sample_branch='interface_counters', max_age=86400):
    """Return bytes/s only for comparable, continuous samples; otherwise return a reason."""
    unavailable = 'Need a second continuous sample'
    if not previous or previous.get('endpoint') != current.get('endpoint'):
        return None, unavailable
    now, old = current.get('data', {}), previous.get('data', {})
    def stamp(snapshot):
        return snapshot.get('branches', {}).get(sample_branch, {}).get('timestamp', snapshot.get('timestamp'))
    t1, t0 = number(stamp(current)), number(stamp(previous))
    if t1 is None or t0 is None or not 0 < t1 - t0 <= max_age:
        return None, 'Sample interval invalid or too old'
    dt = t1 - t0
    # SNMP agent restart and host reboot both invalidate cumulative counters.
    checked_uptime = False
    for uptime in ('1.3.6.1.2.1.1.3.0', '1.3.6.1.2.1.25.1.1.0'):
        a, b = number(now.get(uptime), 0), number(old.get(uptime), 0)
        if a is not None and b is not None:
            checked_uptime = True
            if a < b:
                return None, 'Uptime reset; baseline renewed'
            if abs((a - b) / 100 - dt) > max(5, dt * 0.05):
                return None, 'Uptime and sample interval disagree; baseline renewed'
    if not checked_uptime:
        return None, 'No comparable uptime to validate counter continuity'
    if identity and (now.get(identity) is None or now.get(identity) != old.get(identity)):
        return None, 'Interface identity changed or unavailable'
    if discontinuity and (now.get(discontinuity) is None or old.get(discontinuity) is None
                          or now[discontinuity] != old[discontinuity]):
        return None, 'Counter discontinuity changed or unavailable'
    a, b = counter(now.get(oid), bits), counter(old.get(oid), bits)
    if a is None or b is None:
        return None, unavailable
    # Keep integer precision for Counter64; floats lose low bits above 2**53.
    if bits == 32 and (not speed_bps or speed_bps * dt / 8 >= 2 ** 32):
        return None, '32-bit counter may wrap more than once; interval is too long'
    if a < b:
        if bits != 32 or not discontinuity:
            return None, 'Counter decreased; baseline renewed'
        delta = (a - b) % (2 ** 32)
    else:
        delta = a - b
    rate = delta / dt
    if speed_bps and rate * 8 > speed_bps * 1.05:
        return None, 'Counter delta exceeds link capacity; baseline renewed'
    return rate, ''


class Report:
    def __init__(self, snapshot):
        self.result = {'checks': [], 'resources': [], 'coverage': [],
                       'capabilities': snapshot.get('branches', {})}

    def check(self, name, status, details):
        self.result['checks'].append({'name': name, 'status': status,
                                     'ok': True if status in ('OK', 'WARN') else False if status == 'FAIL' else None,
                                     'warning': status == 'WARN', 'details': details, 'resource': False})

    def metric(self, name, value, unit='', source=None, display=None, reason='Not exposed or invalid'):
        supported = value is not None and (not isinstance(value, str) or bool(value.strip()))
        status = 'SUPPORTED' if supported else 'UNAVAILABLE'
        self.result['resources'].append({'name': name, 'value': value if supported else None,
                                         'unit': unit, 'source': source, 'status': status,
                                         'display': display if supported and display is not None else
                                         f'{value} {unit}'.strip() if supported else f'UNAVAILABLE ({reason})'})
        self.result['coverage'].append({'name': name, 'status': status,
                                       'reason': '' if supported else reason})

    def health(self, name, value):
        text = str(value).strip().lower() if value is not None else ''
        if text in ('good', 'healthy', 'normal', 'ok', 'passed', 'pass', 'online'):
            status = 'OK'
        elif any(word in text for word in ('fail', 'bad', 'error', 'degrad', 'crash', 'fault', 'critical', 'abnormal')):
            status = 'FAIL'
        elif any(word in text for word in ('rebuild', 'repair', 'recover', 'resync', 'initializ', 'warn')):
            status = 'WARN'
        else:
            status = 'UNAVAILABLE'
        self.check(name, status, str(value) if text else 'No readable status')

    def high(self, name, value, limit, unit='%'):
        if value is None:
            self.check(name, 'UNAVAILABLE', 'No valid reading')
        else:
            self.check(name, 'WARN' if value > limit else 'OK',
                       f'{value:.1f}{unit}; warning above {limit:g}{unit}')


def evaluate(snapshot, item, previous=None):
    """Interpret only discovered data, using exact columns and units from the supplied MIBs."""
    r = Report(snapshot)
    if not snapshot.get('connected'):
        r.check('SNMPv3 connection', 'FAIL', snapshot.get('error', 'No SNMP response'))
        r.result['coverage'].append({'name': 'NAS resources', 'status': 'UNAVAILABLE',
                                      'reason': 'SNMP connection failed'})
        return r.result
    r.check('SNMPv3 connection', 'OK', 'SNMPv3 MD5 authNoPriv; read-only discovery completed')
    data = snapshot['data']
    get = data.get
    cpu_limit = threshold(item, 'cpu_warn_percent', 80)
    ram_limit = threshold(item, 'memory_warn_percent', 85)
    storage_limit = threshold(item, 'disk_warn_percent', 90)
    cpu_temp_limit = threshold(item, 'cpu_temp_warn_c', 80, 150)
    disk_temp_limit = threshold(item, 'disk_temp_warn_c', 50, 150)
    sys_temp_limit = threshold(item, 'system_temp_warn_c', 60, 150)
    ups_limit = threshold(item, 'ups_battery_warn_percent', 20)
    ups_runtime_limit = threshold(item, 'ups_runtime_warn_seconds', 300, 86400)
    for label, oid in [('Hostname', IDENTITY[2]), ('Model', VENDOR + '.2.1.0'),
                       ('ADM version', VENDOR + '.1.2.0')]:
        r.metric(label, get(oid), source=oid)
    uptime_oid = '1.3.6.1.2.1.25.1.1.0'
    uptime = number(get(uptime_oid), 0)
    if uptime is not None:
        r.metric('NAS uptime', uptime / 100, 's', uptime_oid, duration(uptime / 100))
    else:
        r.metric('NAS uptime', get(VENDOR + '.1.4.0'), source=VENDOR + '.1.4.0')
    agent_uptime = number(get(IDENTITY[1]), 0)
    r.metric('SNMP agent uptime', agent_uptime / 100 if agent_uptime is not None else None,
             's', IDENTITY[1], duration(agent_uptime / 100) if agent_uptime is not None else None)

    cpu_source = VENDOR + '.2.3.1'
    cpus = [number(row.get(2), 0, 100) for row in table(data, cpu_source).values()]
    cpus = [v for v in cpus if v is not None]
    if not cpus:
        cpu_source = '1.3.6.1.2.1.25.3.3.1'
        cpus = [number(row.get(2), 0, 100) for row in table(data, cpu_source).values()]
        cpus = [v for v in cpus if v is not None]
    cpu = sum(cpus) / len(cpus) if cpus else None
    if cpu is None:
        idle = number(get('1.3.6.1.4.1.2021.11.11.0'), 0, 100)
        cpu, cpu_source = (100 - idle if idle is not None else None), '1.3.6.1.4.1.2021.11.11.0'
    r.metric('CPU', cpu, '%', cpu_source, f'{cpu:.1f}% used' if cpu is not None else None)
    r.high('CPU utilisation', cpu, cpu_limit)
    # ASUSTOR memory sizes have no unit in this MIB. Use its explicit free percentage.
    memory = table(data, VENDOR + '.2.6.1')
    free_percents = [number(row.get(4), 0, 100) for row in memory.values()]
    free_percents = [v for v in free_percents if v is not None]
    ram = 100 - free_percents[0] if len(free_percents) == 1 else None
    ram_source = VENDOR + '.2.6.1.4'
    if ram is None:
        total = number(get('1.3.6.1.4.1.2021.4.5.0'), 1)
        free = number(get('1.3.6.1.4.1.2021.4.6.0'), 0)
        if total is not None and free is not None and free <= total:
            ram = 100 * (total - free) / total
            ram_source = '1.3.6.1.4.1.2021.4 (total real minus free real; includes cache)'
        else:
            for row in table(data, '1.3.6.1.2.1.25.2.3.1').values():
                total, used = number(row.get(5), 1), number(row.get(6), 0)
                if row.get(2) == '1.3.6.1.2.1.25.2.1.2' and total is not None and used is not None and used <= total:
                    ram = used / total * 100
                    ram_source = '1.3.6.1.2.1.25.2.3.1'
                    break
    r.metric('RAM', ram, '%', ram_source, f'{ram:.1f}% used' if ram is not None else None)
    r.high('RAM utilisation', ram, ram_limit)
    swap_total = number(get('1.3.6.1.4.1.2021.4.3.0'), 1)
    swap_free = number(get('1.3.6.1.4.1.2021.4.4.0'), 0)
    swap = 100 * (swap_total - swap_free) / swap_total if swap_total is not None and swap_free is not None and swap_free <= swap_total else None
    r.metric('Swap', swap, '%', '1.3.6.1.4.1.2021.4', f'{swap:.1f}% used' if swap is not None else None)
    for idx, label in [('1', '1 minute'), ('2', '5 minutes'), ('3', '15 minutes')]:
        oid = '1.3.6.1.4.1.2021.10.1.3.' + idx
        r.metric(f'CPU load average ({label})', number(get(oid), 0), source=oid)

    temperatures = table(data, VENDOR + '.2.5.1')
    if not temperatures:
        temperatures = {'': {}}
    for idx, row in temperatures.items():
        for column, label, limit in [(2, 'CPU temperature', cpu_temp_limit), (3, 'System temperature', sys_temp_limit)]:
            value = number(row.get(column), -20, 150)
            name = label + (f' sensor {idx}' if len(temperatures) > 1 else '')
            r.metric(name, value, 'C', f'{VENDOR}.2.5.1.{column}.{idx}', reason='Sensor absent or invalid/sentinel reading')
            r.high(name, value, limit, 'C')
    fans = table(data, VENDOR + '.2.4.1')
    for idx, row in fans.items():
        rpm = number(row.get(2), 0, 100000)
        name = f'Fan {idx}'
        r.metric(name, rpm, 'RPM', f'{VENDOR}.2.4.1.2.{idx}')
        r.check(name + ' speed', 'UNAVAILABLE' if rpm is None else 'WARN' if rpm == 0 else 'OK',
                'No valid reading' if rpm is None else 'Zero RPM; investigate whether the fan is stopped intentionally' if rpm == 0 else f'{rpm:g} RPM')
    if not fans:
        r.metric('Fan speed', None)
        r.check('Fan speed', 'UNAVAILABLE', 'No readable fan instances')

    disks = table(data, VENDOR + '.4.1.1')
    for idx, row in disks.items():
        label = f'Disk {idx}'
        r.metric(label, row.get(5), source=f'{VENDOR}.4.1.1.5.{idx}',
                 display=f"{row.get(2, idx)}: {row.get(5, 'UNAVAILABLE')}; model {row.get(3, 'UNAVAILABLE')}")
        r.health(label + ' health', row.get(5))
        r.metric(label + ' SMART', row.get(6), source=f'{VENDOR}.4.1.1.6.{idx}')
        r.health(label + ' SMART health', row.get(6))
        temp = number(row.get(7), -20, 150)
        r.metric(label + ' temperature', temp, 'C', f'{VENDOR}.4.1.1.7.{idx}')
        r.high(label + ' temperature', temp, disk_temp_limit, 'C')
        r.metric(label + ' capacity', number(row.get(8), 1), 'GB (MIB-reported)', f'{VENDOR}.4.1.1.8.{idx}')
    if not disks:
        r.metric('Physical disks', None)
        r.check('Disk health', 'UNAVAILABLE', 'No ASUSTOR disk instances; standard device status is not SMART health')

    volumes = table(data, VENDOR + '.5.1.1')
    for idx, row in volumes.items():
        label = f'Volume {idx}'
        r.metric(label + ' status', row.get(4), source=f'{VENDOR}.5.1.1.4.{idx}')
        r.health(label + ' health', row.get(4))
        r.metric(label + ' RAID level', row.get(3), source=f'{VENDOR}.5.1.1.3.{idx}')
        total, free = number(row.get(6), 1), number(row.get(7), 0)
        percent = 100 * (total - free) / total if total is not None and free is not None and free <= total else None
        display = f'{percent:.1f}% used; {total - free:g} GB used / {total:g} GB total; {free:g} GB free (MIB-reported)' if percent is not None else None
        r.metric(label + ' usage', percent, '%', VENDOR + '.5.1.1', display)
        if percent is not None:
            r.result['resources'][-1].update(total=total, used=total-free, free=free, capacity_unit='GB (MIB-reported)')
        r.high(label + ' storage usage', percent, storage_limit)
    if not volumes:
        r.check('RAID/volume health', 'UNAVAILABLE', 'No ASUSTOR volume status; standard storage counters do not indicate RAID health')
    # Standard volume counters provide byte-accurate capacities. Prefer them only when
    # a vendor row lacks capacity, or no vendor volume exists; ignore bind-mount aliases.
    vendor_names = {str(row.get(2, '')).lower(): idx for idx, row in volumes.items()}
    storage = table(data, '1.3.6.1.2.1.25.2.3.1')
    seen = set()
    for idx, row in storage.items():
        if row.get(2) != '1.3.6.1.2.1.25.2.1.4':
            continue
        path = str(row.get(3, ''))
        if not path.startswith('/volume') or '/' in path[1:]:
            continue
        match = vendor_names.get(path.strip('/').lower())
        vendor_row = volumes.get(match, {})
        vt, vf = number(vendor_row.get(6), 1), number(vendor_row.get(7), 0)
        if match and vt is not None and vf is not None and vf <= vt:
            continue
        units, total, used = number(row.get(4), 1), number(row.get(5), 1), number(row.get(6), 0)
        if units is None or total is None or used is None or used > total:
            continue
        if path in seen:
            continue
        seen.add(path)
        label = f'Volume {match}' if match else f'Storage {path}'
        percent = 100 * used / total
        # Replace the missing vendor capacity metric rather than emitting a duplicate.
        r.result['resources'] = [v for v in r.result['resources'] if v['name'] != label + ' usage']
        r.result['coverage'] = [v for v in r.result['coverage'] if v['name'] != label + ' usage']
        r.result['checks'] = [v for v in r.result['checks'] if v['name'] != label + ' storage usage']
        r.metric(label + ' usage', percent, '%', f'1.3.6.1.2.1.25.2.3.1.*.{idx}',
                 f'{percent:.1f}% used; {used * units / 2**30:.2f} GiB used / {total * units / 2**30:.2f} GiB total; {(total-used)*units/2**30:.2f} GiB free')
        r.result['resources'][-1].update(total=total*units, used=used*units, free=(total-used)*units, capacity_unit='bytes')
        r.high(label + ' storage usage', percent, storage_limit)
    if not volumes and not seen:
        r.metric('Volume capacity', None)

    add_network(r, snapshot, previous, item)
    add_disk_io(r, snapshot)
    add_ups(r, data, ups_limit, ups_runtime_limit)
    update = get(VENDOR + '.1.7.0')
    r.metric('ADM update availability', update, source=VENDOR + '.1.7.0')
    update_text = str(update).strip().lower()
    if update_text in ('unavailable', 'the adm is latest version'):
        r.check('ADM update availability', 'OK', f'NAS reports: {update}')
    elif update_text in ('available', 'there is a new version ready for download'):
        r.check('ADM update availability', 'WARN', f'NAS reports: {update}')
    else:
        r.check('ADM update availability', 'UNAVAILABLE', 'No recognized read-only update status')
    devices = table(data, '1.3.6.1.2.1.25.3.2.1')
    bad = [str(row.get(3, idx)) for idx, row in devices.items() if row.get(5) in (3, 4, 5)]
    incomplete = any(row.get(5) not in (2, 3, 4, 5) for row in devices.values())
    r.check('Host device status', 'FAIL' if any(row.get(5) == 5 for row in devices.values()) else
            'WARN' if bad else 'UNAVAILABLE' if not devices or incomplete else 'OK',
            ', '.join(bad) if bad else 'Some devices have no usable status' if incomplete or not devices else 'All reported devices running')
    for label in ('Malware/ransomware detection', 'ADM security configuration', 'Backup job health',
                  'Firewall and remote-access security', 'Full system event/log diagnostics',
                  'Detailed SMART test results', 'Independent storage pool status'):
        r.check(label, 'UNSUPPORTED', 'No reliable read-only source in the available MIBs')
        r.result['coverage'].append({'name': label, 'status': 'UNSUPPORTED',
                                      'reason': 'Requires another reliable read-only source or ADM access'})
    for name, branch in snapshot.get('branches', {}).items():
        if branch.get('reason') and branch.get('count'):
            r.check(f'{name} discovery', 'WARN', branch['reason'])
        elif branch.get('reason') and 'No readable' not in branch['reason']:
            r.check(f'{name} discovery', 'WARN', branch['reason'])
    return r.result


def add_network(r, snapshot, previous, item):
    data = snapshot['data']
    base, extended = '1.3.6.1.2.1.2.2.1', '1.3.6.1.2.1.31.1.1.1'
    interfaces, extra = table(data, base), table(data, extended)
    required = item.get('required_interfaces', [])
    if not isinstance(required, list) or any(not isinstance(v, str) for v in required):
        raise ValueError('required_interfaces must be a list of interface names')
    names = set()
    for idx in sorted(set(interfaces) | set(extra), key=lambda v: tuple(map(int, v.split('.')))):
        row, x = interfaces.get(idx, {}), extra.get(idx, {})
        name = str(x.get(1) or row.get(2) or f'ifIndex {idx}')
        names.add(name)
        label = f'Interface {name}'
        admin, oper = row.get(7), row.get(8)
        oper_names = {1: 'up', 2: 'down', 3: 'testing', 4: 'unknown', 5: 'dormant', 6: 'notPresent', 7: 'lowerLayerDown'}
        r.metric(label + ' status', oper_names.get(oper), source=f'{base}.8.{idx}')
        if name in required:
            status = 'OK' if oper == 1 else 'FAIL' if oper in (2, 3, 5, 6, 7) else 'UNAVAILABLE'
        elif admin == 2:
            status = 'N/A'
        elif admin == 1 and oper in (2, 6, 7):
            status = 'WARN'
        elif admin == 1 and oper == 1:
            status = 'OK'
        else:
            status = 'UNAVAILABLE'
        r.check(label + ' connection', status, f'admin={admin if admin is not None else "unavailable"}, oper={oper_names.get(oper, "unavailable")}')
        speed = number(x.get(15), 1)
        speed = speed * 1000000 if speed is not None else number(row.get(5), 1, 4294967294)
        r.metric(label + ' link speed', speed, 'bit/s', f'{extended}.15.{idx}' if x.get(15) else f'{base}.5.{idx}',
                 f'{speed / 1000000:g} Mbit/s' if speed is not None else None)
        for direction, hc_column, low_column in [('RX', 6, 10), ('TX', 10, 16)]:
            hc = counter(x.get(hc_column))
            oid = f'{extended}.{hc_column}.{idx}' if hc is not None else f'{base}.{low_column}.{idx}'
            value = data.get(oid)
            r.metric(label + ' ' + direction + ' bytes', counter(value, 64 if hc is not None else 32), 'bytes', oid)
            discontinuity = f'{extended}.19.{idx}' if 19 in x else None
            rate, reason = counter_rate(snapshot, previous, oid, 64 if hc is not None else 32, speed,
                                        discontinuity, f'{extended}.1.{idx}' if x.get(1) else f'{base}.2.{idx}',
                                        'interface_counters' if hc is not None else 'interfaces')
            r.metric(label + ' ' + direction + ' rate', rate, 'bytes/s', oid,
                     f'{rate / 1000000:.3f} MB/s' if rate is not None else None, reason)
        for column, suffix in [(13, 'RX dropped'), (14, 'RX errors'), (19, 'TX dropped'), (20, 'TX errors')]:
            oid = f'{base}.{column}.{idx}'
            value = counter(row.get(column), 32)
            r.metric(label + ' ' + suffix, value, 'packets (cumulative)', oid)
        # A nonzero historical total is not a current fault. Warn on observed increases only.
        deltas = []
        for col in (13, 14, 19, 20):
            oid = f'{base}.{col}.{idx}'
            # Do not treat packet counters as bytes or infer a wrap from a decrease.
            rate, _ = counter_rate(snapshot, previous, oid, 64, None,
                                   f'{extended}.19.{idx}' if 19 in x else None, f'{base}.2.{idx}', 'interfaces')
            if rate is not None:
                deltas.append(rate)
        r.check(label + ' errors/drops', 'WARN' if any(v > 0 for v in deltas) else 'OK' if len(deltas) == 4 else 'UNAVAILABLE',
                'Counters increasing' if any(v > 0 for v in deltas) else 'No increases' if len(deltas) == 4 else 'Need continuous samples and all four counters')
    for name in required:
        if name not in names:
            r.check(f'Interface {name} connection', 'FAIL', 'Required interface is missing from discovery')
    if not interfaces and not extra:
        r.metric('Network interface counters', None)
        r.check('Network interfaces', 'UNAVAILABLE', 'No standard interface instances; vendor KB counters are not byte counters')


def add_disk_io(r, snapshot):
    root = '1.3.6.1.4.1.2021.13.15.1.1'
    rows = table(snapshot['data'], root)
    if not rows:
        r.metric('Disk I/O statistics', None, reason='No readable UCD-DISKIO-MIB instances; absent or SNMP view restricted')
    for idx, row in rows.items():
        label = f'Disk I/O {row.get(2, idx)}'
        for name, hc, low in [('bytes read', 12, 3), ('bytes written', 13, 4)]:
            col = hc if counter(row.get(hc)) is not None else low
            r.metric(label + ' ' + name, counter(row.get(col), 64 if col == hc else 32), 'bytes (cumulative)', f'{root}.{col}.{idx}')
        for name, col in [('read operations', 5), ('write operations', 6)]:
            r.metric(label + ' ' + name, counter(row.get(col), 32), 'operations (cumulative)', f'{root}.{col}.{idx}')


def add_ups(r, data, limit, runtime_limit):
    rows = table(data, VENDOR + '.6.1.1')
    if not rows:
        r.metric('UPS', None, reason='No connected UPS or no SNMP access')
        r.check('UPS health', 'N/A', 'No readable UPS instances; connection not confirmed')
    for idx, row in rows.items():
        label = f'UPS {idx}'
        # This NAS exposes a phantom row (OB, zero battery/runtime, empty model).
        # Never infer a connected or healthy UPS from that placeholder.
        if not str(row.get(2, '')).strip() and not str(row.get(3, '')).strip():
            r.metric(label, None, reason='UPS identity absent; placeholder telemetry cannot confirm a connected UPS')
            r.check(label + ' health', 'N/A', 'No identifiable UPS; ignoring unverified placeholder readings')
            continue
        r.metric(label + ' model', row.get(3) or row.get(2), source=VENDOR + '.6.1.1')
        status = str(row.get(7, '')).strip().upper()
        r.metric(label + ' status', status or None, source=f'{VENDOR}.6.1.1.7.{idx}')
        tokens = set(status.split())
        r.check(label + ' power', 'FAIL' if tokens & {'LB', 'FSD', 'OFF'} else 'WARN' if tokens & {'OB', 'RB', 'OVER', 'BYPASS', 'ALARM'} else
                'OK' if 'OL' in tokens else 'UNAVAILABLE', status or 'No readable status')
        battery = number(row.get(9), 0, 100)
        configured_low = number(row.get(10), 0, 100)
        low = max(limit, configured_low) if configured_low is not None else limit
        r.metric(label + ' battery', battery, '%', f'{VENDOR}.6.1.1.9.{idx}')
        r.check(label + ' battery', 'UNAVAILABLE' if battery is None else 'WARN' if battery <= low else 'OK',
                'No valid reading' if battery is None else f'{battery:g}%; warning at or below {low:g}%')
        runtime = number(row.get(8), 0)
        r.metric(label + ' runtime', runtime, 's', f'{VENDOR}.6.1.1.8.{idx}', duration(runtime) if runtime is not None else None)
        r.check(label + ' remaining runtime', 'UNAVAILABLE' if runtime is None else 'WARN' if runtime <= runtime_limit else 'OK',
                'No valid reading' if runtime is None else f'{runtime:g}s; warning at or below {runtime_limit:g}s')


def cache_path(item):
    host, port, username, _ = connection(item)
    key = hashlib.sha256(f'{host}:{port}:{username}'.encode()).hexdigest()[:24]
    directory = Path(item.get('counter_state_dir', '.snmp-cache'))
    if not directory.is_absolute():
        directory = BASE / directory
    return directory / (key + '.json')


def load_baseline(path):
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(value, dict) or not isinstance(value.get('data'), dict) or not isinstance(value.get('branches'), dict):
            return None
        if any(not isinstance(v, dict) for v in value['branches'].values()):
            return None
        return value
    except (OSError, ValueError, TypeError):
        return None


def save_baseline(path, snapshot):
    """Persist only counter continuity data, never credentials or NAS identity metadata."""
    prefixes = ('1.3.6.1.2.1.2.2.', '1.3.6.1.2.1.31.1.1.')
    reduced = {key: snapshot[key] for key in ('endpoint', 'timestamp', 'branches')}
    reduced['data'] = {oid: value for oid, value in snapshot['data'].items()
                       if oid.startswith(prefixes) or oid in (IDENTITY[1], '1.3.6.1.2.1.25.1.1.0')}
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, suffix='.tmp', delete=False) as handle:
            temp_path = Path(handle.name)
            json.dump(reduced, handle)
        temp_path.replace(path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def asustor(item, timeout):
    # Validate our configuration before entering library code. Library exceptions
    # are sanitized even when their type is ValueError, to avoid credential leaks.
    path = cache_path(item)
    validate_options(item)
    try:
        previous = load_baseline(path)
        snapshot = asyncio.run(collect(item, timeout))
        result = evaluate(snapshot, item, previous)
        if snapshot.get('connected'):
            try:
                save_baseline(path, snapshot)
            except OSError:
                result['checks'].append({'name': 'SNMP counter cache', 'status': 'WARN', 'ok': True,
                                          'warning': True, 'details': 'Unable to save counter baseline; rates may be unavailable'})
        return result
    except ImportError:
        error = 'SNMP dependency missing; run python -m pip install -r requirements.txt'
    except Exception as exc:
        error = f'SNMP resource polling failed ({type(exc).__name__}); check connectivity and MD5 credentials'
    return evaluate({'connected': False, 'error': error}, item)
