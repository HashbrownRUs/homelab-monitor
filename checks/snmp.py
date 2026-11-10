# File: snmp.py
# Last updated: 2026-11-11
# Change: Use an MD5 SNMPv3 auth object for each device check.
# Description: Read standard system OIDs using MD5 authentication without privacy.

import asyncio
import os


OIDS = {
    'System description': '1.3.6.1.2.1.1.1.0',
    'System uptime': '1.3.6.1.2.1.1.3.0',
    'System name': '1.3.6.1.2.1.1.5.0',
}


def snmp(item, timeout):
    host = item.get('host') or os.getenv('ASUSTOR_SNMP_HOST')
    username = os.getenv(item.get('username_env', 'ASUSTOR_SNMP_USERNAME'))
    password = os.getenv(item.get('password_env', 'ASUSTOR_SNMP_PASSWORD'))
    if not host or not username or not password:
        return False, 'SNMP requires a host, ASUSTOR_SNMP_USERNAME, and ASUSTOR_SNMP_PASSWORD (or configured credential variables)'
    port = int(item.get('port', os.getenv('ASUSTOR_SNMP_PORT', '161')))
    if not 1 <= port <= 65535:
        raise ValueError('SNMP port must be between 1 and 65535')
    try:
        return asyncio.run(_check(host, port, username, password, timeout))
    except ImportError:
        return False, 'SNMP dependency missing; run python -m pip install -r requirements.txt'
    except Exception as exc:
        # Library errors may contain authentication data; report only their type.
        return False, f'SNMP check failed ({type(exc).__name__}); check connectivity and SNMPv3 MD5 credentials'


async def _check(host, port, username, password, timeout):
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, UsmUserData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, USM_AUTH_HMAC96_MD5, get_cmd,
    )
    from pysnmp.proto.rfc1905 import NoSuchObject, NoSuchInstance, EndOfMibView

    engine = SnmpEngine()
    try:
        auth = UsmUserData(userName=username, authKey=password,
                           authProtocol=USM_AUTH_HMAC96_MD5)
        target = await UdpTransportTarget.create((host, port), timeout=timeout, retries=1)
        readings = []
        healthy = True
        for name, oid in OIDS.items():
            error, status, index, values = await get_cmd(
                engine, auth, target, ContextData(), ObjectType(ObjectIdentity(oid)))
            if error:
                healthy = False
                readings.append(f'{name}: request failed; check connectivity and SNMPv3 MD5 credentials')
            elif status:
                healthy = False
                readings.append(f'{name}: {status.prettyPrint()}')
            elif len(values) != 1 or isinstance(values[0][1], (NoSuchObject, NoSuchInstance, EndOfMibView)):
                healthy = False
                readings.append(f'{name}: OID unavailable')
            else:
                readings.append(f'{name}: {values[0][1].prettyPrint()}')
        return healthy, '; '.join(readings)
    finally:
        engine.close_dispatcher()
