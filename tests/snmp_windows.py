# File: snmp_windows.py
# Last updated: 2026-11-11
# Change: Move the live test into tests and load .env from the project root.
# Description: Test NAS SNMPv3 MD5 on Windows using the PySNMP Python package.

import asyncio
import os
from pathlib import Path

from dotenv import load_dotenv

from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    UsmUserData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    USM_AUTH_HMAC96_MD5,
    USM_PRIV_NONE,
)
from pysnmp.proto.rfc1905 import NoSuchObject, NoSuchInstance, EndOfMibView


async def main():
    load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)
    host = os.getenv("ASUSTOR_SNMP_HOST")
    username = os.getenv("ASUSTOR_SNMP_USERNAME")
    password = os.getenv("ASUSTOR_SNMP_PASSWORD")

    if not host or not username or not password:
        print("FAIL Configure ASUSTOR_SNMP_HOST, ASUSTOR_SNMP_USERNAME, and ASUSTOR_SNMP_PASSWORD in .env")
        return 2
    try:
        port = int(os.getenv("ASUSTOR_SNMP_PORT", "161"))
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        print("FAIL ASUSTOR_SNMP_PORT must be an integer between 1 and 65535")
        return 2

    engine = SnmpEngine()

    try:
        auth = UsmUserData(
            userName=username,
            authKey=password,
            authProtocol=USM_AUTH_HMAC96_MD5,
            privProtocol=USM_PRIV_NONE,
        )
        target = await UdpTransportTarget.create(
            (host, port), timeout=3, retries=1,
        )
        print(f"Connecting to ASUSTOR NAS: {host}:{port}")
        healthy = True
        for name, oid in [
            ("System description", "1.3.6.1.2.1.1.1.0"),
            ("System uptime", "1.3.6.1.2.1.1.3.0"),
            ("System name", "1.3.6.1.2.1.1.5.0"),
        ]:
            error, status, index, varbinds = await get_cmd(
                engine,
                auth,
                target,
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )

            if error:
                healthy = False
                print(f"FAIL {name}: {error}")
                if 'digest' in str(error).lower():
                    print("     Verify the NAS SNMPv3 user, authentication password, and MD5 setting.")
            elif status:
                healthy = False
                print(f"FAIL {name}: {status.prettyPrint()}")
            elif len(varbinds) != 1 or isinstance(varbinds[0][1], (NoSuchObject, NoSuchInstance, EndOfMibView)):
                healthy = False
                print(f"FAIL {name}: OID unavailable")
            else:
                for result_oid, value in varbinds:
                    print(f"OK {name}: {value.prettyPrint()}")
        return 0 if healthy else 1

    except Exception as e:
        print(f"FAIL SNMP check raised {type(e).__name__}; check connectivity and MD5 credentials")
        return 1

    finally:
        engine.close_dispatcher()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
