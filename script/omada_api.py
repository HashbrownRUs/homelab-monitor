# File: omada_api.py
# Last updated: 2026-11-16
# Change: Add a read-only Omada OpenAPI demonstration command.
# Description: List the first page of sites, devices, or clients without exposing credentials.

import argparse
import json
import os
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[1] / 'backend'
sys.path.insert(0, str(BASE))

from dotenv import load_dotenv
from checks.omada import OmadaClient


def main():
    parser = argparse.ArgumentParser(description='Read-only Omada OpenAPI examples')
    parser.add_argument('resource', choices=('sites', 'devices', 'clients'), nargs='?', default='sites')
    parser.add_argument('--insecure', action='store_true', help='Explicitly accept an unverified controller certificate')
    args = parser.parse_args()
    load_dotenv(BASE / '.env', override=False)
    try:
        client = OmadaClient({'verify_tls': not args.insecure}, 5)
        client.authenticate()
        result = client.list_items(args.resource, os.environ.get('OMADA_SITE_ID'))
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'Omada query failed ({type(exc).__name__}); check .env, TLS certificate, address, and app permissions.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
