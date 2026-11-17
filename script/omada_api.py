# File: omada_api.py
# Last updated: 2026-11-16
# Change: Add a read-only Omada OpenAPI demonstration command.
# Description: List the first page of sites, devices, or clients without exposing credentials.

import argparse
import json
import os
from pathlib import Path
import sys
import urllib.error

BASE = Path(__file__).resolve().parents[1] / 'backend'
sys.path.insert(0, str(BASE))

from dotenv import load_dotenv
from checks.omada import OmadaClient


def main():
    parser = argparse.ArgumentParser(description='Read-only Omada OpenAPI examples')
    parser.add_argument('resource', choices=('sites', 'devices', 'clients', 'check'), nargs='?', default='sites')
    parser.add_argument('--insecure', action='store_true', help='Explicitly accept an unverified controller certificate')
    args = parser.parse_args()
    load_dotenv(BASE / '.env', override=False)
    stage = 'configuration and CA loading'
    try:
        client = OmadaClient({'verify_tls': not args.insecure}, 5)
        stage = 'API authentication'
        client.authenticate()
        if args.resource == 'check':
            print('PASS: API authentication')
            resources = ['sites']
            if os.environ.get('OMADA_SITE_ID'):
                resources += ['devices', 'clients']
            for resource in resources:
                stage = f'{resource} query'
                result = client.list_items(resource, os.environ.get('OMADA_SITE_ID'))
                print(f'PASS: {resource} query; {len(result["data"])} returned '
                      f'(total: {result.get("totalRows", len(result["data"]))})')
            if not os.environ.get('OMADA_SITE_ID'):
                print('SKIP: devices and clients queries; set OMADA_SITE_ID to enable')
            return 0
        stage = f'{args.resource} query'
        result = client.list_items(args.resource, os.environ.get('OMADA_SITE_ID'))
        print(json.dumps(result, indent=2))
        return 0
    except urllib.error.HTTPError as exc:
        print(f'FAIL: {stage}: HTTP {exc.code}; check the Open API Interface Access Address, '
              'controller logs, and app permissions.', file=sys.stderr)
        exc.close()
        return 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'FAIL: {stage} ({type(exc).__name__}); check .env, TLS certificate, address, and app permissions.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
