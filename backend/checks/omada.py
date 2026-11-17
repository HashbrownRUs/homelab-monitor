# File: omada.py
# Last updated: 2026-11-16
# Change: Add read-only Omada OpenAPI client-credentials monitoring.
# Description: Authenticate and list sites, devices, and clients using only the standard library.

import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit

BASE = Path(__file__).resolve().parent.parent


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class OmadaClient:
    def __init__(self, item, timeout):
        self.url = (item.get('url') or os.environ.get('OMADA_URL', '')).rstrip('/')
        parsed = urlsplit(self.url)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or
                parsed.password or parsed.path or parsed.query or parsed.fragment):
            raise ValueError('Set OMADA_URL to an HTTPS controller base URL')
        self.controller = os.environ.get('OMADA_CONTROLLER_ID', '')
        self.client_id = os.environ.get('OMADA_CLIENT_ID', '')
        self.secret = os.environ.get('OMADA_CLIENT_SECRET', '')
        if not all((self.controller, self.client_id, self.secret)):
            raise ValueError('Set OMADA_CONTROLLER_ID, OMADA_CLIENT_ID, and OMADA_CLIENT_SECRET')
        cafile = item.get('cafile') or os.environ.get('OMADA_CA_FILE')
        if cafile and not Path(cafile).is_absolute():
            cafile = str(BASE / cafile)
        context = ssl.create_default_context(cafile=cafile or None)
        if item.get('verify_tls', True) is False:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), NoRedirect())
        self.timeout = timeout
        self.token = None

    def request(self, path, payload=None):
        headers = {'Accept': 'application/json'}
        if self.token:
            headers['Authorization'] = f'AccessToken={self.token}'
        data = None
        if payload is not None:
            data = json.dumps(payload).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(self.url + path, data=data, headers=headers)
        with self.opener.open(req, timeout=self.timeout) as response:
            body = json.load(response)
        if not isinstance(body, dict) or body.get('errorCode') != 0 or 'result' not in body:
            raise ValueError('Omada rejected the request or returned an invalid response')
        return body['result']

    def authenticate(self):
        result = self.request('/openapi/authorize/token?grant_type=client_credentials', {
            'omadacId': self.controller, 'client_id': self.client_id,
            'client_secret': self.secret})
        self.token = result['accessToken']
        if not isinstance(self.token, str) or not self.token or any(c.isspace() for c in self.token):
            raise ValueError('Invalid Omada access token')

    def list_items(self, resource='sites', site_id=None):
        if resource not in ('sites', 'devices', 'clients'):
            raise ValueError('Omada resource must be sites, devices, or clients')
        path = f'/openapi/v1/{quote(self.controller, safe="")}/sites'
        if resource != 'sites':
            if not site_id:
                raise ValueError('Set OMADA_SITE_ID for devices or clients')
            path += f'/{quote(site_id, safe="")}/{resource}'
        result = self.request(path + '?page=1&pageSize=100')
        if (not isinstance(result, dict) or not isinstance(result.get('data'), list)
                or not all(isinstance(row, dict) for row in result['data'])):
            raise ValueError('Invalid Omada list response')
        return result


def omada(item, timeout):
    try:
        client = OmadaClient(item, timeout)
        client.authenticate()
        resource = item.get('resource', 'sites')
        result = client.list_items(resource, item.get('site_id') or os.environ.get('OMADA_SITE_ID'))
        rows = result['data']
        names = [str(row.get('name') or row.get('model') or row.get('mac') or 'unnamed')
                 for row in rows[:5]]
        total = result.get('totalRows', len(rows))
        if item.get('resources', False):
            fields = {
                'sites': ('name', 'region', 'timeZone', 'scenario'),
                'devices': ('name', 'model', 'ip', 'status', 'firmwareVersion',
                            'uptime', 'cpuUtil', 'memUtil'),
                'clients': ('name', 'hostName', 'ip', 'active', 'wireless',
                            'apName', 'ssid', 'rssi', 'rxRate', 'txRate'),
            }
            readings = []
            for index, row in enumerate(rows, 1):
                values = {key: row[key] for key in fields[resource]
                          if key in row and isinstance(row[key], (str, int, float, bool))}
                compact_fields = {
                    'sites': (('timeZone', 'Time zone'),),
                    'devices': (('ip', 'IP'), ('cpuUtil', 'CPU'), ('memUtil', 'Memory')),
                    'clients': (('ip', 'IP'), ('ssid', 'SSID')),
                }
                def clean(value):
                    return str(value).replace('\n', ' ').replace('\r', ' ')
                display = ' | '.join(f'{label}: {clean(values[key])}'
                                     for key, label in compact_fields[resource] if key in values)
                name = clean(values.get('hostName') or values.get('name') or f'Unnamed {index}')
                category = {'sites': 'Site', 'devices': 'Device', 'clients': 'Client'}[resource]
                readings.append({'name': f'{category} {name}',
                                 'display': display or 'No supported fields returned',
                                 'values': values})
            return {'checks': [{'name': item.get('name', f'Omada {resource}'),
                                'ok': True, 'warning': False,
                                'details': f'OpenAPI: {total} {resource}; showing {len(rows)} (first page, up to 100)'}],
                    'resources': readings}
        return True, f'Omada OpenAPI: {total} {resource}; sample: {", ".join(names) or "none"}'
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        return False, f'Omada OpenAPI HTTP {code}; check API address and app permissions'
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return False, f'Omada OpenAPI failed ({type(exc).__name__}); check environment values, CA, connectivity, and API permissions'
