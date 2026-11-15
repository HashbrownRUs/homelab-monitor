# File: mikrotik.py
# Last updated: 2026-11-06
# Description: Read RouterOS resources and run router pings over a verified REST API.

import base64
import json
import math
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit


BASE_DIR = Path(__file__).resolve().parent.parent


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def rest_request(item, url, timeout, payload=None):
    """Send an authenticated RouterOS request with CA verification and no redirects."""
    username = os.environ.get(item.get('username_env', 'MIKROTIK_USERNAME'))
    password = os.environ.get(item.get('password_env', 'MIKROTIK_PASSWORD'))
    if not username or not password:
        raise ValueError('Set MikroTik username and password environment variables')
    if ':' in username:
        raise ValueError('MikroTik username cannot contain a colon')
    cafile = Path(item.get('cafile', 'cert_export_homelab-ca.crt'))
    if not cafile.is_absolute():
        cafile = BASE_DIR / cafile
    context = ssl.create_default_context(cafile=str(cafile))
    token = base64.b64encode(f'{username}:{password}'.encode('utf-8')).decode('ascii')
    headers = {'Authorization': f'Basic {token}', 'Accept': 'application/json',
               'User-Agent': 'HomelabMonitor/1.0'}
    data = None
    if payload is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(payload).encode('utf-8')
    request = urllib.request.Request(url, headers=headers, data=data)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        return json.load(response)


def mikrotik(item, timeout):
    url = item['url'].rstrip('/')
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('MikroTik url must be an HTTPS base URL without credentials, query, or fragment')
    if parsed.path not in ('', '/', '/rest', '/rest/system/resource'):
        raise ValueError('MikroTik url must point to the router, /rest, or /rest/system/resource')
    if parsed.path in ('', '/'):
        url += '/rest/system/resource'
    elif parsed.path == '/rest':
        url += '/system/resource'
    thresholds = {}
    for name, default in [('cpu', 80), ('memory', 85), ('disk', 90)]:
        value = float(item.get(f'{name}_warn_percent', default))
        if not math.isfinite(value) or not 0 <= value <= 100:
            raise ValueError(f'{name}_warn_percent must be between 0 and 100')
        thresholds[name] = value
    try:
        resource = rest_request(item, url, timeout)
        if isinstance(resource, list) and len(resource) == 1:
            resource = resource[0]
        if not isinstance(resource, dict):
            raise ValueError('Expected one resource object')
        cpu = float(resource['cpu-load'])
        usage = {'cpu': cpu}
        summaries = [f'CPU {cpu:.1f}%']
        for name, free_key, total_key in [
            ('memory', 'free-memory', 'total-memory'),
            ('disk', 'free-hdd-space', 'total-hdd-space'),
        ]:
            free, total = float(resource[free_key]), float(resource[total_key])
            if not math.isfinite(total) or total <= 0 or not math.isfinite(free) or not 0 <= free <= total:
                raise ValueError(f'Invalid {name} resource counters')
            usage[name] = 100 * (total - free) / total
            summaries.append(f'{name.capitalize()} {usage[name]:.1f}% used ({free / 1048576:.1f}/{total / 1048576:.1f} MiB free)')
        if not math.isfinite(cpu) or not 0 <= cpu <= 100:
            raise ValueError('Invalid CPU load')
        for key in ('board-name', 'version', 'uptime'):
            if key in resource:
                summaries.append(f'{key}: {resource[key]}')
        warnings = [f'{name} {value:.1f}% exceeds {thresholds[name]:g}%' for name, value in usage.items() if value > thresholds[name]]
        details = '; '.join(summaries)
        if warnings:
            return True, f"WARNING: {', '.join(warnings)}. {details}"
        return True, details
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        return False, f'MikroTik REST HTTP {code}'
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Do not include exception text that might contain authentication data.
        return False, f'MikroTik resource check failed ({type(exc).__name__}); check CA, connectivity, and resource response'


def mikrotik_ping(item, timeout):
    """Ask the router to ping a target; at least one reply is required."""
    url = item['url'].rstrip('/')
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ('', '/', '/rest')):
        raise ValueError('MikroTik ping url must be an HTTPS router base URL or /rest without credentials')
    host = item['host']
    if not isinstance(host, str) or not host.strip():
        raise ValueError('MikroTik ping host must be a nonempty string')
    count = item.get('count', 3)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 10:
        raise ValueError('MikroTik ping count must be an integer between 1 and 10')
    endpoint = url + ('/ping' if parsed.path == '/rest' else '/rest/ping')
    try:
        rows = rest_request(item, endpoint, timeout,
                            {'address': host, 'count': str(count), 'interval': '200ms'})
        if not isinstance(rows, list) or not rows or len(rows) > count:
            raise ValueError('Invalid ping response')
        received = 0
        for row in rows:
            if not isinstance(row, dict) or 'seq' not in row:
                raise ValueError('Invalid ping response row')
            if 'time' in row and 'status' not in row:
                received += 1
            elif 'status' not in row:
                raise ValueError('Missing ping result')
        return received > 0, f'Router ping to {host}: {received}/{count} replies'
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        hint = ' (check router user permissions: read, test, api, rest-api)' if code == 403 else ''
        return False, f'MikroTik ping REST HTTP {code}{hint}'
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return False, f'MikroTik ping check failed ({type(exc).__name__}); check CA, connectivity, credentials, and ping response'
