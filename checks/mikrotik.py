"""Read RouterOS resources over its certificate-verified REST API."""
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
    username = os.environ.get(item.get('username_env', 'MIKROTIK_USERNAME'))
    password = os.environ.get(item.get('password_env', 'MIKROTIK_PASSWORD'))
    if not username or not password:
        raise ValueError('Set MikroTik username and password environment variables')
    if ':' in username:
        raise ValueError('MikroTik username cannot contain a colon')
    cafile = Path(item.get('cafile', 'cert_export_homelab-ca.crt'))
    if not cafile.is_absolute():
        cafile = BASE_DIR / cafile
    try:
        context = ssl.create_default_context(
            cafile=str(cafile)
        )
        token = base64.b64encode(f'{username}:{password}'.encode('utf-8')).decode('ascii')
        request = urllib.request.Request(url, headers={
            'Authorization': f'Basic {token}', 'Accept': 'application/json',
            'User-Agent': 'HomelabMonitor/1.0',
        })
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect())
        with opener.open(request, timeout=timeout) as response:
            resource = json.load(response)
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
