"""Check dispatch and the standard HTTP/HTTPS availability policy."""
from urllib.parse import urlsplit, urlunsplit

from .mikrotik import mikrotik
from .http import http
from .ping import ping
from .tcp import tcp


def execute(item, timeout):
    kind = item['type'].lower()
    if kind == 'mikrotik':
        return mikrotik(item, timeout)
    if kind == 'ping':
        return ping(item['host'], timeout)
    if kind == 'tcp':
        host, port = item['host'], int(item['port'])
        primary = tcp(host, port, timeout)
        if port == 80:
            return web_result(primary, tcp(host, 443, timeout))
        return primary
    if kind == 'http':
        url = item['url']
        parsed = urlsplit(url)
        verify_tls = item.get('verify_tls', True)
        primary = http(url, timeout, verify_tls)
        if parsed.scheme.lower() == 'http' and parsed.port in (None, 80):
            host = parsed.hostname
            if not host:
                raise ValueError('HTTP URL requires a hostname')
            authority = f'[{host}]:443' if ':' in host else f'{host}:443'
            secure_url = urlunsplit(('https', authority, parsed.path, parsed.query, ''))
            return web_result(primary, http(secure_url, timeout, verify_tls))
        return primary
    return False, f'Unsupported check type: {kind}'


def web_result(plain, secure):
    """Require at least one standard web endpoint to pass."""
    plain_ok, plain_details = plain
    secure_ok, secure_details = secure
    details = f'HTTP port 80: {plain_details}; HTTPS port 443: {secure_details}'
    if not plain_ok and secure_ok:
        return True, f'WARNING: HTTP port 80 may be disabled on purpose. {details}'
    if plain_ok and not secure_ok:
        return True, f'WARNING: HTTPS port 443 check failed. {details}'
    return plain_ok or secure_ok, details
