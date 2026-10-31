import ssl
import urllib.error
import urllib.request


def http(url, timeout, verify_tls):
    ctx = None if verify_tls else ssl._create_unverified_context()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'HomelabMonitor/1.0'})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            code = response.status
            return (200 <= code < 400), f'HTTP {code}'
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return True, f'HTTP {exc.code} (authentication required)'
        return False, f'HTTP {exc.code}'
    except Exception as exc:
        return False, str(exc)
