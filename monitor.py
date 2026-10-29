#!/usr/bin/env python3
"""Dependency-free home-lab monitoring: ICMP, TCP, HTTPS, stateful alerts."""
import argparse
import concurrent.futures
import datetime as dt
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

BASE = Path(__file__).resolve().parent


def ping(host, timeout):
    # Linux iputils ping; no raw socket privileges required.
    try:
        cp = subprocess.run(['ping', '-n', '-c', '1', '-W', str(max(1, int(timeout + .999))), host],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                            timeout=timeout + 2)
        return cp.returncode == 0, 'ICMP reply' if cp.returncode == 0 else 'No ICMP reply'
    except FileNotFoundError:
        return False, 'ping command missing (install iputils-ping)'
    except subprocess.TimeoutExpired:
        return False, 'Ping timed out'
    except Exception as exc:
        return False, str(exc)


def tcp(host, port, timeout):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, f'TCP {port} accepting connections'
    except OSError as exc:
        return False, f'TCP {port}: {exc}'


def http(url, timeout, verify_tls):
    ctx = None if verify_tls else ssl._create_unverified_context()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'HomelabMonitor/1.0'})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            code = response.status
            return (200 <= code < 400), f'HTTP {code}'
    except urllib.error.HTTPError as exc:
        # 401/403 still prove web service is alive; authentication may be required.
        if exc.code in (401, 403):
            return True, f'HTTP {exc.code} (authentication required)'
        return False, f'HTTP {exc.code}'
    except Exception as exc:
        return False, str(exc)


def execute(item, timeout):
    kind = item['type'].lower()
    if kind == 'ping':
        return ping(item['host'], timeout)
    if kind == 'tcp':
        return tcp(item['host'], item['port'], timeout)
    if kind == 'http':
        return http(item['url'], timeout, item.get('verify_tls', True))
    return False, f'Unsupported check type: {kind}'


def check_device(device, timeout):
    checks = []
    for item in device['checks']:
        try:
            ok, details = execute(item, timeout)
        except (KeyError, ValueError, TypeError) as exc:
            ok, details = False, f'Invalid configuration: {exc}'
        checks.append({'name': item.get('name', item.get('type', 'unnamed')), 'ok': ok, 'details': details})
    return {'name': device['name'], 'ok': all(c['ok'] for c in checks), 'checks': checks}


def format_report(results, timestamp):
    lines = [f'Home Lab Status — {timestamp}', '-' * 60]
    for device in results:
        lines.append(f"{'OK  ' if device['ok'] else 'FAIL'}  {device['name']}")
        for c in device['checks']:
            lines.append(f"    {'OK  ' if c['ok'] else 'FAIL'} {c['name']}: {c['details']}")
    n = sum(not x['ok'] for x in results)
    lines.append('-' * 60)
    lines.append(f'{len(results) - n}/{len(results)} devices healthy; {n} failing')
    return '\n'.join(lines)


def send_webhook(url, message, timeout):
    # Generic webhook expects JSON payload with `text` (e.g. Slack-compatible).
    data = json.dumps({'text': message}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=timeout) as response:
        if response.status >= 400:
            raise RuntimeError(f'Webhook HTTP {response.status}')


def main():
    parser = argparse.ArgumentParser(description='Check home-lab devices and services')
    parser.add_argument('--config', type=Path, default=BASE / 'config.json')
    parser.add_argument('--state', type=Path, default=BASE / 'state.json')
    parser.add_argument('--json', action='store_true', help='Print machine-readable JSON')
    parser.add_argument('--notify-all', action='store_true', help='Send webhook on every run, not just state changes')
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text(encoding='utf-8'))
        devices = config['devices']
        if not devices:
            raise ValueError('No devices configured')
        for device in devices:
            if not device.get('checks'):
                raise ValueError(f"Device {device.get('name')} has no checks")
        timeout = float(config.get('timeout_seconds', 3))
        if timeout <= 0:
            raise ValueError('timeout_seconds must be > 0')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'Configuration error: {exc}', file=sys.stderr)
        return 2
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(devices))) as pool:
        results = list(pool.map(lambda d: check_device(d, timeout), devices))
    stamp = dt.datetime.now().astimezone().isoformat(timespec='seconds')
    report = format_report(results, stamp)
    if args.json:
        print(json.dumps({'timestamp': stamp, 'devices': results}, indent=2))
    else:
        print(report)
    current = {d['name']: {c['name']: c['ok'] for c in d['checks']} for d in results}
    try:
        previous = json.loads(args.state.read_text(encoding='utf-8')) if args.state.exists() else {}
    except (OSError, ValueError):
        previous = {}
    webhook = os.environ.get('HOMELAB_WEBHOOK_URL', '')
    if webhook and (args.notify_all or any(previous.get(name, {}).get(check) != ok
                                     for name, checks in current.items() for check, ok in checks.items())):
        try:
            send_webhook(webhook, report, timeout)
        except Exception as exc:
            print(f'Webhook notification failed: {exc}', file=sys.stderr)
    try:
        args.state.parent.mkdir(parents=True, exist_ok=True)
        temp = args.state.with_suffix('.tmp')
        temp.write_text(json.dumps(current, indent=2), encoding='utf-8')
        temp.replace(args.state)
    except OSError as exc:
        print(f'Unable to save state: {exc}', file=sys.stderr)
    return 1 if any(not d['ok'] for d in results) else 0


if __name__ == '__main__':
    
    sys.exit(main())
