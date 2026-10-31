# Home Lab Monitor

Python 3 home-lab monitor using only the standard library. Checks ICMP ping on Windows and Linux, TCP ports, and HTTP(S) endpoints. Prints a status report and optionally sends webhook alerts when checks fail or recover.

## Setup

Run commands from the project directory. On Ubuntu, install Python and ping:

```bash
sudo apt update
sudo apt install -y python3 iputils-ping
```

Edit `config.json` with your device addresses, ports, and checks. Use `example_config.json` as a reference and remove checks for services you do not run.

Linux:

```bash
python3 monitor.py
```

Windows PowerShell, with Python 3 installed:

```powershell
python monitor.py
```

## Configuration

Each device needs a `name` and a nonempty `checks` list. Supported check types:

| Type | Required fields | Healthy when |
| --- | --- | --- |
| `ping` | `host` | The host replies to ping |
| `tcp` | `host`, `port` | A TCP connection succeeds |
| `mikrotik` | `url` (HTTPS router base URL) | REST resources can be read; high usage produces warnings |
| `http` | `url` | HTTP status is 200–399, 401, or 403 |

Check implementations live in `checks/ping.py`, `checks/tcp.py`, and `checks/http.py`.

For TCP port 80 and HTTP URLs using port 80 (including the default port), the monitor always also checks HTTPS port 443 on the same host. At least one must pass. If port 80 fails but 443 passes, the result is a warning that HTTP may be disabled on purpose. If only port 80 passes, the result warns that HTTPS failed. Warnings appear as `WARN` in text and `warning: true` in JSON, without a failing exit code. HTTP checks preserve the path, query, and TLS verification setting for the HTTPS request. Other ports and explicitly configured HTTPS checks retain their normal failure behavior.

Checks can have an optional `name`. A device is healthy only when all its checks pass. `timeout_seconds` defaults to 3 and must be positive and finite.

For an HTTPS endpoint with a self-signed certificate:

```json
{"name": "Controller web UI", "type": "http", "url": "https://192.168.0.10:8043/", "verify_tls": false}
```

TLS verification is enabled by default. Set `verify_tls` to `false` only for trusted endpoints where you intentionally accept an unverified certificate.

## Options and exit codes

```bash
python3 monitor.py --json
python3 monitor.py --config example_config.json --state custom-state.json
python3 monitor.py --notify-all
```

`--json` prints machine-readable results. The default config and state files are `config.json` and `state.json` beside the script.

- `0`: all checks healthy
- `1`: one or more checks failed
- `2`: configuration error

## Notifications

Set `HOMELAB_WEBHOOK_URL` to a Slack-compatible webhook accepting `{"text":"..."}`. Notifications include the first run and subsequent check state changes. Use `--notify-all` to send on every run.

Linux:

```bash
export HOMELAB_WEBHOOK_URL="https://your-webhook-url"
python3 monitor.py
```

Windows PowerShell:

```powershell
$env:HOMELAB_WEBHOOK_URL = "https://your-webhook-url"
python monitor.py
```

State is saved after each run. Webhook failures are printed without stopping monitoring.

## Scheduling

On Linux, use `crontab -e` and add a check every five minutes:

```cron
*/5 * * * * /usr/bin/python3 /home/YOUR_USER/homelab-monitor/monitor.py >> /home/YOUR_USER/homelab-monitor/monitor.log 2>&1
```

Replace the paths with your installation location. Set `HOMELAB_WEBHOOK_URL` in the crontab if notifications are needed.

On Windows, use Task Scheduler to run Python with the full path to `monitor.py` as its argument.

## Tests

```bash
python -m unittest test_monitor.py
```

Tests verify ping platform handling, web port availability combinations, HTTPS fallback, and warning reports without contacting devices.

## MikroTik resource monitoring

Enable the RouterOS REST API through `www-ssl` and use a monitoring account with permission to read system resources. The check performs an authenticated GET to `/rest/system/resource` and validates the server certificate and hostname with your CA. See the [official MikroTik REST documentation](https://manual.mikrotik.com/docs/developer-guides/rest-api/).

Add this check to your router's `checks` list (also included in `example_config.json`):

```json
{
  "name": "MikroTik resources",
  "type": "mikrotik",
  "url": "https://192.168.0.1",
  "cafile": "cert_export_homelab-ca.crt",
  "cpu_warn_percent": 80,
  "memory_warn_percent": 85,
  "disk_warn_percent": 90
}
```

Use a URL hostname or IP covered by the router certificate. Relative CA paths resolve from the project folder containing `monitor.py`, regardless of the working directory. Place `cert_export_homelab-ca.crt` there, or set `cafile` to another relative or absolute path. Thresholds are configurable starting points for CPU load, memory used, and disk used, not manufacturer limits. Values strictly above a threshold produce `WARN`, retain a healthy exit status, and trigger a notification when entering or leaving warning state. API, authentication, TLS, and malformed resource responses fail the check. Reports display CPU, memory, disk, and available model, version, and uptime fields.

Set credentials in the process environment before running the monitor:

```bash
export MIKROTIK_USERNAME='monitor'
export MIKROTIK_PASSWORD='your-password'
python3 monitor.py
```

```powershell
$env:MIKROTIK_USERNAME = 'monitor'
$env:MIKROTIK_PASSWORD = 'your-password'
python monitor.py
```

For multiple routers with different credentials, set `username_env` and `password_env` on each check to the appropriate environment variable names. Run all tests with `python -m unittest discover -v`.
