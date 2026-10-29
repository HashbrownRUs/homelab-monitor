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
| `http` | `url` | HTTP status is 200–399, 401, or 403 |

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

Tests verify Windows and Linux ping command arguments and unsupported OS handling. They simulate ping responses without contacting devices.
