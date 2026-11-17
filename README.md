# Home Lab Monitor

Python 3.11+ home-lab monitor with `.env` support through `python-dotenv`. Checks ICMP ping on Windows and Linux, TCP ports, HTTP(S) endpoints, and ASUSTOR SNMPv3 resources. Prints a status report and optionally sends webhook alerts when checks fail or recover.

## Repository layout

- `backend/`: Python monitor, checks, tests, dependencies, and local runtime configuration.
- `frontend/`: reserved for the frontend.
- `script/`: standalone tools, including the live SNMP diagnostic.
- `docs/`: device setup guides.

## Setup

Run commands from the project directory. On Ubuntu, install Python and ping:

```bash
sudo apt update
sudo apt install -y python3 iputils-ping
```

Install the Python dependency with `python -m pip install -r backend/requirements.txt`.

Edit `backend/config.json` with your device addresses, ports, and checks. Use `backend/example_config.json` as a reference and remove checks for services you do not run.

Linux:

```bash
python3 backend/monitor.py
```

Windows PowerShell, with Python 3 installed:

```powershell
python backend/monitor.py
```

## Configuration

Each device needs a `name` and a nonempty `checks` list. Supported check types:

| Type | Required fields | Healthy when |
| --- | --- | --- |
| `ping` | `host` | The host replies to ping |
| `omada` | Environment variables in the [Omada guide](docs/omada.md) | A read-only OpenAPI sites, devices, or clients query succeeds |
| `snmp` | Environment variables in the [ASUSTOR guide](docs/asustor-snmp.md) | System OIDs respond; `resources: true` also checks discovered NAS health |
| `ssh_ping` | `ssh_host`, `host` (IPv4 address) | Remote Windows host receives at least one echo reply |
| `mikrotik_ping` | `url`, `host` | The router receives at least one ping reply |
| `tcp` | `host`, `port` | A TCP connection succeeds |
| `mikrotik` | `url` (HTTPS router base URL) | REST resources can be read; high usage produces warnings |
| `http` | `url` | HTTP status is 200–399, 401, or 403 |

Check implementations live in `backend/checks/ping.py`, `backend/checks/tcp.py`, and `backend/checks/http.py`.

For TCP port 80 and HTTP URLs using port 80 (including the default port), the monitor always also checks HTTPS port 443 on the same host. At least one must pass. If port 80 fails but 443 passes, the result is a warning that HTTP may be disabled on purpose. If only port 80 passes, the result warns that HTTPS failed. Warnings appear as `WARN` in text and `warning: true` in JSON, without a failing exit code. HTTP checks preserve the path, query, and TLS verification setting for the HTTPS request. Other ports and explicitly configured HTTPS checks retain their normal failure behavior.

Checks can have an optional `name`. A device is healthy only when all its checks pass. `timeout_seconds` defaults to 3 and must be positive and finite.

For an HTTPS endpoint with a self-signed certificate:

```json
{"name": "Controller web UI", "type": "http", "url": "https://192.168.0.10:8043/", "verify_tls": false}
```

TLS verification is enabled by default. Set `verify_tls` to `false` only for trusted endpoints where you intentionally accept an unverified certificate.

## Options and exit codes

```bash
python3 backend/monitor.py --json
python3 backend/monitor.py --config backend/example_config.json --state custom-state.json
python3 backend/monitor.py --notify-all
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
python3 backend/monitor.py
```

Windows PowerShell:

```powershell
$env:HOMELAB_WEBHOOK_URL = "https://your-webhook-url"
python backend/monitor.py
```

State is saved after each run. Webhook failures are printed without stopping monitoring.

## Scheduling

On Linux, use `crontab -e` and add a check every five minutes:

```cron
*/5 * * * * /usr/bin/python3 /home/YOUR_USER/homelab-monitor/backend/monitor.py >> /home/YOUR_USER/homelab-monitor/monitor.log 2>&1
```

Replace the paths with your installation location. Set `HOMELAB_WEBHOOK_URL` in the crontab if notifications are needed.

On Windows, use Task Scheduler to run Python with the full path to `backend/monitor.py` as its argument.

## Tests

```bash
cd backend
python -m unittest discover -s tests -v
```

Tests verify ping platform handling, web port availability combinations, HTTPS fallback, and warning reports without contacting devices.

## Environment file

The monitor automatically loads `.env` beside `monitor.py` before running checks. Existing environment variables take priority. `.env` is already excluded from Git.

```dotenv
HOMELAB_WEBHOOK_URL=https://your-webhook-url
```

Device credential variable names and examples are documented in the [device guides](#device-guides).


## Report logs

`monitor.py` automatically generates `latest.log` and `history.log` after each run,
including runs using `--json`. `latest.log` contains the newest report;
`history.log` keeps at most the six most recent complete reports, oldest first.
Existing longer history is trimmed on the next run. Logs are stored beside
`monitor.py` unless the top-level `log_directory` option is set in `config.json`.
Relative log directory paths resolve from the backend folder. Standalone live
test scripts do not generate these report logs.

## Device guides

- [MikroTik configuration](docs/mikrotik.md): router REST resources, credentials, TLS, and internet ping checks.
- [Windows host monitoring](docs/windows-host.md): remote Windows ping checks over SSH.
- [ASUSTOR monitoring details](docs/asustor-snmp.md): supported metrics, OIDs, thresholds, and limitations.
