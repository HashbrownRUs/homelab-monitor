# Home Lab Monitor

Lightweight Python 3 script (stdlib only) for Ubuntu. Checks ICMP ping, TCP ports, and optionally HTTP(S). Reports failed checks, exits with status 1 when unhealthy, optionally posts to a webhook on changes (including recovery).

## Setup

```bash
sudo apt update && sudo apt install -y python3 iputils-ping
mkdir -p ~/homelab-monitor
# Copy monitor.py and config.json into ~/homelab-monitor
cd ~/homelab-monitor
nano config.json   # replace example IPs/ports with your actual values
python3 monitor.py
```

**Important:** All IP addresses in config.json are **examples**. The Omada Controller on OC200 commonly uses TCP port 8043 for HTTPS, but confirm your own configuration. If the router does not serve HTTPS on port 443, remove that check or replace it with the correct port. If a database is intentionally stopped, remove or disable its check.

To check the actual Omada web UI rather than simply whether its TCP port is open, change the controller check to:

```json
{"name": "Controller web UI", "type": "http", "url": "https://192.168.88.10:8043/", "verify_tls": false}
```

`verify_tls: false` is appropriate *only* for a trusted LAN endpoint with a self-signed certificate; otherwise trust the certificate and leave verification enabled.

## Automate (cron)

```bash
crontab -e
```

Check every 5 minutes, saving the most recent report:

```cron
*/5 * * * * /usr/bin/python3 /home/YOUR_USER/homelab-monitor/monitor.py >> /home/YOUR_USER/homelab-monitor/monitor.log 2>&1
```

Use an absolute path to your real home directory rather than `YOUR_USER`.

## JSON + exit codes

```bash
python3 monitor.py --json
```

- `0`: all checks healthy
- `1`: one or more checks failed
- `2`: configuration error

## Optional notifications

Set `HOMELAB_WEBHOOK_URL` in the script's environment to send `{"text":"..."}` JSON to a Slack-compatible webhook when a check changes state (including failure and recovery). This is not a Discord-native format. If you use cron, explicitly provide the environment variable in a wrapper script or crontab; shell exports from your interactive login will not automatically carry over. Webhook destination must be HTTPS and trusted.

To send on every invocation, use `--notify-all`. If a notification fails, its error is printed and monitoring still proceeds. Running via cron could send repeated alerts if no previous state file was stored.
