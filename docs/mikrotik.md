# MikroTik configuration

Setup and credentials for MikroTik resource monitoring and router-originated ping checks.
See the [project README](../README.md) for general setup, scheduling, and logging.

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

Set `MIKROTIK_USERNAME` and `MIKROTIK_PASSWORD` in the project-root `.env` file or process environment before running the monitor:

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

For multiple routers with different credentials, set `username_env` and `password_env` on each check to the appropriate environment variable names. Run all tests with `python -m unittest discover -s tests -v`.

## Internet pings from the router (REST)

Use `mikrotik_ping` to send ICMP packets from the MikroTik router through its REST API.
Ordinary `ping` checks still run on the monitoring server.

```json
{
  "name": "Internet from router to 1.1.1.1",
  "type": "mikrotik_ping",
  "url": "https://192.168.88.1",
  "host": "1.1.1.1",
  "count": 3,
  "cafile": "cert_export_homelab-ca.crt"
}
```

Add a separate check for `8.8.8.8`; both checks are included in the configuration files.
Each check passes if at least one packet receives a reply. All checks must pass for the device to be healthy.
`count` defaults to 3 and must be an integer from 1 to 10. The configured `timeout_seconds`
also limits the REST request; allow enough time for all packets when increasing `count`.
The check reuses `MIKROTIK_USERNAME`, `MIKROTIK_PASSWORD`, and CA verification from resource monitoring,
including optional `username_env` and `password_env` overrides. The router user group needs
`read`, `test`, `api`, and `rest-api` policies; ping requires `test`.
See the [MikroTik REST documentation](https://manual.mikrotik.com/docs/developer-guides/rest-api/).

Example output:

```text
    OK   Internet from router to 1.1.1.1: Router ping to 1.1.1.1: 3/3 replies
```
