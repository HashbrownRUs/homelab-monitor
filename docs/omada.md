# Omada OpenAPI

Uses Python's standard library for HTTPS and the existing python-dotenv dependency.
No new packages are needed. Only token acquisition and read-only GET queries are implemented.

In the controller's Global view, open Settings > Platform Integration > Open API.
Create a Client Credentials app with a read-only role and access to the sites you want to monitor.
Copy the Interface Access Address, Omada ID, Client ID, and Client Secret from that page.
Use the controller's displayed Interface Access Address: the OpenAPI port can differ from the web UI port.

Fill the blank entries added to the ignored `backend/.env`:

```dotenv
OMADA_URL=
OMADA_CONTROLLER_ID=
OMADA_CLIENT_ID=
OMADA_CLIENT_SECRET=
OMADA_SITE_ID=
OMADA_CA_FILE=
```

Store your CA certificate at `backend/certs/rootCA.pem` and set
`OMADA_CA_FILE=certs/rootCA.pem`.
This resolves relative to `backend/` on both Windows and Linux, independently of
the directory from which you run the command.

`OMADA_URL` is an HTTPS base URL such as `https://controller.example:8043`.
`OMADA_CONTROLLER_ID` is the Omada ID, not the application Client ID.
Site ID is optional when listing sites; copy the desired site's ID from that response
before querying devices or clients. CA file is optional when the certificate is already
trusted; otherwise point it to your controller's trusted CA PEM file, using an absolute
path or a path relative to `backend/`. The URL hostname must match the certificate.
Keep credentials in `.env`, not in JSON configuration.

Try these commands from the repository root:

```powershell
python script/omada_api.py sites
python script/omada_api.py devices
python script/omada_api.py clients
python script/omada_api.py check
```

The `check` command reports authentication and sites query results without printing
tokens or network inventory. When `OMADA_SITE_ID` is set, it also checks devices and
clients queries; otherwise those queries are skipped. Failures identify the stage
and HTTP status when available, and return exit code 1. Checks only read data and
do not assess individual device health.

They display the first page (up to 100 entries) and the API's pagination metadata:

| Query | Simple things to inspect |
| --- | --- |
| sites | Site names and IDs |
| devices | Managed device names, models, MAC addresses, and reported status |
| clients | Client names, MAC addresses, IPs, and connection details when returned |

Fields depend on controller version, device type, and app permissions. These commands
do not change network settings. They print network inventory, so review output before sharing.
For a trusted local controller with a self-signed certificate, an explicit one-off
`python script/omada_api.py sites --insecure` is available; configuring CA trust is preferred.

To enable monitoring, add this check to your actual `backend/config.json`:

```json
{"name": "Omada sites", "type": "omada", "resource": "sites"}
```

The check uses `OMADA_URL` unless `url` is supplied in the check. Change `resource` to
`devices` or `clients` and fill `OMADA_SITE_ID` (or supply `site_id` in the check).
Use `cafile` for a per-check CA path or explicitly `verify_tls: false` for an unverified
certificate. A successful check means the API query succeeded, not that every managed
device is healthy. The report shows the total count and up to five sample names.
Each run obtains a fresh token; tokens and secrets are never written to logs.

Set `"resources": true` on an Omada check to show returned fields in the monitor's
Resources section and structured `values` in JSON output. The supplied configuration
includes sites, devices, and clients checks. Devices and clients require `OMADA_SITE_ID`.
Sites show name, region, time zone, and scenario when present. Devices show name,
model, IP, raw status code, firmware, uptime, CPU (`cpuUtil`), and memory (`memUtil`).
Clients show name, host name, IP, active/wireless flags, AP, SSID, RSSI, and receive/
transmit rates when returned. Units and status codes are preserved as returned by
the controller; missing fields are omitted. Each query shows only the first page
(up to 100 records), with the total count separately. Query success does not imply
that every device is online. These inventory details are included in saved reports
and any configured webhook notifications. Text resource lines use a compact summary:
site name and time zone; device name, IP, CPU, and memory; client name, IP, and SSID.
The other selected fields remain available in JSON `values`.

Authentication uses `POST /openapi/authorize/token?grant_type=client_credentials`
with `omadacId`, `client_id`, and `client_secret`, followed by the
`Authorization: AccessToken=...` header. Queries use `/openapi/v1/{omadacId}/sites`
and `/openapi/v1/{omadacId}/sites/{siteId}/devices` or `/clients`, with
`page=1&pageSize=100`. Redirects are blocked to protect credentials.

References: [account-level access guide](https://omada-northbound-docs.tplinkcloud.com/guides/account-level-access-guide#basic-guide-info),
[TP-Link OpenAPI setup](https://community.tp-link.com/en/home/kb/detail/412930),
[TP-Link OpenAPI reference](https://use1-omada-northbound.tplinkcloud.com/doc.html).

Run unit tests from `backend/`: `python -m unittest discover -s tests -p test_omada.py`.
