# ASUSTOR SNMP monitoring

The NAS check uses SNMPv3 MD5 `authNoPriv` with the existing
`ASUSTOR_SNMP_HOST`, `ASUSTOR_SNMP_PORT`, `ASUSTOR_SNMP_USERNAME`, and
`ASUSTOR_SNMP_PASSWORD` environment variables. `backend/monitor.py` loads the backend
`.env` once; process environment variables take priority. Credentials are never
written to reports, logs, or the counter cache. The NAS account must have
read-only SNMP access; the code sends GET and GETBULK requests only.

## Connection setup

The NAS entry includes an `snmp` check based on the supplied test script. Install
dependencies with `python -m pip install -r backend/requirements.txt` and add these values
to `.env` beside `monitor.py`:

```dotenv
ASUSTOR_SNMP_HOST=192.168.88.253
ASUSTOR_SNMP_PORT=161
ASUSTOR_SNMP_USERNAME=your-snmp-user
ASUSTOR_SNMP_PASSWORD=your-snmp-auth-password
```

The NAS configuration enables `"resources": true` for dynamic ASUSTOR disk,
volume, hardware and standard network monitoring, plus read-only discovery of
fallback MIBs. Missing data is `UNAVAILABLE`; checks outside SNMP's capabilities
are `UNSUPPORTED`, never passing defaults. The sections below describe supported metrics, exact OIDs/units, thresholds,
counter rates, and observed limitations on this NAS. Set `resources` to `false` to use only the original
three-OID check.

Enable SNMPv3 on the NAS with MD5 authentication and no privacy encryption
(`authNoPriv`), matching the test script. Allow UDP port 161 from the monitoring
server. Run `python backend/monitor.py` to include system description, uptime, and name
in the normal report, JSON output, and failure/recovery notifications. All three
OIDs must succeed. Each request uses `timeout_seconds` and one retry.

To test the NAS directly on Windows using the PySNMP Python package, run from
the project folder in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv\Scripts\python.exe .\script\snmp_windows.py
.\.venv\Scripts\python.exe .\script\snmp_windows.py --resources
```

The script loads the `backend/.env` regardless of the working directory.
It queries the real NAS and prints each OID result. No Windows SNMP feature or
external SNMP command is required. Exit codes are `0` for success, `1` for SNMP
failure, and `2` for invalid configuration. This live script runs separately
from `test_snmp.py`, whose unit tests use simulated responses.

Run `--resources` twice to obtain network rates from counter deltas. The full
monitor writes text reports to `latest.log` and retains the six most recent reports in `history.log`;
`--json` also includes resource values, units, source OIDs, and availability.

Optional check fields `host` and `port` override the environment defaults;
`username_env` and `password_env` select alternate credential variables.
The basic connection test prints raw SNMP TimeTicks (hundredths of a second);
the resource report formats uptime as days, hours, minutes, and seconds. Credentials stay in the environment and are excluded from reports.

## Run on Windows

From the project directory in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv\Scripts\python.exe backend/monitor.py
.\.venv\Scripts\python.exe backend/monitor.py --json
```

Test just the NAS resources, without webhook notifications or polling the other
devices:

```powershell
.\.venv\Scripts\python.exe .\script\snmp_windows.py --resources
.\.venv\Scripts\python.exe .\script\snmp_windows.py --resources --json
```

Run twice to establish network rates; the first sample deliberately reports
rates as `UNAVAILABLE`. The ordinary `snmp_windows.py` command without arguments
still performs the original three-OID connection test. Paths resolve from the
script location, so these commands also work with absolute script paths from
another working directory.

Run offline unit tests separately:

```powershell
cd backend
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Python 3.11 or newer is required for the bounded asynchronous resource polling.
No Windows SNMP service, external `snmpwalk`, or MIB compiler is needed.

## Configuration and reporting

The existing NAS `snmp` entry enables the expanded check with `"resources": true`.
Other device checks retain their existing behavior. Disabling this flag restores
the original three-OID check. `host`, `port`, `username_env`, and `password_env`
continue to override the ASUSTOR environment defaults.

The resource check produces individual health checks, a `Resources:` section,
and JSON `resources`, `coverage`, and `capabilities` fields. Each resource has a
value, unit, source OID, availability status and display text. Volume usage also
includes numeric total, used and free capacities with their capacity unit.
`capabilities` describes discovery for each branch; a readable branch does not
mean every metric within it is supported.

`WARN` means an observed threshold or health warning; existing healthy exit
status behavior is retained. Known disk/SMART failure, RAID degradation and a
failed required interface produce `FAIL` and a failing exit code.
`UNAVAILABLE`, `UNSUPPORTED` and `N/A` have JSON `ok: null` and are never printed
as passing. Overall device `OK` means no observed check failed; it is not a
claim that the unsupported security or diagnostic checks passed. Missing optional
telemetry is visible without making an otherwise reachable NAS fail.

Unrecognized health strings remain `UNAVAILABLE` rather than defaulting to healthy.
Rebuilding/recovering arrays warn. Positive fan RPM is a speed-based check, not
an independent fan controller health signal; zero RPM warns because some fan
profiles intentionally stop the fan. Interface administrative disablement is
`N/A` unless the interface is explicitly required.

Thresholds are monitoring policy, not manufacturer-certified safety limits:

| Field | Default | Warning condition |
| --- | ---: | --- |
| `cpu_warn_percent` | 80 | CPU usage strictly above threshold |
| `memory_warn_percent` | 85 | RAM usage strictly above threshold |
| `disk_warn_percent` | 90 | Volume usage strictly above threshold |
| `cpu_temp_warn_c` | 80 | CPU temperature strictly above threshold |
| `system_temp_warn_c` | 60 | System temperature strictly above threshold |
| `disk_temp_warn_c` | 50 | Disk temperature strictly above threshold |
| `ups_battery_warn_percent` | 20 | Battery at/below threshold or UPS-reported low threshold, whichever is higher |
| `ups_runtime_warn_seconds` | 300 | Identified UPS runtime at/below threshold |

`required_interfaces` is a list of names which must be present and operational;
the supplied NAS config requires `eth0`, as found during discovery. Other
administratively enabled interfaces that go down warn. Errors/drops warn on
increases between valid polls, not merely a nonzero historical total.

Per-request timeout uses the existing `timeout_seconds`, with one retry.
Discovery is bounded to `poll_budget_seconds` (default 60) after the connection
probe, with at most 100 bulk responses/2000 varbinds per branch and a per-branch
deadline. Truncation/timeouts produce warnings and mark the branch incomplete.
Empty walks cannot distinguish an unsupported MIB from a restricted SNMP view;
the report states this limitation. Failed authentication stops discovery.

`monitor.py` writes the same formatted report to `latest.log` (replaced each run)
and `history.log` (the six most recent reports, oldest first), including when
`--json` is used. Both files are generated automatically on each monitor run. Set the
top-level `log_directory` config option to change their directory; relative
paths resolve from the backend folder. Log write failures are printed to stderr.
Existing `state.json`, state-file override, webhook and failure/recovery behavior
remain; appearance/disappearance of dynamic checks also triggers a state change.
The direct live-test script does not write those report logs or send webhooks.

## OID mapping and units

Mappings below were derived from the supplied `ASUSTOR-SYSTEM-MIB.txt`,
`ASUSTOR-DISK-MIB.txt` and `ASUSTOR-UPS-MIB.txt`. These files supply definitions,
not executable instructions. Numeric OIDs are used at runtime. Let `V` denote
`1.3.6.1.4.1.44738` and `i` a discovered instance index, which need not start at
one or be contiguous.

| Metric | ASUSTOR OID | Interpretation / fallback |
| --- | --- | --- |
| Hostname | Standard `1.3.6.1.2.1.1.5.0` | System name |
| Model | `V.2.1.0` | Report the agent's model string verbatim |
| ADM version | `V.1.2.0` | No substitution of Linux kernel version for ADM |
| NAS uptime | Standard `1.3.6.1.2.1.25.1.1.0` | TimeTicks / 100 seconds; fallback `V.1.4.0` is an opaque vendor string |
| Agent uptime | Standard `1.3.6.1.2.1.1.3.0` | TimeTicks / 100; separate from host uptime |
| CPU usage | `V.2.3.1.2.i` | Mean of valid per-core percentages; fallback `hrProcessorLoad`, then `100 - ssCpuIdle` |
| Fan | `V.2.4.1.2.i` | RPM; dynamic sensor rows |
| CPU/system temperature | `V.2.5.1.2.i` / `.3.i` | Celsius; invalid sentinel values rejected |
| RAM used | `V.2.6.1.4.i` | `100 - free percentage`; fallback UCD real total/free, then HR physical memory |
| Disk ID/model | `V.4.1.1.2.i` / `.3.i` | Disk bay identifier / model |
| Disk/SMART status | `V.4.1.1.5.i` / `.6.i` | Separate status strings, not detailed SMART tests |
| Disk temperature/capacity | `V.4.1.1.7.i` / `.8.i` | Celsius / MIB-reported GB |
| Volume name/RAID/status | `V.5.1.1.2.i` / `.3.i` / `.4.i` | Dynamic volume and RAID-level/status fields |
| Volume total/free | `V.5.1.1.6.i` / `.7.i` | MIB-reported GB; used = total - free |
| UPS identity/status | `V.6.1.1.2.i`, `.3.i`, `.7.i` | Require nonempty manufacturer or model before using battery readings |
| UPS runtime/charge/low charge | `V.6.1.1.8.i` / `.9.i` / `.10.i` | Seconds / percent / percent |
| ADM update availability | `V.1.7.0` | Recognized agent response; no independent online update check |

ASUSTOR's size descriptions say GB without defining the binary/decimal base;
their disk sizes resemble binary GiB on this NAS. Values are labeled
`GB (MIB-reported)` and are not silently converted to bytes. Volume percentages
are valid because numerator and denominator have the same unit. The hardware
memory size fields have no documented unit, so RAM uses the explicit percentage
rather than guessing. RAM's vendor percentage and UCD free-real fallback include
memory used for cache; they do not represent an out-of-memory diagnosis.

The standard fallbacks follow [HOST-RESOURCES-MIB (RFC 2790)](https://www.rfc-editor.org/rfc/rfc2790):
storage bytes = allocation units × allocation count. Only root `/volume*`
mounts are reported as volume fallbacks; nested shares/bind mounts are excluded.
Valid vendor volume counters take priority over the corresponding standard row.
Standard capacity counters cannot establish RAID or SMART health.

Network interfaces use [IF-MIB (RFC 2863)](https://www.rfc-editor.org/rfc/rfc2863):
`ifAdminStatus`, `ifOperStatus`, `ifHighSpeed` (Mbit/s) or `ifSpeed` (bit/s),
`ifHCInOctets`/`ifHCOutOctets` (64-bit bytes), falling back to 32-bit
`ifInOctets`/`ifOutOctets`. Discards/errors are separate cumulative packet
counters. Vendor `V.3` counters are documented in KB and were zero in discovery;
they are not substituted for the standard byte counters.

UCD memory, swap, CPU load and idle sources use the
[Net-SNMP UCD definitions](https://www.net-snmp.org/docs/mibs/ucdavis.html).
Load averages are displayed as load values, not CPU percentages. Disk I/O uses
[UCD-DISKIO-MIB](https://www.net-snmp.org/docs/mibs/ucdDiskIOMIB.html) byte and
operation totals, preferring its 64-bit byte counters. Recognized UPS power
strings use [NUT status tokens](https://networkupstools.org/docs/developer-guide.chunked/apas02.html),
including `OL`, `OB`, `LB` and `FSD`; unrecognized strings are not healthy defaults.

Network rates use `(new bytes - old bytes) / actual elapsed seconds`, displayed
as decimal MB/s (1 MB = 1,000,000 bytes). Counter64 arithmetic retains integer
precision. Baselines are stored separately per host/port/username under the
ignored `.snmp-cache/` directory, overridable with `counter_state_dir` on the
check. Only interface counters, identity/continuity fields and uptime are saved;
no credentials, NAS account details, disk serials or system description are cached.
The existing alert state file is separate.

Reboot/agent-uptime rollback, changed interface identity or counter discontinuity,
decreasing 64-bit counters, uptime/sample interval disagreement, impossible link throughput, backwards time and
samples older than one day invalidate rates. A 32-bit wrap is accepted only
with an unchanged discontinuity marker and an interval short enough that link
speed rules out multiple wraps. Otherwise the rate remains unavailable until
comparable samples exist. Missing/corrupt cache files simply require a new
baseline. Packet counter decreases are discarded rather than guessed to be wraps.

## Observed support on this NAS

Read-only discovery on 11 November 2026 found:

| Category | Result |
| --- | --- |
| System | Hostname, ADM version, host and agent uptime available |
| Model | Agent returns `AS1A02T`; hostname identifies `AS1102TL-A658`. The reported model is preserved, not replaced with the requested marketing model |
| Hardware | Four CPU rows, RAM percentage, CPU temperature and one fan available |
| System temperature | Unavailable: agent returned the invalid value `-2147483648` |
| Disks | Two disks with status, SMART summary, Celsius temperatures and MIB-reported capacities |
| Volumes | One volume with RAID level/status and total/free capacities; standard storage also exposes the system volume |
| Network | `lo` and `eth0`, operational/admin status, link speed, 64-bit bytes, errors and drops available |
| Disk I/O | No readable instances under `1.3.6.1.4.1.2021.13.15`; may need an agent module or broader read-only SNMP view |
| UPS | Unverified placeholder row: empty manufacturer/model, `OB`, zero battery/runtime. Connected UPS cannot be confirmed; readings are ignored and health is `N/A` |
| ADM update availability | Agent reports a recognized latest-version string; available through `V.1.7.0` |
| Host device status | Partial: some HR device rows have no status, so comprehensive hardware health remains unavailable |
| Independent storage pool health | Unsupported by these MIBs; volume/RAID health is reported separately |
| Malware/security/firewall/backup/events/detailed SMART tests | Unsupported by these MIBs; another reliable read-only source or ADM access is required |

No NAS settings were changed. Availability and values can change on subsequent
polls; the runtime report is the source for current readings.
