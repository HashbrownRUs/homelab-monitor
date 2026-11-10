# Windows host monitoring

Remote Windows host setup for the `ssh_ping` check.
See the [project README](../README.md) for general setup, scheduling, and logging.

## Internet pings from the VM host over SSH

`Monitoring_Server` uses password-authenticated SSH to `monitor@192.168.88.254`
and runs `ping -n 4 1.1.1.1` and `ping -n 4 8.8.8.8` on that Windows host.
Install dependencies with `python -m pip install -r requirements.txt`, then fill in
the entry added to `.env`:

```dotenv
MONITORING_SERVER_SSH_PASSWORD=your-password
```

Before running, connect once with `ssh monitor@192.168.88.254` from the monitoring
VM under the same OS account that runs the script. Verify and accept the server's
host key so it is saved in `~/.ssh/known_hosts`. Unknown or changed keys fail the check.
The host must have an SSH server enabled and allow this account to run Windows ping.
The password is passed directly through the SSH library, never as a command argument.
`ssh_user` defaults to `monitor`, `ssh_port` to 22, and `count` to 4 (allowed: 1–10).
Use `password_env` to override the password variable name. Targets must be IPv4
addresses. Each command allows five seconds per packet plus `timeout_seconds`;
the latter also controls SSH connection and authentication timeouts.

