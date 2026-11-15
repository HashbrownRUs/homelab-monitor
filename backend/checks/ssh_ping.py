# File: ssh_ping.py
# Last updated: 2026-11-07
# Description: Run Windows ping over SSH using a password from the environment.

import ipaddress
import os
import re

import paramiko


def ssh_ping(item, timeout):
    # Only IP literals enter the remote shell command.
    host = str(ipaddress.IPv4Address(item['host']))
    count = item.get('count', 4)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 10:
        raise ValueError('SSH ping count must be an integer between 1 and 10')
    password_env = item.get('password_env', 'MONITORING_SERVER_SSH_PASSWORD')
    password = os.environ.get(password_env)
    if not password:
        return False, f'Set {password_env} in .env or the environment'
    client = paramiko.SSHClient()
    try:
        client.load_system_host_keys()
        client.connect(item['ssh_host'], port=int(item.get('ssh_port', 22)),
                       username=item.get('ssh_user', 'monitor'), password=password,
                       timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                       allow_agent=False, look_for_keys=False)
        # Four Windows pings may take longer than the connection timeout.
        command_timeout = count * 5 + timeout
        _, stdout, _ = client.exec_command(f'ping -n {count} {host}', timeout=command_timeout)
        output = stdout.read().decode('utf-8', errors='replace')
        status = stdout.channel.recv_exit_status()
        # Windows may exit zero for destination-unreachable responses. Require
        # an actual echo reply (TTL field), rather than trusting that exit code.
        received = len(re.findall(r'\bTTL\s*=\s*\d+', output, re.IGNORECASE))
        return status == 0 and received > 0, f'SSH ping to {host}: {received}/{count} replies'
    except paramiko.AuthenticationException:
        return False, 'SSH authentication failed; check the username and password in .env'
    except (paramiko.SSHException, OSError, EOFError):
        return False, 'SSH ping failed; check connectivity, known_hosts, and SSH server settings'
    finally:
        client.close()
