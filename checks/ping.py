import platform
import subprocess


def ping(host, timeout):
    """Run the system ping command on Windows or Linux."""
    system = platform.system().lower()
    if system == 'windows':
        # Windows: -n count, -w timeout in milliseconds.
        command = ['ping', '-n', '1', '-w', str(max(1, int(timeout * 1000))), host]
    elif system == 'linux':
        # Linux iputils: -c count, -W timeout in seconds, -n numeric output.
        command = ['ping', '-n', '-c', '1', '-W', str(max(1, int(timeout + 0.999))), host]
    else:
        return False, f'Unsupported OS for ping: {platform.system()}'

    try:
        cp = subprocess.run(command, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, text=True,
                            timeout=timeout + 2)
        return (cp.returncode == 0,
                'ICMP reply' if cp.returncode == 0 else 'No ICMP reply')
    except FileNotFoundError:
        return False, 'ping command not found'
    except subprocess.TimeoutExpired:
        return False, 'Ping timed out'
    except OSError as exc:
        return False, f'Ping error: {exc}'
