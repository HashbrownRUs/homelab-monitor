import socket


def tcp(host, port, timeout):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, f'TCP {port} accepting connections'
    except OSError as exc:
        return False, f'TCP {port}: {exc}'
