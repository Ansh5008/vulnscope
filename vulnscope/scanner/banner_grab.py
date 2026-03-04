import socket
from typing import Optional


def grab_banner(host: str, port: int, timeout: float = 1.0) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(1024)
            except socket.timeout:
                return None
            if not data:
                return None
            return data.decode(errors="ignore").strip()
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None

