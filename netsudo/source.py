"""Source IP detection."""

from __future__ import annotations

import ipaddress
import socket


def detect_source_ip(target_host: str) -> str:
    """Return the local source IP used to reach target_host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((target_host, 443))
            source = sock.getsockname()[0]
    except OSError as exc:
        raise RuntimeError(f"could not detect source IP for {target_host}: {exc}") from exc

    try:
        ipaddress.ip_address(source)
    except ValueError as exc:
        raise RuntimeError(f"detected invalid source IP: {source}") from exc
    return source
