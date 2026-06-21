"""Source IP detection."""

from __future__ import annotations

import ipaddress
import socket


def validate_source_ip(source: str) -> str:
    """Validate and normalize an IPv4 source address."""
    try:
        return str(ipaddress.IPv4Address(str(source).strip()))
    except ValueError as exc:
        raise ValueError(f"source must be an IPv4 address: {source}") from exc


def detect_source_ip(target_host: str) -> str:
    """Return the local source IP used to reach target_host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((target_host, 443))
            source = sock.getsockname()[0]
    except OSError as exc:
        raise RuntimeError(f"could not detect source IP for {target_host}: {exc}") from exc

    return validate_source_ip(source)
