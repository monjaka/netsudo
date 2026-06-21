"""Configuration loading and validation."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .duration import parse_duration


ALIAS_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,30}$")
DEFAULT_CONFIG_PATHS = (
    Path("./netsudo.toml"),
    Path("/etc/netsudo/config.toml"),
    Path.home() / ".config" / "netsudo" / "config.toml",
)


@dataclass(frozen=True)
class PfSenseConfig:
    host: str
    user: str
    helper: str
    backend: str = "ssh"
    ssh: str = "ssh"
    scp: str = "scp"
    connect_timeout: int = 8
    identity_file: str | None = None
    known_hosts: str | None = None
    batch_mode: bool = True


@dataclass(frozen=True)
class Defaults:
    duration_seconds: int
    reason_required: bool
    confirm: bool
    source: str
    audit_log: str


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    interfaces: tuple[str, ...]
    destinations: tuple[str, ...]
    protocol: str
    ports: tuple[str, ...] | str
    max_duration_seconds: int
    require_sudo: bool
    kill_states: bool
    source_alias: str
    destination_alias: str
    port_alias: str | None

    def validate_destinations(self, requested: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        """Return normalized requested destinations if they fit inside this profile."""
        if not requested:
            raise ValueError("at least one destination is required")
        normalized = tuple(dict.fromkeys(normalize_destination(value) for value in requested))
        for destination in normalized:
            if not destination_allowed(destination, self.destinations):
                raise ValueError(
                    f"destination {destination} is outside profile {self.name} allowed destinations: "
                    f"{', '.join(self.destinations)}"
                )
        return normalized


@dataclass(frozen=True)
class Config:
    path: Path
    pfsense: PfSenseConfig
    defaults: Defaults
    profiles: dict[str, Profile]

    def policy_json(self) -> str:
        payload = {
            "version": 1,
            "profiles": {
                name: {
                    "description": profile.description,
                    "interfaces": list(profile.interfaces),
                    "destinations": list(profile.destinations),
                    "protocol": profile.protocol,
                    "ports": profile.ports if profile.ports == "any" else list(profile.ports),
                    "max_seconds": profile.max_duration_seconds,
                    "kill_states": profile.kill_states,
                    "source_alias": profile.source_alias,
                    "destination_alias": profile.destination_alias,
                    "port_alias": profile.port_alias,
                }
                for name, profile in sorted(self.profiles.items())
            },
        }
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def find_config_path(explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)
        return path

    env_path = os.environ.get("NETSUDO_CONFIG")
    if env_path:
        path = Path(env_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)
        return path

    for path in DEFAULT_CONFIG_PATHS:
        expanded = path.expanduser()
        if expanded.exists():
            return expanded
    raise FileNotFoundError("no config found; run `netsudo init ./netsudo.toml`")


def load_config(explicit: str | None = None) -> Config:
    path = find_config_path(explicit)
    with path.open("rb") as handle:
        raw = tomllib.load(handle)

    pfsense = _parse_pfsense(raw.get("pfsense", {}))
    defaults = _parse_defaults(raw.get("defaults", {}))
    profile_data = raw.get("profiles", {})
    if not isinstance(profile_data, dict) or not profile_data:
        raise ValueError("at least one profile is required")
    profiles = {
        name: _parse_profile(name, value)
        for name, value in profile_data.items()
    }

    return Config(path=path, pfsense=pfsense, defaults=defaults, profiles=profiles)


def _parse_pfsense(raw: dict[str, Any]) -> PfSenseConfig:
    host = _required_str(raw, "host", "pfsense")
    user = str(raw.get("user", "admin"))
    helper = str(raw.get("helper", "/usr/local/sbin/netsudo-helper.php"))
    backend = str(raw.get("backend", "ssh")).lower()
    if backend not in {"ssh", "rest"}:
        raise ValueError("pfsense.backend must be ssh or rest")
    return PfSenseConfig(
        host=host,
        user=user,
        helper=helper,
        backend=backend,
        ssh=str(raw.get("ssh", "ssh")),
        scp=str(raw.get("scp", "scp")),
        connect_timeout=int(raw.get("connect_timeout", 8)),
        identity_file=_optional_str(raw.get("identity_file")),
        known_hosts=_optional_str(raw.get("known_hosts")),
        batch_mode=bool(raw.get("batch_mode", True)),
    )


def _parse_defaults(raw: dict[str, Any]) -> Defaults:
    return Defaults(
        duration_seconds=parse_duration(raw.get("duration", "15m")),
        reason_required=bool(raw.get("reason_required", True)),
        confirm=bool(raw.get("confirm", True)),
        source=str(raw.get("source", "auto")),
        audit_log=str(raw.get("audit_log", "~/.local/state/netsudo/audit.log")),
    )


def _parse_profile(name: str, raw: dict[str, Any]) -> Profile:
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$", name):
        raise ValueError(f"invalid profile name: {name}")
    if not isinstance(raw, dict):
        raise ValueError(f"profile {name} must be a table")

    description = str(raw.get("description", name))
    interfaces = _required_string_list(raw, "interfaces", name)
    destinations = _required_string_list(raw, "destinations", name)
    for destination in destinations:
        _validate_destination(destination, name)

    protocol = str(raw.get("protocol", "tcp")).lower()
    if protocol not in {"tcp", "udp", "tcp/udp", "any"}:
        raise ValueError(f"profile {name}: protocol must be tcp, udp, tcp/udp, or any")

    ports_raw = raw.get("ports", "any")
    if ports_raw == "any":
        ports: tuple[str, ...] | str = "any"
        port_alias = None
    else:
        if not isinstance(ports_raw, list) or not ports_raw:
            raise ValueError(f"profile {name}: ports must be 'any' or a non-empty list")
        ports = tuple(str(port) for port in ports_raw)
        for port in ports:
            _validate_port(port, name)
        port_alias = _alias(raw.get("port_alias"), f"NETSUDO_{_alias_slug(name)}_PORTS")

    max_duration_seconds = parse_duration(raw.get("max_duration", "15m"))
    source_alias = _alias(raw.get("source_alias"), f"NETSUDO_{_alias_slug(name)}_SRC")
    destination_alias = _alias(raw.get("destination_alias"), f"NETSUDO_{_alias_slug(name)}_DST")

    return Profile(
        name=name,
        description=description,
        interfaces=tuple(interfaces),
        destinations=tuple(destinations),
        protocol=protocol,
        ports=ports,
        max_duration_seconds=max_duration_seconds,
        require_sudo=bool(raw.get("require_sudo", True)),
        kill_states=bool(raw.get("kill_states", True)),
        source_alias=source_alias,
        destination_alias=destination_alias,
        port_alias=port_alias,
    )


def _required_str(raw: dict[str, Any], key: str, section: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{section}.{key} is required")
    return value.strip()


def _required_string_list(raw: dict[str, Any], key: str, profile: str) -> list[str]:
    value = raw.get(key)
    if not isinstance(value, list) or not value:
        raise ValueError(f"profile {profile}: {key} must be a non-empty list")
    result = [str(item).strip() for item in value]
    if any(not item for item in result):
        raise ValueError(f"profile {profile}: {key} contains an empty value")
    return result


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _validate_destination(value: str, profile: str) -> None:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"profile {profile}: invalid destination {value}") from exc


def _validate_port(value: str, profile: str) -> None:
    if "-" in value:
        left, right = value.split("-", 1)
        start, end = int(left), int(right)
        if not (1 <= start <= end <= 65535):
            raise ValueError(f"profile {profile}: invalid port range {value}")
        return
    port = int(value)
    if not (1 <= port <= 65535):
        raise ValueError(f"profile {profile}: invalid port {value}")


def _alias(value: Any, default: str) -> str:
    alias = str(value or default)
    if not ALIAS_RE.match(alias):
        raise ValueError(f"invalid alias name: {alias}")
    return alias


def _alias_slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name).upper()


def normalize_destination(value: str) -> str:
    """Validate and normalize a destination host or CIDR network."""
    raw = str(value).strip()
    if not raw:
        raise ValueError("destination must not be empty")
    try:
        if "/" in raw:
            return str(ipaddress.ip_network(raw, strict=False))
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise ValueError(f"invalid destination: {value}") from exc


def destination_allowed(destination: str, allowed_destinations: tuple[str, ...] | list[str]) -> bool:
    requested = _destination_network(destination)
    for allowed in allowed_destinations:
        allowed_network = _destination_network(allowed)
        if requested.version != allowed_network.version:
            continue
        if requested.subnet_of(allowed_network):
            return True
    return False


def _destination_network(value: str) -> Any:
    raw = normalize_destination(value)
    if "/" in raw:
        return ipaddress.ip_network(raw, strict=False)
    return ipaddress.ip_network(raw + "/32", strict=False)
