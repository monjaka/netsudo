"""SSH/SCP transport for pfSense."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from .config import PfSenseConfig


class TransportError(RuntimeError):
    """Raised when an SSH or SCP command fails."""


def ssh_base(config: PfSenseConfig) -> list[str]:
    ensure_ssh_backend(config)
    cmd = [
        config.ssh,
        "-o",
        f"ConnectTimeout={config.connect_timeout}",
        "-o",
        f"BatchMode={'yes' if config.batch_mode else 'no'}",
    ]
    if config.identity_file:
        cmd.extend(["-i", config.identity_file])
    if config.known_hosts:
        cmd.extend(["-o", f"UserKnownHostsFile={config.known_hosts}"])
    cmd.append(f"{config.user}@{config.host}")
    return cmd


def scp_base(config: PfSenseConfig) -> list[str]:
    ensure_ssh_backend(config)
    cmd = [
        config.scp,
        "-o",
        f"ConnectTimeout={config.connect_timeout}",
        "-o",
        f"BatchMode={'yes' if config.batch_mode else 'no'}",
    ]
    if config.identity_file:
        cmd.extend(["-i", config.identity_file])
    if config.known_hosts:
        cmd.extend(["-o", f"UserKnownHostsFile={config.known_hosts}"])
    return cmd


def run_ssh(config: PfSenseConfig, remote_command: str, stdin: str | None = None) -> str:
    cmd = ssh_base(config) + [remote_command]
    proc = subprocess.run(
        cmd,
        input=stdin,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise TransportError(proc.stderr.strip() or proc.stdout.strip() or f"ssh failed: {proc.returncode}")
    return proc.stdout


def run_helper(config: PfSenseConfig, action: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    remote = f"/usr/local/bin/php {shell_quote(config.helper)} {shell_quote(action)}"
    stdout = run_ssh(config, remote, json.dumps(payload or {}, sort_keys=True))
    try:
        decoded = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise TransportError(f"helper returned non-JSON output: {stdout.strip()}") from exc
    if not decoded.get("ok", False):
        raise TransportError(decoded.get("error", "helper failed"))
    return decoded


def copy_file(config: PfSenseConfig, local: Path, remote: str) -> None:
    target = f"{config.user}@{config.host}:{remote}"
    cmd = scp_base(config) + [str(local), target]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if proc.returncode != 0:
        raise TransportError(proc.stderr.strip() or proc.stdout.strip() or f"scp failed: {proc.returncode}")


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def ensure_ssh_backend(config: PfSenseConfig) -> None:
    if config.backend == "ssh":
        return
    raise TransportError(
        "pfsense.backend=rest is configured, but the REST transport is not implemented yet; "
        "use backend=\"ssh\" for the current release"
    )
