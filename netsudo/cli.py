"""Command line interface."""

from __future__ import annotations

import argparse
import getpass
import importlib.resources
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from . import __version__
from .audit import write_audit
from .config import Config, load_config
from .duration import format_duration, parse_duration
from .source import detect_source_ip, validate_source_ip
from .transport import TransportError, copy_file, run_helper, run_ssh, shell_quote


SUDO_REEXEC_ENV = "NETSUDO_SUDO_REEXEC"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(raw_argv)
    args._netsudo_argv = raw_argv
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError, RuntimeError, TransportError) as exc:
        print(f"netsudo: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netsudo", description="Temporary audited pfSense firewall grants")
    parser.add_argument("--version", action="version", version=f"netsudo {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init_p = sub.add_parser("init", help="write an example config")
    init_p.add_argument("path", nargs="?", default="./netsudo.toml")
    init_p.set_defaults(func=cmd_init)

    policy_p = sub.add_parser("render-policy", help="render pfSense helper policy JSON")
    add_config_arg(policy_p)
    policy_p.set_defaults(func=cmd_render_policy)

    install_p = sub.add_parser("install-helper", help="copy helper and policy to pfSense")
    add_config_arg(install_p)
    install_p.set_defaults(func=cmd_install_helper)

    setup_p = sub.add_parser("setup", help="install helper and create pfSense aliases/rules")
    add_config_arg(setup_p)
    setup_p.set_defaults(func=cmd_setup)

    allow_p = sub.add_parser("allow", help="grant temporary access")
    add_config_arg(allow_p)
    allow_p.add_argument("profile")
    allow_p.add_argument("--for", dest="duration", default=None, help="duration such as 15m or 1h")
    allow_p.add_argument("--source", default=None, help="source IPv4 to grant; default auto-detects this host")
    allow_p.add_argument(
        "--destination",
        "--dest",
        dest="destinations",
        action="append",
        default=None,
        help="destination host/CIDR to grant; repeat for multiple; default uses the full profile scope",
    )
    allow_p.add_argument("--reason", default="", help="audit reason")
    allow_p.add_argument("-y", "--yes", action="store_true", help="skip confirmation prompt")
    allow_p.add_argument("--no-sudo-check", action="store_true", help="do not require local root for privileged profiles")
    allow_p.set_defaults(func=cmd_allow)

    status_p = sub.add_parser("status", help="show active grants")
    add_config_arg(status_p)
    status_p.add_argument("--json", action="store_true")
    status_p.set_defaults(func=cmd_status)

    revoke_p = sub.add_parser("revoke", help="revoke a grant")
    add_config_arg(revoke_p)
    revoke_p.add_argument("grant", help="grant id, last, or all")
    revoke_p.set_defaults(func=cmd_revoke)

    prune_p = sub.add_parser("prune", help="remove expired grants")
    add_config_arg(prune_p)
    prune_p.set_defaults(func=cmd_prune)

    return parser


def add_config_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", "-c", default=None, help="path to netsudo TOML config")


def cmd_init(args: argparse.Namespace) -> int:
    destination = Path(args.path).expanduser()
    if destination.exists():
        raise RuntimeError(f"{destination} already exists")
    source = Path(__file__).resolve().parent.parent / "config" / "profiles.example.toml"
    if not source.exists():
        with importlib.resources.as_file(importlib.resources.files("netsudo").joinpath("data/profiles.example.toml")) as packaged:
            source = packaged
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    print(f"Wrote {destination}")
    print("Edit it, then run: netsudo setup --config " + str(destination))
    return 0


def cmd_render_policy(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    print(config.policy_json(), end="")
    return 0


def cmd_install_helper(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    install_helper(config)
    print(f"Installed helper at {config.pfsense.helper}")
    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    install_helper(config)
    result = run_helper(config.pfsense, "setup", {"policy": json.loads(config.policy_json())})
    print(result.get("message", "setup complete"))
    for line in result.get("changes", []):
        print(f"- {line}")
    return 0


def cmd_allow(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    profile = config.profiles.get(args.profile)
    if profile is None:
        raise ValueError(f"unknown profile: {args.profile}")

    if profile.require_sudo and not args.no_sudo_check and hasattr(os, "geteuid") and os.geteuid() != 0:
        return rerun_with_sudo(args, config)

    duration = parse_duration(args.duration or config.defaults.duration_seconds)
    if duration > profile.max_duration_seconds:
        raise ValueError(
            f"requested duration {format_duration(duration)} exceeds profile max "
            f"{format_duration(profile.max_duration_seconds)}"
        )

    if config.defaults.reason_required and not args.reason.strip():
        raise ValueError("--reason is required by config")

    source = resolve_source(config, args.source)
    destinations = profile.validate_destinations(args.destinations) if args.destinations else None
    payload = {
        "profile": profile.name,
        "source": source,
        "duration_seconds": duration,
        "reason": args.reason,
        "requested_by": current_operator(),
        "request_host": socket.gethostname(),
        "client_platform": platform.platform(),
    }
    if destinations:
        payload["destinations"] = list(destinations)

    if config.defaults.confirm and not args.yes:
        print_grant_preview(config, payload)
        answer = input("Grant this access? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("aborted")
            return 2

    result = run_helper(config.pfsense, "grant", payload)
    grant = result["grant"]
    write_audit(config.defaults.audit_log, "grant", grant)
    print(f"Granted {grant['id']}")
    print(f"Source: {grant['source']}")
    if grant.get("destinations"):
        print(f"Destinations: {', '.join(grant['destinations'])}")
    print(f"Profile: {grant['profile']}")
    print(f"Expires: {grant['expires_at']}")
    return 0


def current_operator() -> str:
    return os.environ.get("SUDO_USER") or getpass.getuser()


def rerun_with_sudo(args: argparse.Namespace, config: Config) -> int:
    if os.environ.get(SUDO_REEXEC_ENV) == "1":
        raise RuntimeError(f"profile {args.profile} requires local sudo")

    sudo = shutil.which("sudo")
    if sudo is None:
        raise RuntimeError(f"profile {args.profile} requires local sudo, but sudo was not found")

    module_parent = str(Path(__file__).resolve().parent.parent)
    pythonpath_parts = [module_parent]
    if os.environ.get("PYTHONPATH"):
        pythonpath_parts.append(os.environ["PYTHONPATH"])

    command = [
        sudo,
        "env",
        f"{SUDO_REEXEC_ENV}=1",
        "PYTHONPATH=" + os.pathsep.join(pythonpath_parts),
        sys.executable,
        "-m",
        "netsudo.cli",
        *args._netsudo_argv,
        "--config",
        str(config.path.resolve()),
    ]
    return subprocess.call(command)


def cmd_status(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result = run_helper(config.pfsense, "status", {})
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    grants = result.get("grants", [])
    if not grants:
        print("No active grants.")
        return 0
    for grant in grants:
        expires_in = max(0, int(grant.get("expires_at_epoch", 0)) - int(time.time()))
        destinations = grant.get("destinations")
        destination_text = f" -> {','.join(destinations)}" if destinations else ""
        print(
            f"{grant['id']}  {grant['profile']}  {grant['source']}{destination_text}  "
            f"expires in {format_duration(expires_in)}  reason={grant.get('reason', '')}"
        )
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result = run_helper(config.pfsense, "revoke", {"grant": args.grant})
    write_audit(config.defaults.audit_log, "revoke", {"grant": args.grant, "result": result})
    print(result.get("message", "revoked"))
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result = run_helper(config.pfsense, "prune", {})
    print(result.get("message", "pruned"))
    return 0


def install_helper(config: Config) -> None:
    pfsense = config.pfsense
    remote_dir = str(Path(pfsense.helper).parent)
    run_ssh(pfsense, f"mkdir -p {shell_quote(remote_dir)} /usr/local/etc/netsudo /var/db/netsudo")

    with importlib.resources.as_file(importlib.resources.files("netsudo").joinpath("data/pfsense-helper.php")) as helper:
        copy_file(pfsense, Path(helper), "/tmp/netsudo-helper.php")

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write(config.policy_json())
        policy_tmp = Path(handle.name)
    try:
        copy_file(pfsense, policy_tmp, "/tmp/netsudo-policy.json")
    finally:
        policy_tmp.unlink(missing_ok=True)

    run_ssh(
        pfsense,
        "install -m 0755 /tmp/netsudo-helper.php "
        f"{shell_quote(pfsense.helper)} && "
        "install -m 0600 /tmp/netsudo-policy.json /usr/local/etc/netsudo/policy.json && "
        "rm -f /tmp/netsudo-helper.php /tmp/netsudo-policy.json",
    )


def resolve_source(config: Config, source_arg: str | None) -> str:
    source = source_arg or config.defaults.source
    if source == "auto":
        return detect_source_ip(config.pfsense.host)
    return validate_source_ip(source)


def print_grant_preview(config: Config, payload: dict[str, Any]) -> None:
    profile = config.profiles[payload["profile"]]
    print("Grant request")
    print(f"  Source:       {payload['source']}")
    print(f"  Profile:      {profile.name}")
    print(f"  Description:  {profile.description}")
    destinations = payload.get("destinations") or list(profile.destinations)
    print(f"  Destinations: {', '.join(destinations)}")
    print(f"  Protocol:     {profile.protocol}")
    print(f"  Ports:        {profile.ports if profile.ports == 'any' else ', '.join(profile.ports)}")
    print(f"  Duration:     {format_duration(payload['duration_seconds'])}")
    print(f"  Reason:       {payload.get('reason', '')}")


if __name__ == "__main__":
    raise SystemExit(main())
