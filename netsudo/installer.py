"""Interactive installer for netsudo."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .transport import shell_quote


DEFAULT_CONFIG = Path("./netsudo.toml")
DEFAULT_KEY = Path.home() / ".ssh" / "netsudo_pfsense"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Configure netsudo for a pfSense firewall")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="config path to write")
    parser.add_argument("--non-interactive", action="store_true", help="write defaults without prompting")
    args = parser.parse_args(argv)

    try:
        install(Path(args.config).expanduser(), interactive=not args.non_interactive)
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        print(f"netsudo-install: {exc}", file=sys.stderr)
        return 1
    return 0


def install(config_path: Path, *, interactive: bool) -> None:
    print("netsudo installer")
    print("This writes config and can bootstrap an SSH key. It does not store pfSense passwords.")

    host = prompt("pfSense host", "192.168.3.1", interactive)
    user = prompt("pfSense SSH user", "admin", interactive)
    backend = prompt_choice("Backend", ["ssh", "rest"], "ssh", interactive)

    identity_file = ""
    batch_mode = True
    if backend == "ssh":
        key_path = Path(prompt("Dedicated SSH key path", str(DEFAULT_KEY), interactive)).expanduser()
        if confirm("Generate SSH key if missing", True if interactive else False, interactive):
            ensure_ssh_key(key_path)
            identity_file = str(key_path)

        if identity_file and confirm("Install public key on pfSense now", True if interactive else False, interactive):
            install_public_key(host=host, user=user, key_path=key_path)

        batch_mode = not confirm("Allow password prompts from netsudo commands", False, interactive)
    else:
        print("REST backend config is written as an experimental placeholder.")
        print("The current CLI release still uses the SSH helper backend for live changes.")

    config_path.parent.mkdir(parents=True, exist_ok=True)
    if config_path.exists() and not confirm(f"Overwrite {config_path}", False, interactive):
        raise RuntimeError(f"{config_path} already exists")

    config_path.write_text(
        render_config(
            host=host,
            user=user,
            backend=backend,
            identity_file=identity_file,
            batch_mode=batch_mode,
        ),
        encoding="utf-8",
    )
    os.chmod(config_path, 0o600)
    print(f"Wrote {config_path}")

    if backend == "ssh" and confirm("Run netsudo setup now", False, interactive):
        run_netsudo(["setup", "--config", str(config_path)])
    else:
        print(f"Next: edit profiles in {config_path}, then run `python3 -m netsudo.cli setup --config {config_path}`")


def ensure_ssh_key(path: Path) -> None:
    public = Path(str(path) + ".pub")
    if path.exists() and public.exists():
        print(f"Using existing key {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    run(["ssh-keygen", "-t", "ed25519", "-f", str(path), "-N", "", "-C", "netsudo-pfsense"])
    os.chmod(path, 0o600)


def install_public_key(*, host: str, user: str, key_path: Path) -> None:
    public = Path(str(key_path) + ".pub")
    if not public.exists():
        raise RuntimeError(f"missing public key: {public}")

    print("Installing public key. pfSense may prompt for the account password.")
    if shutil.which("ssh-copy-id"):
        run(["ssh-copy-id", "-i", str(public), f"{user}@{host}"])
        return

    public_key = public.read_text(encoding="utf-8").strip()
    remote = (
        "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; "
        "grep -qxF " + shell_quote(public_key) + " ~/.ssh/authorized_keys || "
        "printf '%s\\n' " + shell_quote(public_key) + " >> ~/.ssh/authorized_keys"
    )
    run(["ssh", f"{user}@{host}", remote])


def render_config(*, host: str, user: str, backend: str, identity_file: str, batch_mode: bool) -> str:
    identity_line = f'identity_file = "{escape_toml(identity_file)}"\n' if identity_file else ""
    return f"""[pfsense]
host = "{escape_toml(host)}"
user = "{escape_toml(user)}"
backend = "{escape_toml(backend)}"
helper = "/usr/local/sbin/netsudo-helper.php"
ssh = "ssh"
scp = "scp"
connect_timeout = 8
batch_mode = {str(batch_mode).lower()}
{identity_line}
[defaults]
duration = "15m"
reason_required = true
confirm = true
source = "auto"
audit_log = "~/.local/state/netsudo/audit.log"

[profiles.admin]
description = "Short-lived admin access to management services"
interfaces = ["lan"]
destinations = ["192.168.3.0/24"]
protocol = "tcp"
ports = ["22", "443", "8006"]
max_duration = "30m"
require_sudo = true
kill_states = true

[profiles.all]
description = "Emergency broad internal access"
interfaces = ["lan"]
destinations = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
protocol = "any"
ports = "any"
max_duration = "15m"
require_sudo = true
kill_states = true
"""


def prompt(label: str, default: str, interactive: bool) -> str:
    if not interactive:
        return default
    answer = input(f"{label} [{default}]: ").strip()
    return answer or default


def prompt_choice(label: str, choices: list[str], default: str, interactive: bool) -> str:
    if not interactive:
        return default
    joined = "/".join(choices)
    while True:
        answer = input(f"{label} ({joined}) [{default}]: ").strip().lower() or default
        if answer in choices:
            return answer
        print(f"Choose one of: {', '.join(choices)}")


def confirm(label: str, default: bool, interactive: bool) -> bool:
    if not interactive:
        return default
    suffix = "Y/n" if default else "y/N"
    answer = input(f"{label}? [{suffix}] ").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def run_netsudo(args: list[str]) -> None:
    env = os.environ.copy()
    package_root = Path(__file__).resolve().parents[1]
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(package_root) if not existing else str(package_root) + os.pathsep + existing
    run([sys.executable, "-m", "netsudo.cli", *args], env=env)


def run(command: list[str], env: dict[str, str] | None = None) -> None:
    try:
        subprocess.run(command, check=True, env=env)
    except FileNotFoundError as exc:
        raise RuntimeError(f"missing command: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"command failed: {' '.join(command)}") from exc


def escape_toml(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


if __name__ == "__main__":
    raise SystemExit(main())
