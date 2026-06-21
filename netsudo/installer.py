"""Interactive installer for netsudo."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .config import load_config
from .transport import shell_quote


DEFAULT_CONFIG = Path("./netsudo.toml")
DEFAULT_KEY = Path.home() / ".ssh" / "netsudo_pfsense"
DEFAULT_WRAPPER = "/usr/local/sbin/netsudo-ssh-wrapper.sh"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Configure netsudo for a pfSense firewall")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="config path to write")
    parser.add_argument("--non-interactive", action="store_true", help="write defaults without prompting")
    parser.add_argument(
        "--restrict-key-after-setup",
        dest="restrict_key_after_setup",
        action="store_true",
        default=None,
        help="after a successful setup run, lock the configured SSH key to the netsudo helper only",
    )
    parser.add_argument(
        "--no-restrict-key-after-setup",
        dest="restrict_key_after_setup",
        action="store_false",
        help="do not prompt to restrict the SSH key after setup",
    )
    parser.add_argument(
        "--restrict-key-only",
        action="store_true",
        help="only restrict the SSH key from an existing config; helper must already be installed",
    )
    parser.add_argument(
        "--setup-only",
        action="store_true",
        help="run setup from an existing config without rewriting netsudo.toml",
    )
    args = parser.parse_args(argv)

    try:
        config_path = Path(args.config).expanduser()
        if args.setup_only and args.restrict_key_only:
            raise RuntimeError("--setup-only and --restrict-key-only cannot be used together")
        if args.restrict_key_only:
            restrict_key_from_config(config_path)
        elif args.setup_only:
            setup_from_config(
                config_path,
                interactive=not args.non_interactive,
                restrict_key_after_setup=args.restrict_key_after_setup,
            )
        else:
            install(
                config_path,
                interactive=not args.non_interactive,
                restrict_key_after_setup=args.restrict_key_after_setup,
            )
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        print(f"netsudo-install: {exc}", file=sys.stderr)
        return 1
    return 0


def setup_from_config(config_path: Path, *, interactive: bool, restrict_key_after_setup: bool | None) -> None:
    config = load_config(str(config_path))
    print(f"Installing pfSense helper and applying policy from {config_path}")
    print("This reads netsudo.toml, uploads the rendered policy to pfSense, and creates/updates aliases and rules.")
    run_netsudo(["setup", "--config", str(config_path)])

    if config.pfsense.backend != "ssh":
        return
    if not config.pfsense.identity_file:
        if restrict_key_after_setup:
            raise RuntimeError("key restriction requires pfsense.identity_file in the config")
        return

    if restrict_key_after_setup is None:
        should_restrict = confirm(
            "Restrict the configured SSH key on pfSense so it can only run the netsudo helper",
            True if interactive else False,
            interactive,
        )
    else:
        should_restrict = restrict_key_after_setup

    if should_restrict:
        restrict_public_key(
            host=config.pfsense.host,
            user=config.pfsense.user,
            key_path=Path(config.pfsense.identity_file).expanduser(),
            helper=config.pfsense.helper,
        )


def install(config_path: Path, *, interactive: bool, restrict_key_after_setup: bool | None) -> None:
    print("netsudo installer")
    print("This writes netsudo.toml, can create a dedicated SSH key, and can install the pfSense helper.")
    print("It may ask SSH for your pfSense password during bootstrap, but it does not store that password.")

    host = prompt("pfSense SSH hostname or IP used for setup", "192.168.3.1", interactive)
    user = prompt("pfSense SSH username for initial setup", "admin", interactive)
    backend = prompt_choice("pfSense control backend (ssh is recommended; rest is a placeholder)", ["ssh", "rest"], "ssh", interactive)

    identity_file = ""
    batch_mode = True
    key_path: Path | None = None
    if backend == "ssh":
        key_path = Path(prompt("Local path for the dedicated netsudo SSH key", str(DEFAULT_KEY), interactive)).expanduser()
        if key_pair_exists(key_path):
            print(f"Using existing SSH key pair at {key_path}")
        elif confirm("Create a dedicated Ed25519 SSH key at this path", True if interactive else False, interactive):
            ensure_ssh_key(key_path)

        if key_pair_exists(key_path):
            identity_file = str(key_path)
        elif restrict_key_after_setup:
            raise RuntimeError("key restriction requires a generated or existing SSH key pair")

        if identity_file and confirm(f"Copy this key's public half to {user}@{host} now; SSH may ask for the pfSense password", True if interactive else False, interactive):
            install_public_key(host=host, user=user, key_path=key_path)

        batch_mode = not confirm("Allow future netsudo SSH commands to ask for a pfSense password if key auth fails", False, interactive)
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

    should_restrict = False
    if backend == "ssh" and identity_file:
        if restrict_key_after_setup is None:
            should_restrict = confirm(
                "After setup succeeds, restrict this SSH key on pfSense so it can only run the netsudo helper",
                True if interactive else False,
                interactive,
            )
        else:
            should_restrict = restrict_key_after_setup
    elif restrict_key_after_setup:
        raise RuntimeError("key restriction requires an SSH identity_file in the generated config")

    if backend == "ssh" and confirm("Run setup now to install the helper and pfSense aliases/rules", False, interactive):
        run_netsudo(["setup", "--config", str(config_path)])
        if should_restrict and key_path is not None:
            restrict_public_key(host=host, user=user, key_path=key_path, helper="/usr/local/sbin/netsudo-helper.php")
    else:
        print(
            f"Next: review/edit {config_path}, then run "
            f"`netsudo-install --config {config_path} --setup-only` to install the pfSense helper "
            "and apply the policy generated from that config."
        )
        if should_restrict:
            print(
                "Key restriction was not applied because setup did not run now. "
                f"After setup succeeds, run `netsudo-install --config {config_path} --restrict-key-only`."
            )


def key_pair_exists(path: Path) -> bool:
    return path.exists() and Path(str(path) + ".pub").exists()


def ensure_ssh_key(path: Path) -> None:
    public = Path(str(path) + ".pub")
    if path.exists() and public.exists():
        print(f"Using existing key {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Creating dedicated netsudo SSH key at {path}")
    run(["ssh-keygen", "-t", "ed25519", "-f", str(path), "-N", "", "-C", "netsudo-pfsense"])
    os.chmod(path, 0o600)


def install_public_key(*, host: str, user: str, key_path: Path) -> None:
    public = Path(str(key_path) + ".pub")
    if not public.exists():
        raise RuntimeError(f"missing public key: {public}")

    print(f"Installing public key on {user}@{host}. pfSense may prompt for that account password.")
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


def restrict_key_from_config(config_path: Path) -> None:
    config = load_config(str(config_path))
    if config.pfsense.backend != "ssh":
        raise RuntimeError("key restriction only applies to the SSH backend")
    if not config.pfsense.identity_file:
        raise RuntimeError("config has no pfsense.identity_file to restrict")
    restrict_public_key(
        host=config.pfsense.host,
        user=config.pfsense.user,
        key_path=Path(config.pfsense.identity_file).expanduser(),
        helper=config.pfsense.helper,
    )


def restrict_public_key(*, host: str, user: str, key_path: Path, helper: str) -> None:
    public_key = read_public_key(key_path)
    wrapper = restricted_wrapper_script(helper)
    wrapper_path = DEFAULT_WRAPPER

    print(f"Installing restricted-key wrapper at {wrapper_path} on {host}")
    install_wrapper_remote(host=host, user=user, key_path=key_path, wrapper=wrapper, wrapper_path=wrapper_path)

    restricted_line = restricted_authorized_key_line(public_key, wrapper_path=wrapper_path)
    key_blob = public_key.split()[1]
    awk_script = (
        'BEGIN { found=0 } '
        'index($0, blob) > 0 { if (!found) print new; found=1; next } '
        '{ print } '
        'END { if (!found) print new }'
    )
    remote = (
        "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; "
        "awk -v blob="
        + shell_quote(key_blob)
        + " -v new="
        + shell_quote(restricted_line)
        + " "
        + shell_quote(awk_script)
        + " ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.netsudo && "
        "mv ~/.ssh/authorized_keys.netsudo ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    )
    run(ssh_command(host=host, user=user, key_path=key_path) + [remote])
    print("Restricted the SSH key to the netsudo helper only.")
    print("This key can run allow/status/revoke/prune, but it can no longer copy files or perform bootstrap updates.")


def install_wrapper_remote(*, host: str, user: str, key_path: Path, wrapper: str, wrapper_path: str) -> None:
    remote = (
        "umask 077; cat > /tmp/netsudo-ssh-wrapper.sh && "
        "install -m 0755 /tmp/netsudo-ssh-wrapper.sh "
        + shell_quote(wrapper_path)
        + " && rm -f /tmp/netsudo-ssh-wrapper.sh"
    )
    run(ssh_command(host=host, user=user, key_path=key_path) + [remote], input_text=wrapper)


def ssh_command(*, host: str, user: str, key_path: Path | None = None) -> list[str]:
    command = ["ssh"]
    if key_path is not None:
        command.extend(["-i", str(key_path)])
    command.append(f"{user}@{host}")
    return command


def read_public_key(key_path: Path) -> str:
    public = Path(str(key_path) + ".pub")
    if not public.exists():
        raise RuntimeError(f"missing public key: {public}")
    public_key = public.read_text(encoding="utf-8").strip()
    fields = public_key.split()
    if len(fields) < 2 or not fields[0].startswith("ssh-"):
        raise RuntimeError(f"invalid public key: {public}")
    return public_key


def restricted_authorized_key_line(public_key: str, *, wrapper_path: str = DEFAULT_WRAPPER) -> str:
    options = [
        "no-port-forwarding",
        "no-X11-forwarding",
        "no-agent-forwarding",
        "no-pty",
        "no-user-rc",
        'command="' + wrapper_path.replace("\\", "\\\\").replace('"', '\\"') + '"',
    ]
    return ",".join(options) + " " + public_key


def restricted_wrapper_script(helper: str) -> str:
    helper_escaped = helper.replace("'", "'\"'\"'")
    return f"""#!/bin/sh
php="/usr/local/bin/php"
helper='{helper_escaped}'
original="${{SSH_ORIGINAL_COMMAND:-}}"

case "$original" in
    "$php '$helper' 'grant'"|"$php $helper grant")
        exec "$php" "$helper" grant
        ;;
    "$php '$helper' 'status'"|"$php $helper status")
        exec "$php" "$helper" status
        ;;
    "$php '$helper' 'revoke'"|"$php $helper revoke")
        exec "$php" "$helper" revoke
        ;;
    "$php '$helper' 'prune'"|"$php $helper prune")
        exec "$php" "$helper" prune
        ;;
esac

echo "netsudo: this SSH key is restricted to netsudo helper commands" >&2
exit 126
"""


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


def run(command: list[str], env: dict[str, str] | None = None, input_text: str | None = None) -> None:
    try:
        subprocess.run(command, check=True, env=env, input=input_text, text=input_text is not None)
    except FileNotFoundError as exc:
        raise RuntimeError(f"missing command: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"command failed: {' '.join(command)}") from exc


def escape_toml(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


if __name__ == "__main__":
    raise SystemExit(main())
