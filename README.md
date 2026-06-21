# netsudo

`netsudo` is a sudo-like CLI for temporary, audited access across pfSense firewall boundaries.

It is designed for segmented homelabs and small labs where firewall policy should stay closed by default, but trusted administrators sometimes need short-lived access to a VLAN, host, or service.

## What it does

- Grants access from one source IP for a short time window.
- Enforces named profiles with maximum durations.
- Updates pfSense aliases and fixed firewall rules instead of disabling firewall policy.
- Logs every grant, revoke, and expiry.
- Revokes access by removing the source IP and killing matching firewall states.
- Uses SSH to pfSense by default, so no REST API package is required on the firewall.

## Example

```bash
netsudo allow admin --for 20m --reason "fix Wazuh agent"
netsudo allow service-jellyfin --for 2h
netsudo status
netsudo revoke last
netsudo revoke all
```

`allow all` does not disable the firewall. It means "allow this source IP to the destinations and ports defined by the `all` profile, for a limited time."

## Model

pfSense is configured once with:

- a source alias per profile, such as `NETSUDO_ADMIN_SRC`
- a destination alias per profile, such as `NETSUDO_ADMIN_DST`
- optional port aliases
- pass rules that reference those aliases

The source aliases contain a placeholder IP by default. A grant replaces the alias contents with the active source IPs for that profile and reloads the pfSense filter. Expiry/revoke removes the IP again.

When `--source` is used, `netsudo` dynamically grants that source IP for the request window. Profiles can set `sources` to limit which source IPs are allowed.

When `--destination` is used, `netsudo` creates temporary grant-specific aliases and rules instead of adding the source to the broad profile source alias. That keeps the grant limited to the requested host/CIDR and removes those objects on revoke or expiry.

## Installation

### Linux

`netsudo` supports Python 3.10 and newer.

1. Install the required system packages.

   Fedora:

   ```bash
   sudo dnf install -y git python3 python3-pip openssh-clients
   ```

   Ubuntu/Debian:

   ```bash
   sudo apt update
   sudo apt install -y git python3 python3-pip openssh-client
   ```

2. Clone the repository:

   ```bash
   git clone https://github.com/monjaka/netsudo.git
   cd netsudo
   ```

3. Install `netsudo` for your user:

   ```bash
   python3 -m pip install --user .
   ```

   Run this from inside the cloned `netsudo` directory. This is the standard install method for now.

   On newer Ubuntu/Debian releases, if pip exits with `externally-managed-environment`, use:

   ```bash
   python3 -m pip install --user --break-system-packages .
   ```

   That still installs `netsudo` in your user site-packages; it does not install pfSense credentials or change firewall state.

4. Check the installed command:

   ```bash
   netsudo --version
   ```

5. Run the installer. This creates `netsudo.toml` and can set up the SSH key:

   ```bash
   netsudo-install --config ./netsudo.toml
   ```

   The installer writes the local config file. If it asks whether to run setup now, answer `no` unless you are ready to apply the generated config to pfSense immediately.

6. Review `netsudo.toml` and edit the profile sources, destinations, ports, and durations for your network.

7. Apply the config to pfSense if you skipped setup in the installer or changed `netsudo.toml` after setup:

   ```bash
   netsudo-install --config ./netsudo.toml --setup-only
   ```

   This is the same setup action the installer can run for you. It reads `netsudo.toml`, copies the helper to pfSense, uploads policy rendered from that file, and creates/updates pfSense aliases and rules. It does not edit `netsudo.toml`.

### From A Checkout Without Installing

For development or quick testing only:

```bash
cd netsudo
python3 scripts/install.py
python3 -m netsudo.cli --version
```

## Quick Start

After completing the installation steps above, `netsudo.toml` should already exist and the pfSense helper should already be installed.

Grant access:

```bash
netsudo allow admin --for 20m --reason "maintenance"
```

Grant access for another device by specifying its source IP:

```bash
netsudo allow admin --source 192.168.6.60 --for 20m --reason "workstation maintenance"
```

Grant access to a narrower destination inside the profile scope:

```bash
netsudo allow admin --source 192.168.6.60 --destination 192.168.115.100 --for 20m --reason "check Wazuh"
netsudo allow admin --destination 192.168.9.0/24 --destination 192.168.115.100 --for 30m --reason "maintenance"
```

Check grants:

```bash
netsudo status
```

Revoke:

```bash
netsudo revoke last
```

If you later change `netsudo.toml`, apply the updated policy to pfSense again:

```bash
netsudo-install --config ./netsudo.toml --setup-only
```

## Troubleshooting

If `netsudo allow` says a destination is outside the profile's allowed destinations, edit that profile in `netsudo.toml` and widen `destinations` to the boundary you are willing to delegate to that profile.

You do not need to list every VLAN. Use a broader internal CIDR, then keep each grant narrow with `--destination`:

```toml
[profiles.admin]
sources = ["192.168.0.0/16"]
destinations = ["192.168.0.0/16"]
```

With that scope, this grant is accepted because both `192.168.6.60` and `192.168.115.100` are inside the configured boundaries:

```bash
netsudo allow admin --source 192.168.6.60 --destination 192.168.115.100 --for 20m --reason "check Wazuh"
```

Then apply config changes to pfSense:

```bash
netsudo-install --config ./netsudo.toml --setup-only
```

By default, `interfaces = ["auto"]` makes the pfSense helper resolve rule placement from the requested source IP and the firewall's own interface networks. For example, access from `192.168.6.60` resolves to the pfSense interface whose subnet contains `192.168.6.60`. Use explicit interface names only if auto resolution cannot represent a special case.

## Security notes

Use a dedicated pfSense SSH user.

Do not store pfSense admin passwords in `netsudo.toml`. The intended model is local `sudo` plus a dedicated SSH key.

For profiles with `require_sudo = true`, run `netsudo allow ...` as your normal user. `netsudo` will invoke local `sudo` itself when needed. This avoids the common `sudo: netsudo: command not found` problem caused by `pip --user` installing the command under `~/.local/bin`.

The installer can generate a dedicated SSH key and install the public key on pfSense. It may prompt for the pfSense account password through `ssh` or `ssh-copy-id`, but it does not store that password.

After setup, the installer can restrict the dedicated key in pfSense `authorized_keys` with a forced command and disabled forwarding/PTY options. A restricted key is intended for day-to-day `allow`, `status`, `revoke`, and `prune` operations. Bootstrap tasks such as copying a new helper or policy still require an unrestricted admin SSH path.

If you did not restrict the SSH key during setup, you can do it later:

```bash
netsudo-install --config ./netsudo.toml --restrict-key-only
```

To uninstall local netsudo config/key files and optionally remove helper files from pfSense:

```bash
netsudo-install --config ./netsudo.toml --uninstall
python3 -m pip uninstall netsudo
```

The uninstall flow prompts before deleting local files or pfSense helper files. It does not remove pfSense aliases/rules from `config.xml`; remove `NETSUDO_*` firewall objects in pfSense if you want a fully clean firewall config.

See [SECURITY.md](SECURITY.md) and [docs/security-model.md](docs/security-model.md) for operational guidance.

## Common commands

```bash
netsudo render-policy --config ./netsudo.toml
netsudo install-helper --config ./netsudo.toml
netsudo-install --config ./netsudo.toml --setup-only
netsudo allow admin --for 20m --reason "maintenance"
netsudo allow admin --source 192.168.6.60 --destination 192.168.115.100 --for 20m --reason "maintenance"
netsudo status
netsudo revoke last
netsudo prune
```

## Current status

This is an alpha implementation. Review generated pfSense rules before relying on it in a production network.
