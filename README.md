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
sudo netsudo allow admin --for 20m --reason "fix Wazuh agent"
sudo netsudo allow service-jellyfin --for 2h
sudo netsudo status
sudo netsudo revoke last
sudo netsudo revoke all
```

`allow all` does not disable the firewall. It means "allow this source IP to the destinations and ports defined by the `all` profile, for a limited time."

## Model

pfSense is configured once with:

- a source alias per profile, such as `NETSUDO_ADMIN_SRC`
- a destination alias per profile, such as `NETSUDO_ADMIN_DST`
- optional port aliases
- pass rules that reference those aliases

The source aliases contain a placeholder IP by default. A grant replaces the alias contents with the active source IPs for that profile and reloads the pfSense filter. Expiry/revoke removes the IP again.

When `--destination` is used, `netsudo` creates temporary grant-specific aliases and rules instead of adding the source to the broad profile source alias. That keeps the grant limited to the requested host/CIDR and removes those objects on revoke or expiry.

## Quick start

Install from a checkout:

```bash
python3 -m pip install .
```

Create a local config:

```bash
netsudo init ./netsudo.toml
```

Or use the installer:

```bash
python3 scripts/install.py
# or, after package install:
netsudo-install
```

Edit `netsudo.toml`, then install the helper and create pfSense aliases/rules:

```bash
netsudo setup --config ./netsudo.toml
```

Grant access:

```bash
sudo netsudo allow admin --for 20m --reason "maintenance"
```

Grant access for another device by specifying its source IP:

```bash
sudo netsudo allow admin --source 192.168.6.60 --for 20m --reason "workstation maintenance"
```

Grant access to a narrower destination inside the profile scope:

```bash
sudo netsudo allow admin --source 192.168.6.60 --destination 192.168.115.100 --for 20m --reason "check Wazuh"
sudo netsudo allow admin --destination 192.168.9.0/24 --destination 192.168.115.100 --for 30m --reason "maintenance"
```

Check grants:

```bash
netsudo status
```

Revoke:

```bash
sudo netsudo revoke last
```

## Security notes

Use a dedicated pfSense SSH user or SSH key for automation. For best results, restrict the SSH key on pfSense to the helper command after setup.

Do not store pfSense admin passwords in `netsudo.toml`. The intended model is local `sudo` plus a dedicated SSH key.

The installer can generate a dedicated SSH key and install the public key on pfSense. It may prompt for the pfSense account password through `ssh` or `ssh-copy-id`, but it does not store that password.

See [SECURITY.md](SECURITY.md) and [docs/security-model.md](docs/security-model.md) for operational guidance.

## Common commands

```bash
netsudo render-policy --config ./netsudo.toml
netsudo install-helper --config ./netsudo.toml
netsudo setup --config ./netsudo.toml
sudo netsudo allow admin --for 20m --reason "maintenance"
sudo netsudo allow admin --source 192.168.6.60 --destination 192.168.115.100 --for 20m --reason "maintenance"
netsudo status
sudo netsudo revoke last
sudo netsudo prune
```

## Current status

This is an alpha implementation. Review generated pfSense rules before relying on it in a production network.
