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

## Quick start

Install from a checkout:

```bash
python3 -m pip install .
```

Create a local config:

```bash
netsudo init ./netsudo.toml
```

Edit `netsudo.toml`, then install the helper and create pfSense aliases/rules:

```bash
netsudo setup --config ./netsudo.toml
```

Grant access:

```bash
sudo netsudo allow admin --for 20m --reason "maintenance"
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

See [SECURITY.md](SECURITY.md) and [docs/security-model.md](docs/security-model.md) for operational guidance.

## Common commands

```bash
netsudo render-policy --config ./netsudo.toml
netsudo install-helper --config ./netsudo.toml
netsudo setup --config ./netsudo.toml
sudo netsudo allow admin --for 20m --reason "maintenance"
netsudo status
sudo netsudo revoke last
sudo netsudo prune
```

## Current status

This is an alpha implementation. Review generated pfSense rules before relying on it in a production network.
