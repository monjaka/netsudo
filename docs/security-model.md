# Security model

`netsudo` is meant to make temporary firewall exceptions auditable, not to bypass pfSense.

## Authentication layers

There are two separate trust checks:

- Local authorization: high-risk profiles default to `require_sudo = true`, so `netsudo` invokes local `sudo` before making the grant.
- Firewall authorization: the CLI talks to a helper installed on pfSense over SSH. The helper accepts only profile names from the policy already installed on the firewall.

Initial setup may use your normal pfSense admin account. After setup, prefer a dedicated SSH key and restrict that key to the helper command.

## Why not ask for the firewall password each time?

Repeatedly typing the firewall password is awkward and usually less safe in automation. It encourages password storage, shell history leakage, and broad interactive pfSense access from every client.

The safer operational model is:

1. Use pfSense admin credentials only to install and review the helper.
2. Store no firewall password in the config.
3. Use a dedicated SSH key for day-to-day grants.
4. Restrict that SSH key to `/usr/local/sbin/netsudo-helper.php` after setup.
5. Keep profile durations short and send `/var/log/netsudo.log` to Wazuh.

## Policy boundaries

The client cannot choose arbitrary destinations or ports during `allow`. It sends:

- profile name
- source IP
- requested duration
- audit reason

The helper validates that request against `/usr/local/etc/netsudo/policy.json` on pfSense, then updates only the configured source aliases for that profile.

## Granting another source IP

`netsudo allow PROFILE --source 192.168.6.60` grants access for that specified IPv4 source instead of auto-detecting the client host. This is useful from an admin workstation that needs to temporarily open access for a laptop, VM, or container.

That power should stay behind `require_sudo = true` for sensitive profiles. If a profile defines `sources`, both the local CLI and the firewall-side helper reject source IPs outside that scope. The helper also enforces destinations, ports, and maximum duration.

This mirrors destination scoping: configure a broad source boundary once, such as `192.168.0.0/16`, then use `--source` to dynamically select one host for each grant.

## Granting a narrower destination

`netsudo allow PROFILE --destination 192.168.115.100` limits the grant to a requested host or CIDR inside that profile's configured destination list. Repeat `--destination` for multiple requested destinations.

The requested destination must be equal to or narrower than a configured profile destination. For example, a profile allowing `192.168.0.0/16` can grant `192.168.115.100`, but it cannot grant a public internet destination.

This is the intended way to handle many VLANs: configure a broad internal boundary once, then use `--destination` to dynamically narrow each individual grant.

Destination-scoped grants use temporary grant-specific pfSense aliases and rules. They are removed on revoke or expiry, while profile-wide grants continue to use the profile source alias.

With `interfaces = ["auto"]`, the pfSense helper resolves rule placement from the requested source IP and pfSense's configured interface networks. If a source such as `192.168.6.60` lives on a client VLAN, the helper creates the grant rule on the interface whose subnet contains that source. Explicit interface names remain available for unusual routing or VPN cases where subnet-based inference is not enough.

## Installer bootstrap

`netsudo-install` can generate an Ed25519 key and install its public key on pfSense. The password prompt, if needed, is handled by `ssh` or `ssh-copy-id`; the password is not written to config.

The installer can write `batch_mode = false` for temporary password-prompt bootstrap configs, but the recommended steady state is `batch_mode = true` with a dedicated key.

After the helper is installed, the installer can restrict the dedicated SSH key in `authorized_keys`. It writes a forced command wrapper and replaces the public key line with options equivalent to:

```text
no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,no-user-rc,command="/usr/local/sbin/netsudo-ssh-wrapper.sh"
```

The wrapper allows only the helper actions used for day-to-day grants: `grant`, `status`, `revoke`, and `prune`. A restricted key cannot copy files, run an arbitrary shell, or perform bootstrap/update setup work.

## Uninstall

`netsudo-install --uninstall` can remove the local config/key pair and optionally remove helper files, wrapper files, runtime state, and the matching authorized key entry from pfSense. It prompts before destructive actions by default.

The uninstall command does not currently remove pfSense firewall aliases or rules from `config.xml`; review and remove `NETSUDO_*` aliases/rules from pfSense if you want a completely clean firewall config.

`backend = "rest"` is reserved as an experimental configuration option. The current release uses the SSH helper backend for live pfSense changes because it does not require the unofficial REST API package.

## Failure behavior

Source aliases are initialized with `127.255.255.254`, so a profile has no useful source by default. Expiry, revoke, and status all prune expired grants and reload pfSense if aliases changed.
