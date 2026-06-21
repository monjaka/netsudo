# Security model

`netsudo` is meant to make temporary firewall exceptions auditable, not to bypass pfSense.

## Authentication layers

There are two separate trust checks:

- Local authorization: high-risk profiles default to `require_sudo = true`, so the operator must run the CLI with local sudo.
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

That power should stay behind `require_sudo = true` for sensitive profiles. The firewall-side helper still enforces the profile's destinations, ports, and maximum duration.

## Installer bootstrap

`netsudo-install` can generate an Ed25519 key and install its public key on pfSense. The password prompt, if needed, is handled by `ssh` or `ssh-copy-id`; the password is not written to config.

The installer can write `batch_mode = false` for temporary password-prompt bootstrap configs, but the recommended steady state is `batch_mode = true` with a dedicated key.

`backend = "rest"` is reserved as an experimental configuration option. The current release uses the SSH helper backend for live pfSense changes because it does not require the unofficial REST API package.

## Failure behavior

Source aliases are initialized with `127.255.255.254`, so a profile has no useful source by default. Expiry, revoke, and status all prune expired grants and reload pfSense if aliases changed.
