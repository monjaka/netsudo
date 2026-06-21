# Security

`netsudo` changes firewall access. Treat it as privileged infrastructure.

## Recommended deployment

- Use a dedicated pfSense automation account.
- Use SSH keys, not stored passwords.
- After initial setup, restrict the SSH key with a forced command that only runs the netsudo helper.
- Keep profile maximum durations short.
- Avoid broad `all` profiles unless they require local sudo and have a very short maximum duration.
- Keep audit logs in Wazuh or another central log collector.

## Secrets

Do not commit:

- pfSense passwords
- GitHub tokens
- SSH private keys
- live config files with private hostnames or policy details

The repo includes only `*.example.toml` configuration.

## pfSense support boundary

The default backend uses pfSense SSH and a helper script installed on the firewall. It does not require the unofficial pfSense REST API package. A REST backend may be added later, but should remain optional.

## Responsible use

The tool is intended to create temporary, auditable exceptions. It should not be used to bypass change control or permanently weaken segmentation.
