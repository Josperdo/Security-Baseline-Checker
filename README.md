# Security Baseline Checker

A lightweight Bash utility for auditing basic security configurations on Linux systems. Currently focused on privilege escalation vectors, with plans to expand into a broader baseline assessment tool.

## Overview

This script performs automated checks against common security configurations to identify potential misconfigurations or areas of concern. It is intended for use by system administrators and security professionals during routine audits or hardening exercises.

## Current Checks

### Privilege Escalation Vectors
- Enumerates users with `sudo` group membership
- Enumerates users with `wheel` group membership (RHEL/CentOS-based distributions)
- Detects files with Linux capabilities that may present security risks (`getcap`)

### SSH Configuration Audit
- `PermitRootLogin` — checks if root login is explicitly disabled
- `PasswordAuthentication` — checks if password-based auth is disabled in favor of key-based auth
- `PubkeyAuthentication` — verifies public key authentication is enabled
- Reports whether each setting is explicitly configured or using defaults

## Requirements

- Linux-based operating system
- Bash 4.0+
- Read access to `/etc/group` and `/etc/ssh/sshd_config`
- Root privileges recommended for full capabilities check

## Usage

```bash
chmod +x security_checker.sh
./security_checker.sh
```

## Roadmap

- [x] Sudo/wheel group enumeration
- [x] File capabilities detection (`getcap`)
- [x] SSH configuration audit (`PermitRootLogin`, `PasswordAuthentication`, `PubkeyAuthentication`)
- [x] Additional SSH checks (`PermitEmptyPasswords`, protocol version)
- [x] File permission checks on sensitive files (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`)
- [x] Open port enumeration
- [x] Password policy review
- [ ] Firewall rule validation (iptables/ufw)
- [ ] Unattended upgrade / patch status check

## License

See [LICENSE](LICENSE) for details.
