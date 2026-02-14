# Baselinr

A lightweight Bash utility for auditing security baseline configurations on Linux systems. Checks privilege escalation vectors, network exposure, system hardening, and patch management across Debian/Ubuntu and RHEL/CentOS distributions.

## Overview

This script performs automated checks against common security configurations to identify potential misconfigurations or areas of concern. It is intended for use by system administrators and security professionals during routine audits or hardening exercises.

## Checks

### User & Access Control
- Enumerates users with `sudo` group membership
- Enumerates users with `wheel` group membership (RHEL/CentOS)
- Password policy validation (`PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_MIN_LEN`, `PASS_WARN_AGE`)

### SSH Configuration Audit
- `PermitRootLogin` — checks if root login is explicitly disabled
- `PasswordAuthentication` — checks if password-based auth is disabled in favor of key-based auth
- `PermitEmptyPasswords` — verifies empty passwords are not allowed
- `PubkeyAuthentication` — verifies public key authentication is enabled
- Reports whether each setting is explicitly configured or using defaults

### System Hardening
- File permission validation on sensitive files (`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`)
- Detects files with Linux capabilities that may present security risks (`getcap`)

### Network Exposure
- Enumerates open/listening ports and associated services
- Firewall status and rule validation (supports `ufw`, `firewalld`, and `iptables`)
- Checks default firewall policies for dangerous configurations

### Patch Management
- Detects unattended upgrade configuration (Debian/Ubuntu: `unattended-upgrades`, RHEL/CentOS: `dnf-automatic`)
- Validates whether automatic security updates are enabled

## Requirements

- Linux-based operating system (Debian/Ubuntu or RHEL/CentOS)
- Bash 4.0+
- Root privileges recommended for full results (required for firewall and capabilities checks)

## Usage

```bash
chmod +x security_checker.sh
sudo ./security_checker.sh
```

## Known Limitations

- Firewall checks require root; non-root runs will skip firewall analysis with an informational message
- SSH checks assume the standard `/etc/ssh/sshd_config` path
- Password policy reads from `/etc/login.defs` only (does not check PAM modules)

## Future Enhancements

- [ ] Summary report with pass/warn/fail counts
- [ ] Selective check execution via command-line flags
- [ ] Exit codes reflecting findings for CI/automation use

## License

See [LICENSE](LICENSE) for details.
