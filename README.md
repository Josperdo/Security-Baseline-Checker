# Security Baseline Checker

A lightweight Bash utility for auditing basic security configurations on Linux systems. Currently focused on privilege escalation vectors, with plans to expand into a broader baseline assessment tool.

## Overview

This script performs automated checks against common security configurations to identify potential misconfigurations or areas of concern. It is intended for use by system administrators and security professionals during routine audits or hardening exercises.

## Current Checks

- Enumerates users with `sudo` group membership
- Enumerates users with `wheel` group membership (RHEL/CentOS-based distributions)

## Requirements

- Linux-based operating system
- Bash 4.0+
- Read access to `/etc/group`

## Usage

```bash
chmod +x security_checker.sh
./security_checker.sh
```

## Planned Features

- SSH configuration audit (root login, password authentication, key-based auth)
- Firewall rule validation (iptables/ufw)
- File permission checks on sensitive directories
- Password policy review
- Open port enumeration
- Unattended upgrade / patch status check

## License

See [LICENSE](LICENSE) for details.
