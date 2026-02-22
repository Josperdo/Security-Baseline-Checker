# Baselinr

A lightweight, opinionated Bash utility for auditing security baseline configurations on Linux systems. Surfaces common misconfigurations across privilege escalation vectors, SSH exposure, file integrity, network attack surface, and patch management — the gaps that matter most between a freshly provisioned server and a hardened one.

---

## Why Baseline Auditing Matters

Most Linux compromises don't exploit zero-days. They exploit defaults.

A fresh Ubuntu 22.04 install ships with `PASS_MAX_DAYS=99999`, UFW installed but inactive, and SSH potentially permitting root login depending on the image. These aren't bugs — they're defaults that are acceptable for initial setup and dangerous in production. The hardening gap between "installed" and "compliant" is where most lateral movement and privilege escalation opportunities live.

Frameworks like [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) and [NIST SP 800-123](https://csrc.nist.gov/publications/detail/sp/800-123/final) (Guide to General Server Security) exist precisely because this gap is consistent and predictable. Baselinr operationalizes a subset of those controls — specifically the ones that are easy to miss, easy to check, and high-impact when misconfigured.

The value isn't replacing a full compliance scan. It's giving you a fast, dependency-free read on the most common misconfigurations in under 30 seconds, with no tooling installed beyond Bash.

---

## Checks and Security Rationale

### Privileged Access Enumeration

Enumerates members of the `sudo` (Debian/Ubuntu) and `wheel` (RHEL/CentOS) groups.

**Why it matters:** Overpermissioned sudo groups are a primary privilege escalation vector. Every account with unrestricted sudo access represents a full compromise path if that account is taken over. This check doesn't validate _how_ sudo is configured (see [Known Limitations](#known-limitations)) — it surfaces _who_ has it, which is often more than teams realize.

Relevant: CIS Benchmark 5.3 — "Ensure sudo is configured," CIS 5.4 — "Ensure access to the su command is restricted."

---

### Password Policy (`/etc/login.defs`)

Validates four controls against hardened thresholds:

| Setting | Threshold | Risk if unconfigured |
|---|---|---|
| `PASS_MAX_DAYS` | WARN > 90, INFO > 60 | Stale credentials persist indefinitely. Default on many distros: 99999. |
| `PASS_MIN_DAYS` | WARN = 0 | Allows immediate password recycling, defeating history controls. |
| `PASS_MIN_LEN` | WARN < 8 | Short passwords are trivially brute-forced offline after shadow file exposure. |
| `PASS_WARN_AGE` | WARN < 7 | Users get no warning before forced expiry, leading to lockouts and support pressure. |

**Why it matters:** `/etc/login.defs` controls shadow-utils behavior — the actual enforcement layer for system accounts. CIS Benchmark 5.4.1 specifies max password age ≤ 365 days and warn age ≥ 7 days. Baselinr uses tighter thresholds (90-day max) aligned with common enterprise policy.

**Caveat:** On modern systems, PAM (`pam_pwquality`) may override or supplement these settings. See [Known Limitations](#known-limitations).

---

### SSH Hardening (`/etc/ssh/sshd_config`)

Audits four directives against explicit-configuration requirements:

**`PermitRootLogin`** — Flags `yes` and `prohibit-password` as warnings.
- `yes`: Direct root access with no per-user audit trail. Root activity becomes unattributable.
- `prohibit-password`: Still allows root login via key, bypassing the account separation that sudo enforces.
- Target: `no`. Relevant: CIS 5.2.8.

**`PasswordAuthentication`** — Flags `yes` as a warning.
- Password auth exposes SSH to credential stuffing and brute force. Any service with SSH open to the internet and password auth enabled is a target within minutes of provisioning.
- Target: `no`. Relevant: CIS 5.2.11.

**`PermitEmptyPasswords`** — Flags `yes` as a warning.
- Self-explanatory: accounts without passwords are a free lateral movement path.
- Target: `no`. Relevant: CIS 5.2.10.

**`PubkeyAuthentication`** — Flags `no` as a warning.
- If key auth is disabled alongside password auth, no login mechanism exists. More commonly, this is left at default without explicit configuration — which Baselinr flags as `INFO` to surface the implicit reliance on defaults.

All four checks distinguish between explicitly-configured values and implicit defaults, because a setting that works today can break on an SSH upgrade that changes default behavior.

---

### Critical File Permissions

Validates ownership and mode on four files central to system integrity:

| File | Expected | Risk if wrong |
|---|---|---|
| `/etc/passwd` | `644 root:root` | World-readable is correct; any write access enables account manipulation |
| `/etc/shadow` | `640 root:shadow` | Non-root read access exposes password hashes for offline cracking |
| `/etc/group` | `644 root:root` | Write access enables silent group membership escalation |
| `/etc/sudoers` | `440 root:root` | Any write access = arbitrary privilege escalation |

**Why it matters:** `/etc/shadow` with permissive read permissions is a direct path to offline hash cracking — particularly against accounts with weak passwords or reused credentials. `/etc/sudoers` writable by a non-root account is effectively game over. These files rarely change permissions intentionally; when they do, it's either misconfiguration or tampering.

Relevant: CIS 6.1.2–6.1.9.

---

### Linux Capabilities (`getcap`)

Runs `getcap -r /` to enumerate files with assigned Linux capabilities.

**Why it matters:** Capabilities are a granular alternative to setuid — they grant specific privileged operations to binaries without full root. Legitimate examples: `cap_net_raw+ep` on `/usr/bin/ping`. Dangerous examples: `cap_setuid+ep` on a Python interpreter or shell, which is functionally equivalent to a setuid root binary and a trivial privilege escalation path.

Capabilities are rarely monitored because they don't appear in standard permission checks (`ls -la`). They require `getcap` or `/proc/[pid]/status` to surface. Baselinr lists all capability assignments for manual review — there's no universal safe/unsafe threshold, so the output is informational by design.

Relevant: CIS 5.3 (privilege escalation controls), GTFOBins capability escalation techniques.

---

### Open Ports and Listening Services (`ss`)

Enumerates all TCP/UDP listeners using `ss -tulnp`, including the associated process.

**Why it matters:** Every listening service is attack surface. Common high-risk findings:
- Database ports (3306/MySQL, 5432/PostgreSQL) bound to `0.0.0.0` instead of `127.0.0.1`
- Development servers that shouldn't be running in production
- Unexpected listeners that indicate post-compromise activity

This check surfaces the full picture — Baselinr doesn't make pass/fail judgments because what's appropriate depends on the system's role. The signal is visibility: if a port appears here that you didn't intentionally open, that's your lead.

---

### Firewall Status and Default Policy

Detects the active firewall management layer (`ufw`, `firewalld`, or `iptables`) and validates:
- Whether the firewall is active
- Whether the default incoming policy is `deny`/`DROP` (not `allow`/`ACCEPT`)

**Why it matters:** A firewall that's installed but inactive provides zero protection — and this is the default state for UFW on many Ubuntu images. A firewall with a default `ACCEPT` policy on the INPUT chain is also effectively open: rules only matter if there's a restrictive default to fall back to.

Baselinr checks the default policy explicitly, not just whether the firewall service is running. A running `iptables` with `policy ACCEPT` is worse than nothing — it creates false confidence.

Relevant: CIS 3.5 (firewall configuration), NIST SP 800-123 Section 5 (network-level protection).

---

### Automatic Security Updates

Checks whether the system is configured to apply security patches automatically:
- Debian/Ubuntu: `unattended-upgrades` package + `/etc/apt/apt.conf.d/20auto-upgrades`
- RHEL/CentOS: `dnf-automatic` package + `dnf-automatic.timer` systemd unit

**Why it matters:** The median time between CVE disclosure and exploit availability has shrunk to days. Systems that require manual patching inevitably fall behind — not from negligence, but from operational reality. Unpatched software with known exploits is consistently among the top initial access vectors in incident reports.

Baselinr distinguishes between the tool being installed and the tool being configured and enabled — a common gap where teams install `unattended-upgrades` but never activate it.

Relevant: CIS 1.9, NIST SP 800-40.

---

## Example Output

The following represents a realistic audit on an Ubuntu 22.04 server that hasn't been explicitly hardened:

```
=== Security Baseline Check ===

Checking for users with sudo privileges...

ubuntu,john.doe,deploy-svc

Checking password policy settings...

WARNING: PASS_MAX_DAYS is set to 99999. Consider setting it to 90 or less for better security.

WARNING: PASS_MIN_DAYS is set to 0. Set to 1 or more to prevent password cycling.

WARNING: PASS_MIN_LEN is set to 5. Consider setting it to 8 or more for stronger passwords.

OK: PASS_WARN_AGE is set to 7 (adequate warning period).

Checking SSH configuration for potential security threat...

WARNING: PermitRootLogin is currently set to yes. To enhance security, change this setting
to no in /etc/ssh/sshd_config and restart the SSH service.

WARNING: PasswordAuthentication is currently set to yes. To enhance security, change this
setting to no in /etc/ssh/sshd_config and restart the SSH service.

SSH Configuration secured: PermitEmptyPasswords is currently set to no.

INFO: PubkeyAuthentication is not explicitly set. Default value is in use. Verify.

Checking for files with weak or improper permissions...

OK: /etc/passwd has secure permissions (644 root root).
WARNING: /etc/shadow has permissions 644 shadow root. It should be 640 and owned by shadow:root.
OK: /etc/group has secure permissions (644 root root).
OK: /etc/sudoers has secure permissions (440 root root).

Checking for files with capabilities presenting potential risks...

/usr/bin/ping = cap_net_raw+ep
/usr/bin/python3.10 = cap_setuid+ep

Checking for open ports and associated services...

Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
tcp    LISTEN  0       128     0.0.0.0:22           0.0.0.0:*          users:(("sshd",pid=891))
tcp    LISTEN  0       128     0.0.0.0:80           0.0.0.0:*          users:(("nginx",pid=1204))
tcp    LISTEN  0       128     0.0.0.0:3306         0.0.0.0:*          users:(("mysqld",pid=1587))

Checking firewall status and rules...

UFW detected.
WARNING: UFW is installed but inactive. Consider enabling it for better security.

Checking for unattended upgrade tools and their status...

Unattended Upgrades is installed.
WARNING: Unattended Upgrades is installed but not enabled. Consider enabling it to
automatically install security updates.

Check complete.
```

Reading this output:
- `deploy-svc` in the sudo group warrants review — service accounts generally shouldn't have interactive sudo
- `/etc/shadow` at `644` means any local user can read password hashes
- `python3.10` with `cap_setuid+ep` is a GTFOBins escalation path — `python3 -c "import os; os.setuid(0); os.system('/bin/bash')"` is trivially exploitable
- MySQL bound to `0.0.0.0:3306` with UFW inactive means the database is network-accessible with no firewall enforcement

---

## Requirements

- Linux (Debian/Ubuntu or RHEL/CentOS)
- Bash 4.0+
- Root privileges required for: firewall inspection (`ufw`, `iptables`), capabilities scan (`getcap -r /`)
- Non-root runs complete partial checks with informational messages where privileges are insufficient

No external dependencies beyond standard Linux utilities (`ss`, `stat`, `getcap`, `grep`, `awk`).

---

## Usage

```bash
# Clone and make executable
git clone https://github.com/yourusername/baselinr.git
cd baselinr
chmod +x security_checker.sh

# Run with root for full results
sudo ./security_checker.sh

# Pipe to a file for review
sudo ./security_checker.sh | tee audit-$(hostname)-$(date +%F).txt
```

---

## Design Decisions

**Bash, no dependencies.** The target environment is a Linux system that may not have Python, Ruby, or any specific runtime available. A shell script with standard utilities runs everywhere the target runs.

**`set -euo pipefail`.** The script fails fast on unexpected errors rather than silently continuing with partial results. Pipefail catches errors in the left side of pipes — a common failure mode in shell scripts that parse command output.

**Explicit configuration over implicit defaults.** SSH checks distinguish between a directive being set and it relying on defaults. Defaults change across OpenSSH versions. Explicit configuration is auditable; defaults are not.

**Tiered severity (OK / INFO / WARNING).** Not everything is binary. `PASS_MAX_DAYS=70` is better than `99999` but still worth noting. `INFO` surfaces implicit assumptions and near-threshold values without noise-flooding the output with false positives.

**No remediation.** Baselinr reports, it doesn't fix. Automated remediation on a running system without a change control process is risky. The output is designed to inform a human decision.

---

## Known Limitations

**Password policy is `/etc/login.defs` only.** On modern Debian/Ubuntu systems, `pam_pwquality` (configured in `/etc/security/pwquality.conf`) is the actual complexity enforcer and can override or supplement `login.defs`. Baselinr's password checks reflect shadow-utils configuration, not PAM policy. A system could show `PASS_MIN_LEN=5` in `login.defs` while PAM enforces a 12-character minimum.

**SSH checks use `grep`, not `sshd -T`.** The script parses `sshd_config` directly. OpenSSH supports `Include` directives and drop-in configs (common in cloud images). `sshd -T` returns the _effective_ parsed configuration; `grep` on the main config file may miss settings applied via includes. For a definitive SSH audit, `sshd -T` is more reliable.

**Capabilities output is informational only.** Baselinr lists all capability assignments without a pass/fail verdict. Some assignments are expected (`cap_net_raw` on `ping`); others represent escalation paths. Distinguishing between them requires context the script doesn't have.

**Sudo enumeration is group membership only.** The script checks `/etc/group` for sudo/wheel members. It does not parse `/etc/sudoers` or `/etc/sudoers.d/` for `NOPASSWD` rules, command restrictions, or user-level entries outside those groups. A user not in the sudo group can still have sudo access via direct sudoers configuration.

**Single-node only.** Baselinr audits the system it runs on. Fleet-level auditing requires a separate orchestration layer.

---

## Planned Improvements

- [ ] Summary line with pass/warn/fail counts at exit
- [ ] Structured output mode (JSON) for SIEM ingestion or diff-based change detection
- [ ] Exit codes reflecting finding severity for CI/CD pipeline integration
- [ ] Selective check execution via flags (`--ssh-only`, `--skip-firewall`)
- [ ] PAM configuration parsing to complement `/etc/login.defs` checks
- [ ] `sshd -T` effective configuration parsing for SSH checks

---

## License

See [LICENSE](LICENSE) for details.
