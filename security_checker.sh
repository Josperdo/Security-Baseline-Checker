#!/bin/bash
set -euo pipefail

echo "=== Security Baseline Check ==="
echo ""

function check_users() {
    echo "Checking for users with sudo privileges..."
    echo ""

    # Get users in sudo group
    grep '^sudo:' /etc/group | cut -d: -f4 || true
    echo ""

    # Get users in wheel group (some distros use this)
    grep '^wheel:' /etc/group | cut -d: -f4 2>/dev/null || true
    echo ""
}

function check_password_policy() {
    echo "Checking password policy settings..."
    echo ""

    # Check for password aging and complexity settings
    max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}' || true)
    min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}' || true)
    min_len=$(grep "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}' || true)
    warn_age=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}' || true)

    if [ "$max_days" -gt 90 ]; then
        echo "WARNING: PASS_MAX_DAYS is set to $max_days. Consider setting it to 90 or less for better security."
    elif [ "$max_days" -gt 60 ]; then
        echo "INFO: PASS_MAX_DAYS is set to $max_days. Consider setting it to 60 or less for enhanced security."
    else
        echo "OK: PASS_MAX_DAYS is set to $max_days (90 days or less)."
    fi
    echo ""

    if [ "$min_days" -eq 0 ]; then
        echo "WARNING: PASS_MIN_DAYS is set to $min_days. Set to 1 or more to prevent password cycling."
    elif [ "$min_days" -lt 14 ]; then
        echo "INFO: PASS_MIN_DAYS is set to $min_days. Consider setting it to 14 or more for better security."
    else
        echo "OK: PASS_MIN_DAYS is set to $min_days (14 days or more)."
    fi
    echo ""

    if [ "$min_len" -lt 8 ]; then
        echo "WARNING: PASS_MIN_LEN is set to $min_len. Consider setting it to 8 or more for stronger passwords."
    else
        echo "OK: PASS_MIN_LEN is set to $min_len (8 or more)."
    fi
    echo ""

    if [ "$warn_age" -lt 7 ]; then
        echo "WARNING: PASS_WARN_AGE is set to $warn_age. Consider setting it to 7 or more for better user experience."
    else
        echo "OK: PASS_WARN_AGE is set to $warn_age (adequate warning period)."
    fi
    echo ""
}

function check_ssh_config() {
    echo "Checking SSH configuration for potential security threat..."
    echo ""

    # Check for PermitRootLogin
    if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
        echo "WARNING: PermitRootLogin is currently set to yes. To enhance security, change this setting to no in /etc/ssh/sshd_config and restart the SSH service."
    elif grep -q "^PermitRootLogin prohibit-password" /etc/ssh/sshd_config; then
        echo "WARNING: PermitRootLogin is currently set to prohibit-password. To enhance security, change this setting to no in /etc/ssh/sshd_config and restart the SSH service."
    elif grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        echo "SSH configuration secured: PermitRootLogin is currently set to a secure value ('no' or 'prohibit-password')."
    else
        echo "INFO: PermitRootLogin is not explicitly set. Default value is in use. Verify the default for your SSH version."
    fi
    echo ""

    # Check for PasswordAuthentication
    if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
        echo "WARNING: PasswordAuthentication is currently set to yes. To enhance security, change this setting to no in /etc/ssh/sshd_config and restart the SSH service."
    elif grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
        echo "SSH Configuration secured: PasswordAuthentication is currently set to no."
    else
        echo "INFO: PasswordAuthentication is not explicitly set. Default value is in use. Verify."
    fi
    echo ""

    # Check for PermitEmptyPasswords
    if grep -q "^PermitEmptyPasswords yes" /etc/ssh/sshd_config; then
        echo "WARNING: PermitEmptyPasswords is currently set to yes. To enhance security, change this setting to no in /etc/ssh/sshd_config and restart the SSH service."
    elif grep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config; then
        echo "SSH Configuration secured: PermitEmptyPasswords is currently set to no."
    else
        echo "INFO: PermitEmptyPasswords is not explicitly set. Default value is in use. Verify."
    fi
    echo ""

    # Check for Pubkey Authentication
    if grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config; then
        echo "SSH Configuration secured: PubkeyAuthentication is currently set to yes."
    elif grep -q "^PubkeyAuthentication no" /etc/ssh/sshd_config; then
        echo "WARNING: PubkeyAuthentication is currently set to no. To enhance security, change this setting to yes in /etc/ssh/sshd_config and restart the SSH service."
    else
        echo "INFO: PubkeyAuthentication is not explicitly set. Default value is in use. Verify."
    fi
    echo ""
}

function check_file_permissions() {
    echo "Checking for files with weak or improper permissions..."
    echo ""

    # Check permissions of critical files
    for file in /etc/passwd /etc/shadow /etc/group /etc/sudoers; do
        if [ -e "$file" ]; then
            perms=$(stat -c "%a %G %U" "$file")
            if [[ "$perms" != "644 root root" && "$file" == "/etc/passwd" ]]; then
                echo "WARNING: $file has permissions $perms. It should be 644 and owned by root:root."
            elif [[ "$perms" != "640 shadow root" && "$file" == "/etc/shadow" ]]; then
                echo "WARNING: $file has permissions $perms. It should be 640 and owned by shadow:root."
            elif [[ "$perms" != "644 root root" && "$file" == "/etc/group" ]]; then
                echo "WARNING: $file has permissions $perms. It should be 644 and owned by root:root."
            elif [[ "$perms" != "440 root root" && "$file" == "/etc/sudoers" ]]; then
                echo "WARNING: $file has permissions $perms. It should be 440 and owned by root:root."
            else
                echo "OK: $file has secure permissions ($perms)."
            fi
        else
            echo "WARNING: $file does not exist."
        fi
    done
    echo ""
}

function check_capabilities() {
    # Check for files with potentially risky capabilities
    echo "Checking for files with capabilities presenting potential risks..."
    echo ""
    # List files with capabilities (requires root privileges)
    getcap -r / 2>/dev/null || true
    echo ""

}

function check_open_ports() {
    echo "Checking for open ports and associated services..."
    echo ""

    # List open ports and associated services
    if ss -tulnp 2>/dev/null | grep -q LISTEN; then
        ss -tulnp || true
    else
        echo "No listening ports detected."
    fi
}

function check_firewall() {
    echo "Checking firewall status and rules..."
    echo ""

    # Firewall checks require root to read rules
    if [ "$(id -u)" -ne 0 ]; then
        echo "INFO: Firewall checks require root privileges. Run with sudo for full results."
        return
    fi

    # Check which firewall is in use and its status
    if command -v ufw >/dev/null 2>&1; then
        echo "UFW detected."
        if ufw status | grep -q "Status: active"; then
            # Check default incoming policy
            if ufw status verbose | grep -q "Default: deny (incoming)"; then
                echo "OK: UFW is active with default incoming policy set to deny."
            elif ufw status verbose | grep -q "Default: allow (incoming)"; then
                echo "WARNING: UFW is active but default incoming policy is allow. Consider changing to deny."
            fi
            echo ""
            echo "Current rules:"
            ufw status verbose || true
        elif ufw status | grep -q "Status: inactive"; then
            echo "WARNING: UFW is installed but inactive. Consider enabling it for better security."
        else
            echo "INFO: UFW status could not be determined. Please check manually."
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        echo "firewalld detected."
        firewall-cmd --state || true
        echo "Current firewall rules:"
        firewall-cmd --list-all || true
    elif command -v iptables >/dev/null 2>&1; then
        echo "iptables detected."
        # Check for dangerous default ACCEPT policy first (specific before general)
        if iptables -L INPUT -n | head -1 | grep -q "policy ACCEPT"; then
            echo "WARNING: iptables INPUT chain has default ACCEPT policy. Consider changing to DROP and adding explicit allow rules."
        elif iptables -L INPUT -n | head -1 | grep -q "policy DROP"; then
            echo "OK: iptables INPUT chain has default DROP policy."
        fi
        echo ""
        echo "Current rules:"
        iptables -L -n -v || true
    else
        echo "WARNING: No common firewall management tool detected (ufw, firewalld, iptables)."
    fi
    echo ""
}

function check_unattended_upgrades() {
    echo "Checking for unattended upgrade tools and their status..."
    echo ""

    # Check for unattended upgrade tools based on package manager
    if command -v dpkg >/dev/null 2>&1; then
        if dpkg -l unattended-upgrades 2>/dev/null  | grep -q "^ii"; then
            echo "Unattended Upgrades is installed."
            if grep -q 'APT::Periodic::Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
                echo "OK: Unattended Upgrades is enabled to automatically install security updates."
            else
                echo "WARNING: Unattended Upgrades is installed but not enabled. Consider enabling it to automatically install security updates."
            fi
        else
            echo "INFO: Unattended Upgrades is not installed. Consider installing it to automatically install security updates."
        fi
    elif command -v rpm >/dev/null 2>&1; then
        if rpm -q dnf-automatic >/dev/null 2>&1; then
            echo "DNF Automatic is installed."
            if systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1; then
                echo "OK: DNF Automatic is enabled to automatically install security updates."
            else
                echo "WARNING: DNF Automatic is installed but not enabled. Consider enabling it to automatically install security updates."
            fi
        else
            echo "INFO: DNF Automatic is not installed. Consider installing it to automatically install security updates."
        fi
    else
        echo "INFO: Could not determine package manager. Please check for unattended upgrade tools manually."
    fi
    echo ""
}

check_users
check_password_policy
check_ssh_config
check_file_permissions
check_capabilities
check_open_ports
check_firewall
check_unattended_upgrades

echo ""
echo "Check complete."
