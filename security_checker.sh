#!/bin/bash
set -euo pipefail

echo "=== Security Baseline Check ==="
echo ""

function check_ssh_config() {
    echo "Checking SSH configuration for potential security threat..."
    echo ""
    # Check for PermitRootLogin
    if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
        echo "WARNING: PermitRootLogin is currently set to yes. To enhance security, change this setting to no in /etc/ssh/sshd_config and restart the SSH service."
    elif grep -q "^PermitRootLogin prohibit-password" /etc/ssh/sshd_config; then
        echo "WARNING: PermitRootLogin is currently set to prohibit-password. To enhance security, change this setting to no in /etc/ssh/sshd_config and restart the SSH service."
    else
        echo "SSH configuration secured: PermitRootLogin is currently set to a secure value ('no' or 'prohibit-password')."
    fi
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

check_users
check_ssh_config
check_capabilities


echo ""
echo "Check complete."