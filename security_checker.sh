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