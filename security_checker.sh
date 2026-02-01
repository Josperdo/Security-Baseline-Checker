#!/bin/bash

echo "=== Security Baseline Check ==="
echo ""
echo "Checking for users with sudo privileges..."
echo ""

# Get users in sudo group
grep '^sudo:' /etc/group | cut -d: -f4

# Get users in wheel group (some distros use this)
grep '^wheel:' /etc/group | cut -d: -f4 2>/dev/null

echo ""
echo "Check complete."