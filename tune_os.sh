#!/bin/bash
# tune_os.sh — OS tuning for OBD 10K concurrent calls
# Run as root before starting the service

set -e

echo "=== OBD OS Tuning ==="

# File descriptors
ulimit -n 131072
echo "  ulimit -n: 131072"

# Thread stack size (512KB instead of 8MB default)
ulimit -s 512
echo "  ulimit -s: 512"

# Sysctl tuning
sysctl -w net.core.rmem_max=16777216 >/dev/null
sysctl -w net.core.wmem_max=16777216 >/dev/null
sysctl -w net.core.rmem_default=1048576 >/dev/null
sysctl -w net.core.wmem_default=1048576 >/dev/null
sysctl -w net.core.netdev_max_backlog=10000 >/dev/null
sysctl -w net.ipv4.udp_mem="65536 262144 524288" >/dev/null
sysctl -w net.ipv4.ip_local_port_range="1024 65535" >/dev/null
sysctl -w fs.file-max=2097152 >/dev/null

echo "  net.core.rmem_max: 16MB"
echo "  net.core.wmem_max: 16MB"
echo "  net.ipv4.ip_local_port_range: 1024-65535"
echo "  fs.file-max: 2097152"

# Persist (optional)
cat > /etc/sysctl.d/99-obd.conf <<EOF
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.netdev_max_backlog = 10000
net.ipv4.udp_mem = 65536 262144 524288
net.ipv4.ip_local_port_range = 1024 65535
fs.file-max = 2097152
EOF

cat > /etc/security/limits.d/99-obd.conf <<EOF
* soft nofile 131072
* hard nofile 131072
* soft nproc 65535
* hard nproc 65535
EOF

echo ""
echo "=== Done. Reboot or re-login for limits.d to take effect ==="
