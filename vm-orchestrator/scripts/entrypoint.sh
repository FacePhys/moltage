#!/bin/bash
# entrypoint.sh — Container entrypoint for VM Orchestrator
#
# 1. Sets up the host network bridge (fcbr0) and NAT rules
# 2. Starts the orchestrator binary
#
# Requires: privileged mode + network_mode: host

set -e

echo "=== VM Orchestrator Entrypoint ==="

# Setup network bridge (idempotent — safe to run multiple times)
BRIDGE_NAME="${BRIDGE_NAME:-fcbr0}"
GATEWAY_IP="${GATEWAY_IP:-10.0.1.1}"
VM_SUBNET="${VM_SUBNET:-10.0.1.0/24}"

echo "[1/2] Setting up network bridge..."

# Find the host's default outgoing interface
HOST_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$HOST_IFACE" ]; then
    HOST_IFACE="eth0"
    echo "  Warning: Could not detect default interface, using $HOST_IFACE"
fi

# Create bridge if it doesn't exist
if ! ip link show "$BRIDGE_NAME" &>/dev/null; then
    echo "  Creating bridge $BRIDGE_NAME with gateway $GATEWAY_IP"
    ip link add name "$BRIDGE_NAME" type bridge
    ip addr add "${GATEWAY_IP}/24" dev "$BRIDGE_NAME"
    ip link set "$BRIDGE_NAME" up
else
    echo "  Bridge $BRIDGE_NAME already exists"
fi

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# Setup NAT masquerade (idempotent via -C check)
if ! iptables -t nat -C POSTROUTING -s "$VM_SUBNET" -o "$HOST_IFACE" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s "$VM_SUBNET" -o "$HOST_IFACE" -j MASQUERADE
    echo "  NAT masquerade rule added"
fi

# Allow forwarded traffic
iptables -A FORWARD -i "$BRIDGE_NAME" -o "$HOST_IFACE" -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i "$HOST_IFACE" -o "$BRIDGE_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

echo "  Network setup complete"

# Check for required files
echo ""
echo "[2/2] Checking Firecracker prerequisites..."
if [ -f "/usr/local/bin/firecracker" ]; then
    echo "  ✓ Firecracker binary found"
else
    echo "  ✗ Firecracker binary NOT found"
fi

if [ -f "/var/lib/firecracker/vmlinux" ]; then
    echo "  ✓ Kernel image found"
else
    echo "  ✗ Kernel image NOT found"
fi

if [ -f "/var/lib/firecracker/rootfs/clawdbot.ext4" ]; then
    echo "  ✓ Base rootfs found"
else
    echo "  ✗ Base rootfs NOT found (run: sudo bash rootfs/build-rootfs.sh)"
fi

if [ -c "/dev/kvm" ]; then
    echo "  ✓ KVM available"
else
    echo "  ✗ KVM NOT available (/dev/kvm missing — VMs cannot start)"
fi

echo ""
echo "=== Starting Orchestrator ==="

# Start the orchestrator
exec /usr/local/bin/orchestrator "$@"
