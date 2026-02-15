#!/bin/bash
# build-rootfs.sh — Build the base Firecracker rootfs image with OpenClaw (Clawdbot)
#
# Produces an ext4 disk image with:
#   - Alpine Linux (minimal)
#   - Node.js 22 (required: >= 22.12.0)
#   - OpenSSH server
#   - openclaw (npm: openclaw) + webhook plugin (from local source)
#   - Auto-start init script
#
# Usage: sudo ./build-rootfs.sh [output_path]
#
# Requirements: losetup, chroot, mkfs.ext4
# Note: The clawdbot-plugin-webhook-server directory must exist alongside
#       this script's parent directory (../clawdbot-plugin-webhook-server)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_SRC="${SCRIPT_DIR}/../clawdbot-plugin-webhook-server"
OUTPUT="${1:-clawdbot.ext4}"
SIZE_MB=4096
MOUNTPOINT="/tmp/rootfs-build"

echo "=== Building OpenClaw MicroVM Rootfs ==="
echo "  Output: $OUTPUT"
echo "  Size:   ${SIZE_MB}MB"
echo ""

# Validate plugin source exists
if [ ! -d "$PLUGIN_SRC" ]; then
    echo "ERROR: clawdbot-plugin-webhook-server not found at $PLUGIN_SRC"
    echo "  Expected: ../clawdbot-plugin-webhook-server relative to this script"
    exit 1
fi

# 1. Create sparse disk image
echo "[1/7] Creating disk image..."

# Clean up any stale mounts from previous failed runs
if mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
    echo "  Cleaning up stale mount from previous run..."
    umount -R "$MOUNTPOINT" 2>/dev/null || true
fi
# Detach any loop devices pointing to our output file
losetup -j "$OUTPUT" 2>/dev/null | cut -d: -f1 | while read dev; do
    losetup -d "$dev" 2>/dev/null || true
done

truncate -s ${SIZE_MB}M "$OUTPUT"
mkfs.ext4 -q -F "$OUTPUT"

# 2. Mount the image
echo "[2/7] Mounting image..."
mkdir -p "$MOUNTPOINT"
mount -o loop "$OUTPUT" "$MOUNTPOINT"

# Ensure cleanup on exit
cleanup() {
    echo "[cleanup] Unmounting..."
    umount "$MOUNTPOINT/dev" 2>/dev/null || true
    umount "$MOUNTPOINT/sys" 2>/dev/null || true
    umount "$MOUNTPOINT/proc" 2>/dev/null || true
    umount "$MOUNTPOINT" 2>/dev/null || true
    rmdir "$MOUNTPOINT" 2>/dev/null || true
}
trap cleanup EXIT

# 3. Install Alpine base system
echo "[3/7] Installing Alpine base system..."
ARCH=$(uname -m)
ALPINE_VERSION="3.21.6"

# Use Alpine minirootfs tarball — works reliably on any Linux host (Ubuntu, etc.)
MINIROOTFS_URL="https://mirrors.aliyun.com/alpine/v3.21/releases/${ARCH}/alpine-minirootfs-${ALPINE_VERSION}-${ARCH}.tar.gz"
echo "Downloading Alpine minirootfs v${ALPINE_VERSION} (${ARCH})..."
curl -fSL "$MINIROOTFS_URL" -o /tmp/alpine-minirootfs.tar.gz
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to download Alpine minirootfs from:"
    echo "  $MINIROOTFS_URL"
    exit 1
fi

# Extract into the mounted rootfs
tar -xzf /tmp/alpine-minirootfs.tar.gz -C "$MOUNTPOINT"
rm -f /tmp/alpine-minirootfs.tar.gz

# Configure DNS before installing packages
cat > "$MOUNTPOINT/etc/resolv.conf" << 'EOF'
nameserver 114.114.114.114
nameserver 223.5.5.5
EOF

# Configure Alpine repos (use Alibaba Cloud mirror for China)
cat > "$MOUNTPOINT/etc/apk/repositories" << 'EOF'
https://mirrors.aliyun.com/alpine/v3.21/main
https://mirrors.aliyun.com/alpine/v3.21/community
EOF

# Mount proc/sys/dev for chroot (needed for apk install)
mount -t proc proc "$MOUNTPOINT/proc"
mount -t sysfs sys "$MOUNTPOINT/sys"
mount -t devtmpfs dev "$MOUNTPOINT/dev"

# Install required packages via chroot (including Node.js)
# NOTE: Alpine uses musl libc — nodejs.org binaries (glibc) won't work!
#       Must install Node.js via apk from Alpine repos.
echo "Installing packages in chroot..."
chroot "$MOUNTPOINT" /bin/sh << 'CHROOTEOF'
# Alpine 3.21 has Node.js 22.x + OpenSSL 3.4.x natively — no edge repos needed

apk update
apk add --no-cache \
    openrc openssh bash curl shadow git \
    nodejs npm

# Verify Node.js
echo "Node: $(node --version)"
echo "NPM:  $(npm --version)"

# Use npmmirror registry for faster downloads in China
npm config set registry https://registry.npmmirror.com
CHROOTEOF

# 4. Configure base system
echo "[4/7] Configuring system..."
chroot "$MOUNTPOINT" /bin/sh << 'CHROOTEOF'
# Set hostname
echo "clawdbot" > /etc/hostname

# Configure serial console for Firecracker
sed -i 's/^#ttyS0/ttyS0/' /etc/inittab 2>/dev/null || true

# Auto-start services
rc-update add sshd default 2>/dev/null || true
rc-update add networking default 2>/dev/null || true

# Configure SSH
mkdir -p /etc/ssh
ssh-keygen -A 2>/dev/null || true
sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create user
adduser -D -s /bin/bash user 2>/dev/null || true
echo "user:clawdbot" | chpasswd
echo "root:clawdbot" | chpasswd
CHROOTEOF

# 5. Install OpenClaw + Webhook Plugin
echo "[5/6] Installing OpenClaw + WeChat webhook plugin..."

# Copy the plugin source into rootfs for local install
echo "Copying webhook plugin source into rootfs..."
cp -r "$PLUGIN_SRC" "$MOUNTPOINT/tmp/clawdbot-plugin-webhook-server"

chroot "$MOUNTPOINT" /bin/sh << 'CHROOTEOF'
# Install openclaw globally — this provides the `openclaw` CLI
# --ignore-scripts: skip node-llama-cpp postinstall (compiles llama.cpp locally)
# We use remote ChatGLM-5 API, not local LLM, so llama.cpp is not needed.
echo "Installing openclaw from npm..."

# Force git to use HTTPS instead of SSH for GitHub URLs
# (some deps like libsignal-node use ssh://git@github.com/... which fails without SSH keys)
# Write .gitconfig directly to avoid quoting issues with git config inside heredoc
cat > /root/.gitconfig << 'GITCFG'
[url "https://github.com/"]
    insteadOf = ssh://git@github.com/
    insteadOf = git@github.com:
GITCFG

npm install -g openclaw@latest --ignore-scripts

# Verify openclaw is installed
if ! command -v openclaw &> /dev/null; then
    echo "ERROR: openclaw binary not found after install!"
    exit 1
fi
echo "OpenClaw installed: $(openclaw --version 2>/dev/null || echo 'version check skipped')"

# Install the WeChat webhook plugin from the locally copied directory
# OpenClaw loads TypeScript source directly via jiti (same as official plugins
# like @openclaw/voice-call), so no tsc build step is needed.
echo "Installing webhook-server plugin from local source..."
cd /tmp/clawdbot-plugin-webhook-server

# Install only runtime dependencies (axios, fastify)
# --ignore-scripts: prevent any postinstall scripts from running
npm install --omit=dev --ignore-scripts

cd /
openclaw plugins install /tmp/clawdbot-plugin-webhook-server

# Clean up plugin source from /tmp
rm -rf /tmp/clawdbot-plugin-webhook-server

# ---- Configure OpenClaw for MicroVM mode ----

# Create openclaw home directory (persistent, mounted as /data)
mkdir -p /data/clawdbot
chown user:user /data/clawdbot

# Create default openclaw config that enables the webhook plugin
# Config resides at ~/.openclaw/openclaw.json per OpenClaw conventions
OPENCLAW_HOME="/home/user/.openclaw"
mkdir -p "$OPENCLAW_HOME"
cat > "$OPENCLAW_HOME/openclaw.json" << 'CONFIGEOF'
{
  "env": {
    "ZHIPU_API_KEY": ""
  },
  "channels": {
    "wechat": {
      "enabled": true,
      "config": {
        "callbackUrl": ""
      }
    }
  },
  "plugins": {
    "entries": {
      "webhook-server": {
        "enabled": true
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "zhipu/glm-5"
      },
      "models": {
        "zhipu/glm-5": { "alias": "glm5" }
      },
      "systemPrompt": "You are a helpful AI assistant. Respond in the same language as the user.",
      "contextTokens": 200000,
      "timeoutSeconds": 300
    }
  },
  "models": {
    "mode": "merge",
    "providers": {
      "zhipu": {
        "baseUrl": "${LLM_GATEWAY_URL:-http://10.0.1.1:8081/v1}",
        "apiKey": "gateway-managed",
        "api": "openai-completions",
        "models": [
          {
            "id": "glm-5",
            "name": "ChatGLM-5",
            "reasoning": false,
            "input": ["text"],
            "cost": {
              "input": 0.001,
              "output": 0.0032,
              "cacheRead": 0,
              "cacheWrite": 0
            },
            "contextWindow": 200000,
            "maxTokens": 128000
          }
        ]
      }
    }
  }
}
CONFIGEOF
chown -R user:user "$OPENCLAW_HOME"

# Create OpenRC init script for openclaw
cat > /etc/init.d/openclaw << 'INITEOF'
#!/sbin/openrc-run

name="OpenClaw AI Agent"
description="OpenClaw AI Agent Gateway with Webhook Server"

command="/usr/local/bin/openclaw"
command_args="gateway --port 18789"
command_user="user"
command_background="yes"
pidfile="/run/openclaw.pid"
output_log="/var/log/openclaw.log"
error_log="/var/log/openclaw.log"

directory="/home/user"

# Gateway listens on port 18789
# The webhook-server plugin registers its HTTP handler on the gateway

depend() {
    need net
    after sshd
}

start_pre() {
    checkpath --directory --owner user:user /data/clawdbot
    checkpath --file --owner user:user /var/log/openclaw.log
}
INITEOF
chmod +x /etc/init.d/openclaw
rc-update add openclaw default 2>/dev/null || true

# Create health check endpoint script (for orchestrator readiness probe)
cat > /usr/local/bin/healthcheck << 'HEALTHEOF'
#!/bin/sh
# Simple health check — returns 0 if openclaw gateway is accepting connections
curl -sf http://127.0.0.1:18789/health -o /dev/null 2>/dev/null
exit $?
HEALTHEOF
chmod +x /usr/local/bin/healthcheck
CHROOTEOF

# 7. Networking setup
echo "[7/7] Configuring networking..."
cat > "$MOUNTPOINT/etc/network/interfaces" << 'EOF'
auto lo
iface lo inet loopback

# eth0 is configured via kernel boot params (ip= argument)
auto eth0
iface eth0 inet dhcp
EOF

# MOTD
cat > "$MOUNTPOINT/etc/motd" << 'EOF'

    ___                    ____ _
   / _ \ _ __   ___ _ __ / ___| | __ ___      __
  | | | | '_ \ / _ \ '_ \ |   | |/ _` \ \ /\ / /
  | |_| | |_) |  __/ | | | |___| | (_| |\ V  V /
   \___/| .__/ \___|_| |_|\____|_|\__,_| \_/\_/
        |_|

  OpenClaw AI Agent — Firecracker MicroVM
  Default model: ChatGLM-5 (智谱AI)
  Gateway on port 18789

EOF

# Cleanup chroot mounts
umount "$MOUNTPOINT/dev" 2>/dev/null || true
umount "$MOUNTPOINT/sys" 2>/dev/null || true
umount "$MOUNTPOINT/proc" 2>/dev/null || true

echo ""
echo "=== Rootfs build complete ==="
echo "Output: $OUTPUT ($(du -sh "$OUTPUT" | cut -f1))"
echo ""
echo "Packages installed:"
echo "  • Node.js >= 22.12.0"
echo "  • openclaw (npm: openclaw@latest)"
echo "  • clawdbot-plugin-webhook-server (local install, ngrok removed)"
echo "  • openssh-server (user: user / password: clawdbot)"
echo ""
echo "Next steps:"
echo "  1. Set ZHIPU_API_KEY in the VM environment (get from open.bigmodel.cn)"
echo "  2. Place a vmlinux kernel at /var/lib/firecracker/vmlinux"
echo "  3. Copy $OUTPUT to /var/lib/firecracker/rootfs/"
echo "  4. Run setup-network.sh on the host"
echo "  5. Start the orchestrator"
