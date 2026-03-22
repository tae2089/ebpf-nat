#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

echo "Installing ebpf-nat..."

# 1. Determine architecture and find binary
ARCH=$(uname -m)
BIN_SRC=""
if [ "$ARCH" = "x86_64" ]; then
    BIN_SRC="bin/ebpf-nat-amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    BIN_SRC="bin/ebpf-nat-arm64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

if [ ! -f "$BIN_SRC" ]; then
    echo "Binary $BIN_SRC not found. Please run 'make build' first."
    exit 1
fi

# 2. Copy binary
echo "Copying binary to /usr/local/bin/ebpf-nat"
cp "$BIN_SRC" /usr/local/bin/ebpf-nat
chmod +x /usr/local/bin/ebpf-nat

# 3. Copy configuration file (don't overwrite if exists)
if [ ! -f /etc/default/ebpf-nat ]; then
    echo "Installing default configuration to /etc/default/ebpf-nat"
    cp systemd/ebpf-nat.default /etc/default/ebpf-nat
else
    echo "Configuration file /etc/default/ebpf-nat already exists, keeping current version."
    echo "New template available at systemd/ebpf-nat.default"
fi

# 4. Copy systemd service file
echo "Installing systemd service file..."
cp systemd/ebpf-nat.service /etc/systemd/system/

# 5. Reload systemd and enable service
echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Enabling ebpf-nat service to start on boot..."
systemctl enable ebpf-nat.service

echo ""
echo "Installation complete!"
echo "------------------------------------------------------"
echo "Before starting, please configure your network interface:"
echo "  sudo nano /etc/default/ebpf-nat"
echo ""
echo "Then start the service with:"
echo "  sudo systemctl start ebpf-nat"
echo ""
echo "To check the status:"
echo "  sudo systemctl status ebpf-nat"
echo "  sudo journalctl -u ebpf-nat -f"
echo "------------------------------------------------------"
