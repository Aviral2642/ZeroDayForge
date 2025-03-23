#!/bin/bash
# ZeroDayForge Deployment Script
set -euo pipefail

LOG_FILE="/var/log/zerodayforge_install.log"
CONFIG_DIR="/etc/zerodayforge"
VENV_PATH="/opt/zerodayforge/venv"
LAST_STEP="init"

cleanup() {
	echo "Deployment failed at step: $LAST_STEP" | tee -a "$LOG_FILE"
	[[ -d "$VENV_PATH" ]] && rm -rf "$VENV_PATH"
	exit 1
}

trap cleanup ERR

exec > >(tee -a "$LOG_FILE") 2>&1
echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting deployment"

# Root check
[[ $EUID -ne 0 ]] && { echo "Run as root" >&2; exit 1; }

# Dependency checks
[[ -f "requirements.txt" ]] || { echo "requirements.txt missing" >&2; exit 1; }

# OS-specific installs
if grep -qi "debian\|ubuntu" /etc/os-release; then
	apt-get update && apt-get install -y \
		python3.10 python3-venv python3-pip \
		build-essential libssl-dev libffi-dev \
		linux-headers-$(uname -r) jq
elif grep -qi "rhel\|centos\|fedora" /etc/os-release; then
	dnf install -y python3.11 python3-pip gcc make \
		openssl-devel kernel-devel-$(uname -r) jq
else
	echo "Unsupported OS" >&2
	exit 1
fi
LAST_STEP="dependencies"

# Python environment
python3 -m venv "$VENV_PATH" || cleanup
source "$VENV_PATH/bin/activate"
pip install --no-cache-dir -r requirements.txt || {
	echo "Pip install failed" >&2
	cleanup
}
LAST_STEP="python"

# System setup
mkdir -p "$CONFIG_DIR" /var/lib/zerodayforge/{logs,payloads}
chmod 700 "$CONFIG_DIR" /var/lib/zerodayforge

# Kernel module
if [[ -f "src/hypervisor/kernelghost.ko" ]]; then
	insmod src/hypervisor/kernelghost.ko || \
		echo "Module load failed (maybe loaded?)" | tee -a "$LOG_FILE"
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') - Deployment SUCCESS"
exit 0