#!/bin/bash
# Configuration Generator
set -euo pipefail

[[ $# -ne 3 ]] && { 
	echo "Usage: $0 <target_ip> <port> <protocol>" >&2
	exit 1
}

TARGET_IP="$1"
PORT="$2"
PROTOCOL="$3"
CONFIG_DIR="${CONFIG_DIR:-/etc/zerodayforge}"
CONFIG_FILE="$CONFIG_DIR/targets.json"

validate_ip() {
	[[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
		echo "Invalid IP: $1" >&2
		exit 1
	}
}

validate_port() {
	[[ "$1" =~ ^[0-9]+$ && $1 -le 65535 ]] || {
		echo "Invalid port: $1" >&2
		exit 1
	}
}

validate_protocol() {
	[[ "$1" =~ ^(smb|rdp|dns)$ ]] || {
		echo "Invalid protocol: $1" >&2
		exit 1
	}
}

# Validate inputs
validate_ip "$TARGET_IP"
validate_port "$PORT"
validate_protocol "$PROTOCOL"

# Check jq
command -v jq >/dev/null || { 
	echo "jq required" >&2
	exit 1
}

# Initialize config
mkdir -p "$CONFIG_DIR"
[[ -f "$CONFIG_FILE" ]] || echo '{}' > "$CONFIG_FILE"

# Update config
TMP_FILE=$(mktemp)
jq --arg ip "$TARGET_IP" \
   --arg port "$PORT" \
   --arg proto "$PROTOCOL" \
   '.[$proto] += [{"ip": $ip, "port": ($port | tonumber)}]' \
   "$CONFIG_FILE" > "$TMP_FILE" && mv "$TMP_FILE" "$CONFIG_FILE"

echo "Added $PROTOCOL target $TARGET_IP:$PORT"
exit 0