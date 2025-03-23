#!/bin/bash
# Persistence Installer
set -euo pipefail

detect_platform() {
	case "$(uname -s)" in
		Linux*)  echo "linux" ;;
		Darwin*) echo "macos" ;;
		CYGWIN*|MINGW*) echo "windows" ;;
		*)       echo "unknown" ;;
	esac
}

PLATFORM=$(detect_platform)
METHOD="${1:-}"
SERVICE_NAME="zdforge_daemon"

case $PLATFORM in
	linux)
		DEFAULT_METHOD=$([[ -d /run/systemd/system ]] && echo "systemd" || echo "cron")
		VALID_METHODS=("cron" "systemd")
		;;
	windows)
		DEFAULT_METHOD="registry"
		VALID_METHODS=("registry")
		;;
	*)
		DEFAULT_METHOD="cron"
		VALID_METHODS=("cron")
		;;
esac

METHOD=${METHOD:-$DEFAULT_METHOD}

# Validate method
if [[ ! " ${VALID_METHODS[@]} " =~ " $METHOD " ]]; then
	echo "Invalid method '$METHOD' for $PLATFORM" >&2
	exit 1
fi

# Install persistence
case $METHOD in
	cron)
		echo "Installing cron job"
		(crontab -l 2>/dev/null; 
		 echo "@reboot /opt/zerodayforge/venv/bin/python -m zerodayforge") | crontab -
		;;
	systemd)
		echo "Installing systemd service"
		cat > /etc/systemd/system/$SERVICE_NAME.service <<EOF
[Unit]
Description=ZeroDayForge Service
After=network.target

[Service]
ExecStart=$VENV_PATH/bin/python -m zerodayforge
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
		systemctl enable $SERVICE_NAME
		systemctl start $SERVICE_NAME
		;;
	registry)
		echo "Installing registry entry"
		reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" \
			/v ZeroDayForge /t REG_SZ \
			/d "C:\\Windows\\System32\\cmd.exe /c start /min python -m zerodayforge" /f
		;;
esac

echo "Persistence installed via $METHOD"
exit 0