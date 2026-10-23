#!/usr/bin/env bash
set -euo pipefail
MODE=${1:-}
[[ $EUID == 0 && $MODE =~ ^(serve|node|agent)$ ]] || { echo 'Usage: sudo uninstall-linux.sh serve|node|agent'; exit 2; }
systemctl disable --now "frp-portal-$MODE" || true
rm -f "/etc/systemd/system/frp-portal-$MODE.service"
systemctl daemon-reload
echo 'Service removed. Binaries, config, logs, state and database retained for backup/recovery.'
