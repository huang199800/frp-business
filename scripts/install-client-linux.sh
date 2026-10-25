#!/usr/bin/env bash
set -euo pipefail
CONTROL_URL=${1:-https://frpc.hhse.top}
[[ $CONTROL_URL == https://* ]] || { echo '平台地址必须以 https:// 开头' >&2; exit 2; }
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ -x $SOURCE/portal && -x $SOURCE/frpc ]] || { echo '请在解压后的 Linux 客户端目录运行此脚本' >&2; exit 1; }
DEST=${XDG_DATA_HOME:-$HOME/.local/share}/frp-portal
mkdir -p "$DEST/bin"
chmod 700 "$DEST" "$DEST/bin"
install -m 700 "$SOURCE/portal" "$DEST/bin/portal"
install -m 700 "$SOURCE/frpc" "$DEST/bin/frpc"
"$DEST/bin/portal" connect --control-url "$CONTROL_URL" --setup-only
CONFIG=${XDG_CONFIG_HOME:-$HOME/.config}/frp-portal/agent.json
UNIT=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/frp-portal-agent.service
mkdir -p "$(dirname "$UNIT")"
cat > "$UNIT" <<EOF
[Unit]
Description=FRP Portal client
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=$DEST/bin/portal agent --config $CONFIG
Restart=always
RestartSec=5
[Install]
WantedBy=default.target
EOF
if systemctl --user daemon-reload && systemctl --user enable frp-portal-agent.service && systemctl --user restart frp-portal-agent.service; then
 echo '客户端已启动，并在该用户登录时自动启动。'
 echo '状态：systemctl --user status frp-portal-agent'
else
 echo '用户 systemd 不可用；可以运行：' >&2
 echo "$DEST/bin/portal agent --config $CONFIG" >&2
 exit 1
fi
