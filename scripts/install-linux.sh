#!/usr/bin/env bash
set -euo pipefail
# Offline, signed-directory installation. No remote scripts and no embedded credentials.
SOURCE='' VERIFIER='' KEY='' CONFIG='' MODE='' TARGET=''
while (($#)); do
 case "$1" in
  --source) SOURCE=$2;; --verifier) VERIFIER=$2;; --public-key) KEY=$2;;
  --config) CONFIG=$2;; --mode) MODE=$2;; --target) TARGET=$2;;
  *) echo "Unknown option: $1" >&2; exit 2;;
 esac; shift 2
done
[[ $EUID == 0 ]] || { echo 'Run as root'; exit 1; }
[[ $MODE =~ ^(serve|node|agent)$ ]] || { echo 'mode must be serve, node or agent'; exit 1; }
case "$(uname -m)" in x86_64|aarch64) ;; *) echo 'Supported: Linux amd64/arm64'; exit 1;; esac
[[ -n $SOURCE && -f $SOURCE/portal && -f $VERIFIER && -f $KEY && -f $CONFIG ]] || { echo 'Missing source/verifier/public-key/config'; exit 1; }
TARGET=${TARGET:-/opt/frp-portal/$MODE}
[[ $TARGET == /opt/frp-portal/$MODE ]] || { echo 'Target must be /opt/frp-portal/<mode>'; exit 1; }
"$VERIFIER" verify --key "$KEY" --manifest "$SOURCE/SHA256SUMS"
awk '$2=="portal"{found=1}END{exit !found}' "$SOURCE/SHA256SUMS" || { echo 'portal is not signed'; exit 1; }
VERSION_OUTPUT=$("$SOURCE/portal" version)
[[ $VERSION_OUTPUT == 'portal 0.2.0; frp 0.71.1' ]] || { echo 'Version incompatible with installer'; exit 1; }
command -v systemctl >/dev/null || { echo 'systemd required'; exit 1; }
id frpportal >/dev/null 2>&1 || useradd --system --home-dir /var/lib/frp-portal --shell /usr/sbin/nologin frpportal
install -d -m 755 "$TARGET/releases"
install -d -o frpportal -g frpportal -m 700 "/var/lib/frp-portal/$MODE"
install -d -o frpportal -g frpportal -m 750 /var/log/frp-portal
if [[ ! -f $TARGET/config.json ]]; then install -o root -g frpportal -m 640 "$CONFIG" "$TARGET/config.json"; fi
# One-time port preflight is available with Python; repeat installs preserve existing configs.
if ! systemctl is-active --quiet "frp-portal-$MODE" && command -v python3 >/dev/null; then
 python3 "$(dirname "$0")/preflight.py" --mode "$MODE" --config "$TARGET/config.json"
fi
STAMP=$(date -u +%Y%m%dT%H%M%S)-$$
RELEASE=$TARGET/releases/$STAMP
install -d -m 755 "$RELEASE"
install -m 755 "$SOURCE/portal" "$RELEASE/portal"
cp -p "$SOURCE/SHA256SUMS" "$SOURCE/SHA256SUMS.sig" "$RELEASE/"
cp -p "$TARGET/config.json" "$TARGET/config.backup-$STAMP.json"
OLD=$(readlink "$TARGET/current" || true)
if [[ -n $OLD ]]; then ln -sfn "$OLD" "$TARGET/previous"; fi
ln -sfn "$RELEASE" "$TARGET/current"
cat > "/etc/systemd/system/frp-portal-$MODE.service" <<EOF
[Unit]
Description=FRP Portal $MODE
After=network-online.target
Wants=network-online.target
[Service]
User=frpportal
Group=frpportal
ExecStart=$TARGET/current/portal $MODE --config $TARGET/config.json --log-file /var/log/frp-portal/$MODE.log
Restart=always
RestartSec=5
TimeoutStopSec=10
KillMode=control-group
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/frp-portal/$MODE /var/log/frp-portal
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "frp-portal-$MODE" >/dev/null
systemctl restart "frp-portal-$MODE"
sleep 3
if ! systemctl is-active --quiet "frp-portal-$MODE"; then
 if [[ -n $OLD ]]; then ln -sfn "$OLD" "$TARGET/current"; systemctl restart "frp-portal-$MODE"; fi
 echo 'New service failed startup; restored prior binary if available. Inspect journalctl.' >&2; exit 1
fi
echo "Installed. Config preserved: $TARGET/config.json. Check application health and tunnel echo before promotion."
