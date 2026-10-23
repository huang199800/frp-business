#!/usr/bin/env bash
set -euo pipefail
VERSION=0.1.2
BASE_URL=https://raw.githubusercontent.com/huang199800/frp-business/main/releases/v0.1.2
PUBLIC_KEY='glC7y9BwjYjMSUa/L4DDCBB2mpo2sH9dRgKBdt0Akk0='
LOCAL_BUNDLE=''
ARGS=()
while (($#)); do
 case "$1" in
  --base-url) [[ $# -ge 2 ]] || exit 2; BASE_URL=$2; shift 2;;
  --bundle) [[ $# -ge 2 ]] || exit 2; LOCAL_BUNDLE=$2; shift 2;;
  --help|-h) cat <<'EOF'
FRP Portal 0.1.2 Linux 一键部署
用法：sudo bash install.sh --domain portal.example.com --node-domain node.example.com --email owner@example.com
可选：--control-port 8080 --postgres-port 5432 --without-node --check
离线：--bundle /path/to/extracted/signed/bundle
仅自动化测试：--local-test --admin-password-file /root/password-file
支持 Debian 12、Ubuntu 22.04/24.04 amd64/arm64，必须是 systemd 宿主。
需要真实域名、公网入口和80/443端口；不会自动调整云安全组/防火墙。
EOF
   exit 0;;
  *) ARGS+=("$1"); shift;;
 esac
done
[[ $(uname -s) == Linux ]] || { echo '请在 Linux 服务器运行' >&2; exit 1; }
[[ $EUID == 0 ]] || { echo '请使用 sudo 或 root 执行' >&2; exit 1; }
case "$(uname -m)" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) echo '仅支持amd64/arm64' >&2; exit 1;; esac
[[ -d /run/systemd/system ]] || { echo '需要systemd宿主，容器请使用Compose部署' >&2; exit 1; }
. /etc/os-release
case "$ID:$VERSION_ID" in debian:12|ubuntu:22.04|ubuntu:24.04) ;; *) echo '自动安装仅支持Debian12/Ubuntu22.04/24.04' >&2; exit 1;; esac
if [[ ! -x $(command -v python3 || true) || ! -x $(command -v openssl || true) || ! -x $(command -v curl || true) ]]; then
 command -v apt-get >/dev/null || { echo '缺少python3/openssl/curl且无apt-get' >&2; exit 1; }
 apt-get update
 DEBIAN_FRONTEND=noninteractive apt-get install -y python3 openssl curl ca-certificates
fi
TMP=$(mktemp -d /var/tmp/frp-portal-install.XXXXXXXX)
# Retain the verified payload for retry and incident review; never recursively remove operator paths.
echo "安装工作目录：$TMP"
if [[ -n $LOCAL_BUNDLE ]]; then
 LOCAL_BUNDLE=$(realpath "$LOCAL_BUNDLE")
 cp "$LOCAL_BUNDLE/SHA256SUMS" "$LOCAL_BUNDLE/SHA256SUMS.sig" "$TMP/"
else
 [[ $BASE_URL == https://* ]] || { echo '下载地址必须为HTTPS' >&2; exit 1; }
 curl --fail --location --retry 3 --connect-timeout 15 --max-time 300 "$BASE_URL/SHA256SUMS" -o "$TMP/SHA256SUMS"
 curl --fail --location --retry 3 --connect-timeout 15 --max-time 60 "$BASE_URL/SHA256SUMS.sig" -o "$TMP/SHA256SUMS.sig"
fi
python3 - "$PUBLIC_KEY" "$TMP" <<'PY'
import base64,pathlib,sys
p=pathlib.Path(sys.argv[2]);key=base64.b64decode(sys.argv[1],validate=True)
if len(key)!=32:raise SystemExit('Invalid pinned release key')
der=bytes.fromhex('302a300506032b6570032100')+key
p.joinpath('release-public.der').write_bytes(der)
p.joinpath('signature.bin').write_bytes(base64.b64decode(p.joinpath('SHA256SUMS.sig').read_text().strip(),validate=True))
PY
openssl pkeyutl -verify -pubin -keyform DER -inkey "$TMP/release-public.der" -rawin -in "$TMP/SHA256SUMS" -sigfile "$TMP/signature.bin"
NAME=frp-portal-${VERSION}-linux-${ARCH}.tar.gz
if [[ -n $LOCAL_BUNDLE ]]; then
 cp "$LOCAL_BUNDLE/$NAME" "$TMP/$NAME"
else
 curl --fail --location --retry 3 --connect-timeout 15 --max-time 600 "$BASE_URL/$NAME" -o "$TMP/$NAME"
fi
python3 - "$TMP" "$NAME" <<'PY'
import hashlib,pathlib,re,sys,tarfile
p=pathlib.Path(sys.argv[1]);name=sys.argv[2];found=[]
for line in p.joinpath('SHA256SUMS').read_text().splitlines():
 parts=line.split()
 if len(parts)!=2 or not re.fullmatch('[0-9a-fA-F]{64}',parts[0]):raise SystemExit('Invalid signed manifest')
 if parts[1]==name:found.append(parts[0].lower())
if len(found)!=1:raise SystemExit('Archive not uniquely listed in signed manifest')
if hashlib.sha256(p.joinpath(name).read_bytes()).hexdigest()!=found[0]:raise SystemExit('Archive checksum mismatch')
out=p/'bundle';out.mkdir()
with tarfile.open(p/name,'r:gz') as archive:
 members=archive.getmembers()
 for m in members:
  target=(out/m.name).resolve()
  if not str(target).startswith(str(out.resolve())+'/') or not (m.isfile() or m.isdir()):raise SystemExit('Unsafe archive path/type')
 if sum(m.size for m in members)>512*1024*1024:raise SystemExit('Archive too large')
 # Only regular files/directories were allowed; support system Python 3.10 as shipped in Ubuntu22.04.
 archive.extractall(out,members=members)
for n in ['portal','frps','frpc']:(out/n).chmod(0o755)
PY
exec python3 "$TMP/bundle/oneclick.py" --bundle "$TMP/bundle" "${ARGS[@]}"
