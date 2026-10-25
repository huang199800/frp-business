#!/usr/bin/env python3
"""Install or upgrade a remote FRP node without a database or control-panel secrets."""
import argparse
import base64
import contextlib
import getpass
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse

from oneclick import VERSION, atomic, domain, read_json, run, wait_for, write_json, api, os_supported

if os.name == 'posix':
    import fcntl
    import grp
    import pwd

CONFIG = Path('/etc/frp-portal')
STATE = CONFIG / 'node-oneclick.json'
ROOT = Path('/opt/frp-portal/remote-node')
NODE = CONFIG / 'node/node.json'
CERT = CONFIG / 'node/node.crt'
KEY = CONFIG / 'node/node.key'


def service_unit():
    return f'''[Unit]
Description=FRP Portal remote node
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=frpportal
Group=frpportal
ExecStart={ROOT}/current/portal node --config {NODE} --log-file /var/log/frp-portal/node.log
Restart=always
RestartSec=5
TimeoutStopSec=10
KillMode=control-group
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/frp-portal/node /var/log/frp-portal
UMask=0077
[Install]
WantedBy=multi-user.target
'''


def renewal_hook():
    # certbot runs deploy hooks as root. Only the named certificate may replace the node TLS pair.
    return '''#!/usr/bin/env bash
set -euo pipefail
[[ ${RENEWED_LINEAGE:-} == /etc/letsencrypt/live/$(python3 -c 'import json;print(json.load(open("/etc/frp-portal/node-oneclick.json"))["node_domain"])') ]] || exit 0
install -o root -g frpportal -m 0640 "$RENEWED_LINEAGE/fullchain.pem" /etc/frp-portal/node/node.crt
install -o root -g frpportal -m 0640 "$RENEWED_LINEAGE/privkey.pem" /etc/frp-portal/node/node.key
systemctl restart frp-portal-node
'''


class NodeInstaller:
    def __init__(self, args):
        self.a = args
        self.bundle = Path(args.bundle).resolve()
        self.state = read_json(STATE) if STATE.exists() else {}
        self.stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + secrets.token_hex(3)
        self.old_current = None
        self.backup = None

    def preflight(self):
        if platform.system() != 'Linux' or os.geteuid() != 0:
            raise RuntimeError('请在 Linux 服务器使用 sudo/root 执行')
        release = dict(line.strip().split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        release = {k: v.strip('"') for k, v in release.items()}
        if not os_supported(release) or platform.machine().lower() not in ('x86_64', 'aarch64', 'arm64'):
            raise RuntimeError('仅支持 Debian 12、Ubuntu 22.04/24.04 的 amd64/arm64 宿主')
        if not Path('/run/systemd/system').is_dir():
            raise RuntimeError('需要 systemd 宿主')
        if (CONFIG / 'oneclick.json').exists():
            raise RuntimeError('此机器已经是控制服务器；请在另一台服务器安装远程节点')
        if not self.state and (NODE.exists() or Path('/etc/systemd/system/frp-portal-node.service').exists()):
            raise RuntimeError('发现非本安装器管理的节点配置，拒绝覆盖')
        if self.state and any(self.state.get(k) != v for k, v in {'control_url': self.a.control_url, 'node_domain': self.a.node_domain, 'node_id': self.a.node_id, 'email': self.a.email, 'verify_key': self.a.verify_key}.items()):
            raise RuntimeError('已安装节点的域名、身份或控制台地址不同；拒绝覆盖')
        socket.getaddrinfo(self.a.node_domain, 80)
        if not CERT.exists() and not self.a.check:
            with socket.socket() as listener:
                try: listener.bind(('0.0.0.0', 80))
                except OSError: raise RuntimeError('本机 TCP 80 已被占用，certbot standalone 无法申请证书') from None
        if run(self.bundle / 'portal', 'version').strip() != f'portal {VERSION}; frp 0.71.1':
            raise RuntimeError('安装器与程序版本不匹配')
        if run(self.bundle / 'frps', '--version').strip() != '0.71.1':
            raise RuntimeError('FRP 版本不匹配')
        token = self.state.get('credential') if self.state else ''
        if not token:
            if self.a.credential_file:
                file = Path(self.a.credential_file)
                if file.stat().st_mode & 0o077:
                    raise RuntimeError('节点凭据文件必须仅 root 可读（chmod 600）')
                token = file.read_text().strip()
            else:
                token = getpass.getpass('粘贴控制台一次性显示的节点专属密钥（输入不回显）: ').strip()
        if not re.fullmatch(r'[A-Z2-7]{32}', token):
            raise RuntimeError('节点专属密钥格式无效')
        info = api(self.a.control_url, '/api/node/setup', {'node_id': self.a.node_id}, token)
        if info.get('host') != self.a.node_domain or info.get('tls_public_ca') is not True or info.get('verify_key') != self.a.verify_key:
            raise RuntimeError('控制台节点域名或公网证书模式与本机参数不一致')
        self.credential = token
        if not self.state and not self.a.check:
            self.state = {'control_url': self.a.control_url, 'node_domain': self.a.node_domain, 'node_id': self.a.node_id,
                          'email': self.a.email, 'verify_key': self.a.verify_key, 'credential': token, 'version': VERSION, 'complete': False}
            write_json(STATE, self.state)
        print('预检通过：操作系统、程序版本、节点身份及控制台配置。', flush=True)

    def dependencies(self):
        env = os.environ.copy(); env['DEBIAN_FRONTEND'] = 'noninteractive'; env['NEEDRESTART_MODE'] = 'l'
        run('apt-get', 'update', env=env)
        run('apt-get', 'install', '-y', 'certbot', 'openssl', 'ca-certificates', env=env)
        try: pwd.getpwnam('frpportal')
        except KeyError: run('useradd', '--system', '--home-dir', '/var/lib/frp-portal', '--shell', '/usr/sbin/nologin', 'frpportal')
        identity = (pwd.getpwnam('frpportal').pw_uid, grp.getgrnam('frpportal').gr_gid)
        NODE.parent.mkdir(parents=True, exist_ok=True); os.chown(NODE.parent, 0, identity[1]); os.chmod(NODE.parent, 0o750)
        data = Path('/var/lib/frp-portal/node'); data.mkdir(parents=True, exist_ok=True); os.chown(data, *identity); os.chmod(data, 0o700)
        logs = Path('/var/log/frp-portal'); logs.mkdir(exist_ok=True); os.chown(logs, *identity); os.chmod(logs, 0o750)
        self.identity = identity

    def backup_existing(self):
        if not NODE.exists(): return
        backup = Path('/var/backups/frp-portal') / ('node-' + self.stamp)
        backup.mkdir(parents=True, mode=0o700); os.chmod(backup, 0o700)
        for source in (STATE, NODE, CERT, KEY, Path('/etc/systemd/system/frp-portal-node.service')):
            if source.exists(): shutil.copy2(source, backup / source.name)
        self.backup = backup
        print('节点升级前配置备份：' + str(backup), flush=True)

    def binaries(self):
        releases = ROOT / 'releases'; releases.mkdir(parents=True, exist_ok=True)
        target = releases / (VERSION + '-' + self.stamp); target.mkdir()
        for name in ('portal', 'frps'):
            shutil.copyfile(self.bundle / name, target / name); os.chmod(target / name, 0o755)
        shutil.copytree(self.bundle / 'third_party', target / 'third_party')
        current = ROOT / 'current'; self.old_current = os.readlink(current) if current.is_symlink() else None
        temporary = ROOT / ('.current-' + self.stamp); temporary.symlink_to(target); os.replace(temporary, current)

    def certificates(self):
        if CERT.exists() != KEY.exists(): raise RuntimeError('现有证书与私钥不完整，拒绝覆盖')
        if not CERT.exists():
            run('certbot', 'certonly', '--standalone', '--non-interactive', '--agree-tos', '--preferred-challenges', 'http', '-m', self.a.email, '-d', self.a.node_domain, '--keep-until-expiring', timeout=300)
        live = Path('/etc/letsencrypt/live') / self.a.node_domain
        if not live.joinpath('fullchain.pem').exists() or not live.joinpath('privkey.pem').exists():
            raise RuntimeError('Let’s Encrypt 证书未签发；请检查 DNS、80 端口及云防火墙')
        shutil.copyfile(live / 'fullchain.pem', CERT); shutil.copyfile(live / 'privkey.pem', KEY)
        for path in (CERT, KEY): os.chown(path, 0, self.identity[1]); os.chmod(path, 0o640)
        run('openssl', 'x509', '-in', CERT, '-checkend', '86400', '-noout')
        hook = Path('/etc/letsencrypt/renewal-hooks/deploy/frp-portal-node')
        atomic(hook, renewal_hook(), 0o700)

    def configure(self):
        if not NODE.exists():
            data = {'control_url': self.a.control_url, 'node_id': self.a.node_id, 'credential': self.credential, 'verify_key': self.a.verify_key,
                    'frp_path': str(ROOT / 'current/frps'), 'tls_cert': str(CERT), 'tls_key': str(KEY), 'state_dir': '/var/lib/frp-portal/node'}
            write_json(NODE, data, 0o640, (0, self.identity[1]))
        self.state = {'control_url': self.a.control_url, 'node_domain': self.a.node_domain, 'node_id': self.a.node_id,
                      'email': self.a.email, 'verify_key': self.a.verify_key, 'credential': self.credential, 'version': VERSION, 'complete': False}
        write_json(STATE, self.state)
        atomic('/etc/systemd/system/frp-portal-node.service', service_unit(), 0o644)
        run('systemctl', 'daemon-reload'); run('systemctl', 'enable', '--now', 'frp-portal-node'); run('systemctl', 'restart', 'frp-portal-node')
        wait_for(lambda: run('systemctl', 'is-active', 'frp-portal-node').strip() == 'active', 30)

    def rollback(self):
        if self.backup:
            for destination in (STATE, NODE, CERT, KEY, Path('/etc/systemd/system/frp-portal-node.service')):
                saved = self.backup / destination.name
                if saved.exists(): shutil.copy2(saved, destination)
        if self.old_current:
            temporary = ROOT / ('.rollback-' + self.stamp); temporary.symlink_to(self.old_current); os.replace(temporary, ROOT / 'current')
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
            subprocess.run(['systemctl', 'restart', 'frp-portal-node'], capture_output=True)
            print('程序已切回旧版本；备份目录：' + str(self.backup), file=sys.stderr)

    def install(self):
        self.preflight()
        if self.a.check: return
        self.dependencies(); self.backup_existing()
        try:
            self.binaries(); self.certificates(); self.configure()
            self.state['complete'] = True; write_json(STATE, self.state)
            print(f'远程节点已部署：{self.a.node_domain}\n控制台：{self.a.control_url}\n节点服务：systemctl status frp-portal-node\n请放行 80/TCP 用于证书签发与续期，并按控制台节点端口池放行 TCP/UDP。', flush=True)
        except Exception:
            self.rollback(); raise


def main():
    parser = argparse.ArgumentParser(description='FRP Portal 远程节点一键安装/升级')
    parser.add_argument('--bundle', default=str(Path(__file__).resolve().parent))
    parser.add_argument('--control-url', required=True)
    parser.add_argument('--node-domain', type=domain, required=True)
    parser.add_argument('--node-id', required=True)
    parser.add_argument('--verify-key', required=True)
    parser.add_argument('--email', required=True)
    parser.add_argument('--credential-file')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    uri = urllib.parse.urlparse(args.control_url)
    if uri.scheme != 'https' or not uri.hostname or uri.path or uri.username or uri.query or uri.fragment:
        parser.error('控制台地址必须是 https://域名')
    if not re.fullmatch(r'[A-Z2-7]{32}', args.node_id): parser.error('节点 ID 格式无效')
    if len(base64.b64decode(args.verify_key, validate=True)) != 32: parser.error('验证公钥格式无效')
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', args.email): parser.error('邮箱格式无效')
    if os.geteuid() != 0: parser.error('请使用 sudo/root')
    with open('/run/lock/frp-portal-node-install.lock', 'w') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('另一节点安装正在执行') from None
        NodeInstaller(args).install()


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('节点安装失败：' + str(error) + '\n原有节点配置及备份已保留；修正问题后重试。', file=sys.stderr)
        sys.exit(1)
