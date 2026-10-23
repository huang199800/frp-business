#!/usr/bin/env python3
"""Signed-bundle, native systemd installer for Debian 12 / Ubuntu 22.04,24.04.
Run only as root. Passwords are read from the terminal or a root-only file.
"""
import argparse
import base64
import contextlib
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

if os.name=='posix':
    import fcntl
    import grp
    import pwd

VERSION = '0.1.4'
CONFIG = Path('/etc/frp-portal')
ROOT = Path('/opt/frp-portal/oneclick')
STATE = CONFIG / 'oneclick.json'
PUBLIC = Path('/var/lib/frp-portal/public')


def domain(value):
    value = value.lower().rstrip('.')
    if len(value)>253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', value):
        raise argparse.ArgumentTypeError('请填写真实域名，不带协议、路径或端口')
    return value


def os_supported(data):
    return (data.get('ID'), data.get('VERSION_ID')) in {('debian','12'),('ubuntu','22.04'),('ubuntu','24.04')}


def atomic(path, content, mode=0o600, owner=None):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name('.'+path.name+'.'+secrets.token_hex(6))
    try:
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
        with os.fdopen(fd,'wb') as f:
            f.write(content.encode() if isinstance(content,str) else content); f.flush(); os.fsync(f.fileno())
        if owner is not None:os.chown(temp,*owner)
        os.chmod(temp,mode); os.replace(temp,path)
    finally:
        with contextlib.suppress(FileNotFoundError):temp.unlink()


def read_json(path):
    return json.loads(Path(path).read_text())


def write_json(path,data,mode=0o600,owner=None):
    atomic(path,json.dumps(data,ensure_ascii=False,indent=2)+'\n',mode,owner)


def run(*args,stdin=None,env=None,sensitive=False,timeout=300):
    print('执行：'+str(args[0])+(' （安全初始化）' if sensitive else ' '+' '.join(str(x) for x in args[1:])),flush=True)
    # Package post-install hooks may spawn descendants holding output descriptors.
    # Anonymous files avoid PIPE EOF hangs; a separate process group bounds timeouts.
    with tempfile.TemporaryFile() as output,tempfile.TemporaryFile() as errors:
        process=subprocess.Popen([str(x) for x in args],stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,stdout=output,stderr=errors,env=env,start_new_session=os.name=='posix')
        timed_out=False
        try:process.communicate(None if stdin is None else stdin.encode(),timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out=True
            if os.name=='posix':
                with contextlib.suppress(ProcessLookupError):os.killpg(process.pid,signal.SIGKILL)
            else:process.kill()
            process.wait(timeout=5)
        output.seek(0);stdout=output.read().decode('utf-8',errors='replace');errors.seek(0);stderr=errors.read().decode('utf-8',errors='replace')
    if timed_out or process.returncode:
        detail='（含敏感信息的命令输出已隐藏）' if sensitive else (stdout+'\n'+stderr)[-4000:]
        raise RuntimeError(f'{args[0]} '+(f'超过{timeout}秒' if timed_out else '执行失败')+': '+detail)
    return stdout


def totp(secret):
    digest=hmac.new(base64.b32decode(secret),struct.pack('>Q',int(time.time())//30),hashlib.sha1).digest()
    offset=digest[-1]&15
    return f'{(struct.unpack(">I",digest[offset:offset+4])[0]&0x7fffffff)%1000000:06d}'


def api(url,path,data=None,token='',reauth=None,ca=None):
    headers={'Content-Type':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    if reauth:headers.update({'X-Admin-Password':reauth[0],'X-Admin-OTP':reauth[1]})
    request=urllib.request.Request(url+path,data=None if data is None else json.dumps(data).encode(),headers=headers)
    try:
        with urllib.request.urlopen(request,context=ssl.create_default_context(cafile=ca),timeout=5) as response:return json.load(response)
    except urllib.error.HTTPError as error:
        try:message=json.loads(error.read()).get('error','API错误')
        except Exception:message='API错误'
        raise RuntimeError(f'HTTP {error.code}: {message}') from None


def wait_for(fn,seconds=60):
    end=time.monotonic()+seconds; last=None
    while time.monotonic()<end:
        try:
            result=fn()
            if result:return result
        except Exception as error:last=error
        time.sleep(1)
    raise RuntimeError(f'健康检查超时: {last}')


def check_port(port,managed=False):
    if managed:return
    with socket.socket() as s:
        try:s.bind(('127.0.0.1',port))
        except OSError:raise RuntimeError(f'TCP {port} 已被占用，请通过 --control-port 指定空闲端口') from None


def get_password(path):
    if path:
        p=Path(path); info=p.stat()
        if info.st_uid!=0 or info.st_mode&0o077:raise RuntimeError('密码文件必须root持有、权限600或更严格')
        value=p.read_text().rstrip('\r\n')
    else:
        value=getpass.getpass('设置管理员密码（12–72 UTF-8字节）: ')
        if value!=getpass.getpass('再次输入管理员密码: '):raise RuntimeError('两次密码不一致')
    if not 12<=len(value.encode())<=72 or value!=value.strip():raise RuntimeError('密码需12–72字节且首尾无空格')
    return value


def service_unit(mode):
    return f'''[Unit]
Description=FRP Portal {mode}
After=network-online.target postgresql.service
Wants=network-online.target
[Service]
User=frpportal
Group=frpportal
ExecStart={ROOT}/current/portal {mode} --config {CONFIG}/{mode}/{'control' if mode=='serve' else 'node'}.json --log-file /var/log/frp-portal/{mode}.log
Restart=always
RestartSec=5
TimeoutStopSec=10
KillMode=control-group
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/frp-portal/{mode} /var/log/frp-portal
UMask=0077
[Install]
WantedBy=multi-user.target
'''


class Installer:
    def __init__(self,args):
        self.a=args; self.bundle=Path(args.bundle).resolve(); self.stamp=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+secrets.token_hex(3)
        self.state=read_json(STATE) if STATE.exists() else {}
        self.public_url=('https://localhost:8443' if args.local_test else 'https://'+args.domain)
        self.private_url=f'http://127.0.0.1:{args.control_port}'
        self.control=CONFIG/'serve/control.json'; self.node=CONFIG/'node/node.json'
        self.old_current=None; self.backup=None; self.was_complete=bool(self.state.get('complete'))

    def save(self):write_json(STATE,self.state)

    def preflight(self):
        if platform.system()!='Linux' or os.geteuid()!=0:raise RuntimeError('请在Linux服务器使用sudo/root执行')
        release=dict(line.strip().split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        release={k:v.strip('"') for k,v in release.items()}
        if not os_supported(release):raise RuntimeError('自动安装仅支持Debian12、Ubuntu22.04/24.04；其他系统请手动部署')
        if platform.machine().lower() not in ('x86_64','aarch64','arm64'):raise RuntimeError('仅支持amd64/arm64')
        if not Path('/run/systemd/system').is_dir():raise RuntimeError('需要systemd宿主；普通容器请使用Compose方案')
        if not self.state and (self.control.exists() or self.node.exists() or any(Path('/etc/systemd/system/frp-portal-'+mode+'.service').exists() for mode in ('serve','node'))):
            raise RuntimeError('检测到非本一键安装器管理的平台配置/服务，拒绝接管；请按迁移手册处理')
        if not self.a.local_test:
            socket.getaddrinfo(self.a.domain,443); socket.getaddrinfo(self.a.node_domain,17100)
        if self.state and any(self.state.get(k)!=v for k,v in {'public_url':self.public_url,'node_domain':self.a.node_domain,'control_port':self.a.control_port,'postgres_port':self.a.postgres_port,'email':self.a.email}.items()):
            raise RuntimeError('已安装配置与本次域名/邮箱/端口不同，拒绝覆盖；请使用原参数重跑或按迁移手册操作')
        check_port(self.a.control_port,self.control.exists())
        if not self.bundle.joinpath('portal').is_file():raise RuntimeError('签名发布包缺少portal')
        if run(self.bundle/'portal','version').strip()!=f'portal {VERSION}; frp 0.71.1':raise RuntimeError('安装器与二进制版本不匹配')
        if not self.a.without_node:
            for name in ('frps','frpc'):
                if run(self.bundle/name,'--version').strip()!='0.71.1':raise RuntimeError('FRP版本不匹配')
        print('预检通过：操作系统、架构、DNS、配置一致性与程序版本。',flush=True)

    def dependencies(self):
        print('安装系统依赖：PostgreSQL、Caddy、OpenSSL、CA证书…',flush=True)
        env=os.environ.copy(); env['DEBIAN_FRONTEND']='noninteractive';env['NEEDRESTART_MODE']='l'
        run('apt-get','update',env=env)
        # Ubuntu 22.04's default sources may not provide Caddy. Use its documented
        # official stable repository, with a pinned signing-key download.
        # Use the vendor stable repository on all supported distributions.
        run('apt-get','install','-y','gnupg','ca-certificates','curl',env=env)
        with urllib.request.urlopen('https://dl.cloudsmith.io/public/caddy/stable/gpg.key',timeout=30) as response:key=response.read(65536)
        if hashlib.sha256(key).hexdigest()!='783dfee04b19e851a928cd87b34710213ebbe7628f98d9f34595ab83be578c00':
            raise RuntimeError('Caddy仓库签名密钥与已核实版本不符，请维护者重新核查，拒绝自动放行')
        result=subprocess.run(['gpg','--batch','--dearmor'],input=key,capture_output=True)
        if result.returncode:raise RuntimeError('Caddy签名密钥格式无效')
        atomic('/usr/share/keyrings/caddy-stable-archive-keyring.gpg',result.stdout,0o644)
        atomic('/etc/apt/sources.list.d/caddy-stable.list','deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main\n',0o644)
        run('apt-get','update',env=env)
        run('apt-get','install','-y','postgresql','postgresql-client','caddy','openssl','ca-certificates','curl',env=env)
        try:pwd.getpwnam('frpportal')
        except KeyError:run('useradd','--system','--home-dir','/var/lib/frp-portal','--shell','/usr/sbin/nologin','frpportal')
        self.identity=(pwd.getpwnam('frpportal').pw_uid,grp.getgrnam('frpportal').gr_gid)
        CONFIG.mkdir(mode=0o755,parents=True,exist_ok=True)
        for mode in ('serve','node'):
            directory=CONFIG/mode; directory.mkdir(exist_ok=True);os.chown(directory,0,self.identity[1]);os.chmod(directory,0o750)
            state=Path('/var/lib/frp-portal')/mode;state.mkdir(parents=True,exist_ok=True);os.chown(state,*self.identity);os.chmod(state,0o700)
        logs=Path('/var/log/frp-portal');logs.mkdir(exist_ok=True);os.chown(logs,*self.identity);os.chmod(logs,0o750)
        PUBLIC.mkdir(parents=True,exist_ok=True);os.chmod(PUBLIC,0o755)

    def backup_existing(self):
        if not self.control.exists():return
        backup=Path('/var/backups/frp-portal')/self.stamp;backup.mkdir(parents=True,mode=0o700)
        os.chmod(backup,0o700)
        shutil.copytree(CONFIG,backup/'config',dirs_exist_ok=True)
        with open(backup/'portal.dump','wb') as output:
            result=subprocess.run(['runuser','-u','postgres','--','pg_dump','-p',str(self.a.postgres_port),'-Fc','frp_portal'],stdout=output,stderr=subprocess.PIPE)
        if result.returncode:raise RuntimeError('升级前数据库备份失败，已停止升级')
        self.backup=backup
        print('配置与数据库升级前备份：'+str(backup),flush=True)

    def psql(self,sql,database='postgres'):
        return run('runuser','-u','postgres','--','psql','-p',str(self.a.postgres_port),'-d',database,'-X','-t','-A','-v','ON_ERROR_STOP=1',stdin=sql,sensitive=True).strip()

    def database(self):
        run('systemctl','start','postgresql')
        wait_for(lambda:self.psql('SELECT 1;')=='1',30)
        if not self.state:
            if self.psql("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='frp_portal') OR EXISTS(SELECT 1 FROM pg_database WHERE datname='frp_portal');")=='t':
                raise RuntimeError('检测到非本安装器创建的frp_portal数据库/角色，拒绝接管')
            self.state={'public_url':self.public_url,'node_domain':self.a.node_domain,'control_port':self.a.control_port,'postgres_port':self.a.postgres_port,'email':self.a.email,'db_password':secrets.token_hex(32),'complete':False}
            self.save()
        password=self.state['db_password']
        if not re.fullmatch('[0-9a-f]{64}',password):raise RuntimeError('本地安装状态中的数据库密码格式错误')
        if self.psql("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='frp_portal');")!='t':
            self.psql("CREATE ROLE frp_portal LOGIN PASSWORD '"+password+"';")
        if self.psql("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname='frp_portal');")!='t':
            self.psql('CREATE DATABASE frp_portal OWNER frp_portal;')

    def binaries(self):
        releases=ROOT/'releases';releases.mkdir(parents=True,exist_ok=True)
        target=releases/(VERSION+'-'+self.stamp);target.mkdir()
        for name in ('portal','frps','frpc'):
            shutil.copyfile(self.bundle/name,target/name);os.chmod(target/name,0o755)
        shutil.copytree(self.bundle/'third_party',target/'third_party')
        shutil.copyfile(self.bundle/'oneclick.py',target/'oneclick.py')
        current=ROOT/'current';self.old_current=os.readlink(current) if current.is_symlink() else None
        temp=ROOT/('.current-'+self.stamp);temp.symlink_to(target);os.replace(temp,current)
        self.target=target

    def control_config(self):
        if not self.control.exists():
            env=os.environ.copy();env['FRP_DATABASE_URL']=f'postgres://frp_portal:{self.state["db_password"]}@127.0.0.1:{self.a.postgres_port}/frp_portal?sslmode=disable'
            run(ROOT/'current/portal','init','--dir',self.control.parent,'--public-url',self.public_url,env=env,sensitive=True)
            c=read_json(self.control);c['listen']=f'127.0.0.1:{self.a.control_port}';c['reverse_proxy_tls']=True
            write_json(self.control,c,0o640,(0,self.identity[1]))
        run(ROOT/'current/portal','migrate','--config',self.control,sensitive=True)
        self.state['schema_version']=1;self.save()
        atomic('/etc/systemd/system/frp-portal-serve.service',service_unit('serve'),0o644)
        run('systemctl','daemon-reload');run('systemctl','enable','--now','frp-portal-serve');run('systemctl','restart','frp-portal-serve')
        wait_for(lambda:api(self.private_url,'/healthz'))

    def admin(self):
        if self.was_complete and (self.a.without_node or self.node.exists()):return
        password=get_password(self.a.admin_password_file)
        if not self.state.get('admin_created'):
            output=run(ROOT/'current/portal','bootstrap','--config',self.control,'--email',self.a.email,stdin=password+'\n',sensitive=True)
            match=re.search(r'otpauth://\S+',output)
            if not match:raise RuntimeError('初始化输出不包含TOTP信息，请检查数据库状态')
            uri=match.group(0);secret=urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)['secret'][0]
            self.state['admin_created']=True;self.save()
            print('\n管理员TOTP密钥（请立即录入认证器并离线保存，只显示这一次）：'+secret+'\n'+uri+'\n',flush=True)
            otp=totp(secret)
        else:otp=getpass.getpass('恢复未完成安装：输入管理员当前6位动态验证码: ')
        token=api(self.private_url,'/api/login',{'email':self.a.email,'password':password,'otp':otp})['token']
        if not self.a.without_node and not self.node.exists():
            info=api(self.private_url,'/api/admin/nodes',{'name':'默认节点','host':self.a.node_domain,'control_start':17100,'control_end':17199,'port_start':20100,'port_end':20199},token,(password,otp))
            c=read_json(self.control)
            node={'control_url':self.public_url,'node_id':info['node_id'],'credential':info['credential'],'verify_key':info['verify_key'],'frp_path':str(ROOT/'current/frps'),'tls_cert':str(CONFIG/'node/node.crt'),'tls_key':str(CONFIG/'node/node.key'),'state_dir':'/var/lib/frp-portal/node'}
            if self.a.local_test:node['ca_file']=str(CONFIG/'node/control-ca.pem')
            write_json(self.node,node,0o640,(0,self.identity[1]))
            api(self.private_url,'/api/admin/plans',{'name':'基础套餐','node_id':info['node_id'],'max_devices':1,'max_tunnels':3,'tunnel_kibps':1024,'price_cents':0},token,(password,otp))
        api(self.private_url,'/api/logout',{},token)

    def certificates(self):
        pki=CONFIG/'pki';pki.mkdir(mode=0o700,exist_ok=True);os.chmod(pki,0o700)
        ca_key,ca_crt=pki/'node-ca.key',pki/'node-ca.pem'
        if not ca_key.exists() and not ca_crt.exists():
            run('openssl','req','-x509','-newkey','rsa:3072','-nodes','-sha256','-days','3650','-subj','/CN=FRP Portal Node CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',ca_key,'-out',ca_crt,sensitive=True)
            os.chmod(ca_key,0o600)
        if not ca_key.exists() or not ca_crt.exists():raise RuntimeError('节点CA状态不完整，拒绝自动替换信任根')
        key,crt=CONFIG/'node/node.key',CONFIG/'node/node.crt'
        if key.exists()!=crt.exists():raise RuntimeError('节点证书/私钥不完整，拒绝自动覆盖')
        if not key.exists():
            csr=pki/'node.csr';extension=pki/'node.ext'
            atomic(extension,'subjectAltName=DNS:'+self.a.node_domain+'\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
            run('openssl','req','-new','-newkey','rsa:3072','-nodes','-subj','/CN='+self.a.node_domain,'-keyout',key,'-out',csr,sensitive=True)
            run('openssl','x509','-req','-sha256','-days','365','-in',csr,'-CA',ca_crt,'-CAkey',ca_key,'-CAcreateserial','-extfile',extension,'-out',crt,sensitive=True)
        run('openssl','verify','-CAfile',ca_crt,crt)
        run('openssl','x509','-in',crt,'-checkend','86400','-noout')
        for path in (key,crt):os.chown(path,0,self.identity[1]);os.chmod(path,0o640)
        atomic(PUBLIC/'node-ca.pem',ca_crt.read_bytes(),0o644)

    def caddy(self):
        root=Path('/etc/caddy/Caddyfile');include='import /etc/caddy/frp-portal.d/*.caddy'
        current=root.read_text() if root.exists() else ''
        if include not in current:
            if not self.a.local_test and self.a.domain in current:raise RuntimeError('已有Caddy主文件包含此域名，请人工整合，避免覆盖现有站点')
            if root.exists():shutil.copyfile(root,root.with_name('Caddyfile.before-frp-'+self.stamp))
            atomic(root,current+'\n'+include+'\n',0o644)
        site=f'''{self.public_url} {{
 {'tls internal' if self.a.local_test else ''}
 handle /downloads/node-ca.pem {{
  root * {PUBLIC}
  rewrite * /node-ca.pem
  file_server
 }}
 handle {{
  reverse_proxy 127.0.0.1:{self.a.control_port}
 }}
}}
'''
        sitefile=Path('/etc/caddy/frp-portal.d/portal.caddy');self.old_site=sitefile.read_bytes() if sitefile.exists() else None
        atomic(sitefile,site,0o644)
        run('caddy','validate','--config',root,'--adapter','caddyfile')
        run('systemctl','enable','--now','caddy');run('systemctl','reload','caddy')
        ca=None
        if self.a.local_test:
            ca='/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt'
            wait_for(lambda:Path(ca).exists(),30)
            atomic(CONFIG/'node/control-ca.pem',Path(ca).read_bytes(),0o640,(0,self.identity[1]))
        wait_for(lambda:api(self.public_url,'/healthz',ca=ca),180)

    def start_node(self):
        if self.a.without_node:return
        atomic('/etc/systemd/system/frp-portal-node.service',service_unit('node'),0o644)
        run('systemctl','daemon-reload');run('systemctl','enable','--now','frp-portal-node');run('systemctl','restart','frp-portal-node')
        nodeid=read_json(self.node)['node_id']
        if not re.fullmatch('[A-Z2-7]{32}',nodeid):raise RuntimeError('节点ID格式错误')
        wait_for(lambda:self.psql("SELECT (last_seen>clock_timestamp()-interval '10 seconds') FROM nodes WHERE id='"+nodeid+"';",'frp_portal')=='t',30)

    def rollback(self):
        if self.old_current:
            temp=ROOT/('.rollback-'+self.stamp);temp.symlink_to(self.old_current);os.replace(temp,ROOT/'current')
            for mode in ('serve','node'):
                subprocess.run(['systemctl','restart','frp-portal-'+mode],capture_output=True)
            print('已切回旧程序；数据库不自动倒退，备份路径：'+str(self.backup),file=sys.stderr)
        if hasattr(self,'old_site'):
            site=Path('/etc/caddy/frp-portal.d/portal.caddy')
            if self.old_site is None:
                with contextlib.suppress(FileNotFoundError):site.unlink()
            else:atomic(site,self.old_site,0o644)
            subprocess.run(['systemctl','reload','caddy'],capture_output=True)

    def install(self):
        self.preflight()
        if self.a.check:return
        self.dependencies();self.database();self.backup_existing()
        try:
            self.binaries();self.control_config();self.admin();self.certificates();self.caddy();self.start_node()
            self.state.update(complete=True,version=VERSION);self.save()
            print(f'\n部署完成：{self.public_url}\n管理员：{self.a.email}\n节点CA：{self.public_url}/downloads/node-ca.pem\n配置：{CONFIG}\n日志：/var/log/frp-portal\n请放行80/443 TCP、17100–17199 TCP、20100–20199 TCP/UDP；脚本不会改防火墙。\n节点证书365天到期，需按手册维护续签。',flush=True)
        except Exception:
            self.rollback();raise


def main():
    parser=argparse.ArgumentParser(description='FRP Portal Linux一键安装（Debian12 / Ubuntu22.04,24.04）')
    parser.add_argument('--bundle',default=str(Path(__file__).resolve().parent))
    parser.add_argument('--domain',type=domain)
    parser.add_argument('--node-domain',type=domain)
    parser.add_argument('--email',required=True)
    parser.add_argument('--control-port',type=int,default=8080)
    parser.add_argument('--postgres-port',type=int,default=5432)
    parser.add_argument('--admin-password-file')
    parser.add_argument('--without-node',action='store_true')
    parser.add_argument('--local-test',action='store_true',help='仅CI/隔离主机测试，使用localhost:8443及本地CA')
    parser.add_argument('--check',action='store_true',help='只检查，不安装/修改系统')
    args=parser.parse_args()
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',args.email):parser.error('管理员邮箱格式错误')
    if not 1024<=args.control_port<=65535 or not 1<=args.postgres_port<=65535:parser.error('端口范围无效')
    if args.local_test:args.domain=args.node_domain='localhost'
    elif not args.domain or not args.node_domain:parser.error('需要--domain和--node-domain')
    if platform.system()!='Linux' or os.geteuid()!=0:raise RuntimeError('请在Linux服务器使用sudo执行')
    with open('/run/lock/frp-portal-install.lock','w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('另一个安装任务正在运行') from None
        Installer(args).install()


if __name__=='__main__':
    try:main()
    except Exception as error:print('安装失败：'+str(error)+'\n已保留配置和数据库。修正问题后用相同参数重试，勿删除账目。',file=sys.stderr);sys.exit(1)
