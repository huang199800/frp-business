"""Real PostgreSQL + portal + upstream frpc/frps TCP/UDP acceptance test.
Use a disposable database. No business payload is retained beyond 'echo'.
"""
import argparse, base64, concurrent.futures, hashlib, hmac, json, os, pathlib, socket
import struct, subprocess, threading, time, urllib.request, urllib.error, uuid
from datetime import datetime, timezone, timedelta

p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--frp-dir',required=True)
p.add_argument('--work-dir',required=True);p.add_argument('--database-url',required=True);args=p.parse_args()
binary=str(pathlib.Path(args.binary).resolve());frp=pathlib.Path(args.frp_dir).resolve();work=pathlib.Path(args.work_dir).resolve();work.mkdir(parents=True,exist_ok=True)
suffix='.exe' if os.name=='nt' else '';url='http://127.0.0.1:18080';processes=[];results=[]
def check(name,value=True):
 if not value:raise AssertionError(name)
 results.append({'test':name,'passed':True});print('PASS',name,flush=True)
def run(cmd,stdin=None,env=None):
 return subprocess.run(cmd,input=stdin,text=True,encoding='utf-8',env=env,check=True,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0).stdout
def start(name,cmd):
 log=open(work/(name+'.log'),'w',encoding='utf-8');pr=subprocess.Popen(cmd,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0);processes.append((pr,log));return pr
def stop(pr):
 if pr.poll() is None:pr.terminate();pr.wait(timeout=10)
def api(path,body=None,token='',admin=False,method=None):
 headers={'Content-Type':'application/json'}
 if token:headers['Authorization']='Bearer '+token
 if admin:headers.update({'X-Admin-Password':password,'X-Admin-OTP':totp(secret)})
 data=json.dumps(body).encode() if body is not None else None
 req=urllib.request.Request(url+path,data=data,headers=headers,method=method or ('POST' if data is not None else 'GET'))
 try:
  with urllib.request.urlopen(req,timeout=8) as r:return json.load(r)
 except urllib.error.HTTPError as e:
  detail=e.read().decode();raise RuntimeError(f'HTTP {e.code} {detail}') from e
def totp(s):
 key=base64.b32decode(s);digest=hmac.new(key,struct.pack('>Q',int(time.time())//30),hashlib.sha1).digest();o=digest[-1]&15;return f'{(struct.unpack(">I",digest[o:o+4])[0]&0x7fffffff)%1000000:06d}'
def wait(fn,timeout=15):
 end=time.monotonic()+timeout;last=None
 while time.monotonic()<end:
  try:
   v=fn()
   if v:return v
  except Exception as e:last=e
  time.sleep(.2)
 raise AssertionError('condition timeout: '+str(last))
def tcp_echo(port):
 with socket.create_connection(('127.0.0.1',port),timeout=.8) as s:s.sendall(b'echo');return s.recv(4)==b'echo'
def udp_echo(port):
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:s.settimeout(.8);s.sendto(b'echo',('127.0.0.1',port));return s.recv(4)==b'echo'
def closed(port):
 try:
  with socket.create_connection(('127.0.0.1',port),timeout=.3):return False
 except OSError:return True
def no_echo(port):
 try:return not tcp_echo(port)
 except OSError:return True
def stream_closed(s):
 try:s.sendall(b'x');return s.recv(1)==b''
 except OSError:return True
def tcp_server():
 listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();port=listener.getsockname()[1]
 def connection(s):
  with s:
   while True:
    try:
     b=s.recv(65535)
     if not b:return
     s.sendall(b)
    except OSError:return
 def loop():
  while True:
   try:s,_=listener.accept();threading.Thread(target=connection,args=(s,),daemon=True).start()
   except OSError:return
 threading.Thread(target=loop,daemon=True).start();return port,listener
def udp_server():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 def loop():
  while True:
   try:b,a=s.recvfrom(65535);s.sendto(b,a)
   except OSError:return
 threading.Thread(target=loop,daemon=True).start();return port,s

try:
 env=os.environ.copy();env['FRP_DATABASE_URL']=args.database_url
 run([binary,'init','--dir',str(work),'--public-url',url],env=env)
 control_path=work/'control.json';c=json.loads(control_path.read_text());c.update(listen='127.0.0.1:18080',dev_http=True);control_path.write_text(json.dumps(c))
 password='test-'+uuid.uuid4().hex;email='admin-'+uuid.uuid4().hex+'@test.invalid'
 output=run([binary,'bootstrap','--config',str(control_path),'--email',email],password+'\n');secret=output.split('secret=')[1].split('&')[0]
 control=start('control',[binary,'serve','--config',str(control_path)]);wait(lambda:api('/healthz'))
 admin_token=api('/api/login',{'email':email,'password':password,'otp':totp(secret)})['token']
 user_email=uuid.uuid4().hex+'@test.invalid';api('/api/register',{'email':user_email,'password':password});user_token=api('/api/login',{'email':user_email,'password':password})['token'];user_id=api('/api/me',token=user_token)['id']
 n=api('/api/admin/nodes',{'name':'acceptance','host':'localhost','control_start':17100,'control_end':17199,'port_start':20100,'port_end':20199},admin_token,True)
 plan=api('/api/admin/plans',{'name':'acceptance','node_id':n['node_id'],'max_devices':2,'max_tunnels':4,'tunnel_kibps':64,'price_cents':100},admin_token,True)['id']
 def card(seconds=120):return api('/api/admin/cards',{'name':'e2e','note':'test','plan_id':plan,'seconds':seconds,'count':1,'deadline':(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()},admin_token,True)['codes'][0]
 code=card();request_id=str(uuid.uuid4());r=api('/api/redeem',{'code':code,'request_id':request_id},user_token);retry=api('/api/redeem',{'code':code,'request_id':request_id},user_token);check('response-loss retry grants no duplicate time',r['after_at']==retry['after_at'] and retry['repeated'])
 before=datetime.fromisoformat(r['after_at'].replace('Z','+00:00'));r2=api('/api/redeem',{'code':card(60),'request_id':str(uuid.uuid4())},user_token);check('active same-plan renewal',datetime.fromisoformat(r2['after_at'].replace('Z','+00:00'))==before+timedelta(seconds=60))
 run([binary,'dev-cert','--dir',str(work),'--host','localhost'])
 node_config={'control_url':url,'dev_http':True,'node_id':n['node_id'],'credential':n['credential'],'verify_key':n['verify_key'],'frp_path':str(frp/('frps'+suffix)),'tls_cert':str(work/'node.crt'),'tls_key':str(work/'node.key'),'state_dir':str(work/'node-state')}
 node_path=work/'node.json';node_path.write_text(json.dumps(node_config));node=start('node',[binary,'node','--config',str(node_path)])
 binding=api('/api/bind-codes',{'name':'test-device'},user_token)['code'];agent_path=work/'agent.json';agent_path.write_text(json.dumps({'control_url':url,'dev_http':True,'ca_file':str(work/'node.crt'),'state_dir':str(work/'agent-state'),'frp_path':str(frp/('frpc'+suffix))}))
 run([binary,'bind','--config',str(agent_path)],binding+'\n');device=json.loads(agent_path.read_text())['device_id'];check('CLI one-time device binding')
 try:api('/api/device/bind',{'code':binding});raise AssertionError('bind code reused')
 except RuntimeError as e:check('binding code cannot be replayed','HTTP 400' in str(e))
 tcp_local,tcp_sock=tcp_server();udp_local,udp_sock=udp_server()
 t=api('/api/tunnels',{'name':'echo','device_id':device,'protocol':'tcp','local_host':'127.0.0.1','local_port':tcp_local,'remote_port':0},user_token)
 u=api('/api/tunnels',{'name':'echo UDP','device_id':device,'protocol':'udp','local_host':'127.0.0.1','local_port':udp_local,'remote_port':0},user_token)
 agent=start('agent',[binary,'agent','--config',str(agent_path)]);wait(lambda:tcp_echo(t['remote_port']),25);check('actual upstream TCP forwarding');wait(lambda:udp_echo(u['remote_port']));check('actual upstream UDP forwarding');run([binary,'diagnose','--config',str(agent_path)]);check('CLI diagnostics')
 # From now on use an unmodified raw frpc. Enforcement must hold without a cooperative Agent.
 raw_config=work/'raw.toml';raw_config.write_bytes((work/'agent-state'/'frpc.toml').read_bytes());stop(agent)
 bad=work/'forged.toml';bad.write_text(raw_config.read_text().replace('remotePort = '+str(t['remote_port']),'remotePort = 20199'))
 evil=start('forged-frpc',[str(frp/('frpc'+suffix)),'-c',str(bad)]);time.sleep(3);check('modified frpc cannot obtain unpurchased port',closed(20199));stop(evil)
 raw=start('raw-frpc',[str(frp/('frpc'+suffix)),'-c',str(raw_config)]);wait(lambda:tcp_echo(t['remote_port']));check('raw frpc operates only purchased tunnel')
 payload=b'a'*(256*1024);started=time.monotonic()
 with socket.create_connection(('127.0.0.1',t['remote_port']),timeout=15) as speed:
  speed.sendall(payload);received=bytearray()
  while len(received)<len(payload):
   part=speed.recv(len(payload)-len(received))
   if not part:raise AssertionError('bandwidth transfer interrupted')
   received.extend(part)
 transfer_seconds=time.monotonic()-started;check('server enforces purchased 64 KiB/s despite raw frpc lacking client limit',received==payload and transfer_seconds>3)
 outsider=uuid.uuid4().hex+'@test.invalid';api('/api/register',{'email':outsider,'password':password});other_token=api('/api/login',{'email':outsider,'password':password})['token']
 try:api('/api/tunnels/'+t['id'],token=other_token,method='DELETE');raise AssertionError('cross-account deletion succeeded')
 except RuntimeError as e:check('cross-tenant mutation denied','HTTP 404' in str(e))
 try:api('/api/admin/overview',token=other_token);raise AssertionError('admin visible')
 except RuntimeError as e:check('user cannot access admin','HTTP 403' in str(e))
 # Force expiration through an audited adjustment; retain raw frpc and an active stream.
 held=socket.create_connection(('127.0.0.1',t['remote_port']),timeout=1);held.sendall(b'ok');check('established TCP stream before expiry',held.recv(2)==b'ok');held.settimeout(.5)
 entitlement=api('/api/me',token=user_token)['entitlements'][0];expiry=datetime.fromisoformat(entitlement['expires_at'].replace('Z','+00:00'));delta=int((expiry-datetime.now(timezone.utc)).total_seconds())
 api(f'/api/admin/users/{user_id}/adjust',{'seconds':-delta+3,'reason':'e2e expiration verification'},admin_token,True)
 wait(lambda:closed(t['remote_port']),18);check('expiry stops new TCP connections');wait(lambda:stream_closed(held),3);held.close();check('expiry closes existing TCP stream')
 try:udp_echo(u['remote_port']);raise AssertionError('UDP still forwarding')
 except (socket.timeout,ConnectionError,OSError):check('expiry stops UDP forwarding')
 api('/api/redeem',{'code':card(120),'request_id':str(uuid.uuid4())},user_token);wait(lambda:tcp_echo(t['remote_port']),30);check('redeeming after expiry restores raw frpc forwarding')
 held=socket.create_connection(('127.0.0.1',t['remote_port']),timeout=1);held.sendall(b'ok');held.recv(2);held.settimeout(.5)
 api(f'/api/admin/users/{user_id}/state',{'disabled':True},admin_token,True);wait(lambda:closed(t['remote_port']),18);wait(lambda:stream_closed(held),3);held.close();check('account ban closes existing and new TCP connections')
 api(f'/api/admin/users/{user_id}/state',{'disabled':False},admin_token,True);wait(lambda:tcp_echo(t['remote_port']),30)
 # Node must enforce its own finite lease even with a modified/raw client.
 held=socket.create_connection(('127.0.0.1',t['remote_port']),timeout=1);held.sendall(b'ok');held.recv(2);held.settimeout(.5);start_time=time.monotonic();stop(control)
 wait(lambda:no_echo(t['remote_port']),3);check('control outage refuses fresh TCP authorization before lease expiration')
 wait(lambda:closed(t['remote_port']),18);wait(lambda:stream_closed(held),3);elapsed=time.monotonic()-start_time;held.close();check('control outage closes existing/new forwarding within finite lease',elapsed<17)
 control=start('control-restored',[binary,'serve','--config',str(control_path)]);wait(lambda:api('/healthz'));wait(lambda:tcp_echo(t['remote_port']),30);check('control recovery reconciles and restores forwarding')
 stop(node);wait(lambda:closed(t['remote_port']),3);check('node manager termination cleans up isolated frps')
 node=start('node-restored',[binary,'node','--config',str(node_path)]);wait(lambda:tcp_echo(t['remote_port']),30);check('node restart obtains fresh signed authorization')
 api(f'/api/devices/{device}/revoke',{},user_token);wait(lambda:closed(t['remote_port']),18);check('device credential revocation stops forwarding')
 print(json.dumps({'status':'passed','tests':len(results),'control_outage_seconds':round(elapsed,3)},ensure_ascii=False),flush=True)
finally:
 for pr,log in reversed(processes):
  try:stop(pr)
  except Exception:pass
  log.close()
 (work/'results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
