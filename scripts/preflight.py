"""Read-only config/architecture/port checks. Run before installing service."""
import argparse,json,platform,socket,pathlib,sys
p=argparse.ArgumentParser();p.add_argument('--mode',choices=['serve','node','agent'],required=True);p.add_argument('--config',required=True);a=p.parse_args();c=json.loads(pathlib.Path(a.config).read_text(encoding='utf-8-sig'))
if platform.machine().lower() not in ['amd64','x86_64','aarch64','arm64']:sys.exit('Unsupported architecture')
if a.mode=='serve':
 host,port=c.get('listen','127.0.0.1:8080').rsplit(':',1)
 with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET) as s:s.bind((host.strip('[]'),int(port)))
 if not c.get('database_url') or not c.get('signing_seed'):sys.exit('Database URL and signing seed required')
else:
 if not pathlib.Path(c.get('frp_path','missing')).is_file():sys.exit('FRP binary missing')
 if a.mode=='node':
  for k in ['tls_cert','tls_key']:
   if not pathlib.Path(c.get(k,'missing')).is_file():sys.exit(k+' missing')
 else:
  if not pathlib.Path(c.get('ca_file','missing')).is_file():sys.exit('CA file missing')
print('Preflight passed. Node control/business pools also need external firewall/port checks; allocation detects bind failures in frps logs.')
