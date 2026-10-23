"""Fetch only pinned upstream assets, validate SHA-256, reject unsafe archive members.
Requires Python 3.12+. No credentials or account state involved.
"""
import argparse,hashlib,json,pathlib,tarfile,urllib.request,zipfile
p=argparse.ArgumentParser();p.add_argument('--os',choices=['windows','linux'],required=True);p.add_argument('--arch',choices=['amd64','arm64'],required=True);p.add_argument('--out',required=True);a=p.parse_args()
lock=json.loads((pathlib.Path(__file__).resolve().parents[1]/'third_party/frp-lock.json').read_text());ext='.zip' if a.os=='windows' else '.tar.gz';name=f'frp_{lock["version"]}_{a.os}_{a.arch}{ext}'
if name not in lock['assets']:raise SystemExit('Unsupported build target')
asset=lock['assets'][name];out=pathlib.Path(a.out).resolve();out.mkdir(parents=True,exist_ok=True);archive=out/name
if not archive.exists():urllib.request.urlretrieve(asset['url'],archive)
if hashlib.sha256(archive.read_bytes()).hexdigest()!=asset['sha256']:raise SystemExit('SHA256 mismatch; refusing extraction')
if ext=='.zip':
 with zipfile.ZipFile(archive) as z:
  for member in z.infolist():
   target=(out/member.filename).resolve()
   if not target.is_relative_to(out) or (member.external_attr>>16)&0o170000==0o120000:raise SystemExit('Unsafe archive member')
  z.extractall(out)
else:
 with tarfile.open(archive) as t:t.extractall(out,filter='data')
print(out/name.removesuffix(ext))
