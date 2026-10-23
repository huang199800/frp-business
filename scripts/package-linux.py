"""Build deterministic, self-contained Linux installer bundles (sign separately offline)."""
import argparse
import hashlib
import io
import gzip
from pathlib import Path
import tarfile

p=argparse.ArgumentParser();p.add_argument('--out',default='release');p.add_argument('--version',default='0.1.1');a=p.parse_args()
root=Path(__file__).resolve().parents[1];out=Path(a.out).resolve();out.mkdir(parents=True,exist_ok=True);manifest=[]
for arch in ('amd64','arm64'):
    name=f'frp-portal-{a.version}-linux-{arch}.tar.gz';archive=out/name
    files={n:root/'dist'/('linux-'+arch)/n for n in ('portal','frps','frpc')}
    files['oneclick.py']=root/'scripts/oneclick.py'
    files['README.md']=root/'docs/Linux一键部署.md'
    for f in (root/'third_party').rglob('*'):
        if f.is_file():files[f.relative_to(root).as_posix()]=f
    with archive.open('wb') as raw,gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w') as tar:
        for target,source in sorted(files.items()):
            content=source.read_bytes();entry=tarfile.TarInfo(target);entry.size=len(content);entry.mode=0o755 if target in ('portal','frps','frpc') else 0o644;entry.mtime=0
            tar.addfile(entry,io.BytesIO(content))
    manifest.append(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+name+'\n')
(out/'SHA256SUMS').write_text(''.join(manifest),encoding='ascii');print(out)
