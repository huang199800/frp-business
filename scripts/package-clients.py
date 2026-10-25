"""Append signed-manifest-ready Windows/Linux client archives to server release."""
import argparse
import hashlib
from pathlib import Path
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('--out', default='release')
parser.add_argument('--version', default='0.2.0')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
out = Path(args.out).resolve()
manifest = out / 'SHA256SUMS'
if not manifest.exists(): raise SystemExit('先运行 package-linux.py')
lines = manifest.read_text(encoding='ascii').splitlines(keepends=True)
for system, arch in (('linux', 'amd64'), ('linux', 'arm64'), ('windows', 'amd64')):
    extension = '.exe' if system == 'windows' else ''
    name = f'frp-portal-client-{args.version}-{system}-{arch}.zip'
    files = {
        'portal' + extension: root / 'dist' / f'{system}-{arch}' / ('portal' + extension),
        'frpc' + extension: root / 'dist' / f'{system}-{arch}' / ('frpc' + extension),
        'README.md': root / 'docs' / '客户端快速上手.md',
        'third_party/NOTICE.md': root / 'third_party' / 'NOTICE.md',
        'third_party/frp-LICENSE': root / 'third_party' / 'frp-LICENSE',
    }
    script = 'install-client-windows.ps1' if system == 'windows' else 'install-client-linux.sh'
    files['scripts/' + script] = root / 'scripts' / script
    for license_file in (root / 'third_party/licenses').rglob('*'):
        if license_file.is_file(): files[license_file.relative_to(root).as_posix()] = license_file
    with zipfile.ZipFile(out / name, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for target, source in sorted(files.items()):
            info = zipfile.ZipInfo(target, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100755 if target.startswith(('portal', 'frpc')) or target.endswith('.sh') else 0o100644) << 16
            archive.writestr(info, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    lines.append(hashlib.sha256((out / name).read_bytes()).hexdigest() + '  ' + name + '\n')
manifest.write_text(''.join(lines), encoding='ascii')
print(out)
