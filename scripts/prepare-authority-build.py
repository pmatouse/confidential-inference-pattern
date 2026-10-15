#!/usr/bin/env python3
"""Create a public-only authority build context; never include deployment state."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def prepare(wheels, output):
    component = ROOT / 'components/confidential-storage-authority'
    pins = json.loads((component / 'runtime-wheels.json').read_text())
    entries = {}
    for name, digest in pins.items():
        data = (wheels / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('wheel hash mismatch')
        entries['wheels/' + name] = data
    for path in sorted(component.glob('*.py')):
        if not path.name.startswith(('test_', 'generate_')) and path.name != 'publication_fixture.py':
            entries[str(path.relative_to(ROOT))] = path.read_bytes()
    for name in ('runtime-requirements.txt',):
        entries[str((component / name).relative_to(ROOT))] = (component / name).read_bytes()
    for path in sorted((ROOT / 'components/confidential-storage-guest/profiles').glob('*.json')):
        entries[str(path.relative_to(ROOT))] = path.read_bytes()
    enrollment = ROOT / 'components/inference-release/enroll.py'
    entries[str(enrollment.relative_to(ROOT))] = enrollment.read_bytes()
    entries['Containerfile'] = (component / 'Containerfile').read_bytes()
    entries['LICENSE'] = (ROOT / 'LICENSE').read_bytes()
    with output.open('xb') as stream, tarfile.open(fileobj=stream, mode='w:gz') as tar:
        for name, data in sorted(entries.items()):
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = 0o644
            tar.addfile(entry, io.BytesIO(data))
    report = {'schemaVersion': 1, 'purpose': 'public-authority-build-context',
              'archiveSha256': hashlib.sha256(output.read_bytes()).hexdigest(),
              'files': {n: hashlib.sha256(data).hexdigest() for n, data in sorted(entries.items())}}
    output.with_suffix('.inputs.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--wheels', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    r = prepare(a.wheels, a.output)
    print(json.dumps({'archiveSha256': r['archiveSha256'], 'files': len(r['files'])}))
