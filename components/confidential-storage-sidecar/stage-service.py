#!/usr/bin/env python3
"""Stage add-on Rust sources and unchanged pinned CoCo protocol definitions."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

PIN = '0ab1fb1be6e46293f29600085f929ae035ca3739'
LOCK = '88ba3f0378dbb6031b19ffe1a29172ebea42871c16c2ae7f8822c90b78658299'
ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = ('confidential-storage-guest', 'confidential-storage-client',
              'confidential-storage-kbs', 'confidential-storage-service')


def stage(source, output):
    if output.exists():
        raise ValueError('use a new build directory')
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != PIN:
        raise ValueError('unexpected protocol source revision')
    archive = subprocess.check_output(['git', '-C', str(source), 'archive', PIN])
    upstream = output / 'upstream'
    upstream.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(upstream, filter='data')
    if hashlib.sha256((upstream / 'Cargo.lock').read_bytes()).hexdigest() != LOCK:
        raise ValueError('unexpected upstream lock')
    # Do not patch upstream. Only the protos crate is a compiled dependency;
    # keeping its workspace intact preserves inherited dependency versions.
    for name in COMPONENTS:
        shutil.copytree(ROOT / 'components' / name, output / 'components' / name,
                        ignore=shutil.ignore_patterns('target', '__pycache__', '*.pyc'))
    record = {'schemaVersion': 1, 'protocolRepository': 'https://github.com/manuelh-dev/guest-components',
              'protocolCommit': PIN, 'upstreamModified': False,
              'compilerImage': 'rust@sha256:4ec71e955e6c08aeb238885083222ddff79d82eb87654a96c76e38e94da1a53b',
              'files': {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
                        for top in (output / 'components', upstream / 'protos')
                        for p in sorted(top.rglob('*')) if p.is_file()}}
    (output / 'source-lock.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    return record


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--upstream', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    record = stage(a.upstream, a.output)
    print(json.dumps({k: v for k, v in record.items() if k != 'files'}))
