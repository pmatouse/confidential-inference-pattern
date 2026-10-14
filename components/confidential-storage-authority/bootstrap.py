#!/usr/bin/env python3
"""Explicit trusted first-use bootstrap. Normal server restart must never call this."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid
from contextlib import closing
from authority import Authority

MARKER='bootstrap.json'

def check_directory(path):
    st=path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode & 0o077:
        raise ValueError('authority state must be an owned private directory')

def fsync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def verify(path, identity):
    check_directory(path)
    marker=path/MARKER;db=path/'authority.db'
    for f in (marker,db):
        st=f.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode & 0o077:
            raise ValueError('invalid retained authority file')
    record=json.loads(marker.read_text())
    if record.get('installation')!=identity or record.get('schemaVersion')!=1 or record.get('state')!='Ready':
        raise ValueError('authority bootstrap identity mismatch or incomplete bootstrap')
    # Read-only validation: never silently reconstruct a missing database.
    with closing(sqlite3.connect(db.as_uri()+'?mode=ro',uri=True)) as c:
        if c.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('authority database corrupt')
        tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'volumes','events','operations','initialization_sources'} <= tables:
            raise ValueError('authority schema missing')
    return record

def verify_server(path, state, identity):
    """Normal restart validates retained history before Authority can open it."""
    state=Path(state).absolute()
    verify(state, identity)
    config=json.loads(Path(path).read_text())
    if Path(config['database']).absolute() != state/'authority.db':
        raise ValueError('server database differs from verified retained history')

def bootstrap(path,identity):
    path=Path(path).absolute()
    if not identity or len(identity)>128:raise ValueError('stable installation identity required')
    if path.exists():return verify(path,identity)
    os.umask(0o077)
    # mkdir is the exclusive creation fence. A crash leaves partial state that
    # must be investigated; a retry cannot mistake it for a fresh empty volume.
    path.mkdir(mode=0o700)
    fsync_dir(path.parent)
    record={'schemaVersion':1,'installation':identity,'bootstrapId':str(uuid.uuid4()),'state':'Ready'}
    Authority(path/'authority.db')
    with (path/MARKER).open('x') as f:
        json.dump(record,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
    fsync_dir(path)
    return verify(path,identity)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state',type=Path,required=True)
    p.add_argument('--installation',required=True)
    a=p.parse_args()
    print(json.dumps(bootstrap(a.state,a.installation),sort_keys=True))
