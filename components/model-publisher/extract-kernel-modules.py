#!/usr/bin/env python3
"""Extract only approved module bytes from a hash-pinned signed RPM; never install it."""
import ctypes
import hashlib
import json
import lzma
from pathlib import Path
import struct
import sys

rpm, lockfile, destination=map(Path,sys.argv[1:])
lock=json.loads(lockfile.read_text());raw=rpm.read_bytes()
assert hashlib.sha256(raw).hexdigest()==lock['kernelModulesRPM']['sha256'],'RPM hash mismatch'
def header_end(offset):
    assert raw[offset:offset+4]==b'\x8e\xad\xe8\x01','invalid RPM header'
    count,size=struct.unpack('>II',raw[offset+8:offset+16])
    return offset+16+count*16+size
end=header_end(96);start=header_end((end+7)&~7);payload=raw[start:]
if payload.startswith(b'\xfd7zXZ'):
    data=lzma.decompress(payload)
else:
    assert payload.startswith(b'\x28\xb5\x2f\xfd'),'unsupported RPM compression'
    z=ctypes.CDLL('libzstd.so.1');z.ZSTD_decompressBound.argtypes=[ctypes.c_void_p,ctypes.c_size_t];z.ZSTD_decompressBound.restype=ctypes.c_ulonglong
    size=z.ZSTD_decompressBound(payload,len(payload));assert 0<size<1024**3,'unbounded RPM payload'
    buf=ctypes.create_string_buffer(size);z.ZSTD_decompress.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t];z.ZSTD_decompress.restype=ctypes.c_size_t
    actual=z.ZSTD_decompress(buf,size,payload,len(payload));assert actual<=size,'RPM decompression failed'
    data=buf.raw[:actual]
destination.mkdir(parents=True,exist_ok=True);offset=0;found=set()
while offset+110<=len(data):
    head=data[offset:offset+110];assert head[:6] in (b'070701',b'070702'),'invalid cpio'
    fields=[int(head[i:i+8],16) for i in range(6,110,8)]
    ne=offset+110+fields[11];name=data[offset+110:ne-1].decode();start=(ne+3)&~3;end=start+fields[6];offset=(end+3)&~3
    assert end<=len(data),'truncated RPM'
    if name=='TRAILER!!!':break
    for module,digest in lock['modules'].items():
        if name.endswith('/'+module+'.ko.xz'):
            body=data[start:end];assert module not in found and hashlib.sha256(body).hexdigest()==digest,'module hash mismatch'
            (destination/(module+'.ko.xz')).write_bytes(body);found.add(module)
assert found==set(lock['modules']),'missing modules'
print('Verified and extracted',len(found),'stock signed modules')
