"""Exercise the actual initializer module under a 512 MiB cluster memory limit."""
import hashlib
import json
import os
from pathlib import Path
import resource
import sys

sys.path.insert(0, '/scripts')
from encrypt_model import encrypt_file_streaming
from kserve_storage.confidential import JWEDecryptor
from jwcrypto import jwe

key = os.urandom(32)
class Resolver:
    def resolve_key(self, resource_id):
        assert resource_id == 'test-only'
        return key

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

os.chdir('/data')
plain = Path('large.bin')
with plain.open('wb') as stream:
    stream.truncate(2 * 1024**3)
expected = digest(plain)
encrypted = Path('large.bin.jwe')
encrypt_file_streaming(str(plain), str(encrypted), key, plain.stat().st_size)
plain.unlink()
result = JWEDecryptor(Resolver(), 'test-only').decrypt_file(encrypted)
assert result.stat().st_size == 2 * 1024**3
assert digest(result) == expected
result.unlink()
print(json.dumps({'event':'STREAMING_2GIB_PASS','peakRssKiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}), flush=True)

plain = Path('small.bin'); plain.write_bytes(b'approved plaintext')
encrypted = Path('small.bin.jwe')
encrypt_file_streaming(str(plain), str(encrypted), key, plain.stat().st_size)
parts = encrypted.read_bytes().split(b'.'); tag = bytearray(parts[-1]); tag[0] = ord('A') if tag[0] != ord('A') else ord('B'); parts[-1] = bytes(tag)
encrypted.write_bytes(b'.'.join(parts))
before = encrypted.read_bytes()
try:
    JWEDecryptor(Resolver(), 'test-only').decrypt_file(encrypted)
except jwe.InvalidJWEData:
    pass
else:
    raise AssertionError('corrupt authentication tag accepted')
assert plain.read_bytes() == b'approved plaintext'
assert encrypted.read_bytes() == before
assert not list(Path('.').glob('*.tmp'))
print('TAMPERED_JWE_REJECTED_WITH_ORIGINAL_FILES_PRESERVED', flush=True)
