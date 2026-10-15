"""Create fresh authority/signing credentials and public trust pins in a trusted workspace."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def create(private, public, hostname, identity):
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,240}',hostname) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,50}',identity):
        raise ValueError('invalid authority identity')
    os.umask(0o077)
    private.mkdir(mode=0o700);public.mkdir(mode=0o755)
    keys={'tls':ec.generate_private_key(ec.SECP256R1()),'receipt':ed25519.Ed25519PrivateKey.generate(),'approval':ed25519.Ed25519PrivateKey.generate()}
    for name,key in keys.items():
        with (private/(name+'.key')).open('xb') as f:f.write(key.private_bytes(ser.Encoding.PEM,ser.PrivateFormat.PKCS8,ser.NoEncryption()))
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,hostname)])
    now=dt.datetime.now(dt.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(keys['tls'].public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=30)).add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]),critical=False).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(keys['tls'],hashes.SHA256()))
    (public/'tls.pem').write_bytes(cert.public_bytes(ser.Encoding.PEM))
    pins={'trustee_rcar':True,'audience':'https://'+hostname+':8443/v1','certificate_der':list(cert.public_bytes(ser.Encoding.DER)),'address':None,'receipt_public_key':list(keys['receipt'].public_key().public_bytes_raw()),'receipt_issuer':identity,'receipt_key_id':'receipt-v1'}
    (public/'authority.json').write_text(json.dumps(pins,indent=2)+'\n')
    (public/'approval-keys.json').write_text(json.dumps({identity:keys['approval'].public_key().public_bytes_raw().hex()},indent=2)+'\n')
    return pins

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--private',type=Path,required=True);p.add_argument('--public',type=Path,required=True)
    p.add_argument('--hostname',required=True);p.add_argument('--identity',required=True)
    a=p.parse_args();create(a.private,a.public,a.hostname,a.identity)
    print('Fresh credentials created privately; public trust pins written separately.')
