"""Synthetic publisher-shaped test data. Never an approved real model release."""

def fixture():
    size=64*1024*1024
    data=size-1024*1024
    source={'format':'luks-verity-v1','repository':'synthetic-test/model',
        'manifestDigest':'sha256:'+'a'*64,'diskDigest':'sha256:'+'b'*64,'diskBytes':size}
    descriptor={'format':'luks-verity-v1','diskBytes':size,'dataBytes':data,
        'hashOffsetBytes':data,'blockBytes':4096,'hashAlgorithm':'sha256',
        'verityRoot':'c'*64,'veritySalt':'d'*64,
        'luksUuid':'12345678-1234-4234-8234-123456789abc','headerSha256':'e'*64,
        'headerBytes':16*1024*1024,'filesystem':'ext4',
        'files':[{'path':'synthetic.bin','bytes':32,'sha256':'f'*64}]}
    return descriptor,source
