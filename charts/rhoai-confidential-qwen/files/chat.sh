#!/bin/bash
set -euo pipefail
# Reuse the existing chat server, with TLS terminating in the confidential guest.
# The API server receives only KBS resource identifiers, never the TLS private key.
exec python3 - <<'PY'
import importlib.util,os,pathlib,ssl,time,urllib.request
root=pathlib.Path('/dev/shm/chat-tls');root.mkdir(mode=0o700,exist_ok=True)
for variable,filename in [('TLS_CERT_RESOURCE','cert.pem'),('TLS_KEY_RESOURCE','key.pem')]:
    uri='http://127.0.0.1:8006/cdh/resource/'+os.environ[variable].removeprefix('kbs:///')
    with urllib.request.urlopen(uri,timeout=60) as response: data=response.read()
    path=root/filename;path.write_bytes(data);path.chmod(0o600)
while True:
    try:
        with urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3) as response:
            if response.status==200:break
    except Exception:pass
    time.sleep(2)
spec=importlib.util.spec_from_file_location('chat',str(pathlib.Path(os.environ.get('CHAT_FILES','/app'))/'server.py'));chat=importlib.util.module_from_spec(spec);spec.loader.exec_module(chat)
server=chat.ThreadingHTTPServer(('0.0.0.0',8443),chat.Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
context.load_cert_chain(root/'cert.pem',root/'key.pem');server.socket=context.wrap_socket(server.socket,server_side=True)
print('CHAT_TLS_READY inference=guest-loopback',flush=True)
server.serve_forever()
PY
