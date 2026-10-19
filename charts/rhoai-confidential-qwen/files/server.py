"""Small internal-network chat proxy. No Kubernetes credentials or exec fallback."""
import json
import os
import secrets
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import urllib.request
from urllib.parse import urlsplit
BACKEND=os.environ['INFERENCE_BACKEND'].rstrip('/')
MODEL=os.environ['INFERENCE_MODEL']
MAX_BODY=32768
NONCE=secrets.token_urlsafe(24)
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass # Do not record prompts or generated content.
    def send(self,status,data,content_type='application/json'):
        self.send_response(status)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'none'; connect-src 'self'; script-src 'nonce-"+NONCE+"'; style-src 'nonce-"+NONCE+"'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers();self.wfile.write(data)
    def do_GET(self):
        if self.path=='/healthz':
            try:
                with urllib.request.urlopen(BACKEND+'/health',timeout=3) as response:
                    if response.status!=200:raise ValueError()
                self.send(200,b'{"status":"ok"}')
            except Exception:self.send(503,b'{"status":"inference unavailable"}')
        elif self.path=='/':self.send(200,(Path(os.environ.get('CHAT_FILES','/app'))/'index.html').read_text().replace('__NONCE__',NONCE).encode(),'text/html; charset=utf-8')
        else:self.send(404,b'{}')
    def do_POST(self):
        if self.path!='/api/chat':return self.send(404,b'{}')
        origin=self.headers.get('Origin')
        if origin and urlsplit(origin).netloc!=self.headers.get('Host'):return self.send(403,b'{"error":"origin denied"}')
        if self.headers.get('Content-Type','').split(';')[0]!='application/json':return self.send(415,b'{}')
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=MAX_BODY:raise ValueError()
            obj=json.loads(self.rfile.read(length));messages=obj['messages']
            if not isinstance(messages,list) or not 1<=len(messages)<=20:raise ValueError()
            for m in messages:
                if set(m)!={'role','content'} or m['role'] not in ('user','assistant') or not isinstance(m['content'],str) or len(m['content'])>8192:raise ValueError()
        except (ValueError,KeyError,TypeError):return self.send(400,b'{"error":"invalid messages"}')
        try:
            req=urllib.request.Request(BACKEND+'/v1/chat/completions',data=json.dumps({'model':MODEL,'messages':messages,'max_tokens':256,'stream':False,'chat_template_kwargs':{'enable_thinking':False}}).encode(),headers={'Content-Type':'application/json'},method='POST')
            with urllib.request.urlopen(req,timeout=90) as response:
                data=response.read(1024*1024+1)
            if len(data)>1024*1024:raise ValueError()
            result=json.loads(data)
            if not isinstance(result['choices'][0]['message']['content'],str):raise ValueError()
            self.send(200,json.dumps(result).encode())
        except Exception:self.send(502,b'{"error":"inference backend unavailable"}')
if __name__=='__main__':ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
