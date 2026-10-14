"""Bounded TLS transport for Gateway; no administrator or key-delivery routes.

The caller constructs a pinned EarVerifier/ReceiptIssuer and loads the database
and TLS identity from administrator-owned configuration. Request fields never
select trust roots, policy, a database path or an attestation-service URL.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
from socketserver import ThreadingMixIn
import ssl
import threading

from attestation import MAX_TOKEN, read_object, unb64
from authority import Denied
from gateway import MAX_REQUEST
from receipts import compact

MAX_ENVELOPE = MAX_TOKEN + 2 * MAX_REQUEST + 1024

# Exact local exception strings only. Never print an exception or client field.
DENIAL_CODES = {
    "Trustee RCAR response rejected": "trustee-response",
    "Trustee RCAR unavailable": "trustee-unavailable",
    "invalid Trustee token response": "trustee-token-envelope",
    "unsupported JWS profile": "token-profile",
    "stale attestation result": "token-time",
    "wrong attestation issuer/profile": "token-issuer-profile",
    "unexpected device appraisal set": "device-set",
    "unacceptable device appraisal": "device-appraisal",
    "missing expected hardware evidence": "device-evidence",
    "wrong measured guest configuration": "guest-initdata",
    "RCAR device/session binding mismatch": "device-session-binding",
    "malformed attestation result": "token-shape",
    "invalid ES256 signature": "token-signature",
    "invalid ES256 signature length": "token-signature-length",
    "invalid base64url": "base64url",
    "noncanonical base64url": "base64url-canonical",
    "invalid JSON": "json",
    "expected JSON object": "json-object",
    "invalid message size": "message-size",
    "duplicate JSON member": "json-duplicate",
    "invalid composite evidence size": "composite-size",
    "RCAR signing-key binding mismatch": "signing-key-binding",
    "expected dedicated P-256 storage key": "signing-key-profile",
    "invalid EC coordinates": "signing-key-coordinates",
    "invalid EC key": "signing-key-invalid",
    "invalid composite evidence envelope": "composite-envelope",
    "NVIDIA evidence required": "gpu-evidence-missing",
    "unknown, expired or already attempted handshake": "handshake-state",
}


def tls_context(certificate, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certificate, key)
    context.set_alpn_protocols(["http/1.1"])
    return context


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    # One request per connection avoids ambiguous framing and pipelined actions.
    server_version = "StorageAuthority"
    sys_version = ""

    def log_message(self, *_args):
        # BaseHTTPRequestHandler logs attacker-controlled paths by default.
        pass

    def reply(self, status, body):
        # Fixed route/status only: no URL parameters, request body, evidence,
        # token, proof, receipt, key or exception text reaches the audit log.
        route = (
            self.path
            if getattr(self, "path", "")
            in ("/v1/challenge", "/v1/attest", "/v1/execute")
            else "other"
        )
        print(f"STORAGE_AUTHORITY route={route} status={status}", flush=True)
        raw = compact(body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        # Never reflect a path, exception, token, proof or receipt in an error.
        self.reply(code, {"error": "invalid HTTP request"})

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler interface
        self.close_connection = True
        if self.path not in ("/v1/challenge", "/v1/attest", "/v1/execute"):
            self.reply(404, {"error": "unknown route"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        types = self.headers.get_all("Content-Type", [])
        if (
            len(lengths) != 1
            or not lengths[0].isascii()
            or not lengths[0].isdecimal()
            or len(lengths[0]) > 8
            or types != ["application/json"]
            or "Transfer-Encoding" in self.headers
            or "Content-Encoding" in self.headers
            or "Expect" in self.headers
        ):
            self.reply(400, {"error": "invalid request framing"})
            return
        length = int(lengths[0])
        limit = MAX_REQUEST if self.path == "/v1/challenge" else MAX_ENVELOPE
        if not 0 < length <= limit:
            self.reply(413, {"error": "invalid message size"})
            return
        raw = self.rfile.read(length)
        if len(raw) != length:
            self.reply(400, {"error": "incomplete message"})
            return
        try:
            if self.path == "/v1/challenge":
                result = self.server.gateway.challenge(raw)
            elif self.path == "/v1/attest":
                body = read_object(raw, MAX_ENVELOPE)
                if set(body) != {"nonce", "key", "evidence"}:
                    raise Denied("invalid attestation envelope")
                result = self.server.gateway.attest(**body)
            else:
                body = read_object(raw, MAX_ENVELOPE)
                if set(body) != {"nonce", "request", "token", "proof"}:
                    raise Denied("invalid execute envelope")
                request = unb64(body["request"])
                if not 0 < len(request) <= MAX_REQUEST:
                    raise Denied("invalid request size")
                result = self.server.gateway.execute(
                    body["nonce"], request, body["token"], body["proof"]
                )
        except Denied as exc:
            code = DENIAL_CODES.get(str(exc), "other")
            print(f"STORAGE_AUTHORITY denial={code}", flush=True)
            self.reply(403, {"error": "request denied"})
            return
        except Exception:  # Do not expose SQLite/crypto/configuration details.
            self.reply(500, {"error": "authority unavailable"})
            return
        self.reply(200, result)


class Server(ThreadingMixIn, HTTPServer):
    """TLS handshake, headers and body share one wall-clock deadline.

    Bounded workers include unfinished handshakes. Expiry closes the connection,
    but does not cancel a durable authority transition already in progress. Lost
    responses require a fresh challenge and the same idempotent operation ID.
    Thread shutdown waits for those transitions. No plaintext listener exists.
    """

    daemon_threads = False
    block_on_close = True
    request_queue_size = 16

    def __init__(self, address, gateway, context, *, workers=16, deadline=10):
        if (
            not isinstance(context, ssl.SSLContext)
            or context.protocol != ssl.PROTOCOL_TLS_SERVER
            or context.minimum_version != ssl.TLSVersion.TLSv1_3
            or context.maximum_version != ssl.TLSVersion.TLSv1_3
        ):
            raise ValueError("explicit TLS 1.3 server context required")
        if type(workers) is not int or not 1 <= workers <= 128:
            raise ValueError("invalid worker bound")
        if isinstance(deadline, bool) or not 0 < deadline <= 30:
            raise ValueError("invalid connection deadline")
        self.gateway = gateway
        self.context = context
        self.deadline = deadline
        self.slots = threading.BoundedSemaphore(workers)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        # wrap_socket detaches the input fd, so timeout and replacement share a
        # lock. Handshake runs after wrapping, outside the lock, under the timer.
        lock = threading.Lock()
        connection = [request]

        def expire():
            with lock:
                try:
                    connection[0].shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection[0].close()

        timer = threading.Timer(self.deadline, expire)
        timer.daemon = True
        timer.start()
        try:
            request.settimeout(self.deadline)
            with lock:
                connection[0] = self.context.wrap_socket(
                    request, server_side=True, do_handshake_on_connect=False
                )
            connection[0].do_handshake()
            self.finish_request(connection[0], client_address)
        except (OSError, ssl.SSLError):
            pass
        finally:
            timer.cancel()
            timer.join()
            self.shutdown_request(connection[0])
            self.slots.release()

    def handle_error(self, request, client_address):
        # Standard server tracebacks can contain request/credential values.
        pass
