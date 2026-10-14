"""Fixed TLS client for standard Trustee RCAR. No resource or admin operations."""

import base64
from dataclasses import dataclass
import http.client
from http.cookies import SimpleCookie
import ipaddress
import re
import socket
import ssl
import threading
from urllib.parse import urlsplit

from attestation import MAX_TOKEN, read_object
from authority import Denied
from receipts import compact


@dataclass(frozen=True, repr=False)
class Session:
    nonce: str
    cookie: str

    def challenge(self):
        # Session cookies stay exclusively on the authority side.
        return {
            "kind": "trustee-rcar-v1",
            "nonce": self.nonce,
            "hash_algorithm": "sha384",
        }


def nonce_valid(value):
    if not isinstance(value, str) or len(value) != 44:
        return False
    try:
        raw = base64.b64decode(value, validate=True)
        return len(raw) == 32 and base64.b64encode(raw).decode() == value
    except ValueError:
        return False


class KbsRcar:
    def __init__(
        self,
        origin,
        ca_file,
        init_data,
        *,
        address=None,
        timeout=8,
        policy_selector=None
    ):
        url = urlsplit(origin)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.path
            or url.query
            or url.fragment
            or not origin.isascii()
            or url.netloc != origin.removeprefix("https://")
            or url.netloc.endswith(":")
            or url.port == 0
        ):
            raise ValueError("pin an exact HTTPS KBS origin without a path")
        if not isinstance(init_data, str) or not 0 < len(init_data.encode()) <= 65536:
            raise ValueError("pin the approved InitData TOML")
        if isinstance(timeout, bool) or not 0 < timeout <= 10:
            raise ValueError("invalid RCAR timeout")
        if policy_selector is not None and not re.fullmatch(
            r"[a-zA-Z0-9_-]{1,64}", policy_selector
        ):
            raise ValueError("invalid administrator policy selector")
        if address is not None:
            if (
                not isinstance(address, tuple)
                or len(address) != 2
                or type(address[1]) is not int
                or not 1 <= address[1] <= 65535
            ):
                raise ValueError("invalid fixed KBS address")
            ipaddress.ip_address(address[0])
        self.host, self.port = url.hostname, url.port or 443
        self.address = address or (self.host, self.port)
        self.timeout, self.init_data, self.policy_selector = (
            timeout,
            init_data,
            policy_selector,
        )
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_verify_locations(cafile=ca_file)
        self.context.set_alpn_protocols(["http/1.1"])

    def _request(self, route, body, cookie=None):
        if route not in {"auth", "attest"}:
            raise Denied("unsupported RCAR operation")
        connection = http.client.HTTPSConnection(
            self.host, self.port, context=self.context, timeout=self.timeout
        )
        timer, channel = None, None
        try:
            raw_socket = socket.create_connection(self.address, self.timeout)
            try:
                channel = self.context.wrap_socket(
                    raw_socket, server_hostname=self.host
                )
            except Exception:
                raw_socket.close()
                raise
            connection.sock = channel

            def expire():
                try:
                    channel.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(self.timeout, expire)
            timer.daemon = True
            timer.start()
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            if cookie is not None:
                if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", cookie):
                    raise Denied("invalid retained KBS session")
                headers["Cookie"] = "kbs-session-id=" + cookie
            connection.request("POST", "/kbs/v0/" + route, compact(body), headers)
            response = connection.getresponse()
            if (
                response.status != 200
                or response.getheader("Content-Encoding") is not None
                or response.getheader("Content-Type", "").split(";")[0]
                != "application/json"
            ):
                raise Denied("Trustee RCAR response rejected")
            data = read_object(response.read(MAX_TOKEN + 4097), MAX_TOKEN + 4096)
            cookies = response.headers.get_all("Set-Cookie", [])
            return data, cookies
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise Denied("Trustee RCAR unavailable") from exc
        finally:
            if timer is not None:
                timer.cancel()
                timer.join()
            connection.close()

    def begin(self):
        extra = (
            {}
            if self.policy_selector is None
            else {"attestation-policy-selector": self.policy_selector}
        )
        body, cookies = self._request(
            "auth",
            {
                "version": "0.4.0",
                "tee": "snp",
                "extra-params": extra,
            },
        )
        if (
            set(body) != {"nonce", "extra-params"}
            or not nonce_valid(body["nonce"])
            or body["extra-params"] not in ("", {})
            or len(cookies) != 1
        ):
            raise Denied("unsupported Trustee challenge")
        parsed = SimpleCookie()
        try:
            parsed.load(cookies[0])
        except http.cookies.CookieError as exc:
            raise Denied("invalid Trustee cookie") from exc
        if set(parsed) != {"kbs-session-id"}:
            raise Denied("invalid Trustee cookie set")
        cookie = parsed["kbs-session-id"].value
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", cookie):
            raise Denied("invalid Trustee cookie")
        return Session(body["nonce"], cookie)

    def attest(self, session, key, evidence):
        body, _ = self._request(
            "attest",
            {
                "init-data": {"format": "toml", "body": self.init_data},
                "runtime-data": {
                    "nonce": session.nonce,
                    "tee-pubkey": {**key, "alg": "ES256"},
                },
                "tee-evidence": evidence,
            },
            session.cookie,
        )
        if (
            set(body) != {"token"}
            or not isinstance(body["token"], str)
            or not 0 < len(body["token"]) <= MAX_TOKEN
        ):
            raise Denied("invalid Trustee token response")
        return body["token"]
