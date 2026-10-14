"""Fixed loopback Trustee AS adapter; its administrative API is never forwarded.

AS and authority must share a trusted network namespace. The AS listener stays
on loopback. Its signer, issuer, exact InitData and policy are independently pinned
by EarVerifier. There is no caller-selected URL, redirect, proxy or trust root.
"""

import http.client
import socket
import threading

from attestation import MAX_TOKEN, b64
from authority import Denied
from receipts import compact


class AttestationServiceClient:
    def __init__(self, verifier, port, *, timeout=8):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid loopback AS port")
        if isinstance(timeout, bool) or not 0 < timeout <= 10:
            raise ValueError("invalid AS timeout")
        if len(verifier.appraisals) != 1 or verifier.appraisals[0].tee != "snp":
            raise ValueError("this adapter supports one SNP appraisal only")
        self.port = port
        self.timeout = timeout
        self.policy_id = verifier.appraisals[0].policy_id
        self.init_data = verifier.init_data

    def evaluate(self, runtime, evidence):
        request = {
            "verification_requests": [
                {
                    "tee": "snp",
                    "evidence": evidence,
                    "runtime_data": {"structured": runtime},
                    "runtime_data_hash_algorithm": "sha256",
                    "init_data": {
                        "init_data_digest": b64(bytes.fromhex(self.init_data))
                    },
                }
            ],
            "policy_ids": [self.policy_id],
        }
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=self.timeout
        )
        timer = None
        try:
            connection.connect()
            channel = connection.sock

            def expire():
                try:
                    channel.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            # Bound the whole response, including a peer that trickles bytes.
            timer = threading.Timer(self.timeout, expire)
            timer.daemon = True
            timer.start()
            connection.request(
                "POST",
                "/attestation",
                compact(request),
                {"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            if response.status != 200:
                raise Denied("attestation service denied evidence")
            raw = response.read(MAX_TOKEN + 1)
            if not 0 < len(raw) <= MAX_TOKEN:
                raise Denied("invalid attestation response size")
            return raw.decode("ascii")
        except (OSError, http.client.HTTPException, UnicodeError) as exc:
            raise Denied("attestation service unavailable") from exc
        finally:
            if timer is not None:
                timer.cancel()
                timer.join()
            connection.close()
