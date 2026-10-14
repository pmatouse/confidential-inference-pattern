"""RCAR wire validation with synthetic HTTP responses; no hardware claims."""

import base64
import unittest
from unittest.mock import patch

from authority import Denied
from kbs_rcar import KbsRcar, nonce_valid


class RcarWireTests(unittest.TestCase):
    def client(self):
        # Wire methods do not need a network in these tests.
        client = object.__new__(KbsRcar)
        client.init_data = 'version = "0.1.0"'
        client.policy_selector = None
        return client

    def challenge(self):
        return (
            {"nonce": base64.b64encode(bytes(32)).decode(), "extra-params": ""},
            ["kbs-session-id=" + "a" * 32 + "; Path=/; HttpOnly"],
        )

    def test_exact_auth_attest_fields_and_no_key_resource_operation(self):
        client = self.client()
        with patch.object(client, "_request", return_value=self.challenge()) as request:
            session = client.begin()
            request.assert_called_once_with(
                "auth", {"version": "0.4.0", "tee": "snp", "extra-params": {}}
            )
            self.assertNotIn(session.cookie, repr(session))
            self.assertNotIn("cookie", session.challenge())
        key = {"kty": "EC", "crv": "P-256", "x": "synthetic", "y": "synthetic"}
        evidence = {"primary_evidence": {}, "additional_evidence": '{"nvidia":{}}'}
        with patch.object(
            client, "_request", return_value=({"token": "synthetic.jwt.token"}, [])
        ) as request:
            client.attest(session, key, evidence)
            route, body, cookie = request.call_args.args
            self.assertEqual(route, "attest")
            self.assertEqual(cookie, session.cookie)
            self.assertEqual(body["runtime-data"]["tee-pubkey"]["alg"], "ES256")
            self.assertEqual(body["tee-evidence"], evidence)
            self.assertEqual(
                body["init-data"], {"format": "toml", "body": client.init_data}
            )
        with self.assertRaises(Denied):
            client._request("resource", {})

    def test_cookie_nonce_algorithm_and_duplicate_cookie_rejection(self):
        client = self.client()
        body, cookies = self.challenge()
        cases = [
            ({**body, "nonce": "old"}, cookies),
            ({**body, "extra-params": {"selected-hash-algorithm": "sha256"}}, cookies),
            (body, []),
            (body, cookies * 2),
            (body, ["other=" + "a" * 32]),
            (body, ["kbs-session-id=short"]),
            ({**body, "extra": 1}, cookies),
        ]
        for value in cases:
            with patch.object(client, "_request", return_value=value):
                with self.assertRaises(Denied):
                    client.begin()
        for invalid in (None, "", "A" * 44, "\n" + body["nonce"], body["nonce"][:-1]):
            self.assertFalse(nonce_valid(invalid))

    def test_policy_selection_is_explicit_and_no_fallback(self):
        client = self.client()
        client.policy_selector = "storage-v1"
        with patch.object(
            client, "_request", side_effect=Denied("unrecognized")
        ) as request:
            with self.assertRaises(Denied):
                client.begin()
            self.assertEqual(request.call_count, 1)
            self.assertEqual(
                request.call_args.args[1]["extra-params"],
                {"attestation-policy-selector": "storage-v1"},
            )

    def test_arbitrary_origins_and_static_addresses_rejected_before_trust_loading(self):
        for origin in (
            "http://kbs",
            "https://kbs:0",
            "https://kbs:",
            "https://user@kbs",
            "https://kbs/",
            "https://kbs?redirect=x",
            "https://kbs/#x",
        ):
            with self.assertRaises(ValueError):
                KbsRcar(origin, "never-read", "init")
        for address in (
            ("hostname", 443),
            ("127.0.0.1", 0),
            ("127.0.0.1", True),
            ["127.0.0.1", 443],
        ):
            with self.assertRaises(ValueError):
                KbsRcar("https://kbs", "never-read", "init", address=address)
