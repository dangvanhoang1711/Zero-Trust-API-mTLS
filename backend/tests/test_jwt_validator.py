import base64
import json
import time
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app import create_app
from services.jwt_validator import JWKSValidator


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise ValueError(f"http {self.status_code}")

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self._responses = responses
        self.calls = []

    def get(self, url, timeout=10):
        self.calls.append(("GET", url, timeout))
        return self._responses[url]


class JWKSValidatorTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.ctx = self.app.app_context()
        self.ctx.push()

        self.private_key = ec.generate_private_key(ec.SECP256R1())
        public_numbers = self.private_key.public_key().public_numbers()
        self.kid = "test-kid"
        self.issuer = "http://keycloak:8080/realms/zero-trust"
        self.discovery_url = f"{self.issuer}/.well-known/openid-configuration"
        self.jwks_url = f"{self.issuer}/protocol/openid-connect/certs"

        self.jwk = {
            "kty": "EC",
            "kid": self.kid,
            "alg": "ES256",
            "crv": "P-256",
            "x": b64url_encode(public_numbers.x.to_bytes(32, "big")),
            "y": b64url_encode(public_numbers.y.to_bytes(32, "big")),
        }

        self.validator = JWKSValidator()
        self.validator._session = FakeSession(
            {
                self.discovery_url: FakeResponse(
                    {"issuer": self.issuer, "jwks_uri": self.jwks_url}
                ),
                self.jwks_url: FakeResponse({"keys": [self.jwk]}),
            }
        )

    def tearDown(self):
        self.ctx.pop()

    def _build_token(self, payload):
        header = {"alg": "ES256", "kid": self.kid, "typ": "JWT"}
        header_segment = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_segment = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_segment}.{payload_segment}".encode("utf-8")
        der_signature = self.private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        signature_segment = b64url_encode(signature)
        return f"{header_segment}.{payload_segment}.{signature_segment}"

    def test_verify_token_accepts_valid_es256_token(self):
        token = self._build_token(
            {
                "iss": self.issuer,
                "aud": "api-gateway",
                "sub": "integration-user",
                "exp": int(time.time()) + 300,
                "nbf": int(time.time()) - 5,
            }
        )

        payload = self.validator.verify_token(token)

        self.assertEqual(payload["sub"], "integration-user")
        self.assertEqual(len(self.validator._session.calls), 2)

    def test_verify_token_rejects_wrong_audience(self):
        token = self._build_token(
            {
                "iss": self.issuer,
                "aud": "wrong-audience",
                "sub": "integration-user",
                "exp": int(time.time()) + 300,
                "nbf": int(time.time()) - 5,
            }
        )

        with self.assertRaisesRegex(ValueError, "audience mismatch"):
            self.validator.verify_token(token)

    def test_verify_token_rejects_tampered_signature(self):
        token = self._build_token(
            {
                "iss": self.issuer,
                "aud": "api-gateway",
                "sub": "integration-user",
                "exp": int(time.time()) + 300,
                "nbf": int(time.time()) - 5,
            }
        )
        header_segment, payload_segment, signature_segment = token.split(".")
        tampered_signature = bytearray(base64.urlsafe_b64decode(signature_segment + "=="))
        tampered_signature[0] ^= 0x01
        tampered = ".".join(
            [
                header_segment,
                payload_segment,
                b64url_encode(bytes(tampered_signature)),
            ]
        )

        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            self.validator.verify_token(tampered)
