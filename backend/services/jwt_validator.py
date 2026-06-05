import json
import time
import base64

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

from flask import current_app


class JWKSValidator:
    def __init__(self):
        self._session = requests.Session()
        self._jwks_cache = None
        self._jwks_fetched_at = 0.0

    def _jwks_url(self):
        cfg = current_app.config
        base = cfg["KEYCLOAK_URL"]
        realm = cfg["KEYCLOAK_REALM"]
        return f"{base}/realms/{realm}/protocol/openid-connect/certs"

    def _cache_ttl(self):
        return current_app.config.get("JWKS_CACHE_TTL", 300)

    def fetch_jwks(self):
        now = time.time()
        if self._jwks_cache and (now - self._jwks_fetched_at) < self._cache_ttl():
            return self._jwks_cache
        resp = self._session.get(self._jwks_url(), timeout=10)
        resp.raise_for_status()
        self._jwks_cache = resp.json()
        self._jwks_fetched_at = now
        return self._jwks_cache

    def verify_token(self, token):
        header = self._decode_header(token)
        kid = header.get("kid")
        if not kid:
            raise ValueError("Token header missing 'kid'")

        jwks = self.fetch_jwks()
        key_data = None
        for jwk in jwks.get("keys", []):
            if jwk.get("kid") == kid:
                key_data = jwk
                break
        if not key_data:
            raise ValueError(f"Key with kid '{kid}' not found in JWKS")

        public_key = self._jwk_to_public_key(key_data)

        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Token must have 3 parts")

        message = f"{parts[0]}.{parts[1]}".encode("utf-8")
        signature = self._urlsafe_b64decode(parts[2])

        try:
            public_key.verify(signature, message, ec.ECDSA(ec.SECP256R1()))
        except InvalidSignature:
            raise ValueError("Token signature verification failed")

        payload = self._decode_payload(parts[1])
        exp = payload.get("exp", 0)
        if exp and time.time() > exp:
            raise ValueError("Token has expired")
        return payload

    def get_payload(self, token):
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Token must have 3 parts")
        return self._decode_payload(parts[1])

    def _decode_header(self, token):
        parts = token.split(".")
        if len(parts) < 2:
            raise ValueError("Invalid token format")
        raw = self._urlsafe_b64decode(parts[0])
        return json.loads(raw)

    def _decode_payload(self, payload_part):
        raw = self._urlsafe_b64decode(payload_part)
        return json.loads(raw)

    def _urlsafe_b64decode(self, data):
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    def _jwk_to_public_key(self, jwk):
        x = self._urlsafe_b64decode(jwk["x"])
        y = self._urlsafe_b64decode(jwk["y"])
        curve = ec.SECP256R1()
        public_numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"),
            int.from_bytes(y, "big"),
            curve,
        )
        return public_numbers.public_key()
