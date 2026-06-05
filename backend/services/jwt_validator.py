import json
import time
import base64

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature

from flask import current_app


class JWKSValidator:
    def __init__(self):
        self._session = requests.Session()
        self._oidc_cache = None
        self._oidc_fetched_at = 0.0
        self._jwks_cache = None
        self._jwks_fetched_at = 0.0

    def _discovery_cache_ttl(self):
        return current_app.config.get("OIDC_DISCOVERY_CACHE_TTL", 300)

    def _jwks_cache_ttl(self):
        return current_app.config.get("JWKS_CACHE_TTL", 300)

    def _discovery_url(self):
        cfg = current_app.config
        configured = cfg.get("OIDC_DISCOVERY_URL", "").strip()
        if configured:
            return configured

        base = cfg["KEYCLOAK_URL"].rstrip("/")
        realm = cfg["KEYCLOAK_REALM"]
        return f"{base}/realms/{realm}/.well-known/openid-configuration"

    def _fetch_discovery_document(self):
        now = time.time()
        if self._oidc_cache and (now - self._oidc_fetched_at) < self._discovery_cache_ttl():
            return self._oidc_cache

        resp = self._session.get(self._discovery_url(), timeout=10)
        resp.raise_for_status()
        self._oidc_cache = resp.json()
        self._oidc_fetched_at = now
        return self._oidc_cache

    def _jwks_url(self):
        configured = current_app.config.get("JWKS_URL", "").strip()
        if configured:
            return configured
        return self._fetch_discovery_document()["jwks_uri"]

    def _expected_issuer(self):
        configured = current_app.config.get("JWT_ISSUER", "").strip()
        if configured:
            return configured
        return self._fetch_discovery_document().get("issuer", "")

    def _expected_audience(self):
        configured = current_app.config.get("JWT_AUDIENCE", "").strip()
        if configured:
            return configured
        return current_app.config.get("KEYCLOAK_CLIENT_ID", "").strip()

    def fetch_jwks(self):
        now = time.time()
        if self._jwks_cache and (now - self._jwks_fetched_at) < self._jwks_cache_ttl():
            return self._jwks_cache
        resp = self._session.get(self._jwks_url(), timeout=10)
        resp.raise_for_status()
        self._jwks_cache = resp.json()
        self._jwks_fetched_at = now
        return self._jwks_cache

    def verify_token(self, token):
        header = self._decode_header(token)
        algorithm = header.get("alg", "").upper()
        if algorithm not in {"ES256", "ES384", "ES512", "RS256", "RS384", "RS512"}:
            raise ValueError(f"Unsupported token algorithm '{header.get('alg', '')}'")

        kid = header.get("kid")
        if not kid:
            raise ValueError("Token header missing 'kid'")

        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Token must have 3 parts")

        jwks = self.fetch_jwks()
        key_data = None
        for jwk in jwks.get("keys", []):
            if jwk.get("kid") == kid:
                key_data = jwk
                break
        if not key_data:
            raise ValueError(f"Key with kid '{kid}' not found in JWKS")

        public_key = self._jwk_to_public_key(key_data)
        message = f"{parts[0]}.{parts[1]}".encode("utf-8")
        signature = self._urlsafe_b64decode(parts[2])
        payload = self._decode_payload(parts[1])

        try:
            self._verify_signature(public_key, algorithm, signature, message)
        except InvalidSignature:
            raise ValueError("Token signature verification failed")

        self._validate_registered_claims(payload)
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

    def _verify_signature(self, public_key, algorithm, signature, message):
        hash_algorithm = self._hash_algorithm_for(algorithm)
        if algorithm.startswith("RS"):
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("JWK key type does not match RSA token algorithm")
            public_key.verify(signature, message, padding.PKCS1v15(), hash_algorithm)
            return

        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("JWK key type does not match EC token algorithm")

        coordinate_size = (public_key.curve.key_size + 7) // 8
        expected_size = coordinate_size * 2
        if len(signature) != expected_size:
            raise ValueError("Invalid ECDSA signature length")

        r = int.from_bytes(signature[:coordinate_size], "big")
        s = int.from_bytes(signature[coordinate_size:], "big")
        der_signature = encode_dss_signature(r, s)
        public_key.verify(der_signature, message, ec.ECDSA(hash_algorithm))

    def _hash_algorithm_for(self, algorithm):
        mapping = {
            "ES256": hashes.SHA256(),
            "RS256": hashes.SHA256(),
            "ES384": hashes.SHA384(),
            "RS384": hashes.SHA384(),
            "ES512": hashes.SHA512(),
            "RS512": hashes.SHA512(),
        }
        return mapping[algorithm]

    def _validate_registered_claims(self, payload):
        now = time.time()

        exp = payload.get("exp")
        if exp is not None and now > float(exp):
            raise ValueError("Token has expired")

        nbf = payload.get("nbf")
        if nbf is not None and now < float(nbf):
            raise ValueError("Token is not yet valid")

        issuer = self._expected_issuer()
        if issuer and payload.get("iss") != issuer:
            raise ValueError("Token issuer mismatch")

        audience = self._expected_audience()
        if audience and not self._matches_audience(payload.get("aud"), audience):
            raise ValueError("Token audience mismatch")

    def _matches_audience(self, raw_audience, expected_audience):
        if isinstance(raw_audience, str):
            return raw_audience == expected_audience
        if isinstance(raw_audience, list):
            return expected_audience in raw_audience
        return False

    def _jwk_to_public_key(self, jwk):
        key_type = jwk.get("kty")
        if key_type == "EC":
            x = self._urlsafe_b64decode(jwk["x"])
            y = self._urlsafe_b64decode(jwk["y"])
            curve = self._curve_for_name(jwk.get("crv", ""))
            public_numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"),
                int.from_bytes(y, "big"),
                curve,
            )
            return public_numbers.public_key()

        if key_type == "RSA":
            modulus = int.from_bytes(self._urlsafe_b64decode(jwk["n"]), "big")
            exponent = int.from_bytes(self._urlsafe_b64decode(jwk["e"]), "big")
            public_numbers = rsa.RSAPublicNumbers(exponent, modulus)
            return public_numbers.public_key()

        raise ValueError(f"Unsupported JWK key type '{key_type}'")

    def _curve_for_name(self, curve_name):
        curves = {
            "P-256": ec.SECP256R1(),
            "P-384": ec.SECP384R1(),
            "P-521": ec.SECP521R1(),
        }
        try:
            return curves[curve_name]
        except KeyError as exc:
            raise ValueError(f"Unsupported EC curve '{curve_name}'") from exc
