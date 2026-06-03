import os
import json
import time
import base64
import hashlib
import uuid
import requests
from flask import Flask, request, jsonify

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
PROXY_URL = os.environ.get("PROXY_URL", "http://dpop-token-proxy:5002")
KEYCLOAK_ADMIN_USER = os.environ.get("KEYCLOAK_ADMIN", "admin")
KEYCLOAK_ADMIN_PASS = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
REALM = "zero-trust"
CLIENT_ID = "demo-client-dpop"
MAPPER_NAME = "cnf-jkt"

DPOP_MAX_AGE = int(os.environ.get("DPOP_MAX_AGE_SECONDS", "120"))
DPOP_CLOCK_SKEW = int(os.environ.get("DPOP_CLOCK_SKEW_SECONDS", "5"))

SUPPORTED_ALGS = {"ES256", "ES384", "ES512"}

ALG_TO_CURVE = {
    "ES256": "P-256",
    "ES384": "P-384",
    "ES512": "P-521",
}

ALG_TO_HASH = {
    "ES256": hashes.SHA256(),
    "ES384": hashes.SHA384(),
    "ES512": hashes.SHA512(),
}

CURVE_CLASS = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}

CURVE_KEY_LEN = {
    "P-256": 32,
    "P-384": 48,
    "P-521": 66,
}


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode_padded(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    data = data.decode("utf-8") if isinstance(data, bytes) else data
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def compute_jkt(jwk):
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return b64url_encode(digest)


def jwk_to_ec_public_key(jwk, alg):
    crv_name = ALG_TO_CURVE[alg]
    if jwk.get("crv") != crv_name:
        raise ValueError(f"crv mismatch: expected {crv_name}, got {jwk.get('crv')}")

    curve = CURVE_CLASS[crv_name]
    key_len = CURVE_KEY_LEN[crv_name]

    x_bytes = b64url_decode_padded(jwk["x"])
    y_bytes = b64url_decode_padded(jwk["y"])

    if len(x_bytes) > key_len:
        x_bytes = x_bytes[-key_len:]
    if len(y_bytes) > key_len:
        y_bytes = y_bytes[-key_len:]

    encoded_point = b"\x04" + x_bytes + y_bytes
    return ec.EllipticCurvePublicKey.from_encoded_point(curve, encoded_point)


def verify_dpop_signature(dpop_header, hash_alg):
    parts = dpop_header.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    signing_input = f"{parts[0]}.{parts[1]}"
    sig_bytes = b64url_decode_padded(parts[2])

    return parts, signing_input, sig_bytes


def validate_dpop_proof(dpop_header, expected_htm, expected_htu):
    parts = dpop_header.split(".")
    if len(parts) != 3:
        raise ValueError("invalid DPoP proof: malformed JWT")

    header_raw = b64url_decode_padded(parts[0])
    header = json.loads(header_raw)

    typ = header.get("typ", "")
    if typ.lower() != "dpop+jwt":
        raise ValueError(f"invalid DPoP proof type: {typ}")

    alg = header.get("alg", "")
    if alg not in SUPPORTED_ALGS:
        raise ValueError(f"unsupported DPoP algorithm: {alg}")

    jwk = header.get("jwk")
    if not jwk or not isinstance(jwk, dict):
        raise ValueError("missing or invalid DPoP jwk")

    if jwk.get("kty") != "EC":
        raise ValueError(f"unsupported DPoP jwk kty: {jwk.get('kty')}")

    payload_raw = b64url_decode_padded(parts[1])
    payload = json.loads(payload_raw)

    htm = payload.get("htm", "")
    if htm.upper() != expected_htm.upper():
        raise ValueError(f"DPoP htm mismatch: {htm} != {expected_htm}")

    htu = payload.get("htu", "")
    if htu.rstrip("/") != expected_htu.rstrip("/"):
        raise ValueError(f"DPoP htu mismatch: {htu} != {expected_htu}")

    jti = payload.get("jti", "")
    if not jti:
        raise ValueError("missing DPoP jti")

    iat = payload.get("iat")
    if not iat:
        raise ValueError("missing DPoP iat")

    now = time.time()
    if iat > now + DPOP_CLOCK_SKEW:
        raise ValueError("DPoP proof used before issued")
    if now - iat > DPOP_MAX_AGE:
        raise ValueError("DPoP proof expired")

    public_key = jwk_to_ec_public_key(jwk, alg)

    signing_input = f"{parts[0]}.{parts[1]}"
    sig_bytes = b64url_decode_padded(parts[2])

    crv_name = ALG_TO_CURVE[alg]
    key_len = CURVE_KEY_LEN[crv_name]

    r_bytes = sig_bytes[:key_len]
    s_bytes = sig_bytes[key_len:]
    if len(r_bytes) != key_len or len(s_bytes) != key_len:
        raise ValueError(f"invalid DPoP signature length")

    r = int.from_bytes(r_bytes, "big")
    s = int.from_bytes(s_bytes, "big")
    sig_der = encode_dss_signature(r, s)

    try:
        public_key.verify(sig_der, signing_input.encode("utf-8"), ec.ECDSA(ALG_TO_HASH[alg]))
    except Exception as e:
        raise ValueError(f"DPoP signature verification failed: {e}")

    jkt = compute_jkt(jwk)
    return jkt, jti


def keycloak_admin_request(method, path, data=None, token=None, form=False):
    url = f"{KEYCLOAK_URL}{path}"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if form:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        headers["Content-Type"] = "application/json"

    body = None
    if data is not None:
        if form:
            body = data
        else:
            body = json.dumps(data)

    try:
        resp = requests.request(method, url, headers=headers, data=body, timeout=10)
        resp.raise_for_status()
        if resp.status_code == 204:
            return True
        return resp.json()
    except requests.exceptions.RequestException as e:
        err = ""
        if hasattr(e, "response") and e.response is not None:
            try:
                err = e.response.json()
            except Exception:
                err = e.response.text[:500]
        raise RuntimeError(f"Keycloak API error: {e} - {err}")


def get_admin_token():
    data = {
        "client_id": "admin-cli",
        "username": KEYCLOAK_ADMIN_USER,
        "password": KEYCLOAK_ADMIN_PASS,
        "grant_type": "password",
    }
    token_data = keycloak_admin_request(
        "POST", "/realms/master/protocol/openid-connect/token",
        data=data, form=True
    )
    if not token_data or "access_token" not in token_data:
        raise RuntimeError("failed to get Keycloak admin token")
    return token_data["access_token"]


def update_keycloak_dpop_jkt(jkt):
    admin_token = get_admin_token()

    clients = keycloak_admin_request(
        "GET", f"/admin/realms/{REALM}/clients?clientId={CLIENT_ID}",
        token=admin_token
    )
    if not clients or len(clients) == 0:
        raise RuntimeError(f"client '{CLIENT_ID}' not found")
    client_uuid = clients[0]["id"]

    mappers = keycloak_admin_request(
        "GET", f"/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models",
        token=admin_token
    )
    if not mappers:
        raise RuntimeError(f"no mappers found for client '{CLIENT_ID}'")

    mapper = next((m for m in mappers if m.get("name") == MAPPER_NAME), None)
    if not mapper:
        available = [m.get("name") for m in mappers]
        raise RuntimeError(f"mapper '{MAPPER_NAME}' not found. Available: {available}")
    mapper_uuid = mapper["id"]

    new_value = json.dumps({"jkt": jkt})
    mapper["config"]["claim.value"] = new_value

    keycloak_admin_request(
        "PUT",
        f"/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models/{mapper_uuid}",
        data=mapper,
        token=admin_token,
    )


def error_response(status_code, error, description):
    return jsonify({"error": error, "error_description": description}), status_code


@app.route("/token", methods=["POST"])
def token():
    dpop_header = request.headers.get("DPoP", "").strip()
    if not dpop_header:
        return error_response(400, "invalid_request", "missing DPoP header")

    expected_htu = f"{PROXY_URL.rstrip('/')}/token"

    try:
        jkt, jti = validate_dpop_proof(dpop_header, "POST", expected_htu)
    except ValueError as e:
        return error_response(400, "invalid_dpop_proof", str(e))

    try:
        update_keycloak_dpop_jkt(jkt)
    except RuntimeError as e:
        return error_response(502, "keycloak_error", str(e))

    token_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    try:
        kc_resp = requests.post(
            token_url,
            data=request.form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
    except requests.exceptions.RequestException as e:
        return error_response(502, "keycloak_error", f"token request failed: {e}")

    excluded_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    headers = [
        (k, v) for k, v in kc_resp.raw.headers.items()
        if k.lower() not in excluded_headers
    ]

    body = kc_resp.content
    if kc_resp.ok and jti:
        try:
            body_json = json.loads(body)
            body_json["dpop_jti"] = jti
            body = json.dumps(body_json).encode("utf-8")
        except Exception:
            pass

    resp = app.make_response((body, kc_resp.status_code, headers))
    return resp


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("DPOP_PROXY_PORT", 5002))
    print(f"DPoP Token Proxy listening on :{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
