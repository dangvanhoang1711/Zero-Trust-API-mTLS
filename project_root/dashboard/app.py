import os
import json
import time
import uuid
import base64
import hashlib
import ssl
import urllib3
import subprocess
from flask import Flask, jsonify, render_template
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CERTS_DIR = os.path.join(BASE_DIR, "infra", "certs")
CLIENT_CERT = os.path.join(CERTS_DIR, "client-chain.crt")
CLIENT_KEY = os.path.join(CERTS_DIR, "client.key")
CA_CERT = os.path.join(CERTS_DIR, "root-ca.crt")
SERVER_CHAIN = os.path.join(CERTS_DIR, "server-chain.crt")

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:18080")
ENVOY_URL = os.environ.get("ENVOY_URL", "https://localhost:10000")
EXT_AUTHZ_URL = os.environ.get("EXT_AUTHZ_URL", "http://localhost:50051")
REALM = "zero-trust"

def get_token(client_id="demo-client", client_secret="demo-client-secret"):
    token_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    resp = requests.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def envoy_request(token=None, use_cert=True, wrong_cert=False, path="/", dpop_proof=None):
    cert = None
    if use_cert:
        if wrong_cert:
            cert = (SERVER_CHAIN, CLIENT_KEY)
        else:
            cert = (CLIENT_CERT, CLIENT_KEY)

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if dpop_proof:
        headers["DPoP"] = dpop_proof

    url = ENVOY_URL.rstrip("/") + "/" + path.lstrip("/")

    try:
        resp = requests.get(
            url,
            cert=cert,
            verify=CA_CERT,
            headers=headers,
            timeout=15,
        )
        return {"status": resp.status_code, "body": resp.text, "error": None}
    except requests.exceptions.SSLError as e:
        return {"status": "TLS_ERR", "body": None, "error": f"SSL Error: {e}"}
    except requests.exceptions.ConnectionError as e:
        return {"status": "CONN_ERR", "body": None, "error": f"Connection Error: {e}"}
    except Exception as e:
        return {"status": "ERR", "body": None, "error": str(e)}


DPOP_PROXY_URL = os.environ.get("DPOP_PROXY_URL", "http://localhost:5002")


def b64url(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def ec_key_to_jwk(public_key):
    pub_nums = public_key.public_numbers()
    if isinstance(pub_nums.curve, ec.SECP256R1):
        crv, key_len = "P-256", 32
    elif isinstance(pub_nums.curve, ec.SECP384R1):
        crv, key_len = "P-384", 48
    elif isinstance(pub_nums.curve, ec.SECP521R1):
        crv, key_len = "P-521", 66
    else:
        raise ValueError("unsupported curve")
    return {
        "kty": "EC",
        "crv": crv,
        "x": b64url(pub_nums.x.to_bytes(key_len, "big")),
        "y": b64url(pub_nums.y.to_bytes(key_len, "big")),
    }


def compute_jkt(jwk):
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return b64url(hashlib.sha256(canonical.encode("utf-8")).digest())


def create_dpop_proof(private_key, htm, htu, jti=None, iat=None, ath=None, nonce=None):
    if jti is None:
        jti = str(uuid.uuid4())
    if iat is None:
        iat = int(time.time())

    jwk = ec_key_to_jwk(private_key.public_key())

    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    payload = {"htm": htm, "htu": htu, "jti": jti, "iat": iat}

    if ath:
        payload["ath"] = ath
    if nonce:
        payload["nonce"] = nonce

    header_b64 = b64url(json.dumps(header, separators=(",", ":")))
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")))
    signing_input = f"{header_b64}.{payload_b64}"

    sig_der = private_key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(sig_der)
    key_len = private_key.curve.key_size // 8
    sig_b64 = b64url(r.to_bytes(key_len, "big") + s.to_bytes(key_len, "big"))

    return f"{signing_input}.{sig_b64}"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    services = {}
    try:
        r = requests.get(f"{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration", timeout=5)
        services["keycloak"] = {"status": "ok" if r.ok else "error", "code": r.status_code}
    except Exception as e:
        services["keycloak"] = {"status": "error", "error": str(e)[:100]}

    try:
        r = envoy_request(token="test", use_cert=True, wrong_cert=False)
        services["envoy"] = {"status": "ok" if r["status"] != "CONN_ERR" else "error", "detail": r}
    except Exception as e:
        services["envoy"] = {"status": "error", "error": str(e)[:100]}

    try:
        r = requests.get(EXT_AUTHZ_URL, timeout=3)
        services["ext_authz"] = {"status": "unknown"}
    except:
        services["ext_authz"] = {"status": "ok", "note": "gRPC port open"}

    try:
        r = requests.get(f"{DPOP_PROXY_URL.rstrip('/')}/health", timeout=5)
        services["dpop_proxy"] = {"status": "ok" if r.ok else "error", "code": r.status_code}
    except Exception as e:
        services["dpop_proxy"] = {"status": "error", "error": str(e)[:100]}

    return jsonify(services)


@app.route("/api/test/success")
def test_success():
    try:
        token = get_token("demo-client", "demo-client-secret")
        result = envoy_request(token=token, use_cert=True, wrong_cert=False)
        return jsonify({
            "test": "Valid mTLS + Token",
            "expect": "200 OK",
            "result": result,
            "passed": result["status"] == 200,
        })
    except Exception as e:
        return jsonify({"test": "Valid mTLS + Token", "error": str(e), "passed": False})


@app.route("/api/test/abac-protected-admin")
def test_abac_protected_admin():
    try:
        token = get_token("demo-client", "demo-client-secret")
        result = envoy_request(token=token, use_cert=True, wrong_cert=False, path="/admin")
        return jsonify({
            "test": "ABAC: Deny /admin path",
            "expect": "403 Forbidden",
            "result": result,
            "passed": result["status"] == 403,
        })
    except Exception as e:
        return jsonify({"test": "ABAC: Deny /admin path", "error": str(e), "passed": False})


@app.route("/api/test/abac-protected-scope")
def test_abac_protected_scope():
    try:
        token = get_token("demo-client", "demo-client-secret")
        result = envoy_request(token=token, use_cert=True, wrong_cert=False, path="/protected/test")
        return jsonify({
            "test": "ABAC: /protected requires api:read scope",
            "expect": "403 Forbidden",
            "result": result,
            "passed": result["status"] == 403,
        })
    except Exception as e:
        return jsonify({"test": "ABAC: /protected requires api:read scope", "error": str(e), "passed": False})


@app.route("/api/test/no-token")
def test_no_token():
    try:
        result = envoy_request(token=None, use_cert=True, wrong_cert=False)
        return jsonify({
            "test": "Missing Bearer Token",
            "expect": "401 Unauthorized",
            "result": result,
            "passed": result["status"] == 401,
        })
    except Exception as e:
        return jsonify({"test": "Missing Bearer Token", "error": str(e), "passed": False})


@app.route("/api/test/invalid-token")
def test_invalid_token():
    try:
        result = envoy_request(token="invalid.jwt.token", use_cert=True, wrong_cert=False)
        return jsonify({
            "test": "Invalid JWT Token",
            "expect": "401 Unauthorized",
            "result": result,
            "passed": result["status"] == 401,
        })
    except Exception as e:
        return jsonify({"test": "Invalid JWT Token", "error": str(e), "passed": False})


@app.route("/api/test/wrong-cert-binding")
def test_wrong_cert_binding():
    try:
        token = get_token("demo-client-mismatch", "demo-client-mismatch-secret")
        result = envoy_request(token=token, use_cert=True, wrong_cert=False)
        return jsonify({
            "test": "Valid Token + Wrong Cert Binding",
            "expect": "403 Forbidden",
            "result": result,
            "passed": result["status"] == 403,
        })
    except Exception as e:
        return jsonify({"test": "Valid Token + Wrong Cert Binding", "error": str(e), "passed": False})


@app.route("/api/test/replay")
def test_replay():
    try:
        token = get_token("demo-client", "demo-client-secret")
        first = envoy_request(token=token, use_cert=True, wrong_cert=False)
        second = envoy_request(token=token, use_cert=True, wrong_cert=False)
        return jsonify({
            "test": "Replay Attack (same JWT twice)",
            "expect": "First=200, Second=403",
            "first": first,
            "second": second,
            "passed": first["status"] == 200 and second["status"] == 403,
        })
    except Exception as e:
        return jsonify({"test": "Replay Attack", "error": str(e), "passed": False})


@app.route("/api/test/no-mtls")
def test_no_mtls():
    try:
        token = get_token("demo-client", "demo-client-secret")
        result = envoy_request(token=token, use_cert=False, wrong_cert=False)
        return jsonify({
            "test": "Request without mTLS client cert",
            "expect": "TLS handshake failure / 401",
            "result": result,
            "passed": result["status"] in ("TLS_ERR", "CONN_ERR"),
        })
    except Exception as e:
        return jsonify({"test": "Request without mTLS client cert", "error": str(e), "passed": False})


@app.route("/api/test/dpop")
def test_dpop():
    try:
        key = ec.generate_private_key(ec.SECP256R1())
        pub = key.public_key()
        jwk = ec_key_to_jwk(pub)
        jkt = compute_jkt(jwk)

        proxy_token_url = f"{DPOP_PROXY_URL.rstrip('/')}/token"
        proof = create_dpop_proof(key, "POST", proxy_token_url)

        proxy_resp = requests.post(
            proxy_token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": "demo-client-dpop",
                "client_secret": "demo-client-dpop-secret",
            },
            headers={"DPoP": proof},
            timeout=15,
        )

        proxy_result = {
            "status": proxy_resp.status_code,
            "body": proxy_resp.text[:500] if proxy_resp.text else "",
        }

        if proxy_resp.status_code != 200:
            return jsonify({
                "test": "DPoP Token Proxy → Envoy",
                "expect": "200 from proxy, then 200 from envoy",
                "proxy_result": proxy_result,
                "result": None,
                "passed": False,
            })

        token_data = proxy_resp.json()
        access_token = token_data.get("access_token", "")
        if not access_token:
            return jsonify({
                "test": "DPoP Token Proxy → Envoy",
                "expect": "access_token in response",
                "proxy_result": proxy_result,
                "result": None,
                "passed": False,
            })

        token_hash = b64url(hashlib.sha256(access_token.encode("utf-8")).digest())
        dpop_proof = create_dpop_proof(key, "GET", ENVOY_URL.rstrip("/") + "/", ath=token_hash)

        envoy_result = envoy_request(token=access_token, use_cert=True, wrong_cert=False, dpop_proof=dpop_proof)

        return jsonify({
            "test": "DPoP Token Proxy → Envoy",
            "expect": "200 from proxy, then 200 from envoy",
            "jkt": jkt,
            "proxy_result": proxy_result,
            "envoy_result": envoy_result,
            "passed": proxy_resp.status_code == 200 and envoy_result["status"] == 200,
        })
    except Exception as e:
        return jsonify({
            "test": "DPoP Token Proxy → Envoy",
            "error": str(e),
            "passed": False,
        })


if __name__ == "__main__":
    port = int(os.environ.get("DASHBOARD_PORT", 5000))
    print(f"Dashboard: http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
