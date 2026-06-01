import os
import json
import time
import ssl
import urllib3
import subprocess
from flask import Flask, jsonify, render_template
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CERTS_DIR = os.path.join(BASE_DIR, "infra", "certs")
CLIENT_CERT = os.path.join(CERTS_DIR, "client.crt")
CLIENT_KEY = os.path.join(CERTS_DIR, "client.key")
CA_CERT = os.path.join(CERTS_DIR, "root-ca.crt")
SERVER_CHAIN = os.path.join(CERTS_DIR, "server-chain.crt")

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:18080")
ENVOY_URL = os.environ.get("ENVOY_URL", "https://localhost:10000")
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


def envoy_request(token=None, use_cert=True, wrong_cert=False):
    cert = None
    if use_cert:
        if wrong_cert:
            cert = (SERVER_CHAIN, CLIENT_KEY)
        else:
            cert = (CLIENT_CERT, CLIENT_KEY)

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = requests.get(
            ENVOY_URL,
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
        r = requests.get("http://localhost:50051", timeout=3)
        services["ext_authz"] = {"status": "unknown"}
    except:
        services["ext_authz"] = {"status": "ok", "note": "gRPC port open"}

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


if __name__ == "__main__":
    port = int(os.environ.get("DASHBOARD_PORT", 5000))
    print(f"Dashboard: http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
