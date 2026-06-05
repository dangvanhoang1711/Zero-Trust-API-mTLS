import os
import json
import time
import requests
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "zero-trust-frontend-secret-key")

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
REALM = "zero-trust"
CLIENT_ID = "web-app"
KEYCLOAK_ADMIN_USER = os.environ.get("KEYCLOAK_ADMIN", "admin")
KEYCLOAK_ADMIN_PASS = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")

TOKEN_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
ADMIN_TOKEN_URL = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
ADMIN_USERS_URL = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"
ADMIN_ROLES_URL = f"{KEYCLOAK_URL}/admin/realms/{REALM}/roles"

_jwks_cache = {"keys": None, "fetched": 0}
_JWKS_TTL = 300

def fetch_jwks():
    now = time.time()
    if not _jwks_cache["keys"] or now - _jwks_cache["fetched"] > _JWKS_TTL:
        resp = requests.get(JWKS_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        _jwks_cache["keys"] = {k["kid"]: k for k in data.get("keys", [])}
        _jwks_cache["fetched"] = now
    return _jwks_cache["keys"]

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64
import hashlib

def b64url_decode(data):
    pad = 4 - len(data) % 4
    if pad != 4:
        data += "=" * pad
    return base64.urlsafe_b64decode(data)

def validate_jwt(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        header = json.loads(b64url_decode(header_b64).decode("utf-8"))
        kid = header.get("kid")
        if not kid:
            return None
        jwks = fetch_jwks()
        jwk = jwks.get(kid)
        if not jwk:
            return None
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            return None
        x = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(jwk["y"]), "big")
        public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(default_backend())

        message = f"{header_b64}.{payload_b64}".encode("utf-8")
        sig_raw = b64url_decode(sig_b64)
        sig_len = len(sig_raw) // 2
        r = int.from_bytes(sig_raw[:sig_len], "big")
        s = int.from_bytes(sig_raw[sig_len:], "big")
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        sig_der = encode_dss_signature(r, s)
        public_key.verify(sig_der, message, ec.ECDSA(hashes.SHA256()))
        payload = json.loads(b64url_decode(payload_b64).decode("utf-8"))
        return payload
    except Exception:
        return None

def get_admin_token():
    resp = requests.post(
        ADMIN_TOKEN_URL,
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": KEYCLOAK_ADMIN_USER,
            "password": KEYCLOAK_ADMIN_PASS,
        },
        timeout=10,
    )
    if resp.status_code != 200:
        return None
    return resp.json()["access_token"]

def get_token_via_password(username, password):
    resp = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "username": username,
            "password": password,
        },
        timeout=10,
    )
    if resp.status_code != 200:
        return None, resp.text
    data = resp.json()
    return data, None

@app.route("/")
def index():
    if "token" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Vui lòng nhập tên đăng nhập và mật khẩu", "error")
            return render_template("login.html")
        data, error = get_token_via_password(username, password)
        if error or not data:
            flash("Sai tên đăng nhập hoặc mật khẩu", "error")
            return render_template("login.html")
        payload = validate_jwt(data["access_token"])
        if not payload:
            flash("Token không hợp lệ từ Keycloak", "error")
            return render_template("login.html")
        session["token"] = data["access_token"]
        session["refresh_token"] = data.get("refresh_token")
        session["username"] = username
        session["payload"] = payload
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not all([username, email, password, confirm]):
            flash("Vui lòng nhập đầy đủ thông tin", "error")
            return render_template("register.html")
        if password != confirm:
            flash("Mật khẩu xác nhận không khớp", "error")
            return render_template("register.html")
        if len(password) < 3:
            flash("Mật khẩu phải có ít nhất 3 ký tự", "error")
            return render_template("register.html")
        admin_token = get_admin_token()
        if not admin_token:
            flash("Lỗi hệ thống, vui lòng thử lại sau", "error")
            return render_template("register.html")
        new_user = {
            "username": username,
            "email": email,
            "firstName": username,
            "lastName": username,
            "enabled": True,
            "emailVerified": True,
            "credentials": [
                {"type": "password", "value": password, "temporary": False}
            ],
        }
        headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}
        resp = requests.post(ADMIN_USERS_URL, json=new_user, headers=headers, timeout=10)
        if resp.status_code not in (201, 200, 204):
            err_text = resp.text[:200]
            if "already exists" in err_text.lower():
                flash("Tên đăng nhập đã tồn tại", "error")
            else:
                flash(f"Đăng ký thất bại: {err_text}", "error")
            return render_template("register.html")

        # Get user ID and assign 'user' role
        users_resp = requests.get(
            f"{ADMIN_USERS_URL}?username={username}",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=10,
        )
        if users_resp.status_code == 200:
            users_data = users_resp.json()
            if users_data:
                uid = users_data[0]["id"]
                roles_resp = requests.get(
                    KEYCLOAK_URL + f"/admin/realms/{REALM}/roles/user",
                    headers={"Authorization": f"Bearer {admin_token}"},
                    timeout=10,
                )
                if roles_resp.status_code == 200:
                    role_data = roles_resp.json()
                    requests.post(
                        KEYCLOAK_URL + f"/admin/realms/{REALM}/users/{uid}/role-mappings/realm",
                        headers={"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"},
                        json=[{"id": role_data["id"], "name": "user"}],
                        timeout=10,
                    )

        flash("Đăng ký thành công! Vui lòng đăng nhập.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    if "token" not in session or "payload" not in session:
        return redirect(url_for("login"))
    payload = session["payload"]
    roles = payload.get("realm_access", {}).get("roles", [])
    scope_claims = payload.get("scope", "").split()
    return render_template(
        "dashboard.html",
        username=session.get("username", ""),
        payload=payload,
        roles=roles,
        scopes=scope_claims,
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/api/public")
def api_public():
    return jsonify({
        "service": "Zero-Trust API Gateway",
        "version": "1.0.0",
        "status": "running",
        "message": "Public endpoint - không yêu cầu xác thực",
    })

@app.route("/api/profile")
def api_profile():
    if "token" not in session or "payload" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    payload = session["payload"]
    roles = payload.get("realm_access", {}).get("roles", [])
    return jsonify({
        "username": session.get("username"),
        "roles": roles,
        "email": payload.get("email", ""),
        "sub": payload.get("sub", ""),
        "message": "Profile cá nhân — yêu cầu JWT hợp lệ",
    })

@app.route("/api/user-data")
def api_user_data():
    if "token" not in session or "payload" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    payload = session["payload"]
    roles = payload.get("realm_access", {}).get("roles", [])
    if "user" not in roles:
        return jsonify({"error": "Forbidden — cần role 'user'", "your_roles": roles}), 403
    return jsonify({
        "data": [
            {"id": 1, "title": "Báo cáo tài chính Q1", "content": "Doanh thu tăng 15% so với cùng kỳ"},
            {"id": 2, "title": "Tài liệu dự án", "content": "Yêu cầu mock data cho zero-trust demo"},
            {"id": 3, "title": "Hồ sơ nhân viên", "content": "25 nhân viên, 3 phòng ban"},
        ],
        "message": "Dữ liệu người dùng — yêu cầu role 'user'",
        "your_roles": roles,
    })

@app.route("/api/admin-data")
def api_admin_data():
    if "token" not in session or "payload" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    payload = session["payload"]
    roles = payload.get("realm_access", {}).get("roles", [])
    if "admin" not in roles:
        return jsonify({"error": "Forbidden — cần role 'admin'", "your_roles": roles}), 403
    return jsonify({
        "data": [
            {"id": 1, "title": "Cấu hình hệ thống", "secret": "admin-zerotrust-secret-key"},
            {"id": 2, "title": "Danh sách người dùng", "users": ["admin", "demo-user"]},
            {"id": 3, "title": "Nhật ký kiểm toán", "entries": 1284, "last_event": "2026-06-04T12:00:00Z"},
            {"id": 4, "title": "Vault PKI Health", "status": "healthy", "certificates_issued": 42},
        ],
        "message": "Dữ liệu quản trị — yêu cầu role 'admin'",
        "your_roles": roles,
    })

@app.route("/api/jwt-info")
def api_jwt_info():
    if "token" not in session or "payload" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "username": session.get("username"),
        "payload": session["payload"],
        "token_preview": session["token"][:60] + "...",
    })

@app.route("/api/check-auth")
def api_check_auth():
    if "token" not in session:
        return jsonify({"authenticated": False}), 401
    return jsonify({
        "authenticated": True,
        "username": session.get("username"),
        "roles": session.get("payload", {}).get("realm_access", {}).get("roles", []),
    })

if __name__ == "__main__":
    port = int(os.environ.get("FRONTEND_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
