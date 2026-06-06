from functools import wraps

from flask import Blueprint, jsonify, request, session, g

from services.jwt_validator import JWKSValidator
from routes.abac import abac_enforce

api_bp = Blueprint("api", __name__, url_prefix="/api")
validator = JWKSValidator()


def require_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token()
        if not token:
            return f"""
            <!DOCTYPE html>
            <html><head><meta charset="utf-8"><title>Access Denied</title></head>
            <body style="font-family: sans-serif; padding: 2rem; background: #fee; color: #900;">
                <h1>❌ Access Denied - No Token</h1>
                <p>Missing authorization token.</p>
            </body></html>
            """, 401
        try:
            g.token_payload = validator.verify_token(token)
        except Exception as e:
            return f"""
            <!DOCTYPE html>
            <html><head><meta charset="utf-8"><title>Access Denied</title></head>
            <body style="font-family: sans-serif; padding: 2rem; background: #fee; color: #900;">
                <h1>❌ Access Denied - Invalid Token</h1>
                <p>{str(e)}</p>
            </body></html>
            """, 401
        return f(*args, **kwargs)
    return decorated


def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = _extract_token()
            if not token:
                return f"""
                <!DOCTYPE html>
                <html><head><meta charset="utf-8"><title>Access Denied</title></head>
                <body style="font-family: sans-serif; padding: 2rem; background: #fee; color: #900;">
                    <h1>❌ Access Denied - No Token</h1>
                    <p>Missing authorization token.</p>
                </body></html>
                """, 401
            try:
                payload = validator.verify_token(token)
            except Exception as e:
                return f"""
                <!DOCTYPE html>
                <html><head><meta charset="utf-8"><title>Access Denied</title></head>
                <body style="font-family: sans-serif; padding: 2rem; background: #fee; color: #900;">
                    <h1>❌ Access Denied - Invalid Token</h1>
                    <p>{str(e)}</p>
                </body></html>
                """, 401
            roles = payload.get("realm_access", {}).get("roles", [])
            if role not in roles:
                return f"""
                <!DOCTYPE html>
                <html><head><meta charset="utf-8"><title>Access Denied</title></head>
                <body style="font-family: sans-serif; padding: 2rem; background: #fee; color: #900;">
                    <h1>❌ Access Denied - Insufficient Privileges</h1>
                    <p>This endpoint requires role <code>{role}</code>.</p>
                    <p>Your roles: <code>{", ".join(roles) if roles else "none"}</code></p>
                </body></html>
                """, 403
            g.token_payload = payload
            return f(*args, **kwargs)
        return decorated
    return decorator


def _extract_token():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return session.get("access_token")


@api_bp.route("/public", methods=["GET"])
def public():
    return """
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"><title>Public API</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #f0f9ff; color: #0369a1;">
        <h1>🌐 Public API</h1>
        <p>This endpoint is publicly accessible — no authentication required.</p>
    </body></html>
    """, 200


@api_bp.route("/profile", methods=["GET"])
@require_jwt
def profile():
    payload = g.token_payload
    roles = payload.get("realm_access", {}).get("roles", [])
    username = payload.get("preferred_username", "unknown")
    email = payload.get("email", "—")
    sub = payload.get("sub", "—")
    return f"""
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"><title>Profile</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #f0f9ff; color: #0369a1;">
        <h1>👤 Profile</h1>
        <p>User: <strong>{username}</strong></p>
        <ul>
            <li>Email: <code>{email}</code></li>
            <li>Subject: <code>{sub}</code></li>
            <li>Roles: <code>{", ".join(roles)}</code></li>
            <li>Issuer: <code>{payload.get("iss", "—")}</code></li>
        </ul>
    </body></html>
    """, 200


@api_bp.route("/user-data", methods=["GET"])
@require_role("user")
@abac_enforce("user-data-weekday")
def user_data():
    payload = g.token_payload
    roles = payload.get("realm_access", {}).get("roles", [])
    username = payload.get("preferred_username", "unknown")
    return f"""
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"><title>User Data</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #f0fdf4; color: #166534;">
        <h1>✅ Access Success - User Data</h1>
        <p>Welcome, <strong>{username}</strong>!</p>
        <p>Rule <strong>user-data-weekday</strong> matched — weekday access granted.</p>
        <ul>
            <li>Roles: <code>{", ".join(roles)}</code></li>
        </ul>
    </body></html>
    """, 200


@api_bp.route("/admin-data", methods=["GET"])
@require_role("admin")
@abac_enforce("admin-business-hours")
def admin_data():
    payload = g.token_payload
    username = payload.get("preferred_username", "unknown")
    import datetime
    from zoneinfo import ZoneInfo
    now = datetime.datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))
    return f"""
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"><title>Admin Data</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #f0fdf4; color: #166534;">
        <h1>✅ Access Success - Admin Data</h1>
        <p>Welcome, <strong>{username}</strong>!</p>
        <p>Rule <strong>admin-business-hours</strong> matched — business hours access granted.</p>
        <ul>
            <li>Current time (VN): <code>{now.strftime("%H:%M:%S %A")}</code></li>
        </ul>
    </body></html>
    """, 200


@api_bp.route("/protected", methods=["GET"])
@require_jwt
@abac_enforce("protected-api")
def protected_api():
    payload = g.token_payload
    roles = payload.get("realm_access", {}).get("roles", [])
    scope = payload.get("scope", "")
    username = payload.get("preferred_username", "unknown")
    return f"""
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"><title>Protected API</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #f0fdf4; color: #166534;">
        <h1>✅ Access Success - Protected API</h1>
        <p>Welcome, <strong>{username}</strong>!</p>
        <p>Rule <strong>protected-api</strong> matched — <code>protected-reader</code> role verified.</p>
        <ul>
            <li>Roles: <code>{", ".join(roles)}</code></li>
            <li>Scope: <code>{scope}</code></li>
        </ul>
    </body></html>
    """, 200


@api_bp.route("/jwt-info", methods=["GET"])
@require_jwt
def jwt_info():
    import datetime
    token = _extract_token()
    raw_payload = validator.get_payload(token)
    roles = raw_payload.get("realm_access", {}).get("roles", [])
    scope = raw_payload.get("scope", "")
    username = raw_payload.get("preferred_username", "unknown")
    email = raw_payload.get("email", "—")
    sub = raw_payload.get("sub", "—")
    iss = raw_payload.get("iss", "—")
    exp = raw_payload.get("exp")
    exp_str = datetime.datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M:%S") if exp else "—"
    roles_html = "".join(f"<li><code>{r}</code></li>" for r in roles)
    scope_items = "".join(f"<li><code>{s}</code></li>" for s in scope.split())
    return f"""
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"><title>JWT Info</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #f8fafc; color: #1e293b;">
        <h1>🔑 JWT Info</h1>
        <table style="border-collapse: collapse; font-size: 0.9rem;">
            <tr><td style="padding: 0.3rem 1rem 0.3rem 0; color: #64748b;">User</td><td><strong>{username}</strong></td></tr>
            <tr><td style="padding: 0.3rem 1rem 0.3rem 0; color: #64748b;">Email</td><td><code>{email}</code></td></tr>
            <tr><td style="padding: 0.3rem 1rem 0.3rem 0; color: #64748b;">Subject</td><td><code>{sub}</code></td></tr>
            <tr><td style="padding: 0.3rem 1rem 0.3rem 0; color: #64748b;">Issuer</td><td><code>{iss}</code></td></tr>
            <tr><td style="padding: 0.3rem 1rem 0.3rem 0; color: #64748b;">Expires</td><td><code>{exp_str}</code></td></tr>
            <tr><td style="padding: 0.3rem 1rem 0.3rem 0; color: #64748b; vertical-align: top;">Roles</td><td><ul style="margin:0; padding-left:1.2rem;">{roles_html}</ul></td></tr>
            <tr><td style="padding: 0.3rem 1rem 0.3rem 0; color: #64748b; vertical-align: top;">Scope</td><td><ul style="margin:0; padding-left:1.2rem;">{scope_items}</ul></td></tr>
        </table>
    </body></html>
    """, 200
