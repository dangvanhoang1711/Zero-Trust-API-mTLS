from functools import wraps

from flask import Blueprint, jsonify, request, session, g

from services.jwt_validator import JWKSValidator

api_bp = Blueprint("api", __name__, url_prefix="/api")
validator = JWKSValidator()


def require_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token()
        if not token:
            return jsonify({"error": "Missing authorization token"}), 401
        try:
            g.token_payload = validator.verify_token(token)
        except Exception as e:
            return jsonify({"error": "Invalid token", "detail": str(e)}), 401
        return f(*args, **kwargs)
    return decorated


def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = _extract_token()
            if not token:
                return jsonify({"error": "Missing authorization token"}), 401
            try:
                payload = validator.verify_token(token)
            except Exception as e:
                return jsonify({"error": "Invalid token", "detail": str(e)}), 401
            roles = payload.get("realm_access", {}).get("roles", [])
            if role not in roles:
                return jsonify({"error": "Insufficient privileges"}), 403
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
    return jsonify({"message": "public"})


@api_bp.route("/profile", methods=["GET"])
@require_jwt
def profile():
    return jsonify(g.token_payload)


@api_bp.route("/user-data", methods=["GET"])
@require_role("user")
def user_data():
    return jsonify({
        "message": "User data",
        "data": {
            "id": "usr_001",
            "name": "Sample User",
            "email": "user@example.com",
            "items": ["item_a", "item_b", "item_c"],
        },
    })


@api_bp.route("/admin-data", methods=["GET"])
@require_role("admin")
def admin_data():
    return jsonify({
        "message": "Admin data",
        "data": {
            "id": "adm_001",
            "name": "Sample Admin",
            "email": "admin@example.com",
            "permissions": ["read", "write", "delete"],
            "users_managed": 42,
        },
    })


@api_bp.route("/jwt-info", methods=["GET"])
@require_jwt
def jwt_info():
    token = _extract_token()
    raw_payload = validator.get_payload(token)
    return jsonify({
        "payload": raw_payload,
        "token_preview": token[:50] + "...",
    })
