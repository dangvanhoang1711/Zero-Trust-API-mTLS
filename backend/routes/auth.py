from flask import Blueprint, request, jsonify, session

from services.keycloak import KeycloakService

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")
keycloak = KeycloakService()


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    try:
        token_data = keycloak.get_token(username, password)
        session["access_token"] = token_data["access_token"]
        response = jsonify({
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token"),
            "expires_in": token_data.get("expires_in"),
            "token_type": token_data.get("token_type"),
        })
        response.set_cookie(
            "access_token",
            token_data["access_token"],
            max_age=token_data.get("expires_in"),
            secure=True,
            httponly=True,
            samesite="Lax",
        )
        return response
    except Exception as e:
        return jsonify({"error": "Authentication failed", "detail": str(e)}), 401


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    firstName = data.get("firstName", username)
    lastName = data.get("lastName", "User")
    if not username or not password or not email:
        return jsonify({"error": "username, password, and email are required"}), 400

    try:
        keycloak.create_user(username, password, email, firstName, lastName)
        return jsonify({"message": f"User '{username}' created successfully"}), 201
    except Exception as e:
        return jsonify({"error": "Registration failed", "detail": str(e)}), 400


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    response = jsonify({"message": "Logged out successfully"})
    response.delete_cookie("access_token")
    return response
