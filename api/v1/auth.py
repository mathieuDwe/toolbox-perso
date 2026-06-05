from flask import Blueprint, redirect, request, jsonify, session, url_for
from services.user_service import (
    authenticate_user,
    service_get_user,
    service_get_all_users,
    service_create_user,
    service_update_user,
    service_delete_user
)

auth_bp = Blueprint("auth", __name__)


# =====================================================
#   LOGIN
# =====================================================

@auth_bp.post("/login")
def login():
    data = request.json or {}

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username/password"}), 400

    user = authenticate_user(username, password)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = user["id"]
    session["role"] = user["role"]

    return jsonify({"message": "Logged in", "user": user})


# =====================================================
#   LOGGED USER INFO
# =====================================================

@auth_bp.get("/me")
def me():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user = service_get_user(session["user_id"])
    return jsonify(user.to_dict())


# =====================================================
#   LOGOUT
# =====================================================

@auth_bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# =====================================================
#   ADMIN : LIST USERS
# =====================================================

@auth_bp.get("/users")
def list_users():
    if session.get("role") != "admin":
        return jsonify({"error": "Admin only"}), 403

    users = service_get_all_users()
    return jsonify(users)


# =====================================================
#   ADMIN : CREATE USER
# =====================================================

@auth_bp.post("/users")
def create_user():
    if session.get("role") != "admin":
        return jsonify({"error": "Admin only"}), 403

    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")

    if not username or not password:
        return jsonify({"error": "Missing username/password"}), 400

    success = service_create_user(username, password, role)
    if not success:
        return jsonify({"error": "User already exists"}), 409

    return jsonify({"message": "User created"}), 201


# =====================================================
#   ADMIN : UPDATE USER
# =====================================================

@auth_bp.put("/users/<int:user_id>")
def update_user(user_id, username, password, role=None):
    if session.get("role") != "admin":
        return jsonify({"error": "Admin only"}), 403

    data = request.json or {}
    success = service_update_user(
        user_id,
        username=data.get("username"),
        password=data.get("password"),
        role=data.get("role")
    )

    if not success:
        return jsonify({"error": "Update failed"}), 400

    return jsonify({"message": "User updated"})


# =====================================================
#   ADMIN : DELETE USER
# =====================================================

@auth_bp.delete("/users/<int:user_id>")
def remove_user(user_id):
    if session.get("role") != "admin":
        return jsonify({"error": "Admin only"}), 403

    success = service_delete_user(user_id)
    if not success:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "User deleted"})

# =====================================================
#   UPDATE LOGGED USER PROFILE
@auth_bp.put("/me")
def update_profile(user_id, new_username, new_password):
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.json or {}
    username = data.get("username")
    password = data.get("password")

    success = service_update_user(
        session["user_id"],
        username=username,
        password=password
    )

    if not success:
        return jsonify({"error": "Update failed"}), 400

    return jsonify({"message": "Profile updated"})