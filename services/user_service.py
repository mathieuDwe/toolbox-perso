from flask import flash
from werkzeug.security import check_password_hash, generate_password_hash
from database.init_db import (
    get_user_by_id,
    get_user_by_username,
    get_all_users,
    add_user,
    update_user,
    delete_user
)

# ============================================================
#   AUTHENTIFICATION
# ============================================================

def authenticate_user(username, password):
    """
    Vérifie username/password et retourne un dict user si OK.
    Retourne None si mauvais identifiants.
    """
    user = get_user_by_username(username)
    
    if not user:
        return None

    user_id, username_db, hashed_pw, role = user

    if not check_password_hash(hashed_pw, password):
        return None

    return {
        "id": user_id,
        "username": username_db,
        "role": role
    }


# ============================================================
#   UTILISATEURS — CRUD
# ============================================================

def service_get_user(user_id):
    """Retourne un utilisateur sous forme de dict."""
    row = get_user_by_id(user_id)

    if not row:
        return None

    return {
        "id": row["id"] if "id" in row.keys() else row[0],
        "username": row["username"] if "username" in row.keys() else row[1],
        "password": row["password"] if "password" in row.keys() else row[2],
        "role": row["role"] if "role" in row.keys() else row[3],
    }


def service_get_all_users():
    """Retourne tous les users sous forme exploitable par Flask/JSON."""
    rows = get_all_users()
    users = []

    for u in rows:
        users.append({
            "id": u[0],
            "username": u[1],
            "role": u[2],
        })

    return users


def service_create_user(username, password, role="user"):
    """
    Crée un utilisateur.
    Retourne True si OK / False si username existe déjà.
    """
    print("Creating user:", username, role)
    success = add_user(username, password, role)
    if success:
        flash("Utilisateur ajouté avec succès!")       
        return success
    else:
        flash("Erreur: le nom d'utilisateur existe déjà.")
        return success



def service_update_user(user_id, username=None, password=None, role=None):
    """
    Modifie un utilisateur.
    Retourne True si OK, False si erreur ou username existe déjà.
    """
    return update_user(user_id, username, password, role)


def service_delete_user(user_id):
    """Supprime un utilisateur."""
    return delete_user(user_id)


# ============================================================
#   OUTILS
# ============================================================

def user_exists(username):
    """Vérifie si un user existe."""
    return get_user_by_username(username) is not None


