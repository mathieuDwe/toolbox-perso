import os
import sqlite3
import hashlib
import hmac
import binascii
from config.config import DB_PATH

# ===============================================================
#   UTILITAIRES
# ===============================================================

def generate_password_hash(password, iterations=100000):
    """Hash password using PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)
    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations
    )
    return f"pbkdf2:sha256:{iterations}${binascii.hexlify(salt).decode()}${binascii.hexlify(hash_bytes).decode()}"


def check_password_hash(hashed_password, password):
    """Verify a password against a hash."""
    try:
        method, algorithm, rest = hashed_password.split(":", 2)
        iterations, salt_hex, hash_hex = rest.split("$", 2)

        salt = binascii.unhexlify(salt_hex)
        expected_hash = binascii.unhexlify(hash_hex)

        test_hash = hashlib.pbkdf2_hmac(
            algorithm,
            password.encode("utf-8"),
            salt,
            int(iterations)
        )
        return hmac.compare_digest(expected_hash, test_hash)
    except (ValueError, TypeError):
        return False


# ===============================================================
#   CONNEXION DB
# ===============================================================

def get_connection():
    """Retourne une connexion SQLite."""
    conn = sqlite3.connect( DB_PATH)
    conn.row_factory = sqlite3.Row  # retourne des dict-like
    return conn


def test_db_connection():
    try:
        conn = get_connection()
        conn.execute("SELECT 1")
        conn.close()
        return True
    except Exception as e:
        print(f"Erreur de connexion DB : {e}")
        return False


# ===============================================================
#   INITIALISATION DB
# ===============================================================

def init_db():
    """Création DB + admin par défaut."""
    conn = get_connection()
    cur = conn.cursor()

    # Table users avec colonne role + created_at
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

    # Vérifie s'il existe déjà un utilisateur
    cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]

    # Création admin si DB vide
    if count == 0:
        hashed_pw = generate_password_hash("admin")
        cur.execute("""
            INSERT INTO users (username, password, role)
            VALUES (?, ?, ?)
        """, ("admin", hashed_pw, "admin"))

        conn.commit()
        print("✨ Utilisateur admin créé (admin / admin)")

    cur.close()
    conn.close()


# ===============================================================
#   CRUD UTILISATEURS
# ===============================================================

def add_user(username, password, role="user"):
    """Ajoute un utilisateur."""
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO users (username, password, role)
            VALUES (?, ?, ?)
        """, (username, generate_password_hash(password), role))

        conn.commit()
        return True

    except sqlite3.IntegrityError:
        return False

    finally:
        cur.close()
        conn.close()


def get_all_users():
    """Retourne tous les utilisateurs."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, username, role
        FROM users
        ORDER BY created_at DESC
    """)

    users = cur.fetchall()

    cur.close()
    conn.close()

    return users


def get_user_by_id(user_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, username, password, role
        FROM users
        WHERE id = ?
    """, (user_id,))

    row = cur.fetchone()

    cur.close()
    conn.close()

    return row


def get_user_by_username(username):
    """Utile pour le login."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, username, password, role
        FROM users
        WHERE username = ?
    """, (username,))

    row = cur.fetchone()

    cur.close()
    conn.close()

    return row


def update_user(user_id, username=None, password=None, role=None):
    """Met à jour un utilisateur."""

    conn = get_connection()
    cur = conn.cursor()

    updates = []
    params = []

    if username:
        updates.append("username = ?")
        params.append(username)

    if password:
        updates.append("password = ?")
        params.append(generate_password_hash(password))

    if role:
        updates.append("role = ?")
        params.append(role)

    if not updates:
        return False

    params.append(user_id)

    query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"

    try:
        cur.execute(query, params)
        conn.commit()
        success = cur.rowcount > 0
        return success

    except sqlite3.IntegrityError:
        return False

    finally:
        cur.close()
        conn.close()


def delete_user(user_id):
    """Supprime un utilisateur."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()

    success = cur.rowcount > 0

    cur.close()
    conn.close()

    return success


def count_users():
    """Retourne le nombre total d’utilisateurs."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]

    cur.close()
    conn.close()

    return count
