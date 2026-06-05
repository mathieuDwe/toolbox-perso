# config.py

import os

# Chemin vers la base de données SQLite
DB_PATH = os.environ.get("DB_PATH", r"C:\Users\Mathi\Documents\cours\fil rouge\Pentool\pentestDB.db")

# Clé secrète Flask (pour les sessions, le CSRF, etc.)
SECRET_KEY = os.environ.get("SECRET_KEY", "5565fcf40c9b3fa0232c8d9ead83275fe68d27ebb10c1e008d2ab5d38725f11d")

# Mode debug Flask
DEBUG = os.environ.get("FLASK_DEBUG", "True") == "True"

# Configuration du port et de l'hôte Flask (optionnel)
FLASK_HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.environ.get("FLASK_PORT", 5000))

# Paramètres de sécurité supplémentaires (optionnels)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = False  # Passe à True si tu utilises HTTPS
REMEMBER_COOKIE_DURATION = 3600  # Durée en secondes

# Exemple d'ajout d'autres paramètres (ex : pagination, logs, etc.)
ITEMS_PER_PAGE = 20
LOG_FILE = os.environ.get("LOG_FILE", "pentest.log")