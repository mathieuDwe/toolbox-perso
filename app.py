from flask import Flask, redirect, render_template, request, session, url_for
from flask_cors import CORS

from config.config import SECRET_KEY, DEBUG, FLASK_HOST, FLASK_PORT
from database.init_db import init_db

# Blueprints API
from api.v1.auth import auth_bp
from api.v1.scans import scans_bp
from api.v1.reports import reports_bp

# Blueprints WEB
from web.auth import web_auth_bp
from web.scans import web_scans_bp
from web.admin import web_admin_bp
from web.reports import web_reports_bp

def create_app():
    app = Flask(__name__, template_folder='interface/templates')
    app.secret_key = SECRET_KEY
    app.config['DEBUG'] = DEBUG

    CORS(app)
    init_db()

    # ===== MIDDLEWARE POUR FORCER LOGIN =====
    @app.before_request
    def require_login():
        # Autoriser les fichiers statiques
        if request.path.startswith("/static"):
            return

        # Autoriser toutes les routes du blueprint web_auth (login, register, logout…)
        if request.endpoint and request.endpoint.startswith("web_auth."):
            return

        # Autoriser les routes d'API auth
        if request.endpoint and request.endpoint.startswith("auth."):
            return

        # Si utilisateur connecté → OK
        if session.get("user_id"):
            return

        # Sinon → redirection login
        return redirect(url_for("web_auth.login"))

    # ===== ROUTE TEST/PROFILE =====
    @app.route("/profile")
    def profile():
        return render_template("profile.html")

    # ===== BLUEPRINTS API =====
    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(scans_bp, url_prefix="/api/v1/scans")
    app.register_blueprint(reports_bp, url_prefix="/api/v1/reports")

    # ===== BLUEPRINTS WEB =====
    app.register_blueprint(web_auth_bp)            # routes /login, /logout etc.
    app.register_blueprint(web_scans_bp)           # routes /scan/*
    app.register_blueprint(web_admin_bp)           # routes /admin/*
    app.register_blueprint(web_reports_bp, url_prefix="/reports")  # /reports/*

    return app


# ===== APPLICATION =====
app = create_app()

if __name__ == "__main__":
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=DEBUG)
