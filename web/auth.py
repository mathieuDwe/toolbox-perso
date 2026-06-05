from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from api.v1.auth import update_user
from services.user_service import authenticate_user, service_get_user
from functools import wraps
from werkzeug.security import generate_password_hash
from database.init_db import get_connection, update_user
# Créer le blueprint
web_auth_bp = Blueprint(
    "web_auth",
    __name__,
    template_folder="templates",
    static_folder="static",
    url_prefix="/web"
)


# Décorateur
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('web_auth.login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@web_auth_bp.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('web_auth.dashboard'))
    return redirect(url_for('web_auth.login'))

@web_auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = authenticate_user(username, password)
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Bienvenue {user["username"]} !', 'success')
            return redirect(url_for('web_auth.dashboard'))
        else:
            flash('Identifiants incorrects', 'error')
    
    return render_template('auth/login.html')

@web_auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Vous avez été déconnecté', 'info')
    return redirect(url_for('web_auth.login'))

@web_auth_bp.route('/dashboard')
@login_required
def dashboard():
    user = service_get_user(session['user_id'])
    return render_template('dashboard/dashboard.html', user=user)


@web_auth_bp.route("/profile")
@login_required
def profile():
    user = service_get_user(session['user_id'])
    return render_template("auth/profile.html", user=user)




@web_auth_bp.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('web_auth.login'))

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        
        if not new_username or not new_password:
            flash("Veuillez remplir tous les champs.")
            return redirect(url_for('web_auth.update_profile'))

        hashed = generate_password_hash(new_password)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET username = ?, password = ? WHERE id = ?",
            (new_username, hashed, user_id)
        )
        conn.commit()
        cursor.close()
        conn.close()

        # Met à jour la session
        session['username'] = new_username

        flash("Profil mis à jour avec succès.")
        return redirect(url_for('web_auth.profile'))

    # Récupère l'utilisateur pour l'afficher dans le formulaire
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    user = {"username": row[0]} if row else None

    return render_template('auth/update_profile.html', user=user)






