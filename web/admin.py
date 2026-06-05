"""
Blueprint Web pour l'administration
Gestion des utilisateurs, statistiques, configuration système
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
from datetime import datetime
import os

# Import des services
from services.user_service import (
    service_get_user,
    service_get_all_users,
    service_create_user,
    service_update_user,
    service_delete_user
)

from database.init_db import count_users, get_all_users, get_user_by_id

# ============================================================
#   CRÉATION DU BLUEPRINT
# ============================================================

web_admin_bp = Blueprint('web_admin', __name__, url_prefix='/admin')


# ============================================================
#   DÉCORATEURS
# ============================================================

def login_required(f):
    """Vérifie que l'utilisateur est connecté"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Vous devez être connecté pour accéder à cette page', 'error')
            return redirect(url_for('web_auth.login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Vérifie que l'utilisateur est administrateur"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Vous devez être connecté pour accéder à cette page', 'error')
            return redirect(url_for('web_auth.login'))
        
        if session.get('role') != 'admin':
            flash('Accès réservé aux administrateurs', 'error')
            return redirect(url_for('web_auth.dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function


# ============================================================
#   ROUTES PRINCIPALES
# ============================================================

@web_admin_bp.route('/')
@admin_required
def admin_dashboard():
    user_data = get_user_by_id(session.get('user_id'))
    username = user_data[0] if user_data else "Utilisateur"
    role = user_data[1] if user_data and len(user_data) > 1 else "user"
    print(user_data)
    if user_data[1] != 'admin':
        flash("Accès refusé")
        print(user_data)
        return redirect(url_for('dashboard'))
    
    users = get_all_users()
    admin_count = sum(1 for u in users if u[2] == 'admin')
    user_count = len(users) - admin_count
    
    return render_template('admin/admin.html', users=users, admin_count=admin_count,user_count=user_count,user={"username": username, "role": role})


# ============================================================
#   GESTION DES UTILISATEURS - CRUD
# ============================================================

@web_admin_bp.route('/users')
@admin_required
def list_users():
    """
    Liste tous les utilisateurs (API JSON)
    Utilisé pour les requêtes AJAX
    """
    try:
        users = service_get_all_users()
        return jsonify({
            'success': True,
            'users': users,
            'count': len(users)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@web_admin_bp.route('/users/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    """
    Ajouter un nouvel utilisateur
    GET: Affiche le formulaire
    POST: Crée l'utilisateur
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', 'user')   
        # Validation
        if not username or not password:
            print("Validation failed: Missing username or password")
            flash('Le nom d\'utilisateur et le mot de passe sont obligatoires', 'error')
            return redirect(url_for('web_admin.admin_dashboard'))
        
        if len(username) < 3:
            print("Validation failed: Username too short")
            flash('Le nom d\'utilisateur doit contenir au moins 3 caractères', 'error')
            return redirect(url_for('web_admin.admin_dashboard'))
        
        if len(password) < 4:
            print("Validation failed: Password too short")
            flash('Le mot de passe doit contenir au moins 4 caractères', 'error')
            return redirect(url_for('web_admin.admin_dashboard'))
        
        if role not in ['user', 'admin']:
            print("Validation failed: Invalid role")
            flash('Rôle invalide', 'error')
            return redirect(url_for('web_admin.admin_dashboard'))
        
        # Création de l'utilisateur
        try:
            print("Creating user:", username, role)
            if service_create_user(username, password, role):
                print("User created successfully")
                flash(f'Utilisateur "{username}" créé avec succès avec le rôle "{role}"', 'success')
                
                # Log de l'action
                log_admin_action('CREATE_USER', f'Création de l\'utilisateur {username}')
            else:
                flash(f'Erreur: l\'utilisateur "{username}" existe déjà', 'error')
        except Exception as e:
            flash(f'Erreur lors de la création de l\'utilisateur: {str(e)}', 'error')
        
        return redirect(url_for('web_admin.admin_dashboard'))
    
    # GET: Afficher le formulaire
    return render_template('add_user.html')


@web_admin_bp.route('/users/edit', methods=['POST'])
@admin_required
def admin_edit_user():
    """
    Modifier un utilisateur existant
    """
    try:
        user_id = request.form.get('user_id')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role')
        
        # Validation
        if not user_id:
            flash('ID utilisateur manquant', 'error')
            return redirect(url_for('web_admin.admin_dashboard'))
        
        user_id = int(user_id)
        
        # Empêcher la modification de son propre rôle
        if user_id == session['user_id'] and role != session['role']:
            flash('Vous ne pouvez pas modifier votre propre rôle', 'error')
            return redirect(url_for('web_admin.admin_dashboard'))
        
        # Vérification du dernier admin
        if role == 'user':
            users = service_get_all_users()
            admin_count = len([u for u in users if u['role'] == 'admin'])
            current_user = service_get_user(user_id)
            
            if current_user and current_user['role'] == 'admin' and admin_count <= 1:
                flash('Impossible de retirer les privilèges admin : il doit y avoir au moins un administrateur', 'error')
                return redirect(url_for('web_admin.admin_dashboard'))
        
        # Mise à jour
        update_password = password if password else None
        
        if service_update_user(user_id, username=username, password=update_password, role=role):
            flash(f'Utilisateur modifié avec succès', 'success')
            
            # Log de l'action
            log_admin_action('UPDATE_USER', f'Modification de l\'utilisateur ID {user_id}')
        else:
            flash('Erreur lors de la modification de l\'utilisateur', 'error')
    
    except ValueError:
        flash('ID utilisateur invalide', 'error')
    except Exception as e:
        flash(f'Erreur lors de la modification: {str(e)}', 'error')
    
    return redirect(url_for('web_admin.admin_dashboard'))


@web_admin_bp.route('/users/delete', methods=['POST'])
@admin_required
def admin_delete_user():
    """
    Supprimer un utilisateur
    """
    try:
        user_id = request.form.get('user_id')
        
        if not user_id:
            flash('ID utilisateur manquant', 'error')
            return redirect(url_for('web_admin.admin_dashboard'))
        
        user_id = int(user_id)
        
        # Empêcher la suppression de son propre compte
        if user_id == session['user_id']:
            flash('Vous ne pouvez pas supprimer votre propre compte', 'error')
            return redirect(url_for('web_admin.admin_dashboard'))
        
        # Vérifier qu'on ne supprime pas le dernier admin
        user_to_delete = service_get_user(user_id)
        
        if user_to_delete and user_to_delete['role'] == 'admin':
            users = service_get_all_users()
            admin_count = len([u for u in users if u['role'] == 'admin'])
            
            if admin_count <= 1:
                flash('Impossible de supprimer le dernier administrateur du système', 'error')
                return redirect(url_for('web_admin.admin_dashboard'))
        
        # Suppression
        if service_delete_user(user_id):
            username = user_to_delete['username'] if user_to_delete else 'inconnu'
            flash(f'Utilisateur "{username}" supprimé avec succès', 'success')
            
            # Log de l'action
            log_admin_action('DELETE_USER', f'Suppression de l\'utilisateur {username}')
        else:
            flash('Erreur lors de la suppression de l\'utilisateur', 'error')
    
    except ValueError:
        flash('ID utilisateur invalide', 'error')
    except Exception as e:
        flash(f'Erreur lors de la suppression: {str(e)}', 'error')
    
    return redirect(url_for('web_admin.admin_dashboard'))


@web_admin_bp.route('/users/<int:user_id>')
@admin_required
def view_user(user_id):
    """
    Voir les détails d'un utilisateur
    """
    try:
        user = service_get_user(user_id)
        
        if not user:
            flash('Utilisateur introuvable', 'error')
            return redirect(url_for('web_admin.admin_dashboard'))
        
        # Récupérer les statistiques de l'utilisateur (scans, etc.)
        user_stats = get_user_statistics(user_id)
        
        return render_template('user_details.html', user=user, stats=user_stats)
    
    except Exception as e:
        flash(f'Erreur lors du chargement des détails: {str(e)}', 'error')
        return redirect(url_for('web_admin.admin_dashboard'))


# ============================================================
#   STATISTIQUES ET MONITORING
# ============================================================

@web_admin_bp.route('/stats')
@admin_required
def system_stats():
    """
    Statistiques système complètes
    """
    try:
        stats = {
            'users': {
                'total': count_users(),
                'admins': len([u for u in service_get_all_users() if u['role'] == 'admin']),
                'regular': len([u for u in service_get_all_users() if u['role'] == 'user'])
            },
            'scans': get_scan_statistics(),
            'system': get_system_info()
        }
        
        return render_template('admin_stats.html', stats=stats)
    
    except Exception as e:
        flash(f'Erreur lors du chargement des statistiques: {str(e)}', 'error')
        return redirect(url_for('web_admin.admin_dashboard'))


@web_admin_bp.route('/logs')
@admin_required
def view_logs():
    """
    Voir les logs d'activité admin
    """
    try:
        logs = get_admin_logs()
        return render_template('admin_logs.html', logs=logs)
    except Exception as e:
        flash(f'Erreur lors du chargement des logs: {str(e)}', 'error')
        return redirect(url_for('web_admin.admin_dashboard'))


# ============================================================
#   CONFIGURATION SYSTÈME
# ============================================================


# ============================================================
#   MAINTENANCE
# ============================================================

@web_admin_bp.route('/maintenance/clear-scans', methods=['POST'])
@admin_required
def clear_old_scans():
    """
    Supprimer les anciens scans
    """
    try:
        days = int(request.form.get('days', 30))
        scans_dir = 'scans'
        
        if not os.path.exists(scans_dir):
            flash('Aucun dossier de scans trouvé', 'info')
            return redirect(url_for('web_admin.admin_dashboard'))
        
        deleted_count = 0
        cutoff_date = datetime.now().timestamp() - (days * 24 * 60 * 60)
        
        for filename in os.listdir(scans_dir):
            filepath = os.path.join(scans_dir, filename)
            if os.path.isfile(filepath):
                file_time = os.path.getmtime(filepath)
                if file_time < cutoff_date:
                    os.remove(filepath)
                    deleted_count += 1
        
        flash(f'{deleted_count} scan(s) supprimé(s) (plus vieux que {days} jours)', 'success')
        log_admin_action('CLEAR_SCANS', f'Suppression de {deleted_count} scans')
    
    except Exception as e:
        flash(f'Erreur lors de la suppression des scans: {str(e)}', 'error')
    
    return redirect(url_for('web_admin.admin_dashboard'))


@web_admin_bp.route('/maintenance/backup-db', methods=['POST'])
@admin_required
def backup_database():
    """
    Créer une sauvegarde de la base de données
    """
    try:
        from config.config import DB_PATH
        import shutil
        
        backup_dir = 'backups'
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(backup_dir, f'backup_{timestamp}.db')
        
        shutil.copy2(DB_PATH, backup_file)
        
        flash(f'Sauvegarde créée avec succès: {backup_file}', 'success')
        log_admin_action('BACKUP_DB', 'Création d\'une sauvegarde de la base de données')
    
    except Exception as e:
        flash(f'Erreur lors de la sauvegarde: {str(e)}', 'error')
    
    return redirect(url_for('web_admin.admin_dashboard'))


# ============================================================
#   FONCTIONS UTILITAIRES
# ============================================================

def get_scan_statistics():
    """Récupère les statistiques des scans"""
    try:
        scans_dir = 'scans'
        
        if not os.path.exists(scans_dir):
            return {
                'total': 0,
                'today': 0,
                'this_week': 0,
                'total_size': 0
            }
        
        import json
        from datetime import datetime, timedelta
        
        total = 0
        today = 0
        this_week = 0
        total_size = 0
        
        now = datetime.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = now - timedelta(days=7)
        
        for filename in os.listdir(scans_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(scans_dir, filename)
                total += 1
                total_size += os.path.getsize(filepath)
                
                file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                
                if file_time >= today_start:
                    today += 1
                
                if file_time >= week_start:
                    this_week += 1
        
        return {
            'total': total,
            'today': today,
            'this_week': this_week,
            'total_size': round(total_size / (1024 * 1024), 2)  # MB
        }
    
    except Exception as e:
        print(f"Erreur lors du calcul des statistiques: {e}")
        return {
            'total': 0,
            'today': 0,
            'this_week': 0,
            'total_size': 0
        }


def get_user_statistics(user_id):
    """Récupère les statistiques d'un utilisateur spécifique"""
    # À implémenter selon vos besoins
    return {
        'scans_count': 0,
        'last_login': None
    }


def get_system_info():
    """Récupère les informations système"""
    import platform
    import psutil
    
    return {
        'os': platform.system(),
        'os_version': platform.version(),
        'python_version': platform.python_version(),
        'cpu_count': psutil.cpu_count(),
        'memory_total': round(psutil.virtual_memory().total / (1024**3), 2),  # GB
        'disk_usage': round(psutil.disk_usage('/').percent, 2)
    }


def log_admin_action(action_type, description):
    """Enregistre une action admin dans les logs"""
    try:
        log_dir = 'logs'
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, 'admin_actions.log')
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        username = session.get('username', 'unknown')
        
        log_entry = f"[{timestamp}] {username} - {action_type}: {description}\n"
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    
    except Exception as e:
        print(f"Erreur lors de l'enregistrement du log: {e}")


def get_admin_logs(limit=100):
    """Récupère les derniers logs admin"""
    try:
        log_file = 'logs/admin_actions.log'
        
        if not os.path.exists(log_file):
            return []
        
        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Retourner les dernières lignes
        return lines[-limit:][::-1]  # Inverser pour avoir les plus récents en premier
    
    except Exception as e:
        print(f"Erreur lors de la lecture des logs: {e}")
        return []