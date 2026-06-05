import datetime
from flask import Blueprint, flash, json, redirect, render_template, request, jsonify, session, send_file, url_for
from reporting.report_generator import ReportGenerator
from services.report_service import (
    create_report
)   
import os
import zipfile
from werkzeug.utils import secure_filename
from web.admin import login_required

REPORTS_DIR = os.path.join(os.getcwd(), 'reports')  # dossier où sont stockés les fichiers
SCANS_DIR = os.path.join(os.getcwd(), "scans_results")
reports_bp = Blueprint("reports", __name__)


def list_available_scans():
    """
    Return a list of available scan filenames in the given directory.
    Missing directory returns an empty list.
    """
    try:
        entries = os.listdir(SCANS_DIR)
        print (f"Entries in {SCANS_DIR}: {entries}")
    except FileNotFoundError:
        return []
    scans = [f for f in entries if os.path.isfile(os.path.join(SCANS_DIR, f)) and f.lower().endswith(('.json', '.txt', '.xml'))]
    return scans


# =====================================================
#   PROTECTION
# =====================================================

def require_auth():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401


# =====================================================
#   LISTE DES SCANS DISPONIBLES POUR RAPPORTS
# =====================================================

@reports_bp.get("/scans")
def get_scans():
    print("SCANS_DIR =", SCANS_DIR)
    print("Exists =", os.path.exists(SCANS_DIR))
    print("Files =", os.listdir(SCANS_DIR) if os.path.exists(SCANS_DIR) else "none")
    require_auth()
    scans = list_available_scans(SCANS_DIR)
    return jsonify(scans)


# ======================== GÉNÉRATION DE RAPPORTS ==================== #

@reports_bp.route('/report/generate', methods=['POST'])
@login_required
def generate_report():
    """Générer un rapport complet et le télécharger automatiquement"""
    try:
        project_name = request.form.get('project_name', 'Pentest Report')
        report_files = request.form.getlist('reports')
        report_format = request.form.get('format', 'html')  # 'html' ou 'json'
        
        # Créer le rapport
        report = ReportGenerator(project_name)
        
        # Charger et ajouter les scans sélectionnés
        for filename in report_files:
            filepath = os.path.join(SCANS_DIR, filename)
            print
            with open(filepath, 'r') as f:
                data = json.load(f)
                report.add_scan_results(data.get('scan_type', 'Scan'), data.get('data', data))
                
                # Ajouter les vulnérabilités si présentes
                if 'vulnerabilities' in data.get('data', {}):
                    for vuln in data['data']['vulnerabilities']:
                        report.add_vulnerability(vuln)
        
        # Générer le rapport selon le format demandé
        if report_format == 'json':
            report_file = report.generate_json()
            mimetype = 'application/json'
        else:
            report_file = report.generate_html()
            mimetype = 'text/html'
        
        # Vérifier que le fichier existe
        if not os.path.exists(report_file):
            flash("Erreur: le fichier de rapport n'a pas été créé", "error")
            return redirect(url_for('scan_history'))
        
        # Télécharger le fichier
        return send_file(
            report_file,
            mimetype=mimetype,
            as_attachment=True,
            download_name=os.path.basename(report_file)
        )
        
    except Exception as e:
        flash(f"Erreur lors de la génération du rapport: {str(e)}", "error")
        return redirect(url_for('scan_history'))


@reports_bp.route('/report/download/<filename>')
@login_required
def download_report(filename):
    """Télécharger un rapport existant"""
    try:
        # Sécurité: vérifier que le fichier est bien dans le répertoire reports
        reports_dir = os.path.join(os.getcwd(), 'reports')
        filepath = os.path.join(reports_dir, filename)
        
        # Vérifier que le chemin est sécurisé (éviter les attaques de type path traversal)
        if not os.path.abspath(filepath).startswith(os.path.abspath(reports_dir)):
            flash("Accès refusé", "error")
            return redirect(url_for('scan_history'))
        
        if not os.path.exists(filepath):
            flash("Fichier introuvable", "error")
            return redirect(url_for('scan_history'))
        
        # Déterminer le type MIME selon l'extension
        if filename.endswith('.json'):
            mimetype = 'application/json'
        elif filename.endswith('.html'):
            mimetype = 'text/html'
        elif filename.endswith('.pdf'):
            mimetype = 'application/pdf'
        else:
            mimetype = 'application/octet-stream'
        
        return send_file(
            filepath,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        flash(f"Erreur lors du téléchargement: {str(e)}", "error")
        return redirect(url_for('scan_history'))


# Route alternative avec génération des deux formats
@reports_bp.route('/report/generate/both', methods=['POST'])
@login_required
def generate_report_both():
    """Générer et télécharger les rapports HTML et JSON en archive ZIP"""
    try:
        import zipfile
        from io import BytesIO
        
        project_name = request.form.get('project_name', 'Pentest Report')
        scan_files = request.form.getlist('scans')
        
        # Créer le rapport
        report = ReportGenerator(project_name)
        
        # Charger et ajouter les scans sélectionnés
        for filename in scan_files:
            filepath = os.path.join(SCANS_DIR, filename)
            with open(filepath, 'r') as f:
                data = json.load(f)
                report.add_scan_results(data.get('scan_type', 'Scan'), data.get('data', data))
                
                if 'vulnerabilities' in data.get('data', {}):
                    for vuln in data['data']['vulnerabilities']:
                        report.add_vulnerability(vuln)
        
        # Générer les deux formats
        html_file = report.generate_html()
        json_file = report.generate_json()
        
        # Créer une archive ZIP en mémoire
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.write(html_file, os.path.basename(html_file))
            zf.write(json_file, os.path.basename(json_file))
        
        memory_file.seek(0)
        
        # Télécharger l'archive
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'{project_name.replace(" ", "_")}_reports.zip'
        )
        
    except Exception as e:
        flash(f"Erreur lors de la génération des rapports: {str(e)}", "error")
        return redirect(url_for('scan_history'))
# =====================================================
#   VIEW SCAN DATA USED IN REPORT
# =====================================================

@reports_bp.get("/scan/<filename>")
def view_scan(filename):
    try:
        filename = secure_filename(filename)
        filepath = os.path.join(SCANS_DIR, filename)
        print("Viewing scan file:", filepath) 
        print("Exists:", os.path.exists(filepath))
        if not os.path.exists(filepath):
            flash("Fichier introuvable", "error")
            return redirect(url_for('web_reports.scan_history'))

        print("File exists, loading...")
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # On envoie TOUT le JSON au template
        return render_template(
            'reports/scan_results.html',
            scan_type=data.get('scan_type', 'Scan'),
            results=data,      
            filename=filename
        )

    except Exception as e:
        flash(f"Erreur lors du chargement du scan: {str(e)}", "error")
        print("💥 ERREUR DANS view_scan :", e)
        return redirect(url_for('web_reports.scan_history'))


@reports_bp.route('/api/scan/stats')
@login_required
def scan_stats():
    """API pour récupérer les statistiques des scans"""
    try:
        stats = {
            'total_scans': 0,
            'today_scans': 0,
            'total_size': 0,
            'scan_types': set(),
            'by_type': {},
            'recent_scans': []
        }
        
        today = datetime.now().strftime('%Y-%m-%d')
        
        for filename in os.listdir(SCANS_DIR):
            if filename.endswith('.json'):
                filepath = os.path.join(SCANS_DIR, filename)
                stats['total_scans'] += 1
                stats['total_size'] += os.path.getsize(filepath)
                
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    scan_type = data.get('scan_type', 'unknown')
                    timestamp = data.get('timestamp', '')
                    
                    stats['scan_types'].add(scan_type)
                    
                    # Compter par type
                    stats['by_type'][scan_type] = stats['by_type'].get(scan_type, 0) + 1
                    
                    # Scans du jour
                    if timestamp.startswith(today):
                        stats['today_scans'] += 1
                    
                    # Scans récents
                    if len(stats['recent_scans']) < 5:
                        stats['recent_scans'].append({
                            'filename': filename,
                            'scan_type': scan_type,
                            'timestamp': timestamp
                        })
                
                except:
                    continue
        
        stats['scan_types'] = list(stats['scan_types'])
        stats['total_size_mb'] = round(stats['total_size'] / (1024 * 1024), 2)
        
        return jsonify(stats)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
 