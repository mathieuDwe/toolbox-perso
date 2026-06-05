from datetime import datetime
from fileinput import filename
from io import BytesIO
from zipfile import ZipFile
from flask import Blueprint, flash, json, jsonify, render_template, request, send_file, session, redirect, url_for, g
from werkzeug.utils import secure_filename
import os
import json  

from reporting.report_generator import ReportGenerator
from web.admin import login_required
# Nom du blueprint visible dans url_for()
web_reports_bp = Blueprint("web_reports", __name__, template_folder="../templates")

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')

REPORTS_DIR = os.path.join(os.getcwd(), 'reports')  # dossier où sont stockés les fichiers
# -------------dossier où sont stockés les scans---------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', 'scans_results'))


#-------------------------------------------

DATA_FILE = 'tests.json'
#-------------------------------------------
if not os.path.exists(SCANS_DIR):
    os.makedirs(SCANS_DIR)
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, 'w') as f:
        json.dump([], f)
from config.config import SECRET_KEY

#-------------------------------------------
# PAGE DE TÉLÉCHARGEMENT D’UN RAPPORT   
@web_reports_bp.route('/report/generate', methods=['POST'])
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
            filepath = os.path.join(REPORTS_DIR, filename)
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
            return redirect(url_for('web_reports.scan_history'))
        
        # Télécharger le fichier
        return send_file(
            report_file,
            mimetype=mimetype,
            as_attachment=True,
            download_name=os.path.basename(report_file)
        )
        
    except Exception as e:
        flash(f"Erreur lors de la génération du rapport: {str(e)}", "error")
        return redirect(url_for('web_reports.scan_history'))


@web_reports_bp.route('/report/download/<filename>')
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
            return redirect(url_for('web_reports.scan_history'))
        
        if not os.path.exists(filepath):
            flash("Fichier introuvable", "error")
            return redirect(url_for('web_reports.scan_history'))
        
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
        return redirect(url_for('web_reports.scan_history'))


# Route alternative avec génération des deux formats
@web_reports_bp.route('/report/generate/both', methods=['POST'])
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
        return redirect(url_for('web_reports.scan_history'))

 #================= scan history page =====================
@web_reports_bp.route("/scan_history")
def scan_history():
    """Historique des scans avec métadonnées enrichies"""
    try:
        scan_files = []
        
        for filename in os.listdir(SCANS_DIR):
            if filename.endswith('.json'):
                filepath = os.path.join(SCANS_DIR, filename)
                print(f"Lecture du fichier: {filename}")
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    # CORRECTION: La cible est au premier niveau, pas dans 'data'
                    # D'abord vérifier si 'target' existe directement
                    target = data.get('target')
                    
                    # Si pas de target au premier niveau, chercher dans 'results' ou 'data'
                    if not target:
                        scan_data = data.get('results', {}) or data.get('data', {})
                        target = (scan_data.get('target') or 
                                 scan_data.get('url') or 
                                 scan_data.get('domain') or 
                                 scan_data.get('network') or 
                                 'N/A')
                    
                    # Récupérer aussi les infos supplémentaires
                    results = data.get('results', {})
                    print(f"  -> Results found: {results.keys()}")  
                    scan_files.append({
                        'filename': filename,
                        'scan_type': data.get('scan_type', 'Unknown'),
                        'timestamp': data.get('timestamp', 'Unknown'),
                        'date': data.get('date', 'Unknown'),  # Date formatée
                        'user': data.get('user', 'Unknown'),
                        'size': os.path.getsize(filepath),
                        'target': target,
                        'domain': results.get('domain'),
                        'url': results.get('url')
                    })
                    
                    # Debug: afficher ce qui a été trouvé
                    print(f"  -> Type: {data.get('scan_type')}, Target: {target}")
                    
                except json.JSONDecodeError as e:
                    # Fichier JSON corrompu, on l'ignore
                    print(f"Erreur de lecture du fichier {filename}: {e}")
                    continue
                except Exception as e:
                    print(f"Erreur inattendue pour {filename}: {e}")
                    continue
        
        # Trier par timestamp (plus récent d'abord)
        scan_files.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return render_template('/reports/scan_history.html', 
                             scans=scan_files, 
                             user=session)
    
    except Exception as e:
        print("💥 ERREUR DANS scan_history :", e)
        flash(f"Erreur lors du chargement de l'historique: {str(e)}", "error")
        return render_template('/reports/scan_history.html', 
                             scans=[], 
                             user=session)
#-------------------------------------------------
@web_reports_bp.route('/scan/view/<filename>')
@login_required
def view_scan(filename):
    try:
        filename = secure_filename(filename)
        filepath = os.path.join(SCANS_DIR, filename)

        if not os.path.exists(filepath):
            flash("Fichier introuvable", "error")
            return redirect(url_for('web_scans.scan_history'))

        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # On envoie TOUT le JSON au template
        return render_template(
            '/reports/scan_results.html',
            scan_type=data.get('scan_type', 'Scan'),
            results=data,      
            filename=filename
        )

    except Exception as e:
        flash(f"Erreur lors du chargement du scan: {str(e)}", "error")
        print("💥 ERREUR DANS view_scan :", e)
        return redirect(url_for('web_reports.scan_history'))


#================= download scan report page =====================
@web_reports_bp.route("/scan_report/<filename>")
def download_scan_report(filename):
    filepath = os.path.join(SCANS_DIR, filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        return "File not found", 404
    

@web_reports_bp.route('/download/<filename>')
@login_required
def download_scan(filename):
    """Télécharger un fichier de scan individuel"""
    try:
        filepath = os.path.join(SCANS_DIR, filename)
        
        if not os.path.exists(filepath):
            flash("Fichier introuvable", "error")
            return redirect(url_for('web_reports.scan_history'))
        
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype='application/json'
        )
    
    except Exception as e:
        flash(f"Erreur lors du téléchargement: {str(e)}", "error")
        return redirect(url_for('web_reports.scan_history'))
    
@web_reports_bp.route('/report/multiple-download', methods=['POST'])
@login_required
def report_multiple_download():
    """Télécharger plusieurs scans en ZIP"""
    try:
        # Récupérer les fichiers sélectionnés depuis le formulaire
        filenames = request.form.getlist('scans')
        
        if not filenames:
            flash("Aucun scan sélectionné", "error")
            return redirect(url_for('web_reports.scan_history'))
        
        print(f"[DEBUG] Téléchargement multiple: {len(filenames)} fichiers")
        print(f"[DEBUG] Fichiers: {filenames}")
        
        # Créer un ZIP en mémoire
        zip_buffer = BytesIO()
        
        with ZipFile(zip_buffer, 'w') as zip_file:
            for filename in filenames:
                from werkzeug.utils import secure_filename
                filename = secure_filename(filename)
                
                # 🔥 Utiliser SCANS_DIR, pas REPORTS_DIR
                filepath = os.path.join(SCANS_DIR, filename)
                
                if os.path.exists(filepath):
                    # Ajouter au ZIP avec son nom original
                    zip_file.write(filepath, arcname=filename)
                    print(f"[DEBUG] ✅ Ajouté au ZIP: {filename}")
                else:
                    print(f"[WARNING] ⚠️ Fichier introuvable: {filename}")
        
        zip_buffer.seek(0)
        
        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name='scans_archive.zip',
            mimetype='application/zip'
        )
    
    except Exception as e:
        print(f"[ERROR] ❌ Téléchargement multiple: {e}")
        import traceback
        traceback.print_exc()
        flash(f"Erreur lors du téléchargement: {str(e)}", "error")
        return redirect(url_for('web_reports.scan_history'))
    
#================= export all scans to json =====================
@web_reports_bp.route("/export_all_json")
def export_all_json():
    import json

    all_scans = []
    for filename in os.listdir(SCANS_DIR):
        filepath = os.path.join(SCANS_DIR, filename)
        if os.path.exists(filepath):
            with open(filepath, 'r') as file:
                scan_data = file.read()
                all_scans.append({
                    'filename': filename,
                    'data': scan_data
                })

    json_buffer = json.dumps(all_scans, indent=4)

    from io import BytesIO
    json_bytes = BytesIO()
    json_bytes.write(json_buffer.encode('utf-8'))
    json_bytes.seek(0)

    return send_file(
        json_bytes,
        as_attachment=True,
        download_name='all_scans.json',
        mimetype='application/json'
    )

   
    # =====================================================
#   DELETE SCAN FILE
# =====================================================     
@web_reports_bp.route('/scan/delete/<filename>', methods=['GET', 'POST'])  # Ajoutez methods=['GET', 'POST']
def delete_scan(filename):
    """Supprimer un résultat de scan"""
    try:
        filepath = os.path.join(SCANS_DIR, filename)
        
        # Vérification de sécurité : fichier existe et dans le bon dossier
        if not os.path.exists(filepath):
            flash("Fichier introuvable", "error")
            return redirect(url_for('web_reports.scan_history'))
        
        if not os.path.abspath(filepath).startswith(os.path.abspath(SCANS_DIR)):
            flash("Accès refusé", "error")
            return redirect(url_for('web_reports.scan_history'))
        
        os.remove(filepath)
        flash("Scan supprimé avec succès", "success")
        
    except Exception as e:
        flash(f"Erreur lors de la suppression: {str(e)}", "error")
    
    return redirect(url_for('web_reports.scan_history'))

#--------------------- multiple lines removed ---------------------
@web_reports_bp.route('/scan/delete-multiple', methods=['POST'])
@login_required
def delete_multiple():
    """Supprimer plusieurs scans"""
    try:
        selected_scans = request.form.getlist('scans')
        
        if not selected_scans:
            flash("Aucun scan sélectionné", "error")
            return redirect(url_for('web_reports.scan_history'))
        
        deleted_count = 0
        
        for filename in selected_scans:
            filepath = os.path.join(SCANS_DIR, filename)
            
            if os.path.exists(filepath):
                os.remove(filepath)
                deleted_count += 1
        
        flash(f"{deleted_count} scan(s) supprimé(s) avec succès", "success")
    
    except Exception as e:
        flash(f"Erreur lors de la suppression: {str(e)}", "error")
    
    return redirect(url_for('web_reports.scan_history'))






