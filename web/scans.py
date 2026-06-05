from concurrent.futures import ThreadPoolExecutor
from fileinput import filename
from unittest import result
from flask import Blueprint, jsonify, render_template, request, redirect, url_for, session, flash


import requests

from models import user
from modules.exploitation import BruteForce, VulnerabilityScanner
from modules.reconnaissance import DNSRecon, PortFingerprint, SubdomainEnumerator, WhoisRecon
from modules.scan import (
    NetworkScanner,
    PortScanner,
    ServiceDetector,
    ScanManager
)
from web.auth import login_required

import pywifi
import time
from datetime import datetime





web_scans_bp = Blueprint('web_scans', __name__, url_prefix='/scan')



# ---- Wordlists prédéfinies ----
def load_wordlist_from_url(url):
    """Télécharge une wordlist depuis une URL (une entrée par ligne)."""
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return [line.strip() for line in r.text.splitlines() if line.strip()]
    except Exception as e:
        print("Erreur téléchargement :", e)
        return None

# Presets de wordlists pour l'énumération de sous-domaines (valeurs par défaut)
# Ces listes peuvent être étendues ou chargées dynamiquement si besoin.
WORDLISTS = {
    "fast": [
        "www", "mail", "ftp", "admin", "test", "dev", "api", "blog", "webmail"
    ],
    "common": [
        "www", "mail", "ftp", "admin", "test", "dev", "api", "blog",
        "webmail", "ns1", "ns2", "smtp", "cpanel", "webdisk", "shop"
    ],
    # "full" peut être rempli à partir d'un fichier plus complet si nécessaire
    "full": [
        "www", "mail", "ftp", "admin", "test", "dev", "api", "blog",
        "webmail", "ns1", "ns2", "smtp", "cpanel", "webdisk", "shop",
        "portal", "secure", "vpn", "staging", "beta", "m", "old", "static"
    ]
}
# ------------------------------
#   RESOLUTION DNS
# ------------------------------
def resolve_subdomain(domain, resolve_ips, check_http, results):
    try:
        answers = dns_scan.resolver.resolve(domain)
        ip = answers[0].to_text() if resolve_ips else None

        entry = {"subdomain": domain, "ip": ip}

        if check_http:
            import requests
            try:
                r = requests.get(f"http://{domain}", timeout=2)
                entry["http"] = r.status_code
            except:
                entry["http"] = None

        results.append(entry)

    except:
        pass  # sous-domaine non valide : on ignore

# ------------------------------
#   THREAD WORKER
# ------------------------------
def worker(queue, base_domain, resolve_ips, check_http, results):
    while not queue.empty():
        sub = queue.get()
        full = f"{sub}.{base_domain}"
        resolve_subdomain(full, resolve_ips, check_http, results)
        queue.task_done()

#============== NETWORK SCAN ==============#
@web_scans_bp.route('/network',methods=['GET', 'POST'])
@login_required
def network_scan():
    """Scanner réseau"""
    if request.method == 'POST':
        network_range = request.form.get('network_range')
        timeout = int(request.form.get('timeout', 1))
        
        try:
            scanner = NetworkScanner(timeout=timeout)
            results = scanner.scan_network(network_range)
            
            # Sauvegarder les résultats
            filename = ScanManager.save_scan_results('network_scan', results)
            
            flash(f"Scan terminé: {results['active_hosts']} hôte(s) actif(s)", "success")
            return render_template('reports/scan_results.html', 
                                 scan_type='Network Scan',
                                 results=results,
                                 filename=filename,
                                 user=session)
        except Exception as e:
            flash(f"Erreur lors du scan: {str(e)}", "error")
            return redirect(url_for('web_scans.toolbox'))
    
    return render_template('network_scan.html', user=session)


def resolve_subdomain(domain, resolve_ips, check_http, results):
    try:
        answers = dns_scan.resolver.resolve(domain)
        ip = answers[0].to_text() if resolve_ips else None

        entry = {"subdomain": domain, "ip": ip}

        if check_http:
            import requests
            try:
                r = requests.get(f"http://{domain}", timeout=2)
                entry["http"] = r.status_code
            except:
                entry["http"] = None

        results.append(entry)

    except:
        pass  # sous-domaine non valide : on ignore

#============== PORT network ==============#
@web_scans_bp.route('/scan/port', methods=['GET', 'POST'])
@login_required
def port_scan():
    """Scanner de ports"""
    if request.method == 'POST':
        target = request.form.get('target')
        scan_type = request.form.get('scan_type', 'common')
        timeout = int(request.form.get('timeout', 1))
        
        try:
            scanner = PortScanner(timeout=timeout)
            results = scanner.scan_host(target, scan_type=scan_type)
            
            # Sauvegarder les résultats
            filename = ScanManager.save_scan_results('port_scan', results)
            
            flash(f"Scan terminé: {results['open_ports']} port(s) ouvert(s)", "success")
            
            # 🔥 Rediriger vers la route d'affichage (réutilise le code de l'historique)
            return redirect(url_for('web_reports.view_scan', filename=filename))
            
        except Exception as e:
            flash(f"Erreur lors du scan: {str(e)}", "error")
            print(f"Erreur Port Scan: {e}")
            import traceback
            traceback.print_exc()
            return redirect(url_for('web_scans.toolbox'))
    
    return render_template('port_scan.html', user=session)

# ==================== Reconnaissance Web ==================== #

@web_scans_bp.route('/scan/web_analysis', methods=['GET', 'POST'])
@login_required
def web_analysis():
    user = session  # Ajuste selon la façon dont tu gères les utilisateurs
    if request.method == 'POST':
        target_url = request.form.get('url')
        if not target_url:
            flash("Veuillez entrer une URL", "error")
            return redirect(url_for('web_scans.web_analysis'))

        results = {}

        # Technologies (exemple simplifié)
        results['technologies'] = ["Nginx", "PHP", "jQuery"]

        # Security Headers
        try:
            r = requests.get(target_url, timeout=5)
            headers = r.headers
            present = {}
            missing = []

            for h in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"]:
                if h in headers:
                    present[h] = headers[h]
                else:
                    missing.append(h)

            results['security_headers'] = {
                "score": len(present),
                "percentage": int(len(present)/3*100),
                "present": present,
                "missing": missing
            }
        except Exception as e:
            results['security_headers'] = {
                "score": 0,
                "percentage": 0,
                "present": {},
                "missing": ["Impossible de récupérer les headers"]
            }

        # SSL / TLS (exemple simplifié)
        results['ssl'] = {"valid": True, "issuer": "Let's Encrypt"}

        # Sauvegarder les résultats
        results['target'] = target_url
        results['url'] = target_url
        filename = ScanManager.save_scan_results('web_analysis', results)

        return render_template('reports/scan_results.html',
                               scan_type='Web Analysis',
                               results=results,
                               filename=filename,
                               user=user)

    # GET request -> afficher le formulaire
    return render_template('web_analysis.html', user=user)
#============== WIFI SCAN ==============#
@web_scans_bp.route('/scan_wifi')
@login_required
def scan_wifi():
    """Scan des réseaux WiFi à proximité"""

    print("user:", session)
    wifi = pywifi.PyWiFi()
    interfaces = wifi.interfaces()
    if not interfaces:
        return jsonify({"error": "Aucune interface WiFi détectée"}), 500

    iface = interfaces[0]
    iface.scan()
    time.sleep(3)
    results_raw = iface.scan_results()

    # Préparer les données
    networks = []
    for net in sorted(results_raw, key=lambda x: x.signal, reverse=True)[:10]:
        ssid = net.ssid if net.ssid else "Réseau caché"
        band = "2.4 GHz" if net.freq < 5000 else "5 GHz"
        networks.append({
            "ssid": ssid,
            "signal": net.signal,
            "channel": net.freq,
            "band": band
        })

    # Structure identique aux autres modules
    results = {
        "scan_type": "WiFi Analyzer",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "networks": networks
    }

    # Sauvegarde avec ta fonction existante
    filename = ScanManager.save_scan_results('wifi_analyzer', results)
    return render_template('/reports/scan_results.html',
                           scan_type='WiFi Analyzer',
                           results=results,
                           filename=filename)


#=================== Fuzzing ==================== #
@web_scans_bp.route('/fuzzing', methods=['GET', 'POST'])
def fuzzing():
    if request.method == 'GET':
        return render_template('fuzzing.html', user=session)  # Affiche le formulaire

    # POST : exécuter le fuzzing
    target_url = request.form.get('url')
    wordlist_path = request.form.get('wordlist')
    threads = int(request.form.get('threads', 10))
    extensions = request.form.get('extensions', '').split(',')
    print("test")
    if not target_url:
        flash("Veuillez entrer une URL", "error")
        return redirect(url_for('web_scans.fuzzing'))

    results = []
    print("Starting fuzzing with the following parameters:")
    print(f"Target URL: {target_url}")
    print(f"Wordlist path: {wordlist_path}")
    print(f"Threads: {threads}")
    print(f"Extensions: {extensions}")

    # Fonction brute force
    def check_path(path):
        url = f"{target_url.rstrip('/')}/{path}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code in [200, 403]:
                results.append({"url": url, "status": r.status_code})
            for ext in extensions:
                if ext.strip():
                    url_ext = f"{url}{ext.strip()}"
                    r2 = requests.get(url_ext, timeout=3)
                    if r2.status_code in [200, 403]:
                        results.append({"url": url_ext, "status": r2.status_code})
        except requests.RequestException:
            pass

    # Charger la wordlist
    paths = []
    if wordlist_path:
        try:
            with open(wordlist_path, 'r') as f:
                paths = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            flash("Wordlist introuvable, utilisation d'une liste par défaut", "warning")

    # Wordlist par défaut si aucune fournie
    if not paths:
        paths = [
            "admin", "login", "uploads", "images", "config", "backup",
            "test", "private", "secure", "api", "robots.txt", "sitemap.xml"
        ]

    # Multi-threading
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for path in paths:
            executor.submit(check_path, path)

    # Sauvegarde des résultats
    scan_data = {
        "target": target_url,
        "found": results,
        "total": len(results)
    }
    filename = ScanManager.save_scan_results('fuzzing', scan_data)

    return render_template('reports/scan_results.html',
                           scan_type='Fuzzing scan',
                           results=scan_data,
                           filename=filename,
                           user=session)


# ================ == Scan de vulnérabilités ==================== #
@web_scans_bp.route('/vulnerability', methods=['GET', 'POST'])
@login_required
def vulnerability_scan():
    if request.method == 'POST':
        url = request.form.get('url')
        
        try:
            vuln_scanner = VulnerabilityScanner(url)
            results = vuln_scanner.scan_all()
            
            filename = ScanManager.save_scan_results('vulnerability_scan', results)
            
            vuln_count = len(results['vulnerabilities'])
            flash(f"Scan terminé: {vuln_count} vulnérabilité(s) détectée(s)", 
                  "warning" if vuln_count > 0 else "success")
            print(filename)
            return render_template(
                'reports/scan_results.html',
                scan_type='Vulnerability Scan',
                results=results,
                filename=filename,
                user=session
            )

        except Exception as e:
            flash(f"Erreur lors du scan: {str(e)}", "error")
            return redirect(url_for('web_scans.toolbox'))
    
    return render_template('vulnerability_scan.html', user=session)

# ==================== Brute Force ==================== #

@web_scans_bp.route('/brute-force', methods=['GET', 'POST'])
@login_required
def brute_force():
    """Brute force (SSH/FTP/HTTP)"""
    
    print(f"\n{'='*80}")
    print(f"[BRUTE FORCE] Route appelée - Méthode: {request.method}")
    print(f"{'='*80}\n")
    
    if request.method == 'POST':
        try:
            # Récupération des données du formulaire
            target = request.form.get('target')
            service = request.form.get('service')
            username = request.form.get('username')
            wordlist_url = request.form.get('wordlist_url')
            
            print(f"[DEBUG] 📝 Données reçues:")
            print(f"  - target: {target}")
            print(f"  - service: {service}")
            print(f"  - username: {username}")
            print(f"  - wordlist_url: {wordlist_url}")
            
        except Exception as form_error:
            print(f"[ERROR] ❌ Erreur lors de la lecture du formulaire: {form_error}")
            import traceback
            traceback.print_exc()
            flash(f"Erreur de formulaire: {str(form_error)}", "error")
            return redirect(url_for('web_scans.toolbox'))
        
        # Validation des inputs
        if not target or not service or not username:
            print(f"[ERROR] ❌ Validation échouée - Champs manquants")
            flash("Target, service et username sont requis", "error")
            return redirect(url_for('web_scans.brute_force'))
        
        # Télécharger la wordlist depuis l'URL côté serveur
        wordlist = []
        if wordlist_url and wordlist_url.strip():
            try:
                print(f"[DEBUG] 📥 Téléchargement de la wordlist depuis: {wordlist_url}")
                import requests
                response = requests.get(wordlist_url, timeout=30)
                response.raise_for_status()
                
                wordlist_text = response.text
                wordlist = [line.strip() for line in wordlist_text.split('\n') if line.strip()]
                
                print(f"[DEBUG] ✅ Wordlist téléchargée: {len(wordlist)} mots")
                if wordlist:
                    print(f"[DEBUG] Premiers mots: {wordlist[:5]}")
                    
            except requests.exceptions.RequestException as download_error:
                print(f"[ERROR] ❌ Erreur téléchargement wordlist: {download_error}")
                flash(f"Impossible de télécharger la wordlist: {str(download_error)}", "error")
                return redirect(url_for('web_scans.brute_force'))
            except Exception as parse_error:
                print(f"[ERROR] ❌ Erreur parsing wordlist: {parse_error}")
                flash("Erreur lors du traitement de la wordlist", "error")
                return redirect(url_for('web_scans.brute_force'))
        
        # Si pas de wordlist ou vide, utiliser une par défaut
        if not wordlist:
            print(f"[WARNING] ⚠️ Pas de wordlist fournie - Utilisation d'une wordlist par défaut")
            wordlist = ["admin", "password", "123456", "root", "test"]
            flash("Aucune wordlist fournie - Utilisation d'une liste par défaut (5 mots)", "warning")
        
        try:
            print(f"\n{'='*60}")
            print(f"[BRUTE FORCE] Démarrage")
            print(f"  Target: {target}")
            print(f"  Service: {service}")
            print(f"  Username: {username}")
            print(f"  Wordlist size: {len(wordlist)}")
            print(f"  Wordlist preview: {wordlist[:5]}")
            print(f"{'='*60}\n")
            
            # Initialisation du BruteForce
            try:
                bf = BruteForce(target, username, wordlist)
                print(f"[DEBUG] ✅ BruteForce instance créée")
            except Exception as init_error:
                print(f"[ERROR] ❌ Erreur lors de l'init de BruteForce: {init_error}")
                raise
            
            results = None
            
            if service == 'ssh':
                port = int(request.form.get('port', 22))
                print(f"[*] SSH Brute force sur {target}:{port}")
                try:
                    results = bf.ssh_bruteforce(port=port)
                    print(f"[DEBUG] ✅ SSH brute force terminé")
                except Exception as ssh_error:
                    print(f"[ERROR] ❌ Erreur SSH brute force: {ssh_error}")
                    import traceback
                    traceback.print_exc()
                    raise
                
            elif service == 'ftp':
                port = int(request.form.get('port', 21))
                print(f"[*] FTP Brute force sur {target}:{port}")
                try:
                    results = bf.ftp_bruteforce(port=port)
                    print(f"[DEBUG] ✅ FTP brute force terminé")
                except Exception as ftp_error:
                    print(f"[ERROR] ❌ Erreur FTP brute force: {ftp_error}")
                    import traceback
                    traceback.print_exc()
                    raise
                
            elif service == 'http':
                url = request.form.get('url')
                if not url:
                    flash("URL requise pour HTTP brute force", "error")
                    return redirect(url_for('web_scans.brute_force'))
                print(f"[*] HTTP Brute force sur {url}")
                try:
                    results = bf.http_form_bruteforce(url)
                    print(f"[DEBUG] ✅ HTTP brute force terminé")
                except Exception as http_error:
                    print(f"[ERROR] ❌ Erreur HTTP brute force: {http_error}")
                    import traceback
                    traceback.print_exc()
                    raise
            
            else:
                flash(f"Service non supporté: {service}", "error")
                return redirect(url_for('web_scans.brute_force'))
            
            if not results:
                raise ValueError("Le brute force n'a retourné aucun résultat")
            
            print(f"\n[DEBUG] Résultats du brute force:")
            print(f"  Type: {type(results)}")
            print(f"  Contenu: {results}")
            
            # Sauvegarder les résultats
            filename = ScanManager.save_scan_results('brute_force', results)
            print(f"[DEBUG] ✅ Sauvegardé dans: {filename}")
            
            # Messages flash selon le résultat
            if results.get('found'):
                flash(f"✅ Credentials trouvées: {results['found']}", "success")
            else:
                flash("ℹ️ Aucune credential trouvée", "info")
            
            # 🔥 SOLUTION: Rediriger vers la vue (comme pour port_scan)
            redirect_url = url_for('web_reports.view_scan', filename=filename)
            print(f"[DEBUG] 🔀 Redirection vers: {redirect_url}")
            
            return redirect(redirect_url)
            
        except Exception as e:
            print(f"\n{'='*60}")
            print(f"[ERROR] Erreur brute force:")
            print(f"  Type: {type(e).__name__}")
            print(f"  Message: {str(e)}")
            print(f"{'='*60}\n")
            
            import traceback
            traceback.print_exc()
            
            flash(f"Erreur lors du brute force: {str(e)}", "error")
            return redirect(url_for('web_scans.toolbox'))
    
    # GET request - Afficher le formulaire
    return render_template('bruteforce.html', user=session)

#   ================ TOOLBOX MAIN ==================== #
@web_scans_bp.route('/toolbox')
@login_required
def toolbox():
    return render_template('toolbox.html', user=session)

#============================= ROUTE DNS =============================#
@web_scans_bp.route('/dns', methods=['GET', 'POST'])
@login_required
def dns_scan():
    """Reconnaissance DNS complète"""
    if request.method == 'POST':
        scan_mode = request.form.get('scan_mode')
        
        try:
            dns_recon = DNSRecon()
            results = {}
            
            # Mode 1: DNS Lookup classique
            if scan_mode == 'dns_lookup':
                domain = request.form.get('domain', '').strip()
                
                if not domain:
                    flash("Veuillez entrer un nom de domaine", "error")
                    return redirect(url_for('dns_scan'))
                
                # Récupérer les types d'enregistrements sélectionnés
                record_types = request.form.getlist('record_types')
                
                if not record_types:
                    flash("Veuillez sélectionner au moins un type d'enregistrement", "error")
                    return redirect(url_for('dns_scan'))
                
                # Effectuer le DNS lookup
                results = dns_recon.dns_lookup(domain, record_types=record_types)
                results['scan_mode'] = 'DNS Lookup'
                results['query'] = domain
                
                # Message de succès
                total_records = sum(len(records) for records in results.get('records', {}).values() if records)
                flash(f"✅ DNS Lookup terminé: {total_records} enregistrement(s) trouvé(s)", "success")
            
            # Mode 2: Reverse DNS
            elif scan_mode == 'reverse_dns':
                ip_address = request.form.get('ip_address', '').strip()
                
                if not ip_address:
                    flash("Veuillez entrer une adresse IP", "error")
                    return redirect(url_for('dns_scan'))
                
                # Effectuer le reverse DNS
                results = dns_recon.reverse_dns(ip_address)
                results['scan_mode'] = 'Reverse DNS'
                results['query'] = ip_address
                
                if results.get('hostname'):
                    flash(f"✅ Hostname trouvé: {results['hostname']}", "success")
                else:
                    flash("⚠️ Aucun hostname trouvé pour cette IP", "warning")
            
            # Mode 3: Analyse avancée
            elif scan_mode == 'advanced':
                domain = request.form.get('domain', '').strip()
                
                if not domain:
                    flash("Veuillez entrer un nom de domaine", "error")
                    return redirect(url_for('dns_scan'))
                
                results = {
                    'domain': domain,
                    'scan_mode': 'Advanced DNS Analysis',
                    'query': domain,
                    'timestamp': datetime.now().isoformat()
                }
                
                # DNS Lookup complet
                print("[*] DNS Lookup...")
                dns_results = dns_recon.dns_lookup(domain)
                results['dns_records'] = dns_results.get('records', {})
                
                # Récupérer toutes les IPs
                if request.form.get('get_all_ips'):
                    print("[*] Récupération de toutes les IPs...")
                    all_ips = dns_recon.get_all_ips(domain)
                    results['all_ips'] = all_ips
                
                # WHOIS Lookup
                if request.form.get('whois_lookup'):
                    print("[*] WHOIS Lookup...")
                    whois_recon = WhoisRecon()
                    whois_results = whois_recon.lookup(domain)
                    results['whois'] = whois_results
                
                # Vérification des sous-domaines communs
                if request.form.get('subdomain_check'):
                    print("[*] Vérification des sous-domaines...")
                    subdomain_enum = SubdomainEnumerator()
                    # Utiliser seulement les sous-domaines très communs
                    common_subs = ['www', 'mail', 'ftp', 'webmail', 'admin']
                    subdomain_results = subdomain_enum.enumerate(domain, wordlist=common_subs, threads=5)
                    results['subdomains'] = subdomain_results.get('found', [])
                
                # Check des ports communs sur l'IP principale
                if request.form.get('port_check') and dns_results.get('records', {}).get('A'):
                    print("[*] Vérification des ports...")
                    target_ip = dns_results['records']['A'][0]
                    port_fp = PortFingerprint()
                    port_results = port_fp.quick_check(target_ip, timeout=1)
                    results['open_ports'] = port_results.get('open_ports', [])
                
                # Compter les résultats
                total_info = 0
                if results.get('dns_records'):
                    total_info += sum(len(v) for v in results['dns_records'].values() if v)
                if results.get('subdomains'):
                    total_info += len(results['subdomains'])
                if results.get('open_ports'):
                    total_info += len(results['open_ports'])
                
                flash(f"✅ Analyse avancée terminée: {total_info} information(s) collectée(s)", "success")
            
            else:
                flash("Mode de scan non reconnu", "error")
                return redirect(url_for('dns_scan'))
            
            # Sauvegarder les résultats
            filename = ScanManager.save_scan_results('dns_scan', results)
            
            # Afficher les résultats
            return render_template('/reports/scan_results.html',
                                 scan_type='DNS Reconnaissance',
                                 results=results,
                                 filename=filename,
                                 user=session)
        
        except Exception as e:
            flash(f"❌ Erreur lors de la reconnaissance DNS: {str(e)}", "error")
            print(f"Erreur DNS: {e}")
            import traceback
            traceback.print_exc()
            return redirect(url_for('toolbox'))
    
    return render_template('dns_scan.html', user=session)


# Fonction helper pour formater les résultats DNS pour l'affichage
def format_dns_results(results):
    """Formate les résultats DNS pour un affichage propre"""
    formatted = {
        'summary': {},
        'details': []
    }
    
    # Résumé
    if 'records' in results:
        formatted['summary'] = {
            'total_records': sum(len(v) for v in results['records'].values() if v),
            'record_types': len([k for k, v in results['records'].items() if v])
        }
    
    # Détails par type
    if 'records' in results:
        for record_type, values in results['records'].items():
            if values:
                formatted['details'].append({
                    'type': record_type,
                    'count': len(values),
                    'values': values
                })
    
    return formatted

#============== SUBDOMAIN ENUMERATION ==============#
@web_scans_bp.route('/subdomain', methods=['GET', 'POST'])
@login_required
def subdomain_scan():
    """Énumération de sous-domaines"""
    if request.method == 'POST':
        domain = request.form.get('domain')
        threads = int(request.form.get('threads', 10))
        
        try:
            subdomain_enum = SubdomainEnumerator()
            results = subdomain_enum.enumerate(domain, threads=threads)
            
            filename = ScanManager.save_scan_results('subdomain_scan', results)
            
            flash(f"Scan terminé: {len(results['found'])} sous-domaine(s) trouvé(s)", "success")
            return render_template('reports/scan_results.html',
                                 scan_type='Subdomain Enumeration',
                                 results=results,
                                 filename=filename,
                                 user=session)
        except Exception as e:
            flash(f"Erreur lors de l'énumération: {str(e)}", "error")
            return redirect(url_for('web_scans.toolbox'))
    
    return render_template('subdomain_scan.html', user=session)

@web_scans_bp.route("/subdomain_enum", methods=["POST"])
def subdomain_enum():

    domain = request.form.get("domain").strip()
    scan_mode = request.form.get("scan_mode")
    wordlist_url = request.form.get("wordlist_url", "").strip()

    # --- MODE : WORDLIST URL ---
    if wordlist_url:
        print("[INFO] Téléchargement wordlist URL…", wordlist_url)
        wordlist = load_wordlist_from_url(wordlist_url)

        if not wordlist:
            return "Impossible de télécharger la wordlist URL.", 400

        print(f"[INFO] Wordlist URL chargée : {len(wordlist)} entrées")
    
    # --- MODE : CUSTOM TEXTAREA ---
    elif scan_mode == "custom":
        raw = request.form.get("custom_wordlist", "").strip()
        wordlist = [l.strip() for l in raw.split("\n") if l.strip()]

    # --- PRESETS ---
    else:
        wordlist = WORDLISTS.get(scan_mode, WORDLISTS["fast"])

    # ... ton code de scan ici ...

    return render_template("scan_results.html", results=result)
