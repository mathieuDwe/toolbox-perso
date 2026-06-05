"""
Module de scan réseau et ports pour Pentool
"""

import socket
import ipaddress
import subprocess
import platform
import concurrent.futures
from datetime import datetime
import json
import os
from pathlib import Path

from flask import session


# ============================================================
#   CONFIGURATION DU DOSSIER DE SAUVEGARDE
# ============================================================

# Définir le dossier de sauvegarde par défaut
# Il sera créé au même niveau que le module, dans un dossier "scans"
SCANS_DIR = os.path.join(os.path.dirname(__file__), "..", "scans_results")

# Alternative: Chemin absolu fixe
# SCANS_DIR = r"C:\Users\Mathi\Documents\cours\fil rouge\Pentool\


# ======================================================
#                    Network Scanner
# ======================================================

class NetworkScanner:
    """Scanner réseau pour détecter les hôtes actifs"""
    
    def __init__(self, timeout=1):
        self.timeout = timeout
        self.results = []
    
    def ping_host(self, ip):
        """Ping un hôte pour vérifier s'il est actif"""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w' if platform.system().lower() == 'windows' else '-W', str(self.timeout), str(ip)]
        
        try:
            output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout + 1)
            return output.returncode == 0
        except:
            return False
    
    def scan_network(self, network_range):
        """Scanne un réseau complet pour trouver les hôtes actifs
        
        Args:
            network_range (str): Range réseau (ex: "192.168.1.0/24")
        
        Returns:
            list: Liste des hôtes actifs avec leurs informations
        """
        try:
            network = ipaddress.ip_network(network_range, strict=False)
        except ValueError as e:
            return {"error": f"Range réseau invalide: {e}"}
        
        active_hosts = []
        total_hosts = network.num_addresses
        
        print(f"[*] Scan du réseau {network_range} ({total_hosts} hôtes)")
        
        # Utilisation de ThreadPoolExecutor pour scanner en parallèle
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.check_host, str(ip)): str(ip) for ip in network.hosts()}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    active_hosts.append(result)
                    print(f"[+] Hôte actif trouvé: {result['ip']}")
        
        return {
            "network": network_range,
            "total_scanned": total_hosts,
            "active_hosts": len(active_hosts),
            "hosts": active_hosts,
            "timestamp": datetime.now().isoformat()
        }
    
    def check_host(self, ip):
        """Vérifie si un hôte est actif et récupère ses informations"""
        if self.ping_host(ip):
            hostname = self.get_hostname(ip)
            return {
                "ip": ip,
                "hostname": hostname,
                "status": "up"
            }
        return None
    
    def get_hostname(self, ip):
        """Récupère le hostname d'une IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"


class PortScanner:
    """Scanner de ports pour identifier les services en écoute"""
    
    def __init__(self, timeout=1):
        self.timeout = timeout
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            8008: "AUTRE"
        }
    
    def scan_port(self, ip, port):
        """Scanne un port spécifique"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                service = self.common_ports.get(port, "Unknown")
                banner = self.grab_banner(ip, port)
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner
                }
        except:
            pass
        return None
    
    def grab_banner(self, ip, port):
        """Tente de récupérer la bannière du service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:100] if banner else None
        except:
            return None
    
    def scan_host(self, ip, ports=None, scan_type="common"):
        """Scanne les ports d'un hôte
        
        Args:
            ip (str): Adresse IP cible
            ports (list): Liste des ports à scanner (optionnel)
            scan_type (str): Type de scan - "common", "full", "custom"
        
        Returns:
            dict: Résultats du scan
        """
        print(f"[*] Scan des ports sur {ip}")
        
        if scan_type == "common":
            ports_to_scan = list(self.common_ports.keys())
        elif scan_type == "full":
            ports_to_scan = range(1, 1025)  # Ports 1-1024
        elif scan_type == "custom" and ports:
            ports_to_scan = ports
        else:
            ports_to_scan = list(self.common_ports.keys())
        
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.scan_port, ip, port): port for port in ports_to_scan}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"[+] Port ouvert: {result['port']}/{result['service']}")
        
        return {
            "target": ip,
            "scan_type": scan_type,
            "total_ports_scanned": len(ports_to_scan),
            "open_ports": len(open_ports),
            "ports": sorted(open_ports, key=lambda x: x['port']),
            "timestamp": datetime.now().isoformat()
        }
    
    def quick_scan(self, ip):
        """Scan rapide des ports les plus communs"""
        return self.scan_host(ip, scan_type="common")


# ======================================================
#                    Port Scanner
# ======================================================
class PortScanner:
    """Scanner de ports pour identifier les services en écoute"""
    
    def __init__(self, timeout=1):
        self.timeout = timeout
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            8008: "AUTRE"
        }
    
    def scan_port(self, ip, port):
        """Scanne un port spécifique"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                service = self.common_ports.get(port, "Unknown")
                banner = self.grab_banner(ip, port)
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner
                }
        except:
            pass
        return None
    
    def grab_banner(self, ip, port):
        """Tente de récupérer la bannière du service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:100] if banner else None
        except:
            return None
    
    def scan_host(self, ip, ports=None, scan_type="common"):
        """Scanne les ports d'un hôte
        
        Args:
            ip (str): Adresse IP cible
            ports (list): Liste des ports à scanner (optionnel)
            scan_type (str): Type de scan - "common", "full", "custom"
        
        Returns:
            dict: Résultats du scan
        """
        print(f"[*] Scan des ports sur {ip}")
        
        if scan_type == "common":
            ports_to_scan = list(self.common_ports.keys())
        elif scan_type == "full":
            ports_to_scan = range(1, 1025)  # Ports 1-1024
        elif scan_type == "custom" and ports:
            ports_to_scan = ports
        else:
            ports_to_scan = list(self.common_ports.keys())
        
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.scan_port, ip, port): port for port in ports_to_scan}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"[+] Port ouvert: {result['port']}/{result['service']}")
        
        return {
            "target": ip,
            "scan_type": scan_type,
            "total_ports_scanned": len(ports_to_scan),
            "open_ports": len(open_ports),
            "ports": sorted(open_ports, key=lambda x: x['port']),
            "timestamp": datetime.now().isoformat()
        }
    
    def quick_scan(self, ip):
        """Scan rapide des ports les plus communs"""
        return self.scan_host(ip, scan_type="common")
 # =====================================================
 #             Service Detector
 #======================================================
class ServiceDetector:
    """Détecteur de services et versions pour les ports ouverts"""
    
    def __init__(self, timeout=2):
        self.timeout = timeout
        self.service_probes = {
            80: {
                "name": "HTTP",
                "probe": b"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n",
                "pattern": r"Server: ([^\r\n]+)"
            },
            443: {
                "name": "HTTPS",
                "probe": b"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n",
                "pattern": r"Server: ([^\r\n]+)"
            },
            21: {
                "name": "FTP",
                "probe": None,  # FTP envoie banner automatiquement
                "pattern": r"220[- ](.+)"
            },
            22: {
                "name": "SSH",
                "probe": None,
                "pattern": r"SSH-[\d\.]+-(.+)"
            },
            25: {
                "name": "SMTP",
                "probe": b"EHLO test\r\n",
                "pattern": r"220[- ](.+)"
            },
            3306: {
                "name": "MySQL",
                "probe": None,
                "pattern": r"[\x00-\xFF]*mysql"
            }
        }
    
    def detect_service(self, ip, port):
        """Détecte le service et sa version sur un port
        
        Args:
            ip (str): Adresse IP cible
            port (int): Numéro de port
            
        Returns:
            dict: Informations sur le service détecté
        """
        result = {
            "port": port,
            "service": "unknown",
            "version": None,
            "banner": None,
            "confidence": "low"
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Récupérer les infos du service si on a une probe
            if port in self.service_probes:
                probe_info = self.service_probes[port]
                result["service"] = probe_info["name"]
                result["confidence"] = "medium"
                
                # Envoyer la probe si définie
                if probe_info["probe"]:
                    probe = probe_info["probe"]
                    if b"{target}" in probe:
                        probe = probe.replace(b"{target}", ip.encode())
                    sock.send(probe)
                
                # Lire la réponse
                banner = sock.recv(2048).decode('utf-8', errors='ignore')
                result["banner"] = banner[:200]
                
                # Extraire la version avec le pattern
                if probe_info["pattern"] and banner:
                    match = re.search(probe_info["pattern"], banner, re.IGNORECASE)
                    if match:
                        result["version"] = match.group(1).strip()
                        result["confidence"] = "high"
            else:
                # Pour les ports inconnus, essayer de récupérer une bannière
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if banner:
                    result["banner"] = banner[:200]
                    result["service"] = self._guess_service_from_banner(banner)
                    result["confidence"] = "low"
            
            sock.close()
            
        except socket.timeout:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _guess_service_from_banner(self, banner):
        """Devine le service à partir de la bannière
        
        Args:
            banner (str): Bannière du service
            
        Returns:
            str: Nom du service deviné
        """
        banner_lower = banner.lower()
        
        if "http" in banner_lower or "html" in banner_lower:
            return "HTTP"
        elif "ssh" in banner_lower:
            return "SSH"
        elif "ftp" in banner_lower:
            return "FTP"
        elif "smtp" in banner_lower or "mail" in banner_lower:
            return "SMTP"
        elif "mysql" in banner_lower:
            return "MySQL"
        elif "postgresql" in banner_lower or "postgres" in banner_lower:
            return "PostgreSQL"
        elif "redis" in banner_lower:
            return "Redis"
        elif "mongodb" in banner_lower or "mongo" in banner_lower:
            return "MongoDB"
        
        return "unknown"
    
    def scan_services(self, ip, ports):
        """Scanne les services sur plusieurs ports
        
        Args:
            ip (str): Adresse IP cible
            ports (list): Liste des ports à scanner
            
        Returns:
            dict: Résultats de la détection de services
        """
        print(f"[*] Détection des services sur {ip}")
        
        detected_services = []
        
        for port in ports:
            service_info = self.detect_service(ip, port)
            detected_services.append(service_info)
            
            if service_info.get("version"):
                print(f"[+] {port}/{service_info['service']} - {service_info['version']}")
            else:
                print(f"[+] {port}/{service_info['service']}")
        
        return {
            "target": ip,
            "total_services": len(detected_services),
            "services": detected_services,
            "timestamp": datetime.now().isoformat()
        }
    
    def get_service_vulnerabilities(self, service_name, version=None):
        """Retourne les vulnérabilités potentielles d'un service
        
        Note: Ceci est un placeholder - vous devriez intégrer avec une vraie
        base de données de vulnérabilités (CVE, NVD, etc.)
        
        Args:
            service_name (str): Nom du service
            version (str): Version du service (optionnel)
            
        Returns:
            list: Liste des vulnérabilités potentielles
        """
        # TODO: Intégrer avec une API CVE ou base de données locale
        return {
            "service": service_name,
            "version": version,
            "vulnerabilities": [],
            "note": "Intégration CVE à implémenter"
        }

# ======================================================
#               list scan
# ======================================================
class ScanManager:
    """Gestionnaire de scans sauvegardés"""
# ======================================================
#               Saving & Wrapper Functions
# =====================================================
#------------------  CONFIGURATION DU DOSSIER DE SAUVEGARDE  -------------
#  
# Définir le dossier de sauvegarde par défaut
# Il sera créé au même niveau que le module, dans un dossier "scans"
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    SCANS_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', 'scans_results'))
    print(SCANS_DIR)
# Alternative: Chemin absolu fixe
# SCANS_DIR = r"C:\Users\Mathi\Documents\cours\fil rouge\Pentool\scans"


# ============================================================
#   FONCTION DE SAUVEGARDE MODIFIÉE
# ============================================================

    def save_scan_results(scan_type, results):
        """Sauvegarde les résultats d'un scan avec métadonnées"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{scan_type}_{timestamp}.json"
        filepath = os.path.join(ScanManager.SCANS_DIR, filename)
        
        data = {
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'user': session.get('username'),
            'data': results
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        
        return filename

            # ======================================================
        #               Scan Listing Functions
    def list_all_scans(scan_dir="scans"):
                """
                Liste tous les scans sauvegardés dans le répertoire spécifié.
                
                Args:
                    scan_dir (str): Chemin du répertoire contenant les scans (par défaut: "scans")
                
                Returns:
                    list: Liste de dictionnaires contenant les informations de chaque scan
                        Format: [
                            {
                                "filename": "network_scan_20250101_120000.json",
                                "scan_type": "network_scan",
                                "timestamp": "2025-01-01 12:00:00",
                                "size": 2048,
                                "target": "192.168.1.0/24",
                                "domain": None,
                                "url": None
                            },
                            ...
                        ]
                """
                # Créer le répertoire s'il n'existe pas
                if not os.path.exists(scan_dir):
                    os.makedirs(scan_dir)
                    return []
                
                scans = []
                
                # Parcourir tous les fichiers du répertoire
                for filename in os.listdir(scan_dir):
                    if not filename.endswith('.json'):
                        continue
                    
                    filepath = os.path.join(scan_dir, filename)
                    
                    try:
                        # Récupérer les informations du fichier
                        file_stats = os.stat(filepath)
                        file_size = file_stats.st_size
                        
                        # Charger le contenu du scan
                        with open(filepath, 'r', encoding='utf-8') as f:
                            scan_data = json.load(f)
                        
                        # Extraire le type de scan depuis le nom de fichier
                        scan_type = filename.split('_')[0]
                        if len(filename.split('_')) > 1:
                            # Gérer les types de scan avec underscore (ex: network_scan)
                            parts = filename.split('_')
                            if parts[1] not in ['scan', 'analysis', 'enum']:
                                scan_type = f"{parts[0]}_{parts[1]}"
                        
                        # Extraire le timestamp
                        timestamp_str = scan_data.get('timestamp', 
                                                    datetime.fromtimestamp(file_stats.st_mtime).isoformat())
                        
                        # Formater le timestamp pour l'affichage
                        try:
                            if 'T' in timestamp_str:
                                dt = datetime.fromisoformat(timestamp_str)
                            else:
                                dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                            formatted_timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            formatted_timestamp = timestamp_str
                        
                        # Extraire les cibles/domaines/URLs selon le type de scan
                        target = scan_data.get('target') or scan_data.get('network')
                        domain = scan_data.get('domain')
                        url = scan_data.get('url')
                        
                        # Créer l'entrée du scan
                        scan_info = {
                            'filename': filename,
                            'scan_type': scan_type,
                            'timestamp': formatted_timestamp,
                            'size': file_size,
                            'target': target,
                            'domain': domain,
                            'url': url,
                            'user': scan_data.get('user', 'unknown'),
                            'filepath': filepath
                        }
                        
                        scans.append(scan_info)
                        
                    except json.JSONDecodeError:
                        print(f"[!] Erreur de lecture JSON: {filename}")
                        continue
                    except Exception as e:
                        print(f"[!] Erreur lors du traitement de {filename}: {e}")
                        continue
                
                # Trier par timestamp (du plus récent au plus ancien)
                scans.sort(key=lambda x: x['timestamp'], reverse=True)
                
                return scans


    def list_scans_by_type(scan_type, scan_dir="scans"):
            """
            Liste tous les scans d'un type spécifique.
            
            Args:
                scan_type (str): Type de scan à filtrer (ex: "network_scan", "port_scan")
                scan_dir (str): Chemin du répertoire contenant les scans
            
            Returns:
                list: Liste filtrée des scans du type demandé
            """
            all_scans = ScanManager.list_all_scans(scan_dir)
            return [scan for scan in all_scans if scan['scan_type'] == scan_type]


    def list_scans_by_date(date_str, scan_dir="scans"):
            """
            Liste tous les scans effectués à une date spécifique.
            
            Args:
                date_str (str): Date au format "YYYY-MM-DD"
                scan_dir (str): Chemin du répertoire contenant les scans
            
            Returns:
                list: Liste filtrée des scans de la date demandée
            """
            all_scans = ScanManager.list_all_scans(scan_dir)
            return [scan for scan in all_scans if scan['timestamp'].startswith(date_str)]


    def get_scan_statistics(scan_dir="scans"):
            """
            Calcule des statistiques sur l'ensemble des scans.
            
            Args:
                scan_dir (str): Chemin du répertoire contenant les scans
            
            Returns:
                dict: Dictionnaire contenant les statistiques
            """
            all_scans = ScanManager.list_all_scans(scan_dir)
            
            if not all_scans:
                return {
                    'total_scans': 0,
                    'total_size': 0,
                    'scan_types': {},
                    'oldest_scan': None,
                    'newest_scan': None
                }
            
            # Compter par type
            scan_types = {}
            total_size = 0
            
            for scan in all_scans:
                scan_type = scan['scan_type']
                scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
                total_size += scan['size']
            
            return {
                'total_scans': len(all_scans),
                'total_size': total_size,
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'scan_types': scan_types,
                'oldest_scan': all_scans[-1]['timestamp'] if all_scans else None,
                'newest_scan': all_scans[0]['timestamp'] if all_scans else None
            }


    def delete_scan(filename, scan_dir="scans"):
            """
            Supprime un fichier de scan.
            
            Args:
                filename (str): Nom du fichier à supprimer
                scan_dir (str): Chemin du répertoire contenant les scans
            
            Returns:
                bool: True si la suppression a réussi, False sinon
            """
            filepath = os.path.join(scan_dir, filename)
            
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    print(f"[+] Scan supprimé: {filename}")
                    return True
                else:
                    print(f"[-] Fichier introuvable: {filename}")
                    return False
            except Exception as e:
                print(f"[-] Erreur lors de la suppression: {e}")
                return False


        # ============================================================
        #   EXEMPLE D'UTILISATION
        # ============================================================

    if __name__ == "__main__":
            print("=" * 80)
            print("LISTE DES SCANS DISPONIBLES")
            print("=" * 80)
            
            # Lister tous les scans
            scans = list_all_scans()
            
            if not scans:
                print("\n[!] Aucun scan trouvé dans le répertoire 'scans/'")
            else:
                print(f"\n[+] {len(scans)} scan(s) trouvé(s):\n")
                
                for i, scan in enumerate(scans, 1):
                    print(f"{i}. {scan['filename']}")
                    print(f"   Type: {scan['scan_type']}")
                    print(f"   Date: {scan['timestamp']}")
                    print(f"   Taille: {scan['size']} octets")
                    
                    if scan['target']:
                        print(f"   Cible: {scan['target']}")
                    if scan['domain']:
                        print(f"   Domaine: {scan['domain']}")
                    if scan['url']:
                        print(f"   URL: {scan['url']}")
                    
                    print()
            
            # Afficher les statistiques
            print("\n" + "=" * 80)
            print("STATISTIQUES")
            print("=" * 80)
            
            stats = get_scan_statistics()
            print(f"\nTotal de scans: {stats['total_scans']}")
            print(f"Espace utilisé: {stats['total_size_mb']} MB")
            print(f"\nRépartition par type:")
            for scan_type, count in stats['scan_types'].items():
                print(f"  - {scan_type}: {count}")
            
            if stats['oldest_scan']:
                print(f"\nScan le plus ancien: {stats['oldest_scan']}")
            if stats['newest_scan']:
                print(f"Scan le plus récent: {stats['newest_scan']}")
            
            print("\n" + "=" * 80)