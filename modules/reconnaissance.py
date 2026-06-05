"""
Module de reconnaissance avancé pour Pentool
Collecte d'informations OSINT (Open Source Intelligence)
"""

import socket
import requests
import ssl
import re
import json
import subprocess
import platform
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings

# Désactiver les warnings SSL
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class DNSRecon:
    """Reconnaissance DNS complète"""
    
    def __init__(self):
        self.results = {}
    
    def dns_lookup(self, domain, record_types=None):
        """Effectue une recherche DNS complète"""
        if record_types is None:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        results = {
            'domain': domain,
            'records': {},
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"[*] Recherche DNS pour {domain}")
        
        for record_type in record_types:
            try:
                # Utilisation de nslookup pour la compatibilité multi-plateforme
                cmd = f"nslookup -type={record_type} {domain}"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
                output_str = output.decode('utf-8', errors='ignore')
                
                # Parse basique de la sortie nslookup
                records = self._parse_nslookup_output(output_str, record_type)
                if records:
                    results['records'][record_type] = records
                    print(f"[+] {record_type}: {len(records)} enregistrement(s)")
                
            except subprocess.TimeoutExpired:
                print(f"[-] Timeout pour {record_type}")
            except subprocess.CalledProcessError as e:
                # Pas d'enregistrement trouvé
                results['records'][record_type] = []
            except Exception as e:
                print(f"[-] Erreur pour {record_type}: {e}")
                results['records'][record_type] = []
        
        return results
    
    def _parse_nslookup_output(self, output, record_type):
        """Parse la sortie de nslookup"""
        records = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if record_type == 'A' and 'Address:' in line and not 'Server' in lines[lines.index(line) - 1] if lines.index(line) > 0 else True:
                # Extraire l'adresse IP
                parts = line.split('Address:')
                if len(parts) > 1:
                    ip = parts[1].strip()
                    if ip and not ip.startswith('#'):
                        records.append(ip)
            
            elif record_type == 'MX' and 'mail exchanger' in line.lower():
                records.append(line.split('=')[-1].strip())
            
            elif record_type == 'NS' and 'nameserver' in line.lower():
                records.append(line.split('=')[-1].strip())
            
            elif record_type == 'TXT' and '"' in line:
                # Extraire le contenu entre guillemets
                txt_match = re.findall(r'"([^"]*)"', line)
                records.extend(txt_match)
            
            elif record_type == 'CNAME' and 'canonical name' in line.lower():
                records.append(line.split('=')[-1].strip())
        
        return records
    
    def reverse_dns(self, ip):
        """Recherche DNS inversée"""
        print(f"[*] Reverse DNS pour {ip}")
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(f"[+] Hostname trouvé: {hostname}")
            return {
                'ip': ip,
                'hostname': hostname,
                'timestamp': datetime.now().isoformat()
            }
        except socket.herror:
            print(f"[-] Aucun hostname trouvé pour {ip}")
            return {'ip': ip, 'hostname': None, 'error': 'No hostname found'}
        except Exception as e:
            print(f"[-] Erreur: {e}")
            return {'ip': ip, 'hostname': None, 'error': str(e)}
    
    def get_all_ips(self, domain):
        """Récupère toutes les IPs associées à un domaine"""
        print(f"[*] Récupération des IPs pour {domain}")
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            print(f"[+] {len(ips)} IP(s) trouvée(s)")
            return {
                'domain': domain,
                'ips': ips,
                'count': len(ips),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            print(f"[-] Erreur: {e}")
            return {'domain': domain, 'ips': [], 'error': str(e)}


class WhoisRecon:
    """Reconnaissance WHOIS simplifiée"""
    
    def lookup(self, domain):
        """Recherche WHOIS d'un domaine"""
        print(f"[*] Recherche WHOIS pour {domain}")
        
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Utilisation de whois en ligne de commande
            if platform.system() == 'Windows':
                print("[-] WHOIS non disponible nativement sur Windows")
                results['error'] = "WHOIS command not available on Windows"
            else:
                cmd = f"whois {domain}"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=15)
                whois_data = output.decode('utf-8', errors='ignore')
                
                # Extraction d'informations basiques
                results['registrar'] = self._extract_field(whois_data, ['Registrar:', 'registrar:'])
                results['creation_date'] = self._extract_field(whois_data, ['Creation Date:', 'created:'])
                results['expiration_date'] = self._extract_field(whois_data, ['Expiration Date:', 'Expiry Date:', 'expires:'])
                results['status'] = self._extract_field(whois_data, ['Status:', 'status:'])
                results['name_servers'] = self._extract_nameservers(whois_data)
                results['raw'] = whois_data[:1000]  # Limiter la taille
                
                print(f"[+] Informations WHOIS récupérées")
                
        except subprocess.TimeoutExpired:
            results['error'] = "WHOIS lookup timeout"
            print("[-] Timeout lors de la requête WHOIS")
        except subprocess.CalledProcessError as e:
            results['error'] = f"WHOIS command failed: {e}"
            print(f"[-] Erreur WHOIS: {e}")
        except Exception as e:
            results['error'] = str(e)
            print(f"[-] Erreur: {e}")
        
        return results
    
    def _extract_field(self, text, patterns):
        """Extrait un champ du texte WHOIS"""
        for pattern in patterns:
            for line in text.split('\n'):
                if pattern in line:
                    return line.split(pattern)[1].strip()
        return None
    
    def _extract_nameservers(self, text):
        """Extrait les nameservers"""
        nameservers = []
        for line in text.split('\n'):
            if 'Name Server:' in line or 'nserver:' in line:
                ns = line.split(':')[1].strip()
                if ns:
                    nameservers.append(ns)
        return nameservers if nameservers else None


class WebRecon:
    """Reconnaissance Web avancée"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        self.session = requests.Session()
    
    def analyze_website(self, url):
        """Analyse complète d'un site web"""
        print(f"[*] Analyse de {url}")
        
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'accessible': False
        }
        
        try:
            # Vérifier si l'URL a un schéma
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Requête HTTP
            response = self.session.get(
                url, 
                headers=self.headers, 
                timeout=self.timeout, 
                verify=False, 
                allow_redirects=True
            )
            
            results['accessible'] = True
            results['status_code'] = response.status_code
            results['final_url'] = response.url
            results['redirects'] = [r.url for r in response.history]
            results['content_length'] = len(response.content)
            
            # Headers
            results['server'] = response.headers.get('Server', 'Unknown')
            results['powered_by'] = response.headers.get('X-Powered-By', 'Unknown')
            results['headers'] = dict(response.headers)
            
            # Analyse du contenu
            results['title'] = self._extract_title(response.text)
            results['technologies'] = self.detect_technologies(response)
            results['security_headers'] = self.check_security_headers(response.headers)
            
            # Analyse SSL/TLS
            if url.startswith('https://'):
                results['ssl_info'] = self.check_ssl(url)
            
            # Extraction d'informations
            results['emails'] = self.extract_emails(response.text)
            results['internal_links'] = self.extract_links(response.text, url, internal_only=True)[:30]
            results['external_links'] = self.extract_links(response.text, url, internal_only=False)[:20]
            
            # Détection de CMS
            results['cms'] = self.detect_cms(response)
            
            # Cookies
            results['cookies'] = [{'name': c.name, 'secure': c.secure, 'httponly': c.has_nonstandard_attr('HttpOnly')} 
                                 for c in response.cookies]
            
            print(f"[+] Analyse terminée: {response.status_code}")
            
        except requests.exceptions.SSLError:
            results['error'] = "SSL Certificate Error"
            print(f"[-] Erreur SSL")
        except requests.exceptions.ConnectionError:
            results['error'] = "Connection Error"
            print(f"[-] Impossible de se connecter")
        except requests.exceptions.Timeout:
            results['error'] = "Timeout"
            print(f"[-] Timeout")
        except Exception as e:
            results['error'] = str(e)
            print(f"[-] Erreur: {e}")
        
        return results
    
    def _extract_title(self, html):
        """Extrait le titre de la page"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()
        return None
    
    def detect_technologies(self, response):
        """Détecte les technologies utilisées"""
        tech = []
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        # Détection via headers
        if 'x-powered-by' in headers:
            tech.append(response.headers['X-Powered-By'])
        
        if 'server' in headers:
            server = headers['server']
            if 'nginx' in server:
                tech.append('Nginx')
            elif 'apache' in server:
                tech.append('Apache')
            elif 'iis' in server:
                tech.append('IIS')
            elif 'cloudflare' in server:
                tech.append('Cloudflare')
        
        # Détection via contenu
        technologies = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
            'Joomla': ['joomla', '/components/com_'],
            'Drupal': ['drupal', 'sites/default/files'],
            'Magento': ['magento', 'mage/cookies.js'],
            'Shopify': ['cdn.shopify.com', 'shopify'],
            'jQuery': ['jquery.js', 'jquery.min.js'],
            'Bootstrap': ['bootstrap.css', 'bootstrap.min.css'],
            'React': ['react.js', 'react-dom'],
            'Angular': ['ng-app', 'angular.js'],
            'Vue.js': ['vue.js', 'vue.min.js'],
            'PHP': ['.php', '<?php'],
            'ASP.NET': ['__viewstate', 'asp.net', '.aspx'],
            'Node.js': ['x-powered-by: express'],
            'Django': ['csrfmiddlewaretoken', 'django'],
            'Flask': ['werkzeug'],
            'Laravel': ['laravel'],
            'Google Analytics': ['google-analytics.com/analytics.js', 'gtag'],
            'Font Awesome': ['font-awesome', 'fontawesome'],
            'Cloudflare': ['cloudflare'],
            'reCAPTCHA': ['recaptcha']
        }
        
        for tech_name, patterns in technologies.items():
            if any(pattern in content for pattern in patterns):
                if tech_name not in tech:
                    tech.append(tech_name)
        
        return tech
    
    def detect_cms(self, response):
        """Détection spécifique du CMS"""
        content = response.text.lower()
        
        cms_signatures = {
            'WordPress': {
                'paths': ['/wp-content/', '/wp-includes/', '/wp-admin/'],
                'meta': ['wordpress', 'wp-'],
                'confidence': 0
            },
            'Joomla': {
                'paths': ['/components/', '/modules/', '/templates/'],
                'meta': ['joomla', 'com_content'],
                'confidence': 0
            },
            'Drupal': {
                'paths': ['/sites/default/', '/modules/', '/themes/'],
                'meta': ['drupal', 'sites/all'],
                'confidence': 0
            },
            'Shopify': {
                'paths': ['cdn.shopify.com'],
                'meta': ['shopify'],
                'confidence': 0
            },
            'Wix': {
                'paths': ['wix.com', 'parastorage.com'],
                'meta': ['wix'],
                'confidence': 0
            }
        }
        
        detected_cms = None
        max_confidence = 0
        
        for cms_name, signatures in cms_signatures.items():
            confidence = 0
            
            # Check paths
            for path in signatures['paths']:
                if path in content:
                    confidence += 1
            
            # Check meta tags
            for meta in signatures['meta']:
                if meta in content:
                    confidence += 1
            
            if confidence > max_confidence:
                max_confidence = confidence
                detected_cms = cms_name
        
        if detected_cms and max_confidence > 0:
            return {
                'name': detected_cms,
                'confidence': max_confidence,
                'detected': True
            }
        
        return {'detected': False}
    
    def check_security_headers(self, headers):
        """Vérifie la présence des headers de sécurité"""
        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'Referrer-Policy': headers.get('Referrer-Policy'),
            'Permissions-Policy': headers.get('Permissions-Policy')
        }
        
        present = {k: v for k, v in security_headers.items() if v is not None}
        missing = [k for k, v in security_headers.items() if v is None]
        
        score = len(present)
        total = len(security_headers)
        
        return {
            'present': present,
            'missing': missing,
            'score': f"{score}/{total}",
            'percentage': round((score / total) * 100, 2)
        }
    
    def check_ssl(self, url):
        """Vérifie les informations SSL/TLS"""
        hostname = urlparse(url).hostname
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'valid': True,
                        'version': ssock.version(),
                        'cipher': ssock.cipher()[0],
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'serial_number': cert.get('serialNumber'),
                        'san': cert.get('subjectAltName', [])
                    }
        except ssl.SSLError as e:
            return {'valid': False, 'error': f"SSL Error: {str(e)}"}
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def extract_emails(self, content):
        """Extrait les emails du contenu"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, content)
        # Filtrer les faux positifs communs
        filtered = [e for e in emails if not any(x in e.lower() for x in ['example.com', 'domain.com', 'test.com'])]
        return list(set(filtered))[:20]  # Limiter à 20
    
    def extract_links(self, content, base_url, internal_only=True):
        """Extrait les liens du contenu"""
        link_pattern = r'href=["\'](.*?)["\']'
        links = re.findall(link_pattern, content)
        
        base_domain = urlparse(base_url).netloc
        clean_links = []
        
        for link in links:
            # Ignorer les ancres et javascript
            if link.startswith('#') or link.startswith('javascript:') or link.startswith('mailto:'):
                continue
            
            # Construire l'URL complète
            if link.startswith('http'):
                full_url = link
            elif link.startswith('//'):
                full_url = 'https:' + link
            elif link.startswith('/'):
                full_url = urljoin(base_url, link)
            else:
                full_url = urljoin(base_url, link)
            
            # Filtrer interne/externe
            link_domain = urlparse(full_url).netloc
            
            if internal_only and link_domain == base_domain:
                clean_links.append(full_url)
            elif not internal_only and link_domain != base_domain:
                clean_links.append(full_url)
        
        return list(set(clean_links))


class SubdomainEnumerator:
    """Énumération de sous-domaines"""
    
    def __init__(self):
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'admin', 'blog', 'shop', 'api', 'dev', 'test', 'staging',
            'portal', 'vpn', 'remote', 'backup', 'cloud', 'cdn', 'mobile',
            'app', 'beta', 'demo', 'docs', 'forum', 'help', 'support',
            'secure', 'static', 'media', 'images', 'img', 'assets'
        ]
    
    def enumerate(self, domain, wordlist=None, threads=10):
        """Énumère les sous-domaines"""
        if wordlist:
            self.common_subdomains = wordlist
        
        print(f"[*] Énumération de sous-domaines pour {domain}")
        print(f"[*] Test de {len(self.common_subdomains)} sous-domaines...")
        
        results = {
            'domain': domain,
            'found': [],
            'tested': len(self.common_subdomains),
            'timestamp': datetime.now().isoformat()
        }
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._check_subdomain, subdomain, domain): subdomain 
                      for subdomain in self.common_subdomains}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results['found'].append(result)
                    print(f"[+] Trouvé: {result['subdomain']} -> {result['ip']}")
        
        print(f"[*] {len(results['found'])} sous-domaine(s) trouvé(s)")
        return results
    
    def _check_subdomain(self, subdomain, domain):
        """Vérifie si un sous-domaine existe"""
        full_domain = f"{subdomain}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            return {
                'subdomain': full_domain,
                'ip': ip,
                'subdomain_prefix': subdomain
            }
        except socket.gaierror:
            return None
        except Exception:
            return None


class PortFingerprint:
    """Fingerprinting de services via ports"""
    
    def __init__(self):
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
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            27017: "MongoDB"
        }
    
    def quick_check(self, host, timeout=2):
        """Vérifie rapidement les ports communs"""
        print(f"[*] Quick port check sur {host}")
        
        results = {
            'host': host,
            'open_ports': [],
            'timestamp': datetime.now().isoformat()
        }
        
        for port, service in self.common_ports.items():
            if self._is_port_open(host, port, timeout):
                results['open_ports'].append({
                    'port': port,
                    'service': service
                })
                print(f"[+] Port {port} ({service}) OUVERT")
        
        return results
    
    def _is_port_open(self, host, port, timeout):
        """Vérifie si un port est ouvert"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False


# Exemple d'utilisation
if __name__ == "__main__":
    target_domain = "example.com"
    target_url = f"https://{target_domain}"
    
    print("=" * 80)
    print("PENTOOL - MODULE DE RECONNAISSANCE")
    print("=" * 80)
    
    # DNS Reconnaissance
    print("\n[1] DNS RECONNAISSANCE")
    print("-" * 80)
    dns_recon = DNSRecon()
    dns_results = dns_recon.dns_lookup(target_domain)
    print(json.dumps(dns_results, indent=2))
    
    # WHOIS
    print("\n[2] WHOIS RECONNAISSANCE")
    print("-" * 80)
    whois_recon = WhoisRecon()
    whois_results = whois_recon.lookup(target_domain)
    print(json.dumps(whois_results, indent=2))
    
    # Web Reconnaissance
    print("\n[3] WEB RECONNAISSANCE")
    print("-" * 80)
    web_recon = WebRecon()
    web_results = web_recon.analyze_website(target_url)
    print(json.dumps(web_results, indent=2))
    
    # Subdomain Enumeration
    print("\n[4] SUBDOMAIN ENUMERATION")
    print("-" * 80)
    subdomain_enum = SubdomainEnumerator()
    subdomain_results = subdomain_enum.enumerate(target_domain, threads=20)
    print(json.dumps(subdomain_results, indent=2))
    
    # Port Fingerprinting
    print("\n[5] PORT FINGERPRINTING")
    print("-" * 80)
    if dns_results['records'].get('A'):
        target_ip = dns_results['records']['A'][0]
        port_check = PortFingerprint()
        port_results = port_check.quick_check(target_ip)
        print(json.dumps(port_results, indent=2))
    
    print("\n" + "=" * 80)
    print("RECONNAISSANCE TERMINÉE")
    print("=" * 80)