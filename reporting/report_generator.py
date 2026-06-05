"""
Générateur de rapports pour Pentool
Crée des rapports HTML, PDF et JSON des résultats de pentest
"""

from datetime import datetime
import json
import os
from jinja2 import Template

class ReportGenerator:
    """Générateur de rapports de pentest"""
    
    def __init__(self, project_name="Pentest Report"):
        self.project_name = project_name
        self.timestamp = datetime.now()
        self.data = {
            'project_name': project_name,
            'date': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'scans': [],
            'vulnerabilities': [],
            'summary': {}
        }
    
    def add_scan_results(self, scan_type, results):
        """Ajoute les résultats d'un scan"""
        self.data['scans'].append({
            'type': scan_type,
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
    
    def add_vulnerability(self, vuln):
        """Ajoute une vulnérabilité"""
        self.data['vulnerabilities'].append(vuln)
    
    def calculate_summary(self):
        """Calcule le résumé du rapport"""
        severities = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for vuln in self.data['vulnerabilities']:
            severity = vuln.get('severity', 'INFO')
            if severity in severities:
                severities[severity] += 1
        
        self.data['summary'] = {
            'total_vulnerabilities': len(self.data['vulnerabilities']),
            'total_scans': len(self.data['scans']),
            'severities': severities,
            'risk_score': self._calculate_risk_score(severities)
        }
    
    def _calculate_risk_score(self, severities):
        """Calcule un score de risque"""
        score = (
            severities['CRITICAL'] * 10 +
            severities['HIGH'] * 5 +
            severities['MEDIUM'] * 2 +
            severities['LOW'] * 1
        )
        
        if score >= 50:
            return {'score': score, 'level': 'CRITICAL', 'color': '#dc3545'}
        elif score >= 30:
            return {'score': score, 'level': 'HIGH', 'color': '#fd7e14'}
        elif score >= 15:
            return {'score': score, 'level': 'MEDIUM', 'color': '#ffc107'}
        else:
            return {'score': score, 'level': 'LOW', 'color': '#28a745'}
    
    def generate_json(self, filename=None):
        """Génère un rapport JSON"""
        if filename is None:
            filename = f"report_{self.timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        
        self.calculate_summary()
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=4, ensure_ascii=False)
        
        print(f"[+] Rapport JSON généré: {filename}")
        return filename
    
    def generate_html(self, filename=None):
        """Génère un rapport HTML"""
        if filename is None:
            filename = f"report_{self.timestamp.strftime('%Y%m%d_%H%M%S')}.html"
        
        self.calculate_summary()
        
        html_template = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ project_name }} - Rapport de Pentest</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        .metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .metadata-item {
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .metadata-label {
            font-size: 0.9rem;
            color: #666;
            margin-bottom: 5px;
        }
        
        .metadata-value {
            font-size: 1.2rem;
            font-weight: bold;
            color: #333;
        }
        
        .section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            color: white;
        }
        
        .critical { background: #dc3545; }
        .high { background: #fd7e14; }
        .medium { background: #ffc107; color: #333; }
        .low { background: #28a745; }
        .info { background: #17a2b8; }
        
        .summary-card h3 {
            font-size: 2.5rem;
            margin-bottom: 5px;
        }
        
        .summary-card p {
            font-size: 0.9rem;
            opacity: 0.9;
        }
        
        .risk-score {
            text-align: center;
            padding: 30px;
            border-radius: 10px;
            margin: 20px 0;
        }
        
        .risk-score h3 {
            font-size: 3rem;
            margin-bottom: 10px;
        }
        
        .vulnerability {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }
        
        .vulnerability.critical { border-left-color: #dc3545; }
        .vulnerability.high { border-left-color: #fd7e14; }
        .vulnerability.medium { border-left-color: #ffc107; }
        .vulnerability.low { border-left-color: #28a745; }
        
        .vulnerability h4 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: bold;
            color: white;
            margin-bottom: 10px;
        }
        
        .scan-result {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
        }
        
        .scan-result h4 {
            color: #667eea;
            margin-bottom: 10px;
        }
        
        pre {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.9rem;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background: #667eea;
            color: white;
        }
        
        tr:hover {
            background: #f5f5f5;
        }
        
        footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9rem;
        }
        
        @media print {
            body {
                background: white;
            }
            
            .section {
                box-shadow: none;
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ {{ project_name }}</h1>
            <p>Rapport de Test d'Intrusion</p>
            <p>{{ date }}</p>
        </header>
        
        <div class="metadata">
            <div class="metadata-item">
                <div class="metadata-label">Total Scans</div>
                <div class="metadata-value">{{ summary.total_scans }}</div>
            </div>
            <div class="metadata-item">
                <div class="metadata-label">Vulnérabilités</div>
                <div class="metadata-value">{{ summary.total_vulnerabilities }}</div>
            </div>
            <div class="metadata-item">
                <div class="metadata-label">Niveau de Risque</div>
                <div class="metadata-value">{{ summary.risk_score.level }}</div>
            </div>
            <div class="metadata-item">
                <div class="metadata-label">Score de Risque</div>
                <div class="metadata-value">{{ summary.risk_score.score }}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Résumé Exécutif</h2>
            
            <div class="risk-score" style="background-color: {{ summary.risk_score.color }}; color: white;">
                <h3>Score de Risque: {{ summary.risk_score.score }}</h3>
                <p>Niveau: {{ summary.risk_score.level }}</p>
            </div>
            
            <div class="summary-grid">
                <div class="summary-card critical">
                    <h3>{{ summary.severities.CRITICAL }}</h3>
                    <p>Critique</p>
                </div>
                <div class="summary-card high">
                    <h3>{{ summary.severities.HIGH }}</h3>
                    <p>Élevé</p>
                </div>
                <div class="summary-card medium">
                    <h3>{{ summary.severities.MEDIUM }}</h3>
                    <p>Moyen</p>
                </div>
                <div class="summary-card low">
                    <h3>{{ summary.severities.LOW }}</h3>
                    <p>Faible</p>
                </div>
                <div class="summary-card info">
                    <h3>{{ summary.severities.INFO }}</h3>
                    <p>Info</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔍 Vulnérabilités Détectées</h2>
            {% if vulnerabilities %}
                {% for vuln in vulnerabilities %}
                <div class="vulnerability {{ vuln.severity.lower() }}">
                    <span class="severity-badge" style="background-color: 
                        {% if vuln.severity == 'CRITICAL' %}#dc3545
                        {% elif vuln.severity == 'HIGH' %}#fd7e14
                        {% elif vuln.severity == 'MEDIUM' %}#ffc107
                        {% elif vuln.severity == 'LOW' %}#28a745
                        {% else %}#17a2b8{% endif %}">
                        {{ vuln.severity }}
                    </span>
                    <h4>{{ vuln.type }}</h4>
                    <p><strong>Description:</strong> {{ vuln.description }}</p>
                    {% if vuln.get('target') %}
                    <p><strong>Cible:</strong> {{ vuln.target }}</p>
                    {% endif %}
                    {% if vuln.get('recommendation') %}
                    <p><strong>Recommandation:</strong> {{ vuln.recommendation }}</p>
                    {% endif %}
                </div>
                {% endfor %}
            {% else %}
                <p>Aucune vulnérabilité détectée.</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>📋 Résultats des Scans</h2>
            {% for scan in scans %}
            <div class="scan-result">
                <h4>{{ scan.type }}</h4>
                <p><small>{{ scan.timestamp }}</small></p>
                <pre>{{ scan.results | tojson(indent=2) }}</pre>
            </div>
            {% endfor %}
        </div>
        
        <footer>
            <p>Généré par Pentool - {{ date }}</p>
            <p>Ce rapport est confidentiel et destiné uniquement au client.</p>
        </footer>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        html_content = template.render(**self.data)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] Rapport HTML généré: {filename}")
        return filename
    
    def generate_txt(self, filename=None):
        """Génère un rapport texte simple"""
        if filename is None:
            filename = f"report_{self.timestamp.strftime('%Y%m%d_%H%M%S')}.txt"
        
        self.calculate_summary()
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"{self.project_name}\n")
            f.write(f"Rapport de Test d'Intrusion\n")
            f.write(f"Date: {self.data['date']}\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("RÉSUMÉ\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Scans: {self.data['summary']['total_scans']}\n")
            f.write(f"Total Vulnérabilités: {self.data['summary']['total_vulnerabilities']}\n")
            f.write(f"Score de Risque: {self.data['summary']['risk_score']['score']} ({self.data['summary']['risk_score']['level']})\n\n")
            
            f.write("VULNÉRABILITÉS PAR SÉVÉRITÉ\n")
            f.write("-" * 80 + "\n")
            for severity, count in self.data['summary']['severities'].items():
                f.write(f"{severity}: {count}\n")
            f.write("\n")
            
            f.write("VULNÉRABILITÉS DÉTECTÉES\n")
            f.write("-" * 80 + "\n")
            for i, vuln in enumerate(self.data['vulnerabilities'], 1):
                f.write(f"\n{i}. [{vuln['severity']}] {vuln['type']}\n")
                f.write(f"   Description: {vuln['description']}\n")
                if 'target' in vuln:
                    f.write(f"   Cible: {vuln['target']}\n")
            
            f.write("\n" + "=" * 80 + "\n")
        
        print(f"[+] Rapport TXT généré: {filename}")
        return filename


# Exemple d'utilisation
if __name__ == "__main__":
    # Création d'un rapport exemple
    report = ReportGenerator("Test Pentest - example.com")
    
    # Ajout de résultats de scan
    report.add_scan_results("Network Scan", {
        "network": "192.168.1.0/24",
        "active_hosts": 15
    })
    
    report.add_scan_results("Port Scan", {
        "target": "192.168.1.100",
        "open_ports": [22, 80, 443]
    })
    
    # Ajout de vulnérabilités
    report.add_vulnerability({
        "type": "SQL Injection",
        "severity": "CRITICAL",
        "target": "https://example.com/login.php",
        "description": "Le paramètre 'id' est vulnérable aux injections SQL",
        "recommendation": "Utiliser des requêtes préparées"
    })
    
    report.add_vulnerability({
        "type": "Weak Password",
        "severity": "HIGH",
        "target": "SSH - 192.168.1.100:22",
        "description": "Mot de passe faible détecté (admin/admin123)",
        "recommendation": "Implémenter une politique de mots de passe forts"
    })
    
    report.add_vulnerability({
        "type": "Missing Security Headers",
        "severity": "MEDIUM",
        "target": "https://example.com",
        "description": "Headers de sécurité manquants: X-Frame-Options, CSP",
        "recommendation": "Configurer les headers de sécurité appropriés"
    })
    
    # Génération des rapports
    report.generate_json()
    report.generate_html()
    report.generate_txt()
    
    print("\n[+] Tous les rapports ont été générés avec succès!")