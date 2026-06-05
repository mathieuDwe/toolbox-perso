from flask import Blueprint, request, jsonify, session
from services.scan_service import (
    NetworkScanner,
    PortScanner,
    ServiceDetector,
    ScanManager
    ) 
from modules.wifi_analyzer import scan_wifi as run_wifi_scan

scans_bp = Blueprint("scans", __name__)


# =====================================================
#   PROTECTION
# =====================================================

def require_auth():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401


# =====================================================
#   LIST SCANS
# =====================================================

@scans_bp.get("/")
def list_scans():
    require_auth()
    scans = ScanManager.list_all_scans()
    return jsonify(scans)


# =====================================================
#   NETWORK SCAN
# =====================================================

@scans_bp.post("/network")
def scan_network():
    require_auth()
    data = request.json
    result = NetworkScanner(data["network_range"], data.get("timeout", 1))
    return jsonify(result)


# =====================================================
#   PORT SCAN
# =====================================================

@scans_bp.post("/port")
def scan_port():
    require_auth()
    data = request.json
    result = PortScanner(
        target=data["target"],
        scan_type=data.get("scan_type", "common"),
        timeout=data.get("timeout", 1)
    )
    return jsonify(result)


# =====================================================
#   WEB ANALYSIS
# =====================================================

@scans_bp.post("/web")
def scan_web():
    require_auth()
    data = request.json
    result = ServiceDetector.web_analysis(data["url"])
    return jsonify(result)


# =====================================================
#   DNS
# =====================================================

@scans_bp.post("/dns")
def scan_dns():
    require_auth()
    data = request.json
    result = ServiceDetector.dns_scan(data)
    return jsonify(result)


# =====================================================
#   SUBDOMAIN ENUM
# =====================================================

@scans_bp.post("/subdomains")
def subdomain_enum():
    require_auth()
    data = request.json
    result = ServiceDetector.subdomain_scan(data["domain"], data.get("threads", 10))
    return jsonify(result)


# =====================================================
#   FUZZING
# =====================================================

@scans_bp.post("/fuzz")
def fuzz():
    require_auth()
    data = request.json
    result = ServiceDetector.fuzz(data)
    return jsonify(result)


# =====================================================
#   VULNERABILITY SCAN
# =====================================================

@scans_bp.post("/vuln")
def vuln_scan():
    require_auth()
    data = request.json
    result = ServiceDetector.vuln_scan(data["url"])
    return jsonify(result)


# =====================================================
#   BRUTE FORCE
# =====================================================

@scans_bp.post("/bruteforce")
def bf_scan():
    require_auth()
    data = request.json
    result = ServiceDetector.bruteforce_scan(data)
    return jsonify(result)


# =====================================================
#   WIFI
# =====================================================

@scans_bp.post("/wifi")
def wifi_scan():
    require_auth()
    data = request.json
    result = run_wifi_scan(data)
    return jsonify(result)