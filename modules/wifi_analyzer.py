from flask import Blueprint, jsonify
import pywifi
from pywifi import const
import time

wifi_analyzer_bp = Blueprint('wifi_analyzer', __name__)

@wifi_analyzer_bp.route('/scan_wifi')
def scan_wifi():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]  # Première interface WiFi
    iface.scan()
    time.sleep(3)  # Attendre le scan
    results = iface.scan_results()

    # Trier par force du signal et limiter à 10 meilleurs
    sorted_results = sorted(results, key=lambda x: x.signal, reverse=True)[:10]

    networks = []
    for network in sorted_results:
        ssid = network.ssid if network.ssid else "Réseau caché"
        signal = network.signal
        channel = network.freq
        band = "2.4 GHz" if network.freq < 5000 else "5 GHz"

        networks.append({
            "ssid": ssid,
            "signal": signal,
            "channel": channel,
            "band": band
        })

    return jsonify(networks)