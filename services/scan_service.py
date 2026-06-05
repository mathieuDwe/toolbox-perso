from modules.scan import (
    NetworkScanner,
    PortScanner,
    ServiceDetector,
    ScanManager

)


def run_network_scan(network_range, timeout=1):
    scanner = NetworkScanner(timeout=timeout)
    results = scanner.scan_network(network_range)
    filename = ScanManager.save_scan_results("network_scan", results)
    return {"results": results, "file": filename}
