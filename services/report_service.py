from reporting.report_generator import ReportGenerator

def create_report(project_name, scans, output="html"):
    report = ReportGenerator(project_name)
    
    for scan in scans:
        report.add_scan_results(scan["type"], scan["data"])

    if output == "json":
        return report.generate_json()
    else:
        return report.generate_html()
