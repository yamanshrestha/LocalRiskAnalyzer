import os
import json
from datetime import datetime

def save_logs(services, processes, state_counts):
    # Create timestamped folder inside logs/
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_dir = os.path.join("logs", timestamp)
    os.makedirs(log_dir, exist_ok=True)

    # Save PRETTY TXT files
    save_txt_pretty(services, processes, state_counts, log_dir)

    # Save JSON files (same structure as before)
    with open(os.path.join(log_dir, "services.json"), "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": timestamp,
            "state_counts": state_counts,
            "services": services
        }, f, indent=4)

    with open(os.path.join(log_dir, "processes.json"), "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": timestamp,
            "processes": processes
        }, f, indent=4)
    
    save_html_report(services, processes, state_counts, log_dir) # to save html


def save_txt_pretty(services, processes, state_counts, log_folder):
    # === SERVICES TXT ===
    with open(os.path.join(log_folder, "services.txt"), "w", encoding="utf-8") as f:
        f.write("=== WINDOWS SERVICES ===\n")
        f.write(f"{'NAME':<25} {'STATE':<10} {'VERSION':<20} {'RISK':<10} PATH\n")
        f.write("-" * 120 + "\n")
        for s in services:
            risk = s.get("risk", "Unknown")
            f.write(f"{s['name']:<25} {s['state']:<10} {s['version']:<20} {risk:<10} {s['path']}\n")

            # Show associated CVEs (if any)
            if s.get("cves"):
                for cve in s["cves"]:
                    cve_id = cve.get("cve_id", "N/A")
                    cvss = cve.get("cvss", "N/A")
                    desc = cve.get("description", "").strip()[:60] + "..."
                    f.write(f"{'':<25} {'':<10} {'':<20} {'':<10}  → {cve_id} | CVSS: {cvss} | {desc}\n")

        f.write("\n=== SERVICE STATE COUNTS ===\n")
        for state, count in state_counts.items():
            f.write(f"{state:<10}: {count}\n")

    # === PROCESSES TXT ===
    with open(os.path.join(log_folder, "processes.txt"), "w", encoding="utf-8") as f:
        f.write("=== RUNNING PROCESSES ===\n")
        f.write(f"{'NAME':<25} {'PID':<7} {'VERSION':<20} {'RISK':<10} {'LINKED_SERVICE':<20} PATH\n")
        f.write("-" * 140 + "\n")
        for p in processes:
            risk = p.get("risk", "Unknown")
            linked_service = p.get("linked_service", "None")
            f.write(f"{p['name']:<25} {p['pid']:<7} {p['version']:<20} {risk:<10} {linked_service:<20} {p['path']}\n")

            if p.get("cves"):
                for cve in p["cves"]:
                    cve_id = cve.get("cve_id", "N/A")
                    cvss = cve.get("cvss", "N/A")
                    desc = cve.get("description", "").strip()[:60] + "..."
                    f.write(f"{'':<25} {'':<7} {'':<20} {'':<10} {'':<20}  → {cve_id} | CVSS: {cvss} | {desc}\n")


def save_html_report(services, processes, state_counts, log_folder):
    html_path = os.path.join(log_folder, "report.html")

    def risk_color(risk):
        return {
            "High": "#ff4c4c",
            "Medium": "#ffa500",
            "Low": "#66cc66",
            "Unknown": "#dddddd"
        }.get(risk, "#eeeeee")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Local Risk Report</title>")
        f.write("<style>")
        f.write("body { font-family: Arial; }")
        f.write("h1, h2 { color: #333; }")
        f.write("table { border-collapse: collapse; width: 100%; margin-bottom: 40px; }")
        f.write("th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }")
        f.write("th { background-color: #f2f2f2; }")
        f.write("</style></head><body>")

        f.write("<h1>🛡️ LocalRiskAnalyzer - Report</h1>")
        f.write("<h2>🧩 Windows Services</h2>")
        f.write("<table><tr><th>Name</th><th>State</th><th>Version</th><th>Risk</th><th>Path</th></tr>")
        for s in services:
            risk = s.get("risk", "Unknown")
            f.write(f"<tr style='background-color:{risk_color(risk)};'>")
            f.write(f"<td>{s['name']}</td><td>{s['state']}</td><td>{s['version']}</td><td>{risk}</td><td>{s['path']}</td></tr>")
            if s.get("cves"):
                for cve in s["cves"]:
                    f.write(f"<tr><td colspan='5'>→ <b>{cve['cve_id']}</b> | CVSS: {cve['cvss']}<br>{cve['description']}</td></tr>")
        f.write("</table>")

        f.write("<h2>🖥️ Processes</h2>")
        f.write("<table><tr><th>Name</th><th>PID</th><th>Version</th><th>Risk</th><th>Linked Service</th><th>Path</th></tr>")
        for p in processes:
            risk = p.get("risk", "Unknown")
            linked_service = p.get("linked_service", "None")
            f.write(f"<tr style='background-color:{risk_color(risk)};'>")
            f.write(f"<td>{p['name']}</td><td>{p['pid']}</td><td>{p['version']}</td><td>{risk}</td><td>{linked_service}</td><td>{p['path']}</td></tr>")
            if p.get("cves"):
                for cve in p["cves"]:
                    f.write(f"<tr><td colspan='6'>→ <b>{cve['cve_id']}</b> | CVSS: {cve['cvss']}<br>{cve['description']}</td></tr>")
        f.write("</table>")

        f.write("<h3>📊 Service State Counts</h3>")
        f.write("<ul>")
        for state, count in state_counts.items():
            f.write(f"<li><b>{state}:</b> {count}</li>")
        f.write("</ul>")

        f.write("</body></html>")
