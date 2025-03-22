import argparse
from scanner import scan_services
from scanner import scan_processes, safe_cvss_score
from logger import save_logs
from cve import search_cves, get_cpe_matches, search_cves_by_cpe

def main(enable_cve=False, stop_limit=None):
    print("[+] Scanning services...")
    services, state_counts = scan_services()

    print("[+] Scanning processes...")
    processes = scan_processes()

    if enable_cve:
        print("[+] Scanning CVEs for services...")
    # Step 2: Add CVE info and risk scoring to services
        for idx, service in enumerate(services):
            if stop_limit is not None and idx >= stop_limit:
                print(f"[!] CVE scan stopped after {stop_limit} service(s)")
                break
            
            cpe_matches = get_cpe_matches(service["name"])
            if cpe_matches:
                print(f"    ↳ {service['name']} → CPE: {cpe_matches[0]}")
                cves = search_cves_by_cpe(cpe_matches[0])
            else:
                print(f"    ↳ {service['name']} → No CPE match, using keyword search")
                cves = search_cves(service["name"])
            service['cves'] = cves
            service['risk'] = (
                "High" if any(safe_cvss_score(cve.get("cvss")) >= 7.0 for cve in cves) else
                "Medium" if cves else
                "Low"
            )

        print("[+] Scanning CVEs for processes...")
        # Step 3: Add CVE info and risk scoring to processes
        for idx, process in enumerate(processes):
            if stop_limit is not None and idx >= stop_limit:
                print(f"[!] CVE scan stopped after {stop_limit} service(s)")
                break
            
            # Prefer linked service name for CVE checking if available
            keyword = process.get('linked_service') if process.get('linked_service') != "None" else process['name']
            
             # Try CPE match
            cpe_matches = get_cpe_matches(keyword)
            if cpe_matches:
                print(f"    ↳ {keyword} → CPE: {cpe_matches[0]}")
                cves = search_cves_by_cpe(cpe_matches[0])
            else:
                print(f"    ↳ {keyword} → No CPE match, using keyword search")
                cves = search_cves(keyword)

            process['cves'] = cves
            process['risk'] = (
                "High" if any(safe_cvss_score(cve.get("cvss")) >= 7.0 for cve in cves) else
                "Medium" if cves else
                "Low"
            )
    else:
        print("[+] Skipping CVE scanning (no -cve flag provided)")
    # Step 4: Save all logs (JSON + TXT)
    print("[+] Saving logs...")
    save_logs(services, processes, state_counts)
    print("[✔] Done!")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LocalRiskAnalyzer - Service and Process Scanner")
    parser.add_argument("-cve", action="store_true", help="Enable CVE scanning for services and processes")
    parser.add_argument("-stop", type=int, help="Stop CVE scanning after N services and N processes")
    args = parser.parse_args()
    # Friendly warning for invalid flag combo
    if not args.cve and args.stop is not None:
        print("[!] Warning: '--stop' has no effect unless used with '-cve'")

    main(enable_cve=args.cve, stop_limit=args.stop)