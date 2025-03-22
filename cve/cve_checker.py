import os
from dotenv import load_dotenv
import requests
import time
# Load the .env file
load_dotenv()

# Grab the API key securely from environment
API_KEY = os.getenv("NVD_API_KEY")

# NVD Endpoints
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_cpe_matches(product_name):
    """
    Use NVD's CPE API to fetch matching CPE names based on product name.
    Returns a list of matching CPE strings.
    """
    if not API_KEY:
        print("[!] Missing NVD API Key.")
        return []

    headers = {"apiKey": API_KEY}
    params = {
        "keywordSearch": product_name,
        "resultsPerPage": 3  # You can adjust to get more results if needed
    }

    try:
        time.sleep(0.7)
        response = requests.get(NVD_CPE_API, headers=headers, params=params, timeout=8)
        response.raise_for_status()
        data = response.json()

        cpe_matches = [
            item["cpe"]["cpeName"]
            for item in data.get("products", [])
            if "cpe" in item and "cpeName" in item["cpe"]
        ]

        return cpe_matches

    except Exception as e:
        print(f"[!] CPE lookup error for '{product_name}': {e}")
        return []

def search_cves_by_cpe(cpe_name):
    """
    Search CVEs using a known CPE string.
    """
    if not API_KEY:
        print("[!] Missing NVD API Key.")
        return []

    headers = {"apiKey": API_KEY}
    params = {
        "cpeName": cpe_name,
        "resultsPerPage": 5
    }

    try:
        time.sleep(0.7)
        response = requests.get(NVD_CVE_API, headers=headers, params=params, timeout=8)
        response.raise_for_status()
        data = response.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id")
            description = cve_data.get("descriptions", [{}])[0].get("value", "No description")
            cvss = (
                cve_data.get("metrics", {})
                .get("cvssMetricV31", [{}])[0]
                .get("cvssData", {})
                .get("baseScore", "N/A")
            )

            cves.append({
                "cve_id": cve_id,
                "cvss": cvss,
                "description": description
            })

        return cves

    except Exception as e:
        print(f"[!] Error fetching CVEs for CPE '{cpe_name}': {e}")
        return []

def search_cves(keyword, results_limit=5):
    """
    Fallback search using product name keyword.
    """
    if not API_KEY:
        print("[!] Missing NVD API Key.")
        return []

    headers = {"apiKey": API_KEY}
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_limit
    }

    try:
        time.sleep(0.7)
        response = requests.get(NVD_CVE_API, headers=headers, params=params, timeout=8)
        response.raise_for_status()
        data = response.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id")
            description = cve_data.get("descriptions", [{}])[0].get("value", "No description")
            cvss = (
                cve_data.get("metrics", {})
                .get("cvssMetricV31", [{}])[0]
                .get("cvssData", {})
                .get("baseScore", "N/A")
            )

            cves.append({
                "cve_id": cve_id,
                "cvss": cvss,
                "description": description
            })

        return cves

    except Exception as e:
        print(f"[!] Error fetching CVEs: {e}")
        return []