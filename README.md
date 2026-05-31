# CVE
An automated solution to extract vulnerabilities from Linux package names by converting them to CPE format and querying the NVD API. Useful when traditional vulnerability scanners like Nessus cannot be used.

## Workflow
1. how to get package names and version
```
apt list
rpm -l
```

2. convert the package to CPE
   
Use this tool to convert a package list to CPE: https://github.com/ra1nb0rn/cpe_search
```
cpe_search -q "Sudo 1.8.2"
while IFS= read -r line; do cpe_search -q "$line"| xargs echo ; done < installed_package_list.txt | tee CPE_LIST
```

3. convert CPE contains file to the CVE
```
import requests
import csv
import sys
import time
import os
from datetime import datetime

# ================== CONFIGURATION ==================
SLEEP_SECONDS = 5
INPUT_FILE = "CPEs"          # File containing CPEs (one per line)
OUTPUT_FILE = "nvd_cves_report.csv"
TEMP_FILE = "nvd_cves_temp.csv"  # For crash recovery
# ===================================================

def fetch_nvd_cves(cpe_name):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}"
    headers = {"Accept": "application/json"}
    
    response = requests.get(url, headers=headers, timeout=60)
    response.raise_for_status()
    return response.json()


def extract_cvss_v3_score(cve):
    try:
        metrics = cve.get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30"]:
            if version in metrics:
                for metric in metrics[version]:
                    if metric.get("type") == "Primary":
                        return metric["cvssData"].get("baseScore", "")
        return ""
    except:
        return ""


def get_severity(cve):
    try:
        metrics = cve.get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30"]:
            if version in metrics:
                for metric in metrics[version]:
                    if metric.get("type") == "Primary":
                        return metric["cvssData"].get("baseSeverity", "")
        return ""
    except:
        return ""


def get_fixed_version(cve):
    try:
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        if "versionEndExcluding" in cpe_match:
                            return cpe_match["versionEndExcluding"]
                        if "versionEndIncluding" in cpe_match:
                            return cpe_match["versionEndIncluding"]
    except:
        pass
    return ""


def main():
    # Read CPEs from file
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found!")
        print("Please create the file and put one CPE per line.")
        sys.exit(1)

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        cpes = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not cpes:
        print("No CPEs found in the file.")
        sys.exit(1)

    print(f"Loaded {len(cpes)} CPEs from {INPUT_FILE}\n")

    # CSV Headers
    headers = [
        "CVE", "Risk Severity", "Name", "Description", "Solution",
        "CVSS v3.0 Base Score", "Component", "Installed version",
        "Fixed version", "Missing patch", "Path", "Remote package installed",
        "Should be", "Third-Party Advice", "Advice Type", "Security Comments",
        "Owner Comments", "Security Reviews", "CPE"
    ]

    # Check if output file exists, if not write headers
    file_exists = os.path.exists(OUTPUT_FILE)

    # Use temp file for safety
    write_file = TEMP_FILE if os.path.exists(TEMP_FILE) else OUTPUT_FILE

    mode = "a" if file_exists or os.path.exists(TEMP_FILE) else "w"
    
    with open(write_file, mode, newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        
        # Write headers only if new file
        if mode == "w":
            writer.writerow(headers)

        for i, cpe in enumerate(cpes, 1):
            print(f"[{i}/{len(cpes)}] Processing: {cpe}")
            
            try:
                data = fetch_nvd_cves(cpe)
                vulnerabilities = data.get("vulnerabilities", [])

                for item in vulnerabilities:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")

                    # Description
                    description = ""
                    for d in cve.get("descriptions", []):
                        if d.get("lang") == "en":
                            description = d.get("value", "").replace("\n", " ").replace("\r", " ")
                            break

                    cvss_score = extract_cvss_v3_score(cve)
                    severity = get_severity(cve)
                    fixed_version = get_fixed_version(cve)

                    # Component & Version from CPE
                    try:
                        parts = cpe.split(":")
                        component = parts[4] if len(parts) > 4 else ""
                        installed_ver = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
                    except:
                        component = ""
                        installed_ver = ""

                    row = [
                        cve_id,
                        severity,
                        cve_id,
                        description,
                        "",                     # Solution
                        cvss_score,
                        component,
                        installed_ver,
                        fixed_version,
                        "", "", "", "", "", "", "", "", "",  # Empty columns
                        cpe                     # Added CPE at the end for traceability
                    ]
                    writer.writerow(row)

                print(f"    ✓ Found {len(vulnerabilities)} vulnerabilities")

            except Exception as e:
                print(f"    ✗ ERROR processing {cpe} -> {type(e).__name__}: {e}")
                # Log error CPE
                error_row = ["ERROR", "", cpe, f"Failed to fetch: {str(e)}", 
                           "", "", "", "", "", "", "", "", "", "", "", "", "", "", cpe]
                writer.writerow(error_row)

            # Sleep between requests (except after last one)
            if i < len(cpes):
                print(f"    Sleeping {SLEEP_SECONDS} seconds to respect rate limit...")
                time.sleep(SLEEP_SECONDS)

    # Final: Rename temp to final file
    if os.path.exists(TEMP_FILE):
        if os.path.exists(OUTPUT_FILE):
            os.remove(OUTPUT_FILE)
        os.rename(TEMP_FILE, OUTPUT_FILE)

    print("\n" + "="*60)
    print("PROCESS COMPLETED!")
    print(f"Final report saved as: {OUTPUT_FILE}")
    print("="*60)


if __name__ == "__main__":
    main()
```
