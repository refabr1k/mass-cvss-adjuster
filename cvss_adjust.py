import requests
import time
import argparse
from cvss import CVSS3

AV_ADJUST = "L"  # Change to "A" for Adjacent or "L" for Local

# Fetch CVSS vector (v3.1 or v3.0)
def fetch_cvss_vector(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"User-Agent": "cvss-adjuster/1.0"}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        metrics = data.get("vulnerabilities", [{}])[0].get("cve", {}).get("metrics", {})
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0]["cvssData"]["vectorString"].replace("\\/", "/")
        elif "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0]["cvssData"]["vectorString"].replace("\\/", "/")
        else:
            return None
    except Exception as e:
        print(f"{cve_id} - Error fetching CVSS vector: {e}")
        return None

# Modify AV and recalculate vector and score
def modify_vector_av(original_vector, new_av):
    BASE_METRICS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
    try:
        cvss = CVSS3(original_vector)
        metrics = cvss.metrics.copy()
        metrics["AV"] = new_av

        # Only rebuild vector from base metrics
        new_vector_parts = [f"{k}:{v}" for k, v in metrics.items() if k in BASE_METRICS]
        new_vector = "CVSS:3.1/" + "/".join(new_vector_parts)

        new_cvss = CVSS3(new_vector)
        return new_vector, new_cvss.scores()[0]
    except Exception as e:
        print(f"Error modifying vector '{original_vector}': {e}")
        return None, None

# Severity rating based on score
def get_severity(score):
    if score is None:
        return "Unknown"
    elif score < 4.0:
        return "Low"
    elif score < 7.0:
        return "Medium"
    elif score < 9.0:
        return "High"
    else:
        return "Critical"

def main():
    parser = argparse.ArgumentParser(description="Fetch and adjust CVSS vectors from CVE list")
    parser.add_argument("filename", help="Path to file containing CVE IDs, one per line")
    args = parser.parse_args()

    try:
        with open(args.filename, "r") as file:
            cve_list = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"File '{args.filename}' not found.")
        return

    # CSV Header
    print("CVE ID,Original Vector,Original Severity,Modified Vector,Modified Severity")

    for idx, cve in enumerate(cve_list):
        original_vector = fetch_cvss_vector(cve)
        if original_vector:
            try:
                original_cvss = CVSS3(original_vector)
                original_score = original_cvss.scores()[0]
                original_severity = get_severity(original_score)
            except Exception as e:
                original_score = None
                original_severity = "Invalid"

            modified_vector, modified_score = modify_vector_av(original_vector, AV_ADJUST)
            modified_severity = get_severity(modified_score) if modified_score is not None else "Invalid"

            if modified_vector:
                print(f"{cve},{original_vector},{original_severity},{modified_vector},{modified_severity}")
            else:
                print(f"{cve},{original_vector},{original_severity},Error,Error")
        else:
            print(f"{cve},No CVSS v3.x vector found,Unknown,Error,Error")

        if idx < len(cve_list) - 1:
            time.sleep(6.1)  # respect NVD rate limits

if __name__ == "__main__":
    main()
