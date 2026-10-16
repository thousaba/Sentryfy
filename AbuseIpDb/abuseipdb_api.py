import sys
import csv
import urllib.request
import json
import os

LOCAL_PREFIXES = (
    "10.", "192.168.", "127.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
    "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.",
)
API_URL = "https://www.abuseipdb.com/api/v2/check"


def load_dotenv(path):
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    sys.exit("API_KEY bulunamadı. Proje köküne .env dosyası ekleyip içine 'API_KEY = <senin-keyin>' yaz.")


def check_ip(ip):
    if not ip or ip.startswith(LOCAL_PREFIXES):
        return 0, "LOCAL", 0

    req = urllib.request.Request(
        f"{API_URL}?ipAddress={ip}&maxAgeInDays=90",
        headers={"Key": API_KEY, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            attrs = json.loads(response.read().decode()).get("data", {})
            return (
                attrs.get("abuseConfidenceScore", 0),
                attrs.get("countryCode", "N/A"),
                attrs.get("totalReports", 0),
            )
    except Exception:
        return -1, "ERROR", 0


def main():
    reader = csv.reader(sys.stdin)
    writer = csv.writer(sys.stdout)

    header = next(reader, None)
    if not header:
        return

    try:
        ip_idx = header.index("ip")
    except ValueError:
        writer.writerow(header + ["abuseConfidenceScore", "countryCode", "totalReports"])
        return

    writer.writerow(header + ["abuseConfidenceScore", "countryCode", "totalReports"])

    for row in reader:
        if not row:
            continue
        score, country, reports = check_ip(row[ip_idx])
        writer.writerow(row + [score, country, reports])


if __name__ == "__main__":
    main()
