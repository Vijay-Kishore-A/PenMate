import requests
import json

from modules.header import check_headers
from modules.cookies import check_cookies

if __name__ == "__main__":
    import argparse
    import csv
    import io
    
    parser = argparse.ArgumentParser(description="PenMate - Web Application Security Recon Tool")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--output", choices=["json", "csv"], default="text", help="Output format: json, csv, or text")
    args = parser.parse_args()

    try:
        response = requests.get(args.url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.Timeout:
        print("ERROR: Request timed out")
        exit(1)
    except requests.exceptions.ConnectionError:
        print("ERROR: Could not connect to target")
        exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"ERROR: HTTP error {e}")
        exit(1)

    header_findings = check_headers(response)
    cookie_findings = check_cookies(response)
    results = header_findings + cookie_findings

    if args.output == "json":
        print(json.dumps(results, indent=2))
    elif args.output == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["header", "status", "severity", "value"])
        writer.writeheader()
        writer.writerows(results)
        print(output.getvalue())
    else:
        for r in results:
            print(r)