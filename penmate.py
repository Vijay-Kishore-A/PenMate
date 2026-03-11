import requests
import json

def check_headers(url):
    security_headers = {
        "Strict-Transport-Security": "HIGH",
        "Content-Security-Policy": "HIGH",
        "X-Frame-Options": "MEDIUM",
        "X-Content-Type-Options": "MEDIUM",
        "Referrer-Policy": "LOW",
        "Permissions-Policy": "LOW"
    }
    
    findings = []
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.Timeout:
        return [{"header": None, "status": "ERROR", "severity": None, "value": "Request timed out"}]
    except requests.exceptions.ConnectionError:
        return [{"header": None, "status": "ERROR", "severity": None, "value": "Could not connect to target"}]
    except requests.exceptions.HTTPError as e:
        return [{"header": None, "status": "ERROR", "severity": None, "value": f"HTTP error {e}"}]
    
    for header, severity in security_headers.items():
        if header == "Content-Security-Policy":
            if header in response.headers:
                findings.append({
                    "header": header,
                    "status": "PRESENT",
                    "severity": severity,
                    "value": response.headers[header]
                })
            elif "Content-Security-Policy-Report-Only" in response.headers:
                findings.append({
                    "header": header,
                    "status": "MISCONFIGURED",
                    "severity": severity,
                    "value": "CSP in report-only mode — not enforced, XSS mitigations ineffective"
                })
            else:
                findings.append({
                    "header": header,
                    "status": "MISSING",
                    "severity": severity,
                    "value": None
                })
        else:
            if header not in response.headers:
                findings.append({
                    "header": header,
                    "status": "MISSING",
                    "severity": severity,
                    "value": None
                })
            else:
                findings.append({
                    "header": header,
                    "status": "PRESENT",
                    "severity": severity,
                    "value": response.headers[header]
                })
    
    return findings

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="PenMate - Web Application Security Recon Tool")
    parser.add_argument("url", help="Target URL to scan")
    args = parser.parse_args()
    
    results = check_headers(args.url)
    for r in results:
        print(r)