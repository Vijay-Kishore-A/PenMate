import requests
import json

def check_headers(response):
    security_headers = {
        "Strict-Transport-Security": "HIGH",
        "Content-Security-Policy": "HIGH",
        "X-Frame-Options": "MEDIUM",
        "X-Content-Type-Options": "MEDIUM",
        "Referrer-Policy": "LOW",
        "Permissions-Policy": "LOW"
    }
    
    findings = []
    
    redirect_headers = set()
    for redirect in response.history:
        for header in redirect.headers:
            redirect_headers.add(header)
    
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
                if header in redirect_headers:
                    findings.append({
                        "header": header,
                        "status": "PARTIAL",
                        "severity": severity,
                        "value": "Present on redirect only — not enforced on final response"
                    })
                else:
                    findings.append({
                        "header": header,
                        "status": "MISSING",
                        "severity": severity,
                        "value": None
                    })
        else:
            if header in response.headers:
                findings.append({
                    "header": header,
                    "status": "PRESENT",
                    "severity": severity,
                    "value": response.headers[header]
                })
            elif header in redirect_headers:
                findings.append({
                    "header": header,
                    "status": "PARTIAL",
                    "severity": severity,
                    "value": "Present on redirect only — not enforced on final response"
                })
            else:
                findings.append({
                    "header": header,
                    "status": "MISSING",
                    "severity": severity,
                    "value": None
                })
    print(f"Redirect headers found: {redirect_headers}", file=__import__('sys').stderr)
    return findings


def check_cookies(response):
    findings = []
    raw_cookies = response.raw.headers.getlist("Set-Cookie")
    
    if not raw_cookies:
        return [{"cookie": None, "status": "INFO", "severity": "LOW", "value": "No cookies found"}]
    
    for cookie in raw_cookies:
        cookie_name = cookie.split("=")[0].strip()
        
        if "HttpOnly" not in cookie:
            findings.append({
                "cookie": cookie_name,
                "status": "MISSING",
                "severity": "HIGH",
                "attribute": "HttpOnly",
                "value": "Cookie accessible via JavaScript — XSS can steal session"
            })
        
        if "Secure" not in cookie:
            findings.append({
                "cookie": cookie_name,
                "status": "MISSING",
                "severity": "HIGH",
                "attribute": "Secure",
                "value": "Cookie transmitted over HTTP — vulnerable to interception"
            })
        
        if "SameSite" not in cookie:
            findings.append({
                "cookie": cookie_name,
                "status": "MISSING",
                "severity": "MEDIUM",
                "attribute": "SameSite",
                "value": "No SameSite attribute — CSRF risk"
            })
        elif "SameSite=None" in cookie and "Secure" not in cookie:
            findings.append({
                "cookie": cookie_name,
                "status": "MISCONFIGURED",
                "severity": "HIGH",
                "attribute": "SameSite",
                "value": "SameSite=None requires Secure flag — missing"
            })
    
    return findings


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