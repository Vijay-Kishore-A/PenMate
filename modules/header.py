
import requests

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