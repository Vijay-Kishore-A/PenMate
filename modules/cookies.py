import requests

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