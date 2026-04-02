# ============================================================
# WAF Simulator — Flask Backend
# Nivedhitha KS | Cybersecurity Portfolio
# Simulates a Web Application Firewall — shows how WAF rules
# detect attacks and how attackers attempt bypasses
# ============================================================

from flask import Flask, render_template, request, jsonify
import re
import datetime

app = Flask(__name__)

# ── WAF Rule Engine ──────────────────────────────────────────

WAF_RULES = [
    # SQLi rules
    {
        "id": "WAF-001",
        "name": "SQL Injection — Classic",
        "category": "SQLi",
        "severity": "CRITICAL",
        "pattern": r"('|\"|--|;|\/\*|\*\/|xp_|exec\s|union\s+select|select\s+\*|insert\s+into|drop\s+table|alter\s+table|1=1|or\s+1|and\s+1)",
        "description": "Detects classic SQL injection payloads including UNION SELECT, OR 1=1, comment sequences.",
        "cve_ref": "CWE-89"
    },
    {
        "id": "WAF-002",
        "name": "SQL Injection — Blind/Boolean",
        "category": "SQLi",
        "severity": "HIGH",
        "pattern": r"(sleep\s*\(|waitfor\s+delay|benchmark\s*\(|and\s+\d+=\d+|or\s+\d+=\d+|if\s*\()",
        "description": "Detects time-based and boolean-based blind SQL injection payloads.",
        "cve_ref": "CWE-89"
    },
    # XSS rules
    {
        "id": "WAF-003",
        "name": "XSS — Script Tag Injection",
        "category": "XSS",
        "severity": "HIGH",
        "pattern": r"(<script[\s>]|<\/script>|javascript:|on\w+\s*=|<img[^>]+onerror|<svg[^>]+onload)",
        "description": "Detects script tag injection, event handler injection, and javascript: URI schemes.",
        "cve_ref": "CWE-79"
    },
    {
        "id": "WAF-004",
        "name": "XSS — HTML Attribute Injection",
        "category": "XSS",
        "severity": "MEDIUM",
        "pattern": r"(expression\s*\(|vbscript:|<iframe|<object|<embed|<link[^>]+href|data:text\/html)",
        "description": "Detects HTML attribute-based XSS including iframe injection and data URIs.",
        "cve_ref": "CWE-79"
    },
    # Path traversal
    {
        "id": "WAF-005",
        "name": "Path Traversal",
        "category": "LFI/RFI",
        "severity": "HIGH",
        "pattern": r"(\.\.[\/\\]|%2e%2e|%252e|\/etc\/passwd|\/etc\/shadow|\/windows\/win\.ini|c:\\\\windows)",
        "description": "Detects directory traversal attempts to access files outside web root.",
        "cve_ref": "CWE-22"
    },
    # Command injection
    {
        "id": "WAF-006",
        "name": "Command Injection",
        "category": "RCE",
        "severity": "CRITICAL",
        "pattern": r"(;\s*\w+|&&\s*\w+|\|\s*\w+|`[^`]+`|\$\([^)]+\)|%0a|%0d%0a|nc\s+-|wget\s+http|curl\s+http)",
        "description": "Detects OS command injection via shell metacharacters and common reverse shell patterns.",
        "cve_ref": "CWE-78"
    },
    # SSRF
    {
        "id": "WAF-007",
        "name": "SSRF — Internal Host Access",
        "category": "SSRF",
        "severity": "HIGH",
        "pattern": r"(169\.254\.169\.254|localhost|127\.0\.0\.1|0\.0\.0\.0|::1|internal\.|intranet\.|169\.254\.)",
        "description": "Detects Server-Side Request Forgery attempts targeting internal AWS metadata endpoint and localhost.",
        "cve_ref": "CWE-918"
    },
    # XXE
    {
        "id": "WAF-008",
        "name": "XXE Injection",
        "category": "XXE",
        "severity": "HIGH",
        "pattern": r"(<!entity|<!doctype[^>]*\[|system\s+\"file:|<!element|<!attlist)",
        "description": "Detects XML External Entity injection that can read server files or trigger SSRF.",
        "cve_ref": "CWE-611"
    },
]

# ── Bypass techniques with examples ─────────────────────────

BYPASS_TECHNIQUES = [
    {
        "name": "Case Variation",
        "description": "Changing letter case to evade case-sensitive pattern matching.",
        "original": "SELECT * FROM users",
        "bypass": "SeLeCt * FrOm UsErS",
        "works_against": "Weak regex without case-insensitive flag",
        "mitigation": "Always compile WAF rules with case-insensitive flag (re.IGNORECASE)"
    },
    {
        "name": "URL Encoding",
        "description": "Encoding special characters using %XX hex notation to evade string matching.",
        "original": "' OR 1=1--",
        "bypass": "%27%20OR%201%3D1--",
        "works_against": "WAFs that don't decode URL encoding before analysis",
        "mitigation": "Decode all URL encoding before applying WAF rules. Apply rules to normalised input."
    },
    {
        "name": "Double URL Encoding",
        "description": "Encoding the % sign itself, which some WAFs only decode once.",
        "original": "../etc/passwd",
        "bypass": "%252e%252e%252fetc%252fpasswd",
        "works_against": "WAFs that only perform single-pass URL decoding",
        "mitigation": "Apply recursive URL decoding until input is fully normalised"
    },
    {
        "name": "SQL Comment Injection",
        "description": "Using inline SQL comments to break up keywords the WAF is looking for.",
        "original": "UNION SELECT",
        "bypass": "UN/**/ION SEL/**/ECT",
        "works_against": "WAFs looking for exact keyword strings",
        "mitigation": "Strip SQL comments before analysis, or use semantic SQL parsing"
    },
    {
        "name": "Whitespace Substitution",
        "description": "Replacing spaces with alternative whitespace characters SQL accepts.",
        "original": "SELECT * FROM users",
        "bypass": "SELECT%09*%09FROM%09users (using TAB)",
        "works_against": "WAFs that only check for space characters in queries",
        "mitigation": "Normalise all whitespace characters (\\t, \\n, \\r, \\x0b) to spaces before analysis"
    },
    {
        "name": "HTTP Parameter Pollution",
        "description": "Sending the same parameter multiple times — different servers merge them differently.",
        "original": "id=1 UNION SELECT",
        "bypass": "id=1&id= UNION SELECT",
        "works_against": "WAFs that only inspect the first or last instance of a repeated parameter",
        "mitigation": "Concatenate or reject duplicate parameters before WAF analysis"
    },
]

# ── Pre-built test payloads ───────────────────────────────────

TEST_PAYLOADS = {
    "sqli_classic":    "' OR '1'='1",
    "sqli_union":      "' UNION SELECT username,password FROM users--",
    "sqli_blind":      "1 AND SLEEP(5)--",
    "xss_script":      "<script>alert('XSS')</script>",
    "xss_event":       "<img src=x onerror=alert(1)>",
    "path_traversal":  "../../../../etc/passwd",
    "cmd_injection":   "; cat /etc/passwd",
    "ssrf":            "http://169.254.169.254/latest/meta-data/",
    "xxe":             "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
    "safe":            "SELECT a nice day for learning cybersecurity",
    "bypass_case":     "SeLeCt * FrOm UsErS WhErE Id=1",
    "bypass_encode":   "%27%20OR%20%271%27%3D%271",
    "bypass_comment":  "UN/**/ION SEL/**/ECT username,password FR/**/OM users",
}

def run_waf(payload: str, mode: str = "prevention") -> dict:
    payload_lower = payload.lower()
    triggered = []

    for rule in WAF_RULES:
        pattern = re.compile(rule["pattern"], re.IGNORECASE)
        match = pattern.search(payload)
        if match:
            triggered.append({
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "matched_text": match.group()[:60],
                "description": rule["description"],
                "cve_ref": rule["cve_ref"],
                "action": "BLOCKED" if mode == "prevention" else "LOGGED"
            })

    if triggered:
        highest_sev = "CRITICAL" if any(t["severity"]=="CRITICAL" for t in triggered) \
            else "HIGH" if any(t["severity"]=="HIGH" for t in triggered) \
            else "MEDIUM"
        action = "BLOCKED — 403 Forbidden" if mode == "prevention" else "LOGGED — Passed to application"
        verdict = "MALICIOUS"
    else:
        action = "ALLOWED — 200 OK"
        verdict = "CLEAN"
        highest_sev = "NONE"

    return {
        "payload": payload,
        "verdict": verdict,
        "action": action,
        "mode": mode.upper(),
        "rules_triggered": len(triggered),
        "highest_severity": highest_sev,
        "triggered_rules": triggered,
        "rules_checked": len(WAF_RULES),
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S")
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/inspect', methods=['POST'])
def inspect():
    data = request.get_json()
    payload = data.get('payload', '').strip()
    mode = data.get('mode', 'prevention')
    if not payload:
        return jsonify({"error": "Empty payload"}), 400
    return jsonify(run_waf(payload, mode))

@app.route('/api/payloads')
def payloads():
    return jsonify(TEST_PAYLOADS)

@app.route('/api/rules')
def rules():
    return jsonify(WAF_RULES)

@app.route('/api/bypasses')
def bypasses():
    return jsonify(BYPASS_TECHNIQUES)

if __name__ == '__main__':
    print("\n" + "="*55)
    print("  WAF SIMULATOR")
    print("  Nivedhitha KS | Cybersecurity Portfolio")
    print("  Open: http://127.0.0.1:5000")
    print("="*55 + "\n")
    app.run(debug=False, host='0.0.0.0', port=5000)
