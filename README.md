# WAF Simulator — Web Application Firewall 🛡️

**Nivedhitha KS | Cybersecurity Portfolio**

Simulates a Web Application Firewall with 8 detection rules across SQLi, XSS, Path Traversal, Command Injection, SSRF, and XXE. Includes Prevention and Detection modes, pre-built attack payloads, and 6 WAF bypass techniques with mitigations.

## Live Demo
> Add Render URL after deployment

## WAF Rules (8)
SQLi Classic, SQLi Blind/Boolean, XSS Script Injection, XSS HTML Attributes, Path Traversal, Command Injection, SSRF Internal Host, XXE Injection

## Bypass Techniques (6)
Case variation, URL encoding, Double URL encoding, SQL comment injection, Whitespace substitution, HTTP parameter pollution

## Features
- Prevention mode (blocks) vs Detection mode (logs only)
- Live request inspector with rule-by-rule breakdown
- Pre-built attack payload library (9 attack types + 3 bypass demos)
- Matched text highlighted in results
- Rules reference page with CWE IDs

## Run Locally
```bash
pip install flask
python app.py
# Open http://127.0.0.1:5000
```

## What to Tell Recruiters
> "I built a WAF simulation tool with 8 detection rules covering SQLi, XSS, SSRF, and command injection. It has prevention and detection modes, a request inspector that shows exactly which rules fired and what text was matched, and a bypass techniques section demonstrating how attackers evade WAFs and how to fix the gaps."
