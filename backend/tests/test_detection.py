"""
Digi Save WAF — Detection Engine Test Suite
Tests all 12 detection modules against known attack payloads and verifies
clean traffic passes through (false positive validation).
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection.engine import DetectionEngine, DetectionResult


def make_request(url="/", path="/", query="", body="", user_agent="Mozilla/5.0", method="GET", headers=None):
    """Helper to create a request_data dict."""
    h = {"user-agent": user_agent, "host": "example.com"}
    if headers:
        h.update(headers)
    return {
        "url": f"http://example.com{path}{'?' + query if query else ''}",
        "path": path,
        "query": query,
        "body": body,
        "headers": h,
        "method": method,
    }


engine = DetectionEngine()  # All modules in default mode


# =====================================================================
# 1. SQL Injection Module
# =====================================================================
class TestSQLInjection:
    def test_classic_union_select(self):
        r = engine.detect(make_request(query="id=1 UNION SELECT 1,2,3--"))
        assert r.is_attack, "Should detect UNION SELECT"
        assert r.module_key == "sqli"

    def test_single_quote_or(self):
        r = engine.detect(make_request(query="id=1' OR '1'='1"))
        assert r.is_attack, "Should detect OR-based SQLi"

    def test_sleep_based_blind(self):
        r = engine.detect(make_request(query="id=1 AND SLEEP(5)"))
        assert r.is_attack, "Should detect time-based blind SQLi"

    def test_body_sqli(self):
        r = engine.detect(make_request(body="username=admin' OR '1'='1&password=x"))
        assert r.is_attack, "Should detect SQLi in POST body"

    def test_encoded_sqli(self):
        r = engine.detect(make_request(query="id=1%27%20OR%20%271%27%3D%271"))
        assert r.is_attack, "Should detect URL-encoded SQLi"


# =====================================================================
# 2. XSS Module
# =====================================================================
class TestXSS:
    def test_script_tag(self):
        r = engine.detect(make_request(query="q=<script>alert(1)</script>"))
        assert r.is_attack, "Should detect script tag XSS"
        assert r.module_key == "xss"

    def test_img_onerror(self):
        r = engine.detect(make_request(query='q=<img src=x onerror=alert(1)>'))
        assert r.is_attack, "Should detect img onerror XSS"

    def test_event_handler(self):
        r = engine.detect(make_request(body='comment=<div onmouseover="alert(1)">'))
        assert r.is_attack, "Should detect event handler XSS"

    def test_svg_onload(self):
        r = engine.detect(make_request(query='q=<svg/onload=alert(1)>'))
        assert r.is_attack, "Should detect SVG onload XSS"


# =====================================================================
# 3. RCE / Command Injection Module
# =====================================================================
class TestRCE:
    def test_semicolon_cmd(self):
        r = engine.detect(make_request(query="cmd=;cat /etc/passwd"))
        assert r.is_attack, "Should detect semicolon command injection"

    def test_pipe_cmd(self):
        r = engine.detect(make_request(body="input=test|ls -la"))
        assert r.is_attack, "Should detect pipe command injection"

    def test_backtick_cmd(self):
        r = engine.detect(make_request(query="x=`whoami`"))
        assert r.is_attack, "Should detect backtick command injection"


# =====================================================================
# 4. Path Traversal Module
# =====================================================================
class TestPathTraversal:
    def test_dot_dot_slash(self):
        r = engine.detect(make_request(path="/../../etc/passwd"))
        assert r.is_attack, "Should detect ../../ path traversal"

    def test_encoded_traversal(self):
        r = engine.detect(make_request(query="file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"))
        assert r.is_attack, "Should detect encoded path traversal"

    def test_windows_traversal(self):
        r = engine.detect(make_request(query="file=..\\..\\windows\\win.ini"))
        assert r.is_attack, "Should detect Windows path traversal"


# =====================================================================
# 5. SSRF Module
# =====================================================================
class TestSSRF:
    def test_internal_ip(self):
        r = engine.detect(make_request(query="url=http://169.254.169.254/latest/meta-data"))
        assert r.is_attack, "Should detect cloud metadata SSRF"

    def test_localhost(self):
        r = engine.detect(make_request(body="target=http://127.0.0.1:8080/admin"))
        assert r.is_attack, "Should detect localhost SSRF"


# =====================================================================
# 6. XXE Module
# =====================================================================
class TestXXE:
    def test_entity_declaration(self):
        payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
        r = engine.detect(make_request(body=payload))
        assert r.is_attack, "Should detect XXE entity declaration"


# =====================================================================
# 7. SSTI Module
# =====================================================================
class TestSSTI:
    def test_jinja2(self):
        r = engine.detect(make_request(query="name={{7*7}}"))
        assert r.is_attack, "Should detect Jinja2 SSTI"

    def test_twig(self):
        r = engine.detect(make_request(body="input={{_self.env.getRuntime}}"))
        assert r.is_attack, "Should detect Twig SSTI"


# =====================================================================
# 8. Scanner Detection Module
# =====================================================================
class TestScanner:
    def test_sqlmap_ua(self):
        r = engine.detect(make_request(user_agent="sqlmap/1.5.2"))
        assert r.is_attack, "Should detect sqlmap user-agent"

    def test_nikto_ua(self):
        r = engine.detect(make_request(user_agent="Mozilla/5.0 (Nikto)"))
        assert r.is_attack, "Should detect Nikto user-agent"

    def test_nmap_ua(self):
        r = engine.detect(make_request(user_agent="Nmap Scripting Engine"))
        assert r.is_attack, "Should detect Nmap user-agent"


# =====================================================================
# 9. Sensitive Info Module
# =====================================================================
class TestSensitive:
    def test_env_file(self):
        r = engine.detect(make_request(path="/.env"))
        assert r.is_attack, "Should detect .env file access"

    def test_git_config(self):
        r = engine.detect(make_request(path="/.git/config"))
        assert r.is_attack, "Should detect .git config access"

    def test_wp_config(self):
        r = engine.detect(make_request(path="/wp-config.php"))
        assert r.is_attack, "Should detect wp-config.php access"


# =====================================================================
# 10. CRLF Injection Module
# =====================================================================
class TestCRLF:
    def test_crlf_in_url(self):
        r = engine.detect(make_request(query="redirect=http://evil.com%0d%0aSet-Cookie:%20admin=true"))
        assert r.is_attack, "Should detect CRLF injection"


# =====================================================================
# 11. LDAP Injection Module
# =====================================================================
class TestLDAP:
    def test_ldap_wildcard(self):
        r = engine.detect(make_request(query="user=*)(uid=*))(|(uid=*"))
        assert r.is_attack, "Should detect LDAP injection"


# =====================================================================
# 12. XPath Injection Module
# =====================================================================
class TestXPath:
    def test_xpath_injection(self):
        r = engine.detect(make_request(query="user=' or '1'='1"))
        assert r.is_attack, "Should detect XPath/SQLi injection"


# =====================================================================
# FALSE POSITIVE Tests — Clean traffic must PASS
# =====================================================================
class TestFalsePositives:
    def test_normal_get(self):
        r = engine.detect(make_request(path="/products", query="category=electronics&sort=price"))
        assert not r.is_attack, "Normal GET should pass"

    def test_normal_post(self):
        r = engine.detect(make_request(method="POST", body='{"name":"John","email":"john@example.com"}'))
        assert not r.is_attack, "Normal JSON POST should pass"

    def test_normal_user_agent(self):
        r = engine.detect(make_request(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"))
        assert not r.is_attack, "Normal browser UA should pass"

    def test_normal_search(self):
        r = engine.detect(make_request(query="q=best+laptop+2024&page=1"))
        assert not r.is_attack, "Normal search query should pass"

    def test_normal_static_file(self):
        r = engine.detect(make_request(path="/css/style.css"))
        assert not r.is_attack, "Static file access should pass"

    def test_normal_api(self):
        r = engine.detect(make_request(path="/api/v1/users/123", method="GET"))
        assert not r.is_attack, "Normal API access should pass"


# =====================================================================
# Custom DB Rule Tests
# =====================================================================
class TestCustomRules:
    def test_custom_deny_rule(self):
        rules = [{"id": 1, "name": "test", "pattern": r"/secret-admin", "pattern_type": "regex",
                  "target": "url", "action": "deny", "risk_level": "high", "is_enabled": True}]
        r = engine.detect(make_request(path="/secret-admin"), db_rules=rules)
        assert r.is_attack, "Custom deny rule should trigger"
        assert r.module_key == "custom_rule"

    def test_custom_disabled_rule(self):
        rules = [{"id": 2, "name": "test off", "pattern": r"/secret", "pattern_type": "regex",
                  "target": "url", "action": "deny", "risk_level": "high", "is_enabled": False}]
        r = engine.detect(make_request(path="/secret"), db_rules=rules)
        assert not r.is_attack, "Disabled rule should not trigger"


# =====================================================================
# Module Mode Tests
# =====================================================================
class TestModuleModes:
    def test_disabled_module_passes_attack(self):
        disabled_engine = DetectionEngine({"sqli": {"mode": "disabled"}})
        r = disabled_engine.detect(make_request(query="id=1' UNION SELECT 1,2--"))
        # SQLi module disabled, but XSS module might catch the quote... check sqli specifically
        if r.is_attack:
            assert r.module_key != "sqli", "Disabled sqli module should not fire"

    def test_strict_mode_higher_risk(self):
        strict_engine = DetectionEngine({"sqli": {"mode": "strict", "high_risk_action": "deny"}})
        r = strict_engine.detect(make_request(query="id=1' OR '1'='1"))
        assert r.is_attack
        assert r.risk_level == 3, "Strict mode should produce high risk"


# =====================================================================
# Runner
# =====================================================================
def run_all_tests():
    """Simple test runner that works without pytest."""
    test_classes = [
        TestSQLInjection, TestXSS, TestRCE, TestPathTraversal, TestSSRF,
        TestXXE, TestSSTI, TestScanner, TestSensitive, TestCRLF, TestLDAP,
        TestXPath, TestFalsePositives, TestCustomRules, TestModuleModes,
    ]

    total = 0
    passed = 0
    failed = 0
    errors = []

    for cls in test_classes:
        instance = cls()
        methods = [m for m in dir(instance) if m.startswith("test_")]
        for method_name in methods:
            total += 1
            try:
                getattr(instance, method_name)()
                passed += 1
                print(f"  [PASS] {cls.__name__}.{method_name}")
            except AssertionError as e:
                failed += 1
                errors.append(f"  [FAIL] {cls.__name__}.{method_name}: {e}")
                print(f"  [FAIL] {cls.__name__}.{method_name}: {e}")
            except Exception as e:
                failed += 1
                errors.append(f"  [ERR]  {cls.__name__}.{method_name}: {type(e).__name__}: {e}")
                print(f"  [ERR]  {cls.__name__}.{method_name}: {type(e).__name__}: {e}")

    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"{'='*60}")

    if errors:
        print("\nFailures:")
        for e in errors:
            print(e)
    
    return failed == 0


if __name__ == "__main__":
    print("=" * 60)
    print("  Digi Save WAF — Detection Engine Test Suite")
    print("=" * 60)
    success = run_all_tests()
    sys.exit(0 if success else 1)
