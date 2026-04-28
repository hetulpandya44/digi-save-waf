"""LDAP Injection Detection Module"""

PATTERNS = [
    r"(\)\(\|)",
    r"(\)\(\&)",
    r"(\b(objectClass|objectCategory)\s*=\s*\*)",
    r"(\*\)\()",
    r"(%28%7c)",
    r"(%29%28)",
    r"(\bnull\b.*\bdn\b)",
    r"(\badminCount\s*=)",
    r"(\buserPassword\s*=)",
    r"(\bsamaccountname\s*=)",
]

MODULE_INFO = {
    "name": "LDAP Injection",
    "key": "ldap",
    "attack_type": 4,
    "description": "Detects LDAP injection attempts targeting directory services",
    "pattern_count": len(PATTERNS),
}
