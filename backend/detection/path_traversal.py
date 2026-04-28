"""Path Traversal Detection Module — 15+ patterns"""

PATTERNS = [
    r"(\.\.[\\/])",
    r"(\.\./){2,}",
    r"(%2e%2e[%2f%5c])",
    r"(%252e%252e%252f)",
    r"(\.\.%2f)",
    r"(%2e%2e/)",
    r"(\.\.%255c)",
    r"(\.\.\\\\)",
    r"(/etc/(passwd|shadow|hosts|group|sudoers|crontab))",
    r"(/proc/(self|version|cmdline|environ))",
    r"(/var/log/)",
    r"(C:\\\\(Windows|WINDOWS|boot\.ini|win\.ini))",
    r"(%00)",  # Null byte injection
    r"(\.\./\.\./\.\./)",
    r"(file://)",
]

MODULE_INFO = {
    "name": "Path Traversal",
    "key": "path_traversal",
    "attack_type": 13,
    "description": "Detects directory traversal and local file inclusion attempts",
    "pattern_count": len(PATTERNS),
}
