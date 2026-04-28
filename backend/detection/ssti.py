"""Server-Side Template Injection (SSTI) Detection Module"""

PATTERNS = [
    r"(\{\{.*\}\})",  # Jinja2/Twig
    r"(\{%.*%\})",    # Jinja2 block
    r"(\$\{.*\})",    # Java EL / FreeMarker
    r"(#\{.*\})",     # Thymeleaf
    r"(\{\{[0-9]+\s*\*\s*[0-9]+\}\})",  # Math probe
    r"(\{\{config\}\})",
    r"(\{\{self\}\})",
    r"(\{\{request\}\})",
    r"(\b__class__\b.*\b__mro__\b)",  # Python class traversal
    r"(\b__subclasses__\b\s*\(\s*\))",
    r"(\b__globals__\b)",
    r"(\b__builtins__\b)",
    r"(\b__import__\b)",
    r"(\blipsum\b.*\b__globals__\b)",  # Jinja sandbox escape
    r"(\bcycler\b.*\b__init__\b.*\b__globals__\b)",
    r"(#set\s*\(\s*\$\w+\s*=)",  # Velocity
    r"(<#assign\s+\w+\s*=)",     # FreeMarker
]

MODULE_INFO = {
    "name": "Template Injection (SSTI)",
    "key": "ssti",
    "attack_type": 11,
    "description": "Detects server-side template injection in Jinja2, Twig, FreeMarker, Velocity, and Thymeleaf",
    "pattern_count": len(PATTERNS),
}
