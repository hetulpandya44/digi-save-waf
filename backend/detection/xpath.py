"""XPath Injection Detection Module"""

PATTERNS = [
    r"(\bstring-length\s*\()",
    r"(\bsubstring\s*\()",
    r"(\bcontains\s*\()",
    r"(\bcount\s*\(/)",
    r"(\bconcat\s*\()",
    r"(\bnormalize-space\s*\()",
    r"(' or '1'='1)",
    r"(' and '1'='1)",
    r"(\btext\s*\(\s*\)\s*=)",
    r"(\bnode\s*\(\s*\))",
    r"(\[position\s*\(\s*\)\s*=\s*\d+\])",
    r"(/child::\*)",
    r"(/descendant::\*)",
]

MODULE_INFO = {
    "name": "XPath Injection",
    "key": "xpath",
    "attack_type": 5,
    "description": "Detects XPath injection attempts targeting XML databases and queries",
    "pattern_count": len(PATTERNS),
}
