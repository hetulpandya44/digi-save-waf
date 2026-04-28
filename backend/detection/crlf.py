"""CRLF Injection & HTTP Response Splitting Detection Module"""

PATTERNS = [
    r"(%0[dD]%0[aA])",
    r"(%0[aA])",
    r"(%0[dD])",
    r"(\r\n)",
    r"(\\r\\n)",
    r"(%5cr%5cn)",
    r"(%e5%98%8a%e5%98%8d)",  # Unicode CRLF
    r"(\bSet-Cookie\s*:)",
    r"(\bLocation\s*:\s*https?://)",
    r"(\bContent-Type\s*:)",
    r"(\bX-Forwarded-For\s*:.*%0[dDaA])",
]

MODULE_INFO = {
    "name": "CRLF Injection",
    "key": "crlf",
    "attack_type": 3,
    "description": "Detects CRLF injection and HTTP response splitting attacks",
    "pattern_count": len(PATTERNS),
}
