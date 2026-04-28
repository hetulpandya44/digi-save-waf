"""Server-Side Request Forgery (SSRF) Detection Module"""

PATTERNS = [
    r"(https?://(127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+))",
    r"(https?://\[?(::1|0:0:0:0:0:0:0:1|fe80::)\]?)",
    r"(https?://169\.254\.169\.254)",  # AWS metadata
    r"(https?://metadata\.google\.internal)",  # GCP metadata
    r"(https?://100\.100\.100\.200)",  # Alibaba Cloud metadata
    r"(file:///)",
    r"(gopher://)",
    r"(dict://)",
    r"(ftp://127\.|ftp://localhost)",
    r"(ldap://)",
    r"(tftp://)",
    r"(\burl\s*=\s*https?://)",
    r"(\bredirect\s*=\s*https?://)",
    r"(\bnext\s*=\s*https?://)",
    r"(\breturn\s*=\s*https?://)",
]

MODULE_INFO = {
    "name": "Server-Side Request Forgery",
    "key": "ssrf",
    "attack_type": 9,
    "description": "Detects SSRF attempts targeting internal services, cloud metadata, and local resources",
    "pattern_count": len(PATTERNS),
}
