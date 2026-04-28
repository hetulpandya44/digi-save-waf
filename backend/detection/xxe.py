"""XML External Entity (XXE) Detection Module"""

PATTERNS = [
    r"(<!DOCTYPE[^>]*\[)",
    r"(<!ENTITY\s+\w+\s+SYSTEM)",
    r"(<!ENTITY\s+%\s+\w+)",
    r"(SYSTEM\s+[\"']file://)",
    r"(SYSTEM\s+[\"']https?://)",
    r"(SYSTEM\s+[\"']ftp://)",
    r"(SYSTEM\s+[\"']gopher://)",
    r"(PUBLIC\s+[\"'][^\"']*[\"']\s+[\"']https?://)",
    r"(<\?xml\s+version)",
    r"(<!ATTLIST\s+\w+\s+\w+\s+CDATA)",
    r"(xmlns:xi\s*=\s*[\"']http://www\.w3\.org/2001/XInclude[\"'])",
    r"(<xi:include\s)",
]

MODULE_INFO = {
    "name": "XML External Entity (XXE)",
    "key": "xxe",
    "attack_type": 23,
    "description": "Detects XXE injection and XML bombs targeting XML parsers",
    "pattern_count": len(PATTERNS),
}
