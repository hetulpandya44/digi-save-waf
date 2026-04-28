"""Cross-Site Scripting (XSS) Detection Module — 35+ patterns"""

PATTERNS = [
    # Script tags
    r"(<\s*script[^>]*>)",
    r"(<\s*/\s*script\s*>)",
    r"(<\s*script[^>]*\bsrc\b\s*=)",
    # Event handlers
    r"(\bon\w+\s*=\s*[\"'][^\"']*[\"'])",
    r"(\bon(load|error|click|mouseover|focus|blur|submit|change|input|keydown|keyup|keypress|mouseenter|mouseleave|contextmenu|dblclick|drag|drop|abort|beforeunload|hashchange|message|offline|online|pagehide|pageshow|popstate|resize|scroll|storage|unload|animationend|animationiteration|animationstart|transitionend)\s*=)",
    # JavaScript URI
    r"(javascript\s*:)",
    r"(vbscript\s*:)",
    r"(livescript\s*:)",
    r"(data\s*:\s*text/html)",
    # DOM manipulation
    r"(document\s*\.\s*(cookie|domain|write|writeln|location|referrer))",
    r"(window\s*\.\s*(location|open|navigate|moveTo|resizeTo))",
    r"(\.innerHTML\s*=)",
    r"(\.outerHTML\s*=)",
    r"(\.insertAdjacentHTML\s*\()",
    r"(document\s*\.\s*createElement\s*\()",
    # Common XSS payloads
    r"(<\s*img[^>]+\bonerror\b)",
    r"(<\s*svg[^>]*\bonload\b)",
    r"(<\s*body[^>]*\bonload\b)",
    r"(<\s*iframe[^>]*>)",
    r"(<\s*object[^>]*>)",
    r"(<\s*embed[^>]*>)",
    r"(<\s*applet[^>]*>)",
    r"(<\s*form[^>]*>)",
    r"(<\s*input[^>]*>)",
    r"(<\s*link[^>]*\bhref\b\s*=\s*[\"']javascript)",
    # Encoding evasion
    r"(&#x?[0-9a-fA-F]+;)",
    r"(%3[Cc]script)",
    r"(%22%3[Ee])",
    r"(\\u003[Cc])",
    # Expression/eval
    r"(\beval\s*\()",
    r"(\bsetTimeout\s*\(\s*[\"'])",
    r"(\bsetInterval\s*\(\s*[\"'])",
    r"(\bFunction\s*\(\s*[\"'])",
    r"(\balert\s*\()",
    r"(\bconfirm\s*\()",
    r"(\bprompt\s*\()",
]

MODULE_INFO = {
    "name": "Cross-Site Scripting (XSS)",
    "key": "xss",
    "attack_type": 1,
    "description": "Detects reflected, stored, and DOM-based XSS attacks including encoded payloads",
    "pattern_count": len(PATTERNS),
}
