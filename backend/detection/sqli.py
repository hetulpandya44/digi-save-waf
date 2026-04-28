"""SQL Injection Detection Module — 40+ patterns based on OWASP CRS"""

PATTERNS = [
    # Classic SQL injection
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE|UNION)\b\s)",
    r"(\b(SELECT)\b\s+.*\b(FROM)\b)",
    r"(\bUNION\b\s+(ALL\s+)?SELECT\b)",
    r"(\bSELECT\b\s+.*\b(CONCAT|GROUP_CONCAT|CHAR)\b\s*\()",
    # Tautology attacks
    r"(\bOR\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?)",
    r"(\bOR\b\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+[\'\"]?)",
    r"(\bAND\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?)",
    r"('|\");\s*--",
    r"('\s*OR\s+'[^']*'\s*=\s*'[^']*')",
    # Comment injection
    r"(/\*.*?\*/)",
    r"(--\s+.*$)",
    r"(#\s+.*$)",
    # Quote-based injection
    r"([\'\"];\s*(DROP|DELETE|UPDATE|INSERT|ALTER)\b)",
    r"([\'\"];\s*SELECT\b)",
    r"(\bWAITFOR\b\s+\bDELAY\b)",
    r"(\bBENCHMARK\b\s*\(\s*\d+)",
    r"(\bSLEEP\b\s*\(\s*\d+\s*\))",
    # Information schema
    r"(\bINFORMATION_SCHEMA\b)",
    r"(\bSYSTABLES\b|\bSYSCOLUMNS\b|\bSYSOBJECTS\b)",
    r"(\bpg_catalog\b)",
    r"(\bsqlite_master\b)",
    # Stacked queries
    r"(;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b)",
    # MySQL specific
    r"(\bLOAD_FILE\b\s*\()",
    r"(\bINTO\s+(OUT|DUMP)FILE\b)",
    r"(\bEXTRACTVALUE\b\s*\()",
    r"(\bUPDATEXML\b\s*\()",
    # PostgreSQL specific
    r"(\bpg_sleep\b\s*\()",
    r"(\bstring_agg\b\s*\()",
    r"(\barray_to_string\b\s*\()",
    # MSSQL specific
    r"(\bxp_cmdshell\b)",
    r"(\bsp_executesql\b)",
    r"(\bOPENROWSET\b)",
    # Blind SQLi
    r"(\bSUBSTRING\b\s*\(.*,\s*\d+\s*,\s*\d+\s*\))",
    r"(\bASCII\b\s*\(\s*\bSUBSTR)",
    r"(\bIF\b\s*\(.*,\s*\bSLEEP\b)",
    r"(\bCASE\b\s+\bWHEN\b.*\bTHEN\b.*\bELSE\b)",
    # Hex and char encoding
    r"(0x[0-9a-fA-F]{8,})",
    r"(\bCHAR\b\s*\(\s*\d+(\s*,\s*\d+)*\s*\))",
    r"(\bCONVERT\b\s*\(.*\bUSING\b)",
    # Error-based
    r"(\bGROUP\s+BY\b.*\bHAVING\b)",
    r"(\bORDER\s+BY\b\s+\d{2,})",
    r"(\bEXP\b\s*\(\s*~)",
]

MODULE_INFO = {
    "name": "SQL Injection",
    "key": "sqli",
    "attack_type": 0,
    "description": "Detects SQL injection attempts including union-based, blind, error-based, and stacked queries",
    "pattern_count": len(PATTERNS),
}
