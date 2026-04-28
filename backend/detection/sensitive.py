"""Sensitive File Access Detection Module"""

PATTERNS = [
    # Configuration files
    r"(/\.env(\b|$))",
    r"(/\.git(/|$))",
    r"(/\.svn(/|$))",
    r"(/\.hg(/|$))",
    r"(/\.htaccess$)",
    r"(/\.htpasswd$)",
    r"(/wp-config\.php$)",
    r"(/config\.(php|yml|yaml|json|xml|ini)$)",
    r"(/\.DS_Store$)",
    r"(/Thumbs\.db$)",
    # Backup files
    r"(\.(bak|backup|old|orig|save|swp|swo|tmp)$)",
    r"(~$)",
    r"(/\.\w+\.swp$)",
    # Source code / debug
    r"(/\.vscode(/|$))",
    r"(/\.idea(/|$))",
    r"(/node_modules(/|$))",
    r"(/__pycache__(/|$))",
    r"(/\.pytest_cache(/|$))",
    r"(/composer\.(json|lock)$)",
    r"(/package\.json$)",
    r"(/Gemfile$)",
    r"(/requirements\.txt$)",
    r"(/Dockerfile$)",
    r"(/docker-compose\.(yml|yaml)$)",
    # Database files
    r"(\.(sql|sqlite|sqlite3|db|mdb)$)",
    # Key / credential files
    r"(/id_rsa$)",
    r"(/id_dsa$)",
    r"(/\.ssh(/|$))",
    r"(/\.aws(/|$))",
    r"(/\.npmrc$)",
    r"(/\.netrc$)",
    r"(\.(pem|key|crt|cer|p12|pfx)$)",
]

MODULE_INFO = {
    "name": "Sensitive File Access",
    "key": "sensitive",
    "attack_type": 31,
    "description": "Detects attempts to access configuration files, backups, source code, credentials, and database files",
    "pattern_count": len(PATTERNS),
}
