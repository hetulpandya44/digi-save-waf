"""Remote Code Execution & Command Injection Detection — 30+ patterns"""

PATTERNS = [
    # Shell metacharacters
    r"(;\s*(cat|ls|id|whoami|uname|pwd|echo|wget|curl|nc|netcat|python|perl|ruby|php|bash|sh|zsh|csh|ksh|dash)\b)",
    r"(\|\s*(cat|ls|id|whoami|uname|pwd|echo|wget|curl|nc|netcat|python|perl|ruby|php|bash|sh)\b)",
    r"(`[^`]*`)",
    r"(\$\([^)]*\))",
    r"(\$\{[^}]*\})",
    # Command chaining
    r"(&&\s*(cat|ls|id|whoami|uname|pwd|echo|wget|curl|rm|chmod|chown|kill|pkill)\b)",
    r"(\|\|\s*(cat|ls|id|whoami|uname|pwd|echo|wget|curl)\b)",
    r"(\|\s*\w+)",
    # Dangerous commands
    r"(\b(rm|rmdir)\s+(-rf?|--recursive)\b)",
    r"(\bchmod\s+[0-7]{3,4}\b)",
    r"(\bchown\b.*:\w+)",
    r"(\bkill\s+-\d+)",
    r"(\bpkill\b)",
    r"(\bdd\s+if=)",
    r"(\bmkfs\b)",
    # Reverse shells
    r"(\bnc\b.*-[elp])",
    r"(\b(bash|sh)\s+-i\b.*>/dev/tcp/)",
    r"(\bpython\b.*\bsocket\b.*\bconnect\b)",
    r"(\bperl\b.*\bsocket\b.*\bINET\b)",
    r"(\bphp\b.*\bfsockopen\b)",
    # Code execution functions
    r"(\bsystem\s*\()",
    r"(\bexec\s*\()",
    r"(\bpassthru\s*\()",
    r"(\bshell_exec\s*\()",
    r"(\bpopen\s*\()",
    r"(\bproc_open\s*\()",
    r"(\bpcntl_exec\s*\()",
    # Python specific
    r"(\b__import__\s*\()",
    r"(\bos\s*\.\s*system\s*\()",
    r"(\bsubprocess\s*\.\s*(call|run|Popen)\s*\()",
    r"(\beval\s*\(\s*compile\b)",
]

MODULE_INFO = {
    "name": "Command Injection / RCE",
    "key": "rce",
    "attack_type": 2,
    "description": "Detects OS command injection, reverse shell attempts, and remote code execution",
    "pattern_count": len(PATTERNS),
}
