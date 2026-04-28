"""Digi Save WAF — Version & Configuration Constants"""

VERSION = "2.1.0"
BUILD = "2026.04.18"
APP_NAME = "Digi Save WAF"

# Allowed settings keys that can be modified via API
ALLOWED_SETTINGS_KEYS = {
    "ssl_cert_path",
    "ssl_key_path",
    "log_retention_days",
    "src_ip_method",
    "auto_refresh",
    "dark_mode",
    "alert_threshold",
    "email_alerts",
    "webhook_url",
    "auth_gate_password",
}
