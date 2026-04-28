import os
import sqlite3
from typing import Generator

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DB_DIR, exist_ok=True)
DATABASE_PATH = os.path.join(DB_DIR, 'digisave.db')


def _ensure_supported_policy_groups(cursor: sqlite3.Cursor):
    from detection.engine import get_all_module_info

    legacy_key_map = {
        "m_sqli": "sqli",
        "m_xss": "xss",
        "m_cmd_injection": "rce",
        "m_path_traversal": "path_traversal",
        "m_ssrf": "ssrf",
        "m_ssti": "ssti",
        "m_scanner": "scanner",
        "m_sensitive_info": "sensitive",
        "m_xxe": "xxe",
    }

    cursor.execute("SELECT id, module FROM policy_groups")
    existing = {row[1]: row[0] for row in cursor.fetchall()}

    for legacy_key, current_key in legacy_key_map.items():
        if legacy_key in existing and current_key not in existing:
            cursor.execute(
                "UPDATE policy_groups SET module = ?, updated_at = CURRENT_TIMESTAMP WHERE module = ?",
                (current_key, legacy_key),
            )
            existing[current_key] = existing.pop(legacy_key)

    cursor.execute("SELECT module FROM policy_groups")
    normalized_existing = {row[0] for row in cursor.fetchall()}

    for info in get_all_module_info():
        if info["key"] in normalized_existing:
            cursor.execute(
                """
                UPDATE policy_groups
                SET description = CASE WHEN description = '' THEN ? ELSE description END
                WHERE module = ?
                """,
                (info["description"], info["key"]),
            )
            continue

        cursor.execute(
            """
            INSERT INTO policy_groups
            (module, mode, high_risk_action, medium_risk_action, low_risk_action, state, description)
            VALUES (?, 'default', 'deny', 'continue', 'continue', 'enabled', ?)
            """,
            (info["key"], info["description"]),
        )


def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Ensure connections also benefit from WAL timeout
    conn.execute("PRAGMA busy_timeout=5000;")
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Enable industry-grade SQLite high concurrency optimizations
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.execute("PRAGMA busy_timeout=5000;")
    cursor.execute("PRAGMA temp_store=MEMORY;")
    cursor.execute("PRAGMA cache_size=-64000;") # 64MB cache
    
    # users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        comment VARCHAR(255) DEFAULT '',
        tfa_enabled BOOLEAN DEFAULT 0,
        tfa_secret VARCHAR(255) DEFAULT '',
        last_login_time DATETIME,
        is_enabled BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # websites table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS websites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        comment VARCHAR(255) DEFAULT '',
        server_names TEXT DEFAULT '[]',
        ports TEXT DEFAULT '[]',
        upstreams TEXT DEFAULT '[]',
        cert_filename VARCHAR(255) DEFAULT '',
        key_filename VARCHAR(255) DEFAULT '',
        captcha_enabled BOOLEAN DEFAULT 0,
        auth_enabled BOOLEAN DEFAULT 0,
        dynamic_enabled BOOLEAN DEFAULT 0,
        detection_mode VARCHAR(20) DEFAULT 'balance',
        is_enabled BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Add new columns if the table already exists
    try:
        cursor.execute("ALTER TABLE websites ADD COLUMN captcha_enabled BOOLEAN DEFAULT 0")
        cursor.execute("ALTER TABLE websites ADD COLUMN auth_enabled BOOLEAN DEFAULT 0")
        cursor.execute("ALTER TABLE websites ADD COLUMN dynamic_enabled BOOLEAN DEFAULT 0")
        cursor.execute("ALTER TABLE websites ADD COLUMN detection_mode VARCHAR(20) DEFAULT 'balance'")
    except sqlite3.OperationalError:
        pass  # Columns probably already exist

    # detect_logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS detect_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id VARCHAR(64) UNIQUE NOT NULL,
        site_uuid VARCHAR(64) DEFAULT '',
        src_ip VARCHAR(45),
        socket_ip VARCHAR(45) DEFAULT '',
        protocol INTEGER DEFAULT 1,
        host VARCHAR(255) DEFAULT '',
        url_path TEXT DEFAULT '',
        dst_port INTEGER DEFAULT 80,
        country VARCHAR(100) DEFAULT '',
        province VARCHAR(100) DEFAULT '',
        city VARCHAR(100) DEFAULT '',
        attack_type INTEGER DEFAULT 0,
        risk_level INTEGER DEFAULT 0,
        action INTEGER DEFAULT 0,
        rule_id VARCHAR(255) DEFAULT '',
        timestamp INTEGER,
        src_port INTEGER DEFAULT 0,
        dst_ip VARCHAR(45) DEFAULT '',
        method VARCHAR(10) DEFAULT 'GET',
        query_string TEXT DEFAULT '',
        status_code INTEGER DEFAULT 200,
        req_header TEXT DEFAULT '',
        req_body TEXT DEFAULT '',
        rsp_header TEXT DEFAULT '',
        rsp_body TEXT DEFAULT '',
        payload TEXT DEFAULT '',
        location VARCHAR(255) DEFAULT '',
        decode_path VARCHAR(255) DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # policy_rules table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS policy_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name VARCHAR(255) NOT NULL,
        pattern TEXT DEFAULT '',
        pattern_type VARCHAR(50) DEFAULT 'regex',
        target VARCHAR(50) DEFAULT 'url',
        action VARCHAR(50) DEFAULT 'deny',
        risk_level VARCHAR(20) DEFAULT 'medium',
        description TEXT DEFAULT '',
        is_enabled BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # policy_groups table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS policy_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        module VARCHAR(100) UNIQUE NOT NULL,
        mode VARCHAR(20) DEFAULT 'default',
        high_risk_action VARCHAR(20) DEFAULT 'deny',
        medium_risk_action VARCHAR(20) DEFAULT 'continue',
        low_risk_action VARCHAR(20) DEFAULT 'continue',
        state VARCHAR(20) DEFAULT 'enabled',
        description VARCHAR(255) DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    _ensure_supported_policy_groups(cursor)

    # system_statistics table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_statistics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type VARCHAR(50) NOT NULL,
        value INTEGER DEFAULT 0,
        value_type VARCHAR(20) DEFAULT 'count',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # options table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS options (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key VARCHAR(100) UNIQUE NOT NULL,
        value TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ip_acl table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ip_acl (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_cidr VARCHAR(100) NOT NULL,
        action VARCHAR(20) DEFAULT 'block',
        note VARCHAR(255) DEFAULT '',
        is_enabled BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # rate_limits table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rate_limits (
        ip VARCHAR(45) PRIMARY KEY,
        count INTEGER DEFAULT 1,
        window_start REAL
    )
    """)

    # captcha_sessions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS captcha_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip VARCHAR(45) NOT NULL,
        token VARCHAR(255) UNIQUE NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # auth_challenges table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id INTEGER NOT NULL,
        ip VARCHAR(45) NOT NULL,
        session_token VARCHAR(255) UNIQUE NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # geoip_cache table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS geoip_cache (
        ip VARCHAR(45) PRIMARY KEY,
        country VARCHAR(100) DEFAULT '',
        province VARCHAR(100) DEFAULT '',
        city VARCHAR(100) DEFAULT '',
        cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Create indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_detect_logs_event_id ON detect_logs(event_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_detect_logs_src_ip ON detect_logs(src_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_detect_logs_timestamp ON detect_logs(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_detect_logs_attack_type ON detect_logs(attack_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_system_statistics_type ON system_statistics(type)")

    conn.commit()
    conn.close()
