from datetime import datetime, timedelta
import random
import sqlite3
import json

from database import DATABASE_PATH, init_db
from detection.engine import get_all_module_info

def hash_password(password):
    import bcrypt
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def get_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def seed_database():
    init_db()
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    try:
        # Seed User
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            cursor.execute(
                """INSERT INTO users (username, password_hash, comment, is_enabled, tfa_enabled) 
                   VALUES (?, ?, ?, 1, 0)""",
                ("admin", hash_password("admin123"), "System Administrator")
            )

        # Seed Websites
        cursor.execute("SELECT COUNT(*) FROM websites")
        if cursor.fetchone()[0] == 0:
            websites_data = [
                ("Main Corporate Site", ["www.example.com", "example.com"], [80, 443], ["10.0.0.10:8080"]),
                ("Customer Portal", ["portal.example.com"], [443], ["10.0.0.11:8080"]),
                ("API Gateway", ["api.example.com"], [443], ["10.0.0.12:8000"]),
                ("Legacy App", ["legacy.example.com"], [80], ["10.0.0.20:80"]),
                ("Staging Environment", ["staging.example.com"], [443], ["10.0.1.10:8080"]),
                ("Internal Docs", ["docs.internal"], [80], ["10.0.2.10:80"]),
            ]
            for comment, servers, ports, upstreams in websites_data:
                cursor.execute(
                    """INSERT INTO websites (comment, server_names, ports, upstreams, is_enabled) 
                       VALUES (?, ?, ?, ?, 1)""",
                    (comment, json.dumps(servers), json.dumps(ports), json.dumps(upstreams))
                )

        demo_hosts = ["demo.local", "localhost", "127.0.0.1"]
        demo_upstreams = ["http://127.0.0.1:8090"]
        cursor.execute("SELECT id, server_names FROM websites WHERE comment = ?", ("Vulnerable Demo Site",))
        demo_site = cursor.fetchone()
        if demo_site:
            existing_hosts = json.loads(demo_site[1]) if demo_site[1] else []
            merged_hosts = list(dict.fromkeys([*(existing_hosts or []), *demo_hosts]))
            cursor.execute(
                """
                UPDATE websites
                SET server_names = ?, upstreams = ?, ports = ?, detection_mode = 'strict',
                    is_enabled = 1, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (json.dumps(merged_hosts), json.dumps(demo_upstreams), json.dumps([80, 8085]), demo_site[0])
            )
        else:
            cursor.execute(
                """INSERT INTO websites (comment, server_names, ports, upstreams, is_enabled, detection_mode)
                   VALUES (?, ?, ?, ?, 1, 'strict')""",
                ("Vulnerable Demo Site", json.dumps(demo_hosts), json.dumps([80, 8085]), json.dumps(demo_upstreams))
            )

        # Seed Policy Modules
        cursor.execute("SELECT COUNT(*) FROM policy_groups")
        if cursor.fetchone()[0] == 0:
            for module_info in get_all_module_info():
                cursor.execute(
                    """INSERT INTO policy_groups 
                       (module, mode, high_risk_action, medium_risk_action, low_risk_action, state, description)
                       VALUES (?, 'default', 'deny', 'continue', 'continue', 'enabled', ?)""",
                    (module_info["key"], module_info["description"])
                )

        # Seed Custom Policy Rules
        cursor.execute("SELECT COUNT(*) FROM policy_rules")
        if cursor.fetchone()[0] == 0:
            rules = [
                ("OWASP CRS - SQLi", r"(?i)(\b(select|union|update|delete|insert|drop)\b|--|\#|\%27|\%22)", "regex", "url", "deny", "high", "OWASP standard SQLi payload detection"),
                ("OWASP CRS - XSS", r"(?i)(<script>|<img.*?onerror=|<svg.*?onload=)", "regex", "url", "deny", "high", "OWASP standard XSS vector detection"),
                ("OWASP CRS - RCE/PHP", r"(?i)(\b(system|exec|passthru|shell_exec|phpinfo)\s*\()", "regex", "url", "deny", "critical", "OWASP PHP code injection detection"),
                ("OWASP CRS - Path Traversal", r"(?i)(\.\./\.\./|%2e%2e%2f|etc/passwd|windows/win.ini)", "regex", "url", "deny", "critical", "OWASP LFI/Path Traversal detection"),
                ("Scanner Block", r"(?i)(nmap|nikto|sqlmap|acunetix|nessus)", "regex", "user-agent", "deny", "high", "Block generic vulnerability scanners"),
                ("Block Admin Access", "^/admin", "regex", "url", "deny", "medium", "Block access to admin paths"),
            ]
            for name, pattern, ptype, target, action, risk, desc in rules:
                cursor.execute(
                    """INSERT INTO policy_rules 
                       (name, pattern, pattern_type, target, action, risk_level, description, is_enabled)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
                    (name, pattern, ptype, target, action, risk, desc)
                )

        # Seed IP ACL
        cursor.execute("SELECT COUNT(*) FROM ip_acl")
        if cursor.fetchone()[0] == 0:
            acls = [
                ("192.168.1.100", "block", "Known malicious scanner"),
                ("10.0.0.0/8", "allow", "Internal corporate network"),
            ]
            for ip, action, note in acls:
                cursor.execute(
                    "INSERT INTO ip_acl (ip_cidr, action, note, is_enabled) VALUES (?, ?, ?, 1)",
                    (ip, action, note)
                )

        # Seed Statistics (last 30 days)
        cursor.execute("SELECT COUNT(*) FROM system_statistics")
        if cursor.fetchone()[0] == 0:
            now = datetime.utcnow()
            for i in range(30):
                date = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
                req_val = random.randint(50000, 150000)
                denied_val = int(req_val * random.uniform(0.01, 0.05))
                str_date = date.strftime("%Y-%m-%d %H:%M:%S")
                
                cursor.execute(
                    "INSERT INTO system_statistics (type, value, value_type, created_at) VALUES (?, ?, 'count', ?)",
                    ("total-req", req_val, str_date)
                )
                cursor.execute(
                    "INSERT INTO system_statistics (type, value, value_type, created_at) VALUES (?, ?, 'count', ?)",
                    ("total-denied", denied_val, str_date)
                )
                
            # Recent QPS (last 75 minutes approx)
            for i in range(75):
                dt = now - timedelta(minutes=i)
                str_dt = dt.strftime("%Y-%m-%d %H:%M:%S")
                qps = random.randint(50, 400)
                cursor.execute(
                    "INSERT INTO system_statistics (type, value, value_type, created_at) VALUES (?, ?, 'qps', ?)",
                    ("req", qps, str_dt)
                )

        # Seed Detection Logs
        cursor.execute("SELECT COUNT(*) FROM detect_logs")
        if cursor.fetchone()[0] == 0:
            now = datetime.utcnow()
            cursor.execute("SELECT id, server_names, ports, upstreams FROM websites")
            sites = cursor.fetchall()
            if not sites:
                conn.commit()
                return

            risk_levels = [1, 2, 3]
            methods = ["GET", "POST", "PUT", "DELETE"]
            countries = ["US", "CN", "RU", "BR", "IN", "DE", "FR", "GB", "KR", "JP"]
            module_samples = {
                "sqli": "id=1 UNION SELECT username,password FROM users--",
                "xss": "<script>alert(1)</script>",
                "rce": "name=;cat /etc/passwd",
                "path_traversal": "../../etc/passwd",
                "ssrf": "url=http://169.254.169.254/latest/meta-data",
                "xxe": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
                "ssti": "{{7*7}}",
                "scanner": "sqlmap/1.7",
                "sensitive": "/.env",
                "crlf": "%0d%0aSet-Cookie: admin=true",
                "ldap": "*)(uid=*))(|(uid=*",
                "xpath": "' or '1'='1",
            }
            detection_modules = get_all_module_info()
            
            for _ in range(250):
                site = random.choice(sites)
                site_id, server_names_json, ports_json, upstreams_json = site
                server_names = json.loads(server_names_json)
                ports = json.loads(ports_json)
                upstreams = json.loads(upstreams_json)
                module_info = random.choice(detection_modules)

                event_time = now - timedelta(hours=random.randint(0, 720), minutes=random.randint(0, 60))
                attack_type = module_info["attack_type"]
                risk_level = random.choice(risk_levels)
                action = 1 if risk_level >= 2 or random.random() > 0.5 else 0 
                
                host = server_names[0] if server_names else "localhost"
                dst_port = ports[0] if ports else 80
                protocol = 2 if 443 in ports else 1
                dst_ip = upstreams[0].split(':')[0] if upstreams else "127.0.0.1"
                str_time = event_time.strftime("%Y-%m-%d %H:%M:%S")
                timestamp = int(event_time.timestamp())

                cursor.execute(
                    """INSERT INTO detect_logs 
                       (event_id, site_uuid, src_ip, src_port, socket_ip, dst_ip, dst_port, protocol, 
                        host, method, url_path, query_string, status_code, country, province, city, 
                        attack_type, risk_level, action, rule_id, payload, location, timestamp, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        f"evt_{random.randint(10000000, 99999999)}",
                        f"site_{site_id}",
                        get_random_ip(),
                        random.randint(1024, 65535),
                        get_random_ip(),
                        dst_ip,
                        dst_port,
                        protocol,
                        host,
                        random.choice(methods),
                        f"/path/{random.randint(1, 100)}/resource",
                        "id=1" if random.random() > 0.5 else "",
                        403 if action == 1 else 200,
                        random.choice(countries),
                        "Unknown",
                        "Unknown",
                        attack_type,
                        risk_level,
                        action,
                        f"m_{module_info['key']}",
                        module_samples.get(module_info["key"], module_info["name"]),
                        "url",
                        timestamp,
                        str_time
                    )
                )

        conn.commit()

    except Exception as e:
        print(f"Error seeding database: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    seed_database()
    print("Database seeding completed.")
