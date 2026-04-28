# Digi Save WAF Project Guide

## 1. Project Summary

Digi Save WAF is a reverse-proxy web application firewall. Instead of modifying the protected website directly, the system places a proxy in front of it. Every request first enters Digi Save WAF, where it is checked for suspicious payloads, abusive traffic, forbidden IPs, or protection-gate requirements. Only safe traffic is forwarded to the real website.

This design lets one WAF protect multiple websites from one place.

## 2. Project Type

- Category: Cybersecurity / Web Security
- Type: Final-year implementation project
- Style: Full-stack defensive security system
- Deployment model: Self-hosted local or lab deployment

## 3. Full Stack And Technologies

| Layer | Technology | Why it is used |
|---|---|---|
| Programming language | Python | Rapid backend development and readable security logic |
| Backend framework | FastAPI | Fast routing, async support, clean API design |
| HTTP client/proxy | `httpx` | Sending requests to upstream websites |
| Frontend | Vanilla HTML, CSS, JavaScript | Lightweight admin UI without a large frontend framework |
| Charts | Chart.js | Dashboard metrics and visualization |
| Authentication | JWT | Stateless session tokens for admin APIs |
| Password hashing | bcrypt | Secure password storage |
| MFA | TOTP using `pyotp` | Two-factor authentication |
| QR generation | `qrcode` | Local MFA QR generation without third-party leakage |
| Database | SQLite | Simple embedded database for configuration and logs |
| Scheduled jobs | APScheduler | Cleanup and periodic maintenance |

## 4. Database Type And Working

### Database type

The project uses SQLite, which is a file-based relational database.

Database file:

`C:\Users\hetul\Documents\Arduino\dcn ss\integrated project\pmdemo\backend\data\digisave.db`

### Why SQLite was chosen

- Easy to ship with a student project
- No external database server required
- Very fast for a single-machine deployment
- Good enough for settings, logs, and admin data in a demo environment

### SQLite tuning in this project

The project enables SQLite WAL mode and related performance settings in [`backend/database.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/database.py).

This improves:

- read/write concurrency
- stability during frequent logging
- responsiveness of the management UI

### Main tables

| Table | Purpose |
|---|---|
| `users` | Admin usernames, hashed passwords, MFA state |
| `websites` | Protected websites, server names, upstreams, site protection flags |
| `policy_groups` | Detection-module modes such as strict/default/disabled |
| `policy_rules` | Custom rules created by the admin |
| `detect_logs` | Attack events and forensic request details |
| `ip_acl` | Explicit allow/block IP or CIDR rules |
| `options` | App settings like SSL paths and log retention |
| `system_statistics` | Dashboard statistics |
| `captcha_sessions` | CAPTCHA validation sessions |
| `auth_challenges` | Auth-gate and dynamic challenge sessions |
| `geoip_cache` | Cached IP location lookups |
| `rate_limits` | Per-IP traffic counters |

## 5. How The Project Works Internally

### A. Management server

The management server in [`backend/main.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/main.py) serves:

- login and authentication APIs
- dashboard APIs
- settings APIs
- site management APIs
- rule management APIs
- static frontend pages

It also starts the WAF proxy as a child process.

### B. WAF proxy engine

The WAF engine in [`backend/waf_engine.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/waf_engine.py) is the real traffic path.

For each request it:

1. Determines the client IP
2. Checks rate limiting
3. Checks IP ACL rules
4. Checks CAPTCHA/Auth/Dynamic gates if enabled
5. Loads matching website configuration
6. Runs the detection engine
7. Logs attacks if needed
8. Forwards clean traffic to the upstream server

### C. Detection engine

The detection engine in [`backend/detection/engine.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/detection/engine.py) calls individual modules.

Each module focuses on one attack family.

Examples:

- [`backend/detection/sqli.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/detection/sqli.py)
- [`backend/detection/xss.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/detection/xss.py)
- [`backend/detection/rce.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/detection/rce.py)
- [`backend/detection/path_traversal.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/detection/path_traversal.py)

## 6. Detection Modules In Your Project

| Module | What it detects |
|---|---|
| SQL Injection | `UNION`, boolean, stacked, suspicious query patterns |
| XSS | script tags, inline event handlers, dangerous payload fragments |
| Command Injection | shell metacharacters and chained command patterns |
| Path Traversal | `../` and encoded traversal attempts |
| SSRF | internal addresses and metadata endpoint patterns |
| SSTI | template syntax used to inject expressions |
| XXE | dangerous XML entity declarations |
| Scanner Detection | common offensive tool fingerprints |
| Sensitive File Access | `.env`, backups, config dumps, protected files |
| CRLF Injection | header-splitting payloads |
| LDAP Injection | LDAP filter manipulation |
| XPath Injection | XPath query abuse patterns |

## 7. Where And How To Change Username And Password

### Change from the UI

Go to:

`Settings -> Security`

You now have two separate sections:

- `Change Admin Username`
- `Change Admin Password`

### Related backend endpoints

- Username change: [`backend/routers/auth.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/routers/auth.py) route `POST /api/change-username`
- Password change: [`backend/routers/auth.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/routers/auth.py) route `POST /api/change-password`

### Where credentials are stored

User accounts are stored in the `users` table in SQLite.

Fields:

- `username`
- `password_hash`
- `tfa_enabled`
- `tfa_secret`

Passwords are stored as bcrypt hashes, not plain text.

### Default seeded admin

The default admin user is created in [`backend/seed_data.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/seed_data.py).

Default values:

- username: `admin`
- password: `admin123`

### Manual reset from terminal if needed

If you get locked out and need to reset credentials locally, run this in the backend directory:

```powershell
python -c "import sqlite3; from routers.auth import hash_password; from database import DATABASE_PATH; conn=sqlite3.connect(DATABASE_PATH); conn.execute('UPDATE users SET username=?, password_hash=? WHERE id=1', ('admin', hash_password('NewPass123'))); conn.commit(); print('Admin credentials reset.')"
```

Do not write a plain text password directly into `password_hash`.

## 8. How To Integrate A Website Into Digi Save WAF

### Using the UI

Go to `Protected Sites` and click `Add Website`.

Fields:

- `Comment / Name`: friendly name for the site
- `Server Names`: hostnames the WAF should match
- `Ports`: expected ports
- `Upstreams`: real backend application addresses
- `Site Enabled`: whether routing is active
- `Detection Mode`: `Strict`, `Balance`, or `Disabled`
- Optional gates: `CAPTCHA`, `Auth Gate`, `Dynamic HTML/JS`

### Example

- Comment: `Vulnerable Demo App`
- Server name: `demo.local`
- Upstream: `http://127.0.0.1:8090`

### What happens after saving

1. The site is inserted into the `websites` table.
2. The WAF cache is refreshed.
3. Future requests whose `Host` header matches the configured server name are routed through that site configuration.

## 9. Important Files For Explaining The Project

| Topic | File |
|---|---|
| Entry point | [`backend/main.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/main.py) |
| WAF proxy | [`backend/waf_engine.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/waf_engine.py) |
| DB schema | [`backend/database.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/database.py) |
| Auth | [`backend/routers/auth.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/routers/auth.py) |
| Site config | [`backend/routers/websites.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/routers/websites.py) |
| Settings | [`backend/routers/settings.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/routers/settings.py) |
| Logs | [`backend/routers/detect_logs.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/routers/detect_logs.py) |
| Rules | [`backend/routers/policy_rules.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/backend/routers/policy_rules.py) |
| Demo target | [`demo_target/app.py`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/demo_target/app.py) |

## 10. Strengths Of The Project

- Full working stack from UI to proxy to database
- Real-time blocking, not just passive logging
- Multi-site support
- Modular detection engine
- Built-in demo target for a safe presentation
- Admin authentication, MFA, IP ACL, and site-specific protection features

## 11. Current Limitations

These are honest points you can mention in viva:

- SQLite is excellent for the demo but not ideal for large multi-node production workloads
- Detection is mostly signature and pattern based, not ML based
- Centralized distributed deployment is not implemented
- TLS automation and enterprise-grade secret management are limited
- UI is strong for a project, but not yet at enterprise product maturity

## 12. Future Scope

- PostgreSQL or MySQL backend for larger deployments
- Redis-backed rate limiting
- ML-assisted anomaly detection
- Role-based multi-user administration
- SIEM, Slack, or webhook integrations
- Distributed WAF cluster mode

