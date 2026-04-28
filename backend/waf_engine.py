import asyncio
import json
import logging
import random
import sqlite3
import time
import re
import urllib.parse
from datetime import datetime
from typing import Any, Dict, Optional, Tuple, List

import httpx  # type: ignore
from fastapi import FastAPI, Request, Response  # type: ignore
from fastapi.responses import HTMLResponse, StreamingResponse  # type: ignore
import uvicorn  # type: ignore
import ipaddress
from collections import defaultdict

from database import DATABASE_PATH
from detection.engine import DetectionEngine, DetectionResult
from routers import protection as protection_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("waf_engine")

app = FastAPI(title="Digi Save WAF Proxy", docs_url=None, redoc_url=None)
app.include_router(protection_router.router)

# Separate clients keep upstream TLS verification strict without breaking internal service calls.
proxy_http_client = httpx.AsyncClient(
    timeout=30.0,
    verify=True,
    follow_redirects=False,
    limits=httpx.Limits(max_connections=200, max_keepalive_connections=60),
)
service_http_client = httpx.AsyncClient(
    timeout=10.0,
    follow_redirects=False,
    limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
)

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn

RATE_LIMIT_MAX_REQS = 200    # requests per window
RATE_LIMIT_WINDOW_SEC = 10.0  # sliding window

def is_rate_limited(conn, ip: str) -> bool:
    now = time.time()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO rate_limits (ip, count, window_start) 
            VALUES (?, 1, ?)
            ON CONFLICT(ip) DO UPDATE SET 
                count = CASE WHEN ? - window_start > ? THEN 1 ELSE count + 1 END,
                window_start = CASE WHEN ? - window_start > ? THEN ? ELSE window_start END
        """, (ip, now, now, RATE_LIMIT_WINDOW_SEC, now, RATE_LIMIT_WINDOW_SEC, now))
        
        cursor.execute("SELECT count FROM rate_limits WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        conn.commit()
        
        if row and row["count"] > RATE_LIMIT_MAX_REQS:
            return True
            
        return False
    except sqlite3.OperationalError:
        return False


def get_real_ip(request: Request) -> str:
    """
    Detect the real client IP behind proxies, CDNs, and load balancers.
    Priority: CF-Connecting-IP → X-Real-IP → X-Forwarded-For (first) → direct connection
    """
    # Cloudflare
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip and _is_valid_ip(cf_ip.strip()):
        return cf_ip.strip()
    # Common reverse proxy header
    real_ip = request.headers.get("x-real-ip")
    if real_ip and _is_valid_ip(real_ip.strip()):
        return real_ip.strip()
    # Standard proxy chain header (use leftmost = original client)
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        first = xff.split(",")[0].strip()
        if _is_valid_ip(first):
            return first
    # Direct connection fallback
    return request.client.host if request.client else "127.0.0.1"


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def check_ip_acl(conn, ip: str) -> Optional[str]:
    """
    Returns 'block' if the IP should be blocked, 'allow' if whitelisted, None if no rule.
    """
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT ip_cidr, action FROM ip_acl WHERE is_enabled = 1 ORDER BY id")
    except sqlite3.OperationalError:
        return None
        
    acls = cursor.fetchall()
    
    try:
        client_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
        
    for acl in acls:
        cidr = acl["ip_cidr"]
        action = acl["action"]
        try:
            if client_obj in ipaddress.ip_network(cidr, strict=False):
                return action   # 'block' or 'allow'
        except ValueError:
            pass
    return None


# -------------------------------
# Site Config Cache (short TTL keeps live demos responsive without hammering SQLite)
# -------------------------------
_site_cache: List[dict] = []
_site_cache_ts: float = 0.0
_SITE_CACHE_TTL = 5.0  # seconds

def get_cached_sites(conn) -> List[dict]:
    global _site_cache, _site_cache_ts
    now = time.time()
    if now - _site_cache_ts > _SITE_CACHE_TTL:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM websites WHERE is_enabled = 1")
        rows = cursor.fetchall()
        _site_cache = [dict(r) for r in rows]
        _site_cache_ts = now
    return _site_cache


def invalidate_site_cache():
    global _site_cache_ts
    _site_cache_ts = 0.0


@app.post("/internal/cache/invalidate")
async def invalidate_site_cache_route():
    invalidate_site_cache()
    return {"status": "ok", "ttl_seconds": _SITE_CACHE_TTL}


# -----------------------------------------------
# Geolocation (with in-process cache)
# -----------------------------------------------
geo_cache = {}

async def get_geolocation(ip: str) -> tuple:
    if ip in ["127.0.0.1", "localhost", "0.0.0.0"] or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return "Private", "Private", "Private"
        
    if ip in geo_cache:
        return geo_cache[ip]
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT country, province, city FROM geoip_cache WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        
        if row:
            result = (row["country"], row["province"], row["city"])
            geo_cache[ip] = result
            conn.close()
            return result
            
        # Not in DB, fetch from API
        resp = await service_http_client.get(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,status", timeout=2.0)
        data = resp.json()
        if data.get("status") == "success":
            result = (str(data.get("country", "Unknown")), str(data.get("regionName", "Unknown")), str(data.get("city", "Unknown")))
            geo_cache[ip] = result
            
            # Save to db
            cursor.execute(
                "INSERT OR IGNORE INTO geoip_cache (ip, country, province, city) VALUES (?, ?, ?, ?)",
                (ip, result[0], result[1], result[2])
            )
            conn.commit()
            conn.close()
            return result
        conn.close()
    except Exception as e:
        logger.warning(f"GeoIP error: {e}")
        try:
            conn.close()
        except: pass
        
    geo_cache[ip] = ("Unknown", "Unknown", "Unknown")
    return "Unknown", "Unknown", "Unknown"


# -----------------------------------------------
# Attack Logger
# -----------------------------------------------
def log_attack(conn, req_data, rule_id, payload, site_id, action=1, country="Unknown", province="Unknown", city="Unknown", attack_type=62, risk_level=2):
    """Write attack to detect_logs with full forensic data."""
    cursor = conn.cursor()
    event_id = f"evt_{int(time.time()*1000)}_{random.randint(100,999)}"
    headers_dict = req_data.get("headers", {})
    req_header_str = json.dumps(dict(headers_dict), default=str)[:4000] if headers_dict else ""
    req_body_str = str(req_data.get("body", ""))[:4000]
    try:
        cursor.execute(
            """INSERT INTO detect_logs 
               (event_id, site_uuid, src_ip, src_port, socket_ip, dst_ip, dst_port, protocol, 
                host, method, url_path, query_string, status_code, country, province, city, 
                attack_type, risk_level, action, rule_id, payload, location, 
                req_header, req_body, timestamp, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                f"site_{site_id}",
                req_data.get("client_ip", "127.0.0.1"),
                req_data.get("client_port", 0),
                req_data.get("client_ip", "127.0.0.1"),
                "127.0.0.1",
                80,
                1,
                req_data.get("host", "unknown"),
                req_data.get("method", "GET"),
                req_data.get("path", "/"),
                req_data.get("query", ""),
                403 if action == 1 else 200,
                country, province, city,
                attack_type,
                risk_level,
                action,
                rule_id,
                str(payload)[:500] if payload else "",
                "url",
                req_header_str,
                req_body_str,
                int(time.time()),
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            )
        )
        today = datetime.utcnow().strftime("%Y-%m-%d 00:00:00")
        cursor.execute("SELECT id FROM system_statistics WHERE type='total-req' AND created_at >= ?", (today,))
        row = cursor.fetchone()
        if row:
            cursor.execute("UPDATE system_statistics SET value = value + 1 WHERE id = ?", (row["id"],))
        else:
            cursor.execute("INSERT INTO system_statistics (type, value, value_type, created_at) VALUES ('total-req', 1, 'count', ?)", (today,))
        if action == 1:
            cursor.execute("SELECT id FROM system_statistics WHERE type='total-denied' AND created_at >= ?", (today,))
            row = cursor.fetchone()
            if row:
                cursor.execute("UPDATE system_statistics SET value = value + 1 WHERE id = ?", (row["id"],))
            else:
                cursor.execute("INSERT INTO system_statistics (type, value, value_type, created_at) VALUES ('total-denied', 1, 'count', ?)", (today,))
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to log attack: {e}")


def increment_request_count(conn):
    """Increment clean (non-attack) traffic counter."""
    try:
        cursor = conn.cursor()
        today = datetime.utcnow().strftime("%Y-%m-%d 00:00:00")
        cursor.execute("SELECT id FROM system_statistics WHERE type='total-req' AND created_at >= ?", (today,))
        row = cursor.fetchone()
        if row:
            cursor.execute("UPDATE system_statistics SET value = value + 1 WHERE id = ?", (row["id"],))
        else:
            cursor.execute("INSERT INTO system_statistics (type, value, value_type, created_at) VALUES ('total-req', 1, 'count', ?)", (today,))
        conn.commit()
    except Exception:
        pass


# -----------------------------------------------
# Premium WAF Block Page
# -----------------------------------------------
def build_block_page(rule_id: str, client_ip: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Blocked | Digi Save WAF</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono:wght@400&display=swap');
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Outfit', sans-serif;
            background: #060913;
            color: white;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background-image: radial-gradient(circle at top left, #121b33 0%, #060913 60%);
        }}
        .container {{
            text-align: center;
            max-width: 560px;
            padding: 60px 40px;
            background: rgba(17, 24, 43, 0.7);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 24px;
            box-shadow: 0 25px 60px rgba(0,0,0,0.5);
        }}
        .shield {{ font-size: 72px; margin-bottom: 24px; filter: drop-shadow(0 0 20px rgba(0,240,255,0.5)); }}
        h1 {{ font-size: 32px; font-weight: 700; color: #ff4d6d; margin-bottom: 16px; }}
        .subtitle {{ font-size: 18px; color: #a0aabf; font-weight: 300; line-height: 1.6; margin-bottom: 40px; }}
        .details {{
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 12px;
            padding: 20px 24px;
            text-align: left;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: #5e6b8c;
            line-height: 2;
        }}
        .details span {{ color: #a0aabf; }}
        .badge {{
            display: inline-block;
            margin-top: 32px;
            padding: 8px 20px;
            background: rgba(0,240,255,0.1);
            border: 1px solid rgba(0,240,255,0.3);
            border-radius: 20px;
            color: #00f0ff;
            font-size: 13px;
            font-weight: 500;
            letter-spacing: 1px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="shield">🛡️</div>
        <h1>Request Blocked</h1>
        <p class="subtitle">
            Your request was intercepted and blocked by <strong>Digi Save WAF</strong> 
            because it matched a security rule. If you believe this is an error, 
            contact the site administrator.
        </p>
        <div class="details">
            Rule: <span>{rule_id}</span><br>
            Time: <span>{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</span><br>
            Protected by: <span>Digi Save WAF v2.1.0</span>
        </div>
        <div class="badge">DIGI SAVE WAF · PROTECTED</div>
    </div>
</body>
</html>"""


# -----------------------------------------------
# Main WAF Middleware
# -----------------------------------------------
@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/protection/") or request.url.path.startswith("/internal/"):
        return await call_next(request)

    # 1. Get real client IP (respects X-Forwarded-For, CF-Connecting-IP, etc.)
    client_ip = get_real_ip(request)
    client_port = request.client.port if request.client else 0
    host = request.headers.get("host", "").split(":")[0]  # strip port from host header
    path = request.url.path
    query = request.url.query
    url = str(request.url)
    method = request.method

    # Read and cache the body once for inspection/proxying.
    # Replacing request._receive here breaks Starlette's disconnect handling
    # for streamed upstream responses and can surface as incomplete chunk reads.
    body_bytes = await request.body()

    req_data = {
        "host": host,
        "client_ip": client_ip,
        "client_port": client_port,
        "path": path,
        "query": query,
        "url": url,
        "method": method,
        "headers": dict(request.headers),
        "body": body_bytes.decode('utf-8', errors='ignore')[:2000000]  # Cap regex inspection at 2MB to prevent ReDoS CPU exhaustion
    }

    conn = get_db_connection()
    try:
        # ── Rate Limiting ──
        if is_rate_limited(conn, client_ip):
            logger.warning(f"RATE LIMIT: {client_ip}")
            return HTMLResponse(
                content="<html><body><h1>429 Too Many Requests</h1><p>Rate limit exceeded. Try again in a few seconds.</p></body></html>",
                status_code=429
            )

        # ── IP ACL ──
        acl_result = check_ip_acl(conn, client_ip)
        if acl_result == "block":
            logger.warning(f"ACL BLOCK: {client_ip}")
            log_attack(conn, req_data, "ip_acl_block", "Blocked by IP Access Control List", 0, action=1)
            return HTMLResponse(content=build_block_page("ip_acl_block", client_ip), status_code=403)
        # acl_result == 'allow' → skip further checks and just proxy

        # ── Site Config Lookup (cached) ──
        websites = get_cached_sites(conn)
        
        target_upstream = None
        site_id = 0
        site_data = None
        all_upstreams = []

        for site in websites:
            try:
                server_names = json.loads(site.get("server_names", "[]"))
                upstreams_list = json.loads(site.get("upstreams", "[]"))

                # Industry-grade matching:
                # 1. Exact host match
                # 2. Wildcard *.domain.com match
                # 3. No "localhost" shortcut — must be explicitly configured
                matched = False
                for name in server_names:
                    name = name.strip().lower()
                    h = host.lower()
                    if name == h:
                        matched = True; break
                    if name.startswith("*.") and h.endswith(name[1:]):
                        matched = True; break
                
                if matched and upstreams_list:
                    all_upstreams = list(upstreams_list)
                    # Start with a random upstream for load balancing
                    random.shuffle(all_upstreams)
                    target_upstream = all_upstreams[0]
                    site_id = site["id"]
                    site_data = dict(site)
                    break
            except Exception:
                pass

        if not target_upstream:
            # No site matched — return a friendly WAF response
            return HTMLResponse(
                content=f"""<html><head><title>Digi Save WAF — No Route</title></head>
                <body style="font-family:sans-serif;background:#060913;color:#a0aabf;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
                <div style="text-align:center"><h1 style="color:#00f0ff">🛡️ Digi Save WAF</h1>
                <p>No website configured for host: <code style="color:white">{host}</code></p>
                <p style="margin-top:12px;font-size:13px">Add this domain in the WAF management console at <a href="http://localhost:8005" style="color:#00f0ff">http://localhost:8005</a></p></div></body></html>""",
                status_code=404
            )

        # Add http:// schema if missing
        def normalize_upstream(u: str) -> str:
            if not u.startswith("http"):
                return f"http://{u}"
            return u

        target_upstream = normalize_upstream(target_upstream)
        all_upstreams = [normalize_upstream(u) for u in all_upstreams]

        # ── Protection Gates (only if not already whitelisted by ACL) ──
        if site_data and acl_result != "allow":
            cursor = conn.cursor()
            
            # CAPTCHA Gate
            if site_data.get("captcha_enabled"):
                token = request.cookies.get("waf_captcha_token")
                valid_token = False
                if token:
                    cursor.execute("SELECT expires_at FROM captcha_sessions WHERE token = ? AND ip = ?", (token, client_ip))
                    row = cursor.fetchone()
                    if row:
                        try:
                            if datetime.fromisoformat(row["expires_at"].split(".")[0]) > datetime.utcnow():
                                valid_token = True
                        except Exception:
                            pass
                if not valid_token:
                    logger.info(f"CAPTCHA GATE: {client_ip} → {host}")
                    captcha_html = f"""<html><head><title>Security Check - Digi Save WAF</title>
                    <style>body{{font-family:'Outfit',sans-serif;background:#060913;color:white;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}.box{{background:rgba(17,24,43,.8);border:1px solid rgba(255,255,255,.08);border-radius:20px;padding:40px;text-align:center;max-width:400px;}}img{{border-radius:8px;margin:20px 0;}}input{{padding:12px 16px;border-radius:8px;border:1px solid rgba(255,255,255,.2);background:rgba(0,0,0,.3);color:white;font-size:16px;width:200px;margin:8px;}}button{{padding:12px 28px;background:linear-gradient(135deg,#00f0ff,#0099ff);color:#000;border:none;border-radius:8px;cursor:pointer;font-weight:700;font-size:14px;}}</style></head>
                    <body><div class="box"><h2>🛡️ Security Check</h2><p style="color:#a0aabf">Please verify you are human to continue.</p><img src="/api/protection/captcha/image" /><br><input type="text" id="cap" placeholder="Enter code..." /><br><button onclick="verify()">Verify & Continue</button><p id="err" style="color:#ff4d6d;display:none"></p></div>
                    <script>async function verify(){{const code=document.getElementById('cap').value;const res=await fetch('/api/protection/captcha/verify',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{captcha_text:code}})}});if(res.ok){{window.location.reload();}}else{{document.getElementById('err').style.display='block';document.getElementById('err').innerText='Incorrect code. Try again.';}}}}</script></body></html>"""
                    return HTMLResponse(content=captcha_html, status_code=403)

            # Auth Gate
            if site_data.get("auth_enabled"):
                session = request.cookies.get(f"waf_auth_{site_id}")
                valid_session = False
                if session:
                    cursor.execute("SELECT expires_at FROM auth_challenges WHERE session_token = ? AND ip = ?", (session, client_ip))
                    row = cursor.fetchone()
                    if row:
                        try:
                            if datetime.fromisoformat(row["expires_at"].split(".")[0]) > datetime.utcnow():
                                valid_session = True
                        except Exception:
                            pass
                if not valid_session:
                    logger.info(f"AUTH GATE: {client_ip} → {host}")
                    auth_html = f"""<html><head><title>Authentication Required - Digi Save WAF</title>
                    <style>body{{font-family:'Outfit',sans-serif;background:#060913;color:white;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}.box{{background:rgba(17,24,43,.8);border:1px solid rgba(255,255,255,.08);border-radius:20px;padding:40px;text-align:center;max-width:400px;}}input{{padding:12px 16px;border-radius:8px;border:1px solid rgba(255,255,255,.2);background:rgba(0,0,0,.3);color:white;font-size:16px;width:250px;margin:16px 0;}}button{{padding:12px 28px;background:linear-gradient(135deg,#00e676,#00b0ff);color:#000;border:none;border-radius:8px;cursor:pointer;font-weight:700;font-size:14px;}}</style></head>
                    <body><div class="box"><h2>🔒 Protected Site</h2><p style="color:#a0aabf">This website requires a password to access.</p><input type="password" id="pwd" placeholder="Enter password..." /><br><button onclick="verify()">Access Site</button><p id="err" style="color:#ff4d6d;display:none"></p></div>
                    <script>async function verify(){{const pwd=document.getElementById('pwd').value;const res=await fetch('/api/protection/auth/verify',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{password:pwd,site_id:{site_id}}})}});if(res.ok){{window.location.reload();}}else{{document.getElementById('err').style.display='block';document.getElementById('err').innerText='Incorrect password.';}}}}</script></body></html>"""
                    return HTMLResponse(content=auth_html, status_code=403)

            # Dynamic JS Challenge Gate
            if site_data.get("dynamic_enabled"):
                session = request.cookies.get(f"waf_dyn_{site_id}")
                valid_session = False
                if session:
                    cursor.execute("SELECT expires_at FROM auth_challenges WHERE session_token = ? AND ip = ?", (session, client_ip))
                    row = cursor.fetchone()
                    if row:
                        try:
                            if datetime.fromisoformat(row["expires_at"].split(".")[0]) > datetime.utcnow():
                                valid_session = True
                        except Exception:
                            pass
                if not valid_session:
                    logger.info(f"JS CHALLENGE: {client_ip} → {host}")
                    target = path + ("?" + query if query else "")
                    challenge_html = f"""<html><head><title>Checking Browser... - Digi Save WAF</title>
                    <style>body{{font-family:'Outfit',sans-serif;background:#060913;color:white;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}.box{{text-align:center;}}.loader{{border:4px solid rgba(255,255,255,.1);border-left-color:#00f0ff;border-radius:50%;width:48px;height:48px;animation:spin 1s linear infinite;margin:0 auto 24px;}}.bar{{width:280px;height:4px;background:rgba(255,255,255,.1);border-radius:2px;margin:24px auto 0;overflow:hidden;}}.fill{{height:100%;width:0%;background:linear-gradient(90deg,#00f0ff,#b05cff);border-radius:2px;transition:width 2s ease;}}@keyframes spin{{0%{{transform:rotate(0deg)}}100%{{transform:rotate(360deg)}}}}</style></head>
                    <body><div class="box"><div class="loader"></div><h2>Checking your browser...</h2><p style="color:#a0aabf;margin-top:8px">Digi Save WAF is verifying this is a real browser.</p><div class="bar"><div class="fill" id="fill"></div></div></div>
                    <script>setTimeout(function(){{document.getElementById('fill').style.width='100%';}},100);setTimeout(async function(){{if(navigator.webdriver){{document.body.innerHTML='<div style="text-align:center;padding:40px"><h2>Automated Activity Detected.</h2><p>Your browser appears to be controlled by automated software.</p></div>';return;}}const res=await fetch('/api/protection/dynamic/solve',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{site_id:{site_id},ua:navigator.userAgent}})}});if(res.ok){{window.location.href='{target}';}}else{{document.body.innerHTML='<div style="text-align:center;padding:40px"><h2>Verification failed. Please refresh.</h2></div>';}}}},2200);</script></body></html>"""
                    return HTMLResponse(content=challenge_html, status_code=403)

        # ── Detection Engine ──
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM policy_rules WHERE is_enabled = 1")
        custom_rules = [dict(r) for r in cursor.fetchall()]
        
        try:
            cursor.execute("SELECT module, mode, high_risk_action, medium_risk_action, low_risk_action FROM policy_groups")
            module_configs = {r["module"]: dict(r) for r in cursor.fetchall()}
        except sqlite3.OperationalError:
            module_configs = {}

        # Apply per-site detection mode
        if site_data:
            site_mode = site_data.get("detection_mode", "balance")
            site_mode_map = {"strict": "strict", "balance": "default", "default": "default", "disabled": "disabled"}
            if site_mode in site_mode_map:
                for mod in module_configs.values():
                    mod["mode"] = site_mode_map[site_mode]

        engine = DetectionEngine(module_configs)
        result = engine.detect(req_data, custom_rules)
        
        if result.is_attack and result.action == 1:
            matched_rule = result.rule_id
            payload = result.matched_payload
            logger.warning(f"BLOCKED ({matched_rule}) from {client_ip} → {url}")
            
            country, province, city = await get_geolocation(client_ip)
            log_attack(
                conn, req_data, matched_rule, payload, site_id,
                action=1, country=country, province=province, city=city,
                attack_type=result.attack_type, risk_level=result.risk_level
            )
            
            # Push live event to management UI
            asyncio.create_task(
                service_http_client.post("http://127.0.0.1:8005/internal/notify_attack", json={
                    "type": "attack",
                    "ip": client_ip,
                    "rule": matched_rule,
                    "country": country,
                    "url": url,
                    "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                }, timeout=2.0)
            )
            return HTMLResponse(content=build_block_page(matched_rule, client_ip), status_code=403)

        # ── Proxy Phase — Count clean traffic ──
        increment_request_count(conn)

    finally:
        conn.close()

    # ── Upstream Proxy with Failover ──
    proxy_headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
    # Inject real IP headers for upstream awareness
    proxy_headers["x-forwarded-for"] = client_ip
    proxy_headers["x-real-ip"] = client_ip
    proxy_headers["x-forwarded-proto"] = "https" if request.url.scheme == "https" else "http"
    proxy_headers["x-waf-protected"] = "Digi-Save-WAF"

    last_error = None
    for upstream in all_upstreams:
        try:
            target_url = f"{upstream}{path}"
            if query:
                target_url += f"?{query}"

            proxy_req = proxy_http_client.build_request(
                method,
                target_url,
                headers=proxy_headers,
                content=body_bytes
            )
            proxy_resp = await proxy_http_client.send(proxy_req, stream=True)
            async def stream_generator(response):
                try:
                    async for chunk in response.aiter_raw():
                        yield chunk
                finally:
                    await response.aclose()
            
            resp_headers = {
                k: v for k, v in proxy_resp.headers.items()
                if k.lower() not in ('transfer-encoding', 'content-length', 'content-encoding')
            }
                    
            return StreamingResponse(
                stream_generator(proxy_resp),
                status_code=proxy_resp.status_code,
                headers=resp_headers
            )
        except httpx.RequestError as exc:
            last_error = exc
            logger.warning(f"Upstream {upstream} failed: {exc}. Trying next...")
            continue

    logger.error(f"All upstreams failed for {host}: {last_error}")
    return HTMLResponse(
        content="""<html><head><title>502 Bad Gateway - Digi Save WAF</title></head>
        <body style="font-family:sans-serif;background:#060913;color:#a0aabf;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
        <div style="text-align:center"><h1 style="color:#ff4d6d">502 Bad Gateway</h1>
        <p>Digi Save WAF could not reach any configured upstream servers.<br>
        Please check the upstream configuration in the management console.</p></div></body></html>""",
        status_code=502
    )


# -----------------------------------------------
# SSL Config Loader
# -----------------------------------------------
def get_ssl_config():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM options WHERE key IN ('ssl_cert_path', 'ssl_key_path')")
        opts = {row['key']: row['value'] for row in cursor.fetchall()}
        conn.close()
        cert = opts.get('ssl_cert_path')
        key = opts.get('ssl_key_path')
        import os
        if cert and key and os.path.exists(cert) and os.path.exists(key):
            return cert, key
    except Exception:
        pass
    return None, None


if __name__ == "__main__":
    cert_path, key_path = get_ssl_config()
    if cert_path and key_path:
        logger.info(f"Starting WAF Proxy on :8085 with HTTPS. Cert: {cert_path}")
        uvicorn.run("waf_engine:app", host="0.0.0.0", port=8085, log_level="warning", ssl_certfile=cert_path, ssl_keyfile=key_path)
    else:
        logger.info("Starting WAF Proxy on :8085 (HTTP — no SSL certs found)")
        uvicorn.run("waf_engine:app", host="0.0.0.0", port=8085, log_level="warning")
