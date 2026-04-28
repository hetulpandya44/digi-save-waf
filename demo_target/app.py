"""
Digi Save WAF - Vulnerable Demo Application
=============================================
A deliberately vulnerable web application for testing and demonstrating
the Digi Save WAF's detection and blocking capabilities.

DO NOT deploy this application in production. It contains intentional
security vulnerabilities for educational and testing purposes only.

Vulnerabilities included:
 - SQL Injection (Union, Error-based, Boolean)
 - Reflected XSS
 - Stored XSS (comment board)
 - Remote Command Execution (OS Command Injection)
 - Path Traversal / Local File Inclusion
 - Server-Side Template Injection (SSTI)
 - Sensitive Data Exposure (/.env, /backup.sql)
"""
import os
import sqlite3
import subprocess
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI(title="Vulnerable Demo Site", docs_url=None, redoc_url=None)

# ---------------------------------------------------------------------------
# In-memory SQLite database with sample data
# ---------------------------------------------------------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row
cur = db.cursor()
cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT, role TEXT)")
cur.execute("INSERT INTO users VALUES (1, 'admin', 'admin@corp.local', 'P@ssw0rd!SUPER_SECRET', 'administrator')")
cur.execute("INSERT INTO users VALUES (2, 'john',  'john@corp.local',  'john1234',              'user')")
cur.execute("INSERT INTO users VALUES (3, 'alice', 'alice@corp.local', 'alice_secret_99',       'user')")
cur.execute("CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, author TEXT, body TEXT)")
cur.execute("INSERT INTO comments (author, body) VALUES ('admin', 'Welcome to the demo application!')")
db.commit()

# ---------------------------------------------------------------------------
# Shared HTML shell
# ---------------------------------------------------------------------------
CSS = """
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
  .navbar{background:#1e293b;padding:16px 32px;display:flex;align-items:center;gap:24px;border-bottom:1px solid #334155}
  .navbar h1{font-size:20px;color:#38bdf8}
  .navbar a{color:#94a3b8;text-decoration:none;font-size:14px;padding:6px 14px;border-radius:6px;transition:all .2s}
  .navbar a:hover,.navbar a.active{color:#fff;background:#334155}
  .container{max-width:900px;margin:40px auto;padding:0 24px}
  .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:28px;margin-bottom:24px}
  .card h2{color:#38bdf8;margin-bottom:12px;font-size:18px}
  .card p{color:#94a3b8;font-size:14px;line-height:1.6}
  input,textarea{width:100%;padding:10px 14px;border:1px solid #475569;border-radius:8px;background:#0f172a;color:#e2e8f0;font-size:14px;margin:8px 0}
  button,.btn{padding:10px 20px;background:linear-gradient(135deg,#0ea5e9,#6366f1);color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:600;font-size:14px;transition:all .2s}
  button:hover,.btn:hover{filter:brightness(1.15);transform:translateY(-1px)}
  .result{background:#0f172a;border:1px solid #475569;border-radius:8px;padding:16px;margin-top:16px;white-space:pre-wrap;font-family:monospace;font-size:13px;color:#a5f3fc;max-height:300px;overflow:auto}
  .danger{border-color:#ef4444;color:#fca5a5}
  .tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;margin-left:8px}
  .tag-red{background:#7f1d1d;color:#fca5a5}
  .tag-yellow{background:#713f12;color:#fde68a}
  .comment{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:14px;margin:10px 0}
  .comment strong{color:#38bdf8}
  table{width:100%;border-collapse:collapse;margin-top:12px}
  th,td{padding:10px 14px;text-align:left;border-bottom:1px solid #334155;font-size:13px}
  th{color:#94a3b8;font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:0.5px}
</style>
"""

NAV = """
<div class="navbar">
  <h1>&#x1f3af; Vulnerable Demo App</h1>
  <a href="/">Home</a>
  <a href="/user-lookup">SQLi</a>
  <a href="/search">XSS</a>
  <a href="/comments">Stored XSS</a>
  <a href="/ping">RCE</a>
  <a href="/file">LFI</a>
  <a href="/template">SSTI</a>
  <a href="/.env">Sensitive</a>
</div>
"""

def page(title, body):
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>{title} - Vulnerable Demo</title>{CSS}</head><body>{NAV}<div class="container">{body}</div></body></html>"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index():
    return page("Home", """
    <div class="card">
        <h2>Vulnerable Demo Application</h2>
        <p>This application is <strong>intentionally vulnerable</strong> and is used to demonstrate how the
        <strong>Digi Save WAF</strong> detects and blocks real-world attacks.</p>
        <p style="margin-top:12px">Use the navigation above to access different vulnerability categories.
        Each page includes a working exploit that succeeds when accessed directly, but is
        <strong>blocked by the WAF</strong> when accessed through the proxy (port 8085).</p>
    </div>
    <div class="card">
        <h2>Vulnerability Coverage</h2>
        <table>
            <tr><th>Type</th><th>Page</th><th>Severity</th></tr>
            <tr><td>SQL Injection</td><td>/user-lookup</td><td><span class="tag tag-red">CRITICAL</span></td></tr>
            <tr><td>Reflected XSS</td><td>/search</td><td><span class="tag tag-red">HIGH</span></td></tr>
            <tr><td>Stored XSS</td><td>/comments</td><td><span class="tag tag-red">HIGH</span></td></tr>
            <tr><td>OS Command Injection</td><td>/ping</td><td><span class="tag tag-red">CRITICAL</span></td></tr>
            <tr><td>Path Traversal / LFI</td><td>/file</td><td><span class="tag tag-red">HIGH</span></td></tr>
            <tr><td>SSTI</td><td>/template</td><td><span class="tag tag-yellow">MEDIUM</span></td></tr>
            <tr><td>Sensitive Data Exposure</td><td>/.env</td><td><span class="tag tag-yellow">MEDIUM</span></td></tr>
        </table>
    </div>
    """)


# ---- SQL Injection ----
@app.get("/user-lookup", response_class=HTMLResponse)
def sqli_page(id: str = ""):
    result_html = ""
    if id:
        try:
            cur.execute(f"SELECT * FROM users WHERE id = {id}")
            rows = cur.fetchall()
            if rows:
                result_html = '<table><tr><th>ID</th><th>Username</th><th>Email</th><th>Password</th><th>Role</th></tr>'
                for r in rows:
                    result_html += f'<tr><td>{r["id"]}</td><td>{r["username"]}</td><td>{r["email"]}</td><td>{r["password"]}</td><td>{r["role"]}</td></tr>'
                result_html += '</table>'
            else:
                result_html = '<div class="result">No user found.</div>'
        except Exception as e:
            result_html = f'<div class="result danger">SQL Error: {e}</div>'

    return page("SQL Injection", f"""
    <div class="card">
        <h2>User Lookup <span class="tag tag-red">SQLi Vulnerable</span></h2>
        <p>Look up a user by their ID. Try: <code>1 UNION SELECT 1,username,password,email,role FROM users</code></p>
        <form method="get">
            <input name="id" placeholder="Enter user ID..." value="{id}">
            <button type="submit">Search</button>
        </form>
        {result_html}
    </div>
    """)


# ---- Reflected XSS ----
@app.get("/search", response_class=HTMLResponse)
def xss_page(q: str = ""):
    return page("XSS", f"""
    <div class="card">
        <h2>Search <span class="tag tag-red">XSS Vulnerable</span></h2>
        <p>Try: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> or <code>&lt;img src=x onerror=alert(1)&gt;</code></p>
        <form method="get">
            <input name="q" placeholder="Search..." value="">
            <button type="submit">Search</button>
        </form>
        <div class="result">Results for: {q}</div>
    </div>
    """)


# ---- Stored XSS (Comment Board) ----
@app.get("/comments", response_class=HTMLResponse)
def comments_page():
    cur.execute("SELECT * FROM comments ORDER BY id DESC")
    rows = cur.fetchall()
    comments_html = ""
    for r in rows:
        comments_html += f'<div class="comment"><strong>{r["author"]}</strong><p>{r["body"]}</p></div>'
    return page("Stored XSS", f"""
    <div class="card">
        <h2>Comment Board <span class="tag tag-red">Stored XSS Vulnerable</span></h2>
        <p>Post a comment. Try: <code>&lt;script&gt;alert('Stored XSS')&lt;/script&gt;</code></p>
        <form method="post" action="/comments">
            <input name="author" placeholder="Your name...">
            <textarea name="body" rows="3" placeholder="Your comment..."></textarea>
            <button type="submit">Post Comment</button>
        </form>
        <h3 style="margin-top:20px;color:#94a3b8">Comments</h3>
        {comments_html}
    </div>
    """)

@app.post("/comments", response_class=HTMLResponse)
def post_comment(author: str = Form("Anonymous"), body: str = Form("")):
    # No sanitization — stored XSS
    cur.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
    db.commit()
    return comments_page()


# ---- Remote Command Execution ----
@app.get("/ping", response_class=HTMLResponse)
def rce_page(ip: str = ""):
    output = ""
    if ip:
        try:
            result = subprocess.run(
                f"ping -n 1 {ip}" if os.name == "nt" else f"ping -c 1 {ip}",
                shell=True, capture_output=True, text=True, timeout=5
            )
            output = result.stdout + result.stderr
        except Exception as e:
            output = str(e)

    return page("RCE", f"""
    <div class="card">
        <h2>Network Ping <span class="tag tag-red">RCE Vulnerable</span></h2>
        <p>Ping a host. Try: <code>127.0.0.1 &amp; whoami</code> or <code>; cat /etc/passwd</code></p>
        <form method="get">
            <input name="ip" placeholder="IP address..." value="{ip}">
            <button type="submit">Ping</button>
        </form>
        <div class="result">{output}</div>
    </div>
    """)


# ---- Path Traversal / LFI ----
@app.get("/file", response_class=HTMLResponse)
def lfi_page(name: str = ""):
    content = ""
    if name:
        try:
            # No path sanitization — LFI/Path Traversal vulnerability
            filepath = os.path.join("uploads", name)
            with open(filepath, "r", errors="ignore") as f:
                content = f.read()[:2000]
        except Exception as e:
            content = str(e)

    return page("LFI", f"""
    <div class="card">
        <h2>File Viewer <span class="tag tag-red">LFI Vulnerable</span></h2>
        <p>View a file. Try: <code>../../../etc/passwd</code> or <code>..\\..\\..\\..\\windows\\win.ini</code></p>
        <form method="get">
            <input name="name" placeholder="Filename..." value="{name}">
            <button type="submit">View File</button>
        </form>
        <div class="result">{content}</div>
    </div>
    """)


# ---- SSTI ----
@app.get("/template", response_class=HTMLResponse)
def ssti_page(name: str = ""):
    greeting = ""
    if name:
        # Intentional unsafe string formatting (simulates SSTI)
        template = f"Hello, {name}! Welcome to our platform."
        greeting = template

    return page("SSTI", f"""
    <div class="card">
        <h2>Greeting Card <span class="tag tag-yellow">SSTI Vulnerable</span></h2>
        <p>Enter a name. Try: <code>{{{{7*7}}}}</code> or <code>{{{{config}}}}</code></p>
        <form method="get">
            <input name="name" placeholder="Your name..." value="{name}">
            <button type="submit">Generate Greeting</button>
        </form>
        <div class="result">{greeting}</div>
    </div>
    """)


# ---- Sensitive Data Exposure ----
@app.get("/.env", response_class=HTMLResponse)
def env_file():
    return page("Sensitive Data", """
    <div class="card">
        <h2>Exposed .env File <span class="tag tag-yellow">Sensitive Data</span></h2>
        <div class="result">DB_HOST=production-db.internal.corp.local
DB_USER=root
DB_PASSWORD=Ultra$ecret_Pr0d_P@ss!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_51H7...abcdef
JWT_SECRET=my_super_secret_jwt_signing_key_2024</div>
    </div>
    """)

@app.get("/backup.sql", response_class=HTMLResponse)
def backup_sql():
    return page("Sensitive Data", """
    <div class="card">
        <h2>Exposed Database Backup <span class="tag tag-yellow">Sensitive Data</span></h2>
        <div class="result">-- MySQL dump 10.13
-- Server version 8.0.32
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255),
  `password` varchar(255),
  PRIMARY KEY (`id`)
);
INSERT INTO `users` VALUES (1,'admin','$2b$12$LJ3...'),(2,'ceo','password123');
</div>
    </div>
    """)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print("  VULNERABLE DEMO APPLICATION")
    print("  Running on http://127.0.0.1:8090")
    print("  WARNING: Contains intentional vulnerabilities!")
    print("=" * 50)
    uvicorn.run(app, host="127.0.0.1", port=8090)
