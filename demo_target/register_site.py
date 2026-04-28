import sqlite3, json, os, sys

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend", "data", "digisave.db")
conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

# Check if demo.local already registered
cur = conn.cursor()
cur.execute("SELECT id FROM websites WHERE server_names LIKE '%demo.local%'")
existing = cur.fetchone()
if existing:
    print(f"demo.local already registered (id={existing['id']}). Skipping insert.")
else:
    cur.execute(
        "INSERT INTO websites (comment, server_names, upstreams, is_enabled) VALUES (?, ?, ?, 1)",
        ("Vulnerable Demo App", json.dumps(["demo.local"]), json.dumps(["http://127.0.0.1:8090"]))
    )
    conn.commit()
    print(f"Registered demo.local -> http://127.0.0.1:8090 (id={cur.lastrowid})")
conn.close()
