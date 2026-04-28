# Digi Save WAF V4 - Professor Presentation Guide

This guide provides a structured, step-by-step manual for successfully demonstrating your Digi Save Web Application Firewall to your professor. It covers everything from launching the application to showing the UI, database, architecture, live attack detection, and final forensic logs.

## IMPORTANT

Before you begin:

- Make sure Python and the project dependencies are installed.
- DB Browser for SQLite is optional but useful for showing the database file.
- Keep the demo limited to the included local vulnerable site or another website you own and are authorized to test.
- Your best presentation order is: problem -> architecture -> UI -> database -> protected site -> clean request -> blocked attacks -> logs -> conclusion.

## Phase 1: Infrastructure & Application Startup

Start by showing the professor the actual running infrastructure. Open your terminal in the `pmdemo` directory.

### 1. Start the Target Application

You need a vulnerable website to protect. Run the included demo target.

Command:

```powershell
cd "C:\Users\hetul\Documents\Arduino\dcn ss\integrated project\pmdemo\demo_target"
python app.py
```

Explain:

"This is an intentionally vulnerable local website running on port `8090`. If we attack it directly, the attack can succeed. I use it only for safe testing and demonstration."

### 2. Start the WAF Engine and Management UI

In a new terminal window, start Digi Save WAF.

Command:

```powershell
cd "C:\Users\hetul\Documents\Arduino\dcn ss\integrated project\pmdemo"
start.bat
```

Alternative command:

```powershell
cd "C:\Users\hetul\Documents\Arduino\dcn ss\integrated project\pmdemo\backend"
python main.py
```

Explain:

"This launches the two main parts of my project. Port `8005` is the management server for the dashboard, login, settings, logs, and rules. Port `8085` is the WAF reverse-proxy engine that inspects requests before they reach the real website."

### 3. Verify the Running Ports

Open these in your browser:

- `http://localhost:8005`
- `http://localhost:8085`
- `http://127.0.0.1:8090`

Explain:

"Port `8005` is the admin side, port `8085` is the protected route, and port `8090` is the original vulnerable target. This lets me compare direct traffic versus WAF-protected traffic."

### 4. Optional Automated Demo Suite

If you want a fast automated proof after your manual demo, run:

```powershell
cd "C:\Users\hetul\Documents\Arduino\dcn ss\integrated project\pmdemo\demo_target"
python professor_demo.py
```

Explain:

"This optional script sends a series of safe local attack simulations directly to the vulnerable app and then through the WAF, showing the before-and-after protection automatically."

Important:

- `professor_demo.py` is not the website server.
- It is only an attack demonstration script.
- The real target application is started with `python app.py`.

## Phase 2: UI and Architecture Walkthrough

Open your browser and go to the Digi Save WAF UI.

### 1. Log In

URL:

`http://localhost:8005/login`

Default credentials:

- Username: `admin`
- Password: `admin123`

Explain:

"The login system uses bcrypt password hashing, JWT session handling, brute-force protection, and optional TOTP-based multi-factor authentication."

### 2. Show the Dashboard

URL:

`http://localhost:8005/dashboard`

Explain:

"This dashboard gives a Security Operations Center style view of the system. It shows total requests, attacks detected, blocked events, and quick visibility into protected sites."

### 3. Explain the Architecture

Use your PPT architecture slide here.

Explain:

"The client sends a request to Digi Save WAF first. The WAF proxy on port `8085` checks the host, matches the protected site, runs pre-checks such as IP ACL and rate limiting, sends the request to the detection engine, and then decides whether to block or forward the request. The management server on port `8005` handles all administration, rules, logs, and settings. Both parts share the same SQLite database."

### 4. Explain the Request Lifecycle

Use your PPT request lifecycle slide here.

Explain:

"The request lifecycle is: receive request, identify protected site, apply pre-checks, run attack detection, make allow or block decision, forward safe traffic to the upstream server, and log malicious traffic into the forensic database."

### 5. Show Protected Sites

URL:

`http://localhost:8005/sites`

Explain:

"This page allows the administrator to register websites behind the WAF, define their host names, set the upstream server, choose the detection mode, and enable extra protections."

### 6. Show Rules and Settings

Open:

- `http://localhost:8005/rules`
- `http://localhost:8005/settings`

Explain:

"The Rules page controls the detection behavior of different modules, while Settings allows the admin to change username, change password, enable MFA, and configure security options."

### 7. Database Inspection

Show the SQLite database file:

`C:\Users\hetul\Documents\Arduino\dcn ss\integrated project\pmdemo\backend\data\digisave.db`

If DB Browser is available, open it there. If not, use this terminal command:

```powershell
cd "C:\Users\hetul\Documents\Arduino\dcn ss\integrated project\pmdemo\backend"
python -c "import sqlite3; conn=sqlite3.connect('data/digisave.db'); print('users:', conn.execute('select id, username, is_enabled from users').fetchall()); print('websites:', conn.execute('select id, comment, server_names, upstreams, is_enabled from websites').fetchall()); print('detect_logs count:', conn.execute('select count(*) from detect_logs').fetchone())"
```

Explain:

"The project uses SQLite as a relational database. It stores admin users, protected websites, detection module settings, IP ACL rules, and full forensic attack logs."

## Phase 3: Integrating a Website into the WAF

Show the professor how easy it is to protect a website.

### Option A: Use the Preconfigured Demo Site

The current final setup already includes the demo target mapped for:

- `demo.local`
- `localhost`
- `127.0.0.1`

with upstream:

- `http://127.0.0.1:8090`

Explain:

"For the final demo, I already configured the vulnerable app as a protected site, so the professor can immediately see the WAF in action."

### Option B: Show Manual Integration from the UI

Navigate to:

`http://localhost:8005/sites`

Click:

`+ Add Website`

Use this configuration:

- Comment / Name: `Professor Demo App`
- Server Names: `localhost`
- Ports: `80`
- Upstreams: `http://127.0.0.1:8090`
- Site Enabled: `On`
- Detection Mode: `Strict`

Keep these off for the main demo unless specifically asked:

- CAPTCHA
- Auth Gate
- Dynamic HTML/JS Challenge

Action:

Click `Save`, then `Test Upstream`.

Explain:

"The WAF now knows that any request coming to port `8085` for this host should be inspected and then forwarded to the upstream application on `8090` only if it is safe."

### Option C: Fast Helper Script

If needed, use the helper script:

```powershell
cd "C:\Users\hetul\Documents\Arduino\dcn ss\integrated project\pmdemo\demo_target"
python register_site.py
```

Explain:

"This helper quickly inserts the demo target into the WAF database for faster setup."

## Phase 4: Live Attack Demonstrations

This is the most important part of the presentation. You must prove that Digi Save WAF actually protects the application.

## IMPORTANT FOR LIVE DEMO

You can now use the browser-friendly route directly:

- `http://localhost:8085`

You can also use PowerShell if you want a cleaner technical demo:

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/"
```

Best practice:

- Show the vulnerable site directly on `8090`
- Then show the same request through the WAF on `8085`
- Then immediately open Detection Logs

### Test 1: Clean Traffic

Action:

Open:

- `http://127.0.0.1:8090`
- `http://localhost:8085`

Expected Result:

- Both pages load the same vulnerable demo site home page.

Explain:

"This proves that normal traffic passes through the WAF correctly. The WAF does not break regular application access."

### Test 2: SQL Injection Attack

Action:

First show the vulnerable app directly:

```powershell
Invoke-WebRequest "http://127.0.0.1:8090/user-lookup?id=1%20UNION%20SELECT%201,username,password,email,role%20FROM%20users"
```

Then send the same payload through the WAF:

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/user-lookup?id=1%20UNION%20SELECT%201,username,password,email,role%20FROM%20users"
```

Expected Result:

- Direct request succeeds or exposes sensitive data.
- WAF request is blocked with `403 Forbidden`.

Explain:

"The direct application is vulnerable, but when the same payload passes through Digi Save WAF, the SQL injection pattern is detected and blocked before it reaches the real application."

### Test 3: Cross-Site Scripting (XSS)

Action:

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

Expected Result:

- Blocked with `403 Forbidden`.

Explain:

"The WAF identifies the malicious JavaScript payload and prevents reflected XSS from reaching the application response."

### Test 4: Path Traversal / Local File Access

Action:

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/file?name=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
```

Expected Result:

- Blocked with `403 Forbidden`.

Explain:

"The request tries to read a system file using path traversal. Digi Save WAF detects the suspicious path pattern and blocks the request."

### Test 5: Sensitive File Access

Action:

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/.env"
```

Expected Result:

- Blocked with `403 Forbidden`.

Explain:

"The WAF recognizes attempts to access sensitive files like `.env` and blocks that request before it reaches the backend."

### Optional Extra Test: Scanner Detection

Action:

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/" -Headers @{"User-Agent"="sqlmap/1.5.8#dev (http://sqlmap.org)"}
```

Expected Result:

- Blocked with `403 Forbidden`.

Explain:

"This shows bot and scanner detection. The WAF can recognize suspicious tool signatures such as `sqlmap` and deny that traffic."

## TIP

Optional "God Mode" presentation:

- Keep `http://localhost:8005/dashboard` open on one side of the screen.
- Keep `http://localhost:8005/logs` ready in another tab.
- Run the attack commands from PowerShell on the other side.

Explain:

"This creates a live SOC-style demo where the professor can see the blocked attack and then immediately see the log entry and dashboard visibility."

## Phase 5: Conclusion and Log Review

After demonstrating the attacks, navigate to:

`http://localhost:8005/logs`

Action:

- Show the newest blocked events.
- Point to the blocked badge, rule ID, source IP, path, and timestamp.

Explain:

"Digi Save WAF not only blocks the attack, but also records forensic evidence. The logs store the request details, rule triggered, source IP, action taken, and timestamp for later analysis."

Then return to:

`http://localhost:8005/dashboard`

Explain:

"The dashboard gives the administrator a quick security summary of how many attacks were detected and blocked."

## Best Final Closing Line

Use this to finish:

"Digi Save WAF is a complete reverse-proxy web application firewall that combines live request inspection, configurable protection, database-backed management, and forensic logging in one practical cybersecurity project."

## Fast Backup Plan If Time Is Short

If your professor asks for a very short demo, do only this:

1. Start `demo_target/app.py`
2. Start `backend/main.py`
3. Log in to `http://localhost:8005`
4. Open `http://localhost:8085`
5. Run one direct SQL injection request on `8090`
6. Run the same request through `8085`
7. Show `Detection Logs`

That short flow is enough to prove the project works.

## Troubleshooting Before Presentation

If `http://localhost:8085` does not load:

- Make sure `demo_target/app.py` is running on `8090`
- Make sure `backend/main.py` is running on `8005`
- Open `Sites` and confirm the demo site points to `http://127.0.0.1:8090`

If login fails:

- Use your latest username and password from Settings
- If needed, reset from the database or seeded defaults

If logs do not update immediately:

- Refresh the Logs page once
- Re-run the blocked request one more time
