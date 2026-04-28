# Digi Save WAF Professor Demo Walkthrough

This guide is designed for your final-semester project presentation. It is written for a safe, authorized demo against the included local vulnerable target only.

## Safety Rule

Use the attack demonstrations only against:

- The included local demo target on your own machine
- A lab environment you own or control
- A website where you have explicit permission to test

Do not use these steps against random public websites.

## Demo Goal

Show your professor four things in sequence:

1. The architecture and idea of the project
2. The management console and configuration flow
3. The database and stored records
4. A live attack demo where the vulnerable app is exposed directly and then protected by Digi Save WAF

## Demo Environment

Open three terminals before the presentation starts.

### Terminal 1: Management server

```powershell
cd "C:\Users\hetul\Documents\Arduino\dcn ss\integrated project\pmdemo\backend"
python main.py
```

### Terminal 2: Vulnerable demo target

```powershell
cd "C:\Users\hetul\Documents\Arduino\dcn ss\integrated project\pmdemo\demo_target"
python app.py
```

### Terminal 3: Optional helper terminal

Use this for database checks and attack requests.

## Browser Tabs To Keep Ready

- Management UI: `http://localhost:8005`
- Optional direct vulnerable app: `http://127.0.0.1:8090`
- Optional WAF-routed site if you map hosts: `http://demo.local:8085`

## Step 1: Log In

- Open the management UI.
- Login with your configured credentials.
- If you never changed them, the default is `admin / admin123`.

## Step 2: Show The Protected Site Configuration

Go to `Protected Sites`.

If the demo site is not already present, add it with:

- Comment / Name: `Vulnerable Demo App`
- Server Names: `demo.local`
- Ports: `80`
- Upstreams: `http://127.0.0.1:8090`
- Site Enabled: `On`
- Detection Mode: `Strict` for a dramatic demo, or `Balance` for the normal mode

Optional:

- Enable `CAPTCHA` to show anti-bot protection
- Enable `Auth Gate` to show password-based pre-access control
- Enable `Dynamic HTML/JS` to show browser verification

Click `Save`, then `Test Upstream` to show that the real website is reachable.

## Step 3: Explain How Traffic Flows

Say this while pointing at the UI or your architecture diagram:

1. A user request first arrives at the WAF proxy on port `8085`.
2. The WAF checks rate limits, IP ACL rules, challenge gates, and detection modules.
3. If the request looks malicious, the WAF blocks it and logs the full event.
4. If the request is clean, the WAF forwards it to the real upstream website.
5. The management console on port `8005` reads data from SQLite and displays dashboard, logs, and settings.

## Step 4: Show The Database

You can show the SQLite file at:

`C:\Users\hetul\Documents\Arduino\dcn ss\integrated project\pmdemo\backend\data\digisave.db`

### Easiest way

Open it in DB Browser for SQLite if you have it.

Show these tables:

- `users`
- `websites`
- `policy_groups`
- `policy_rules`
- `detect_logs`
- `ip_acl`
- `options`

### Terminal-based fallback

Run this in the backend folder:

```powershell
python -c "import sqlite3; conn=sqlite3.connect('data/digisave.db'); print('USERS:', conn.execute('select id, username, is_enabled from users').fetchall()); print('SITES:', conn.execute('select id, comment, server_names, upstreams, is_enabled from websites').fetchall()); print('LOG COUNT:', conn.execute('select count(*) from detect_logs').fetchone())"
```

Explain:

- `users` stores admin accounts
- `websites` stores protected site routing and protection mode
- `policy_groups` stores per-module detection behavior
- `detect_logs` stores blocked or observed attacks
- `ip_acl` stores allow/block IP rules
- `options` stores settings like SSL paths and retention values

## Step 5: Show The Direct Vulnerable Application

Before using the WAF, show that the demo target is vulnerable.

Open:

- `http://127.0.0.1:8090/user-lookup`
- `http://127.0.0.1:8090/search`
- `http://127.0.0.1:8090/ping`

Then demonstrate one or two direct attacks.

### Direct SQL injection

Use the browser or this request:

```powershell
Invoke-WebRequest "http://127.0.0.1:8090/user-lookup?id=1%20UNION%20SELECT%201,username,password,email,role%20FROM%20users"
```

Expected result:

- Sensitive rows are shown
- This proves the target app is intentionally vulnerable

### Direct XSS

```powershell
Invoke-WebRequest "http://127.0.0.1:8090/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

Expected result:

- The payload is reflected by the page

### Direct command injection

```powershell
Invoke-WebRequest "http://127.0.0.1:8090/ping?ip=127.0.0.1%20%26%20whoami"
```

Expected result:

- The command output is returned by the vulnerable app

## Step 6: Show The Same Attacks Through Digi Save WAF

To route the request through the WAF, you need the host header to match `demo.local`.

### Option A: Best browser demo

Add this to your Windows hosts file before the presentation:

```text
127.0.0.1 demo.local
```

Then use:

- `http://demo.local:8085`

### Option B: PowerShell demo without changing hosts

Use `Invoke-WebRequest` with a `Host` header.

### SQL injection through WAF

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/user-lookup?id=1%20UNION%20SELECT%201,username,password,email,role%20FROM%20users" -Headers @{Host="demo.local"}
```

Expected result:

- HTTP `403`
- WAF block page
- New log entry in Detection Logs

### XSS through WAF

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/search?q=%3Cscript%3Ealert(1)%3C/script%3E" -Headers @{Host="demo.local"}
```

Expected result:

- HTTP `403`
- XSS attempt blocked

### Command injection through WAF

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/ping?ip=127.0.0.1%20%26%20whoami" -Headers @{Host="demo.local"}
```

Expected result:

- HTTP `403`
- Command injection blocked

### Path traversal through WAF

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/file?name=..%2F..%2F..%2Fetc%2Fpasswd" -Headers @{Host="demo.local"}
```

Expected result:

- HTTP `403`
- File access blocked

### Sensitive file access through WAF

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/.env" -Headers @{Host="demo.local"}
```

Expected result:

- HTTP `403`
- Sensitive file access blocked

## Step 7: Show Logs And Dashboard

Immediately after each blocked request:

- Open `Detection Logs`
- Filter by attack type if needed
- Open the newest event
- Show:
  - Source IP
  - URL path
  - payload
  - module
  - action
  - timestamp

Then open the dashboard and show:

- Total requests
- Attacks detected
- Attacks blocked
- Attack type distribution
- Top attacker IPs

## Step 8: Show Optional Protection Gates

If you enabled extra gates for the demo site, show one of them.

### CAPTCHA

- Turn on CAPTCHA in the site config
- Visit the protected site through the WAF
- Show that the user must solve the challenge before the website opens

### Auth Gate

- Set the global Auth Gate password in `Settings -> Security`
- Enable `Auth Gate` for the demo site
- Visit the WAF site
- Show that the user needs the password before accessing the app

### Dynamic Browser Challenge

- Enable `Dynamic HTML/JS`
- Visit the WAF site
- Show the temporary browser verification page

## Step 9: Suggested Presentation Order

For an 8 to 12 minute viva, this order works well:

1. Problem statement and why web applications need a WAF
2. Architecture and technology stack
3. Dashboard and site management
4. Database tables
5. Direct attack on vulnerable app
6. Same attack through Digi Save WAF
7. Detection logs and blocked event
8. Conclusion, limitations, and future scope

## What To Say During The Live Attack

Use a simple line like this:

"First I am sending the request directly to the vulnerable application, so the exploit succeeds. Now I am sending the same payload through Digi Save WAF. The proxy inspects the request, identifies the attack pattern, blocks the request, and creates a forensic log entry for the administrator."

## If Something Goes Wrong

- If the WAF shows `No route`, check that the `Host` header or `demo.local` mapping is correct.
- If the site does not update immediately after editing, wait a few seconds and retry. The cache now refreshes quickly and also invalidates on save.
- If login fails, reset credentials using the instructions in [`PROJECT_GUIDE.md`](C:/Users/hetul/Documents/Arduino/dcn%20ss/integrated%20project/pmdemo/PROJECT_GUIDE.md).

