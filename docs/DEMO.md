# Demo Guide

## Goal

Show that the same malicious payload succeeds against the vulnerable application directly, but is blocked when it goes through Digi Save WAF.

## Start the Services

### Terminal 1

```powershell
cd "C:\path\to\digi-save-waf\backend"
python main.py
```

### Terminal 2

```powershell
cd "C:\path\to\digi-save-waf\demo_target"
python app.py
```

## Browser Tabs To Keep Open

- `http://localhost:8005/dashboard`
- `http://localhost:8005/logs`
- `http://localhost:8085`
- `http://127.0.0.1:8090`

## Demo 1: Clean Traffic

Open:

- `http://127.0.0.1:8090`
- `http://localhost:8085`

Expected:

- both pages load successfully

What this proves:

- the proxy path works
- clean traffic is not broken by the WAF

## Demo 2: SQL Injection

### Direct request to vulnerable app

```powershell
Invoke-WebRequest "http://127.0.0.1:8090/user-lookup?id=1%20UNION%20SELECT%201,username,password,email,role%20FROM%20users"
```

### Same request through the WAF

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/user-lookup?id=1%20UNION%20SELECT%201,username,password,email,role%20FROM%20users"
```

Expected:

- direct request succeeds
- WAF request returns `403`

## Demo 3: XSS

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

Expected:

- blocked with `403`

## Demo 4: Path Traversal

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/file?name=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
```

Expected:

- blocked with `403`

## Demo 5: Sensitive File Access

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/.env"
```

Expected:

- blocked with `403`

## Optional Scanner Demo

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/" -Headers @{"User-Agent"="sqlmap/1.5.8#dev (http://sqlmap.org)"}
```

Expected:

- blocked with `403`

## What To Show In Logs

After a blocked request:

1. open `http://localhost:8005/logs`
2. show the newest blocked row
3. point to the rule ID, source IP, request path, action, and timestamp

## Best Short Demo Flow

If you only have two minutes:

1. show `8090` direct app
2. show `8085` protected app
3. run one SQL injection request on `8090`
4. run the same SQL injection request on `8085`
5. open logs

