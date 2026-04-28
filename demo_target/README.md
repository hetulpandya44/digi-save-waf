# Vulnerable Demo Target Site

> **WARNING**: This application is **intentionally vulnerable**. It is used
> exclusively for testing and demonstrating Digi Save WAF's detection capabilities.
> **DO NOT deploy this in production.**

## Quick Start

```bash
cd demo_target
python app.py
```

The demo site starts on **http://127.0.0.1:8090**.

## Registering with Digi Save WAF

1. Open the WAF Management Console: http://localhost:8005
2. Navigate to **Protected Sites** and click **Add Site**.
3. Set **Server Name** to `localhost` or `demo.local` and **Upstream** to `http://127.0.0.1:8090`.
4. Save the configuration.

Now traffic to `http://localhost:8085` can be inspected by the WAF before reaching
the demo application. If you prefer explicit host-header testing, you can also use
the `demo.local` mapping.

## Vulnerabilities Included

| Type                    | Route        | Severity | Example Payload                                      |
|-------------------------|-------------|----------|------------------------------------------------------|
| SQL Injection           | /user-lookup | Critical | `?id=1 UNION SELECT 1,username,password,email,role FROM users` |
| Reflected XSS           | /search      | High     | `?q=<script>alert(1)</script>`                       |
| Stored XSS              | /comments    | High     | Post `<img src=x onerror=alert(1)>` as body          |
| OS Command Injection    | /ping        | Critical | `?ip=127.0.0.1 & whoami`                             |
| Path Traversal / LFI    | /file        | High     | `?name=../../../etc/passwd`                           |
| SSTI                    | /template    | Medium   | `?name={{7*7}}`                                      |
| Sensitive Data Exposure | /.env        | Medium   | Direct access exposes credentials                    |
