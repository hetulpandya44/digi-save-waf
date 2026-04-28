# Results and Validation

This document records the main verification results used for the public portfolio version of Digi Save WAF.

## Automated Test Result

Detection suite:

- `39/39` tests passing

Command:

```bash
cd backend
python tests/test_detection.py
```

## Runtime Validation

The following checks verify that the reverse proxy and detection flow behave correctly:

| Check | Expected | Result |
|---|---|---|
| Direct target homepage on `8090` | `200 OK` | Passed |
| Protected route homepage on `8085` | `200 OK` | Passed |
| SQL injection through WAF | `403 Forbidden` | Passed |
| XSS through WAF | `403 Forbidden` | Passed |
| Sensitive file access through WAF | `403 Forbidden` | Passed |
| Path traversal through WAF | `403 Forbidden` | Passed |

## Manual Demonstration Evidence

### Direct vulnerable SQL injection

```powershell
Invoke-WebRequest "http://127.0.0.1:8090/user-lookup?id=1%20UNION%20SELECT%201,username,password,email,role%20FROM%20users"
```

Observed:

- the vulnerable application processed the request successfully

### Same payload through Digi Save WAF

```powershell
Invoke-WebRequest "http://127.0.0.1:8085/user-lookup?id=1%20UNION%20SELECT%201,username,password,email,role%20FROM%20users"
```

Observed:

- the request was blocked by the WAF with `403`

## What These Results Show

- Digi Save WAF is not only a dashboard project
- it successfully proxies clean traffic
- it blocks malicious requests before they reach the upstream application
- it records attack events for the administrator

## Suggested Future Validation

For a stronger production-grade evolution, the next testing steps would be:

- integration tests for the full proxy lifecycle
- load testing with concurrent traffic
- regression tests for the challenge-gate flows
- containerized end-to-end tests in CI
