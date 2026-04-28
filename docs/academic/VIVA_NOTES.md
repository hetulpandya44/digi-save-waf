# Digi Save WAF Viva Notes

## 1. One-Minute Introduction

"Digi Save WAF is a self-hosted web application firewall that works as a reverse proxy. Instead of changing the protected application, my system sits in front of it, inspects each request, detects web attacks such as SQL injection and XSS, blocks malicious traffic, logs the event, and shows everything in a management dashboard. The project uses FastAPI, SQLite, JWT authentication, modular detection logic, and a full working admin panel."

## 2. Two-Minute Project Explanation

Use this structure:

1. Problem:
   Web applications are exposed to attacks like SQL injection, XSS, command injection, and path traversal.
2. Solution:
   Digi Save WAF sits between the user and the website as a reverse proxy.
3. Working:
   Every request reaches the WAF first, then gets checked against rate limiting, access control, challenge gates, and detection modules.
4. Action:
   Malicious traffic is blocked and logged; safe traffic is forwarded to the real website.
5. Management:
   The admin panel shows protected sites, attacks, rules, system settings, and statistics.

## 3. Main Innovation Points To Mention

- Reverse-proxy based WAF built end-to-end in Python
- Separate management plane and traffic-inspection plane
- Modular detection engine with multiple attack categories
- Local safe demo target for live proof
- Practical admin features such as MFA, IP ACL, CAPTCHA, Auth Gate, and site-wise modes

## 4. If The Professor Asks "Why FastAPI?"

Answer:

- FastAPI is lightweight and fast
- It supports async operations, which is useful for proxying and HTTP calls
- It makes API routing and data validation very clean
- It helped complete the project in an understandable and maintainable way

## 5. If The Professor Asks "Why SQLite?"

Answer:

- SQLite is file-based and easy to deploy
- No external DB server is needed
- It is good for a final-year project because setup is simple
- WAL mode gives enough concurrency for this demo scenario
- If scaled further, PostgreSQL would be the next logical upgrade

## 6. If The Professor Asks "How Does The WAF Decide To Block?"

Answer:

- Each request is converted into a structured request object
- The detection engine checks URL, query string, headers, and body
- Each module searches for malicious patterns relevant to its attack family
- If a module matches, it returns the attack type, risk level, and action
- The WAF blocks the request if the configured policy for that module and risk level says to deny it

## 7. If The Professor Asks "What Is Stored In The Database?"

Answer:

- Users and MFA state
- Protected website configuration
- Detection module configuration
- Custom WAF rules
- IP allow/block rules
- Attack logs and statistics
- Challenge session data
- Operational settings

## 8. If The Professor Asks "How Is Password Security Handled?"

Answer:

- Passwords are stored using bcrypt hashing
- JWT is used for authenticated admin sessions
- TOTP-based two-factor authentication is supported
- Username and password can be changed from the settings page

## 9. If The Professor Asks "What Are The Limitations?"

Answer:

- It is a strong academic prototype, not a full enterprise platform
- Signature-based detection can still have false positives or miss unknown attacks
- SQLite is not ideal for a large distributed deployment
- Multi-node clustering and enterprise-scale operations are future work

## 10. If The Professor Asks "What Is Future Scope?"

Answer:

- Better analytics and anomaly detection
- Distributed deployment
- Stronger enterprise integrations
- More advanced reporting and alerting
- Larger database backend and centralized logging

## 11. Good Closing Line

"The main value of Digi Save WAF is that it turns web security concepts into a full working defensive system. It not only detects attacks, but also manages sites, stores logs, supports admin controls, and demonstrates protection live against a vulnerable application."

