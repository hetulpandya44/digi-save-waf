# Case Study

## Problem

Web applications are exposed to common attacks such as SQL injection, cross-site scripting, command injection, path traversal, and sensitive file leakage. Many academic projects explain these attacks, but fewer show a defensive system that actually sits in the traffic path and blocks them in real time.

## Goal

Build a practical, demo-ready Web Application Firewall that:

- protects a live upstream web application
- provides a management dashboard for rules and logs
- stores configuration and forensic evidence in a database
- supports a strong classroom or interview demonstration

## Solution

Digi Save WAF uses a reverse-proxy architecture:

- the client sends traffic to the WAF
- the WAF checks rate limits, ACL rules, and optional challenge gates
- the detection engine inspects the request
- the WAF either blocks or forwards the request

This structure lets one management interface control multiple protected sites.

## Engineering Decisions

### Why FastAPI

- clean routing
- async support
- fast development for a student project
- easy to use for both management APIs and proxy services

### Why SQLite

- no external database server required
- easy packaging for demos and portfolio review
- enough for configuration, logs, and statistics in a single-machine environment

### Why a Demo Target

- proves the difference between direct exposure and WAF protection
- makes demonstrations repeatable and safe
- turns the project from theory into an observable security system

## Security Features Included

- signature and pattern-based attack detection
- per-site protection modes
- IP allow/block rules
- rate limiting
- JWT admin auth
- bcrypt password hashing
- TOTP MFA
- local CAPTCHA and challenge gates
- forensic logging

## Challenges Solved During Final Polishing

- aligned site routing and demo host configuration
- fixed WAF proxy behavior so streamed responses remain stable
- prevented localhost demo traffic from being misclassified by the SSRF detector
- protected security-sensitive routes with authentication
- made the challenge flows same-origin for real usage
- normalized module configuration behavior across UI and detection logic

## What This Project Demonstrates

For recruiters, interviewers, or reviewers, this project shows:

- practical cybersecurity implementation
- backend system design
- reverse-proxy networking concepts
- authentication and secure settings management
- database-backed application design
- full-stack delivery from UI to runtime validation

## Limitations

- SQLite is ideal for demos, not large distributed deployments
- detection is rule-based rather than ML-based
- no horizontal cluster mode
- enterprise integrations are still limited

## Future Scope

- PostgreSQL-backed configuration
- Redis-backed distributed rate limiting
- webhook or SIEM integrations
- role-based multi-user admin
- more automated end-to-end security tests
