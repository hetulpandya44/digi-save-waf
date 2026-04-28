# Roadmap

## Current State

Digi Save WAF is a strong academic and portfolio project with:

- live reverse-proxy traffic inspection
- modular web attack detection
- SQLite-backed management and forensic logs
- demo-ready vulnerable target application
- admin dashboard, rules, settings, and site configuration

## Next Improvements

### Platform

- restore GitHub Actions after enabling `workflow` token scope
- add containerized end-to-end integration tests
- add sample environment variables file

### Security

- Redis-backed distributed rate limiting
- stronger upstream TLS configuration management
- webhook or SIEM alert integrations
- role-based multi-user administration

### Product Experience

- richer charts and filtering in logs
- cleaner onboarding wizard for new protected sites
- better export/report generation
- more polished mobile admin UI support

### Engineering

- PostgreSQL backend option for larger deployments
- benchmark suite for proxy throughput
- clearer typed schemas for API payloads
- expanded automated regression coverage for gates and proxy forwarding

## Long-Term Direction

Turn Digi Save WAF from a project-grade defensive system into a more production-oriented platform with stronger automation, deployment support, and extensibility.

