**English** | [日本語](README_JP.md)

# ALICE-WAF

Web Application Firewall for the A.L.I.C.E. ecosystem. Rule-based HTTP request inspection with SQL injection, XSS detection, IP filtering, and rate limiting in pure Rust.

## Features

- **Rule Engine** — Configurable rules with match conditions and actions (Block/Allow/Log)
- **SQL Injection Detection** — Pattern-based SQLi detection across URI, headers, and body
- **XSS Detection** — Script tag, event handler, and JavaScript URI pattern matching
- **IP Filtering** — Allowlist and blocklist with `IpAddr` support
- **Rate Limiting** — Per-IP request rate tracking with configurable time windows
- **Request Inspection** — Full HTTP request analysis (method, URI, headers, body, source IP)
- **OWASP Patterns** — Coverage of common OWASP Top 10 attack vectors

## Architecture

```
HTTP Request
  │
  ├── Request      — Method, URI, headers, body, source IP
  ├── RuleEngine   — Rule matching and verdict generation
  ├── SqliDetector — SQL injection pattern detection
  ├── XssDetector  — Cross-site scripting detection
  ├── IpFilter     — Allowlist / blocklist evaluation
  ├── RateLimiter  — Per-IP rate tracking
  └── Verdict      — Block / Allow / Log with reason
```

## Usage

```rust
use alice_waf::{Request, Verdict};

let req = Request::new("GET", "/api/users")
    .with_header("host", "example.com");
```

## License

AGPL-3.0
