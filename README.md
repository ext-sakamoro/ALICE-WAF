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

`AGPL-3.0 OR LicenseRef-Commercial` — dual-licensed. Pick either.

| Option | Terms | Use it when |
|--------|-------|-------------|
| **AGPL-3.0** | [LICENSE-AGPL](LICENSE-AGPL) — free, no reporting obligation | Your project is itself AGPL-compatible open source, or you are only using it internally |
| **Commercial License** | [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) — paid, removes the copyleft | Closed-source product, proprietary SaaS, edge / firmware distribution, plugin redistribution, or a platform NDA that forbids source disclosure |

AGPL is a strong copyleft: a product, firmware image, or service that links
`alice-waf` and is distributed or served to users must be released under the AGPL
as well. That is intentional for the open ecosystem, and the Commercial
License exists for the cases where it is not something you are able to do.

Commercial licence enquiries: <contact@extoria.co.jp>
