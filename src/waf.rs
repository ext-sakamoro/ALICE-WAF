//! `Waf` — main WAF engine.

use crate::action::{Action, Verdict};
use crate::detection::{
    detect_command_injection, detect_header_injection, detect_path_traversal, detect_sqli,
    detect_xss,
};
use crate::inspector::{ContentTypeCheck, RequestInspector};
use crate::ip_filter::IpFilter;
use crate::rate_limit::RateLimiter;
use crate::request::Request;
use crate::rule::Rule;

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
        if let Some(ip) = &request.source_ip {
            let ip_action = self.ip_filter.check(ip);
            if ip_action == Action::Block {
                return Verdict::block("ip-filter", "IP address is blocked");
            }
        }

        if let Some(ref limiter) = self.rate_limiter {
            if let Some(ip) = &request.source_ip {
                if !limiter.allow(ip) {
                    return Verdict::block("rate-limit", "Rate limit exceeded");
                }
            }
        }

        if !self.inspector.check_method(&request.method) {
            return Verdict::block("method-check", "HTTP method not allowed");
        }

        if !self.inspector.check_body_size(&request.body) {
            return Verdict::block("body-size", "Request body too large");
        }

        let missing = self.inspector.check_required_headers(&request.headers);
        if !missing.is_empty() {
            return Verdict::block(
                "required-headers",
                &format!("Missing required headers: {}", missing.join(", ")),
            );
        }

        match self.inspector.check_content_type(&request.headers) {
            ContentTypeCheck::Missing if !self.inspector.allowed_content_types.is_empty() => {
                return Verdict::block("content-type", "Missing Content-Type header");
            }
            ContentTypeCheck::Invalid(ct) => {
                return Verdict::block("content-type", &format!("Content-Type not allowed: {ct}"));
            }
            _ => {}
        }

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
