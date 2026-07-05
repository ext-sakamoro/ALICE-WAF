//! Convenience re-export (= `use alice_waf::prelude::*;`).

pub use crate::action::{Action, Verdict};
pub use crate::detection::{
    detect_command_injection, detect_header_injection, detect_path_traversal, detect_sqli,
    detect_xss,
};
pub use crate::inspector::{ContentTypeCheck, RequestInspector};
pub use crate::ip_filter::IpFilter;
pub use crate::rate_limit::RateLimiter;
pub use crate::request::Request;
pub use crate::rule::{Pattern, Rule, RuleTarget};
pub use crate::waf::Waf;
