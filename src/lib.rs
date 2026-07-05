#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions, clippy::struct_excessive_bools)]

//! ALICE-WAF: Web Application Firewall
//!
//! Pure Rust WAF with rule engine, SQL injection detection, XSS detection,
//! IP allowlist/blocklist, rate limiting, request inspection, and OWASP patterns.

pub mod action;
pub mod detection;
pub mod inspector;
pub mod ip_filter;
pub mod prelude;
pub mod rate_limit;
pub mod request;
pub mod rule;
pub mod waf;

#[cfg(test)]
mod integration_tests;

// Backward-compat re-exports.
pub use crate::action::*;
pub use crate::detection::*;
pub use crate::inspector::*;
pub use crate::ip_filter::*;
pub use crate::rate_limit::*;
pub use crate::request::*;
pub use crate::rule::*;
pub use crate::waf::*;
