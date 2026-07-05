//! `RuleTarget` + `Pattern` + `Rule` — rule engine.

use crate::action::Action;
use crate::request::Request;

/// Target field for rule matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleTarget {
    Uri,
    Body,
    Header(String),
    Method,
    AnyField,
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
    pub(crate) fn matches(&self, input: &str) -> bool {
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

impl Rule {
    pub(crate) fn check(&self, request: &Request) -> bool {
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
