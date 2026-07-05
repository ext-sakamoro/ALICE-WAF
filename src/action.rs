//! `Action` + `Verdict` — WAF decision types.

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
