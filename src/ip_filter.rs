//! `IpFilter` — IP allow/block list.

use std::net::IpAddr;

use crate::action::Action;

/// IP-based allow/block list.
#[derive(Debug, Clone, Default)]
pub struct IpFilter {
    pub(crate) allowlist: Vec<IpAddr>,
    pub(crate) blocklist: Vec<IpAddr>,
    /// If true, only IPs in the allowlist are permitted.
    pub(crate) allowlist_only: bool,
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
        if self.blocklist.contains(ip) {
            return Action::Block;
        }
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
