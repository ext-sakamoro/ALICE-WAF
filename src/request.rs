//! `Request` — incoming HTTP request.

use std::collections::HashMap;
use std::net::IpAddr;

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
