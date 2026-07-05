//! `RequestInspector` — HTTP request property validation.

use std::collections::HashMap;

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
            max_body_size: 1_048_576,
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
