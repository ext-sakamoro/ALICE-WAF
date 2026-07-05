//! `RateLimiter` — token-bucket rate limiter.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Token-bucket rate limiter keyed by IP address.
pub struct RateLimiter {
    max_tokens: u32,
    window: Duration,
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
