// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # Rate limiting
//!
//! Token-bucket rate limiter for all public Sentin8 endpoints. Each `client_id`
//! (typically the Auth subject or the client IP for unauthenticated
//! endpoints) gets an independent in-memory bucket with a configurable
//! `requests_per_minute` and `burst` capacity.
//!
//! The bucket is refilled at a steady rate of `requests_per_minute / 60`
//! tokens per second. `burst` is the maximum bucket size, allowing short
//! spikes. A request that would drain the bucket below zero is rejected.
//!
//! This implementation is suitable for single-node deployments. For
//! multi-node deployments, back the limiter with a shared store.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Configuration for a rate-limited endpoint group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Maximum sustained requests per minute per `client_id`.
    pub requests_per_minute: u32,
    /// Maximum burst size (bucket capacity).
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            burst: 10,
        }
    }
}

/// An in-memory token-bucket rate limiter.
///
/// Cloning a `RateLimiter` shares the underlying state (it wraps an `Arc`),
/// so it can be cheaply cloned into middleware state.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    inner: std::sync::Arc<Mutex<HashMap<String, Bucket>>>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Create a new empty limiter.
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check whether `client_id` may make a request under `config`.
    ///
    /// Returns `Ok(())` if allowed (one token consumed), or
    /// `Err(message)` if the bucket is empty. The error message is suitable
    /// for a 429 response body.
    pub fn check(&self, client_id: &str, config: &RateLimitConfig) -> Result<(), String> {
        let mut buckets = self.inner.lock().expect("rate limiter mutex poisoned");
        let now = Instant::now();
        let refill_rate = config.requests_per_minute as f64 / 60.0_f64;
        let capacity = config.burst as f64;

        let bucket = buckets.entry(client_id.to_string()).or_insert(Bucket {
            tokens: capacity,
            last_refill: now,
        });

        // Refill based on elapsed time.
        let elapsed = now.duration_since(bucket.last_refill);
        bucket.tokens = (bucket.tokens + elapsed.as_secs_f64() * refill_rate).min(capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0_f64 {
            bucket.tokens -= 1.0_f64;
            Ok(())
        } else {
            // Compute the retry-after in whole seconds.
            let needed = 1.0_f64 - bucket.tokens;
            let secs = (needed / refill_rate).ceil() as u64;
            Err(format!(
                "rate limit exceeded for {client_id}; retry after {secs}s"
            ))
        }
    }

    /// Reset the bucket for `client_id` (use in tests).
    pub fn reset(&self, client_id: &str) {
        let mut buckets = self.inner.lock().expect("rate limiter mutex poisoned");
        buckets.remove(client_id);
    }

    /// Current token count for `client_id` (for tests/observability).
    pub fn tokens(&self, client_id: &str, config: &RateLimitConfig) -> f64 {
        let mut buckets = self.inner.lock().expect("rate limiter mutex poisoned");
        let now = Instant::now();
        let refill_rate = config.requests_per_minute as f64 / 60.0_f64;
        let capacity = config.burst as f64;
        let bucket = buckets.entry(client_id.to_string()).or_insert(Bucket {
            tokens: capacity,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill);
        bucket.tokens = (bucket.tokens + elapsed.as_secs_f64() * refill_rate).min(capacity);
        bucket.last_refill = now;
        bucket.tokens
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function: check the rate limit for `client_id` against
/// `config` using a process-global limiter.
///
/// For per-endpoint-group limiters, construct a `RateLimiter` in your
/// service's shared state and call `.check()` directly.
pub fn check_rate_limit(
    limiter: &RateLimiter,
    client_id: &str,
    config: &RateLimitConfig,
) -> Result<(), String> {
    limiter.check(client_id, config)
}

/// Compute the retry-after duration for a bucket that is currently empty
/// under `config`. Returns `None` if the bucket is not empty.
pub fn retry_after(
    client_id: &str,
    limiter: &RateLimiter,
    config: &RateLimitConfig,
) -> Option<Duration> {
    let tokens = limiter.tokens(client_id, config);
    if tokens >= 1.0_f64 {
        return None;
    }
    let needed = 1.0_f64 - tokens;
    let refill_rate = config.requests_per_minute as f64 / 60.0_f64;
    if refill_rate <= 0.0_f64 {
        return Some(Duration::from_secs(60));
    }
    let secs = (needed / refill_rate).ceil() as u64;
    Some(Duration::from_secs(secs.max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(rpm: u32, burst: u32) -> RateLimitConfig {
        RateLimitConfig {
            requests_per_minute: rpm,
            burst,
        }
    }

    #[test]
    fn allows_burst_then_rejects() {
        let limiter = RateLimiter::new();
        let c = cfg(60, 3); // 1/sec, burst 3
        assert!(limiter.check("a", &c).is_ok());
        assert!(limiter.check("a", &c).is_ok());
        assert!(limiter.check("a", &c).is_ok());
        assert!(limiter.check("a", &c).is_err(), "4th should be rejected");
    }

    #[test]
    fn isolates_clients() {
        let limiter = RateLimiter::new();
        let c = cfg(60, 1);
        assert!(limiter.check("a", &c).is_ok());
        assert!(limiter.check("a", &c).is_err());
        assert!(
            limiter.check("b", &c).is_ok(),
            "different client has own bucket"
        );
    }

    #[test]
    fn refills_over_time() {
        let limiter = RateLimiter::new();
        let c = cfg(60, 1); // 1/sec
        assert!(limiter.check("a", &c).is_ok());
        assert!(limiter.check("a", &c).is_err());
        // Simulate time passing by manipulating the bucket directly.
        {
            let mut buckets = limiter.inner.lock().unwrap();
            let b = buckets.get_mut("a").unwrap();
            b.last_refill -= Duration::from_secs(2);
        }
        assert!(limiter.check("a", &c).is_ok(), "should refill after 2s");
    }

    #[test]
    fn check_rate_limit_helper_works() {
        let limiter = RateLimiter::new();
        let c = cfg(120, 5);
        assert!(check_rate_limit(&limiter, "client1", &c).is_ok());
    }

    #[test]
    fn retry_after_returns_some_when_empty() {
        let limiter = RateLimiter::new();
        let c = cfg(60, 1);
        assert!(limiter.check("a", &c).is_ok());
        let ra = retry_after("a", &limiter, &c);
        assert!(ra.is_some(), "should suggest a retry-after");
        let d = ra.unwrap();
        assert!(d.as_secs() >= 1);
    }

    #[test]
    fn retry_after_returns_none_when_tokens_available() {
        let limiter = RateLimiter::new();
        let c = cfg(60, 5);
        assert!(retry_after("a", &limiter, &c).is_none());
    }

    #[test]
    fn reset_clears_bucket() {
        let limiter = RateLimiter::new();
        let c = cfg(60, 1);
        assert!(limiter.check("a", &c).is_ok());
        assert!(limiter.check("a", &c).is_err());
        limiter.reset("a");
        assert!(limiter.check("a", &c).is_ok(), "reset should allow again");
    }

    #[test]
    fn default_config_is_reasonable() {
        let c = RateLimitConfig::default();
        assert_eq!(c.requests_per_minute, 60);
        assert_eq!(c.burst, 10);
    }

    #[test]
    fn tokens_reflects_state() {
        let limiter = RateLimiter::new();
        let c = cfg(60, 5);
        assert!((limiter.tokens("a", &c) - 5.0_f64).abs() < 0.01);
        limiter.check("a", &c).unwrap();
        assert!((limiter.tokens("a", &c) - 4.0_f64).abs() < 0.01);
    }

    #[test]
    fn cloned_limiters_share_state() {
        let limiter = RateLimiter::new();
        let limiter2 = limiter.clone();
        let c = cfg(60, 1);
        assert!(limiter.check("a", &c).is_ok());
        assert!(limiter2.check("a", &c).is_err(), "clone shares state");
    }

    #[test]
    fn error_message_mentions_client_and_retry() {
        let limiter = RateLimiter::new();
        let c = cfg(60, 1);
        limiter.check("client-x", &c).unwrap();
        let err = limiter.check("client-x", &c).unwrap_err();
        assert!(err.contains("client-x"));
        assert!(err.contains("retry"));
    }
}
