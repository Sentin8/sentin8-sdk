// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! In-memory read-only cache for hostname → Mapping.
//!
//! Populated only through explicit calls (service bootstrap or tests);
//! cache misses fall through to the Sys owner-API resolution in
//! `HostContextResolver` (see `context.rs`). Tenant-plane entries carry
//! an insert timestamp and expire after the host-context TTL
//! (README §6): a first touch that raced an env
//! provisioning cannot pin a tenant hostname to a stale mapping for the
//! process lifetime.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use sentin8_tls_contracts::Mapping;
use serde::Serialize;

/// One cached mapping with its insert time (the TTL policy itself is
/// the caller's - see [`MappingCache::get_with_ttl`]).
struct Entry {
    mapping: Arc<Mapping>,
    inserted_at: Instant,
}

/// In-memory hostname → mapping cache (thread-safe, read-only consumer).
#[derive(Clone)]
pub struct MappingCache {
    inner: Arc<RwLock<HashMap<String, Entry>>>,
    stats: Arc<RwLock<CacheStats>>,
}

/// Counters and current size for a `MappingCache`.
#[derive(Debug, Default, Clone, Serialize)]
pub struct CacheStats {
    /// Number of mappings currently held by the cache.
    pub size: usize,
    /// Successful `get` lookups since cache creation.
    pub hits: u64,
    /// Failed `get` lookups since cache creation.
    pub misses: u64,
}

impl MappingCache {
    /// Create an empty cache with zeroed statistics.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    /// Look up a mapping by hostname with NO expiry (the boot-seeded /
    /// explicitly-loaded plane, and tests that pin time).
    pub fn get(&self, hostname: &str) -> Option<Arc<Mapping>> {
        let result = self
            .inner
            .read()
            .get(hostname)
            .map(|e| Arc::clone(&e.mapping));
        let mut stats = self.stats.write();
        match &result {
            Some(_) => stats.hits += 1,
            None => stats.misses += 1,
        }
        result
    }

    /// Look up a mapping by hostname under a TTL: an
    /// entry older than `ttl` is lazily EVICTED (removed, counted as a
    /// miss) so a stale tenant mapping never resurrects - the caller's
    /// miss path re-resolves through the owner API and re-caches fresh.
    /// `Some(Duration::ZERO)` disables expiry (the test pin).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use sentin8_tls::MappingCache;
    /// use sentin8_tls_contracts::Mapping;
    /// use uuid::Uuid;
    ///
    /// let cache = MappingCache::new();
    /// cache.set("auth.tenant.acme.dev", Mapping {
    ///     id: Uuid::new_v4(),
    ///     hostname: "auth.tenant.acme.dev".into(),
    ///     service: "sentin8:auth".into(),
    ///     org_id: Uuid::new_v4(),
    ///     env_id: Uuid::new_v4(),
    ///     application_id: None,
    ///     backend_url: None,
    ///     created_at: Default::default(),
    ///     updated_at: Default::default(),
    /// });
    /// // A zero TTL never expires (the test pin).
    /// assert!(cache
    ///     .get_with_ttl("auth.tenant.acme.dev", Some(Duration::ZERO))
    ///     .is_some());
    /// // The no-TTL lookup still sees the entry.
    /// assert!(cache.get("auth.tenant.acme.dev").is_some());
    /// ```
    pub fn get_with_ttl(&self, hostname: &str, ttl: Option<Duration>) -> Option<Arc<Mapping>> {
        let Some(ttl) = ttl else {
            return self.get(hostname);
        };
        if ttl.is_zero() {
            return self.get(hostname);
        }
        let expired = self
            .inner
            .read()
            .get(hostname)
            .is_some_and(|e| e.inserted_at.elapsed() > ttl);
        if expired {
            self.inner.write().remove(hostname);
        }
        let result = self
            .inner
            .read()
            .get(hostname)
            .map(|e| Arc::clone(&e.mapping));
        let mut stats = self.stats.write();
        match &result {
            Some(_) => stats.hits += 1,
            None => stats.misses += 1,
        }
        result
    }

    /// Insert or replace a mapping in the cache.
    pub fn set(&self, hostname: &str, mapping: Mapping) {
        self.inner.write().insert(
            hostname.to_string(),
            Entry {
                mapping: Arc::new(mapping),
                inserted_at: Instant::now(),
            },
        );
    }

    /// Delete a mapping from the cache.
    pub fn delete(&self, hostname: &str) {
        self.inner.write().remove(hostname);
    }

    /// Load all mappings into the cache (replaces all entries).
    pub fn load_all(&self, mappings: Vec<Mapping>) {
        let mut inner = self.inner.write();
        inner.clear();
        let now = Instant::now();
        for m in mappings {
            inner.insert(
                m.hostname.clone(),
                Entry {
                    mapping: Arc::new(m),
                    inserted_at: now,
                },
            );
        }
        let mut stats = self.stats.write();
        stats.size = inner.len();
    }

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        let mut stats = self.stats.write();
        stats.size = self.inner.read().len();
        stats.clone()
    }

    /// Get all hostnames currently in the cache.
    pub fn all_hostnames(&self) -> Vec<String> {
        self.inner.read().keys().cloned().collect()
    }

    /// Get the count of cached mappings.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Is the cache empty?
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

impl Default for MappingCache {
    fn default() -> Self {
        Self::new()
    }
}
