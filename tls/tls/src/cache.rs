// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! In-memory read-only cache for hostname → Mapping.
//!
//! Populated only through explicit calls (service bootstrap or tests);
//! cache misses fall through to DB-based domain-pattern deduction in
//! `HostContextResolver` (see `context.rs`).

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use sentin8_tls_contracts::Mapping;
use serde::Serialize;

/// In-memory hostname → mapping cache (thread-safe, read-only consumer).
#[derive(Clone)]
pub struct MappingCache {
    inner: Arc<RwLock<HashMap<String, Arc<Mapping>>>>,
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

    /// Look up a mapping by hostname.
    pub fn get(&self, hostname: &str) -> Option<Arc<Mapping>> {
        let result = self.inner.read().get(hostname).cloned();
        let mut stats = self.stats.write();
        match &result {
            Some(_) => stats.hits += 1,
            None => stats.misses += 1,
        }
        result
    }

    /// Insert or replace a mapping in the cache.
    pub fn set(&self, hostname: &str, mapping: Mapping) {
        self.inner
            .write()
            .insert(hostname.to_string(), Arc::new(mapping));
    }

    /// Delete a mapping from the cache.
    pub fn delete(&self, hostname: &str) {
        self.inner.write().remove(hostname);
    }

    /// Load all mappings into the cache (replaces all entries).
    pub fn load_all(&self, mappings: Vec<Mapping>) {
        let mut inner = self.inner.write();
        inner.clear();
        for m in mappings {
            inner.insert(m.hostname.clone(), Arc::new(m));
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
