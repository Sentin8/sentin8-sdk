// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-idempotency
//!
//! Idempotency key store interface for Sentin8 services.
//!
//! Money-movement and state-changing operations accept an `Idempotency-Key`
//! header. If the same key is presented twice, the original result is
//! returned instead of executing the operation a second time.
//!
//! The crate defines the store contract (`IdempotencyStore`) and ships a
//! no-op implementation; services with durable idempotency needs back the
//! trait with their own store (e.g. a Valkey or PostgreSQL implementation).

#![deny(missing_docs)]
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// The idempotency key header name.
pub const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";

/// A stored idempotency record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    /// The idempotency key exactly as presented by the caller.
    pub key: String,
    /// HTTP status code of the original response.
    pub status_code: u16,
    /// Serialized body of the original response.
    pub body: serde_json::Value,
}

/// The idempotency key store contract.
#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Try to claim a key. Returns `Ok(record)` if the key was previously
    /// stored (caller should return the cached response), or `Err(())` if
    /// the key is new (caller should execute the operation and store the
    /// result).
    async fn get_or_claim(&self, key: &str) -> Result<Option<IdempotencyRecord>, StoreError>;

    /// Store the result of an operation for a key.
    async fn store(&self, key: &str, record: IdempotencyRecord) -> Result<(), StoreError>;
}

#[derive(Debug, thiserror::Error)]
/// Store failures surfaced to the caller.
pub enum StoreError {
    /// The backing store failed (connection, serialization, timeout).
    #[error("idempotency store error: {0}")]
    Backend(String),
}

/// A no-op store: every key is treated as new and nothing is persisted.
///
/// Used by services that do not need idempotency (or handle it elsewhere);
/// keeps the middleware wiring uniform across services.
pub struct NoopIdempotencyStore;

#[async_trait]
impl IdempotencyStore for NoopIdempotencyStore {
    async fn get_or_claim(&self, _key: &str) -> Result<Option<IdempotencyRecord>, StoreError> {
        Ok(None)
    }
    async fn store(&self, _key: &str, _record: IdempotencyRecord) -> Result<(), StoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_store_always_new() {
        let store = NoopIdempotencyStore;
        assert!(store.get_or_claim("k1").await.unwrap().is_none());
    }
}
