// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! JWKS caching with configurable TTL.
//!
//! Fetches the issuer's JSON Web Key Set from `jwks_uri` and caches it
//! for token verification (ID tokens, JARM response JWTs).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::discovery::{Jwk, JwkSet};
use crate::error::FapiError;

/// Cached JWKS with a configurable TTL.
#[derive(Clone)]
pub struct JwksCache {
    jwks_uri: String,
    http: reqwest::Client,
    ttl: Duration,
    inner: Arc<RwLock<Option<Cached>>>,
}

struct Cached {
    set: JwkSet,
    fetched_at: Instant,
}

impl JwksCache {
    pub fn new(jwks_uri: impl Into<String>, http: reqwest::Client, ttl: Duration) -> Self {
        Self {
            jwks_uri: jwks_uri.into(),
            http,
            ttl,
            inner: Arc::new(RwLock::new(None)),
        }
    }

    /// Return the cached JWKS, fetching if stale or missing.
    pub async fn get(&self) -> Result<JwkSet, FapiError> {
        {
            let cache = self.inner.read().await;
            if let Some(ref c) = *cache {
                if c.fetched_at.elapsed() < self.ttl {
                    return Ok(c.set.clone());
                }
            }
        }
        self.refresh().await
    }

    /// Force a re-fetch (used on kid-not-found verification failures).
    pub async fn refresh(&self) -> Result<JwkSet, FapiError> {
        let resp = self
            .http
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| FapiError::Jwks(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(FapiError::Jwks(format!("status {}", resp.status())));
        }
        let set: JwkSet = resp
            .json()
            .await
            .map_err(|e| FapiError::Jwks(e.to_string()))?;

        let mut cache = self.inner.write().await;
        *cache = Some(Cached {
            set: set.clone(),
            fetched_at: Instant::now(),
        });
        Ok(set)
    }

    /// Look up a key by `kid`, re-fetching once if not found (FAPI best practice).
    pub async fn find_key(&self, kid: &str) -> Result<Jwk, FapiError> {
        let set = self.get().await?;
        if let Some(k) = set.keys.iter().find(|k| k.kid.as_deref() == Some(kid)) {
            return Ok(k.clone());
        }
        // Re-fetch once on kid-not-found.
        let set = self.refresh().await?;
        set.keys
            .into_iter()
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or_else(|| FapiError::Jwks(format!("key '{}' not found", kid)))
    }
}
