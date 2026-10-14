// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-workload-registry
//!
//! The token-free M2M **authorization record** (, auth DESIGN
//! §4.3f): the enroll-published registry map that replaces the M2M token's
//! `scope`/`vertical`/`service_type` claims on the platform plane.
//!
//! `sentin8-cli vertical enroll` — which already provisions
//! `auth.m2m_scope_grants` and the `captain:*` Valkey keys — additionally
//! publishes the `m2m:workloads` hash: workload CN →
//! `{vertical, service_type, scopes[], enabled}` (JSON per field). Every
//! service boot-loads the map into an in-process `OnceLock` cache and
//! refreshes it on a TTL — the platform's mandated pattern (owner data is
//! seeded on cold start / cache refresh, NEVER read on the request path).
//!
//! Authentication is the TLS client certificate (`sentin8-tls` CA-verifies
//! the `CN=m2m-{workload}` leaf and injects the identity headers); THIS
//! crate answers the authorization half: "what may this workload do".
//!
//! Revocation: enroll (or the admin surface) sets `enabled=false`; every
//! service observes it on its next TTL refresh and refuses the workload.
//! A cache file persisted under `SENTIN8_RUN_DIR` covers a Valkey outage
//! at boot (fail-open for ENROLLED workloads from the last known map,
//! fail-closed for everything else).

#![deny(missing_docs)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

/// The Valkey hash key holding the platform workload registry map.
pub const WORKLOADS_KEY: &str = "m2m:workloads";

/// The Valkey SET of declared workload names — the bootstrap-mint pinning
/// set : Acme's bootstrap-enrollment channel accepts client-cert
/// mints only for declared workloads (permissive on a miss so a Valkey
/// outage cannot wedge first births).
pub const DECLARED_KEY: &str = "m2m:declared";

/// Refresh interval for the boot-loaded map (the platform's TTL-cache
/// pattern; a revocation lands within this window).
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Client-side failure surface of the registry map.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Valkey could not be reached and no usable cache file exists.
    #[error("workload registry unreachable: {0}")]
    Unreachable(String),
    /// A map entry could not be decoded (corrupt publish — enroll owns
    /// the write; a corrupt entry is skipped at load).
    #[error("workload registry decode error: {0}")]
    Decode(String),
}

/// One workload's authorization record — the enroll-published form of
/// `auth.m2m_scope_grants`' row for the token-free plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WorkloadRecord {
    /// The vertical this workload belongs to (VDC-2 — Bus's event-ownership
    /// gate: `bank8` workloads may not produce `sentin8:*` events).
    pub vertical: String,
    /// The service_type the workload performs work FOR (VDC-4 — Sys's
    /// tenant-snapshot scoped discovery).
    pub service_type: String,
    /// The closed scope set this workload may exercise (Shield input).
    pub scopes: Vec<String>,
    /// The revocation flag — `false` refuses every call within the TTL.
    pub enabled: bool,
}

/// The boot-loaded registry map. Cheap to clone (wraps `Arc`).
///
/// # Examples
///
/// ```no_run
/// # async fn demo() -> Result<(), sentin8_workload_registry::RegistryError> {
/// let map = sentin8_workload_registry::WorkloadMap::boot_load("sentin8:bus").await?;
/// // Request-path reads are in-memory (no I/O on the hot path):
/// let scopes = map.scopes("db-audit").await;
/// assert!(scopes.is_empty() || !scopes.is_empty()); // shape demo
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct WorkloadMap {
    inner: Arc<RwLock<HashMap<String, WorkloadRecord>>>,
}

impl WorkloadMap {
    /// Boot-load the map from Valkey (falling back to the persisted cache
    /// file on an outage) and spawn the TTL refresh loop. Called ONCE per
    /// process at boot — the request path reads the in-memory snapshot.
    ///
    /// `workload` is the CALLING SERVICE's workload name: the Valkey
    /// plane authenticates by certificate (the CN maps to the ACL user
    /// of the same name — group DESIGN.md §3.1), so the map fetch presents
    /// the caller's own m2m pair. Every workload user holds READ rights on
    /// `m2m:workloads` — only the enroll-side `m2m-registry-writer`
    /// identity may write it.
    ///
    /// # Errors
    /// [`RegistryError::Unreachable`] when Valkey cannot be reached AND no
    /// cache file exists (nothing to serve — fail-closed: callers refuse
    /// workload traffic).
    pub async fn boot_load(workload: &str) -> Result<Self, RegistryError> {
        let map = Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        };
        let loaded = fetch_map(workload).await;
        match loaded {
            Ok(entries) => {
                *map.inner.write().await = entries.clone();
                persist_cache_file(&entries);
            }
            Err(e) => {
                // Outage at boot: fall back to the persisted cache file.
                let cached = load_cache_file();
                match cached {
                    Some(entries) if !entries.is_empty() => {
                        tracing::warn!(
                            error = %e,
                            count = entries.len(),
                            "workload-registry: Valkey unreachable at boot — serving the persisted cache snapshot"
                        );
                        *map.inner.write().await = entries;
                    }
                    _ => return Err(RegistryError::Unreachable(e.to_string())),
                }
            }
        }
        map.spawn_refresh(workload.to_string());
        Ok(map)
    }

    /// The fail-open boot path for callers that must NOT abort when the
    /// map is unreachable (e.g. a service whose bearer path still serves
    /// users): an EMPTY snapshot with the TTL refresh loop attached —
    /// certificate-workload calls fail-closed (no map rows) until a
    /// refresh succeeds, and the refresh loop heals the map within the
    /// TTL. Prefer [`Self::boot_load`] and handle the error explicitly
    /// where a missing map should abort boot.
    pub fn boot_load_empty(workload: &str) -> Self {
        let map = Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        };
        map.spawn_refresh(workload.to_string());
        map
    }

    /// Look up a workload's authorization record (request-path read —
    /// in-memory, no I/O).
    pub async fn get(&self, workload: &str) -> Option<WorkloadRecord> {
        self.inner.read().await.get(workload).cloned()
    }

    /// The scopes Shield evaluates for a workload (empty for unknown /
    /// disabled workloads — fail-closed: an unenrolled identity exercises
    /// nothing).
    pub async fn scopes(&self, workload: &str) -> Vec<String> {
        match self.get(workload).await {
            Some(rec) if rec.enabled => rec.scopes,
            _ => Vec::new(),
        }
    }

    /// The vertical claim source for Bus's VDC-2 event-ownership gate.
    /// `None` for unknown/disabled workloads (produce refuses them).
    pub async fn vertical(&self, workload: &str) -> Option<String> {
        match self.get(workload).await {
            Some(rec) if rec.enabled => Some(rec.vertical),
            _ => None,
        }
    }

    /// Spawn the TTL refresh loop (one background task per process). The
    /// workload identity is moved into the loop — the refresh presents the
    /// same certificate as the boot fetch.
    fn spawn_refresh(&self, workload: String) {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(REFRESH_INTERVAL).await;
                match fetch_map(&workload).await {
                    Ok(entries) => {
                        persist_cache_file(&entries);
                        *inner.write().await = entries;
                    }
                    Err(e) => {
                        // Transient outage — keep serving the snapshot; the
                        // next tick retries. NEVER fail-open to empty.
                        tracing::debug!(error = %e, "workload-registry refresh failed — keeping snapshot");
                    }
                }
            }
        });
    }
}

/// The map's WRITER workload name — the enroll/admin-side identity. Its
/// certificate (minted by `make infra-tls`, held by the operator's CLI) maps
/// to the sole ACL user with write rights on `m2m:workloads`/`m2m:declared`.
pub const WRITER_WORKLOAD: &str = "valkey-registry-writer";

/// Fetch the whole map from Valkey (one HGETALL on the boot/refresh path —
/// never per-request). Presents the CALLING workload's certificate over
/// the TLS plane (the CN maps to its read-scoped ACL user) via Valkey
/// GLIDE (group DESIGN.md §3.1).
async fn fetch_map(workload: &str) -> Result<HashMap<String, WorkloadRecord>, RegistryError> {
    let url = sentin8_config::Sentin8Config::valkey_url_from_env();
    let client = sentin8_middleware::valkey_client(&url, workload)
        .await
        .map_err(|e| RegistryError::Unreachable(e.to_string()))?;
    use glide::AsyncCommands as _;
    let raw: HashMap<String, String> = client
        .hgetall(WORKLOADS_KEY)
        .await
        .map_err(|e| RegistryError::Unreachable(e.to_string()))?;
    let mut out = HashMap::with_capacity(raw.len());
    for (workload, json) in raw {
        match serde_json::from_str::<WorkloadRecord>(&json) {
            Ok(rec) => {
                out.insert(workload, rec);
            }
            Err(e) => {
                // Corrupt field — skip it (fail-closed for that workload).
                tracing::warn!(error = %e, workload, "workload-registry: corrupt entry skipped");
            }
        }
    }
    Ok(out)
}

/// Persist the map snapshot under `SENTIN8_RUN_DIR` — the boot-time Valkey
/// outage fallback. Best-effort: a write failure only removes the outage
/// fallback (the in-memory map still serves).
fn persist_cache_file(entries: &HashMap<String, WorkloadRecord>) {
    let Some(run_dir) = std::env::var("SENTIN8_RUN_DIR").ok().filter(|s| !s.is_empty()) else {
        return;
    };
    let path = std::path::Path::new(&run_dir).join("workload-registry.json");
    if let Ok(json) = serde_json::to_string(entries) {
        if let Err(e) = std::fs::write(&path, json) {
            tracing::debug!(error = %e, path = %path.display(), "workload-registry cache write failed");
        }
    }
}

/// Load the persisted snapshot (boot-time Valkey outage fallback).
fn load_cache_file() -> Option<HashMap<String, WorkloadRecord>> {
    let run_dir = std::env::var("SENTIN8_RUN_DIR").ok()?;
    let path = std::path::Path::new(&run_dir).join("workload-registry.json");
    let json = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&json).ok()
}

// ── Publish helpers (the enroll/CLI side — the map's owner) ──────────

/// Publish one SERVICE's map entries (the enroll path: delete the
/// service's stale fields first — entries whose `service_type` matches —
/// then publish the fresh set + declared set; idempotent, whole-state per
/// service). Keyed per SERVICE, not per vertical: a vertical owns many
/// services (platform = every service under `sentin8`), and a
/// vertical-keyed sweep would delete sibling services' entries on every
/// pass.
///
/// # Errors
/// [`RegistryError::Unreachable`] when Valkey cannot be reached — enroll
/// aborts loudly (the map is the authorization record; a silent skip
/// would leave services serving stale authorization).
pub async fn publish_service(
    valkey_url: &str,
    entries: &[(String, WorkloadRecord)],
) -> Result<(), RegistryError> {
    // The map's WRITER identity (group DESIGN.md §3.1): the enroll-side
    // `m2m-registry-writer` pair is the ONLY identity holding write rights
    // on `m2m:workloads`/`m2m:declared` — the token-free authorization
    // record is not writable by any service. The CLI loads the same
    // infra-admin material `make infra-tls` minted.
    let client = sentin8_middleware::valkey_client(valkey_url, WRITER_WORKLOAD)
        .await
        .map_err(|e| RegistryError::Unreachable(e.to_string()))?;
    use glide::AsyncCommands as _;

    // The SERVICE's stale fields must go (a workload re-enrolled away or
    // deleted must not linger) — but ONLY this service's: match on the
    // record's `service_type`, never on `vertical` (siblings share it).
    let service_type = entries.first().map(|(_, r)| r.service_type.clone());
    if let Some(service_type) = &service_type {
        let existing: HashMap<String, String> = client
            .hgetall(WORKLOADS_KEY)
            .await
            .map_err(|e| RegistryError::Unreachable(e.to_string()))?;
        for (workload, json) in existing {
            if let Ok(rec) = serde_json::from_str::<WorkloadRecord>(&json) {
                if &rec.service_type == service_type {
                    let _: Result<usize, _> =
                        client.hdel(WORKLOADS_KEY, &workload).await;
                    let _: Result<usize, _> =
                        client.srem(DECLARED_KEY, &workload).await;
                }
            }
        }
    }
    for (workload, rec) in entries {
        let json = serde_json::to_string(rec)
            .map_err(|e| RegistryError::Decode(e.to_string()))?;
        let _: Result<usize, _> =
            client.hset(WORKLOADS_KEY, workload, &json).await;
        let _: Result<usize, _> =
            client.sadd(DECLARED_KEY, workload).await;
    }
    Ok(())
}

/// Set a workload's `enabled` flag (the revocation surface — admin
/// disable / re-enable; observed by services within the TTL).
///
/// # Errors
/// [`RegistryError::Unreachable`] when Valkey cannot be reached.
pub async fn set_enabled(
    valkey_url: &str,
    workload: &str,
    enabled: bool,
) -> Result<(), RegistryError> {
    // Admin-side revocation presents the same WRITER identity as enroll —
    // the only one that may touch the map.
    let client = sentin8_middleware::valkey_client(valkey_url, WRITER_WORKLOAD)
        .await
        .map_err(|e| RegistryError::Unreachable(e.to_string()))?;
    use glide::AsyncCommands as _;
    let json: Option<String> = client
        .hget(WORKLOADS_KEY, workload)
        .await
        .map_err(|e| RegistryError::Unreachable(e.to_string()))?;
    let Some(json) = json else {
        return Err(RegistryError::Decode(format!(
            "workload '{workload}' has no registry entry"
        )));
    };
    let mut rec: WorkloadRecord = serde_json::from_str(&json)
        .map_err(|e| RegistryError::Decode(e.to_string()))?;
    rec.enabled = enabled;
    let updated = serde_json::to_string(&rec)
        .map_err(|e| RegistryError::Decode(e.to_string()))?;
    let _: Result<usize, _> = client.hset(WORKLOADS_KEY, workload, &updated).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips() {
        let rec = WorkloadRecord {
            vertical: "sentin8".into(),
            service_type: "sentin8:db".into(),
            scopes: vec!["sentin8:bus:produce".into()],
            enabled: true,
        };
        let json = serde_json::to_string(&rec).unwrap();
        let back: WorkloadRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn keys_are_stable_contract() {
        // The wire contract — enroll publishes, services consume; renaming
        // either breaks the fleet.
        assert_eq!(WORKLOADS_KEY, "m2m:workloads");
        assert_eq!(DECLARED_KEY, "m2m:declared");
    }
}