// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Service Discovery - resolve service backends from the Captain
//! Valkey registry with automatic reconnection and load-aware selection.
//!
//! ## Architecture
//!
//! The discovery client subscribes to the `captain:changed` Valkey pub/sub
//! channel. On every notification (or on a 30s safety poll), it scans all
//! `captain:svc:*` hashes and builds an in-memory map of
//! `service_type → Vec<ServiceInstance>`. Only `Active` instances with
//! a fresh health check (within 30s) are included.
//!
//! ## Instance selection
//!
//! `resolve(service_type)` returns the best instance:
//!   1. Prefer instances on the same machine (`local_ip` matches
//!      `SENTIN8_CAPTAIN_LOCAL_IP`). Loopback is faster than cross-subnet.
//!   2. Among same-machine instances (or if none on this machine, among
//!      all instances), pick the one with the lowest load score:
//!      `load = cpu_avg_1m * 0.5 + memory_avg_1m * 0.3 + latency_avg_1m_ms * 0.2`.
//!      This balances CPU, memory, and latency.
//!
//! ## Automatic reconnection
//!
//! When an instance's port changes (e.g. after a rolling upgrade), the
//! discovery client picks it up on the next Valkey notification. The
//! caller gets the new URL - no restart needed.
//!
//! ## Usage
//!
//! ```text
//! use sentin8_service_discovery::ServiceDiscovery;
//!
//! let discovery = ServiceDiscovery::spawn("valkey://localhost:6379/1".into(), "127.0.0.1".into());
//!
//! // Resolve a service backend URL
//! if let Some(url) = discovery.resolve("auth") {
//!     let resp = reqwest::get(format!("{url}/v1/health")).await?;
//! }
//! ```

#![deny(missing_docs)]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::Deserialize;

/// The Valkey pub/sub channel for service registry changes.
const SENTIN8_CAPTAIN_CHANGED_CHANNEL: &str = "captain:changed";
/// Glob matching one hash per service type: `captain:svc:{service_type}`.
const SENTIN8_CAPTAIN_SVC_GLOB: &str = "captain:svc:*";
/// Hash-key prefix for one service type's registry hash (FIREHOSE-1's
/// targeted refresh builds `{prefix}{service_type}` from the notification
/// payload).
const SENTIN8_CAPTAIN_SVC_PREFIX: &str = "captain:svc:";
/// A service instance is considered live if its `last_health_check` is
/// within this many seconds of `now`.
const HEALTH_FRESHNESS_S: i64 = 30;
/// Safety poll interval (catches missed pub/sub notifications).
const SAFETY_POLL_S: u64 = 60;

/// One service instance as stored in Valkey.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceInstance {
    /// Registry key (`{ip}:{port}`).
    pub key: String,
    /// The service type this instance serves (e.g. `auth`).
    pub service_type: String,
    /// The machine IP the instance listens on.
    pub local_ip: String,
    /// The bound TLS port.
    pub local_port: u16,
    /// Process id of the instance.
    pub pid: u32,
    /// Captain start-order priority tier.
    pub start_priority: i16,
    /// 1-minute CPU average percentage.
    pub cpu_avg_1m: f32,
    /// 1-minute memory average percentage.
    pub memory_avg_1m: f32,
    /// 1-minute average response latency in milliseconds.
    pub latency_avg_1m_ms: f32,
    /// Unix timestamp of the last captain health probe (`None` = not yet probed).
    pub last_health_check: Option<i64>,
    /// Lifecycle status (only `Active` instances are resolvable).
    pub status: String,
    /// Restart count since registration.
    pub restarts: i32,
    /// Unix timestamp when the instance started.
    pub started_at: Option<i64>,
    /// Service version reported at registration.
    #[serde(default)]
    pub version: String,
    /// Cumulative error count reported by the instance.
    #[serde(default)]
    pub errors: i64,
    /// Cumulative warning count reported by the instance.
    #[serde(default)]
    pub warnings: i64,
}

impl ServiceInstance {
    /// Build the backend URL for this instance.
    ///
    /// Returns `https://` - all Sentin8 services terminate TLS directly.
    /// The Sentin8 Root CA (served by acme at `/v1/ca/root.crt`) must be
    /// installed in the OS trust store so `rustls-tls-native-roots` trusts it.
    pub fn url(&self) -> String {
        format!("https://{}:{}", self.local_ip, self.local_port)
    }

    /// Compute a load score - lower is better.
    /// Weighted: 50% CPU, 30% memory, 20% latency (normalized to 0-100).
    /// A local-machine bonus is applied at selection time, not here.
    pub fn load_score(&self) -> f32 {
        let cpu = self.cpu_avg_1m.min(100.0);
        let mem = self.memory_avg_1m.min(100.0);
        let lat = self.latency_avg_1m_ms.min(2000.0) / 20.0; // 2000ms → 100
        cpu * 0.5 + mem * 0.3 + lat * 0.2
    }

    /// Compute a selection score - lower is better. Applies a local
    /// bonus (score reduction) for instances on the same machine,
    /// but a very busy local instance can still lose to a less busy
    /// remote one.
    pub fn selection_score(&self, my_ip: &str) -> f32 {
        let base = self.load_score();
        if self.local_ip == my_ip {
            // Local instances get a 20-point bonus. This means a local
            // instance with load 80 wins over a remote with load 60
            // (80 - 20 = 60, tie), but loses to a remote with load 50.
            (base - 20.0).max(0.0)
        } else {
            base
        }
    }

    /// Is the health check fresh (within HEALTH_FRESHNESS_S seconds)?
    /// An Active instance with no health check yet is considered healthy
    /// (it just became Active and the monitor hasn't probed it yet).
    pub fn is_healthy(&self) -> bool {
        if self.status != "Active" {
            return false;
        }
        match self.last_health_check {
            Some(ts) => {
                let now = chrono::Utc::now().timestamp();
                now - ts < HEALTH_FRESHNESS_S
            }
            None => true, // Active but not yet probed - give it the benefit of the doubt
        }
    }
}

/// Shared service discovery handle. Clone cheaply (backed by `Arc`).
#[derive(Clone)]
pub struct ServiceDiscovery {
    inner: Arc<RwLock<HashMap<String, Vec<ServiceInstance>>>>,
    local_ip: String,
}

impl ServiceDiscovery {
    /// Spawn the discovery background task. Returns immediately.
    /// The task subscribes to Valkey pub/sub and maintains the in-memory
    /// map. `valkey_url` is the Captain Valkey URL, `local_ip` is this
    /// machine's IP (for same-machine preference). `workload` is the
    /// CALLING SERVICE's identity - the certificate it presents over
    /// the TLS plane (the CN maps to its enroll-provisioned ACL user;
    /// group DESIGN.md §3.1).
    pub fn spawn(valkey_url: String, local_ip: String, workload: String) -> Self {
        let inner = Arc::new(RwLock::new(HashMap::new()));
        let discovery = Self {
            inner: inner.clone(),
            local_ip: local_ip.clone(),
        };

        tokio::spawn(async move {
            // Certificate identity via Valkey GLIDE (group DESIGN.md §3.1):
            // one shared command client (scan + instance reads) and a
            // SEPARATE pubsub-enabled client for the change channel -
            // each heals independently in glide-core.
            let client = match sentin8_middleware::valkey_client(&valkey_url, &workload).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = ?e, "service-discovery: failed to create Valkey client");
                    return;
                }
            };

            // Seed: initial scan before subscribing.
            refresh(&client, &inner).await;
            tracing::info!("service-discovery: initial scan complete");

            // Pub/sub loop with safety poll.
            let safety = Duration::from_secs(SAFETY_POLL_S);
            let mut last_refresh = Instant::now();

            loop {
                // A SEPARATE pubsub-enabled client for the change
                // channel (its push loop is independent of the command
                // client's pipeline).
                let pubsub_client = match sentin8_middleware::valkey_client_pubsub(
                    &valkey_url,
                    &workload,
                )
                .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = ?e, "service-discovery: failed to create pubsub client");
                        tokio::time::sleep(safety).await;
                        refresh(&client, &inner).await;
                        last_refresh = Instant::now();
                        continue;
                    }
                };

                use glide::PubSubCommands as _;
                if let Err(e) = pubsub_client
                    .subscribe(&[SENTIN8_CAPTAIN_CHANGED_CHANNEL])
                    .await
                {
                    tracing::warn!(error = %e, "service-discovery: subscribe failed");
                    tokio::time::sleep(safety).await;
                    refresh(&client, &inner).await;
                    last_refresh = Instant::now();
                    continue;
                }

                // Message loop - ONE subscription, many `captain:changed`
                // notifications. The subscription is rebuilt only on a
                // terminal stream end (connection closed, Valkey restart);
                // a per-message client teardown churned a GLIDE connect +
                // drop for every registry notification captain publishes.
                loop {
                    tokio::select! {
                        maybe_msg = pubsub_client.get_pubsub_message() => {
                            if maybe_msg.is_err() {
                                // Pub/sub channel ended (Valkey restart, idle
                                // eviction, network blip). Break to the outer
                                // loop - the pubsub client + subscription
                                // rebuild keeps discovery refreshing; without
                                // this the map freezes and is_healthy()
                                // (30s freshness) fails for every service.
                                tracing::warn!("service-discovery: pubsub stream ended - reconnecting");
                                tokio::time::sleep(Duration::from_millis(500)).await;
                                refresh(&client, &inner).await;
                                last_refresh = Instant::now();
                                break;
                            }
                            // Debounce: small delay to coalesce bursts,
                            // then refresh. FIREHOSE-1: the payload names the
                            // service type that changed - refresh ONLY that
                            // type's hash (1 HGETALL) instead of a full
                            // registry scan. `captain:changed` broadcasts to
                            // every subscriber; a full-scan-per-message was
                            // 63 HGETALL x 64 services x msg rate ≈ 13,000
                            // HGETALL/s fleet-wide - the root cause of the
                            // fleet-wide idle CPU (~20%/service) and RSS drift
                            // (heaptrack: ~5,000 TLS-decrypt allocations/s
                            // per idle service; MTALEAK-1). A payload that is
                            // not a known service type (or the "alert"
                            // marker) falls back to the coalesced full scan.
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            if let Some(msg) = maybe_msg.ok() {
                                let changed = String::from_utf8_lossy(&msg.payload).to_string();
                                if changed == "alert" {
                                    refresh(&client, &inner).await;
                                } else {
                                    refresh_one(&client, &inner, &changed).await;
                                }
                            } else {
                                refresh(&client, &inner).await;
                            }
                            last_refresh = Instant::now();
                        }
                        _ = tokio::time::sleep(safety) => {
                            // Safety poll - catches missed notifications.
                            if last_refresh.elapsed() >= safety {
                                refresh(&client, &inner).await;
                                last_refresh = Instant::now();
                            }
                        }
                    }
                }
            }
        });
        discovery
    }

    /// Resolve the best instance for a service type.
    /// Returns the backend URL (`https://{ip}:{port}`) or `None` if no
    /// healthy (Active + fresh health check) instance is available.
    ///
    /// Selection: pick the instance with the lowest selection score.
    /// Same-machine instances get a 20-point bonus, but a very busy
    /// local instance loses to a less busy remote one.
    pub fn resolve(&self, service_type: &str) -> Option<String> {
        let map = self.inner.read().ok()?;
        let instances = map.get(service_type)?;
        let healthy: Vec<&ServiceInstance> = instances.iter().filter(|i| i.is_healthy()).collect();
        if healthy.is_empty() {
            return None;
        }
        let best = healthy.iter().min_by(|a, b| {
            a.selection_score(&self.local_ip)
                .partial_cmp(&b.selection_score(&self.local_ip))
                .unwrap_or(std::cmp::Ordering::Equal)
        })?;
        Some(best.url())
    }

    /// Resolve the best instance, returning the full `ServiceInstance`.
    pub fn resolve_instance(&self, service_type: &str) -> Option<ServiceInstance> {
        let map = self.inner.read().ok()?;
        let instances = map.get(service_type)?;
        let healthy: Vec<&ServiceInstance> = instances.iter().filter(|i| i.is_healthy()).collect();
        if healthy.is_empty() {
            return None;
        }
        let best = healthy.iter().min_by(|a, b| {
            a.selection_score(&self.local_ip)
                .partial_cmp(&b.selection_score(&self.local_ip))
                .unwrap_or(std::cmp::Ordering::Equal)
        })?;
        Some((*best).clone())
    }

    /// List all known instances for a service type (including unhealthy).
    pub fn list(&self, service_type: &str) -> Vec<ServiceInstance> {
        self.inner
            .read()
            .ok()
            .and_then(|m| m.get(service_type).cloned())
            .unwrap_or_default()
    }

    /// Get all service types known to the registry.
    pub fn service_types(&self) -> Vec<String> {
        self.inner
            .read()
            .ok()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Scan all `captain:svc:*` hashes from Valkey, parse the JSON blobs, and
/// update the in-memory map. Only `Active` instances with fresh health
/// checks are kept.
async fn refresh(
    client: &glide::GlideClient,
    inner: &Arc<RwLock<HashMap<String, Vec<ServiceInstance>>>>,
) {
    use glide::AsyncCommands as _;
    let keys: Vec<String> = client
        .keys(SENTIN8_CAPTAIN_SVC_GLOB)
        .await
        .unwrap_or_default();

    let mut new_map: HashMap<String, Vec<ServiceInstance>> = HashMap::new();

    for key in keys {
        let entries: Vec<(String, String)> = client.hgetall(&key).await.unwrap_or_default();
        for (_field, json) in entries {
            if let Ok(inst) = serde_json::from_str::<ServiceInstance>(&json) {
                new_map
                    .entry(inst.service_type.clone())
                    .or_default()
                    .push(inst);
            }
        }
    }

    // Sort each service type's instances by load score for quick access.
    for instances in new_map.values_mut() {
        instances.sort_by(|a, b| {
            a.load_score()
                .partial_cmp(&b.load_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    let mut map = inner.write().unwrap();
    let count: usize = new_map.values().map(|v| v.len()).sum();
    *map = new_map;
    tracing::debug!(total_instances = count, "service-discovery: refreshed");
}

/// Refresh ONE service type's instances from its registry hash - the
/// FIREHOSE-1 targeted path. `captain:changed` messages name the changed
/// service type in the payload, so a notification for a single type costs
/// one HGETALL (not a full KEYS + 63-HGETALL scan). Unknown types insert an
/// empty list (the type's hash vanished - every instance stopped), matching
/// the full scan's behavior for missing keys.
async fn refresh_one(
    client: &glide::GlideClient,
    inner: &Arc<RwLock<HashMap<String, Vec<ServiceInstance>>>>,
    service_type: &str,
) {
    use glide::AsyncCommands as _;
    let key = format!("{SENTIN8_CAPTAIN_SVC_PREFIX}{service_type}");
    let entries: Vec<(String, String)> = client.hgetall(&key).await.unwrap_or_default();
    let mut fresh: Vec<ServiceInstance> = Vec::new();
    for (_field, json) in entries {
        if let Ok(inst) = serde_json::from_str::<ServiceInstance>(&json) {
            fresh.push(inst);
        }
    }
    fresh.sort_by(|a, b| {
        a.load_score()
            .partial_cmp(&b.load_score())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut map = inner.write().unwrap();
    map.insert(service_type.to_string(), fresh);
}

// Pure-seam tests: load-score math, local-machine bonus, health
// freshness, URL building, and resolve() selection over a pre-seeded map.
// The Valkey-driven spawn loop is covered by the integration test suite
// against the platform Valkey.

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn inst(
        service_type: &str,
        ip: &str,
        port: u16,
        status: &str,
        cpu: f32,
        mem: f32,
        latency_ms: f32,
        health_check_age_s: Option<i64>,
    ) -> ServiceInstance {
        let now = chrono::Utc::now().timestamp();
        ServiceInstance {
            key: format!("{ip}:{port}"),
            service_type: service_type.into(),
            local_ip: ip.into(),
            local_port: port,
            pid: 1234,
            start_priority: 40,
            cpu_avg_1m: cpu,
            memory_avg_1m: mem,
            latency_avg_1m_ms: latency_ms,
            last_health_check: health_check_age_s.map(|age| now - age),
            status: status.into(),
            restarts: 0,
            started_at: Some(now),
            version: "0.1.0".into(),
            errors: 0,
            warnings: 0,
        }
    }

    fn discovery_with(instances: Vec<ServiceInstance>, local_ip: &str) -> ServiceDiscovery {
        let mut map: HashMap<String, Vec<ServiceInstance>> = HashMap::new();
        for i in instances {
            map.entry(i.service_type.clone()).or_default().push(i);
        }
        ServiceDiscovery {
            inner: Arc::new(RwLock::new(map)),
            local_ip: local_ip.into(),
        }
    }

    #[test]
    fn url_is_https_ip_port() {
        let i = inst("auth", "10.0.0.5", 3101, "Active", 0.0, 0.0, 0.0, Some(5));
        assert_eq!(i.url(), "https://10.0.0.5:3101");
    }

    #[test]
    fn load_score_weights_cpu_mem_latency() {
        // load = cpu*0.5 + mem*0.3 + (latency/20)*0.2
        let i = inst(
            "auth",
            "10.0.0.5",
            3101,
            "Active",
            40.0,
            20.0,
            500.0,
            Some(5),
        );
        let expected = 40.0 * 0.5 + 20.0 * 0.3 + (500.0 / 20.0) * 0.2;
        assert!((i.load_score() - expected).abs() < 1e-4);
    }

    #[test]
    fn load_score_is_clamped() {
        // CPU/mem clamp at 100, latency clamps at 2000ms (→100).
        let i = inst(
            "auth",
            "10.0.0.5",
            3101,
            "Active",
            500.0,
            900.0,
            9999.0,
            Some(5),
        );
        assert!((i.load_score() - 100.0).abs() < 1e-4);
    }

    #[test]
    fn local_instance_gets_20_point_bonus() {
        let i = inst("auth", "10.0.0.5", 3101, "Active", 80.0, 0.0, 0.0, Some(5));
        let base = i.load_score(); // 40
        assert!((i.selection_score("10.0.0.5") - (base - 20.0)).abs() < 1e-4);
        assert!((i.selection_score("10.9.9.9") - base).abs() < 1e-4);
    }

    #[test]
    fn very_busy_local_loses_to_idle_remote() {
        // Remote wins iff remote_load < local_load − 20 (strict min with the
        // local bonus). A fully-saturated local (cpu+mem+latency all clamped
        // → load 100, selection 80) loses to an idle remote (cpu only →
        // load 50). Pins the documented invariant: "a very busy local
        // instance loses to a less busy remote one".
        let local = inst(
            "auth",
            "10.0.0.5",
            3101,
            "Active",
            100.0,
            100.0,
            2000.0,
            Some(5),
        );
        let remote = inst("auth", "10.0.1.5", 3101, "Active", 50.0, 0.0, 0.0, Some(5));
        let expected = remote.url();
        let d = discovery_with(vec![local.clone(), remote.clone()], "10.0.0.5");
        assert_eq!(d.resolve("auth").unwrap(), expected);
    }

    #[test]
    fn local_bonus_breaks_score_tie() {
        // Equal load scores → the local instance wins (20-point bonus).
        let local = inst("auth", "10.0.0.5", 3101, "Active", 50.0, 0.0, 0.0, Some(5));
        let remote = inst("auth", "10.0.1.5", 3101, "Active", 50.0, 0.0, 0.0, Some(5));
        let expected = local.url();
        let d = discovery_with(vec![remote.clone(), local.clone()], "10.0.0.5");
        assert_eq!(d.resolve("auth").unwrap(), expected);
    }

    #[test]
    fn healthy_local_wins_over_remote() {
        let local = inst("auth", "10.0.0.5", 3101, "Active", 30.0, 0.0, 0.0, Some(5));
        let remote = inst("auth", "10.0.1.5", 3101, "Active", 30.0, 0.0, 0.0, Some(5));
        let d = discovery_with(vec![remote, local], "10.0.0.5");
        assert_eq!(d.resolve("auth").unwrap(), "https://10.0.0.5:3101");
    }

    #[test]
    fn non_active_instances_excluded() {
        let starting = inst("auth", "10.0.0.5", 3101, "Starting", 0.0, 0.0, 0.0, Some(1));
        let active = inst(
            "auth",
            "10.0.0.6",
            3102,
            "Active",
            90.0,
            90.0,
            1999.0,
            Some(5),
        );
        let expected = active.url();
        let d = discovery_with(vec![starting, active], "10.0.0.5");
        assert_eq!(d.resolve("auth").unwrap(), expected);
    }

    #[test]
    fn stale_health_check_excluded() {
        // 31s-old health check is beyond HEALTH_FRESHNESS_S (30).
        let stale = inst("auth", "10.0.0.5", 3101, "Active", 0.0, 0.0, 0.0, Some(31));
        let d = discovery_with(vec![stale], "10.0.0.5");
        assert!(d.resolve("auth").is_none());
    }

    #[test]
    fn active_without_health_check_is_healthy() {
        // Active but not yet probed - benefit of the doubt.
        let fresh = inst("auth", "10.0.0.5", 3101, "Active", 0.0, 0.0, 0.0, None);
        assert!(fresh.is_healthy());
    }

    #[test]
    fn unknown_service_returns_none() {
        let d = discovery_with(vec![], "10.0.0.5");
        assert!(d.resolve("nope").is_none());
        assert!(d.resolve_instance("nope").is_none());
        assert!(d.list("nope").is_empty());
        assert!(d.service_types().is_empty());
    }

    #[test]
    fn service_types_lists_known_services() {
        let d = discovery_with(
            vec![
                inst("auth", "10.0.0.5", 3101, "Active", 0.0, 0.0, 0.0, Some(1)),
                inst("bff", "10.0.0.6", 3102, "Active", 0.0, 0.0, 0.0, Some(1)),
            ],
            "10.0.0.5",
        );
        let mut types = d.service_types();
        types.sort();
        assert_eq!(types, vec!["auth".to_string(), "bff".to_string()]);
        assert_eq!(d.list("auth").len(), 1);
    }
}
