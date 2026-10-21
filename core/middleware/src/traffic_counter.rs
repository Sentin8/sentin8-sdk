// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Traffic counter middleware - lets every service count its own inbound
//! API requests and publish them to the same Valkey channel proxy uses.
//!
//! Each service wraps its axum router with [`traffic_counter_layer`] and
//! spawns [`spawn_flush_loop`] at startup. The middleware increments a
//! thread-safe counter for every inbound request **except** health checks
//! (`/v1/health`), and the flush loop publishes the accumulated count to
//! Valkey pub/sub channel `stat:metrics:tls` every 10 seconds with the
//! metric name `proxy.traffic.external→{service}.count`.
//!
//! The counter also carries the in-flight request gauge
//! ([`RequestCounter::active_connections`]) - the drain signal captain
//! polls via the service's `/v1/health` payload during rolling upgrades
//! (proxy README §7 / captain README §7).
//!
//! The shell registers the gauge process-wide at boot
//! ([`set_process_gauge`]); services that mount their own health payload
//! (`with_own_health` / `with_prebuilt_router`) read it via
//! [`process_active_connections`] and append `active_connections` to their
//! custom body the same way the shell-mounted route does (shell README §5).
//!
//! Stat's embedded worker aggregates these into 24-hour rollups on
//! `stat:rollups:day`, and captain's monitor subscriber overwrites the
//! `api_calls` field on each service instance - so the `CALLS` column in
//! `make status` reflects actual per-request counts from every service,
//! including traffic that bypasses proxy (e.g. acme cert fetches).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::extract::State;
use glide::AsyncCommands;
use parking_lot::Mutex;

/// Thread-safe inbound request counter (excludes health checks).
///
/// Also carries the in-flight connection gauge ([`Self::active_connections`]) -
/// the drain signal captain polls via the health payload during
/// rolling upgrades (captain README §7).
#[derive(Clone)]
pub struct RequestCounter {
    inner: Arc<Mutex<u64>>,
    /// In-flight requests: incremented on request entry, decremented on
    /// response completion by [`InFlightGuard`]. Relaxed ordering - the
    /// gauge is a drain hint, never a synchronization point.
    in_flight: Arc<AtomicUsize>,
}

impl RequestCounter {
    /// Create a counter at zero.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(0)),
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Count one request.
    pub fn increment(&self) {
        let mut count = self.inner.lock();
        *count += 1;
    }

    /// Enter one in-flight request - returns a guard that decrements the
    /// gauge on drop, so panics and early returns cannot leak the count.
    pub fn enter(&self) -> InFlightGuard {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlightGuard {
            counter: self.clone(),
        }
    }

    /// Current in-flight request count - the value reported as
    /// `active_connections` in the standard health payload (shell README §5).
    /// Relaxed load: a drain hint, never a fence.
    pub fn active_connections(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed) as u64
    }

    /// Shared handle to the in-flight gauge - the shell registers this Arc
    /// process-wide ([`set_process_gauge`]) so custom health handlers can
    /// report the drain signal (shell README §5 / captain README §7).
    pub fn in_flight_arc(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.in_flight)
    }

    /// Saturating gauge decrement (guards against any unpaired exit).
    fn gauge_exit(&self) {
        let _ = self
            .in_flight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
    }

    fn drain(&self) -> u64 {
        let mut count = self.inner.lock();
        std::mem::take(&mut *count)
    }
}

/// RAII guard for one in-flight request - the drop half of
/// [`RequestCounter::enter`]. Dropping it decrements the in-flight gauge.
pub struct InFlightGuard {
    counter: RequestCounter,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.counter.gauge_exit();
    }
}

impl Default for RequestCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Axum middleware that counts every inbound request except health checks
/// and tracks the in-flight gauge for the drain payload (captain README §7).
/// Installed via `from_fn_with_state`.
pub async fn traffic_counter_layer(
    State(counter): State<RequestCounter>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Skip health-check endpoints - they're captain's monitor probes, not
    // real API calls, and must never hold the drain gauge open.
    if req.uri().path() == "/v1/health" {
        return next.run(req).await;
    }
    counter.increment();
    // RAII guard: decremented when the response completes (or the task
    // unwinds), so error paths cannot leak the in-flight count.
    let _in_flight = counter.enter();
    next.run(req).await
}

// ── Process-wide drain gauge ─────────────────────────────────────────────

/// Process-wide in-flight gauge, registered by the shell at boot (step 9,
/// shell README §5). Services that mount their own `/v1/health` payload
/// (`with_own_health` / `with_prebuilt_router`) cannot reach the counter
/// through their service-defined state - the process-global slot makes the
/// drain signal reachable from any handler in the process (captain README §7).
static PROCESS_GAUGE: OnceLock<Arc<AtomicUsize>> = OnceLock::new();

/// Register the process-wide in-flight gauge.
///
/// Called once by the shell at boot when it built a traffic counter;
/// later calls are no-ops (first registration wins for the process
/// lifetime - a restarted process simply re-registers at boot).
pub fn set_process_gauge(c: Arc<AtomicUsize>) {
    let _ = PROCESS_GAUGE.set(c);
}

/// Current in-flight request count from the process-wide gauge - the value
/// a custom health payload reports as `active_connections` (shell README §5).
///
/// `None` before the shell registered a counter (metrics-disabled shells):
/// the handler omits the field and captain's drain falls back to the fixed
/// window (captain README §7).
pub fn process_active_connections() -> Option<u64> {
    PROCESS_GAUGE
        .get()
        .map(|g| g.load(Ordering::Relaxed) as u64)
}

/// Spawn a 10s flush loop that publishes the accumulated request count to
/// Valkey pub/sub channel `stat:metrics:tls`. The service name is read
/// from the process-wide `SERVICE_NAME` set by `init_structured_logging_try`.
///
/// The metric name follows the same format proxy uses:
///   `proxy.traffic.external→{service_name}.count`
///
/// If `valkey_url` is empty, the flush loop is a no-op.
pub fn spawn_flush_loop(counter: RequestCounter, valkey_url: String, flush_interval_s: u64) {
    use crate::valkey_client;
    let service_name = crate::structured_logging::current_service_name()
        .unwrap_or("unknown")
        .to_string();
    // Use the full service identity (e.g. "sentin8:auth") - this matches
    // the captain catalog keys which are the full `sentin8-*` names.
    let service_type = service_name;

    if valkey_url.is_empty() {
        tracing::info!("traffic-counter: VALKEY_URL not set, metrics flush disabled");
        return;
    }
    let interval = Duration::from_secs(flush_interval_s.max(1));
    tokio::spawn(async move {
        // Certificate identity via Valkey GLIDE (group DESIGN.md §3.1):
        // the flush loop presents the calling service's own m2m pair -
        // the CN maps to its enroll-provisioned ACL user. A degraded
        // (best-effort) consumer: a failure only disables this metrics
        // flush, never the service; glide-core heals the connection.
        let client = match valkey_client(&valkey_url, &service_type).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "traffic-counter: failed to open Valkey client; flush disabled");
                return;
            }
        };

        let metric_name = format!("proxy.traffic.external→{service_type}.count");

        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip first tick
        loop {
            ticker.tick().await;
            let count = counter.drain();
            if count == 0 {
                continue;
            }

            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            let window = format!("{}s", flush_interval_s.max(1));

            let payload = serde_json::json!({
                "ts": ts,
                "source": "proxy",
                "window": window,
                "org_id": null,
                "env_id": null,
                "metrics": {
                    &metric_name: count,
                },
            });
            let payload_str = serde_json::to_string(&payload).unwrap_or_default();

            let _: Result<usize, _> = client
                .publish::<_, _, usize>("stat:metrics:tls", payload_str.as_str())
                .await;

            tracing::debug!(count, service = %service_type, "traffic-counter: published to stat:metrics:tls");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_flight_gauge_pairs_entry_and_exit() {
        let counter = RequestCounter::new();
        assert_eq!(counter.active_connections(), 0);

        let g1 = counter.enter();
        let g2 = counter.enter();
        assert_eq!(counter.active_connections(), 2);

        drop(g1);
        assert_eq!(counter.active_connections(), 1);
        drop(g2);
        assert_eq!(counter.active_connections(), 0);
    }

    #[test]
    fn in_flight_gauge_saturates_at_zero() {
        // A defensive double-exit (should be impossible via the RAII guard)
        // must not wrap the gauge to usize::MAX.
        let counter = RequestCounter::new();
        counter.gauge_exit();
        assert_eq!(counter.active_connections(), 0);
    }

    #[test]
    fn request_count_separate_from_gauge() {
        // The traffic counter (api_calls) and the in-flight gauge are
        // independent: one request entered and completed still counts once
        // for `api_calls` while the gauge returns to zero.
        let counter = RequestCounter::new();
        let guard = counter.enter();
        counter.increment();
        drop(guard);
        assert_eq!(counter.active_connections(), 0);
        // The api_calls bucket is drained by the flush loop, not the gauge.
        assert_eq!(counter.drain(), 1);
    }

    #[test]
    fn process_gauge_none_before_set_some_after() {
        // A fresh process reports None until the shell registers the
        // process-wide counter at boot; after the (first, wins)
        // registration the reading tracks that counter's in-flight gauge.
        let was_unset = process_active_connections().is_none();
        let counter = RequestCounter::new();
        set_process_gauge(counter.in_flight_arc());
        if was_unset {
            assert_eq!(process_active_connections(), Some(0));
            let guard = counter.enter();
            assert_eq!(process_active_connections(), Some(1));
            drop(guard);
            assert_eq!(process_active_connections(), Some(0));
        }
    }
}
