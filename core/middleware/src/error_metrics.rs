// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # Per-service error/warning metrics
//!
//! Each Sentin8 service counts its own `tracing::error!` and `tracing::warn!`
//! events using atomics and publishes deltas to Valkey pub/sub channel
//! `stat:metrics:log` every 10 seconds. Captain subscribes to this channel
//! and accumulates the deltas into the `errors`/`warnings` fields shown in
//! `make status`.
//!
//! This replaces the previous log pipeline: services no longer push
//! `LogEvent` records to a central log server for classification; instead,
//! each service tracks its own counts locally and publishes only the
//! aggregate deltas.
//!
//! ## Usage
//!
//! In `main.rs` (or `server.rs`), after calling `init_structured_logging_try`:
//!
//! ```text
//! sentin8_middleware::error_metrics::init("sentin8:auth");
//! sentin8_middleware::error_metrics::spawn_publisher(
//!     std::env::var("VALKEY_URL").unwrap_or_default(),
//!     "sentin8-auth",
//! );
//! ```
//!
//! The `ErrorMetricsLayer` (a `tracing_subscriber` Layer) hooks into the
//! global subscriber and increments counters on every `ERROR`/`WARN` event.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use glide::AsyncCommands;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Layer;

// ── Global counters ─────────────────────────────────────────────────────

/// Process-wide error/warning counters. Set by [`init`] and read by the
/// [`ErrorMetricsLayer`] and the publisher task.
static ERROR_COUNT: AtomicI64 = AtomicI64::new(0);
static WARNING_COUNT: AtomicI64 = AtomicI64::new(0);
static SERVICE_NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Initialise the error metrics layer. Must be called once at startup
/// before the subscriber is installed. The `service_name` is used in the
/// Valkey publish payload (e.g. `log.errors.sentin8-auth`).
///
/// Services should call `init_structured_logging_try` first, then this
/// function to add the metrics layer. If the global subscriber is already
/// set, the service name is still registered but the layer is not installed
/// (the caller should use [`build_subscriber`] to construct the full subscriber).
pub fn init(service_name: &str) {
    let _ = SERVICE_NAME.set(service_name.to_string());
    // Also set the structured_logging SERVICE_NAME so the JSON layer
    // includes the correct service name in every log line.
    crate::structured_logging::set_service_name(service_name);
}

/// Build the full tracing subscriber with the error metrics layer included.
/// Services should use this instead of `init_structured_logging_try` when
/// they want error/warning metrics.
pub fn build_subscriber(service_name: &str, level: &str) -> impl Subscriber + Send + Sync {
    init(service_name);

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new(level))
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(crate::structured_logging::Sentin8JsonLayer)
        .with(ErrorMetricsLayer)
}

/// Initialise structured logging + error metrics in one shot.
pub fn init_tracing_with_metrics(service_name: &str, level: &str) -> Result<(), String> {
    let subscriber = build_subscriber(service_name, level);
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| format!("global subscriber already set: {e}"))
}

// ── Tracing Layer ───────────────────────────────────────────────────────

/// `tracing_subscriber` Layer that increments the global error/warning
/// counters on every `ERROR`/`WARN` event. No allocation, no I/O — just
/// a relaxed atomic increment.
pub struct ErrorMetricsLayer;

impl ErrorMetricsLayer {
    /// Create the layer (unit struct).
    pub fn new() -> Self {
        ErrorMetricsLayer
    }
}

impl Default for ErrorMetricsLayer {
    fn default() -> Self {
        ErrorMetricsLayer::new()
    }
}

impl<S> Layer<S> for ErrorMetricsLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let level = event.metadata().level();
        if level == &tracing::Level::ERROR {
            ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
        } else if level == &tracing::Level::WARN {
            WARNING_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ── Valkey publisher ─────────────────────────────────────────────────────

/// Spawn a background task that publishes error/warning deltas to Valkey
/// pub/sub channel `stat:metrics:log` every `interval_secs` seconds.
///
/// The payload format matches what captain's `spawn_sentin8_log_metrics_subscriber`
/// expects:
///
/// ```json
/// {
///   "ts": "2026-08-12T17:23:01Z",
///   "source": "self",
///   "window": "10s",
///   "metrics": {
///     "log.errors.sentin8-auth": 3,
///     "log.warnings.sentin8-auth": 12
///   }
/// }
/// ```
///
/// Deltas are computed by tracking the previous cumulative count and
/// subtracting. A daily reset is not needed here — captain resets the
/// accumulated counts at 00:00 UTC.
pub fn spawn_publisher(valkey_url: String, service_name: &str) {
    use crate::valkey_client;
    let service_name = service_name.to_string();
    let interval = Duration::from_secs(10);

    tokio::spawn(async move {
        // If Valkey URL is empty, just silently skip — the service still
        // runs, it just doesn't publish metrics.
        if valkey_url.is_empty() {
            tracing::debug!("error_metrics: VALKEY_URL empty, skipping publisher");
            return;
        }

        // Certificate identity via Valkey GLIDE (group DESIGN.md §3.1):
        // the publisher presents the calling service's own m2m pair.
        // Best-effort by design — a connection failure disables metrics
        // only; glide-core owns reconnection, so a failed PUBLISH is
        // retried on the next tick against the healed connection.
        let client = match valkey_client(&valkey_url, &service_name).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "error_metrics: failed to open Valkey client");
                return;
            }
        };

        let mut prev_errors: i64 = 0;
        let mut prev_warnings: i64 = 0;

        loop {
            tokio::time::sleep(interval).await;

            // Read current cumulative counts.
            let errors = ERROR_COUNT.load(Ordering::Relaxed);
            let warnings = WARNING_COUNT.load(Ordering::Relaxed);

            // Compute deltas.
            let error_delta = errors.saturating_sub(prev_errors);
            let warning_delta = warnings.saturating_sub(prev_warnings);
            prev_errors = errors;
            prev_warnings = warnings;

            // Skip publishing if both deltas are zero (no errors/warnings
            // in this window). This avoids unnecessary Valkey traffic.
            if error_delta == 0 && warning_delta == 0 {
                continue;
            }

            // Build the payload.
            let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            let payload = serde_json::json!({
                "ts": ts,
                "source": "self",
                "window": "10s",
                "metrics": {
                    format!("log.errors.{service_name}"): error_delta,
                    format!("log.warnings.{service_name}"): warning_delta,
                }
            });
            let payload_str = match serde_json::to_string(&payload) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Publish the metric envelope on the `stat:metrics:log` channel.
            if let Err(e) = client
                .publish::<_, _, usize>("stat:metrics:log", payload_str.as_str())
                .await
            {
                tracing::debug!(error = %e, "error_metrics: PUBLISH failed; glide-core will heal the connection");
            }
        }
    });
}

/// Get the current cumulative error/warning counts. Useful for health
/// endpoints or diagnostics.
pub fn counts() -> (i64, i64) {
    (
        ERROR_COUNT.load(Ordering::Relaxed),
        WARNING_COUNT.load(Ordering::Relaxed),
    )
}
