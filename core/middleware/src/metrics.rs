// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # Prometheus metrics
//!
//! Provides an Axum middleware that records per-request Prometheus metrics
//! (total requests, error count, latency histogram) and a `/metrics`
//! endpoint handler that exports the metrics in Prometheus text format.
//!
//! ## Usage
//!
//! ```text
//! use sentin8_middleware::metrics::{MetricsConfig, prometheus_middleware, metrics_handler};
//!
//! let app = axum::Router::new()
//!     .route("/metrics", axum::routing::get(metrics_handler))
//!     .route("/api/*", /* ... */)
//!     .layer(prometheus_middleware());
//! ```

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Configuration for the Prometheus metrics middleware.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// The path at which the `/metrics` endpoint is served.
    pub path: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            path: "/metrics".to_string(),
        }
    }
}

/// Aggregated request metrics — the in-memory counters that the middleware
/// updates and the `/metrics` handler exports.
#[derive(Debug, Default)]
pub struct RequestMetrics {
    /// Total number of requests seen.
    pub total_requests: AtomicU64,
    /// Number of requests that returned a 5xx status.
    pub error_count: AtomicU64,
    /// Sum of all request latencies in microseconds.
    pub latency_sum_us: AtomicU64,
    /// Number of requests that returned a 4xx status.
    pub client_error_count: AtomicU64,
}

impl RequestMetrics {
    /// Create a fresh metrics struct.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a completed request.
    pub fn record(&self, status: StatusCode, latency_us: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.latency_sum_us.fetch_add(latency_us, Ordering::Relaxed);
        let code = status.as_u16();
        if code >= 500 {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        } else if code >= 400 {
            self.client_error_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Render the metrics as a Prometheus text-format string.
    pub fn render(&self) -> String {
        let total = self.total_requests.load(Ordering::Relaxed);
        let errors = self.error_count.load(Ordering::Relaxed);
        let client_errors = self.client_error_count.load(Ordering::Relaxed);
        let latency_us = self.latency_sum_us.load(Ordering::Relaxed);
        let avg_latency_ms = if total > 0 {
            (latency_us as f64 / 1000.0_f64) / (total as f64)
        } else {
            0.0_f64
        };
        format!(
            "# HELP sentin8_requests_total Total number of HTTP requests.\n\
             # TYPE sentin8_requests_total counter\n\
             sentin8_requests_total {total}\n\
             # HELP sentin8_request_errors_total Number of requests that returned 5xx.\n\
             # TYPE sentin8_request_errors_total counter\n\
             sentin8_request_errors_total {errors}\n\
             # HELP sentin8_request_client_errors_total Number of requests that returned 4xx.\n\
             # TYPE sentin8_request_client_errors_total counter\n\
             sentin8_request_client_errors_total {client_errors}\n\
             # HELP sentin8_request_latency_microseconds_sum Sum of request latencies in microseconds.\n\
             # TYPE sentin8_request_latency_microseconds_sum counter\n\
             sentin8_request_latency_microseconds_sum {latency_us}\n\
             # HELP sentin8_request_latency_avg_milliseconds Average request latency in milliseconds.\n\
             # TYPE sentin8_request_latency_avg_milliseconds gauge\n\
             sentin8_request_latency_avg_milliseconds {avg_latency_ms}\n"
        )
    }
}

/// Shared metrics state — cloneable (wraps `Arc`).
#[derive(Debug, Clone)]
pub struct SharedMetrics {
    inner: Arc<RequestMetrics>,
}

impl SharedMetrics {
    /// Create a new shared metrics struct.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RequestMetrics::new()),
        }
    }

    /// Access the underlying `RequestMetrics`.
    pub fn metrics(&self) -> &RequestMetrics {
        &self.inner
    }
}

impl Default for SharedMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Axum middleware that records per-request metrics. Install with
/// `axum::middleware::from_fn_with_state(shared, prometheus_middleware)`.
pub async fn prometheus_middleware(
    metrics: axum::extract::State<SharedMetrics>,
    req: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let resp = next.run(req).await;
    let latency_us = start.elapsed().as_micros() as u64;
    metrics.metrics().record(resp.status(), latency_us);
    resp
}

/// Axum handler for the `/metrics` endpoint. Returns the Prometheus
/// text-format body with `Content-Type: text/plain; version=0.0.4`.
pub async fn metrics_handler(
    axum::extract::State(metrics): axum::extract::State<SharedMetrics>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        metrics.metrics().render(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    #[test]
    fn record_increments_total() {
        let m = RequestMetrics::new();
        m.record(StatusCode::OK, 100);
        m.record(StatusCode::OK, 200);
        assert_eq!(m.total_requests.load(Ordering::Relaxed), 2);
        assert_eq!(m.latency_sum_us.load(Ordering::Relaxed), 300);
    }

    #[test]
    fn record_counts_5xx_as_errors() {
        let m = RequestMetrics::new();
        m.record(StatusCode::INTERNAL_SERVER_ERROR, 50);
        m.record(StatusCode::BAD_GATEWAY, 50);
        assert_eq!(m.error_count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn record_counts_4xx_as_client_errors() {
        let m = RequestMetrics::new();
        m.record(StatusCode::BAD_REQUEST, 10);
        m.record(StatusCode::NOT_FOUND, 10);
        assert_eq!(m.client_error_count.load(Ordering::Relaxed), 2);
        assert_eq!(m.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn render_includes_help_and_type_lines() {
        let m = RequestMetrics::new();
        m.record(StatusCode::OK, 1000);
        let out = m.render();
        assert!(out.contains("# HELP sentin8_requests_total"));
        assert!(out.contains("# TYPE sentin8_requests_total counter"));
        assert!(out.contains("sentin8_requests_total 1"));
    }

    #[test]
    fn render_avg_latency_is_zero_when_no_requests() {
        let m = RequestMetrics::new();
        let out = m.render();
        assert!(out.contains("sentin8_request_latency_avg_milliseconds 0"));
    }

    #[test]
    fn render_avg_latency_correct() {
        let m = RequestMetrics::new();
        m.record(StatusCode::OK, 1_000); // 1ms
        m.record(StatusCode::OK, 3_000); // 3ms
        let out = m.render();
        // avg = (1000 + 3000) / 2 / 1000 = 2.0 ms
        assert!(out.contains("sentin8_request_latency_avg_milliseconds 2"));
    }

    #[test]
    fn shared_metrics_clone_shares_state() {
        let a = SharedMetrics::new();
        let b = a.clone();
        a.metrics().record(StatusCode::OK, 100);
        assert_eq!(b.metrics().total_requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn metrics_handler_returns_prometheus_text() {
        let metrics = SharedMetrics::new();
        metrics.metrics().record(StatusCode::OK, 500);
        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .with_state(metrics);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("text/plain"));
    }

    #[tokio::test]
    async fn middleware_records_metrics() {
        let metrics = SharedMetrics::new();
        let app = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(axum::middleware::from_fn_with_state(
                metrics.clone(),
                prometheus_middleware,
            ));
        let resp = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(metrics.metrics().total_requests.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn default_metrics_config_path() {
        let c = MetricsConfig::default();
        assert_eq!(c.path, "/metrics");
    }
}
