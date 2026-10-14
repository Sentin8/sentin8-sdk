// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Correlation ID and request logging middleware.
//!
//! ## Layers (in recommended install order)
//!
//! 1. [`request_logging`] — opens the root `request` span, captures
//!    `correlation_id` and tenant markers, and emits a single
//!    `request.completed` log line with `method`, `path`, `status`,
//!    `latency_ms`, `correlation_id`, and `tenant` once the response
//!    is built.
//! 2. [`correlation_id`] — generates or propagates `X-Sentin8-Correlation-Id`
//!    so handlers downstream can read it via `axum::Extension<CorrelationId>`.
//! 3. [`sentin8_tls_context`](crate::context::sentin8_tls_context) — extracts
//!    `TLSContext` from TLS-injected headers.
//!
//! `request_logging` is the outermost layer, so it captures the
//! full lifecycle (including the time spent in `correlation_id` and
//! `sentin8_tls_context`).

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::Instrument;
use uuid::Uuid;

use crate::context::TLSContext;

/// The correlation ID header (same value as `X-Sentin8-Correlation-Id` in
/// `context.rs`, redeclared here to avoid a cross-module dependency cycle).
pub const CORRELATION_ID_HEADER: HeaderName = HeaderName::from_static("x-sentin8-correlation-id");

/// Extracted correlation ID, available to handlers via axum extensions.
#[derive(Debug, Clone)]
pub struct CorrelationId(pub String);

impl std::fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Request logging middleware.
///
/// Opens a `request` span, records `method`, `path`, `correlation_id`,
/// and the TLS tenant fields (`env_id`, `app_id`, `service`,
/// `hostname`) on the span, and emits a single structured
/// `request.completed` log line at the end with `status` and
/// `latency_ms`. Every `tracing::*!` call inside the span automatically
/// inherits the correlation_id and tenant fields via the
/// [`Sentin8JsonLayer`](crate::structured_logging::Sentin8JsonLayer).
///
/// This middleware is order-sensitive: install it as the **outermost**
/// layer so the span wraps `correlation_id` and `sentin8_tls_context`.
pub async fn request_logging(mut req: Request, next: Next) -> Response {
    let start = Instant::now();

    // Pull or generate a correlation ID.
    let correlation_id = req
        .headers()
        .get(&CORRELATION_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Ensure the header is on the request (downstream handlers can read
    // it directly).
    if let Ok(val) = HeaderValue::from_str(&correlation_id) {
        req.headers_mut().insert(CORRELATION_ID_HEADER, val.clone());
    }
    req.extensions_mut()
        .insert(CorrelationId(correlation_id.clone()));

    // Pull the TLS tenant context if present.
    let tenant = TLSContext::from_headers(req.headers());

    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    // Build the root request span. We carry the correlation_id and
    // tenant in span *fields* (visible in logs and readable by the
    // Sentin8JsonLayer).
    let span = tracing::info_span!(
        "request",
        method = %method,
        path = %path,
        correlation_id = %correlation_id,
        env_id = %tenant.env_id.map(|u| u.to_string()).unwrap_or_default(),
        app_id = %tenant.application_id.map(|u| u.to_string()).unwrap_or_default(),
        service = %tenant.service.clone().unwrap_or_default(),
        hostname = %tenant.hostname.clone().unwrap_or_default(),
    );

    // Set the thread-local service name so Sentin8HttpClient can attach
    // it as `x-sentin8-caller-service` on outgoing inter-service calls.
    if let Some(ref svc) = tenant.service {
        crate::http_client::set_thread_service(svc);
    }

    // Run the rest of the stack inside the span, then collect the
    // response and emit the request.completed log line.
    let resp = next.run(req).instrument(span.clone()).await;

    // Clear the thread-local service name after the request completes.
    crate::http_client::clear_thread_service();

    let status = resp.status().as_u16();
    let latency_ms = start.elapsed().as_millis() as u64;

    // Attach the correlation ID to the response.
    let mut resp = resp;
    if let Ok(val) = HeaderValue::from_str(&correlation_id) {
        resp.headers_mut().insert(CORRELATION_ID_HEADER, val);
    }

    // Emit the request.completed log line. Because we're inside the
    // span, the JSON layer will automatically attach correlation_id
    // and tenant fields.
    //
    // High-frequency polling endpoints (`/v1/health` probed by Captain
    // every 10s, `/v1/captain/services` polled by the dashboard) would
    // drown the log at `info` level, so they are demoted to `debug`.
    let is_noisy_path = is_polling_endpoint(&path);
    span.in_scope(|| {
        if is_noisy_path {
            tracing::debug!(
                method = %method,
                path = %path,
                status = status,
                latency_ms = latency_ms,
                "request.completed"
            );
        } else {
            tracing::info!(
                method = %method,
                path = %path,
                status = status,
                latency_ms = latency_ms,
                "request.completed"
            );
        }
    });

    resp
}

/// Returns `true` for high-frequency polling endpoints whose
/// `request.completed` log line is demoted from `info` to `debug` to
/// keep the logfile readable.
///
/// Currently covers:
/// - `/v1/health` — probed by Sentin8:Captain for every service every 10s.
/// - `/v1/captain/services` (and its `/v1/captain/services/{key}` sub-paths)
///   — polled by the dashboard and the CLI.
fn is_polling_endpoint(path: &str) -> bool {
    // Strip the query string before matching.
    let path = path.split('?').next().unwrap_or(path);

    // Exact match for the plain health probe.
    if path == "/v1/health" {
        return true;
    }

    // Captain service-list polling: `/v1/captain/services` exactly, or any
    // sub-path like `/v1/captain/services/{key}`. The catalog endpoint
    // `/v1/captain/catalog` is low-frequency and stays at `info`.
    if path == "/v1/captain/services"
        || path == "/v1/captain/machines"
        || path.starts_with("/v1/captain/services/")
    {
        return true;
    }

    false
}

/// Legacy alias for [`request_logging`] — installed as the outermost
/// layer to keep span fields populated. Kept for backwards compatibility
/// with code that imports the old name.
pub async fn correlation_id(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(&CORRELATION_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    if let Ok(val) = HeaderValue::from_str(&id) {
        req.headers_mut().insert(CORRELATION_ID_HEADER, val.clone());
    }
    req.extensions_mut().insert(CorrelationId(id.clone()));

    let mut resp = next.run(req).await;
    if let Ok(val) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert(CORRELATION_ID_HEADER, val);
    }
    resp
}

/// Trace layer wrapper that provides structured request/response logging.
///
/// The full implementation lives in [`request_logging`]. This is kept
/// for backwards compatibility with services that already import it.
pub fn request_logging_layer() -> tower_http::trace::TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
> {
    tower_http::trace::TraceLayer::new_for_http()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    #[tokio::test]
    async fn correlation_id_generates_when_absent() {
        let app = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(axum::middleware::from_fn(correlation_id));
        let resp = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/ping")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(CORRELATION_ID_HEADER));
    }

    #[tokio::test]
    async fn correlation_id_preserves_incoming() {
        let app = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(axum::middleware::from_fn(correlation_id));
        let resp = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/ping")
                    .header(CORRELATION_ID_HEADER, "corr-abc-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.headers().get(CORRELATION_ID_HEADER).unwrap(),
            "corr-abc-123"
        );
    }

    #[tokio::test]
    async fn request_logging_emits_correlation_id_header() {
        let app = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(axum::middleware::from_fn(request_logging));
        let resp = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/ping")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(CORRELATION_ID_HEADER));
    }

    #[tokio::test]
    async fn request_logging_preserves_incoming_correlation_id() {
        let app = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(axum::middleware::from_fn(request_logging));
        let resp = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/ping")
                    .header(CORRELATION_ID_HEADER, "fixed-cid-99")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.headers().get(CORRELATION_ID_HEADER).unwrap(),
            "fixed-cid-99"
        );
    }

    #[test]
    fn is_polling_endpoint_classifies_noisy_paths() {
        assert!(is_polling_endpoint("/v1/health"));
        assert!(is_polling_endpoint("/v1/health?foo=bar"));
        assert!(is_polling_endpoint("/v1/captain/services"));
        assert!(is_polling_endpoint("/v1/captain/services/10.0.0.1:8443"));
        assert!(is_polling_endpoint(
            "/v1/captain/services/10.0.0.1:8443?active=true"
        ));

        // Non-polling endpoints stay at `info`.
        assert!(!is_polling_endpoint("/v1/captain/catalog"));
        assert!(!is_polling_endpoint("/v1/captain/services-something"));
        assert!(!is_polling_endpoint("/v1/accounts"));
        assert!(!is_polling_endpoint("/"));
    }
}
