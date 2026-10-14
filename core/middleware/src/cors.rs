// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # CORS configuration (stories 14.1.5)
//!
//! Returns a configured `tower_http::cors::CorsLayer` for Sentin8 services.
//! Origins are explicitly whitelisted — no wildcard origins in production.
//! Credentials are allowed (for BFF cookie-based auth), so the
//! `Access-Control-Allow-Origin` response is always the specific origin,
//! never `*`.

use axum::http::{HeaderName, HeaderValue, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Build a `CorsLayer` that allows the given origins, the standard Sentin8
/// headers, and the methods used by the platform.
///
/// `origins` must be a list of fully-qualified origin URLs
/// (e.g. `https://sentin8-dash.ops.sys.sentin8.local`). An empty list produces a layer that
/// denies all cross-origin requests.
pub fn cors_config(origins: &[String]) -> CorsLayer {
    let parsed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();

    let allow_origin = if parsed.is_empty() {
        AllowOrigin::exact(HeaderValue::from_static("https://denied.sentin8.local"))
    } else {
        AllowOrigin::list(parsed)
    };

    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
            HeaderName::from_static("x-sentin8-correlation-id"),
            HeaderName::from_static("x-sentin8-env-id"),
            HeaderName::from_static("x-sentin8-app-id"),
            HeaderName::from_static("x-sentin8-service"),
            HeaderName::from_static("x-sentin8-domain-type"),
            HeaderName::from_static("x-fdx-interaction-id"),
            HeaderName::from_static("idempotency-key"),
        ])
        .allow_credentials(true)
        .expose_headers([
            HeaderName::from_static("x-sentin8-correlation-id"),
            HeaderName::from_static("x-fdx-interaction-id"),
            HeaderName::from_static("location"),
        ])
        .max_age(std::time::Duration::from_secs(600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn make_app(origins: &[String]) -> Router {
        Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(cors_config(origins))
    }

    #[tokio::test]
    async fn allows_whitelisted_origin() {
        let app = make_app(&["https://sentin8-dash.ops.sys.sentin8.local".to_string()]);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/ping")
                    .header("origin", "https://sentin8-dash.ops.sys.sentin8.local")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "https://sentin8-dash.ops.sys.sentin8.local"
        );
    }

    #[tokio::test]
    async fn rejects_unknown_origin() {
        let app = make_app(&["https://sentin8-dash.ops.sys.sentin8.local".to_string()]);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/ping")
                    .header("origin", "https://evil.example.com")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // No allow-origin header on rejected preflight.
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn empty_origins_denies_unknown_request_origin() {
        // With no whitelisted origins, the request origin must not be echoed
        // back in access-control-allow-origin (the request origin is
        // "https://anything.sentin8.local" but the only allowed value is the
        // internal "denied" placeholder).
        let app = make_app(&[]);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/ping")
                    .header("origin", "https://anything.sentin8.local")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let allow_origin = resp.headers().get("access-control-allow-origin");
        // The request origin must NOT be echoed back.
        if let Some(ao) = allow_origin {
            assert_ne!(
                ao.to_str().unwrap(),
                "https://anything.sentin8.local",
                "unknown origin must not be allowed"
            );
        }
    }

    #[tokio::test]
    async fn allow_credentials_true() {
        let app = make_app(&["https://sentin8-dash.ops.sys.sentin8.local".to_string()]);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/ping")
                    .header("origin", "https://sentin8-dash.ops.sys.sentin8.local")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("access-control-allow-credentials")
                .unwrap(),
            "true"
        );
    }

    #[tokio::test]
    async fn exposes_correlation_id_header_on_actual_response() {
        // Expose headers are returned on actual responses (not preflight),
        // so we issue a GET request with an Origin header.
        let app = make_app(&["https://sentin8-dash.ops.sys.sentin8.local".to_string()]);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/ping")
                    .header("origin", "https://sentin8-dash.ops.sys.sentin8.local")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let exposed = resp
            .headers()
            .get("access-control-expose-headers")
            .expect("expose-headers should be present on actual response");
        let exposed = exposed.to_str().unwrap();
        assert!(exposed.contains("x-sentin8-correlation-id"));
    }

    #[test]
    fn cors_config_handles_invalid_origin_gracefully() {
        // Invalid header value is filtered out, not panicked.
        let layer = cors_config(&[
            "not a valid origin\n".to_string(),
            "https://ok.sentin8.local".to_string(),
        ]);
        // Building the layer should not panic.
        let _ = layer;
    }
}
