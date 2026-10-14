// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! `context_middleware` trust-model tests — the header-strip
//! self-injection model and host-context resolution behavior.
//!
//! Pure in-process: `MappingCache` fixtures + `tower::ServiceExt::oneshot`
//! against a small axum router. No DB, no sockets.
//!
//! Run: `cargo test -p sentin8-tls` (unit layer, no backing services).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use axum::Router;
use sentin8_tls::cache::MappingCache;
use sentin8_tls::context::{context_middleware, ContextMiddlewareState, HostContextResolver};
use sentin8_tls::resolver::PeerClientCert;
use sentin8_tls_contracts::Mapping;
use tower::ServiceExt;

// ─────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────

/// Build a `Mapping` for a platform service hostname
/// (`{service}.ops.{org}` — env_id = SYSTEM_ENV_ID).
fn platform_mapping(service: &str) -> Mapping {
    Mapping {
        id: uuid::Uuid::new_v4(),
        hostname: format!("{service}.ops.sys.sentin8.local"),
        service: service.to_string(),
        org_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        env_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
        application_id: None,
        backend_url: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Build an app-instance mapping (`{app}.{env}.{org}`) with application_id.
fn app_mapping(app: &str, env: &str) -> Mapping {
    Mapping {
        id: uuid::Uuid::new_v4(),
        hostname: format!("{app}.{env}.ibank22475123.sentin8.local"),
        service: "sentin8:web".to_string(),
        org_id: uuid::Uuid::parse_str("0f5f7c6a-0000-0000-0000-000000000001").unwrap(),
        env_id: uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        application_id: Some(
            uuid::Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
        ),
        backend_url: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Router with one echo route that returns the request's `X-Sentin8-*`
/// headers as a JSON body — lets tests assert what the downstream handler
/// actually received (post-strip, post-injection).
fn echo_router(cache: MappingCache) -> Router {
    let state = ContextMiddlewareState {
        resolver: HostContextResolver::new(cache, "sentin8:test-svc"),
    };
    Router::new()
        .route(
            "/v1/echo",
            get(|req: axum::extract::Request| async move {
                let hdrs: Vec<(String, String)> = req
                    .headers()
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.as_str().to_string(),
                            String::from_utf8_lossy(v.as_bytes()).to_string(),
                        )
                    })
                    .filter(|(k, _)| k.starts_with("x-sentin8-"))
                    .collect();
                axum::Json(serde_json::json!({ "headers": hdrs }))
            }),
        )
        .layer(from_fn_with_state(state, context_middleware))
}

/// Extract a single response header value.
fn resp_header(response: &axum::response::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).to_string())
}

/// Pull the `headers` array (JSON `[[name, value], …]`) out of an echo
/// response body into typed pairs.
async fn echo_headers(response: axum::response::Response) -> Vec<(String, String)> {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    json["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            (
                h[0].as_str().expect("header name").to_string(),
                h[1].as_str().expect("header value").to_string(),
            )
        })
        .collect()
}

// ───────────────────────────────────────────────────────── routers ──────
// Tests
// ─────────────────────────────────────────────────────────────────────────

/// Strip + inject on a resolved host: client-supplied `X-Sentin8-*` headers
/// must not reach the handler; the injected ones carry the cache context.
#[tokio::test]
async fn strips_client_sentin8_headers_and_injects_context() {
    let cache = MappingCache::new();
    cache.set("auth.ops.sys.sentin8.local", platform_mapping("auth"));
    let app = echo_router(cache);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/echo")
                .header("host", "auth.ops.sys.sentin8.local")
                // Attacker-supplied identity headers — must be stripped.
                .header("x-sentin8-env-id", "11111111-1111-1111-1111-111111111111")
                .header("x-sentin8-service", "evil-service")
                .header("x-sentin8-correlation-id", "attacker-correlation")
                .header("x-sentin8-client-cert-thumbprint", "attacker-thumb")
                .header("content-type", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    // Response carries the freshly generated correlation ID (never the
    // attacker's).
    let corr = resp_header(&response, "x-sentin8-correlation-id").expect("correlation id injected");
    assert_ne!(corr, "attacker-correlation");
    assert!(
        uuid::Uuid::parse_str(&corr).is_ok(),
        "correlation id is a UUID: {corr}"
    );
    // The echo body lists what the handler received: injected values, none
    // of the attacker's.
    let headers = echo_headers(response).await;
    let find = |name: &str, hdrs: &[(String, String)]| {
        hdrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
    };
    let env = find("x-sentin8-env-id", &headers).expect("env id injected");
    assert_eq!(env, "00000000-0000-0000-0000-000000000002");
    assert_eq!(find("x-sentin8-service", &headers).as_deref(), Some("auth"));
    assert_eq!(
        find("x-sentin8-hostname", &headers).as_deref(),
        Some("auth.ops.sys.sentin8.local")
    );
    // Attacker values never reached the handler.
    assert!(headers.iter().all(|(_, v)| v != "evil-service"));
    assert!(headers.iter().all(|(_, v)| v != "attacker-thumb"));
    assert!(headers.iter().all(|(_, v)| v != "attacker-correlation"));
}

/// Unregistered hostname → `421 Misdirected Request`.
#[tokio::test]
async fn unregistered_hostname_returns_421() {
    let cache = MappingCache::new();
    let app = echo_router(cache);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/echo")
                .header("host", "unknown.host.sentin8.local")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
}

/// Missing Host header → `400 Bad Request`.
#[tokio::test]
async fn missing_host_returns_400() {
    let cache = MappingCache::new();
    let app = echo_router(cache);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/echo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Health endpoints bypass host resolution (captain probes hit IP:port) —
/// request passes through with only the correlation ID injected.
#[tokio::test]
async fn health_endpoint_bypasses_host_resolution() {
    let cache = MappingCache::new(); // empty cache — would 421 if not bypassed
    let state = ContextMiddlewareState {
        resolver: HostContextResolver::new(cache, "sentin8:test-svc"),
    };
    let app = Router::new()
        .route(
            "/v1/health",
            get(|| async { axum::Json(serde_json::json!({ "status": "ok" })) }),
        )
        .layer(from_fn_with_state(state, context_middleware));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .header("host", "10.0.0.5:8080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let corr = resp_header(&response, "x-sentin8-correlation-id").expect("correlation id");
    assert!(uuid::Uuid::parse_str(&corr).is_ok());
}

/// Client-supplied client-cert headers on a plain request are stripped —
/// they are only legitimate when the TLS accept loop injected them as
/// request extensions.
#[tokio::test]
async fn client_supplied_cert_headers_stripped() {
    let cache = MappingCache::new();
    cache.set("auth.ops.sys.sentin8.local", platform_mapping("auth"));
    let app = echo_router(cache);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/echo")
                .header("host", "auth.ops.sys.sentin8.local")
                .header("x-sentin8-client-cert-subject", "CN=evil")
                .header("x-sentin8-client-cert-thumbprint", "deadbeef")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let headers = echo_headers(response).await;
    assert!(headers
        .iter()
        .all(|(k, _)| k != "x-sentin8-client-cert-subject"));
    assert!(headers
        .iter()
        .all(|(k, _)| k != "x-sentin8-client-cert-thumbprint"));
}

/// When the accept loop places a `PeerClientCert` extension, the
/// middleware computes and injects the `X-Sentin8-Client-Cert-*` headers
/// from it.
#[tokio::test]
async fn peer_cert_extension_injects_cert_headers() {
    use base64::Engine as _;
    use sha2::Digest as _;

    // A minimal DER blob with two CN OIDs (issuer first, then subject) —
    // exercises `extract_cn`'s positional logic.
    let der: Vec<u8> = [
        0x30, 0x82, 0x01, 0x00, // SEQUENCE
        0x06, 0x03, 0x55, 0x04, 0x03, // OID commonName
        0x13, 0x0B, // PrintableString, len 11
    ]
    .iter()
    .copied()
    .chain(b"Test Issuer".iter().copied())
    .chain([0x06, 0x03, 0x55, 0x04, 0x03].iter().copied())
    .chain([0x0C, 0x0C].iter().copied()) // UTF8String, len 12
    .chain(b"Test Subject".iter().copied())
    .collect();

    let cache = MappingCache::new();
    cache.set("auth.ops.sys.sentin8.local", platform_mapping("auth"));
    let state = ContextMiddlewareState {
        resolver: HostContextResolver::new(cache, "sentin8:test-svc"),
    };

    let app = Router::new()
        .route(
            "/v1/echo",
            get(|req: axum::extract::Request| async move {
                let got: Vec<(String, String)> = req
                    .headers()
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.as_str().to_string(),
                            String::from_utf8_lossy(v.as_bytes()).to_string(),
                        )
                    })
                    .filter(|(k, _)| k.starts_with("x-sentin8-client-cert"))
                    .collect();
                axum::Json(serde_json::json!({ "headers": got }))
            }),
        )
        .layer(from_fn_with_state(state, context_middleware));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/echo")
                .header("host", "auth.ops.sys.sentin8.local")
                .extension(PeerClientCert::new(der.clone()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let headers = echo_headers(response).await;
    let find = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    // Thumbprint = base64url-no-pad(SHA-256(DER)) — the RFC 8705 x5t#S256.
    let expected_thumb =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&der));
    assert_eq!(
        find("x-sentin8-client-cert-thumbprint").as_deref(),
        Some(expected_thumb.as_str())
    );
    // Subject is the second CN hit (first is issuer).
    assert_eq!(
        find("x-sentin8-client-cert-subject").as_deref(),
        Some("Test Subject")
    );
    assert_eq!(
        find("x-sentin8-client-cert-issuer").as_deref(),
        Some("Test Issuer")
    );
}

/// App-instance mappings inject `X-Sentin8-App-Id` (the BFF compares it
/// at every session-consuming surface).
#[tokio::test]
async fn app_mapping_injects_app_id_header() {
    let cache = MappingCache::new();
    let m = app_mapping("ebank", "prod");
    cache.set("ebank.prod.ibank22475123.sentin8.local", m);
    let app = echo_router(cache);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/echo")
                .header("host", "ebank.prod.ibank22475123.sentin8.local")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let headers = echo_headers(response).await;
    let app_id = headers
        .iter()
        .find(|(k, _)| k == "x-sentin8-app-id")
        .map(|(_, v)| v.clone())
        .expect("app id injected for app-instance mapping");
    assert_eq!(app_id, "22222222-2222-2222-2222-222222222222");
}

/// Platform-service mappings (no application_id) must NOT inject
/// `X-Sentin8-App-Id`.
#[tokio::test]
async fn platform_mapping_does_not_inject_app_id() {
    let cache = MappingCache::new();
    cache.set("auth.ops.sys.sentin8.local", platform_mapping("auth"));
    let app = echo_router(cache);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/echo")
                .header("host", "auth.ops.sys.sentin8.local")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let headers = echo_headers(response).await;
    assert!(headers.iter().all(|(k, _)| k != "x-sentin8-app-id"));
}
