// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-middleware
//!
//! Shared axum middleware for all Sentin8 services.
//!
//! This crate provides:
//! - [`correlation_id`] — generates or propagates `X-Sentin8-Correlation-Id`
//! - [`sentin8_tls_context`] — extracts tenant context from TLS-injected headers
//! - [`request_logging`] — structured request/response logging
//! - [`recovery`] — catches panics and converts them to 500 errors
//! - [`jwks_verifier`] — Auth JWKS-based token verification
//! - [`rate_limit`] — token-bucket rate limiter
//! - [`cors`] — CORS configuration
//! - [`csp`] — Content-Security-Policy headers
//! - [`mtls`] — mTLS reqwest client builder
//! - [`structured_logging`] — JSON structured logging
//! - [`otel_tracing`] — OpenTelemetry tracing
//! - [`metrics`] — Prometheus metrics middleware
//! - [`health`] — health check endpoints
//!
#![deny(missing_docs)]

use std::sync::Arc;

pub mod batched_log;
pub mod context;
pub mod cors;
pub mod csp;
pub mod error_metrics;
pub mod health;
pub mod http_client;
pub mod logging;
pub mod metrics;
pub mod mtls;
pub mod otel_tracing;
pub mod rate_limit;
pub mod recovery;
pub mod valkey;
pub mod shutdown;
pub mod structured_logging;
pub mod traffic_counter;

pub use context::{sentin8_tls_context, TLSContext};
pub use error_metrics::{init_tracing_with_metrics, spawn_publisher, ErrorMetricsLayer};
pub use http_client::{
    attach_context_to, clear_thread_correlation_id, current_context, set_thread_correlation_id,
    Sentin8HttpClient,
};
pub use logging::{correlation_id, request_logging, CorrelationId};
pub use recovery::recovery;
pub use valkey::{valkey_client, valkey_client_pubsub, valkey_client_sync, ValkeyError};
pub use shutdown::shutdown_signal;
pub use structured_logging::{
    init_structured_logging, init_structured_logging_try, CorrelationIdMarker, Sentin8JsonLayer,
    TenantMarker,
};
pub use traffic_counter::{
    process_active_connections, set_process_gauge, spawn_flush_loop, traffic_counter_layer,
    InFlightGuard, RequestCounter,
};

// ── JWKS verifier ────────────────────────────────────────────────────────

/// Configuration for the Auth JWKS verifier.
///
/// A full implementation fetches the JWKS document from
/// `jwks_url` (Auth `/.well-known/jwks.json`), caches the keys, and
/// verifies JWT signatures + claims (issuer, audience, expiry, token type).
#[derive(Debug, Clone)]
pub struct JwksConfig {
    /// Auth issuer URL (e.g. `https://auth.ops.sys.sentin8.local`).
    pub issuer: String,
    /// JWKS endpoint (e.g. `https://auth.ops.sys.sentin8.local/.well-known/jwks.json`).
    pub jwks_url: String,
    /// Expected audience for this service (e.g. `auth`, `ledger`).
    pub audience: String,
}

/// A verified Auth token — the claims needed by the Sentin8 authorization
/// pipeline. The full implementation will parse these from the JWT payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifiedClaims {
    /// Subject — the authenticated principal id.
    pub sub: String,
    /// Issuer (the Auth issuer URL).
    pub iss: String,
    /// Audience the token was issued for.
    pub aud: String,
    /// Expiry (unix seconds).
    pub exp: i64,
    /// Issued-at (unix seconds).
    pub iat: i64,
    /// Unique token id.
    pub jti: String,
    /// `token_tp` claim — token type marker (e.g. "m2m", "access").
    #[serde(rename = "token_tp")]
    pub token_type: String,
    /// `env_id` claim — environment UUID (globally unique, sole tenant key).
    pub env_id: Option<String>,
    /// Space-separated scope string.
    pub scope: String,
}

/// JWKS verifier. The full implementation holds a cached set of RSA public
/// keys and verifies tokens. This scaffold is the interface other services
/// build against.
#[derive(Debug, Clone)]
pub struct JwksVerifier {
    config: Arc<JwksConfig>,
}

impl JwksVerifier {
    /// Build a verifier from its configuration.
    pub fn new(config: JwksConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// The verifier configuration.
    pub fn config(&self) -> &JwksConfig {
        &self.config
    }

    /// Verify a bearer token and return its claims.
    ///
    /// The full implementation will:
    /// 1. Strip the `Bearer ` prefix
    /// 2. Decode the JWT header and find the key ID
    /// 3. Look up the key in the cached JWKS
    /// 4. Verify signature, expiry, issuer, audience, token type
    /// 5. Return the parsed [`VerifiedClaims`]
    pub async fn verify(
        &self,
        _token: &str,
    ) -> Result<VerifiedClaims, sentin8_errors::Sentin8Error> {
        Err(sentin8_errors::Sentin8Error::new(
            sentin8_errors::ErrorCode::AuthTokenInvalid,
            "JWKS verification not yet implemented",
        ))
    }
}

/// Trace layer for structured request/response logging.
///
/// Wraps `tower_http::TraceLayer` which emits spans for each HTTP request
/// with method, URI, and status. The full implementation will
/// add custom `MakeSpan`/`OnRequest`/`OnResponse` closures that include the
/// correlation ID and tenant context from request extensions.
pub fn trace_layer() -> tower_http::trace::TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
> {
    tower_http::trace::TraceLayer::new_for_http()
}
