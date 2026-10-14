// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! TLS context extraction.
//!
//! All Sentin8 services read tenant context from TLS-injected headers rather
//! than performing their own hostname-based tenant resolution. See
//! (See the sentin8-tls design doc for the header contract.)

use axum::{extract::Request, http::HeaderName, middleware::Next, response::Response};
use std::sync::Arc;
use uuid::Uuid;

/// Header injected by TLS carrying the resolved environment UUID.
pub const HEADER_ENV_ID: HeaderName = HeaderName::from_static("x-sentin8-env-id");
/// Header injected by TLS carrying the resolved application UUID (if any).
pub const HEADER_APP_ID: HeaderName = HeaderName::from_static("x-sentin8-app-id");
/// Header injected by TLS carrying the target service name.
pub const HEADER_SERVICE: HeaderName = HeaderName::from_static("x-sentin8-service");
/// Header injected by TLS carrying the original Host header.
pub const HEADER_HOSTNAME: HeaderName = HeaderName::from_static("x-sentin8-hostname");
/// Header injected by TLS carrying the domain type.
pub const HEADER_DOMAIN_TYPE: HeaderName = HeaderName::from_static("x-sentin8-domain-type");
/// Header (propagated or generated) carrying the correlation ID.
pub const HEADER_CORRELATION_ID: HeaderName = HeaderName::from_static("x-sentin8-correlation-id");

/// mTLS client certificate headers (injected by TLS when mTLS is used).
pub const HEADER_CLIENT_CERT_SUBJECT: HeaderName =
    HeaderName::from_static("x-sentin8-client-cert-subject");
/// mTLS client certificate thumbprint header (base64url SHA-256 of DER).
pub const HEADER_CLIENT_CERT_THUMBPRINT: HeaderName =
    HeaderName::from_static("x-sentin8-client-cert-thumbprint");
/// mTLS client certificate issuer CN header (best-effort).
pub const HEADER_CLIENT_CERT_ISSUER: HeaderName =
    HeaderName::from_static("x-sentin8-client-cert-issuer");

/// Tenant context extracted from TLS-injected headers.
///
/// `env_id` is `None` for system-scoped requests
/// (platform Auth, platform BFF). It is required for env-scoped requests
/// and the caller should reject requests where it is missing when expected.
/// `org_id` is no longer carried in the TLS context — it is resolved from
/// `env_id` via DB lookup when needed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TLSContext {
    /// Resolved environment UUID (from `X-Sentin8-Env-Id`). `None` for
    /// system-scoped requests.
    pub env_id: Option<Uuid>,
    /// Resolved application UUID (from `X-Sentin8-App-Id`). `None` for
    /// non-app routes.
    pub application_id: Option<Uuid>,
    /// Target backend service name (from `X-Sentin8-Service`).
    pub service: Option<String>,
    /// Original Host header (from `X-Sentin8-Hostname`).
    pub hostname: Option<String>,
    /// Domain type from the TLS mapping (from `X-Sentin8-Domain-Type`).
    pub domain_type: Option<String>,
    /// mTLS client certificate thumbprint (from `X-Sentin8-Client-Cert-Thumbprint`).
    pub client_cert_thumbprint: Option<String>,
}

impl TLSContext {
    /// Extract the context from a request's headers.
    pub fn from_headers(headers: &axum::http::HeaderMap) -> Self {
        Self {
            env_id: header_uuid(headers, &HEADER_ENV_ID),
            application_id: header_uuid(headers, &HEADER_APP_ID),
            service: header_str(headers, &HEADER_SERVICE),
            hostname: header_str(headers, &HEADER_HOSTNAME),
            domain_type: header_str(headers, &HEADER_DOMAIN_TYPE),
            client_cert_thumbprint: header_str(headers, &HEADER_CLIENT_CERT_THUMBPRINT),
        }
    }

    /// Returns `true` if this is a system-scoped request (no env header).
    pub fn is_system_scoped(&self) -> bool {
        self.env_id.is_none()
    }
}

fn header_str(headers: &axum::http::HeaderMap, name: &HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

fn header_uuid(headers: &axum::http::HeaderMap, name: &HeaderName) -> Option<Uuid> {
    header_str(headers, name).and_then(|s| Uuid::parse_str(&s).ok())
}

/// axum middleware that extracts the TLS context from headers and inserts
/// it into request extensions so handlers can retrieve it via
/// `axum::Extension<Arc<TLSContext>>`.
pub async fn sentin8_tls_context(mut req: Request, next: Next) -> Response {
    let ctx = TLSContext::from_headers(req.headers());
    req.extensions_mut().insert(Arc::new(ctx));
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn extracts_env_app() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ENV_ID,
            "660e8400-e29b-41d4-a716-446655440001".parse().unwrap(),
        );
        headers.insert(
            HEADER_APP_ID,
            "770e8400-e29b-41d4-a716-446655440002".parse().unwrap(),
        );
        headers.insert(HEADER_SERVICE, "bff".parse().unwrap());
        headers.insert(HEADER_HOSTNAME, "bff.www.ibank.local".parse().unwrap());
        headers.insert(HEADER_DOMAIN_TYPE, "app_bff".parse().unwrap());

        let ctx = TLSContext::from_headers(&headers);
        assert_eq!(
            ctx.env_id,
            Some(Uuid::parse_str("660e8400-e29b-41d4-a716-446655440001").unwrap())
        );
        assert_eq!(
            ctx.application_id,
            Some(Uuid::parse_str("770e8400-e29b-41d4-a716-446655440002").unwrap())
        );
        assert_eq!(ctx.service.as_deref(), Some("bff"));
        assert_eq!(ctx.hostname.as_deref(), Some("bff.www.ibank.local"));
        assert_eq!(ctx.domain_type.as_deref(), Some("app_bff"));
        assert!(!ctx.is_system_scoped());
    }

    #[test]
    fn system_scoped_when_empty() {
        let headers = HeaderMap::new();
        let ctx = TLSContext::from_headers(&headers);
        assert!(ctx.env_id.is_none());
        assert!(ctx.is_system_scoped());
    }

    #[test]
    fn ignores_empty_strings() {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_ENV_ID, "".parse().unwrap());
        let ctx = TLSContext::from_headers(&headers);
        assert!(ctx.env_id.is_none());
    }

    #[test]
    fn ignores_invalid_uuids() {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_ENV_ID, "not-a-uuid".parse().unwrap());
        let ctx = TLSContext::from_headers(&headers);
        assert!(ctx.env_id.is_none());
    }
}
