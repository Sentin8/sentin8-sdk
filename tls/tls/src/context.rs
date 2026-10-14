// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Host-context resolution and `X-Sentin8-*` header injection middleware.
//!
//! `context_middleware()` is an axum layer that:
//! 1. Strips any client-supplied `X-Sentin8-*` headers (self-injection trust model).
//! 2. Resolves the `Host` header via `HostContextResolver` (cache first, then
//!    DB-based domain-pattern deduction).
//! 3. Injects `X-Sentin8-Env-Id`, `X-Sentin8-App-Id`,
//!    `X-Sentin8-Service`, `X-Sentin8-Hostname`, `X-Sentin8-Domain-Type`,
//!    `X-Sentin8-Correlation-Id`.
//!
//! If the `Host` header cannot be resolved, the request
//! is rejected with `421 Misdirected Request`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use sentin8_config::SYSTEM_ENV_ID;
use sentin8_tls_contracts::Mapping;
use uuid::Uuid;

use crate::cache::MappingCache;

// Standard X-Sentin8-* header names.
const HEADER_ENV_ID: &str = "x-sentin8-env-id";
const HEADER_APP_ID: &str = "x-sentin8-app-id";
const HEADER_SERVICE: &str = "x-sentin8-service";
const HEADER_HOSTNAME: &str = "x-sentin8-hostname";
const HEADER_DOMAIN_TYPE: &str = "x-sentin8-domain-type";
const HEADER_CORRELATION_ID: &str = "x-sentin8-correlation-id";
const HEADER_CALLER_SERVICE: &str = "x-sentin8-caller-service";
const HEADER_CLIENT_CERT_SUBJECT: &str = "x-sentin8-client-cert-subject";
const HEADER_CLIENT_CERT_THUMBPRINT: &str = "x-sentin8-client-cert-thumbprint";
const HEADER_CLIENT_CERT_ISSUER: &str = "x-sentin8-client-cert-issuer";
const HEADER_CLIENT_CERT_CHAIN: &str = "x-sentin8-client-cert-chain";

/// All `X-Sentin8-*` headers that the middleware strips from client requests
/// before injecting its own.
const SENTIN8_HEADERS: &[&str] = &[
    HEADER_ENV_ID,
    HEADER_APP_ID,
    HEADER_SERVICE,
    HEADER_HOSTNAME,
    HEADER_DOMAIN_TYPE,
    HEADER_CORRELATION_ID,
    HEADER_CALLER_SERVICE,
    HEADER_CLIENT_CERT_SUBJECT,
    HEADER_CLIENT_CERT_THUMBPRINT,
    HEADER_CLIENT_CERT_ISSUER,
    HEADER_CLIENT_CERT_CHAIN,
];

/// Resolves the `Host` header to a `Mapping` (host context): exact cache
/// match first, then a static platform-plane pattern, then the Sys owner
/// API (`GET /v1/resolve/hostname`) for tenant hostnames.
///
/// TLS-RLS-4 (design/sentin8-vertical-data-plane-contract.md §VDC.7): the
/// resolver is DATABASE-FREE. The library never opens a SQL connection —
/// a vertical service embedding it must not gain any platform-database
/// access (no DSN, no role, no grants), and platform services no longer
/// need routing-table grants for the library path either. Sys owns the
/// hostname tables; its resolve endpoint is the sanctioned read path for
/// TENANT hostnames (M2M `sentin8:sys:instances:read`, cert-bound
/// `{service}-tls` workload), identical for platform and vertical
/// services. PLATFORM hostnames (`{label}.ops.sys.{domain}`) resolve via
/// [`static_platform_mapping`] with no network — a runtime Sys dependency
/// there would deadlock the boot order (Sys needs auth; auth's requests
/// need resolution).
#[derive(Clone)]
pub struct HostContextResolver {
    cache: MappingCache,
    /// Sys base URL (`SENTIN8_SYS_URL` / derived platform domain).
    sys_url: String,
    /// The embedding service's identity (dash form) — names its `-tls`
    /// certificate workload (`bank8-ledger-tls`).
    service_identity: String,
    /// Cert-presenting transport for the resolve call (built lazily on
    /// first cache miss — the `{dash}-tls` certificate IS the
    /// identity; no token is fetched). Shared behind an RwLock so
    /// concurrent misses build it once.
    resolve_http:
        std::sync::Arc<tokio::sync::RwLock<Option<std::sync::Arc<reqwest::Client>>>>,
}

impl HostContextResolver {
    /// Build a resolver over a pre-loaded mapping cache with the Sys owner
    /// API as the miss path.
    ///
    /// `service_identity` names the embedding service (e.g. `bank8:ledger`);
    /// resolve calls present its cert-bound `{dash}-tls` workload identity.
    pub fn new(cache: MappingCache, service_identity: &str) -> Self {
        let cfg = sentin8_config::Sentin8Config::from_env();
        let sys_url = std::env::var("SENTIN8_SYS_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| cfg.sentin8_sys_url());
        Self {
            cache,
            sys_url,
            service_identity: sentin8_config::service_dash_form(service_identity),
            resolve_http: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    /// Resolve a hostname to a mapping.
    ///
    /// 1. Exact match in the positive cache.
    /// 2. **Platform-plane static pattern** — `{label}.ops.sys.{domain}`
    ///    hostnames map with ZERO lookups (service = the registry label,
    ///    org = SYSTEM_ORG_ID, env = SYSTEM_ENV_ID, no app instance).
    ///    This breaks the boot circularity: a booting service (or any
    ///    service while Sys is down) must still resolve the PLATFORM
    ///    hostnames it depends on (auth, acme, bus…) — resolving them
    ///    through a runtime Sys call would make every request depend on
    ///    Sys (and Sys's on auth), a hard deadlock during boot. The
    ///    platform plane is static by construction (the System org/env
    ///    are well-known constants; the subdomain label → service_type
    ///    mapping is carried in `SENTIN8_TLS_PLATFORM_LABELS`, propagated
    ///    by captain from the runtime registry).
    /// 3. Miss → Sys `GET /v1/resolve/hostname` (owner API) for TENANT
    ///    hostnames ({service}.{env}.{org}); a successful resolve
    ///    populates the cache. Transient failures (Sys booting, DCR
    ///    pending) are NOT negatively cached — the next request retries;
    ///    a genuine 404 (unresolvable hostname) returns `None` without
    ///    caching.
    pub async fn resolve(&self, hostname: &str) -> Option<Arc<Mapping>> {
        // 1. Exact match in the cache.
        if let Some(m) = self.cache.get(hostname) {
            return Some(m);
        }

        // 2. Platform-plane static pattern (no network, no Sys dependency).
        if let Some(m) = static_platform_mapping(hostname) {
            self.cache.set(hostname, m.clone());
            return Some(Arc::new(m));
        }

        // 3. Owner-API resolution (tenant hostnames).
        match self.resolve_via_sys(hostname).await {
            Ok(Some(mapping)) => {
                self.cache.set(hostname, mapping.clone());
                Some(Arc::new(mapping))
            }
            Ok(None) => {
                tracing::debug!(hostname, "sentin8-tls: hostname unresolvable (Sys 404)");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, hostname, "sentin8-tls: resolve via Sys failed");
                None
            }
        }
    }

    /// Call Sys `GET /v1/resolve/hostname?hostname=…` presenting the
    /// embedding service's `{service}-tls` CERTIFICATE identity
    /// ( — Sys's TLS layer authenticates the workload from the
    /// handshake; no token exists on this path).
    ///
    /// # Errors
    ///
    /// Returns `Err` for transport/5xx/401/403 failures (retryable) and
    /// `Ok(None)` for a 404 (the hostname genuinely does not resolve).
    async fn resolve_via_sys(&self, hostname: &str) -> Result<Option<Mapping>, String> {
        let http = self.resolve_transport().await?;

        let url = format!(
            "{}/v1/resolve/hostname?hostname={}",
            self.sys_url.trim_end_matches('/'),
            hostname
        );
        let resp = http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("resolve request: {e}"))?;

        match resp.status() {
            s if s.is_success() => {
                let v: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| format!("resolve decode: {e}"))?;
                let parse = |k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
                let service = parse("service").ok_or("resolve response missing service")?;
                let org_id = parse("org_id")
                    .and_then(|s| Uuid::parse_str(&s).ok())
                    .ok_or("resolve response missing org_id")?;
                // `env_id` is absent for system-scoped hostnames — the
                // middleware injects no env header then (platform-scope
                // requests). SYSTEM_ENV_ID fills the non-optional field.
                let env_id = parse("env_id")
                    .and_then(|s| Uuid::parse_str(&s).ok())
                    .unwrap_or(SYSTEM_ENV_ID);
                let application_id = parse("app_id").and_then(|s| Uuid::parse_str(&s).ok());
                let now = chrono::Utc::now();
                Ok(Some(Mapping {
                    id: Uuid::new_v4(),
                    hostname: hostname.to_string(),
                    service,
                    org_id,
                    env_id,
                    application_id,
                    backend_url: None,
                    created_at: now,
                    updated_at: now,
                }))
            }
            reqwest::StatusCode::NOT_FOUND => Ok(None),
            s => Err(format!("resolve returned {s}")),
        }
    }

    /// Build the cert-presenting transport for the resolve call, ensuring
    /// the `{service}-tls` workload certificate on first use
    /// (`ensure_workload_certificate` — mint-if-missing; the grant must be
    /// declared in the embedding service's `m2m_grants` registration for
    /// Sys's registry-map authorization).
    async fn resolve_transport(&self) -> Result<std::sync::Arc<reqwest::Client>, String> {
        {
            let guard = self.resolve_http.read().await;
            if let Some(http) = guard.as_ref() {
                return Ok(std::sync::Arc::clone(http));
            }
        }
        // Fail-soft before touching the m2m crate: `platform_ca_pem_path`
        // PANICS when no CA is configured (correct for real M2M callers —
        // fail-closed identity channel). The RESOLVER must degrade to a
        // 421 instead of crashing the request handler: a cache-miss
        // resolve simply cannot run without the CA, and the next request
        // retries once the operator env is present (captain always
        // propagates it).
        let ca_configured = ["SENTIN8_TLS_CA_PEM", "SENTIN8_TLS_CLIENT_CA_PEM"]
            .iter()
            .any(|v| {
                std::env::var(v)
                    .map(|p| !p.trim().is_empty())
                    .unwrap_or(false)
            });
        if !ca_configured {
            return Err("platform CA not configured — resolve unavailable".into());
        }
        let mut guard = self.resolve_http.write().await;
        if let Some(http) = guard.as_ref() {
            return Ok(std::sync::Arc::clone(http));
        }
        let cfg = sentin8_config::Sentin8Config::from_env();
        let auth_issuer = cfg.sentin8_auth_issuer();
        let workload = format!("{}-tls", self.service_identity);
        let cert = sentin8_m2m::ensure_workload_certificate(
            &auth_issuer,
            &workload,
            &sentin8_m2m::platform_ca_path(),
        )
        .await
        .map_err(|e| format!("workload certificate for '{workload}': {e}"))?;
        // Bounded (BOUNDED-OUTBOUND): the miss path runs INSIDE the request
        // handler's TLS handshake — an unbounded resolve would hang the
        // handshake indefinitely. The miss path itself is the cache-seed
        // exception to the per-request rule (TLS-RLS-4: resolve on miss).
        let ca_pem = std::fs::read(&cert.ca_cert_path)
            .map_err(|e| format!("read CA cert: {e}"))?;
        let ca_cert_obj = reqwest::Certificate::from_pem(&ca_pem)
            .map_err(|e| format!("parse CA cert: {e}"))?;
        let mut identity_pem = cert.cert_pem.as_bytes().to_vec();
        identity_pem.extend_from_slice(cert.key_pem.as_bytes());
        let identity = reqwest::Identity::from_pem(&identity_pem)
            .map_err(|e| format!("build client identity: {e}"))?;
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .add_root_certificate(ca_cert_obj)
            .identity(identity)
            .danger_accept_invalid_certs(false)
            .https_only(true)
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| format!("resolve client: {e}"))?;
        let client = std::sync::Arc::new(client);
        *guard = Some(std::sync::Arc::clone(&client));
        Ok(client)
    }
}

/// The platform-plane static hostname pattern (TLS-RLS-4): map
/// `{label}.ops.sys.{sentin8_domain}` to its service + the System org/env
/// with ZERO lookups.
///
/// Why static: a runtime resolve (Sys API) for PLATFORM hostnames would
/// make every request depend on Sys — and Sys's own boot depends on auth,
/// whose inbound requests depend on resolution: a hard circular dependency
/// that deadlocks cold starts and restart spirals. The platform plane is
/// static by construction: the System org/env ids are well-known platform
/// constants, and the subdomain-label → service_type mapping is
/// bootstrapped via `SENTIN8_TLS_PLATFORM_LABELS` (captain propagates it
/// from the runtime registry; defaults cover the core platform).
///
/// Returns `None` for anything that is not a 3-label
/// `{label}.ops.sys.{domain}` platform hostname (tenant hostnames go
/// through the Sys owner API).
fn static_platform_mapping(hostname: &str) -> Option<Mapping> {
    let cfg = sentin8_config::Sentin8Config::from_env();
    let expected_suffix = format!("ops.sys.{}", cfg.sentin8_domain);
    let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    // Exactly `{label}.ops.sys.{domain}` — no more, no fewer (tenant
    // hostnames carry an env label and go via Sys).
    if labels.len() != 3 + cfg.sentin8_domain.split('.').count() {
        return None;
    }
    let suffix = labels[1..].join(".");
    if suffix != expected_suffix {
        return None;
    }
    let label = labels[0];
    // The label → service_type map: env override first, then the built-in
    // core-platform defaults (every platform service's subdomain is its
    // leaf name; vertical services use their dash identity).
    let service = platform_service_for_label(label)?;
    let now = chrono::Utc::now();
    Some(Mapping {
        id: Uuid::new_v4(),
        hostname: hostname.to_string(),
        service,
        org_id: sentin8_config::SYSTEM_ORG_ID,
        env_id: SYSTEM_ENV_ID,
        application_id: None,
        backend_url: None,
        created_at: now,
        updated_at: now,
    })
}

/// Resolve a platform subdomain label to its full service identity.
/// Order: `SENTIN8_TLS_PLATFORM_LABELS` (comma-separated `label:service`
/// pairs, captain-propagated from the runtime registry — the authoritative
/// source covering vertical subdomains too) → the built-in core-platform
/// table (`label` == the platform leaf: `auth` → `sentin8:auth`).
fn platform_service_for_label(label: &str) -> Option<String> {
    if label.is_empty() {
        return None;
    }
    if let Ok(pairs) = std::env::var("SENTIN8_TLS_PLATFORM_LABELS") {
        for pair in pairs.split(',') {
            if let Some((l, svc)) = pair.trim().split_once(':') {
                if l.trim().eq_ignore_ascii_case(label) {
                    let svc = svc.trim();
                    return (!svc.is_empty()).then(|| svc.to_string());
                }
            }
        }
    }
    // Core-platform default: the label is the leaf of a platform service
    // (`auth` → `sentin8:auth`). Vertical subdomains MUST come via the
    // env override — a bare vertical label here is a misconfiguration
    // (missing propagation), and returning a fabricated platform identity
    // would misroute; fail the resolve instead (421, loud).
    Some(sentin8_config::canonical_service_type(&format!(
        "sentin8-{label}"
    )))
}

/// The state passed to `context_middleware`. Holds the `HostContextResolver`.
#[derive(Clone)]
pub struct ContextMiddlewareState {
    /// Resolves request hostnames to tenant context (cache + deduction).
    pub resolver: HostContextResolver,
}

/// The axum middleware for `X-Sentin8-*` header injection.
///
/// # Errors
/// Returns `400` when the `Host` header is missing, and `421 Misdirected
/// Request` when the host cannot be resolved.
///
/// Usage:
/// ```text
/// use sentin8_tls::context_middleware;
/// use sentin8_tls::context::ContextMiddlewareState;
///
/// let state = ContextMiddlewareState { resolver };
/// let app = Router::new()
///     .route("/v1/health", get(health))
///     .layer(axum::middleware::from_fn_with_state(state, context_middleware));
/// ```
pub async fn context_middleware(
    State(state): State<ContextMiddlewareState>,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers().clone();

    // 1. Extract the Host header (strip port if present).
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default();

    if host.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // 2. Resolve the host context.
    //
    // Bypass host resolution for health endpoints — captain's health
    // probes hit the service directly on IP:port (not through proxy),
    // so the Host header is a raw IP, not a registered domain.
    // Without this bypass, the middleware would return 421 and captain
    // would kill the service for failing health checks.
    let is_health = request.uri().path().ends_with("/health")
        || request.uri().path() == "/v1/health"
        || request.uri().path() == "/health";

    let mapping = if is_health {
        // Return early with just the correlation ID — no host context.
        let mut new_headers = headers.clone();
        // Strip client-supplied X-Sentin8-* headers.
        for name in SENTIN8_HEADERS.iter() {
            if let Ok(hname) = HeaderName::from_bytes(name.as_bytes()) {
                new_headers.remove(&hname);
            }
        }
        let correlation_id = Uuid::new_v4().to_string();
        inject_header(&mut new_headers, HEADER_CORRELATION_ID, &correlation_id);

        let (mut parts, body) = request.into_parts();
        parts.headers = new_headers;
        let request = axum::extract::Request::from_parts(parts, body);

        let mut response = next.run(request).await;

        if let Ok(correlation) = HeaderValue::from_str(&correlation_id) {
            let hname = HeaderName::from_static(HEADER_CORRELATION_ID);
            response.headers_mut().insert(hname, correlation);
        }

        return Ok(response);
    } else {
        state
            .resolver
            .resolve(&host)
            .await
            .ok_or(StatusCode::MISDIRECTED_REQUEST)?
    };

    // 3. Strip client-supplied X-Sentin8-* headers and inject our own.
    let mut new_headers = HeaderMap::new();
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_ascii_lowercase();
        if SENTIN8_HEADERS.contains(&name_str.as_str()) {
            continue;
        }
        new_headers.insert(name.clone(), value.clone());
    }

    // 4. Inject the resolved context headers.
    inject_header(&mut new_headers, HEADER_ENV_ID, &mapping.env_id.to_string());
    inject_header(&mut new_headers, HEADER_SERVICE, &mapping.service);
    inject_header(&mut new_headers, HEADER_HOSTNAME, &host);

    if let Some(app_id) = mapping.application_id {
        inject_header(&mut new_headers, HEADER_APP_ID, &app_id.to_string());
    }

    // Correlation ID: generate a new one (we stripped the client's copy).
    let correlation_id = Uuid::new_v4().to_string();
    inject_header(&mut new_headers, HEADER_CORRELATION_ID, &correlation_id);

    // Inject the mTLS peer certificate headers when the TLS handshake
    // carried a client certificate (extension placed by the accept loop).
    // These headers were also stripped above as client-supplied copies —
    // this is the only legitimate source.
    if let Some(peer) = request
        .extensions()
        .get::<crate::resolver::PeerClientCert>()
        .cloned()
    {
        inject_client_cert_headers(&mut new_headers, &peer.der);
    }

    // 5. Forward the request with the new headers.
    let (mut parts, body) = request.into_parts();
    parts.headers = new_headers;
    let request = axum::extract::Request::from_parts(parts, body);

    let mut response = next.run(request).await;

    // Add correlation ID to the response.
    if let Ok(correlation) = HeaderValue::from_str(&correlation_id) {
        let hname = HeaderName::from_static(HEADER_CORRELATION_ID);
        response.headers_mut().insert(hname, correlation);
    }

    Ok(response)
}

fn inject_header(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(hname), Ok(hvalue)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(hname, hvalue);
    }
}

/// Compute and inject the `X-Sentin8-Client-Cert-*` headers from a peer
/// certificate.
///
/// - `X-Sentin8-Client-Cert-Thumbprint` — base64url(SHA-256(DER)) = `x5t#S256`
/// - `X-Sentin8-Client-Cert-Subject` — best-effort subject CN from the DER
/// - `X-Sentin8-Client-Cert-Issuer` — best-effort issuer CN from the DER
///
/// Subject/issuer extraction is deliberately minimal (no full X.509 parser
/// dependency): the thumbprint is the security-relevant value (RFC 8705 —
/// Sentin8:Auth validates it against the registered thumbprint); the DN
/// fields are informational.
fn inject_client_cert_headers(headers: &mut HeaderMap, cert_der: &[u8]) {
    use base64::Engine as _;
    use sha2::Digest as _;

    let thumb =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(cert_der));
    inject_header(headers, HEADER_CLIENT_CERT_THUMBPRINT, &thumb);

    if let Some(subject) = extract_cn(cert_der, true) {
        inject_header(headers, HEADER_CLIENT_CERT_SUBJECT, &subject);
    }
    if let Some(issuer) = extract_cn(cert_der, false) {
        inject_header(headers, HEADER_CLIENT_CERT_ISSUER, &issuer);
    }
}

/// Best-effort CN extraction from a DER certificate (subject when
/// `subject`, else issuer). Walks the TLV structure looking for the
/// CommonName OID (2.5.4.3 = 55 04 03) and returns the following
/// PrintableString/UTF8String value. Returns None on any parse difficulty —
/// the thumbprint header is the security-critical one.
fn extract_cn(der: &[u8], subject: bool) -> Option<String> {
    // Locate the tbsCertificate: SEQUENCE { version [0], serialNumber,
    // signature AlgorithmIdentifier, issuer Name, validity, subject Name, ... }
    // We scan for the CN OID pattern and take the next string. Both issuer
    // and subject carry the same OID, so for `subject` we skip the first
    // occurrence.
    let oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let mut hits = Vec::new();
    let mut i = 0;
    while i + oid.len() + 2 <= der.len() {
        if &der[i..i + oid.len()] == oid {
            // Next TLV should be a string type with the CN value.
            let rest = &der[i + oid.len()..];
            if rest.len() >= 2 {
                let (tag, len_byte) = (rest[0], rest[1] as usize);
                let is_string = matches!(tag, 0x13 | 0x0C | 0x1E); // Printable/UTF8/BMP
                if is_string && len_byte > 0 && rest.len() >= 2 + len_byte {
                    if let Ok(s) = std::str::from_utf8(&rest[2..2 + len_byte]) {
                        hits.push(s.to_string());
                    }
                }
            }
            i += oid.len();
        } else {
            i += 1;
        }
    }
    match (subject, hits.as_slice()) {
        (true, [_, cn, ..]) => Some(cn.clone()), // first hit is issuer
        (true, [cn]) => Some(cn.clone()),
        (false, [cn, ..]) => Some(cn.clone()),
        _ => None,
    }
}
