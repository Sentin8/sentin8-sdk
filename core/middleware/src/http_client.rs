// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # http_client (correlation propagation)
//!
//! Shared `reqwest::Client` wrapper that automatically forwards the
//! current request's `X-Sentin8-Correlation-Id` (and TLS tenant
//! headers) on every outgoing HTTP request.
//!
//! Every service-to-service call (Func, Storage, Bus, DB, Stat,
//! Step8, Cron, Ledger, Payments, BFF, App, FDX, Auth) should go
//! through this client so a single `correlation_id` thread can be
//! followed end-to-end across the platform.
//!
//! ## Why a custom client?
//!
//! `reqwest::Client` clones cheaply but does not let you attach
//! headers globally. The standard pattern is to call `.header(...)`
//! on every `RequestBuilder`. That's repetitive and easy to forget.
//! `Sentin8HttpClient::new` reads the correlation_id from the
//! `tracing` active span (populated by the `correlation_id` /
//! `request_logging` middleware) and the tenant fields from
//! `TenantMarker` — both of which are set automatically — and
//! attaches them on every request.
//!
//! ## Usage
//!
//! ```text
//! use sentin8_middleware::http_client::Sentin8HttpClient;
//! use std::time::Duration;
//!
//! let http = Sentin8HttpClient::new();
//! let resp = http
//!     .get("http://func:3107/v1/modules")
//!     .bearer_auth(token)
//!     .send()
//!     .await?;
//! ```
//!
//! For per-request correlation_id (e.g. background workers that don't
//! run inside a request scope), use [`Sentin8HttpClient::with_correlation_id`]
//! or call `.header("x-sentin8-correlation-id", id)` directly on the
//! returned `RequestBuilder`.

use reqwest::{Client, RequestBuilder};
use std::time::Duration;
use uuid::Uuid;

use crate::context::HEADER_CORRELATION_ID;
use crate::structured_logging::TenantMarker;

/// Shared HTTP client that propagates `X-Sentin8-Correlation-Id` and
/// TLS tenant headers on every outgoing request.
///
/// Cheap to clone (wraps an inner `Arc<Client>`).
#[derive(Clone, Debug)]
pub struct Sentin8HttpClient {
    inner: Client,
    /// Optional default correlation ID used when the call is made
    /// outside of a request scope (background workers, etc.).
    default_correlation_id: Option<String>,
}

impl Default for Sentin8HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Sentin8HttpClient {
    /// Construct a client that reads the correlation_id from the active
    /// tracing span on every request. If no span is active (e.g. in a
    /// background worker), a fresh UUID v4 is generated.
    pub fn new() -> Self {
        let inner = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("sentin8-http-client/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build Sentin8HttpClient");
        Self {
            inner,
            default_correlation_id: None,
        }
    }

    /// Construct a client for **long-lived / streaming responses** (SSE,
    /// long-poll, chunked downloads) — identical to [`new`](Self::new) but
    /// without the total request `.timeout()`.
    ///
    /// reqwest's client-level `.timeout()` covers the *entire* response,
    /// including the body stream, so it must be omitted for streams that
    /// stay open indefinitely (e.g. Bus's SSE consumer). Otherwise the
    /// stream is aborted once the timeout elapses and surfaces to callers
    /// of `bytes_stream()` as an "error decoding response body".
    /// The `connect_timeout` is retained so connection-establishment
    /// failures still fail fast.
    pub fn new_streaming() -> Self {
        let inner = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .user_agent(concat!("sentin8-http-client/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build Sentin8HttpClient (streaming)");
        Self {
            inner,
            default_correlation_id: None,
        }
    }

    /// Construct a client with a pre-set default correlation ID.
    /// Useful for background workers that want all their outgoing
    /// calls to share one ID.
    pub fn with_correlation_id(correlation_id: impl Into<String>) -> Self {
        let mut s = Self::new();
        s.default_correlation_id = Some(correlation_id.into());
        s
    }

    /// Wrap a pre-built `reqwest::Client` (e.g. an mTLS-configured client
    /// built by `sentin8_middleware::mtls::build_mtls_client`).
    /// The caller is responsible for configuring timeouts / TLS on the
    /// passed client; this constructor preserves them as-is.
    pub fn from_client(client: Client) -> Self {
        Self {
            inner: client,
            default_correlation_id: None,
        }
    }

    /// Underlying `reqwest::Client`. Use this only when you need to
    /// bypass the correlation-id propagation (e.g. health checks).
    pub fn raw(&self) -> &Client {
        &self.inner
    }

    /// `GET` request builder with correlation-id propagation.
    pub fn get(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.attach_context(self.inner.get(url.as_ref()))
    }

    /// `POST` request builder with correlation-id propagation.
    pub fn post(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.attach_context(self.inner.post(url.as_ref()))
    }

    /// `PUT` request builder with correlation-id propagation.
    pub fn put(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.attach_context(self.inner.put(url.as_ref()))
    }

    /// `DELETE` request builder with correlation-id propagation.
    pub fn delete(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.attach_context(self.inner.delete(url.as_ref()))
    }

    /// `PATCH` request builder with correlation-id propagation.
    pub fn patch(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.attach_context(self.inner.patch(url.as_ref()))
    }

    /// `HEAD` request builder with correlation-id propagation.
    pub fn head(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.attach_context(self.inner.head(url.as_ref()))
    }

    /// Generic `request` builder with correlation-id propagation.
    pub fn request(&self, method: reqwest::Method, url: impl AsRef<str>) -> RequestBuilder {
        self.attach_context(self.inner.request(method, url.as_ref()))
    }

    /// Attach the correlation ID and TLS tenant headers to the
    /// given `RequestBuilder`. Looks up the current span's
    /// [`CorrelationIdMarker`] and [`TenantMarker`] extensions; falls
    /// back to [`default_correlation_id`](Self::default_correlation_id)
    /// or a fresh UUID v4.
    pub fn attach_context(&self, builder: RequestBuilder) -> RequestBuilder {
        let (cid, env, app, host, svc) = current_context();
        let cid = cid
            .or_else(|| self.default_correlation_id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let mut b = builder.header(HEADER_CORRELATION_ID, cid);
        if let Some(v) = env {
            b = b.header("x-sentin8-env-id", v);
        }
        if let Some(v) = app {
            b = b.header("x-sentin8-app-id", v);
        }
        if let Some(v) = host {
            b = b.header("x-sentin8-hostname", v);
        }
        if let Some(v) = svc {
            b = b.header("x-sentin8-service", v.clone());
            // Also set the caller-service header so the receiving service's
            // log emission layer can populate `caller_service` on the
            // LogEvent — this is what builds the service-interaction graph
            // (edges) in Log.
            b = b.header("x-sentin8-caller-service", v);
        }
        b
    }
}

/// Walk the current span chain and extract the correlation ID and
/// tenant fields, if any. Returns `(correlation_id, env_id,
/// app_id, hostname, service)`.
///
/// All fields are optional; missing ones are returned as `None`.
///
/// Note: `tracing` doesn't expose `Span::extensions()` on stable, so
/// we read from the thread-local default set by
/// [`set_thread_correlation_id`] / background-worker code. For per-
/// request correlation IDs, handlers should pass the value
/// explicitly via [`attach_context_to`].
/// Logging/trace context carried by outgoing HTTP calls:
/// `(correlation_id, env_id, application_id, hostname, service)`.
pub type RequestContext = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Snapshot the current thread's request context (correlation id, tenant
/// markers, service identity).
pub fn current_context() -> RequestContext {
    let cid = current_thread_correlation_id();
    let tenant = TenantMarker::default();
    let svc = current_thread_service();
    (
        cid,
        tenant.env_id,
        tenant.application_id,
        tenant.hostname,
        svc,
    )
}

/// Set the current thread's correlation ID. Background workers that
/// run outside a request scope can use this to ensure all outgoing
/// HTTP calls share a single thread of traceability.
pub fn set_thread_correlation_id(id: impl Into<String>) {
    THREAD_CID.with(|c| {
        *c.borrow_mut() = Some(id.into());
    });
}

/// Clear the current thread's correlation ID (e.g. when a worker
/// finishes a job and starts a new one).
pub fn clear_thread_correlation_id() {
    THREAD_CID.with(|c| {
        *c.borrow_mut() = None;
    });
}

fn current_thread_correlation_id() -> Option<String> {
    THREAD_CID.with(|c| c.borrow().clone())
}

thread_local! {
    static THREAD_CID: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    static THREAD_SERVICE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Set the current thread's service name (the target service from
/// `x-sentin8-service`, i.e. the service that received the current
/// request). Used by [`Sentin8HttpClient::attach_context`] to set the
/// `x-sentin8-caller-service` header on outgoing inter-service calls.
pub fn set_thread_service(svc: impl Into<String>) {
    THREAD_SERVICE.with(|c| {
        *c.borrow_mut() = Some(svc.into());
    });
}

/// Clear the current thread's service name.
pub fn clear_thread_service() {
    THREAD_SERVICE.with(|c| {
        *c.borrow_mut() = None;
    });
}

fn current_thread_service() -> Option<String> {
    THREAD_SERVICE.with(|c| c.borrow().clone())
}

/// Like [`Sentin8HttpClient::attach_context`] but takes the correlation
/// ID and tenant fields as explicit arguments. Useful when the caller
/// has already extracted them from the request extension.
pub fn attach_context_to(
    builder: RequestBuilder,
    correlation_id: Option<&str>,
    tenant: Option<&TenantMarker>,
) -> RequestBuilder {
    let cid = correlation_id
        .map(|s| s.to_string())
        .or_else(current_thread_correlation_id)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let mut b = builder.header(HEADER_CORRELATION_ID, cid);
    if let Some(t) = tenant {
        if let Some(v) = &t.env_id {
            b = b.header("x-sentin8-env-id", v);
        }
        if let Some(v) = &t.application_id {
            b = b.header("x-sentin8-app-id", v);
        }
        if let Some(v) = &t.hostname {
            b = b.header("x-sentin8-hostname", v);
        }
        if let Some(v) = &t.service {
            b = b.header("x-sentin8-service", v);
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Install the Graviola PQ crypto provider once — reqwest panics with
    /// "No provider set" when a client is built without one.
    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = sentin8_tls::crypto::sentin8_pq_provider().install_default();
        });
    }

    #[test]
    fn thread_correlation_id_round_trip() {
        install_provider();
        assert!(current_thread_correlation_id().is_none());
        set_thread_correlation_id("test-cid-1");
        assert_eq!(
            current_thread_correlation_id().as_deref(),
            Some("test-cid-1")
        );
        clear_thread_correlation_id();
        assert!(current_thread_correlation_id().is_none());
    }

    #[test]
    fn attach_context_includes_correlation_id() {
        install_provider();
        let client = Sentin8HttpClient::new();
        set_thread_correlation_id("thread-cid-42");
        let builder = attach_context_to(client.inner.get("http://example.com/test"), None, None);
        let req = builder.build().unwrap();
        assert_eq!(
            req.headers().get(HEADER_CORRELATION_ID).unwrap(),
            "thread-cid-42"
        );
        clear_thread_correlation_id();
    }

    #[test]
    fn attach_context_includes_tenant_fields() {
        install_provider();
        let tenant = TenantMarker {
            env_id: Some("env-456".to_string()),
            application_id: Some("app-789".to_string()),
            hostname: Some("bff.example.com".to_string()),
            service: Some("bff".to_string()),
        };
        let client = Sentin8HttpClient::new();
        let builder = attach_context_to(
            client.inner.get("http://example.com/test"),
            Some("cid-X"),
            Some(&tenant),
        );
        let req = builder.build().unwrap();
        let headers = req.headers();
        assert_eq!(headers.get(HEADER_CORRELATION_ID).unwrap(), "cid-X");
        assert_eq!(headers.get("x-sentin8-env-id").unwrap(), "env-456");
        assert_eq!(headers.get("x-sentin8-app-id").unwrap(), "app-789");
        assert_eq!(
            headers.get("x-sentin8-hostname").unwrap(),
            "bff.example.com"
        );
        assert_eq!(headers.get("x-sentin8-service").unwrap(), "bff");
    }

    #[test]
    fn attach_context_without_tenant_omits_tenant_headers() {
        install_provider();
        let client = Sentin8HttpClient::new();
        let builder = attach_context_to(
            client.inner.get("http://example.com/test"),
            Some("cid-Y"),
            None,
        );
        let req = builder.build().unwrap();
        let headers = req.headers();
        assert_eq!(headers.get(HEADER_CORRELATION_ID).unwrap(), "cid-Y");
        assert!(headers.get("x-sentin8-env-id").is_none());
        assert!(headers.get("x-sentin8-app-id").is_none());
    }

    #[test]
    fn default_correlation_id_used_when_no_caller_supplied() {
        install_provider();
        let client = Sentin8HttpClient::with_correlation_id("default-cid");
        let builder = client.get("http://example.com/test");
        let req = builder.build().unwrap();
        assert_eq!(
            req.headers().get(HEADER_CORRELATION_ID).unwrap(),
            "default-cid"
        );
    }
}
