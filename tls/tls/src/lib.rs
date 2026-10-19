// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0
//! # sentin8-tls - Per-Service TLS Termination + Host-Context Resolution
//!
//! Platform library for per-service TLS termination. Each backend service
//! links `sentin8-tls`, terminates TLS in-process using Acme certificates
//! and a SNI-aware `WildcardCertResolver`, resolves the `Host`/SNI to a
//! tenant/service context, and injects `X-Sentin8-*`
//! context headers via `context_middleware()`.
//!
//! ## Architecture
//!
//! ```text
//! Client → Proxy (:443, L4 SNI router) → service's sentin8-tls → axum handlers
//!                                           ↓
//!                                      context_middleware()
//!                                      - strip client X-Sentin8-* headers
//!                                      - resolve Host → HostContext
//!                                      - inject X-Sentin8-* headers
//! ```
//!
//! ## Hostname resolution is DATABASE-FREE (TLS-RLS-4)
//!
//! The `HostContextResolver` holds no SQL pool. A cache miss resolves via
//! Sentin8:Sys's owner API - `GET /v1/resolve/hostname` - presented with
//! the embedding service's cert-bound `{dash}-tls` M2M workload (scope
//! `sentin8:sys:instances:read`), identical for platform and vertical
//! services: a vertical embedding this library gains ZERO
//! platform-database access (no DSN, no role, no grants), and platform
//! services no longer need hostname-table grants either.
//!
//! ## Usage
//!
//! ```text
//! use sentin8_tls::Sentin8Tls;
//!
//! let tls = Sentin8Tls::builder()
//!     .service_identity("bank8:ledger")
//!     .acme_directory_url(acme_url)
//!     .sentin8_domain("sentin8.local")
//!     .build()
//!     .await?;
//!
//! let listener = tls.tls_listener("0.0.0.0:443").await?;
//! let app = axum::Router::new()
//!     .route("/v1/health", get(health))
//!     .layer(sentin8_tls::context_middleware(tls.host_context_resolver()));
//!
//! tls.serve(listener, app).await?;
//! ```

pub mod acceptor;
pub mod cache;
pub mod certs;
pub mod config;
pub mod context;
pub mod crypto;
pub mod resolver;
pub mod tcp;

// Re-export the key public types.
pub use acceptor::{cert_der_to_pem, TlsListener, TlsStreamExt};
pub use cache::MappingCache;
pub use certs::WildcardCertResolver;
pub use config::Sentin8TlsConfig;
pub use context::{context_middleware, ContextMiddlewareState, HostContextResolver};
pub use resolver::Sentin8Tls;
pub use tcp::{RawTcpListener, TlsInfo};
