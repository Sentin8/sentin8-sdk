// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! `Sentin8Tls` builder - the main entry point for the `sentin8-tls` library.
//!
//! Each backend service creates a `Sentin8Tls` instance, builds a TLS
//! listener, and wires the `context_middleware` into its axum router.

use std::sync::Arc;

use hyper_util::service::TowerToHyperService;

use crate::acceptor::TlsStreamExt;
use crate::cache::MappingCache;
use crate::certs::WildcardCertResolver;
use crate::config::{Sentin8TlsConfig, TlsMode};
use crate::context::HostContextResolver;

/// The main `sentin8-tls` handle. Created via `Sentin8Tls::builder()`.
///
/// Holds the mapping cache, cert resolver, and host-context resolver.
/// The caller uses `tls_listener()` to create a TLS listener and
/// `host_context_resolver()` to wire the `context_middleware`.
pub struct Sentin8Tls {
    config: Sentin8TlsConfig,
    cache: MappingCache,
    cert_resolver: Arc<WildcardCertResolver>,
    host_context_resolver: HostContextResolver,
}

impl Sentin8Tls {
    /// Create a builder with default config from env vars.
    pub fn builder() -> Sentin8TlsBuilder {
        Sentin8TlsBuilder::default()
    }

    /// Get the `HostContextResolver` (for `context_middleware`).
    pub fn host_context_resolver(&self) -> HostContextResolver {
        self.host_context_resolver.clone()
    }

    /// Get the `MappingCache` (read-only, thread-safe).
    pub fn cache(&self) -> MappingCache {
        self.cache.clone()
    }

    /// Get the `WildcardCertResolver`.
    pub fn cert_resolver(&self) -> Arc<WildcardCertResolver> {
        self.cert_resolver.clone()
    }

    /// Get the config.
    pub fn config(&self) -> &Sentin8TlsConfig {
        &self.config
    }

    /// Create a TLS listener bound to `addr` (e.g. `0.0.0.0:443`).
    ///
    /// When `config.client_ca_pem_path` is set, the listener requests client
    /// certificates (optional mTLS). In `TlsMode::Off`, this
    /// returns `Err` - the caller should use a plain `TcpListener` instead.
    pub async fn tls_listener(&self, addr: &str) -> Result<crate::TlsListener, String> {
        if self.config.tls_mode == TlsMode::Off {
            return Err("sentin8-tls: tls_mode is 'off' - use a plain TCP listener".to_string());
        }

        if let Some(ca_path) = &self.config.client_ca_pem_path {
            let ca_pem = std::fs::read(ca_path)
                .map_err(|e| format!("read SENTIN8_TLS_CLIENT_CA_PEM ({ca_path}): {e}"))?;
            // The trust posture (DESIGN 9a.12): `self_signed` accepts ANY
            // presented client cert at the handshake (the RFC 8705 trust
            // decision moves to the application layer); the default `ca`
            // verifies against the CA PEM.
            if self.config.client_auth_posture == crate::config::ClientAuthPosture::SelfSigned {
                tracing::info!("sentin8-tls: optional mTLS client auth (self_signed posture - trust decided by the application)");
                return crate::acceptor::TlsListener::bind_with_client_auth_allow_self_signed(
                    addr,
                    self.cert_resolver.clone(),
                )
                .await;
            }
            tracing::info!(ca_path, "sentin8-tls: optional mTLS client auth enabled");
            return crate::acceptor::TlsListener::bind_with_client_auth(
                addr,
                self.cert_resolver.clone(),
                &ca_pem,
            )
            .await;
        }

        crate::acceptor::TlsListener::bind(addr, self.cert_resolver.clone()).await
    }

    /// Create a **raw-TCP** listener with STARTTLS/implicit-TLS upgrade
    /// support - for non-HTTP protocols (SMTP, IMAP, POP3, ManageSieve,
    /// LMTP).
    ///
    /// The listener yields plain TCP streams; the caller negotiates the
    /// wire protocol and calls `upgrade_starttls` (or uses `accept_tls`
    /// for implicit-TLS ports like 993/995/465). No protocol knowledge
    /// lives in sentin8-tls - see `tcp.rs`.
    pub async fn raw_tcp_listener(&self, addr: &str) -> Result<crate::RawTcpListener, String> {
        if self.config.tls_mode == TlsMode::Off {
            return Err("sentin8-tls: tls_mode is 'off' - use a plain TCP listener".to_string());
        }
        crate::tcp::RawTcpListener::bind(addr, self.cert_resolver.clone()).await
    }

    /// Serve an axum `Router` on a TLS listener bound to `addr`.
    ///
    /// This is the main entry point for services that want `sentin8-tls`
    /// to handle TLS termination. The `app` router should already have
    /// the `context_middleware` layer applied (see `host_context_resolver()`).
    ///
    /// In `TlsMode::Off`, falls back to plain HTTP via `axum::serve`.
    pub async fn serve(
        &self,
        addr: &str,
        app: axum::Router,
        shutdown_signal_name: &'static str,
    ) -> anyhow::Result<()> {
        if self.config.tls_mode == TlsMode::Off {
            // Dev fallback: plain HTTP.
            tracing::warn!("sentin8-tls: TLS mode is 'off', serving plain HTTP on {addr}");
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app)
                .with_graceful_shutdown(sentin8_middleware::shutdown_signal(shutdown_signal_name))
                .await?;
            return Ok(());
        }

        // TLS mode: accept TLS connections and serve the app on each.
        let listener = self.tls_listener(addr).await.map_err(anyhow::Error::msg)?;
        let local_addr = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| addr.to_string());
        tracing::info!("sentin8-tls: serving HTTPS on {local_addr}");

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    let (tcp_stream, peer_addr) = match accept_result {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!(error = %e, "sentin8-tls: accept failed");
                            continue;
                        }
                    };
                    // The TLS handshake runs INSIDE the per-connection task:
                    // a stalled handshake delays one task, never the accept
                    // loop (tls README §6 - bounded inbound connections).
                    let tls = listener.tls_acceptor().clone();
                    let app = app.clone();
                    tokio::spawn(async move {
                        let tls_stream = match tls.accept(tcp_stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                // TLS handshake failures (no cert for SNI,
                                // plain-HTTP client on TLS port, etc.) are
                                // expected during cert provisioning - log
                                // at debug to avoid noise.
                                tracing::debug!(error = %e, peer = %peer_addr, "sentin8-tls: handshake failed");
                                return;
                            }
                        };
                        serve_tls_stream(tls_stream, app).await;
                    });
                }
                _ = sentin8_middleware::shutdown_signal(shutdown_signal_name) => {
                    tracing::info!("sentin8-tls: shutdown signal received");
                    break;
                }
            }
        }
        Ok(())
    }
}

/// Serve one established TLS stream on the axum app.
///
/// Sets an HTTP/1 header read timeout (with a `TokioTimer` - hyper's
/// timeout needs a timer): a connected-but-silent peer cannot hold its
/// per-connection task and buffers forever (tls README §6). Every
/// platform transport is request/response or SSE-with-frames, so reaping
/// silent connections never breaks a live stream.
async fn serve_tls_stream(
    tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    app: axum::Router,
) {
    // Extract the client certificate (when optional client auth is enabled
    // and the client presented one) and stash it as a request extension so
    // `context_middleware` can inject the `X-Sentin8-Client-Cert-*` headers
    // per request. The value rides as middleware state (never fails to
    // extract - a State extractor is infallible, unlike `Extension`, which
    // 500s on nested routers that predate the layer).
    let peer = tls_stream.peer_cert_der().map(PeerClientCert::new);
    let app = app.layer(axum::middleware::from_fn_with_state(
        peer,
        promote_peer_cert,
    ));
    let svc = TowerToHyperService::new(app);
    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .http1()
        .timer(hyper_util::rt::TokioTimer::default())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection_with_upgrades(io, svc)
        .await;
}

/// Idle bound for inbound HTTP/1 connections: the window a silent peer may
/// hold the connection between request headers before it is reaped.
const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(65);

/// The mTLS peer certificate extracted from the TLS handshake.
///
/// Stashed as a request extension by the accept loop; consumed by
/// `context_middleware` to inject `X-Sentin8-Client-Cert-*` headers.
#[derive(Debug, Clone)]
pub struct PeerClientCert {
    /// DER bytes of the client's leaf certificate.
    pub der: Vec<u8>,
}

impl PeerClientCert {
    /// Wrap raw DER leaf-certificate bytes captured from the TLS handshake.
    pub fn new(der: Vec<u8>) -> Self {
        Self { der }
    }
}

/// Middleware that inserts the per-connection peer certificate into request
/// extensions. The value is carried as middleware **state**
/// (captured once per accepted TLS connection) - a `State` extractor is
/// infallible, so this layer can never break nested routers/merged subrouters
/// that don't know about it (an `Extension` extractor would 500 them with
/// "Missing request extension").
async fn promote_peer_cert(
    axum::extract::State(peer): axum::extract::State<Option<PeerClientCert>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(peer) = peer {
        req.extensions_mut().insert(peer);
    }
    next.run(req).await
}

/// Builder for `Sentin8Tls`.
#[derive(Default)]
pub struct Sentin8TlsBuilder {
    config: Sentin8TlsConfig,
    /// The embedding service's identity (e.g. `bank8:ledger`). Defaults
    /// from `SENTIN8_TLS_SERVICE_IDENTITY`; names the cert-bound
    /// `{dash}-tls` M2M workload the database-free resolver presents to
    /// Sys's resolve endpoint (TLS-RLS-4).
    service_identity: String,
    /// Certs to pre-load into the resolver at build time (hostname, cert_pem, key_pem).
    /// Used by bootstrap services (e.g. acme) that need their own cert
    /// available before any ACME fetch can happen.
    bootstrap_certs: Vec<(String, Vec<u8>, Vec<u8>)>,
}

impl Sentin8TlsBuilder {
    /// Set the embedding service's identity (e.g. `bank8:ledger`,
    /// `sentin8:auth`) - names the cert-bound `{dash}-tls` M2M workload
    /// the database-free resolver uses for Sys `GET /v1/resolve/hostname`
    /// (TLS-RLS-4, design/sentin8-vertical-data-plane-contract.md §VDC.7).
    /// No database URL exists on the builder anymore: the library holds
    /// NO SQL pool, so no service (platform or vertical) gains
    /// platform-database access by embedding sentin8-tls.
    pub fn service_identity(mut self, identity: impl Into<String>) -> Self {
        self.service_identity = identity.into();
        self
    }

    /// Set the Acme directory URL.
    pub fn acme_directory_url(mut self, url: impl Into<String>) -> Self {
        self.config.acme_directory_url = url.into();
        self
    }

    /// Set the root Sentin8 domain.
    pub fn sentin8_domain(mut self, domain: impl Into<String>) -> Self {
        self.config.sentin8_domain = domain.into();
        self
    }

    /// Set the TLS mode.
    pub fn tls_mode(mut self, mode: TlsMode) -> Self {
        self.config.tls_mode = mode;
        self
    }

    /// Pre-load a certificate into the resolver at build time.
    ///
    /// Used by bootstrap services (e.g. acme) that must serve TLS
    /// before any ACME cert fetch can happen. The cert is signed by the
    /// acme's own CA and registered directly in the resolver -
    /// no ACME fetch is needed for this hostname.
    pub fn bootstrap_cert(
        mut self,
        hostname: impl Into<String>,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    ) -> Self {
        self.bootstrap_certs
            .push((hostname.into(), cert_pem, key_pem));
        self
    }

    /// Build the `Sentin8Tls` instance.
    ///
    /// This seeds the mapping cache, starts the cert resolver (empty -
    /// certs are fetched on-the-fly from Acme when a TLS ClientHello
    /// arrives with an unknown SNI), and wires the database-free
    /// host-context resolver (TLS-RLS-4: cache → Sys owner API; the
    /// library opens NO SQL connection).
    pub async fn build(self) -> anyhow::Result<Sentin8Tls> {
        let config = self.config;

        // 0. Install the Graviola CryptoProvider as the process-level
        // default. Graviola is a pure-Rust crypto library (no C compiler,
        // no cmake) that provides ML-KEM-768 for post-quantum key exchange.
        // Default mode is exclusive PQ - only X25519MLKEM768, no classical
        // fallback (see the crate README for the PQ mode table).
        let _ = crate::crypto::sentin8_pq_provider().install_default();

        // 1. Mapping cache - starts empty; hostname → service resolution
        //    rides the Sys owner API on cache miss (see context.rs).
        let cache = MappingCache::new();

        // 2. Create the cert resolver (empty - certs fetched on-the-fly
        //    from Acme when a TLS ClientHello arrives with an unknown SNI).
        //    The discovery connection presents THIS process's workload
        //    identity over the Valkey TLS plane (group DESIGN.md §3.1):
        //    the CN maps to the enroll-provisioned ACL user.
        let discovery = {
            let valkey_url = std::env::var("VALKEY_URL")
                .unwrap_or_else(|_| "valkeys://localhost:6379/0".to_string());
            let local_ip = std::env::var("SENTIN8_CAPTAIN_LOCAL_IP")
                .unwrap_or_else(|_| "127.0.0.1".to_string());
            let workload = sentin8_middleware::structured_logging::current_service_name()
                .unwrap_or("unknown")
                .to_string();
            Some(sentin8_service_discovery::ServiceDiscovery::spawn(
                valkey_url, local_ip, workload,
            ))
        };

        let cert_resolver = Arc::new(WildcardCertResolver::empty(
            config.acme_directory_url.clone(),
            discovery.clone(),
        ));

        // 2a. Pre-warm the persisted leaf cache (WARM-1, README §6.5): a
        //     LOCAL DISK READ ONLY - no Acme/Storage dependency on the boot
        //     path. Every previously-minted hostname serves with zero mint
        //     round-trips after a restart or reset; expired pairs are
        //     pruned by the scan itself; the load is capped
        //     (`SENTIN8_TLS_CERT_CACHE_MAX`) so a client-controlled SNI key
        //     space cannot accumulate unbounded files.
        for leaf in crate::cert_cache::scan_cache() {
            let (cert_pem, key_pem) = match std::fs::read(&leaf.cert_path)
                .and_then(|c| std::fs::read(&leaf.key_path).map(|k| (c, k)))
            {
                Ok(pair) => pair,
                Err(_) => continue, // vanished mid-scan - load-or-mint
            };
            match cert_resolver.add_cert(&leaf.hostname, &cert_pem, &key_pem) {
                Ok(()) => tracing::info!(
                    hostname = %leaf.hostname,
                    "sentin8-tls: pre-warmed cert from persisted cache"
                ),
                Err(e) => {
                    // Corrupt pair - drop it from disk too (fail safe to
                    // re-mint on demand).
                    let _ = std::fs::remove_file(&leaf.cert_path);
                    let _ = std::fs::remove_file(&leaf.key_path);
                    tracing::warn!(
                        hostname = %leaf.hostname,
                        error = %e,
                        "sentin8-tls: cached pair unparsable - pruned"
                    );
                }
            }
        }

        // 2b. Pre-load bootstrap certs (e.g. acme's self-issued cert).
        //     These are registered directly in the resolver - no ACME fetch
        //     is needed for these hostnames.
        for (hostname, cert_pem, key_pem) in &self.bootstrap_certs {
            match cert_resolver.add_cert(hostname, cert_pem, key_pem) {
                Ok(()) => {
                    tracing::info!(hostname = %hostname, "sentin8-tls: bootstrap cert pre-loaded")
                }
                Err(e) => {
                    tracing::error!(hostname = %hostname, error = %e, "sentin8-tls: failed to pre-load bootstrap cert")
                }
            }
        }

        // 3. Build the host-context resolver - DATABASE-FREE (TLS-RLS-4):
        //    cache miss → Sys `GET /v1/resolve/hostname` with this
        //    service's cert-bound `{dash}-tls` M2M workload.
        let host_context_resolver = HostContextResolver::new(cache.clone(), &self.service_identity);

        Ok(Sentin8Tls {
            config,
            cache,
            cert_resolver,
            host_context_resolver,
        })
    }
}
