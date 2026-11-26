// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! TLS certificate management: `WildcardCertResolver` and ACME client.
//!
//! The resolver supports on-the-fly certificate registration via SNI,
//! with exact-match and wildcard-match lookup. Certificates are
//! requested from Sentin8:Acme.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use parking_lot::RwLock;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;

/// Backoff duration (seconds) before retrying a failed ACME fetch for the
/// same hostname. Prevents infinite retry loops when the ACME server is
/// unreachable - every TLS handshake would otherwise trigger a fresh fetch.
const FETCH_FAILURE_BACKOFF_S: u64 = 30;

/// How long a HANDSHAKE may wait for an in-flight on-demand cert mint.
/// The mint's own bound is 3s connect + 10s total per HTTP hop for a
/// LOCAL order; the observed worst case (Acme queue + issuer issuance)
/// is ~15s. An EXTERNAL order (rig `public` mode, RIGMODE-1) rides the
/// upstream relay: public-CA http-01 validation takes 10-60s end to end,
/// so the wait must cover a full validation cycle. 90s (2x the acme
/// poll window's effective external latency, and 2x the local worst
/// case) keeps both shapes inside one handshake wait; the failure
/// backoff still bounds retry storms independently.
const CERT_FETCH_WAIT_S: u64 = 90;

/// A SNI-aware certificate resolver that fetches certs on-the-fly from
/// Acme when an unknown SNI arrives.
///
/// On the first TLS connection for a hostname, `resolve` returns `None`
/// (the handshake fails) but spawns a background task to fetch the cert
/// from Acme. Subsequent connections for the same hostname get the
/// cached cert. This avoids pre-warming all certs at startup - each
/// service only fetches certs for hostnames it actually serves.
pub struct WildcardCertResolver {
    /// hostname → CertifiedKey (exact match, e.g. `www.example.com`)
    exact: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
    /// parent domain → CertifiedKey (wildcard, e.g. `example.com` for `*.example.com`)
    wildcard: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
    /// Acme directory URL (static fallback when discovery has no acme).
    acme_url: String,
    /// Service discovery handle for resolving acme dynamically.
    discovery: Option<sentin8_service_discovery::ServiceDiscovery>,
    /// Hostnames currently being fetched (prevents duplicate concurrent fetches).
    pending: Arc<RwLock<HashMap<String, ()>>>,
    /// Hostnames that recently failed ACME fetch, with the unix timestamp
    /// of the failure. Used to avoid retrying within the backoff window.
    failed: Arc<RwLock<HashMap<String, std::time::Instant>>>,
}

impl std::fmt::Debug for WildcardCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `ServiceDiscovery` and `CertifiedKey` don't impl `Debug`, so report
        // counts instead of the full maps.
        f.debug_struct("WildcardCertResolver")
            .field("exact_count", &self.exact.read().len())
            .field("wildcard_count", &self.wildcard.read().len())
            .field("pending_count", &self.pending.read().len())
            .field("failed_count", &self.failed.read().len())
            .field("acme_url", &self.acme_url)
            .field("has_discovery", &self.discovery.is_some())
            .finish()
    }
}

impl WildcardCertResolver {
    /// Create a new resolver from a map of hostname → (cert_pem, key_pem).
    pub fn new(cert_map: &HashMap<String, (Vec<u8>, Vec<u8>)>) -> Result<Self, String> {
        let resolver = Self {
            exact: Arc::new(RwLock::new(HashMap::new())),
            wildcard: Arc::new(RwLock::new(HashMap::new())),
            acme_url: String::new(),
            discovery: None,
            pending: Arc::new(RwLock::new(HashMap::new())),
            failed: Arc::new(RwLock::new(HashMap::new())),
        };
        for (hostname, (cert_pem, key_pem)) in cert_map {
            resolver.add_cert(hostname, cert_pem, key_pem)?;
        }
        Ok(resolver)
    }

    /// Create an empty resolver (certs fetched on-the-fly from Acme
    /// when a TLS ClientHello arrives with an unknown SNI).
    pub fn empty(
        acme_url: String,
        discovery: Option<sentin8_service_discovery::ServiceDiscovery>,
    ) -> Self {
        Self {
            exact: Arc::new(RwLock::new(HashMap::new())),
            wildcard: Arc::new(RwLock::new(HashMap::new())),
            acme_url,
            discovery,
            pending: Arc::new(RwLock::new(HashMap::new())),
            failed: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a certificate on-the-fly. Wildcard hostnames (`*.foo`)
    /// are stored by parent domain (`foo`).
    pub fn add_cert(&self, hostname: &str, cert_pem: &[u8], key_pem: &[u8]) -> Result<(), String> {
        let mut cert_reader = std::io::BufReader::new(cert_pem);
        let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_reader)
                .filter_map(|r| r.ok())
                .collect();

        let mut key_reader = std::io::BufReader::new(key_pem);
        let key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| format!("parse private key for {hostname}: {e}"))?
            .ok_or_else(|| format!("no private key for {hostname}"))?;

        let signing_key = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| format!("no crypto provider installed for {hostname}"))?
            .key_provider
            .load_private_key(key)
            .map_err(|e| format!("unsupported key type for {hostname}: {e}"))?;

        let certified_key = Arc::new(CertifiedKey::new(cert_chain, signing_key));

        if let Some(parent) = hostname.strip_prefix("*.") {
            tracing::info!("Wildcard SNI cert registered for *.{parent}");
            self.wildcard
                .write()
                .insert(parent.to_string(), certified_key);
        } else {
            tracing::info!("SNI cert registered for {hostname}");
            self.exact
                .write()
                .insert(hostname.to_string(), certified_key);
        }
        Ok(())
    }

    /// Check if a cert is already loaded for the hostname (exact or wildcard).
    pub fn has_cert(&self, hostname: &str) -> bool {
        if self.exact.read().contains_key(hostname) {
            return true;
        }
        let parts: Vec<&str> = hostname.split('.').collect();
        if parts.len() >= 2 {
            let parent = parts[1..].join(".");
            if self.wildcard.read().contains_key(&parent) {
                return true;
            }
        }
        false
    }
}

impl ResolvesServerCert for WildcardCertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni: &str = client_hello.server_name()?;

        // 1. Exact match.
        if let Some(key) = self.exact.read().get(sni) {
            return Some(key.clone());
        }

        // 2. Wildcard match: strip the first label and check the parent domain.
        let parts: Vec<&str> = sni.split('.').collect();
        if parts.len() >= 2 {
            let parent = parts[1..].join(".");
            if let Some(key) = self.wildcard.read().get(&parent) {
                return Some(key.clone());
            }
        }

        // 3. No match - install an on-demand fetch from Acme (tls README §6
        //    "the cert fetch is owned by a DETACHED task, not the
        //    handshake"). The first handshake for an unknown SNI returns
        //    `None` immediately (the client's retry loop covers the initial
        //    reset); the DETACHED fetch survives peer aborts so follow-up
        //    handshakes find the landed cert.
        //
        //    If a fetch is already in progress for this hostname, wait for
        //    it to complete instead of spawning a duplicate.
        //
        //    If a recent fetch failed (within the backoff window), return
        //    None immediately to avoid an infinite retry loop on every
        //    TLS handshake.
        let acme_endpoint = match self.resolve_acme_endpoint() {
            Some(ep) => ep,
            None => {
                tracing::warn!(
                    hostname = %sni,
                    "sentin8-tls: ACME not resolved via service discovery - skipping cert fetch"
                );
                return None;
            }
        };
        {
            // Negative cache: skip fetch if the hostname recently failed.
            let backoff = std::time::Duration::from_secs(FETCH_FAILURE_BACKOFF_S);
            if let Some(fail_time) = self.failed.read().get(sni).copied() {
                if fail_time.elapsed() < backoff {
                    tracing::trace!(
                        hostname = %sni,
                        "sentin8-tls: cert fetch on backoff (recent failure), skipping"
                    );
                    return None;
                }
            }

            // Check if a fetch is already in progress - if so, wait for it.
            let already_pending = self.pending.read().contains_key(sni);
            if already_pending {
                // Poll until the pending fetch completes (up to 15s).
                let hostname = sni.to_string();
                let exact = self.exact.clone();
                let pending = self.pending.clone();
                let failed = self.failed.clone();
                let deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(CERT_FETCH_WAIT_S);
                while std::time::Instant::now() < deadline {
                    if let Some(key) = exact.read().get(&hostname) {
                        return Some(key.clone());
                    }
                    // The owner of the pending entry already reported failure
                    // and re-armed the backoff - fail fast within the window
                    // instead of a 15 s silent wait (tls README §6).
                    if failed.read().contains_key(&hostname) {
                        return None;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                // Timed out waiting - the owner may have failed mid-flight
                // WITHOUT removing its pending marker (aborted future); reach
                // the negative cache from here too, so the NEXT handshake
                // re-triggers a real fetch (post-backoff) instead of eating
                // another 15 s dead wait (tls README §6 "waiters never
                // starve the negative cache").
                pending.write().remove(&hostname);
                failed
                    .write()
                    .insert(hostname.clone(), std::time::Instant::now());
                tracing::warn!(hostname = %sni, "sentin8-tls: timed out waiting for in-progress cert fetch");
                return None;
            }

            // No fetch in progress - arm the fetch as a DETACHED task on the
            // BLOCKING pool (WAITSTARVE-1, observed live 2026-11-01). It
            // must NOT run inline on the handshake task: when the peer
            // resets mid-handshake, the handshake future is dropped and an
            // inline fetch dies with it (Acme receives new-account then
            // silence, the pending marker leaks, and backoff plus
            // client-gave-up suppress re-issuance for minutes - tls README
            // §6 "the cert fetch is owned by a DETACHED task").
            //
            // WAITSTARVE-1: it must ALSO not be `tokio::spawn`-ed. resolve()
            // runs inside the per-connection handshake task ON A RUNTIME
            // WORKER; a plain tokio::spawn lands the fetch in that SAME
            // worker's LIFO slot, which is worker-private (not stealable).
            // The FIRST-TOUCH HOLD below then parks the same worker in its
            // std::thread::sleep poll - the armed fetch is never polled
            // until the hold expires. Observed live: EVERY first-touch
            // mint took exactly CERT_FETCH_WAIT_S from spawn to the first
            // Acme request (the mint itself is ~100 ms), and five
            // concurrent DCR retries (ebank install in bank8 e2e
            // globalSetup) parked five sentin8:auth workers for 45 s each
            // until the proxy's registry view lapsed ("no Active
            // instances") and POST /v1/app/setup 500ed. spawn_blocking
            // queues on the UNPROTECTED blocking-pool queue instead: any
            // blocking thread can take it, the fetch runs concurrently
            // with the hold, the mint lands inside the wait, and the
            // handshake completes with the cert.
            //
            // The result handling (parse, register, persist, negative-cache
            // arming, pending clear) rides INSIDE the same blocking task:
            // spawning it separately as a tokio::spawn would put the
            // registry insert into the parking worker's LIFO slot and
            // re-starve the waiter for the full hold window.
            self.pending.write().insert(sni.to_string(), ());
            let hostname = sni.to_string();
            let acme_url = acme_endpoint.0.clone();
            let acme_sni = acme_endpoint.1.clone();
            let acme_addr = acme_endpoint.2;
            let exact = self.exact.clone();
            let pending = self.pending.clone();
            let failed = self.failed.clone();
            let backoff = std::time::Duration::from_secs(FETCH_FAILURE_BACKOFF_S);

            tracing::info!(hostname = %hostname, "sentin8-tls: fetching cert on-demand");
            let fetch_hostname = hostname.clone();
            tokio::task::spawn_blocking(move || {
                // The detached fetch inherits hard per-request deadlines from
                // `request_cert_from_acme` (3 s connect / 10 s total) - a
                // hung Acme cannot hold a worker thread.
                let fetched = tokio::runtime::Handle::current().block_on(async move {
                    request_cert_from_acme(&acme_url, &acme_sni, acme_addr, &fetch_hostname).await
                });
                match fetched {
                    Ok((cert_pem, key_pem)) => {
                        match parse_certified_key(
                            &hostname,
                            cert_pem.as_slice(),
                            key_pem.as_slice(),
                        ) {
                            Ok(ck) => {
                                exact.write().insert(hostname.clone(), Arc::new(ck));
                                failed.write().remove(&hostname);
                                // (README §6.5): persist the minted pair
                                // so the NEXT process boot pre-warms this
                                // hostname with zero mint round-trips.
                                // Best-effort by contract - an unwritable cache
                                // dir never fails the in-memory registration.
                                crate::cert_cache::persist_leaf_pair(
                                    &hostname, &cert_pem, &key_pem,
                                );
                                tracing::info!(hostname = %hostname, "sentin8-tls: cert registered on-demand");
                            }
                            Err(e) => {
                                tracing::warn!(hostname = %hostname, error = %e, "sentin8-tls: parse cert failed");
                                let mut failed = failed.write();
                                // The backoff is an eviction bound, not only a
                                // retry gate: prune entries older than the
                                // backoff before storing the new one - the SNI
                                // key space is client-controlled and must never
                                // accumulate unpruned for the process lifetime
                                // (tls README §5,).
                                let now = std::time::Instant::now();
                                failed.retain(|_, fail_time| {
                                    now.duration_since(*fail_time) < backoff
                                });
                                failed.insert(hostname.clone(), now);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(hostname = %hostname, error = %e, "sentin8-tls: ACME cert request failed");
                        let mut failed = failed.write();
                        // Same eviction bound as the failure branch above
                        // (tls README §5,).
                        let now = std::time::Instant::now();
                        failed.retain(|_, fail_time| now.duration_since(*fail_time) < backoff);
                        failed.insert(hostname.clone(), now);
                    }
                }
                // Ownership ends here in EVERY branch - a detached task that
                // exits without clearing `pending` would latch the entry and
                // make every follow-up handshake eat the dead wait
                // (tls README §6 "waiters never starve the negative cache").
                pending.write().remove(&hostname);
            });

            // FIRST-TOUCH HOLD (tls README §6): the spawning handshake does
            // not reject - it waits for the fetch it just armed (same poll
            // loop as the already-pending branch). A no-retry client (the
            // OIDF suite's Java client, single-shot HTTP fetches) otherwise
            // receives access_denied for the ~100 ms the fetch takes and
            // reports a spurious failure - every conformance run after a
            // service restart tripped this. The wait shares the same
            // negative-cache exit as the pending branch (failure → None,
            // next handshake re-arms post-backoff).
            let hostname = sni.to_string();
            let exact = self.exact.clone();
            let failed = self.failed.clone();
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(CERT_FETCH_WAIT_S);
            while std::time::Instant::now() < deadline {
                if let Some(key) = exact.read().get(&hostname) {
                    return Some(key.clone());
                }
                if failed.read().contains_key(&hostname) {
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            return None;
        }
    }
}

/// Parse a PEM cert + key into a rustls CertifiedKey.
fn parse_certified_key(
    hostname: &str,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<CertifiedKey, String> {
    let mut cert_reader = std::io::BufReader::new(cert_pem);
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .filter_map(|r| r.ok())
            .collect();

    let mut key_reader = std::io::BufReader::new(key_pem);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("parse private key for {hostname}: {e}"))?
        .ok_or_else(|| format!("no private key for {hostname}"))?;

    let signing_key = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| format!("no crypto provider installed for {hostname}"))?
        .key_provider
        .load_private_key(key)
        .map_err(|e| format!("unsupported key type for {hostname}: {e}"))?;

    Ok(CertifiedKey::new(cert_chain, signing_key))
}

impl WildcardCertResolver {
    /// Resolve the ACME directory URL from service discovery.
    /// Returns `None` if ACME is not yet Active in the registry - fail fast
    /// rather than falling back to a static URL that may be stale.
    ///
    /// Returns `(directory_url, sni_host, socket_addr)` so the caller can
    /// build a reqwest client with `.resolve(&sni_host, socket_addr)` -
    /// this pins the IP while sending the correct SNI hostname, which is
    /// required because the ACME server's `WildcardCertResolver` can only
    /// find its bootstrap cert by SNI hostname, not by raw IP.
    fn resolve_acme_endpoint(&self) -> Option<(String, String, std::net::SocketAddr)> {
        // Discovery first: it carries the live IP:port, which is the only way to
        // pin the connection to a specific ACME instance.
        //
        // When discovery has no healthy `sentin8:acme` - a boot race, or a
        // registry that has not yet observed the instance - the CONFIGURED
        // `acme_url` is the fallback. It exists on this struct precisely for that
        // case, and ignoring it left a service unable to mint a cert whenever
        // discovery lagged, with the failure surfacing only as "ACME not resolved
        // via service discovery".
        let discovered = self
            .discovery
            .as_ref()
            .and_then(|d| d.resolve_instance("sentin8:acme"));
        let Some(inst) = discovered else {
            return self.acme_endpoint_from_config();
        };
        let socket_addr = std::net::SocketAddr::from((
            inst.local_ip
                .parse::<std::net::IpAddr>()
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            inst.local_port,
        ));
        let sentin8_domain =
            std::env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "local.sentin8.dev".to_string());
        let sni_host = format!("acme.ops.sys.{sentin8_domain}");
        // ADDRESSING: a platform hostname URL NEVER carries a port - the
        // name implies 443 through the Proxy. The real backend port rides
        // the pinned SocketAddr (below) and reqwest applies it because the
        // URL has no explicit port (`explicit_port == false` => the
        // resolved address keeps its own port).
        let url = acme_directory_url(&sni_host);
        tracing::info!(url = %url, sni = %sni_host, ip = %inst.local_ip, port = inst.local_port, "sentin8-tls: resolved ACME endpoint from service discovery");
        Some((url, sni_host, socket_addr))
    }

    /// Build the ACME endpoint from the configured `acme_url` alone.
    ///
    /// Used when service discovery has no healthy ACME instance. The host is
    /// resolved to an IP so the pin still applies; the port comes from the URL.
    fn acme_endpoint_from_config(&self) -> Option<(String, String, std::net::SocketAddr)> {
        let url = self.acme_url.trim().trim_end_matches('/').to_string();
        if url.is_empty() {
            return None;
        }
        let parsed = reqwest::Url::parse(&url).ok()?;
        let configured_host = parsed.host_str()?.to_string();

        // The SNI must be ACME's DNS NAME, not an IP. The configured URL usually
        // carries the raw orchestrator IP (`https://192.168.x.y:8002/...`), and
        // the ACME server picks its bootstrap certificate by SNI hostname - an IP
        // SNI matches nothing and the handshake fails. Derive the name from
        // SENTIN8_DOMAIN, which is how every other ACME reference in the fleet
        // is built.
        let sentin8_domain =
            std::env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "local.sentin8.dev".to_string());
        let host_is_ip = configured_host.parse::<std::net::IpAddr>().is_ok();
        let host = if host_is_ip {
            format!("acme.ops.sys.{sentin8_domain}")
        } else {
            configured_host.clone()
        };

        // Port: an explicit one in the configured URL wins; a PORTLESS
        // configured URL means "ACMEC behind the Proxy on 443", so the
        // backend port comes from the captain-assigned var instead of
        // being guessed as 443.
        let port = match parsed.port() {
            Some(p) => p,
            None => std::env::var("SENTIN8_ACME_PORT")
                .ok()
                .and_then(|p| p.trim().parse().ok())
                .unwrap_or_else(sentin8_config::port_pool_low),
        };

        // Pin to the configured IP when it is one; otherwise resolve the name.
        let ip = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            ip
        } else if host_is_ip {
            configured_host.parse::<std::net::IpAddr>().ok()?
        } else {
            std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port))
                .ok()
                .and_then(|mut it| it.next())
                .map(|sa| sa.ip())?
        };

        // ADDRESSING: the emitted URL is ALWAYS portless. A platform
        // hostname URL never carries a port - the port lives on the pinned
        // SocketAddr, which reqwest applies because the URL has none.
        let path = if parsed.path().is_empty() {
            "/acme/directory"
        } else {
            parsed.path()
        };
        let url = format!("https://{host}{path}");

        let socket_addr = std::net::SocketAddr::new(ip, port);
        tracing::info!(
            url = %url,
            sni = %host,
            %ip,
            port,
            "sentin8-tls: resolved ACME endpoint from CONFIGURED url (discovery had no healthy instance)"
        );
        Some((url, host, socket_addr))
    }
}

/// Request a certificate from Acme for the given domain.
///
/// Full ACME (RFC 8555) client flow. Returns `(cert_pem, key_pem)`.
///
/// Parent path of the ACME directory URL, for the sibling endpoints.
///
/// The directory lives at `{base}/acme/directory`, and `new-account` /
/// `new-order` are siblings of `directory`, not children of it. Appending
/// `/../new-account` to the directory URL produces
/// `/acme/directory/../new-account`, which RFC 3986 clients may or may not
/// normalise before sending - and a server that routes on the literal path
/// answers 404. Deriving the parent explicitly removes the ambiguity.
fn acme_sibling_url(acme_directory_url: &str) -> &str {
    let trimmed = acme_directory_url.trim_end_matches('/');
    let Some((parent, _)) = trimmed.rsplit_once('/') else {
        return trimmed;
    };
    // A bare origin (`https://host`) splits at the scheme's own slash and would
    // yield `https:`. Anything with no path left after the authority degrades to
    // the input rather than to a broken URL.
    if parent.ends_with(":/") || parent.ends_with(':') {
        return trimmed;
    }
    parent
}

/// The ACME directory URL for a platform hostname.
///
/// ADDRESSING RULE (repo-wide, non-negotiable): a platform hostname URL
/// never carries a port. `https://{host}/acme/directory` means "port 443
/// through the Proxy", which routes by SNI. The backend port belongs to
/// the pinned `SocketAddr`, never to the URL.
fn acme_directory_url(sni_host: &str) -> String {
    format!("https://{sni_host}/acme/directory")
}

/// `acme_directory_url` - the directory URL with the SNI hostname
/// (e.g. `https://acme.ops.sys.local.sentin8.dev/acme/directory`).
/// `sni_host` - the SNI hostname for the ACME server (same as in the URL).
/// `socket_addr` - the pinned IP:port to connect to (overrides DNS).
/// `domain` - the domain to issue a cert for.
pub async fn request_cert_from_acme(
    acme_directory_url: &str,
    sni_host: &str,
    socket_addr: std::net::SocketAddr,
    domain: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    tracing::info!(domain, "sentin8-tls: requesting certificate from Acme");

    // reqwest keys the override on the DOMAIN ONLY, and its own docs are
    // explicit: "Ports in the URL itself will always be used instead of the port
    // in the overridden addr." So the domain registered here must be the bare
    // hostname - never `host:port`, which would match nothing and send the
    // request to system DNS. Inside the fleet that DNS cannot resolve
    // `acme.ops.sys.{domain}`, and the failure surfaces as a bare
    // "error sending request" with no hint that the pin never applied.
    let pinned_domain = match sni_host.rsplit_once(':') {
        Some((host, _)) if !host.is_empty() => host,
        _ => sni_host,
    };
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(10))
        .resolve(pinned_domain, socket_addr)
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    // Helper: send a request and parse JSON, including the response body
    // text in the error message when the status is not success.
    async fn send_json(
        client: &reqwest::Client,
        method: reqwest::Method,
        url: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let mut req = client
            .request(method, url)
            .header("Content-Type", "application/jose+json");
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| {
            // reqwest's Display is a single opaque line; its Debug carries the
            // cause (`is_dns`, `is_connect`, `is_tls`, ...). Every earlier
            // diagnosis of an ACME fetch failure guessed wrong because Display
            // hid that, so log both plus the structured predicates.
            format!(
                "request to {url} failed: {e} | debug={e:?} | connect={} request={} body={} timeout={}",
                e.is_connect(),
                e.is_request(),
                e.is_body(),
                e.is_timeout(),
            )
        })?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("read body from {url}: {e}"))?;
        if !status.is_success() {
            return Err(format!(
                "{url} returned {status}: {}",
                if text.len() > 200 {
                    &text[..200]
                } else {
                    &text
                }
            ));
        }
        serde_json::from_str(&text).map_err(|e| {
            format!("parse JSON from {url}: {e} (body: {})", {
                let t: String = text.chars().take(200).collect();
                t
            })
        })
    }

    // 1. New account
    let account_url = format!("{}/new-account", acme_sibling_url(acme_directory_url));
    let account_resp = send_json(
        &client,
        reqwest::Method::POST,
        &account_url,
        Some(serde_json::json!({"termsOfServiceAgreed": true, "contact": []})),
    )
    .await?;

    let _account_id = account_resp.get("id").ok_or("new-account: missing id")?;

    // 2. New order
    let order_url = format!("{}/new-order", acme_sibling_url(acme_directory_url));
    let order_resp = send_json(
        &client,
        reqwest::Method::POST,
        &order_url,
        Some(serde_json::json!({
            "identifiers": [{"type": "dns", "value": domain}],
        })),
    )
    .await?;

    let authz_url = order_resp
        .get("authorizations")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|a| a.as_str())
        .ok_or("new-order: missing authorizations")?;

    let finalize_url = order_resp
        .get("finalize")
        .and_then(|f| f.as_str())
        .ok_or("new-order: missing finalize URL")?;

    // 3. Get authorization + challenge
    let authz_resp = send_json(&client, reqwest::Method::GET, authz_url, None).await?;

    let challenge_url = authz_resp
        .get("challenges")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .and_then(|c| c.get("url"))
        .and_then(|u| u.as_str())
        .ok_or("authz: missing challenge URL")?;

    // 4. Notify challenge ready (Acme short-circuits local domains to valid)
    send_json(
        &client,
        reqwest::Method::POST,
        challenge_url,
        Some(serde_json::json!({})),
    )
    .await?;

    // 5. Finalize with a placeholder CSR.
    // Acme decodes the CSR with URL_SAFE_NO_PAD, so we must encode
    // with the same alphabet. The CSR content is a placeholder -
    // acme generates its own key via rcgen and ignores the CSR DER.
    let csr_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(
        "-----BEGIN CERTIFICATE REQUEST-----\n{domain}\n-----END CERTIFICATE REQUEST-----"
    ));
    let finalize_resp = send_json(
        &client,
        reqwest::Method::POST,
        finalize_url,
        Some(serde_json::json!({"csr": csr_b64})),
    )
    .await?;

    let cert_url = finalize_resp
        .get("certificate")
        .and_then(|c| c.as_str())
        .ok_or("finalize: missing certificate URL")?;

    // 6. Download the certificate. Acme's `GET /acme/cert/{id}` returns a
    //    combined PEM (cert chain followed by the private key) for locally-
    //    signed domains - see `acme::acme::get_cert`. Split it into
    //    separate cert and key buffers.
    let combined = client
        .get(cert_url)
        .send()
        .await
        .map_err(|e| format!("cert download failed: {e}"))?
        .text()
        .await
        .map_err(|e| format!("cert body parse failed: {e}"))?;

    let (cert_pem, key_pem) = split_combined_pem(&combined)?;
    tracing::info!(domain, "sentin8-tls: certificate obtained from Acme");
    Ok((cert_pem, key_pem))
}

/// Split a combined PEM (cert chain + private key) returned by Acme's
/// certificate-download endpoint into separate `(cert_pem, key_pem)` buffers.
///
/// We locate the first private-key block and split there: everything before
/// it is the certificate chain, from there on is the key. The original bytes
/// are preserved (no DER re-encoding).
fn split_combined_pem(combined: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    const KEY_MARKERS: [&str; 3] = [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    ];
    let key_start = KEY_MARKERS
        .iter()
        .find_map(|m| combined.find(m))
        .ok_or_else(|| "combined PEM: no private key block found".to_string())?;
    let cert_pem = combined[..key_start].bytes().collect::<Vec<u8>>();
    let key_pem = combined[key_start..].bytes().collect::<Vec<u8>>();
    Ok((cert_pem, key_pem))
}

#[cfg(test)]
mod acme_url_tests {
    use super::acme_sibling_url;

    #[test]
    fn sibling_is_the_parent_path() {
        // A server routing on the literal path would 404 the `/../` form.
        assert_eq!(
            acme_sibling_url("https://acme.ops.sys.example.dev:8002/acme/directory"),
            "https://acme.ops.sys.example.dev:8002/acme"
        );
    }

    #[test]
    fn trailing_slash_is_ignored() {
        assert_eq!(
            acme_sibling_url("https://acme.example.dev/acme/directory/"),
            "https://acme.example.dev/acme"
        );
    }

    #[test]
    fn a_bare_origin_degrades_to_itself() {
        // Defensive: an unexpected shape must not produce an empty URL.
        assert_eq!(
            acme_sibling_url("https://acme.example.dev"),
            "https://acme.example.dev"
        );
    }
}

#[cfg(test)]
mod addressing_rule_tests {
    use super::acme_directory_url;

    /// ADDRESSING RULE: a platform hostname URL never carries a port.
    ///
    /// Regression for the live failure where every service built
    /// `https://acme.ops.sys.{domain}:8002/acme/directory` and reported
    /// "cannot reach acme". The port belongs to the pinned SocketAddr.
    #[test]
    fn acme_directory_url_is_portless() {
        assert_eq!(
            acme_directory_url("acme.ops.sys.local.sentin8.dev"),
            "https://acme.ops.sys.local.sentin8.dev/acme/directory"
        );
    }

    #[test]
    fn acme_directory_url_never_contains_a_port() {
        let url = acme_directory_url("acme.ops.sys.oidf.sentin8.dev");
        let after_scheme = url.trim_start_matches("https://");
        let authority = after_scheme.split('/').next().unwrap_or_default();
        assert!(
            !authority.contains(':'),
            "authority must have no port separator: {authority}"
        );
    }
}

#[cfg(test)]
mod resolve_key_tests {
    /// The domain handed to reqwest's `.resolve()` must be the bare hostname.
    ///
    /// reqwest 0.12 documents: "Ports in the URL itself will always be used
    /// instead of the port in the overridden addr." Registering `host:port`
    /// therefore matches nothing and the override silently never applies - the
    /// request goes to system DNS, which cannot resolve a fleet service name.
    fn pinned_domain(sni_host: &str) -> &str {
        match sni_host.rsplit_once(':') {
            Some((host, _)) if !host.is_empty() => host,
            _ => sni_host,
        }
    }

    #[test]
    fn a_host_port_sni_yields_the_bare_host() {
        assert_eq!(
            pinned_domain("acme.ops.sys.example.dev:8002"),
            "acme.ops.sys.example.dev"
        );
    }

    #[test]
    fn a_bare_host_is_unchanged() {
        assert_eq!(
            pinned_domain("acme.ops.sys.example.dev"),
            "acme.ops.sys.example.dev"
        );
    }

    #[test]
    fn a_scheme_only_string_does_not_become_empty() {
        // Defensive: an odd input must never produce an empty domain, which
        // would register an override for "" and match every request.
        assert_eq!(pinned_domain(":8002"), ":8002");
    }
}
