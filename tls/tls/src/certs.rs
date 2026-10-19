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
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
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

            // No fetch in progress - spawn the fetch as a DETACHED task.
            // It must NOT run inline on the handshake task: when the peer
            // resets mid-handshake, the handshake future is dropped and an
            // inline fetch dies with it (Acme receives new-account then
            // silence, the pending marker leaks, and backoff plus
            // client-gave-up suppress re-issuance for minutes - tls README
            // §6 "the cert fetch is owned by a DETACHED task").
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
            tokio::spawn(async move {
                // The detached fetch inherits hard per-request deadlines from
                // `request_cert_from_acme` (3 s connect / 10 s total) - a
                // hung Acme cannot hold a worker thread.
                let fetched =
                    request_cert_from_acme(&acme_url, &acme_sni, acme_addr, &hostname).await;
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
                                // (tls README §5, CR-TLS-2).
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
                        // (tls README §5, CR-TLS-2).
                        let now = std::time::Instant::now();
                        failed.retain(|_, fail_time| now.duration_since(*fail_time) < backoff);
                        failed.insert(hostname.clone(), now);
                    }
                }
                // Ownership ends here in EVERY branch - a detached task that
                // exits without clearing `pending` would latch the entry and
                // make every follow-up handshake eat the 15 s dead wait
                // (tls README §6 "waiters never starve the negative cache").
                pending.write().remove(&hostname);
            });
        }

        None
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
        let d = self.discovery.as_ref()?;
        let inst = d.resolve_instance("sentin8:acme")?;
        let socket_addr = std::net::SocketAddr::from((
            inst.local_ip
                .parse::<std::net::IpAddr>()
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            inst.local_port,
        ));
        let sentin8_domain =
            std::env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "sentin8.local".to_string());
        let sni_host = format!("acme.ops.sys.{sentin8_domain}");
        let url = format!("https://{}:{}/acme/directory", sni_host, inst.local_port);
        tracing::info!(url = %url, sni = %sni_host, ip = %inst.local_ip, port = inst.local_port, "sentin8-tls: resolved ACME endpoint from service discovery");
        Some((url, sni_host, socket_addr))
    }
}

/// Request a certificate from Acme for the given domain.
///
/// Full ACME (RFC 8555) client flow. Returns `(cert_pem, key_pem)`.
///
/// `acme_directory_url` - the directory URL with the SNI hostname
/// (e.g. `https://acme.ops.sys.sentin8.local:8008/acme/directory`).
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

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(10))
        .resolve(sni_host, socket_addr)
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
        let resp = req
            .send()
            .await
            .map_err(|e| format!("request to {url} failed: {e}"))?;
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
    let account_url = format!("{acme_directory_url}/../new-account");
    let account_resp = send_json(
        &client,
        reqwest::Method::POST,
        &account_url,
        Some(serde_json::json!({"termsOfServiceAgreed": true, "contact": []})),
    )
    .await?;

    let _account_id = account_resp.get("id").ok_or("new-account: missing id")?;

    // 2. New order
    let order_url = format!("{acme_directory_url}/../new-order");
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
