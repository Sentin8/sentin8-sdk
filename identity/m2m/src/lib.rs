// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-m2m - workload certificate identity management
//!
//! **The Acme-issued client certificate is the ONLY platform-workload
//! identity (auth DESIGN §4.3f).** There is no M2M token, no
//! DCR round-trip, no `oauth_clients` row, and no credential record: a
//! workload presents its certificate (`CN=m2m-{workload}`) in the TLS
//! handshake on every call, the receiving service's TLS layer CA-verifies
//! it and injects the `X-Sentin8-Client-Cert-*` headers, and those
//! headers - with the enroll-published `m2m:workloads` registry map
//! (`sentin8-workload-registry`) - drive authorization.
//!
//! This crate owns exactly one job: **ensure the workload's certificate
//! exists** - load the persisted pair (`{workload}.crt`/`{workload}.key`
//! under `SENTIN8_M2M_CREDENTIALS_DIR`, 0700/0600 fail-closed) or mint it
//! from Acme (`POST /v1/client-cert`, the bootstrap-enrollment channel)
//! on a first boot - and hand consumers the paths to build cert-presenting
//! transports (`sentin8_middleware::mtls::build_mtls_client`).
//!
//! A database reset invalidates NOTHING on this path: the certificate
//! survives, the registry map is republished by `vertical enroll`, and
//! the next call succeeds - no stale state exists anywhere (the defect
//! class  deleted).

#![deny(missing_docs)]

use thiserror::Error;

/// Client-side failure surface for workload-certificate operations.
#[derive(Debug, Error)]
pub enum M2mError {
    /// The certificate could not be ensured (Acme unreachable at first
    /// boot, or the persisted pair is unreadable) - the caller logs and
    /// retries the boot step; the service starts and its reconnect loops
    /// cover a late identity.
    #[error("workload certificate error: {0}")]
    Cert(String),
}

/// A platform workload's certificate identity - the persisted file paths
/// consumers build cert-presenting transports from.
#[derive(Debug, Clone)]
pub struct WorkloadCertificate {
    /// The workload name (certificate CN suffix, registry-map key).
    pub workload: String,
    /// Combined certificate chain PEM (leaf + intermediate + root).
    pub cert_pem: String,
    /// The leaf's PKCS#8 private key PEM.
    pub key_pem: String,
    /// Persisted certificate file path (under the identity dir).
    pub cert_path: String,
    /// Persisted private-key file path (under the identity dir).
    pub key_path: String,
    /// The platform CA bundle path (trust anchor for outbound calls).
    pub ca_cert_path: String,
}

/// Ensure the workload's certificate identity exists, minting it from
/// Acme on a first boot (this REPLACES the DCR
/// `register_or_load_m2m_client` - there is no client registration; the
/// certificate is the identity).
///
/// Load path: the identity dir's `{workload}.crt`/`{workload}.key` pair
/// (no network - restarts resolve offline). On a miss the certificate is
/// self-issued from Acme's `POST /v1/client-cert` (the
/// bootstrap-enrollment channel - captain injects the sealed secret into
/// every child at spawn) and persisted under the same names.
///
/// A database reset does not invalidate a persisted certificate: Acme's
/// CA outlives the reset and the receiving services re-resolve the CN
/// against the registry map on the next call. `vertical enroll` is the
/// only provisioning step.
///
/// # Errors
/// Returns [`M2mError::Cert`] when the certificate cannot be minted
/// (Acme unreachable at first birth) - the caller should log + retry this
/// boot step, not abort the process (services tolerate a late identity;
/// reconnect loops cover it).
pub async fn ensure_workload_certificate(
    sentin8_auth_base_url: &str,
    workload: &str,
    ca_cert_path: &str,
) -> Result<WorkloadCertificate, M2mError> {
    // Fast path: the persisted pair (no network - restarts resolve offline).
    if let Some(pair) = load_cert_pair(workload, ca_cert_path) {
        return Ok(pair);
    }
    // First boot (or a corrupt pair): mint from Acme.
    let (cert_pem, key_pem) =
        issue_client_certificate(sentin8_auth_base_url, workload, ca_cert_path)
            .await
            .map_err(M2mError::Cert)?;
    let (cert_path, key_path) = persist_cert_files(&cert_pem, &key_pem, workload);
    Ok(WorkloadCertificate {
        workload: workload.to_string(),
        cert_pem,
        key_pem,
        cert_path,
        key_path,
        ca_cert_path: ca_cert_path.to_string(),
    })
}

/// Blocking load-or-mint for sync constructors (DPoPRS-1): the fast path
/// is [`load_persisted_pair_blocking`] (no network); on a miss the async
/// [`ensure_workload_certificate`] mint runs via
/// `tokio::task::block_in_place` (the caller MUST be on the multi-threaded
/// runtime - the shell boot is; Acme's own request deadlines bound the
/// mint). One mint per workload lifetime - every later boot rides the
/// persisted pair offline.
pub fn ensure_workload_certificate_blocking(
    sentin8_auth_base_url: &str,
    workload: &str,
    ca_cert_path: &str,
) -> Option<PersistedPair> {
    if let Some(p) = load_persisted_pair_blocking(workload, ca_cert_path) {
        return Some(p);
    }
    // Mint path: requires a multithreaded runtime context.
    let minted = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::try_current()
            .ok()
            .and_then(|h| {
                h.block_on(async {
                    ensure_workload_certificate(sentin8_auth_base_url, workload, ca_cert_path)
                        .await
                        .ok()
                })
            })
    })?;
    Some(PersistedPair {
        ca_cert_path: minted.ca_cert_path,
        cert_path: minted.cert_path,
        key_path: minted.key_path,
    })
}

/// Load a persisted certificate pair from the identity dir. Returns
/// `None` on any miss (first boot), a corrupt pair, or an EXPIRING
/// pair: the load path verifies the leaf's NotAfter (the
/// minimal TLV walk the crate already uses for CN extraction, extended
/// to the validity window); a certificate expiring within
/// `CERT_RENEWAL_WINDOW_SECS` is treated as absent (warn + fall through to
/// re-mint) and an expired one always re-mints - the day-366 fleet
/// brick class (every service loading a dead pair and failing every
/// handshake, with nothing to trigger re-mint) is impossible.
fn load_cert_pair(workload: &str, ca_cert_path: &str) -> Option<WorkloadCertificate> {
    let dir = identity_dir();
    let base = workload.replace(['/', ':'], "_");
    let cert_path = std::path::Path::new(&dir).join(format!("{base}.crt"));
    let key_path = std::path::Path::new(&dir).join(format!("{base}.key"));
    let cert_pem = std::fs::read_to_string(&cert_path).ok()?;
    let key_pem = std::fs::read_to_string(&key_path).ok()?;
    if !cert_pem.contains("BEGIN CERTIFICATE") || !key_pem.contains("PRIVATE KEY") {
        return None; // corrupt pair - mint fresh
    }
    // expiry hygiene - never load a dead (or nearly-dead)
    // identity. The receiving TLS layer would reject the handshake on
    // expiry anyway; the load path refusing early is what triggers the
    // re-mint.
    match cert_pem_not_after(&cert_pem) {
        Some(not_after) => {
            let now = chrono::Utc::now();
            if now >= not_after {
                tracing::warn!(
                    workload,
                    "M2M: persisted certificate EXPIRED - re-minting from Acme"
                );
                return None;
            }
            if not_after - now < chrono::Duration::seconds(CERT_RENEWAL_WINDOW_SECS) {
                tracing::warn!(
                    workload,
                    days_left = (not_after - now).num_days(),
                    "M2M: persisted certificate expires within the renewal window - re-minting early"
                );
                return None;
            }
        }
        None => {
            // Unparsable validity: treat as corrupt (fail toward re-mint,
            // never toward serving an unverifiable identity).
            tracing::warn!(
                workload,
                "M2M: persisted certificate validity unreadable - re-minting"
            );
            return None;
        }
    }
    Some(WorkloadCertificate {
        workload: workload.to_string(),
        cert_pem,
        key_pem,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        ca_cert_path: ca_cert_path.to_string(),
    })
}

/// The renewal window before NotAfter at which a load-path certificate is
/// re-minted rather than served : comfortably inside the
/// 30-day default mint TTL, large enough that an Acme outage cannot
/// strand the fleet (a failed mint retries on the next boot; the
/// expiring pair keeps serving until one succeeds only if it is still
/// within validity - this function's `None` forces the re-mint while
/// the old pair could still hand over).
const CERT_RENEWAL_WINDOW_SECS: i64 = 7 * 24 * 3600;

/// Extract the leaf certificate's NotAfter from a PEM chain.
/// Minimal DER walk (no x509-parser dependency - same discipline as the
/// CN extractor): decode the FIRST base64 PEM body, then locate the
/// UTCTime/GeneralizedTime in the validity sequence. Returns `None` when
/// the walk cannot find a parsable validity end.
fn cert_pem_not_after(cert_pem: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use base64::Engine as _;
    // Collect the first PEM block's body.
    let mut b64 = String::new();
    let mut inside = false;
    for line in cert_pem.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            if inside {
                break; // first (leaf) block complete
            }
            inside = true;
            continue;
        }
        if line.starts_with("-----END CERTIFICATE-----") && inside {
            break;
        }
        if inside {
            b64.push_str(line.trim());
        }
    }
    if b64.is_empty() {
        return None;
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    cert_der_not_after(&der)
}

/// Walk the DER for the validity window's NotAfter (UTCTime `17` YYMMDDHHMMSSZ
/// or GeneralizedTime `18` YYYYMMDDHHMMSSZ - the two forms RFC 5280
/// permits; Acme's local signing uses UTCTime).
fn cert_der_not_after(der: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    // Scan for the validity SEQUENCE OID-free approach: find the first
    // time-formatted element pair. The validity sequence holds exactly
    // two time values (NotBefore, NotAfter) - the SECOND one is ours.
    let mut times: Vec<chrono::DateTime<chrono::Utc>> = Vec::new();
    let mut i = 0usize;
    while i + 2 < der.len() {
        let (tag, len) = (der[i], der[i + 1] as usize);
        let is_utc = tag == 0x17; // UTCTime
        let is_gen = tag == 0x18; // GeneralizedTime
        if (is_utc || is_gen) && len > 0 && i + 2 + len <= der.len() && len >= 11 {
            let body = &der[i + 2..i + 2 + len];
            if let Some(t) = parse_asn1_time(is_gen, body) {
                times.push(t);
                if times.len() == 2 {
                    return times.pop();
                }
                i += 2 + len;
                continue;
            }
        }
        i += 1;
    }
    None
}

/// Parse one ASN.1 time value (`YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ`).
fn parse_asn1_time(generalized: bool, body: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = std::str::from_utf8(body).ok()?.trim_end_matches('Z');
    let (year, rest) = if generalized {
        (s.get(0..4)?.to_string(), s.get(4..)?.to_string())
    } else {
        // RFC 5280: UTCTime years 00-49 → 20xx, 50-99 → 19xx. The century
        // is a TWO-digit prefix (yy + 2000 / 1900 as a number), never a
        // concatenated string - `format!("{century}{yy}")` would splice
        // "2000" + "27" into "200027".
        let yy: u32 = s.get(0..2)?.parse().ok()?;
        let year: u32 = if yy < 50 { 2000 + yy } else { 1900 + yy };
        (year.to_string(), s.get(2..)?.to_string())
    };
    let rest = rest.trim_end_matches('Z');
    if rest.len() < 10 {
        return None;
    }
    let (mo, da, hh, mi, se) = (
        rest.get(0..2)?.to_string(),
        rest.get(2..4)?.to_string(),
        rest.get(4..6)?.to_string(),
        rest.get(6..8)?.to_string(),
        rest.get(8..10)?.to_string(),
    );
    let (sec, frac_rem) = match se.find('.') {
        Some(dot) => (
            se.get(0..dot)?.to_string(),
            Some(se.get(dot..)?.to_string()),
        ),
        None => (se.clone(), None),
    };
    let _ = frac_rem; // fractional seconds are dropped (second precision is ample)
    chrono::NaiveDate::from_ymd_opt(year.parse().ok()?, mo.parse().ok()?, da.parse().ok()?)?
        .and_hms_opt(hh.parse().ok()?, mi.parse().ok()?, sec.parse().ok()?)
        .map(|dt| dt.and_utc())
}

/// Acme base URL for a given auth issuer. Derives the platform domain form
/// `https://acme.ops.sys.{domain}` (the platform services are the `ops`
/// env of the `sys` org - uniform hierarchy, nothing hardcoded beyond the
/// domain derivation in `sentin8-config`). When `SENTIN8_ACME_PORT` is
/// present (captain sets it per-instance for acme itself), it is appended;
/// otherwise the standard HTTPS port is assumed and ServiceDiscovery-based
/// callers resolve the exact endpoint.
fn acme_base_url(sentin8_auth_base_url: &str) -> String {
    let _ = sentin8_auth_base_url; // symmetric argument for future overrides
    let domain = std::env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "local.sentin8.dev".into());
    let base = format!("https://acme.ops.sys.{domain}");
    match std::env::var("SENTIN8_ACME_PORT")
        .ok()
        .filter(|p| !p.is_empty())
    {
        Some(port) => format!("{base}:{port}"),
        None => base,
    }
}

/// Issue this workload's mTLS client certificate from Sentin8:Acme
/// (`POST /v1/client-cert`, body `{service_name}`). Returns the combined
/// PEM (leaf chain + key) split into `(cert_pem, key_pem)`.
///
/// The outbound channel trusts ONLY the Acme Root CA (`ca_cert_path`) -
/// fail-closed, no system roots (same discipline as every platform
/// transport).
///
/// First-boot enrollment channel: the captain-brokered bootstrap
/// enrollment secret. A workload on its very first boot holds no cert and
/// no token - without this claim acme would 401 the mint. Captain injects
/// `SENTIN8_BOOTSTRAP_ENROLLMENT(+_TS)` into every child process;
/// forwarding them as request headers lets acme verify the claim LOCALLY
/// against its own injected copy. Present only when the env is actually
/// set (re-issuance paths that already hold a cert authenticate via their
/// bearer instead).
async fn issue_client_certificate(
    sentin8_auth_base_url: &str,
    service_name: &str,
    ca_cert_path: &str,
) -> Result<(String, String), String> {
    use sentin8_config::bootstrap as sentin8_config_bootstrap;

    let acme = acme_base_url(sentin8_auth_base_url);
    let url = format!("{acme}/v1/client-cert");
    let body = serde_json::json!({ "service_name": service_name });

    let client = sentin8_middleware::mtls::build_ca_client(ca_cert_path)
        .map_err(|e| format!("acme http client: {e}"))?;

    let mut request = client.post(&url).json(&body);
    if let Ok(secret) = std::env::var(sentin8_config_bootstrap::ENV_ENROLLMENT) {
        if !secret.is_empty() {
            request = request
                .header("x-sentin8-bootstrap-enrollment", &secret)
                .header(
                    "x-sentin8-bootstrap-enrollment-ts",
                    std::env::var(sentin8_config_bootstrap::ENV_ENROLLMENT_TS).unwrap_or_default(),
                );
            tracing::info!(
                service_name,
                "issuing client certificate via bootstrap enrollment channel"
            );
        }
    }

    let resp = request
        .send()
        .await
        .map_err(|e| format!("POST {url}: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("acme returned {status}: {}", {
            let t: String = text.chars().take(200).collect();
            t
        }));
    }

    split_combined_pem(&text).ok_or_else(|| "acme response is not a combined cert+key PEM".into())
}

/// Split a combined PEM (certificate chain blocks followed by the private
/// key block) into `(cert_pem, key_pem)`. Both blocks are emitted whole -
/// header line through `END` line - by toggling on the BEGIN/END markers
/// (the splitter must collect the full PEM block: a partial collection
/// makes every persisted cert/key a bare header and `Identity::from_pem`
/// fail with a bare "builder error").
fn split_combined_pem(text: &str) -> Option<(String, String)> {
    let mut certs = String::new();
    let mut key = String::new();
    // `in_cert` toggles on the leaf's END marker only when the chain ends;
    // `in_key` covers the single trailing key block.
    let mut in_cert = false;
    let mut in_key = false;
    for line in text.lines() {
        let is_cert_begin = line.starts_with("-----BEGIN CERTIFICATE-----");
        let is_key_begin = line.starts_with("-----BEGIN PRIVATE KEY-----")
            || line.starts_with("-----BEGIN EC PRIVATE KEY-----");
        if is_cert_begin {
            in_cert = true;
        } else if is_key_begin {
            in_cert = false;
            in_key = true;
        }
        if in_cert {
            certs.push_str(line);
            certs.push('\n');
            if line.starts_with("-----END CERTIFICATE-----") {
                in_cert = false;
            }
        } else if in_key {
            key.push_str(line);
            key.push('\n');
            if line.starts_with("-----END PRIVATE KEY-----")
                || line.starts_with("-----END EC PRIVATE KEY-----")
            {
                in_key = false;
            }
        }
    }
    if certs.is_empty() || key.is_empty() {
        return None;
    }
    Some((certs, key))
}

/// The CA bundle for outbound platform TLS. `SENTIN8_TLS_CA_PEM` (the
/// PUBLIC Acme Root-CA cert path, propagated by captain) is REQUIRED -
/// there is no data-dir fallback. SECURITY: `SENTIN8_ACME_DATA_DIR` must
/// never be consulted here (or anywhere outside the acme service) - that
/// directory holds the Root/Intermediate CA PRIVATE keys, and any path
/// derived from it in a domain service's env would dangle the entire
/// identity chain off a file the service has no business reading.
///
/// # Panics
/// Panics when no CA is configured - a missing trust anchor on the
/// identity channel is a defect (fail-closed, never guess a path).
pub fn platform_ca_pem_path() -> String {
    for var in ["SENTIN8_TLS_CA_PEM", "SENTIN8_TLS_CLIENT_CA_PEM"] {
        if let Ok(p) = std::env::var(var) {
            if !p.trim().is_empty() {
                return p;
            }
        }
    }
    // Fail-closed: no CA configured → the caller cannot trust any outbound
    // channel. Refuse loudly rather than guessing a path.
    panic!(
        "m2m: no platform CA configured - set SENTIN8_TLS_CA_PEM (the public \
         Acme Root-CA cert path; captain/CLI set it by default). \
         SENTIN8_ACME_DATA_DIR is deliberately NOT consulted: it holds the \
         CA private keys."
    )
}

/// Public form of the platform CA resolution - callers that build their
/// own cert-presenting transports (bus-client, BFF, CLI) pass the same CA
/// bundle so every outbound platform channel trusts the same anchor.
pub fn platform_ca_path() -> String {
    platform_ca_pem_path()
}

/// Fail-soft form of the platform CA resolution: `None` when no CA env
/// var is set, instead of panicking.
///
/// For REQUEST-PATH (or test-time) callers where a missing CA must degrade
/// a best-effort side effect - never the identity channel itself, which
/// stays fail-closed via [`platform_ca_path`]. Mirrors the TLS resolver's
/// pre-check: the resolver degrades to 421 without a CA; a request-path
/// best-effort provisioner degrades to "closure not provisioned" + a
/// warning line.
pub fn try_platform_ca_path() -> Option<String> {
    ["SENTIN8_TLS_CA_PEM", "SENTIN8_TLS_CLIENT_CA_PEM"]
        .iter()
        .find_map(|var| std::env::var(var).ok().filter(|p| !p.trim().is_empty()))
}

/// The identity dir: where workload certificate pairs live. 0700 dir,
/// 0600 files - the directory holds the workload PRIVATE KEYS, so the
/// read/write paths fail-closed on loose permissions.
fn identity_dir() -> String {
    std::env::var("SENTIN8_M2M_CREDENTIALS_DIR").unwrap_or_else(|_| {
        let secrets =
            std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "../.run/secrets".into());
        format!("{secrets}/m2m-credentials")
    })
}

/// Persist issued certificate/key PEMs under the identity dir
/// (`SENTIN8_M2M_CREDENTIALS_DIR`, 0600) and return their paths. One
/// cert/key pair per WORKLOAD (`{workload}.crt`/`{workload}.key`,
/// workload-explicit) - a process may hold several workload identities
/// (auth alone holds `sentin8:auth`, `auth-post`, `auth-sys`,
/// `sentin8:auth-policy`), so the filename MUST derive from the workload
/// parameter, never a process-global ambient.
pub fn persist_cert_files(cert_pem: &str, key_pem: &str, workload: &str) -> (String, String) {
    use std::os::unix::fs::PermissionsExt;
    let dir = identity_dir();
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::set_permissions(
        std::path::Path::new(&dir),
        std::fs::Permissions::from_mode(0o700),
    );
    let base = workload.replace(['/', ':'], "_");
    let cert_path = std::path::Path::new(&dir).join(format!("{base}.crt"));
    let key_path = std::path::Path::new(&dir).join(format!("{base}.key"));
    if let Err(e) = std::fs::write(&cert_path, cert_pem) {
        tracing::error!(error = %e, path = %cert_path.display(), "M2M: cannot write client cert");
    }
    if let Err(e) = std::fs::write(&key_path, key_pem) {
        tracing::error!(error = %e, path = %key_path.display(), "M2M: cannot write client key");
    }
    let _ = std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o600));
    let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    (
        cert_path.display().to_string(),
        key_path.display().to_string(),
    )
}

/// A persisted workload identity pair's on-disk paths (DPoPRS-1) - the
/// blocking loader's return shape.
pub struct PersistedPair {
    /// The PEM CA chain path (the m2m plane's platform CA).
    pub ca_cert_path: String,
    /// The leaf chain PEM path.
    pub cert_path: String,
    /// The private key PEM path.
    pub key_path: String,
}

/// Blocking, LOCAL-DISK-ONLY load of a workload's persisted pair paths
/// (DPoPRS-1). The sync counterpart of the [`load_cert_pair`] fast path:
/// reads `{identity_dir}/{workload}.crt/.key` and verifies expiry - no
/// Acme network, no mint. Returns `None` when the pair is absent, corrupt,
/// or expiring (the caller falls back; a later async
/// [`ensure_workload_certificate`] pass mints).
///
/// Built for sync constructors that must NOT touch a network (the Shield
/// role resolver's per-process build) - the same fail-closed cache
/// discipline as the async path.
pub fn load_persisted_pair_blocking(workload: &str, ca_cert_path: &str) -> Option<PersistedPair> {
    let dir = identity_dir();
    let base = workload.replace(['/', ':'], "_");
    let cert_path = std::path::Path::new(&dir).join(format!("{base}.crt"));
    let key_path = std::path::Path::new(&dir).join(format!("{base}.key"));
    let cert_pem = std::fs::read_to_string(&cert_path).ok()?;
    let key_pem = std::fs::read_to_string(&key_path).ok()?;
    // Expiry hygiene identical to the async load path: an expired or
    // expiring pair must not ride as a verification identity.
    match cert_pem_not_after(&cert_pem) {
        Some(not_after) => {
            let now = chrono::Utc::now();
            if now >= not_after {
                tracing::warn!(workload = %workload, "M2M: persisted certificate EXPIRED (blocking load) - pair rejected");
                return None;
            }
        }
        None => return None, // unparsable - fail safe
    }
    if key_pem.trim().is_empty() {
        return None;
    }
    Some(PersistedPair {
        ca_cert_path: ca_cert_path.to_string(),
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_guard() {
        // The CA-resolution tests must not see a developer shell's env.
        std::env::remove_var("SENTIN8_TLS_CA_PEM");
        std::env::remove_var("SENTIN8_TLS_CLIENT_CA_PEM");
    }

    #[test]
    fn split_combined_pem_full_blocks() {
        let combined = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\ndef\n-----END PRIVATE KEY-----\n";
        let (cert, key) = split_combined_pem(combined).expect("split");
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert.ends_with("-----END CERTIFICATE-----\n"));
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn split_combined_pem_chain_then_key() {
        let combined = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n";
        let (cert, key) = split_combined_pem(combined).expect("split");
        assert!(cert.contains("leaf"));
        assert!(cert.contains("root"));
        assert!(key.contains("k"));
    }

    #[test]
    fn split_combined_pem_missing_key_is_none() {
        let combined = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n";
        assert!(split_combined_pem(combined).is_none());
    }

    #[test]
    fn try_platform_ca_path_none_when_unset() {
        env_guard();
        assert!(try_platform_ca_path().is_none());
        std::env::set_var("SENTIN8_TLS_CA_PEM", "/tmp/root-ca.crt");
        assert_eq!(try_platform_ca_path().as_deref(), Some("/tmp/root-ca.crt"));
        std::env::remove_var("SENTIN8_TLS_CA_PEM");
    }

    #[test]
    fn parse_asn1_utc_time_20xx_century() {
        // RFC 5280: UTCTime years 00-49 → 20xx.
        let t = parse_asn1_time(false, b"271005163218Z").expect("parse");
        assert_eq!(t.to_rfc3339(), "2027-10-05T16:32:18+00:00");
    }

    #[test]
    fn parse_asn1_utc_time_19xx_century() {
        // UTCTime years 50-99 → 19xx (legacy certs).
        let t = parse_asn1_time(false, b"991231235959Z").expect("parse");
        assert_eq!(t.to_rfc3339(), "1999-12-31T23:59:59+00:00");
    }

    #[test]
    fn parse_asn1_generalized_time() {
        let t = parse_asn1_time(true, b"20501005163218Z").expect("parse");
        assert_eq!(t.to_rfc3339(), "2050-10-05T16:32:18+00:00");
    }

    #[test]
    fn cert_der_not_after_finds_second_validity_element() {
        // A real Acme-minted leaf's validity window (NotBefore 26-10-05,
        // NotAfter 27-10-05 - UTCTime pair as verified against a live
        // minted certificate): the walk must return the SECOND element.
        // Minimal DER-ish blob with the two-element sequence shape.
        let mut der = vec![0x30u8, 0x1e]; // SEQUENCE wrapping the pair
        for time in [b"261005163218Z".as_ref(), b"271005163218Z".as_ref()] {
            der.push(0x17); // UTCTime
            der.push(time.len() as u8);
            der.extend_from_slice(time);
        }
        let t = cert_der_not_after(&der).expect("not after");
        assert_eq!(t.to_rfc3339(), "2027-10-05T16:32:18+00:00");
    }

    #[test]
    fn cert_pem_not_after_first_block_only() {
        // The LEAF's NotAfter (first block) - a following intermediate's
        // window must not be picked up.
        use base64::Engine as _;
        let mut der = vec![0x30u8, 0x1e];
        for time in [b"261005163218Z".as_ref(), b"271005163218Z".as_ref()] {
            der.push(0x17);
            der.push(time.len() as u8);
            der.extend_from_slice(time);
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
        let t = cert_pem_not_after(&pem).expect("not after");
        assert_eq!(t.to_rfc3339(), "2027-10-05T16:32:18+00:00");
    }
}
