// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Valkey GLIDE connection helper (group DESIGN.md §3.1).
//!
//! The Valkey data plane authenticates by **certificate** - the same
//! Acme-issued workload pair (`CN=m2m-{workload}`) that rides the
//! service-to-service mTLS channel. The TLS listener maps the client
//! cert's CN to the ACL user of the same name; there are no Valkey
//! secrets anywhere. [`valkey_client`] presents the workload's pair
//! over secure TLS via **Valkey GLIDE** (`valkey-glide`, imported as
//! `glide`) - the platform's mandated client engine: glide-core owns
//! TLS, reconnection, and backoff natively, so the retry scaffolding
//! the old connection-manager paths needed disappears.
//!
//! Every service passes the workload it already hardcodes
//! (`Sentin8Shell::new("sentin8:db", …)`); the CN maps to the
//! enroll-provisioned ACL user of the same name.
//!
//! ## Usage
//!
//! ```text
//! use sentin8_middleware::valkey_client;
//!
//! # async fn run() -> anyhow::Result<()> {
//! let client = valkey_client("valkeys://localhost:6379/0", "sentin8:db").await?;
//! client.custom_command(&["PING"]).await?;
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use glide::GlideClient;
use glide::GlideClientConfiguration;
use glide::TlsConfig;
use thiserror::Error;

#[derive(Debug, Error)]
/// Failure surface for Valkey GLIDE operations.
pub enum ValkeyError {
    /// Connection establishment failed.
    #[error("failed to connect to Valkey: {0}")]
    Connect(String),
    /// A command failed on an established connection.
    #[error("Valkey command failed: {0}")]
    Command(String),
}

/// Connect a cert-presenting **Valkey GLIDE** client (group DESIGN.md
/// §3.1): `TlsConfig::SecureTls`, the public Acme CA chain, and the
/// workload's m2m pair - the CN maps to the ACL user of the same name
/// server-side. The scheme is resolved BEFORE any normalization helper -
/// the TLS scheme is REQUIRED (there is no plaintext listener to reach),
/// and a silent downgrade would present NO identity at all.
///
/// The returned `GlideClient` is clone-cheap and multiplexed; glide-core
/// reconnects with backoff automatically on connection loss.
///
/// The URL's logical-DB suffix (`…/{N}`) is ACCEPTED-BUT-INERT:
/// `parse_host_port` discards the number and GLIDE connects at its
/// default DB 0 - isolation is entirely the per-workload ACL key
/// namespaces (`~{ns}: *`), never the logical DB (
/// group DESIGN.md §3.1).
///
/// # Errors
/// Returns [`ValkeyError::Connect`] when the pair cannot be read
/// (service workloads mint via `sentin8_m2m::ensure_workload_certificate`
/// or `make infra-tls`; fixed plane identities live in `infra-tls`) or
/// the TLS handshake fails.
pub async fn valkey_client(url: &str, workload: &str) -> Result<GlideClient, ValkeyError> {
    valkey_client_inner(url, workload, false).await
}

/// Same as [`valkey_client`], but with GLIDE's Pub/Sub message channel
/// ENABLED - runtime `SUBSCRIBE` requires it, and messages arrive via
/// `get_pubsub_message` (connect-time subscriptions survive reconnects).
///
/// # Errors
/// Returns [`ValkeyError::Connect`] on an unreadable pair or a failed
/// handshake - same surface as [`valkey_client`].
pub async fn valkey_client_pubsub(url: &str, workload: &str) -> Result<GlideClient, ValkeyError> {
    valkey_client_inner(url, workload, true).await
}

async fn valkey_client_inner(
    url: &str,
    workload: &str,
    pubsub: bool,
) -> Result<GlideClient, ValkeyError> {
    let (host, port, _db) = parse_host_port(url)?;
    // Self-healing pair: on a persisted-pair miss, mint via the Acme
    // bootstrap channel (the same `ensure_workload_certificate` every
    // service's boot mint uses) - the factory never depends on an
    // operator pre-mint for service identities. Fixed plane identities
    // (valkey-admin/control/registry-writer) have no Acme path and are
    // provisioned by `make infra-tls`; their miss surfaces the read
    // error below.
    let (cert_pem, key_pem) = read_workload_pair(workload)?;
    let ca_path = platform_ca_path();
    let ca_pem = std::fs::read_to_string(&ca_path)
        .map_err(|e| ValkeyError::Connect(format!("platform CA ({ca_path}): {e}")))?;
    let mut config = GlideClientConfiguration::with_address(host, port)
        .tls(TlsConfig::SecureTls)
        .tls_ca_cert(ca_pem.as_bytes().to_vec())
        .client_identity(cert_pem, key_pem)
        // Bounded request timeout, comfortably above the longest
        // blocking command the platform issues (Bus's SSE consumer
        // holds `XREADGROUP BLOCK 10000` for the full 10s on idle
        // streams): GLIDE's DEFAULT is 5s, which aborted every idle
        // stream read, ending SSE epochs and churning every consumer
        // - group DESIGN.md §3.1.
        .request_timeout(Duration::from_secs(30))
        .connection_timeout(Duration::from_secs(2));
    if pubsub {
        config = config.enable_pubsub();
    }
    GlideClient::connect(config)
        .await
        .map_err(|e| ValkeyError::Connect(e.to_string()))
}

/// Same certificate-identity plane, **synchronous** - for operator
/// tooling (the CLI's enroll path runs on a plain thread). Wraps
/// `SyncGlideClient`; the same SecureTls + CA chain + m2m pair.
///
/// # Errors
/// Returns [`ValkeyError::Connect`] on an unreadable pair or a failed
/// handshake.
pub fn valkey_client_sync(
    url: &str,
    workload: &str,
) -> Result<glide::sync::SyncGlideClient, ValkeyError> {
    let (host, port, _db) = parse_host_port(url)?;
    let (cert_pem, key_pem) = read_workload_pair(workload)?;
    let ca_path = platform_ca_path();
    let ca_pem = std::fs::read_to_string(&ca_path)
        .map_err(|e| ValkeyError::Connect(format!("platform CA ({ca_path}): {e}")))?;
    let config = GlideClientConfiguration::with_address(host, port)
        .tls(TlsConfig::SecureTls)
        .tls_ca_cert(ca_pem.as_bytes().to_vec())
        .client_identity(cert_pem, key_pem)
        // Same bounded request timeout as the async factory - the
        // operator tooling must tolerate blocking reads too.
        .request_timeout(Duration::from_secs(30))
        .connection_timeout(Duration::from_secs(2));
    glide::sync::SyncGlideClient::connect(config).map_err(|e| ValkeyError::Connect(e.to_string()))
}

/// Parse `valkeys://host:port/db` into its parts. Plaintext schemes
/// are a configuration error - the plane is TLS-only.
fn parse_host_port(url: &str) -> Result<(String, u16, i64), ValkeyError> {
    let trimmed = url.trim();
    let Some(rest) = trimmed.strip_prefix("valkeys://") else {
        return Err(ValkeyError::Connect(format!(
            "certificate identity requires the valkeys:// scheme - got '{url}'. \
             The Valkey data plane has no plaintext listener"
        )));
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| ValkeyError::Connect(format!("invalid port in Valkey URL '{url}'")))?;
            (h.to_string(), port)
        }
        None => (authority.to_string(), 6379),
    };
    let db = rest.split('/').nth(1).unwrap_or("0").parse().unwrap_or(0);
    Ok((host, port, db))
}

/// Read the workload's persisted certificate pair from the m2m identity dir
/// (`SENTIN8_M2M_CREDENTIALS_DIR`, filenames derived the same way
/// `sentin8_m2m::persist_cert_files` derives them - colons/slashes → `_`).
/// The plane's FIXED identities (control/admin/registry-writer) are infra
/// material minted by `make infra-tls` - found in `infra-tls` on the
/// identity-dir miss.
fn read_workload_pair(workload: &str) -> Result<(String, String), ValkeyError> {
    let dir = std::env::var("SENTIN8_M2M_CREDENTIALS_DIR").unwrap_or_else(|_| {
        let secrets =
            std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "../.run/secrets".into());
        format!("{secrets}/m2m-credentials")
    });
    let base = workload.replace(['/', ':'], "_");
    let cert_path = std::path::Path::new(&dir).join(format!("{base}.crt"));
    let key_path = std::path::Path::new(&dir).join(format!("{base}.key"));
    let (cert_path, key_path) = if cert_path.is_file() && key_path.is_file() {
        (cert_path, key_path)
    } else {
        let secrets =
            std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "../.run/secrets".into());
        let infra = std::path::Path::new(&secrets).join("infra-tls");
        (
            infra.join(format!("{base}.crt")),
            infra.join(format!("{base}.key")),
        )
    };
    let cert_pem = std::fs::read_to_string(&cert_path).map_err(|e| {
        ValkeyError::Connect(format!(
            "workload '{workload}' client cert not readable at {} ({e}) - service \
             workloads mint via sentin8_m2m::ensure_workload_certificate; fixed plane \
             identities via make infra-tls",
            cert_path.display()
        ))
    })?;
    let key_pem = std::fs::read_to_string(&key_path)
        .map_err(|e| ValkeyError::Connect(format!("workload '{workload}' client key: {e}")))?;
    Ok((cert_pem, key_pem))
}

/// The platform CA bundle path for the outbound Valkey TLS channel - the
/// PUBLIC Acme Root-CA chain (root + intermediate; Acme leaves are
/// intermediate-signed, so a root-only trust file cannot chain them).
/// Same resolution order the m2m crate uses
/// (`SENTIN8_TLS_CA_PEM` → `SENTIN8_TLS_CLIENT_CA_PEM` → the conventional
/// `{acme_data_dir}/ca/root-ca.crt`), duplicated here because
/// `sentin8-m2m` depends on THIS crate (the dependency edge cannot be
/// inverted).
fn platform_ca_path() -> String {
    for var in ["SENTIN8_TLS_CA_PEM", "SENTIN8_TLS_CLIENT_CA_PEM"] {
        if let Ok(p) = std::env::var(var) {
            if !p.trim().is_empty() {
                return p;
            }
        }
    }
    // The infra material's published chain (root + intermediate).
    if let Ok(secrets) = std::env::var("SENTIN8_SECRETS_DIR") {
        let chain = std::path::Path::new(&secrets).join("acme-ca/root-ca.crt");
        if chain.is_file() {
            return chain.display().to_string();
        }
    }
    let acme_dir = std::env::var("SENTIN8_ACME_DATA_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{home}/.sentin8/acme")
    });
    format!("{acme_dir}/ca/root-ca.crt")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_gate_rejects_plaintext() {
        assert!(parse_host_port("valkey://localhost:6379/0").is_err());
        assert!(parse_host_port("").is_err());
    }

    #[test]
    fn scheme_gate_accepts_tls_and_parses() {
        let (host, port, db) = parse_host_port("valkeys://localhost:6379/0").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 6379);
        assert_eq!(db, 0);
        let (host, _, _) = parse_host_port("valkeys://db.internal:6380/1").unwrap();
        assert_eq!(host, "db.internal");
    }

    #[test]
    fn default_port_applies() {
        let (_, port, _) = parse_host_port("valkeys://localhost").unwrap();
        assert_eq!(port, 6379);
    }
}
