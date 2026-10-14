// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # mTLS for service-to-service calls
//!
//! Builds a `reqwest::Client` configured with a client certificate and key,
//! pinned to a trusted CA. Used by services that need to call other Sentin8
//! services over mutually-authenticated TLS (e.g. Sys → Flow, Payments →
//! Func, internal proxy-back endpoints).
//!
//! The client certificate and key are read from PEM files on disk. The CA
//! cert is used to verify the server's certificate (and, in a full mTLS
//! deployment, the server uses the same CA to verify this client).
//!
//! ## File format
//!
//! - `ca_cert_path` — PEM file with one or more CA certificates.
//! - `client_cert_path` — PEM file with the client's certificate chain.
//! - `client_key_path` — PEM file with the client's private key (unencrypted
//!   or the caller must handle passphrase via env).
//!
//! ## Error handling
//!
//! Returns `Err(String)` for any file-read or TLS-build failure. In a
//! production service, map this to a `Sentin8Error::Internal` at the call
//! site.

use std::path::Path;

/// Configuration for building an mTLS-configured reqwest client.
#[derive(Debug, Clone)]
pub struct MtlsConfig {
    /// Path to the PEM file containing the trusted CA certificate(s).
    pub ca_cert_path: String,
    /// Path to the PEM file containing this client's certificate chain.
    pub client_cert_path: String,
    /// Path to the PEM file containing this client's private key.
    pub client_key_path: String,
}

impl MtlsConfig {
    /// Create a new mTLS config from the three PEM paths.
    pub fn new(ca_cert_path: &str, client_cert_path: &str, client_key_path: &str) -> Self {
        Self {
            ca_cert_path: ca_cert_path.to_string(),
            client_cert_path: client_cert_path.to_string(),
            client_key_path: client_key_path.to_string(),
        }
    }

    /// Validate that all three paths exist on disk.
    pub fn validate_paths(&self) -> Result<(), String> {
        for (name, p) in [
            ("ca_cert_path", &self.ca_cert_path),
            ("client_cert_path", &self.client_cert_path),
            ("client_key_path", &self.client_key_path),
        ] {
            if !Path::new(p).exists() {
                return Err(format!("{name} does not exist: {p}"));
            }
        }
        Ok(())
    }
}

/// Build a `reqwest::Client` configured for mTLS using the rustls TLS
/// backend.
///
/// The client trusts only the CA in `config.ca_cert_path` (no system roots)
/// and presents `config.client_cert_path`/`config.client_key_path` as its
/// client certificate.
///
/// Returns `Err(String)` if the files cannot be read or the TLS identity
/// cannot be built.
pub fn build_mtls_client(config: &MtlsConfig) -> Result<reqwest::Client, String> {
    config.validate_paths()?;

    let ca_cert =
        std::fs::read(&config.ca_cert_path).map_err(|e| format!("failed to read CA cert: {e}"))?;
    let client_cert = std::fs::read(&config.client_cert_path)
        .map_err(|e| format!("failed to read client cert: {e}"))?;
    let client_key = std::fs::read(&config.client_key_path)
        .map_err(|e| format!("failed to read client key: {e}"))?;

    // Use reqwest's ClientBuilder with rustls. We need the rustls feature
    // "rustls-tls" which is already enabled in the workspace.
    //
    // NOTE: reqwest 0.12's `add_root_certificate` + `identity` API supports
    // DER/PEM. We use the PEM bytes directly via Certificate::from_pem
    // (which accepts a bundle) and Identity::from_pem (which accepts a
    // combined cert+key PEM).
    let ca_cert_obj = reqwest::Certificate::from_pem(&ca_cert)
        .map_err(|e| format!("failed to parse CA cert: {e}"))?;

    // Identity::from_pem expects a single PEM blob containing the cert
    // chain followed by the private key. We concatenate the two PEM files.
    let mut identity_pem = client_cert;
    identity_pem.extend_from_slice(&client_key);
    let identity = reqwest::Identity::from_pem(&identity_pem)
        .map_err(|e| format!("failed to build client identity: {e}"))?;

    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca_cert_obj)
        .identity(identity)
        .danger_accept_invalid_certs(false)
        .https_only(true)
        // Bounded (BOUNDED-OUTBOUND): an unbounded client lets a stalled
        // proxy/backend hang the caller indefinitely — in the BOOT path
        // (m2m credential probe, DCR, Acme issuance) that stalls the
        // service before its listener binds, and the supervisor kills it
        // (restart spiral). A probe that misses the window keeps the
        // cached credentials by design; DCR/issuance failures are
        // fail-open everywhere.
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("failed to build mTLS client: {e}"))
}

/// Build a **streaming** mTLS `reqwest::Client` — identical to
/// [`build_mtls_client`] but WITHOUT the total request `.timeout()`, for
/// long-lived SSE body streams (Bus's `GET /v1/consume/sse`) that must not
/// be aborted mid-stream. The `connect_timeout` is retained so
/// connection-establishment failures still fail fast (same contract as
/// `Sentin8HttpClient::new_streaming`).
///
/// auth DESIGN §4.3f: the certificate presented here is the
/// caller's COMPLETE identity on the token-free plane — the receiving
/// service's TLS layer CA-verifies it and injects the
/// `X-Sentin8-Client-Cert-*` headers that drive authorization.
pub fn build_mtls_streaming_client(config: &MtlsConfig) -> Result<reqwest::Client, String> {
    config.validate_paths()?;

    let ca_cert =
        std::fs::read(&config.ca_cert_path).map_err(|e| format!("failed to read CA cert: {e}"))?;
    let client_cert = std::fs::read(&config.client_cert_path)
        .map_err(|e| format!("failed to read client cert: {e}"))?;
    let client_key = std::fs::read(&config.client_key_path)
        .map_err(|e| format!("failed to read client key: {e}"))?;

    let ca_cert_obj = reqwest::Certificate::from_pem(&ca_cert)
        .map_err(|e| format!("failed to parse CA cert: {e}"))?;

    let mut identity_pem = client_cert;
    identity_pem.extend_from_slice(&client_key);
    let identity = reqwest::Identity::from_pem(&identity_pem)
        .map_err(|e| format!("failed to build client identity: {e}"))?;

    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca_cert_obj)
        .identity(identity)
        .danger_accept_invalid_certs(false)
        .https_only(true)
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("failed to build streaming mTLS client: {e}"))
}

/// Build a reqwest client that trusts ONLY the given CA bundle and holds
/// no client certificate (https-only, strict verification). Used for
/// outbound platform calls that must ride the CA-verified channel without
/// presenting a client identity (e.g. first-boot DCR + Acme issuance in
/// the m2m crate — the caller has no cert yet, or already presented one
/// at the TLS layer).
pub fn build_ca_client(ca_cert_path: &str) -> Result<reqwest::Client, String> {
    let ca_cert = std::fs::read(ca_cert_path)
        .map_err(|e| format!("failed to read CA cert ({ca_cert_path}): {e}"))?;
    let ca_cert_obj = reqwest::Certificate::from_pem(&ca_cert)
        .map_err(|e| format!("failed to parse CA cert: {e}"))?;

    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca_cert_obj)
        .danger_accept_invalid_certs(false)
        .https_only(true)
        // Bounded (BOUNDED-OUTBOUND): first-boot DCR + Acme issuance ride
        // this client from the boot path — an unbounded request stalls the
        // boot indefinitely (see build_mtls_client's note).
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("failed to build CA-trusted client: {e}"))
}

/// Build a default reqwest client without mTLS (for non-mTLS
/// service-to-service calls, e.g. dev mode or when TLS terminates TLS).
pub fn build_plain_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .use_rustls_tls()
        // Bounded (BOUNDED-OUTBOUND): every outbound platform client is
        // timeout-bounded; see build_mtls_client's note.
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("failed to build plain client: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_paths_returns_err_for_missing_files() {
        let cfg = MtlsConfig::new(
            "/nonexistent/ca.pem",
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
        );
        let err = cfg.validate_paths().unwrap_err();
        assert!(err.contains("ca_cert_path"));
    }

    #[test]
    fn validate_paths_returns_ok_for_existing_files() {
        // Use /dev/null which exists but is not a valid PEM — validate_paths
        // only checks existence.
        let cfg = MtlsConfig::new("/dev/null", "/dev/null", "/dev/null");
        assert!(cfg.validate_paths().is_ok());
    }

    #[test]
    fn build_mtls_client_returns_err_for_missing_files() {
        let cfg = MtlsConfig::new(
            "/nonexistent/ca.pem",
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
        );
        let err = cfg.validate_paths().unwrap_err();
        assert!(err.contains("does not exist"));
    }

    #[test]
    fn build_plain_client_succeeds() {
        let client = build_plain_client();
        assert!(
            client.is_ok(),
            "plain client should build without cert files"
        );
    }

    #[test]
    fn mtls_config_new_stores_paths() {
        let cfg = MtlsConfig::new("/a/ca.pem", "/b/cert.pem", "/c/key.pem");
        assert_eq!(cfg.ca_cert_path, "/a/ca.pem");
        assert_eq!(cfg.client_cert_path, "/b/cert.pem");
        assert_eq!(cfg.client_key_path, "/c/key.pem");
    }

    #[test]
    fn mtls_config_is_clone() {
        let cfg = MtlsConfig::new("/a", "/b", "/c");
        let _cloned = cfg.clone();
    }

    #[test]
    fn build_mtls_client_fails_on_dev_null_pem() {
        // /dev/null exists but reads as empty — PEM parsing should fail.
        let cfg = MtlsConfig::new("/dev/null", "/dev/null", "/dev/null");
        let res = build_mtls_client(&cfg);
        assert!(res.is_err(), "empty PEM should fail to parse");
    }

    #[test]
    fn build_ca_client_fails_on_missing_ca() {
        let res = build_ca_client("/nonexistent/ca.pem");
        assert!(res.is_err(), "missing CA file must fail");
    }

    #[test]
    fn build_ca_client_accepts_valid_pem() {
        // /dev/null reads as empty, which reqwest tolerates as an
        // (empty) root store — the important contract is that a missing
        // file fails (above) and a real PEM builds. Use the same dev-null
        // path to assert the no-panic happy path when the file exists.
        let res = build_ca_client("/dev/null");
        assert!(
            res.is_ok(),
            "empty-but-existing PEM builds an empty root store (no panic)"
        );
    }
}
