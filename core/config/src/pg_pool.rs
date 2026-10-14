// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # Shared PostgreSQL pool sizing + certificate-identity transport
//!
//! Every Sentin8 service builds its main `PgPool` through [`connect`] so the
//! whole fleet honours a single, small connection cap. This is critical
//! because the platform runs ~20 microservices against one PostgreSQL
//! instance whose default `max_connections` is 100.
//!
//! ## Why a shared helper?
//!
//! `sqlx::PgPool::connect` defaults to `max_connections = 10`. With ~20
//! services that is 200+ connections from the main pools alone — before
//! counting the per-service `sentin8-tls` sync pool. The fleet exhausts
//! PostgreSQL, every pool starts returning `PoolTimedOut`, `sentin8-tls`
//! can no longer resolve hostname mappings, proxy stops routing, BFF
//! forwards fail with 502, and the dash UI stops loading env/org names.
//!
//! Capping each service at 3 (matching the `sentin8-tls` pool) keeps the
//! combined steady-state well under PostgreSQL's limit. The cap is
//! overridable per-deployment via `SENTIN8_PG_POOL_MAX`.
//!
//! ## Certificate identity (group DESIGN.md §3.2)
//!
//! The PostgreSQL data plane is TLS-ONLY: every connection presents an
//! Acme-issued workload certificate (`sslmode=verify-full` against the
//! public CA chain) and PostgreSQL's `cert` auth method resolves the
//! connecting role from the certificate's CN through the `pgm` identity
//! map — there are NO database passwords. Mirroring the Valkey factory
//! (§3.1), this module is the single cert-presenting connection builder:
//! the DSN's `user` segment names the role, and the client pair is
//! resolved from the m2m identity dir the same way
//! `sentin8_m2m::persist_cert_files` writes it (fixed plane identities
//! fall back to `infra-tls`).
//!
//! A DSN that carries a PASSWORD component is rejected — a half-converted
//! DSN from the pre-certificate plane is a configuration error, not a
//! degraded mode the fleet should silently accept.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

/// Default maximum connections per service pool. Matches the `sentin8-tls`
/// pool cap so the entire fleet stays comfortably under PostgreSQL's
/// `max_connections`.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 3;

/// Build [`PgPoolOptions`] with the Sentin8-standard pool sizing.
///
/// - `max_connections`: `SENTIN8_PG_POOL_MAX` env var, default
///   [`DEFAULT_MAX_CONNECTIONS`] (3).
/// - `acquire_timeout`: 8s — long enough to ride out a brief connection
///   spike, short enough to surface a real stall quickly.
pub fn options() -> PgPoolOptions {
    let max = std::env::var("SENTIN8_PG_POOL_MAX")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_MAX_CONNECTIONS);
    PgPoolOptions::new()
        .max_connections(max)
        .acquire_timeout(Duration::from_secs(8))
}

/// Connect to PostgreSQL using the Sentin8-standard pool sizing and the
/// certificate-identity TLS plane.
///
/// Drop-in replacement for `sqlx::PgPool::connect` that enforces the
/// fleet-wide connection cap and the TLS-only transport. The DSN's `user`
/// segment names the role the connection runs as; the workload certificate
/// presented at the TLS handshake must be mapped to that role in the `pgm`
/// identity map (`sentin8-cli vertical enroll` writes the rows).
///
/// # Errors
/// Returns the same `Result<PgPool, sqlx::Error>` so existing `?`
/// propagation is unchanged. A DSN with a password component, an
/// `sslmode=disable` DSN, or an unreadable CA/client pair fails with a
/// [`sqlx::Error::Configuration`] naming the defect.
pub async fn connect(url: &str) -> Result<sqlx::PgPool, sqlx::Error> {
    let connect_options = connect_options_for(url)?;
    options().connect_with(connect_options).await
}

/// Build the certificate-presenting [`PgConnectOptions`] for a DSN
/// (group DESIGN.md §3.2).
///
/// - The DSN's password component (if any) is REJECTED — the plane is
///   passwordless by design.
/// - `ssl_mode` is forced to `VerifyFull`; a DSN that explicitly requests
///   `sslmode=disable` is rejected (there is no plaintext listener).
/// - The root CA is the published Acme chain (root + intermediate).
/// - The client identity is the workload pair resolved from the m2m
///   identity dir (`infra-tls` fallback for fixed plane identities).
///
/// # Errors
/// [`sqlx::Error::Configuration`] on a password-bearing DSN, an
/// `sslmode=disable` DSN, an unparsable DSN, or an unreadable CA/client
/// pair.
pub fn connect_options_for(url: &str) -> Result<PgConnectOptions, sqlx::Error> {
    // Password rejection happens at the URL layer: sqlx parses the
    // password into private state with no public getter, and a URL's
    // userinfo is exactly the component the certificate plane retires.
    if dsn_has_password(url) {
        return Err(sqlx::Error::Configuration(
            "password-bearing PostgreSQL DSN rejected — the data plane is \
             certificate-identity only (group DESIGN.md §3.2); drop the \
             password component"
                .into(),
        ));
    }
    let opts = PgConnectOptions::from_str(url)?;
    if matches!(opts.get_ssl_mode(), PgSslMode::Disable) {
        return Err(sqlx::Error::Configuration(
            "sslmode=disable rejected — the PostgreSQL data plane has no \
             plaintext listener (group DESIGN.md §3.2)"
                .into(),
        ));
    }
    let ca = std::fs::read(platform_ca_path())
        .map_err(|e| sqlx::Error::Configuration(format!("platform CA read: {e}").into()))?;
    let (cert, key) = workload_pair_for_role(opts.get_username())
        .map_err(|e| sqlx::Error::Configuration(e.into()))?;
    Ok(opts
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(ca)
        .ssl_client_cert_from_pem(cert)
        .ssl_client_key_from_pem(key))
}

/// Whether a `postgres://` DSN carries a password component in its
/// userinfo (`scheme://user:password@host`). Percent-decoding is not
/// needed at this layer: ANY nonempty password segment is a defect.
fn dsn_has_password(url: &str) -> bool {
    let Some(rest) = url.split_once("://") else {
        return false;
    };
    let authority = rest.1.split(['/', '?']).next().unwrap_or(rest.1);
    match authority.rsplit_once('@') {
        Some((userinfo, _)) => userinfo.contains(':'),
        None => false,
    }
}

/// The m2m identity dir — the same resolution `sentin8_m2m` uses
/// (`SENTIN8_M2M_CREDENTIALS_DIR`, else `{SENTIN8_SECRETS_DIR}/m2m-
/// credentials`).
fn m2m_identity_dir() -> PathBuf {
    std::env::var("SENTIN8_M2M_CREDENTIALS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let secrets =
                std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "../.run/secrets".into());
            PathBuf::from(secrets).join("m2m-credentials")
        })
}

/// Resolve the client pair for a connecting ROLE (group DESIGN.md §3.2).
///
/// The role↔workload correspondence is registration-driven at the enroll
/// side (`m2m-{service_type}` → `{role}` in `pg_ident.conf`), and the
/// factory derives the SAME mapping from the role's shape at connect
/// time: `{vertical}_{leaf}_service` → workload `{vertical}:{leaf}` →
/// the m2m pair filename (`{vertical}_{leaf}`, the `persist_cert_files`
/// naming with colons/slashes → `_`). Platform roles
/// (`sentin8_{leaf}_service`) and legacy shared roles (`sentin8_app`,
/// `sentin8_app_dev` → workload `sentin8:app`) both reduce through the
/// same rule — the trailing `_service` (and `_dev`) is stripped, nothing
/// is hardcoded per service. The DDL/operator role (`sentin8`) presents
/// the fixed `postgres-ops` infra pair — the `valkey-admin` analogue,
/// `make infra-tls` material.
///
/// # Errors
/// Returns a descriptive error when neither the m2m identity dir nor
/// `infra-tls` holds the pair.
fn workload_pair_for_role(role: &str) -> Result<(String, String), String> {
    let base = if role == "sentin8" {
        // The operator/DDL identity — fixed plane material.
        "postgres-ops".to_string()
    } else {
        // `sentin8_ai_service` → `sentin8_ai`; `sentin8_app_dev` →
        // `sentin8_app`. Vertical roles (`bank8_ledger_service` →
        // `bank8_ledger`) reduce identically — zero vertical knowledge.
        role.trim_end_matches("_service")
            .trim_end_matches("_dev")
            .replace(['/', ':'], "_")
    };
    let id_dir = m2m_identity_dir();
    let secrets = std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "../.run/secrets".into());
    let infra = Path::new(&secrets).join("infra-tls");
    for dir in [id_dir, infra] {
        let cert_path = dir.join(format!("{base}.crt"));
        let key_path = dir.join(format!("{base}.key"));
        if let (Ok(cert), Ok(key)) = (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
        ) {
            return Ok((cert, key));
        }
    }
    Err(format!(
        "no workload certificate pair for PostgreSQL role '{role}' (expected \
         '{base}.crt/.key') — service workloads mint via \
         sentin8_m2m::ensure_workload_certificate, fixed plane identities via \
         make infra-tls (group DESIGN.md §3.2)"
    ))
}

/// The platform CA bundle path for the outbound PostgreSQL TLS channel —
/// the PUBLIC Acme Root-CA chain (root + intermediate; Acme leaves are
/// intermediate-signed, so a root-only trust file cannot chain them).
/// Same resolution order and rationale as the Valkey factory in this
/// crate's sibling module (duplicated because `sentin8-m2m` sits behind
/// this crate — the dependency edge cannot be inverted).
fn platform_ca_path() -> String {
    for var in ["SENTIN8_TLS_CA_PEM", "SENTIN8_TLS_CLIENT_CA_PEM"] {
        if let Ok(p) = std::env::var(var) {
            if !p.trim().is_empty() {
                return p;
            }
        }
    }
    if let Ok(secrets) = std::env::var("SENTIN8_SECRETS_DIR") {
        let chain = Path::new(&secrets).join("acme-ca/root-ca.crt");
        if chain.is_file() {
            return chain.display().to_string();
        }
    }
    let acme_dir = std::env::var("SENTIN8_ACME_DATA_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{home}/.sentin8/acme")
    });
    Path::new(&acme_dir)
        .join("ca/root-ca.crt")
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_password_bearing_dsn() {
        let err = connect_options_for("postgres://user:pw@localhost:5432/sentin8")
            .expect_err("password DSN must be rejected");
        assert!(err.to_string().contains("password-bearing"));
    }

    #[test]
    fn accepts_passwordless_dsn_shape() {
        // The password gate itself (parse happens after; the DSN shape
        // passes the gate — CA/pair resolution is what fails next in a
        // bare test env, which is out of this unit's scope).
        assert!(!dsn_has_password("postgres://user@localhost:5432/sentin8"));
        assert!(!dsn_has_password("postgres://localhost/sentin8"));
    }

    #[test]
    fn rejects_plaintext_dsn() {
        let err = connect_options_for("postgres://user@localhost:5432/sentin8?sslmode=disable")
            .expect_err("plaintext DSN must be rejected");
        assert!(err.to_string().contains("plaintext listener"));
    }
}
