// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Configuration for the `sentin8-tls` library.
//!
//! All values derive from environment variables with sensible defaults;
//! see the crate design doc (README.md) for the full variable table.

use std::env;

/// Configuration for the `sentin8-tls` library.
#[derive(Debug, Clone)]
pub struct Sentin8TlsConfig {
    /// The embedding service's identity (e.g. `bank8:ledger`). Names the
    /// cert-bound `{dash}-tls` M2M workload the database-free resolver
    /// uses for Sys `GET /v1/resolve/hostname` (TLS-RLS-4) — the library
    /// holds NO database connection.
    /// Reads from `SENTIN8_TLS_SERVICE_IDENTITY` if not set.
    pub service_identity: String,
    /// Acme directory URL for certificate ordering.
    /// e.g. `https://acme.ops.sys.sentin8.local/acme/directory`
    pub acme_directory_url: String,
    /// Root Sentin8 domain (e.g. `sentin8.local`).
    pub sentin8_domain: String,
    /// TLS mode: "off" (plain HTTP), "internal" (Acme for all), "acme"
    /// (production with an upstream ACME provider).
    pub tls_mode: TlsMode,
    /// Optional mTLS client authentication: when set, this service's TLS
    /// listener REQUESTS client certificates and verifies them against this
    /// CA PEM (Sentin8:Acme Root CA). Handshakes without a client cert are
    /// still accepted.
    /// Read from `SENTIN8_TLS_CLIENT_CA_PEM` (path to the CA file).
    pub client_ca_pem_path: Option<String>,
}

/// How the listener terminates TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Plain HTTP — no TLS termination (local development only).
    Off,
    /// Use Sentin8:Acme for all domains (local + custom).
    Internal,
    /// Use Sentin8:Acme with an upstream ACME provider for production.
    Acme,
}

impl TlsMode {
    /// Parse a mode string, defaulting to `Internal` for unknown values
    /// (parsing never fails). Not `FromStr` because failure is impossible.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "off" => Self::Off,
            "acme" => Self::Acme,
            _ => Self::Internal, // default
        }
    }
}

impl Default for Sentin8TlsConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Sentin8TlsConfig {
    /// Build configuration from environment variables.
    pub fn from_env() -> Self {
        // TLS-RLS-4: NO database URL — the resolver is database-free (Sys
        // owner API on cache miss). The identity defaults to the env var;
        // services using the builder set it explicitly.
        let service_identity = env::var("SENTIN8_TLS_SERVICE_IDENTITY").unwrap_or_default();

        let sentin8_domain =
            env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "sentin8.local".to_string());

        let acme_directory_url = env::var("SENTIN8_ACME_DIRECTORY_URL").unwrap_or_else(|_| {
            // Default: Acme on the local machine. The port is auto-assigned
            // by captain and propagated via SENTIN8_ACME_PORT; fall back to
            // a base-port-derived value only when that var is unset (e.g.
            // running tls standalone).
            let orch_ip =
                env::var("SENTIN8_CAPTAIN_LOCAL_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
            let sentin8_acme_port = env::var("SENTIN8_ACME_PORT").unwrap_or_else(|_| {
                // Last-resort fallback: the first auto-assigned pool port.
                sentin8_config::port_pool_low().to_string()
            });
            format!("https://{orch_ip}:{sentin8_acme_port}/acme/directory")
        });

        let tls_mode = TlsMode::from_str(
            &env::var("SENTIN8_TLS_MODE").unwrap_or_else(|_| "internal".to_string()),
        );

        let client_ca_pem_path = env::var("SENTIN8_TLS_CLIENT_CA_PEM")
            .ok()
            .filter(|s| !s.is_empty());

        Self {
            service_identity,
            acme_directory_url,
            sentin8_domain,
            tls_mode,
            client_ca_pem_path,
        }
    }
}
