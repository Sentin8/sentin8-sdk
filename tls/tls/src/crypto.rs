// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 post-quantum TLS configuration.
//!
//! Controls both the crypto provider (key exchange groups) and the TLS
//! protocol versions via a single env var: `SENTIN8_TLS_PQ_MODE`.
//!
//! | Mode         | Key exchange              | TLS versions     | Use case                    |
//! |-------------|---------------------------|------------------|-----------------------------|
//! | `exclusive` | X25519MLKEM768 only       | TLS 1.3 only     | **Default** - full PQ, no fallback |
//! | `hybrid`    | X25519MLKEM768 + classical| TLS 1.3 only     | PQ-preferred, classical fallback for old clients |
//! | `classical` | X25519, P-256, P-384      | TLS 1.2 + 1.3    | **Emergency rollback** - no ML-KEM, max compatibility |
//!
//! Uses [Graviola](https://github.com/ctz/graviola) (pure Rust, no C compiler
//! or cmake) as the crypto backend.
//!
//! See `sentin8/design/sentin8-sentin8-tls-technical-design.md` for the full design.

use rustls::crypto::CryptoProvider;
use rustls::version::{TLS12, TLS13};
use rustls_graviola::kx::X25519MLKEM768;

/// Reads `SENTIN8_TLS_PQ_MODE` (default: `exclusive`).
fn pq_mode() -> String {
    std::env::var("SENTIN8_TLS_PQ_MODE").unwrap_or_else(|_| "exclusive".to_string())
}

/// Sentin8's CryptoProvider, keyed off `SENTIN8_TLS_PQ_MODE`.
///
/// - `exclusive`: only X25519MLKEM768 - no classical fallback.
/// - `hybrid`: Graviola default (X25519MLKEM768 first, classical fallback).
/// - `classical`: classical groups only (no ML-KEM) - emergency rollback.
pub fn sentin8_pq_provider() -> CryptoProvider {
    let base = rustls_graviola::default_provider();
    let base = cipher_profile(base);
    match pq_mode().as_str() {
        "exclusive" => CryptoProvider {
            kx_groups: vec![X25519MLKEM768],
            ..base
        },
        "hybrid" => base,
        "classical" => CryptoProvider {
            kx_groups: rustls_graviola::kx::ALL_KX_GROUPS
                .iter()
                .copied()
                .filter(|g| g.name() != rustls::NamedGroup::X25519MLKEM768)
                .collect(),
            ..base
        },
        _ => CryptoProvider {
            kx_groups: vec![X25519MLKEM768],
            ..base
        },
    }
}

/// Cipher-suite profile keyed off `SENTIN8_TLS_CIPHER_PROFILE`.
///
/// - `default` (unset): graviola's full suite list.
/// - `fapi`: the FAPI-permitted ciphers only (FAPI1-ADV / FAPI2 SP:
///   TLS 1.3 AES_256_GCM_SHA384 + CHACHA20_POLY1305_SHA256; TLS 1.2
///   ECDHE with AES_256_GCM_SHA384 + CHACHA20_POLY1305_SHA256) - the
///   AES_128_GCM suites are the FAPI-rejected weak set.
fn cipher_profile(base: CryptoProvider) -> CryptoProvider {
    let profile = std::env::var("SENTIN8_TLS_CIPHER_PROFILE")
        .unwrap_or_else(|_| "default".to_string());
    if profile != "fapi" {
        return base;
    }
    let mut suites = base.cipher_suites;
    suites.retain(|s| {
        use rustls::CipherSuite;
        matches!(
            s.suite(),
            CipherSuite::TLS13_AES_256_GCM_SHA384
                | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                | CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                | CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        )
    });
    CryptoProvider {
        cipher_suites: suites,
        ..base
    }
}

/// The TLS protocol versions to enable, keyed off `SENTIN8_TLS_PQ_MODE`.
///
/// - `exclusive` / `hybrid`: TLS 1.3 only (ML-KEM requires TLS 1.3).
/// - `classical`: TLS 1.2 + 1.3 (max compatibility for emergency rollback).
///
/// Pass this vec to `ServerConfig::builder_with_provider(...).with_protocol_versions(...)`.
pub fn sentin8_tls_versions() -> Vec<&'static rustls::SupportedProtocolVersion> {
    match pq_mode().as_str() {
        "classical" => vec![&TLS12, &TLS13],
        _ => vec![&TLS13],
    }
}
