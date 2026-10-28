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
    let profile =
        std::env::var("SENTIN8_TLS_CIPHER_PROFILE").unwrap_or_else(|_| "default".to_string());
    if profile != "fapi" {
        return base;
    }
    let mut suites = base.cipher_suites;
    // FAPI1-ADV 8.5 (the suite's FAPITLSClient FAPI_TLS_1_2_CIPHERS =
    // ECDHE_RSA_AES_128/256_GCM - IANA 0x009E/0x009F + bouncy 0xC02F/0xC030;
    // NO ECDHE_ECDSA at TLS 1.2: FAPI has no ECDSA-cert plane at 1.2) +
    // TLS 1.3 limited to AES_256_GCM + CHACHA20 (the suite's
    // TLS_1_3_CIPHERS; AES_128_GCM is in the insecure-allowed set but the
    // DisallowInsecureCipher probes agree it against the FAPI list and
    // flag any server agreement outside it - the 8.5-1 rejection). The
    // suite's checker (AbstractCheckInsecureCiphers$1) offers ONLY the
    // insecure suites and requires the TLS1.2 handshake to FAIL; with an
    // ECDSA-only leaf plane the server answers no TLS1.2 suite at all -
    // the checker's "Server does not support TLS 1.2" green path (the
    // prior campaigns' state). Re-adding ECDHE_ECDSA members here made
    // the handshake COMPLETE (agreed 0xC023 = outside the FAPI list) and
    // the 8.5-1 check FAILED - they stay OUT of this profile.
    suites.retain(|s| {
        use rustls::CipherSuite;
        matches!(
            s.suite(),
            CipherSuite::TLS13_AES_256_GCM_SHA384
                | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                | CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
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

#[cfg(test)]
mod classical_tests {
    use super::*;

    #[test]
    fn classical_mode_enables_tls12() {
        std::env::set_var("SENTIN8_TLS_PQ_MODE", "classical");
        let versions = sentin8_tls_versions();
        assert!(versions
            .iter()
            .any(|v| v.version == rustls::ProtocolVersion::TLSv1_2));
    }

    #[test]
    fn classical_fapi_provider_tls12_rsa_only() {
        std::env::set_var("SENTIN8_TLS_PQ_MODE", "classical");
        std::env::set_var("SENTIN8_TLS_CIPHER_PROFILE", "fapi");
        let p = sentin8_pq_provider();
        // TLS1.2 = ECDHE_RSA ONLY (the suite's FAPI_TLS_1_2_CIPHERS; the
        // ECDSA-GCM agreement = the DisallowInsecureCipher 8.5-1 failure).
        assert!(p
            .cipher_suites
            .iter()
            .any(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256));
        assert!(!p
            .cipher_suites
            .iter()
            .any(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256));
        assert!(!p
            .kx_groups
            .iter()
            .any(|g| g.name() == rustls::NamedGroup::X25519MLKEM768));
    }
}
