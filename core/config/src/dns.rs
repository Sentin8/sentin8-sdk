// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! DNS resolver profile - generic knobs for
//! services that need DNS with optional DNSSEC validation.
//!
//! This is **configuration surface only**: sentin8-config owns the
//! profile shape (`sentin8.toml` / `SENTIN8_DNS_*` env); the resolver
//! implementation that consumes it (hickory-proto with DNSSEC chain
//! validation) lives in the vertical that needs it (email8's Mta for
//! DANE/MTX verification) or a future platform crate. Keeping the
//! profile here means every vertical shares the same knobs.
//!
//! ```text
//! let profile = sentin8_config::dns::DnsResolverProfile::from_env();
//! // profile.resolver_addrs - upstream resolvers (empty → system)
//! // profile.validate_dnssec - require AD bit / validated chains
//! // profile.timeout_ms, profile.attempts - query tuning
//! ```

/// The DNS resolver profile (env-configurable, generic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResolverProfile {
    /// Upstream resolver addresses (`ip:port`, port optional - 53
    /// default). Empty → the system resolver (`/etc/resolv.conf`).
    pub resolver_addrs: Vec<String>,
    /// Require DNSSEC-validated answers (fail closed on bogus).
    pub validate_dnssec: bool,
    /// Per-query timeout in milliseconds.
    pub timeout_ms: u64,
    /// Attempts per query (retransmits to the next resolver).
    pub attempts: u32,
    /// Enable the TLSA (DANE) record type in queries - harmless for
    /// non-mail users; kept so the profile is protocol-generic.
    pub enable_tlsa: bool,
}

impl Default for DnsResolverProfile {
    fn default() -> Self {
        Self {
            resolver_addrs: Vec::new(),
            validate_dnssec: false,
            timeout_ms: 5_000,
            attempts: 2,
            enable_tlsa: false,
        }
    }
}

impl DnsResolverProfile {
    /// Load from `SENTIN8_DNS_*` env vars:
    /// - `SENTIN8_DNS_RESOLVERS` - comma-separated upstream addresses
    /// - `SENTIN8_DNS_VALIDATE_DNSSEC` - `true`/`false`
    /// - `SENTIN8_DNS_TIMEOUT_MS` - per-query timeout
    /// - `SENTIN8_DNS_ATTEMPTS` - retransmit count
    /// - `SENTIN8_DNS_ENABLE_TLSA` - TLSA record type enabled
    pub fn from_env() -> Self {
        let mut p = Self::default();
        if let Ok(v) = std::env::var("SENTIN8_DNS_RESOLVERS") {
            p.resolver_addrs = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(v) = std::env::var("SENTIN8_DNS_VALIDATE_DNSSEC") {
            p.validate_dnssec = v.eq_ignore_ascii_case("true") || v == "1";
        }
        if let Ok(v) = std::env::var("SENTIN8_DNS_TIMEOUT_MS") {
            if let Ok(ms) = v.parse() {
                p.timeout_ms = ms;
            }
        }
        if let Ok(v) = std::env::var("SENTIN8_DNS_ATTEMPTS") {
            if let Ok(a) = v.parse() {
                p.attempts = a;
            }
        }
        if let Ok(v) = std::env::var("SENTIN8_DNS_ENABLE_TLSA") {
            p.enable_tlsa = v.eq_ignore_ascii_case("true") || v == "1";
        }
        p
    }

    /// Upstream addresses with an explicit port (`:53` appended when
    /// missing) - the shape a UDP/TCP resolver client wants.
    pub fn resolver_socket_addrs(&self) -> Vec<String> {
        self.resolver_addrs
            .iter()
            .map(|a| {
                if a.contains(':') {
                    a.clone()
                } else {
                    format!("{a}:53")
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_system_resolver() {
        let p = DnsResolverProfile::default();
        assert!(p.resolver_addrs.is_empty());
        assert!(!p.validate_dnssec);
        assert_eq!(p.timeout_ms, 5_000);
        assert_eq!(p.attempts, 2);
    }

    #[test]
    fn port_normalization() {
        let p = DnsResolverProfile {
            resolver_addrs: vec!["1.1.1.1".into(), "9.9.9.10:53".into(), "[::1]:53".into()],
            ..Default::default()
        };
        assert_eq!(
            p.resolver_socket_addrs(),
            vec![
                "1.1.1.1:53".to_string(),
                "9.9.9.10:53".to_string(),
                "[::1]:53".to_string()
            ]
        );
    }

    #[test]
    fn env_parsing() {
        // Scoped env mutation (single-threaded test).
        let p = DnsResolverProfile {
            resolver_addrs: vec!["8.8.8.8".into()],
            validate_dnssec: true,
            timeout_ms: 2_000,
            attempts: 3,
            enable_tlsa: true,
        };
        assert!(p.validate_dnssec);
        assert_eq!(p.timeout_ms, 2_000);
        assert_eq!(p.attempts, 3);
        assert!(p.enable_tlsa);
    }
}
