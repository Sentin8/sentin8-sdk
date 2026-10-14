// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Bootstrap enrollment credential — shared contract between Sentin8:Captain
//! (producer/broker) and enrolled services that need to break the first-boot
//! chicken-and-egg problem of bootstrap-time identity.
//!
//! ## The problem
//!
//! A first-boot workload holds no client certificate and no token — it
//! cannot authenticate to ANYONE, including the Acme `POST /v1/client-cert`
//! endpoint it needs to mint its identity (unauthenticated minting would be
//! a security hole). The captain-brokered enrollment credential is the
//! closed-loop alternative: the captain generates a
//! time-boxed secret at boot, shares it with BOTH the workload and acme via
//! their process environment, and acme admits enrollment mints presenting
//! the SAME secret — verified locally, with no auth round-trip.
//!
//! ## Trust model (why a shared env secret is acceptable here)
//!
//! The captain process is the root of trust for the fleet's runtime
//! configuration: it already distributes TLS roots, master keys, and peer
//! ports via process environment. The enrollment credential extends the
//! same channel with a strictly narrower grant: it authorizes ONLY
//! `m2m-*` client-cert mints, ONLY for the TTL window, ONLY against the
//! one acme instance the captain spawned with the same value. A process
//! that can read another process's environment could read its credential
//! files too — the env channel adds no new attack surface.
//!
//! ## Lifetime
//!
//! - Generated lazily on the first spawn (`ensure_enrollment`), sealed at
//!   rest on disk (captain side, 0600) with a key derived from
//!   `SENTIN8_BOOTSTRAP_MASTER_KEY || SENTIN8_AUTH_MASTER_KEY`.
//! - Propagated as plaintext env vars to workloads + acme (env is the
//!   transport; the sealed file protects the at-rest copy).
//! - `claim_is_valid` enforces the TTL — the captain rotates the record
//!   after [`TTL_SECS`]; acme rejects stale claims (clock skew tolerance
//!   is [`CLOCK_SKEW_SECS`], acme's stamp is its own — it must simply be
//!   fresh; the captain's stamp must be within [`CLOCK_SKEW_SECS`] of
//!   now from the verifier's perspective).
//! - Cleared on captain shutdown; a restart regenerates it, so the
//!   credential never outlives the captain process that brokered it.

/// Environment variable holding the enrollment secret (hex, 32 bytes).
pub const ENV_ENROLLMENT: &str = "SENTIN8_BOOTSTRAP_ENROLLMENT";
/// Environment variable holding the Unix-seconds timestamp the secret was
/// generated at (captain stamps; acme re-stamps with its own receive time —
/// both are validated for freshness).
pub const ENV_ENROLLMENT_TS: &str = "SENTIN8_BOOTSTRAP_ENROLLMENT_TS";
/// Enrollment secret TTL in seconds. Short on purpose: the credential only
/// bridges the window between a process spawn and its first successful
/// DCR; a fleet-wide re-roll regenerates it.
pub const TTL_SECS: u64 = 600;
/// Clock-skew tolerance applied to timestamp comparisons.
pub const CLOCK_SKEW_SECS: i64 = 30;

/// Freshness check for an enrollment claim: the timestamp must parse, be a
/// plausible Unix timestamp (not zero / not absurdly far in the future), and
/// fall within [`TTL_SECS`] (+ skew) of now. Used verbatim by BOTH captain
/// (`ensure_enrollment` record validation) and acme (claim verification) so
/// the two sides agree on expiry.
pub fn claim_is_valid(secret: &str, ts: i64) -> bool {
    if secret.is_empty() || ts <= 0 {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let drift = now - ts;
    drift >= -CLOCK_SKEW_SECS && drift <= (TTL_SECS as i64) + CLOCK_SKEW_SECS
}

/// The sealed enrollment record captain maintains:
/// `{run_dir}/bootstrap-enrollment.json.enc` (0600, envelope-encrypted with
/// a key derived from `SENTIN8_BOOTSTRAP_MASTER_KEY` falling back to
/// `SENTIN8_AUTH_MASTER_KEY` — the same derivation captain uses when
/// sealing). Captain regenerates the record on every TTL expiry
/// (`ensure_enrollment`), so the file always holds the CURRENT claim.
pub fn enrollment_record_path() -> std::path::PathBuf {
    std::path::Path::new(&crate::run_dir()).join("bootstrap-enrollment.json.enc")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn claim_valid_within_ttl() {
        assert!(claim_is_valid("abc", now()));
        assert!(claim_is_valid("abc", now() - TTL_SECS as i64));
    }

    #[test]
    fn claim_invalid_outside_ttl() {
        assert!(!claim_is_valid(
            "abc",
            now() - TTL_SECS as i64 - CLOCK_SKEW_SECS - 1
        ));
        assert!(!claim_is_valid("abc", 0));
        assert!(!claim_is_valid("", now()));
    }

    #[test]
    fn claim_invalid_future_beyond_skew() {
        assert!(!claim_is_valid("abc", now() + CLOCK_SKEW_SECS + 60));
    }
}
