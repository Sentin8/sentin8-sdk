// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Mapping-cache maintenance hook.
//!
//! The `MappingCache` starts empty and is populated only through its
//! explicit mutation methods (service bootstrap or tests). Hostname →
//! service resolution is authoritative through DB-based domain-pattern
//! deduction in `HostContextResolver` (see `context.rs`); the cache
//! serves as an optional pre-seeded fast path.

/// Maintain the mapping cache from change notifications.
///
/// Currently a no-op: there is no active change-notification loop, and
/// the cache is populated only via explicit `MappingCache` calls.
/// Retained so services can call it through `Sentin8Tls::builder().build()`.
pub fn spawn_sync(
    _pool: sqlx::PgPool,
    _cache: crate::cache::MappingCache,
    _cert_resolver: std::sync::Arc<crate::certs::WildcardCertResolver>,
    _notify_channel: String,
) {
    // No maintenance loop - see the module doc.
}
