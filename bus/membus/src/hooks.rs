// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Optional, sampled metrics hooks.
//!
//! Default is a no-op - **zero cost on the hot path unless opted in**.
//! Adopters can wire a sampling implementation into Sentin8:Stat.
//! `on_gap` is how `sq` sequence gaps become visible.

/// Delivery class of a publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Durable - Valkey Stream + consumer group.
    Stream,
    /// Ephemeral - Pub/Sub channel.
    PubSub,
}

/// Metrics sink. All methods have default no-op bodies; implement only
/// what you observe.
pub trait MetricsHooks: Send + Sync {
    /// A publish completed - `latency_us` is the full round trip
    /// (envelope build included).
    fn on_publish(&self, _family: &str, _class: Class, _latency_us: u64) {}

    /// A consume batch of `n` messages was delivered to `group`.
    fn on_batch(&self, _family: &str, _group: &str, _n: usize) {}

    /// A sequence gap: expected `expected_sq` next but saw `got_sq`.
    /// Distinguishes trim-loss (benign) from real drops (investigate).
    fn on_gap(&self, _family: &str, _expected_sq: u64, _got_sq: u64) {}

    /// A connection re-established after a failure.
    fn on_reconnect(&self, _class: Class) {}
}

/// The default hooks - every method a no-op.
pub struct NoopMetrics;

impl MetricsHooks for NoopMetrics {}
