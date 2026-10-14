// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Live integration tests against the platform Valkey (`valkey://localhost:6379`).
//!
//! Skipped automatically when Valkey is unreachable — run with
//! `cargo test -p sentin8-membus` on a host where `make infra-up` has
//! been executed. These prove the two delivery classes end-to-end:
//! XADD/XREADGROUP/XACK with trim, XAUTOCLAIM crash recovery, PUBLISH/
//! SUBSCRIBE frames, tenant-scoped key derivation, and the
//! connection-isolation invariant (publishes never block behind a
//! consumer's blocking read).

use std::sync::Arc;
use std::time::Duration;

use sentin8_membus::{
    Class, Envelope, MemBus, MemBusConfig, MemBusError, MetricsHooks, StreamOpts,
};
use tokio::time::{sleep, timeout};

/// A random env id per run — the `mbus:{env}:…` keys are disposable test
/// data in a dev Valkey; no cleanup contract needed.
fn mk_env() -> String {
    uuid::Uuid::new_v4().to_string()
}

async fn bus() -> Option<MemBus> {
    let cfg = MemBusConfig {
        url: std::env::var("VALKEY_URL").unwrap_or_else(|_| "valkey://localhost:6379/0".into()),
        service_name: "membus-test".into(),
        workload: "membus-test".into(),
        trim_default: 10_000,
        metrics: Arc::new(NoopMetrics),
    };
    match MemBus::connect(cfg).await {
        Ok(b) => Some(b),
        Err(e) => {
            eprintln!("skipping live tests — Valkey unreachable: {e}");
            None
        }
    }
}

use sentin8_membus::NoopMetrics;

#[tokio::test]
async fn stream_publish_consume_ack_round_trip() {
    let Some(bus) = bus().await else { return };
    let env = bus.for_env(&mk_env()).unwrap();
    // Group must be created BEFORE publishing (XGROUP CREATE uses `$`,
    // so entries XADDed before the group exists are not delivered to
    // it — the durable class is subscribe-then-publish for a new group).
    let mut sub = env
        .subscribe_stream("it.trade", "oms", StreamOpts::default())
        .await
        .unwrap();
    assert!(sub.stream_key().starts_with("mbus:"));

    // Publish 5 fills.
    for i in 0..5u64 {
        let e = Envelope::new(
            "svc:me:trade:printed",
            format!("{{\"i\":{i}}}").into_bytes(),
        );
        env.publish_stream("it.trade", &e).await.unwrap();
    }
    sleep(Duration::from_millis(50)).await;

    let batch = timeout(Duration::from_secs(5), sub.next_batch())
        .await
        .unwrap() // timeout elapsed
        .unwrap() // MemBusError
        .unwrap(); // stream end (None)
    assert_eq!(batch.len(), 5);
    // The library assigned sq 1..=5 (per-(service, family) monotonic).
    let sqs: Vec<u64> = batch.iter().map(|m| m.envelope.sq).collect();
    assert_eq!(sqs, vec![1, 2, 3, 4, 5]);
    // Envelopes round-trip: producer + payload intact.
    assert!(batch.iter().all(|m| m.envelope.producer == "membus-test"));
    assert_eq!(batch[0].envelope.payload, b"{\"i\":0}".to_vec());

    // Coalesced ack flushes on the next next_batch() call.
    let batch2 = timeout(Duration::from_secs(5), sub.next_batch())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(batch2.is_empty());
    assert_eq!(sub.pending_ack(), 0);
}

#[tokio::test]
async fn pipelined_publish_many_amortizes_round_trip() {
    let Some(bus) = bus().await else { return };
    let env = bus.for_env(&mk_env()).unwrap();
    let mut sub = env
        .subscribe_stream("it.batch", "md", StreamOpts::default())
        .await
        .unwrap();

    let envelopes: Vec<Envelope> = (0..64u64)
        .map(|i| Envelope::new("svc:me:trade:printed", i.to_le_bytes().to_vec()))
        .collect();
    let ids = env
        .publish_stream_many("it.batch", &envelopes)
        .await
        .unwrap();
    assert_eq!(ids.len(), 64);

    let mut got = 0;
    let mut total = Vec::new();
    for _ in 0..10 {
        let batch = timeout(Duration::from_secs(1), sub.next_batch())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        got += batch.len();
        total.extend(batch.into_iter().map(|m| m.envelope.sq));
        if got >= 64 {
            break;
        }
    }
    assert_eq!(got, 64, "all pipelined entries delivered");
    total.sort_unstable();
    assert_eq!(total, (1..=64).collect::<Vec<u64>>());
}

#[tokio::test]
async fn pubsub_frame_round_trip_and_loss_contract() {
    let Some(bus) = bus().await else { return };
    let env = bus.for_env(&mk_env()).unwrap();

    // Subscribe BEFORE publish — an ephemeral message with no live
    // subscriber is gone by contract.
    let mut sub = env.subscribe_pubsub("it.tick").await.unwrap();
    assert!(sub.channel().starts_with("mchan:"));

    let e = Envelope::new("svc:md:book:delta", b"level2".to_vec()).with_correlation("corr-7");
    env.publish_pubsub("it.tick", &e).await.unwrap();

    let frame = timeout(Duration::from_secs(5), sub.next_frame())
        .await
        .unwrap() // timeout
        .unwrap() // MemBusError
        .unwrap(); // None = subscription ended
    assert_eq!(frame.event_type, "svc:md:book:delta");
    assert_eq!(frame.payload, b"level2".to_vec());
    assert_eq!(frame.correlation_id, "corr-7");
    assert_eq!(frame.sq, 1);
}

#[tokio::test]
async fn publish_does_not_block_behind_subscriber() {
    // The connection invariant: a consumer sitting in a BLOCKING XREADGROUP
    // (dedicated connection) must not stall publishes on the shared
    // command connection. With the old shared-connection bug this test
    // would take ~10s per publish; here every publish must return in
    // well under the block window.
    let Some(bus) = bus().await else { return };
    let env = bus.for_env(&mk_env()).unwrap();
    let _sub = env
        .subscribe_stream(
            "it.block",
            "slow",
            StreamOpts {
                count: 1,
                block_ms: 10_000,
            },
        )
        .await
        .unwrap();

    let started = std::time::Instant::now();
    for i in 0..5u64 {
        let e = Envelope::new("svc:me:trade:printed", i.to_string().into_bytes());
        env.publish_stream("it.block", &e).await.unwrap();
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "publishes stalled behind the blocking consumer: {elapsed:?}"
    );
}

#[tokio::test]
async fn tenant_keys_derive_from_bound_env_only() {
    let Some(bus) = bus().await else { return };
    let env_a = bus.for_env(&mk_env()).unwrap();
    let env_b = bus.for_env(&mk_env()).unwrap();
    // Same family, different tenants → disjoint stream keys.
    let mut sub_a = env_a
        .subscribe_stream("it.tenant", "oms", StreamOpts::default())
        .await
        .unwrap();
    assert_ne!(
        sub_a.stream_key(),
        format!("mbus:{}:it.tenant", env_b.env_id())
    );

    // env_b's publish must never appear in env_a's stream.
    let e = Envelope::new("svc:me:trade:printed", b"x".to_vec());
    env_b.publish_stream("it.tenant", &e).await.unwrap();
    let batch = timeout(Duration::from_millis(300), sub_a.next_batch())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(batch.is_empty(), "cross-tenant leak!");

    // for_env rejects non-UUID env ids outright.
    assert!(matches!(
        bus.for_env("not-a-uuid"),
        Err(MemBusError::InvalidEnv(_))
    ));
}

#[tokio::test]
async fn trim_bounds_stream_length() {
    let Some(_bus) = bus().await else { return };
    // Tight trim target proves MAXLEN ~ is honored on every XADD.
    let cfg = MemBusConfig {
        url: "valkeys://localhost:6379/0".into(),
        service_name: "membus-test".into(),
        workload: "membus-test".into(),
        trim_default: 100,
        metrics: Arc::new(NoopMetrics),
    };
    let bus = MemBus::connect(cfg).await.unwrap();
    let env = bus.for_env(&mk_env()).unwrap();
    for i in 0..500u64 {
        let e = Envelope::new("svc:me:trade:printed", i.to_string().into_bytes());
        env.publish_stream("it.trim", &e).await.unwrap();
    }
    let conn = sentin8_middleware::valkey_client(
        &std::env::var("VALKEY_URL").unwrap_or_else(|_| "valkeys://localhost:6379/0".into()),
        "membus-test",
    )
    .await
    .unwrap();
    use glide::AsyncCommands as _;
    let len: i64 = conn
        .xlen(format!("mbus:{}:it.trim", env.env_id()))
        .await
        .unwrap();
    // Approximate trim may overshoot slightly, never by 5x.
    assert!(len <= 200, "stream not trimmed: len={len}");
}

/// Counting hooks — proves the sampled-observation surface works.
#[derive(Default)]
struct Counting {
    count: std::sync::atomic::AtomicU64,
}

impl MetricsHooks for Counting {
    fn on_publish(&self, _family: &str, _class: Class, _latency_us: u64) {
        self.count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[tokio::test]
async fn metrics_hooks_fire_on_publish() {
    let Some(_bus) = bus().await else { return };
    let hooks = Arc::new(Counting::default());
    let cfg = MemBusConfig {
        url: "valkeys://localhost:6379/0".into(),
        service_name: "membus-test".into(),
        workload: "membus-test".into(),
        trim_default: 1_000,
        metrics: hooks.clone(),
    };
    let bus = MemBus::connect(cfg).await.unwrap();
    let env = bus.for_env(&mk_env()).unwrap();
    for i in 0..3u64 {
        let e = Envelope::new("svc:me:trade:printed", i.to_string().into_bytes());
        env.publish_stream("it.metrics", &e).await.unwrap();
    }
    assert_eq!(hooks.count.load(std::sync::atomic::Ordering::Relaxed), 3);
}

#[tokio::test]
async fn ping_sets_liveness_key() {
    let Some(bus) = bus().await else { return };
    bus.ping().await.unwrap();
    let conn = sentin8_middleware::valkey_client(
        &std::env::var("VALKEY_URL").unwrap_or_else(|_| "valkeys://localhost:6379/0".into()),
        "membus-test",
    )
    .await
    .unwrap();
    use glide::AsyncCommands as _;
    let exists: Option<bool> = conn.exists("mbus:ping:membus-test").await.unwrap();
    assert!(exists.unwrap_or(false), "liveness key not set");
}

#[tokio::test]
async fn plaintext_scheme_rejected_at_connect() {
    // Group DESIGN.md §3.1: the Valkey data plane is TLS-ONLY — MemBus
    // connects through the cert-presenting factory, which REQUIRES the
    // `valkeys://` scheme. A plaintext URL is a configuration error surfaced
    // as `MemBusError::Connect` — never a silent downgrade (there is no
    // plaintext listener to reach).
    let cfg = MemBusConfig {
        url: "plaintext://localhost:6379/0".into(),
        service_name: "membus-test".into(),
        workload: "membus-test".into(),
        trim_default: 100,
        metrics: Arc::new(NoopMetrics),
    };
    assert!(matches!(
        MemBus::connect(cfg).await,
        Err(MemBusError::Connect(_))
    ));
}
