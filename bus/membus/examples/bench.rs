// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! MemBus latency bench.
//!
//! Run: `cargo run --release -p sentin8-membus --example bench`
//! (or `make bench-membus` from the sentin8 workspace).
//!
//! Measures, against the live platform Valkey:
//! - stream publish (single XADD) P50/P99
//! - pipelined publish_many amortized per-message
//! - pub/sub end-to-end (PUBLISH → subscriber frame)
//! - stream consume (XADD → consumer delivery)
//!
//! Acceptance gate: stream publish P50 ≤ 200µs and
//! pub/sub e2e P50 ≤ 500µs on the dev host. The process exits
//! non-zero when the gate fails.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sentin8_membus::{Envelope, MemBus, MemBusConfig, NoopMetrics, StreamOpts};

const N: usize = 2_000;
const PIPE_N: usize = 5_000;
const WARMUP: usize = 200;

fn percentile(mut samples: Vec<u128>, p: f64) -> u128 {
    samples.sort_unstable();
    let idx = ((p / 100.0) * samples.len() as f64).round() as usize;
    let idx = idx.min(samples.len() - 1);
    samples[idx]
}

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(run());
}

async fn run() {
    let cfg = MemBusConfig {
        url: std::env::var("VALKEY_URL").unwrap_or_else(|_| "valkey://localhost:6379/0".into()),
        service_name: "membus-bench".into(),
        workload: "membus-bench".into(),
        trim_default: 100_000,
        metrics: Arc::new(NoopMetrics),
    };
    let bus = match MemBus::connect(cfg).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("bench: Valkey unreachable - {e}");
            std::process::exit(2);
        }
    };
    let env = bus.for_env(&uuid::Uuid::new_v4().to_string()).unwrap();

    // ── 1. Single stream publish ─────────────────────────────────
    let mut sub = env
        .subscribe_stream("bench.stream", "bench", StreamOpts::default())
        .await
        .unwrap();
    // Warmup (JIT allocator, connection pools, page faults).
    for i in 0..WARMUP {
        let e = Envelope::new("svc:me:trade:printed", i.to_le_bytes().to_vec());
        env.publish_stream("bench.stream", &e).await.unwrap();
    }
    // Drain warmup.
    let mut drained = 0;
    while drained < WARMUP {
        let b = sub.next_batch().await.unwrap().unwrap();
        drained += b.len();
    }

    let mut samples = Vec::with_capacity(N);
    for i in 0..N {
        let e = Envelope::new(
            "svc:me:trade:printed",
            format!("{{\"i\":{i}}}").into_bytes(),
        );
        let t0 = Instant::now();
        env.publish_stream("bench.stream", &e).await.unwrap();
        samples.push(t0.elapsed().as_micros());
    }
    let p50 = percentile(samples.clone(), 50.0);
    let p99 = percentile(samples.clone(), 99.0);
    println!("stream publish     : P50 {p50:>6} µs  P99 {p99:>7} µs  (n={N})");

    // Drain + measure consume path (XADD → delivered).
    let mut consumed = 0;
    let mut consume_us: Vec<u128> = Vec::new();
    while consumed < N {
        let b = sub.next_batch().await.unwrap().unwrap();
        if !b.is_empty() {
            // Delivery latency from the LAST XADD of the batch.
            let last_ts = b.last().unwrap().envelope.ts_us;
            let now = now_micros();
            let delta = now.saturating_sub(last_ts);
            for _ in b.iter() {
                consume_us.push(delta as u128);
            }
            consumed += b.len();
        }
    }
    let c_p50 = percentile(consume_us.clone(), 50.0);
    println!("stream consume     : P50 {c_p50:>6} µs (XADD→delivered)");

    // ── 2. Pipelined publish_many ──────────────────────────────
    let envelopes: Vec<Envelope> = (0..PIPE_N)
        .map(|i| Envelope::new("svc:me:trade:printed", i.to_le_bytes().to_vec()))
        .collect();
    let t0 = Instant::now();
    env.publish_stream_many("bench.pipe", &envelopes)
        .await
        .unwrap();
    let total = t0.elapsed().as_micros();
    println!(
        "publish_many x{PIPE_N:<4}: total {total:>9} µs  amortized {:>4} µs/msg",
        total / PIPE_N as u128
    );

    // ── 3. Pub/sub end-to-end ──────────────────────────────────
    let mut ps = env.subscribe_pubsub("bench.pubsub").await.unwrap();
    // Give the SUBSCRIBE a moment to register server-side.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut e2e = Vec::with_capacity(N / 2);
    for i in 0..(N / 2) {
        let e = Envelope::new("svc:md:book:delta", i.to_le_bytes().to_vec());
        let t0 = Instant::now();
        env.publish_pubsub("bench.pubsub", &e).await.unwrap();
        let frame = ps.next_frame().await.unwrap().unwrap();
        e2e.push(t0.elapsed().as_micros());
        let _ = frame;
    }
    let pp_p50 = percentile(e2e.clone(), 50.0);
    let pp_p99 = percentile(e2e.clone(), 99.0);
    println!(
        "pub/sub e2e        : P50 {pp_p50:>6} µs  P99 {pp_p99:>7} µs  (n={})",
        N / 2
    );

    // ── Acceptance gate ─────────────────────────────────────────
    println!();
    let mut ok = true;
    if p50 > 200 {
        println!("✗ FAIL gate: stream publish P50 {p50} µs > 200 µs");
        ok = false;
    } else {
        println!("✓ stream publish P50 {p50} µs ≤ 200 µs");
    }
    if pp_p50 > 500 {
        println!("✗ FAIL gate: pub/sub e2e P50 {pp_p50} µs > 500 µs");
        ok = false;
    } else {
        println!("✓ pub/sub e2e P50 {pp_p50} µs ≤ 500 µs");
    }
    if !ok {
        std::process::exit(1);
    }
    println!("bench: all gates passed");
}

fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}
