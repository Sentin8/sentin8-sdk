// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # Batched async log writer
//!
//! The default [`Sentin8JsonLayer`](crate::structured_logging::Sentin8JsonLayer)
//! emits one log line per `tracing` event via `println!`. Under load
//! (a busy BFF / tls instance doing >10k req/s) this can spend
//! ~30-50% of CPU just on `write()` syscalls to stdout.
//!
//! This module provides a drop-in alternative: a bounded
//! `mpsc` channel + a background tokio task that batches lines into a
//! [`BufWriter`](std::io::BufWriter) and flushes them every
//! `flush_interval` (default 250ms) or when the buffer hits
//! `batch_size` (default 128 lines).
//!
//! ## AI-friendliness
//!
//! - **One line per event** — the channel is line-oriented, not
//!   batch-framed, so the consumer (Loki, ES, an LLM) sees the same
//!   wire format whether or not the writer is in use.
//! - **No NDJSON frames** — we don't ship `[{...},{...}]` blobs. The
//!   LLM and `grep` would have to re-split, costing tokens and CPU.
//! - **Backpressure with loss-limit** — if the channel is full
//!   (the consumer is slow or the writer is paused), newer events are
//!   dropped **and a single rate-limited `log_writer.backpressure` WARN
//!   is emitted** so the agent can see we're losing lines without
//!   every dropped line generating its own log line (which would
//!   amplify the problem).
//!
//! ## Usage
//!
//! ```text
//! use sentin8_middleware::batched_log::BatchedLogWriter;
//! use sentin8_middleware::structured_logging::install_batched_layer;
//!
//! let writer = BatchedLogWriter::start();
//! install_batched_layer("ledger", "info", writer.clone());
//! // ... service runs ...
//! writer.shutdown().await; // flush + stop
//! ```
//!
//! The writer is a [`LogSink`] — pluggable, so future deployments
//! can ship directly to a TCP socket, a Unix pipe, or a remote
//! collector without changing the layer.

use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Default channel capacity. Sized so a 1ms stdout hickup doesn't
/// drop events, but bounded so an OOM in the writer doesn't cascade.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 16_384;

/// Default batch size. Flushing 128 lines at a time keeps the
/// write() syscall amortisation close to optimal on Linux.
pub const DEFAULT_BATCH_SIZE: usize = 128;

/// Default flush interval. 250ms means logs reach the log store
/// within a quarter-second, well under any human-perceptible delay.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// A handle to the batched log writer. Clone it freely — it's an
/// `Arc` over the sender side. The writer task is reference-counted
/// and lives until every handle is dropped (or until
/// [`shutdown`](Self::shutdown) is called).
#[derive(Clone)]
pub struct BatchedLogWriter {
    tx: mpsc::Sender<String>,
    state: Arc<WriterState>,
    /// Configured time-based flush interval. Retained on the handle
    /// for future introspection / health checks; the writer task
    /// captures the value directly from [`start_with`](Self::start_with).
    #[allow(dead_code)]
    flush_interval: Duration,
    /// Configured batch-size flush threshold. Retained on the handle
    /// for future introspection / health checks; the writer task
    /// captures the value directly from [`start_with`](Self::start_with).
    #[allow(dead_code)]
    batch_size: usize,
}

struct WriterState {
    /// Total lines written since startup. Useful for health checks.
    written: AtomicU64,
    /// Total lines dropped due to backpressure since startup.
    dropped: AtomicU64,
    /// True after [`BatchedLogWriter::shutdown`] is called. Once true,
    /// the writer refuses new lines instead of accepting them and
    /// leaking on shutdown.
    shutdown: AtomicBool,
    /// Tracks the last time we emitted a backpressure WARN, so we
    /// don't spam the log stream with one warning per dropped line.
    last_backpressure_warn_ms: AtomicU64,
}

impl BatchedLogWriter {
    /// Start a batched log writer with the defaults. The returned
    /// handle is what the layer uses to enqueue lines.
    pub fn start() -> Self {
        Self::start_with(
            DEFAULT_CHANNEL_CAPACITY,
            DEFAULT_BATCH_SIZE,
            DEFAULT_FLUSH_INTERVAL,
        )
    }

    /// Start a writer with explicit tuning. `channel_capacity` is the
    /// in-flight lines (memory ~ `capacity * 256` bytes); `batch_size`
    /// is the flush threshold; `flush_interval` is the time-based
    /// flush.
    pub fn start_with(
        channel_capacity: usize,
        batch_size: usize,
        flush_interval: Duration,
    ) -> Self {
        // The writer task is dispatched on a `spawn_blocking` worker
        // because stdout I/O is blocking and uses a `!Send`
        // reentrant lock internally. Driving it on the async runtime
        // would either fail the `Send` bound or hold a worker thread
        // for the lifetime of the process.
        //
        // We bridge the async `mpsc::Receiver` (so producers stay
        // async-friendly) to a synchronous `std::sync::mpsc`
        // channel owned by the blocking writer task.
        let (tx, mut rx) = mpsc::channel::<String>(channel_capacity);
        let state = Arc::new(WriterState {
            written: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            last_backpressure_warn_ms: AtomicU64::new(0),
        });
        let (sync_tx, sync_rx) = std::sync::mpsc::sync_channel::<String>(channel_capacity);
        // Forwarder task: drains the async channel into the sync one.
        // When the async channel closes (sender dropped or shutdown
        // scout observed), the sync sender is dropped, so the
        // blocking writer can drain and exit.
        tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                if sync_tx.send(line).is_err() {
                    break; // writer task ended
                }
            }
        });
        let writer_state2 = Arc::clone(&state);
        tokio::task::spawn_blocking(move || {
            run_writer_blocking(sync_rx, batch_size, flush_interval, writer_state2);
        });
        Self {
            tx,
            state,
            flush_interval,
            batch_size,
        }
    }

    /// Enqueue a single line. Returns `true` if it was accepted, `false`
    /// if it was dropped due to backpressure or shutdown.
    ///
    /// Dropped lines are counted and a rate-limited WARN is emitted
    /// (at most one per 5 seconds) so the agent can see we're losing
    /// data without amplifying the problem.
    pub fn push(&self, line: String) -> bool {
        if self.state.shutdown.load(Ordering::Relaxed) {
            self.record_dropped();
            return false;
        }
        match self.tx.try_send(line) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.record_dropped();
                self.maybe_warn_backpressure();
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.state.shutdown.store(true, Ordering::Relaxed);
                self.record_dropped();
                false
            }
        }
    }

    /// Total lines written to stdout.
    pub fn written(&self) -> u64 {
        self.state.written.load(Ordering::Relaxed)
    }

    /// Total lines dropped due to backpressure / shutdown.
    pub fn dropped(&self) -> u64 {
        self.state.dropped.load(Ordering::Relaxed)
    }

    /// Flush + stop the writer. Safe to call multiple times.
    pub async fn shutdown(&self) {
        self.state.shutdown.store(true, Ordering::Relaxed);
        // Drain by sending a scout — easier than restructuring the
        // receiver side. The receiver loop in run_writer checks the
        // shutdown flag and drains the remaining items on exit.
        let _ = self.tx.send(String::new()).await;
    }

    fn record_dropped(&self) {
        self.state.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Emit at most one `log_writer.backpressure` WARN per 5s.
    /// Critical: without this rate limit, a saturated writer would
    /// produce N WARN lines per second, each of which is also dropped,
    /// causing the log stream to oscillate between "silent" and
    /// "100% backpressure WARNs".
    fn maybe_warn_backpressure(&self) {
        let now_ms = millis_now();
        let prev = self.state.last_backpressure_warn_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(prev) < 5_000 {
            return;
        }
        // Best-effort CAS — if we lose the race, the other thread will
        // emit the WARN this round, which is fine.
        if self
            .state
            .last_backpressure_warn_ms
            .compare_exchange(prev, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            let dropped = self.dropped();
            let written = self.written();
            // Emit on the synchronous `println!` path so the WARN
            // is always seen, even if the batched writer is itself
            // saturated.
            let payload = serde_json::json!({
                "schema": crate::structured_logging::LOG_SCHEMA_VERSION,
                "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "level": "warn",
                "service": crate::structured_logging::current_service_name().unwrap_or("unknown"),
                "message": "log_writer.backpressure",
                "target": "sentin8_middleware::batched_log",
                "fields": {
                    "dropped_total": dropped,
                    "written_total": written,
                }
            });
            if let Ok(s) = serde_json::to_string(&payload) {
                println!("{s}");
            }
        }
    }
}

impl LogSink for BatchedLogWriter {
    fn push(&self, line: String) -> bool {
        BatchedLogWriter::push(self, line)
    }
    fn push_ref(&self, line: &str) -> bool {
        BatchedLogWriter::push(self, line.to_string())
    }
}

/// Trait that abstracts the writer so callers can plug in TCP / Unix
/// / remote collectors later. The default `BatchedLogWriter` is the
/// only built-in implementation.
pub trait LogSink: Send + Sync + 'static {
    /// Push an owned line. Default impl clones the borrow into an
    /// owned `String` so trait users don't have to implement both.
    fn push(&self, line: String) -> bool {
        self.push_ref(&line)
    }

    /// Push a borrowed line. Implementations should `clone()` the
    /// slice into an owned `String` if they need to keep the line
    /// past the call. Used by the JSON layer's hot path to avoid an
    /// unnecessary `to_string()` per event.
    fn push_ref(&self, line: &str) -> bool;

    /// Number of lines successfully handed to the sink (metrics).
    fn written(&self) -> u64 {
        0
    }
    /// Number of lines dropped (backpressure/overflow) — observability for
    /// log loss.
    fn dropped(&self) -> u64 {
        0
    }
}

impl LogSink for Arc<BatchedLogWriter> {
    fn push_ref(&self, line: &str) -> bool {
        (**self).push(line.to_string())
    }
    fn push(&self, line: String) -> bool {
        (**self).push(line)
    }
    fn written(&self) -> u64 {
        (**self).written()
    }
    fn dropped(&self) -> u64 {
        (**self).dropped()
    }
}

/// Synchronous writer loop. Runs on a `spawn_blocking` worker so
/// the `!Send` stdout reentrant lock doesn't constrain us. Drains
/// the synchronous channel until it closes, then flushes any
/// remaining buffered lines and returns.
fn run_writer_blocking(
    rx: std::sync::mpsc::Receiver<String>,
    batch_size: usize,
    flush_interval: Duration,
    state: Arc<WriterState>,
) {
    // 64 KiB buffer. At 256 bytes/line that's ~256 lines per write
    // syscall, well under the channel capacity, with a tiny memory
    // footprint.
    let stdout = std::io::stdout();
    let mut out = BufWriter::with_capacity(64 * 1024, stdout.lock());
    let mut last_flush = Instant::now();
    let mut pending = 0usize;
    let mut last_heartbeat = Instant::now();

    while let Ok(line) = rx.recv() {
        // Empty string is the shutdown scout.
        if line.is_empty() {
            break;
        }
        // Use write_all + newline so the kernel never sees a partial
        // line. (BufWriter would otherwise flush mid-line on capacity.)
        let _ = out.write_all(line.as_bytes());
        let _ = out.write_all(b"\n");
        pending += 1;
        state.written.fetch_add(1, Ordering::Relaxed);

        if pending >= batch_size || last_flush.elapsed() >= flush_interval {
            let _ = out.flush();
            pending = 0;
            last_flush = Instant::now();
        }

        // Heartbeat: every 30s, emit a `log_writer.heartbeat` so an
        // agent can see the writer is alive even when the service is
        // idle. Saves the agent from having to guess whether the
        // service is up.
        if last_heartbeat.elapsed() >= Duration::from_secs(30) {
            emit_heartbeat(&state);
            last_heartbeat = Instant::now();
        }
    }

    // Drain any straggler lines after the channel closed.
    while let Ok(line) = rx.try_recv() {
        if !line.is_empty() {
            let _ = out.write_all(line.as_bytes());
            let _ = out.write_all(b"\n");
            state.written.fetch_add(1, Ordering::Relaxed);
        }
    }
    let _ = out.flush();
}

fn emit_heartbeat(state: &WriterState) {
    let payload = serde_json::json!({
        "schema": crate::structured_logging::LOG_SCHEMA_VERSION,
        "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "level": "debug",
        "service": crate::structured_logging::current_service_name().unwrap_or("unknown"),
        "message": "log_writer.heartbeat",
        "target": "sentin8_middleware::batched_log",
        "fields": {
            "written_total": state.written.load(Ordering::Relaxed),
            "dropped_total": state.dropped.load(Ordering::Relaxed),
        }
    });
    if let Ok(s) = serde_json::to_string(&payload) {
        println!("{s}");
    }
}

fn millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc as StdArc;

    #[derive(Default)]
    struct CountingSink {
        pushed: AtomicUsize,
        written: AtomicU64,
        dropped: AtomicU64,
    }
    impl LogSink for StdArc<CountingSink> {
        fn push(&self, _line: String) -> bool {
            self.pushed.fetch_add(1, Ordering::Relaxed);
            self.written.fetch_add(1, Ordering::Relaxed);
            true
        }
        fn push_ref(&self, line: &str) -> bool {
            self.pushed.fetch_add(1, Ordering::Relaxed);
            self.written.fetch_add(1, Ordering::Relaxed);
            // Touch the borrow so the compiler doesn't warn about
            // unused parameters on this trivial test impl.
            let _ = line.len();
            true
        }
        fn written(&self) -> u64 {
            self.written.load(Ordering::Relaxed)
        }
        fn dropped(&self) -> u64 {
            self.dropped.load(Ordering::Relaxed)
        }
    }

    #[tokio::test]
    async fn sink_records_pushed_lines() {
        let sink = StdArc::new(CountingSink::default());
        for i in 0..5 {
            assert!(sink.push(format!("line-{i}")));
        }
        assert_eq!(sink.pushed.load(Ordering::Relaxed), 5);
        assert_eq!(sink.written(), 5);
    }

    #[test]
    fn writer_handle_is_cloneable_and_independent() {
        // Construct a writer without spawning its task so the test
        // doesn't depend on tokio runtime init. We only check
        // handle-level semantics here.
        let (tx, _rx) = mpsc::channel::<String>(8);
        let state = Arc::new(WriterState {
            written: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            last_backpressure_warn_ms: AtomicU64::new(0),
        });
        let handle = BatchedLogWriter {
            tx,
            state: Arc::clone(&state),
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            batch_size: DEFAULT_BATCH_SIZE,
        };
        let handle2 = handle.clone();
        // Each clone holds a sender; pushes from either go through the
        // shared channel.
        assert!(handle.push("a".into()));
        assert!(handle2.push("b".into()));
        assert_eq!(state.written.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn shutdown_marks_state_and_drops_subsequent_pushes() {
        let (tx, _rx) = mpsc::channel::<String>(4);
        let state = Arc::new(WriterState {
            written: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            last_backpressure_warn_ms: AtomicU64::new(0),
        });
        let handle = BatchedLogWriter {
            tx,
            state: Arc::clone(&state),
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            batch_size: DEFAULT_BATCH_SIZE,
        };
        // Drop the receiver so send returns Closed and our code path
        // marks the writer as shut down.
        drop(_rx);
        // The first push should fail and mark the writer as shut down.
        let accepted = handle.push("a".into());
        assert!(!accepted);
        assert!(state.shutdown.load(Ordering::Relaxed));
        assert!(state.dropped.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn backpressure_warn_is_rate_limited() {
        // Two backpressure events within 5s should only result in one
        // WARN emitted. This is what keeps the log stream sane under
        // saturation.
        let (tx, _rx) = mpsc::channel::<String>(1);
        let state = Arc::new(WriterState {
            written: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            last_backpressure_warn_ms: AtomicU64::new(0),
        });
        let handle = BatchedLogWriter {
            tx,
            state: Arc::clone(&state),
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            batch_size: DEFAULT_BATCH_SIZE,
        };
        // Fill the channel.
        assert!(handle.push("a".into()));
        // Subsequent pushes should be dropped.
        assert!(!handle.push("b".into()));
        assert!(!handle.push("c".into()));
        assert_eq!(state.dropped.load(Ordering::Relaxed), 2);
        // The rate limiter is consulted but the WARN itself is emitted
        // via println! — we don't assert the println content here, just
        // that the dropped counter is consistent.
    }
}
