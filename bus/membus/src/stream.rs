// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Durable-class consumer - `XREADGROUP … BLOCK` on a **dedicated**
//! connection, with the library-owned `XAUTOCLAIM` crash-recovery sweep
//! and coalesced `XACK`.
//!
//! The connection invariant is structural: this struct OWNS its connection
//! (opened by `EnvBus::subscribe_stream`), so the blocking read can
//! never occupy the shared multiplexed command connection. A consumer
//! that dies releases its connection; a consumer that blocks cannot
//! stall anyone else's XADD/ACK/PUBLISH.

use std::sync::Arc;
use std::time::{Duration, Instant};

use glide::GlideClient;

use crate::envelope::Envelope;
use crate::error::MemBusError;
use crate::hooks::MetricsHooks;

/// Raw XREADGROUP reply: `(stream_key, [(entry_id, [(field, bytes)])])`.
type RawStreamEntries = Vec<(String, Vec<(String, Vec<(String, Vec<u8>)>)>)>;
/// Raw XAUTOCLAIM reply: `(next_cursor, [(entry_id, fields)], deleted_ids)`.
type RawAutoclaim = (String, Vec<(String, Vec<(String, Vec<u8>)>)>, Vec<String>);

/// Consumer tuning knobs.
#[derive(Debug, Clone)]
pub struct StreamOpts {
    /// `XREADGROUP COUNT` - max entries per read.
    pub count: u64,
    /// `XREADGROUP BLOCK` in ms; `0` = non-blocking drain for
    /// spin-style consumers. Default 50ms (snappier than the
    /// control-plane bus's 10s - the fast path wants quick shutdown and
    /// tight claim sweeps).
    pub block_ms: u64,
}

impl Default for StreamOpts {
    fn default() -> Self {
        Self {
            count: 50,
            block_ms: 50,
        }
    }
}

/// One delivered stream entry: the Valkey id plus the decoded envelope.
#[derive(Debug, Clone)]
pub struct StreamMessage {
    /// The Valkey stream entry id (`{ms}-{seq}`).
    pub id: String,
    /// The decoded envelope.
    pub envelope: Envelope,
}

/// A durable-class consumer bound to one stream, group, and its own GLIDE
/// client (the blocking read never stalls the shared command client;
/// glide-core heals this connection independently).
pub struct StreamSubscriber {
    pub(crate) conn: GlideClient,
    pub(crate) key: String,
    pub(crate) group: String,
    pub(crate) consumer: String,
    pub(crate) opts: StreamOpts,
    pub(crate) metrics: Arc<dyn MetricsHooks>,
    /// Ids delivered but not yet acked - flushed (coalesced) with the
    /// next `next_batch()` call or by `ack_now()`.
    pub(crate) unacked: Vec<String>,
    pub(crate) last_autoclaim: Instant,
    pub(crate) autoclaim_interval_ms: u64,
    pub(crate) autoclaim_min_idle_ms: u64,
    pub(crate) autoclaim_count: u64,
}

impl StreamSubscriber {
    /// The stream key this consumer reads (`mbus:{env}:{family}`).
    pub fn stream_key(&self) -> &str {
        &self.key
    }

    /// The consumer group.
    pub fn group(&self) -> &str {
        &self.group
    }

    /// Await the next batch. Each call:
    ///
    /// 1. Flushes any pending coalesced `XACK` **before** the blocking
    ///    read (ack latency never rides on the next message).
    /// 2. Every ~5s, runs one `XAUTOCLAIM` pass (min-idle 60s, COUNT 20)
    ///    so entries abandoned by a crashed sibling of the same group
    ///    are re-delivered.
    /// 3. Issues `XREADGROUP GROUP {g} {consumer} COUNT {n} BLOCK {ms}
    ///    STREAMS {key} >`.
    ///
    /// Returns `Ok(None)` on a clean end (connection closed). At
    /// least-once: unacked entries survive in the PEL and are
    /// re-claimed later; consumers dedupe on `sq`.
    pub async fn next_batch(&mut self) -> Result<Option<Vec<StreamMessage>>, MemBusError> {
        self.flush_ack().await?;

        let mut batch = Vec::new();

        // Crash-recovery sweep - abandoned PEL entries from a crashed
        // sibling instance of the same group.
        if self.last_autoclaim.elapsed() >= Duration::from_millis(self.autoclaim_interval_ms) {
            self.last_autoclaim = Instant::now();
            batch.extend(self.autoclaim_pass().await?);
        }

        let conn = self.conn.clone();
        // Byte-typed fields - the `p` payload is opaque binary and must
        // NOT be forced through UTF-8.
        let read: Option<RawStreamEntries> = {
            let mut cmd = glide::Cmd::new();
            cmd.arg("XREADGROUP")
                .arg("GROUP")
                .arg(&self.group)
                .arg(&self.consumer)
                .arg("COUNT")
                .arg(self.opts.count)
                .arg("BLOCK")
                .arg(self.opts.block_ms)
                .arg("STREAMS")
                .arg(&self.key)
                .arg(">");
            cmd.query_async(&conn)
                .await
                .map_err(|e| MemBusError::Valkey(e.to_string()))?
        };

        if let Some(streams) = read {
            for (_stream, entries) in streams {
                for (id, fields) in entries {
                    if let Some(msg) = Self::decode_entry(&id, &fields) {
                        self.unacked.push(id);
                        batch.push(msg);
                    } else {
                        // Undecodable entry: ack and skip - the fast
                        // path has no DLQ by design.
                        self.unacked.push(id);
                    }
                }
            }
        }

        if !batch.is_empty() {
            self.metrics.on_batch(&self.key, &self.group, batch.len());
        }
        // With BLOCK=0 (non-blocking drain) an empty batch is a normal
        // poll result, not a stream end - surface it as Some(vec![]).
        Ok(Some(batch))
    }

    /// Force the coalesced `XACK` flush now (otherwise it rides with
    /// the next `next_batch()`).
    pub async fn ack_now(&mut self) -> Result<(), MemBusError> {
        self.flush_ack().await
    }

    /// The un-acked id count (PEL view, process-local).
    pub fn pending_ack(&self) -> usize {
        self.unacked.len()
    }

    async fn flush_ack(&mut self) -> Result<(), MemBusError> {
        if self.unacked.is_empty() {
            return Ok(());
        }
        let ids: Vec<String> = std::mem::take(&mut self.unacked);
        let mut cmd = glide::Cmd::new();
        cmd.arg("XACK").arg(&self.key).arg(&self.group);
        for id in &ids {
            cmd.arg(id);
        }
        let _: Result<i64, _> = cmd.query_async(&self.conn).await;
        Ok(())
    }

    async fn autoclaim_pass(&mut self) -> Result<Vec<StreamMessage>, MemBusError> {
        let conn = self.conn.clone();
        let claimed: Result<RawAutoclaim, _> = {
            let mut cmd = glide::Cmd::new();
            cmd.arg("XAUTOCLAIM")
                .arg(&self.key)
                .arg(&self.group)
                .arg(&self.consumer)
                .arg(self.autoclaim_min_idle_ms)
                .arg("0-0")
                .arg("COUNT")
                .arg(self.autoclaim_count);
            cmd.query_async(&conn).await
        };
        match claimed {
            Ok((_, entries, _deleted)) => {
                let mut out = Vec::new();
                for (id, fields) in entries {
                    if let Some(msg) = Self::decode_entry(&id, &fields) {
                        self.unacked.push(id);
                        out.push(msg);
                    } else {
                        self.unacked.push(id);
                    }
                }
                Ok(out)
            }
            Err(e) => {
                // The sweep is best-effort - a transient failure must
                // not kill the consume loop; the PEL keeps the entries.
                tracing::debug!(error = %e, key = %self.key, "membus: XAUTOCLAIM sweep skipped");
                Ok(Vec::new())
            }
        }
    }

    fn decode_entry(id: &str, fields: &[(String, Vec<u8>)]) -> Option<StreamMessage> {
        Envelope::from_stream_fields(fields)
            .ok()
            .map(|envelope| StreamMessage {
                id: id.to_string(),
                envelope,
            })
    }
}
