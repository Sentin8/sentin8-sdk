// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-outbox
//!
//! DBX producer path: local outbox + Bus produce API.
//!
//! Every service that publishes domain events owns a **local outbox table**
//! (`{service}.outbox`, in its own database/schema). The producer writes an
//! outbox row **in the same DB transaction as the domain change**
//! (outbox-first — the row commits atomically with the domain rows). A
//! post-commit relay task ([`spawn_relay`]) drains unrelayed rows and pushes
//! each one to Bus's `POST /v1/produce` (M2M token, scope
//! `sentin8:bus:produce`), marking the row relayed on success.
//!
//! Producers hold NO grants on `bus.inbox` — that table is Bus's own
//! internal durability. Delivery is at-least-once: a Bus outage leaves rows
//! unrelayed in the local outbox and the relay retries with backoff;
//! consumers dedupe on `idempotency_key` (the outbox row id).
//!
//! The per-service SQL for the outbox table + NOTIFY trigger ships in
//! [`outbox_table_sql`]; each service's init.sql applies it (schema-qualified
//! by the service at bind time).

#![deny(missing_docs)]

use sqlx::{Executor, Row};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
/// Failure surface for outbox operations and relaying.
pub enum OutboxError {
    /// A database operation failed.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// The stream family failed validation before storage.
    #[error("invalid stream_family: {0}")]
    InvalidStreamFamily(String),
    /// The Bus produce API rejected the row. The payload is the typed
    /// client error — a [`sentin8_bus_client::BusError::Permanent`] 4xx is
    /// a terminal rejection (parked, never retried) while every other form
    /// stays retryable (outbox relay design).
    #[error("bus produce failed: {0}")]
    Produce(#[from] sentin8_bus_client::BusError),
}

/// Validate a `stream_family` string before it is stored/interpolated into a
/// Valkey key. Rules: `^[a-zA-Z0-9._-]+$`, 1-64 chars, no reserved prefixes.
pub fn validate_stream_family(family: &str) -> Result<(), OutboxError> {
    if family.is_empty() || family.len() > 64 {
        return Err(OutboxError::InvalidStreamFamily(
            "length must be 1-64 characters".into(),
        ));
    }
    if family == "dlq" || family == "delayed" || family == "jti" {
        return Err(OutboxError::InvalidStreamFamily(format!(
            "'{family}' is a reserved prefix"
        )));
    }
    for ch in family.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '.' && ch != '_' && ch != '-' {
            return Err(OutboxError::InvalidStreamFamily(format!(
                "invalid character '{ch}'"
            )));
        }
    }
    Ok(())
}

/// The `{service}.outbox` DDL + NOTIFY trigger, parameterized by schema.
///
/// Applied by each service's init.sql with its own schema. `relayed` is
/// `false` until the produce API accepts the row (idempotency_key = row id).
/// `relay_attempts` counts produce failures — the relay stops retrying at
/// [`RELAY_MAX_ATTEMPTS`] (the row stays unrelayed for manual replay;
/// architecture-principles §6.7: exhausted retries must never hot-loop).
pub fn outbox_table_sql(schema: &str) -> String {
    format!(
        r#"
CREATE SCHEMA IF NOT EXISTS {schema};
CREATE TABLE IF NOT EXISTS {schema}.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_outbox_unrelayed
    ON {schema}.outbox (created_at) WHERE relayed = false;
ALTER TABLE {schema}.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE {schema}.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON {schema}.outbox;
CREATE POLICY outbox_select ON {schema}.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON {schema}.outbox;
CREATE POLICY outbox_insert ON {schema}.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON {schema}.outbox;
CREATE POLICY outbox_update ON {schema}.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION {schema}.{schema}_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('{schema}_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON {schema}.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON {schema}.outbox
    FOR EACH ROW
    EXECUTE FUNCTION {schema}.{schema}_notify_outbox();
"#
    )
}

/// Insert an event into the service's local outbox within an existing DB
/// transaction. Call this from the same connection that wrote the domain
/// row, so the outbox entry commits atomically with the domain change
/// (outbox-first). The relayed state starts `false`; [`spawn_relay`] pushes
/// it to Bus post-commit.
pub async fn insert_outbox_row<'e, E>(
    executor: E,
    env_id: Uuid,
    stream_family: &str,
    event_type: &str,
    payload: &serde_json::Value,
) -> Result<Uuid, OutboxError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    insert_outbox_row_with_publisher(
        executor,
        env_id,
        stream_family,
        event_type,
        payload,
        None,
        None,
    )
    .await
}

/// Insert an outbox row with publisher identity: the bearer JWT that
/// authenticated the request which triggered the domain change, plus its
/// `sub` claim. For scheduled/background operations the service's own M2M
/// token IS the publisher token. Both are carried forward by the relay to
/// the produce API call.
pub async fn insert_outbox_row_with_publisher<'e, E>(
    executor: E,
    env_id: Uuid,
    stream_family: &str,
    event_type: &str,
    payload: &serde_json::Value,
    publisher_id_token: Option<&str>,
    publisher_subject: Option<&str>,
) -> Result<Uuid, OutboxError>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    validate_stream_family(stream_family)?;
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO outbox (id, env_id, event_type, stream_family, payload, publisher_id_token, publisher_subject)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(id)
    .bind(env_id)
    .bind(event_type)
    .bind(stream_family)
    .bind(payload)
    .bind(publisher_id_token)
    .bind(publisher_subject)
    .execute(executor)
    .await?;
    Ok(id)
}

/// Convenience: insert an outbox row using a `&PgPool`.
///
/// Opens its own EXPLICIT transaction and sets the RLS tenant context on
/// THAT transaction before the INSERT. The helpers are
/// transaction-local (`set_config(..., true)`) — a context set on a bare
/// autocommit connection evaporates at the statement's implicit commit
/// and the INSERT lands with `context_initialized=false`, so FORCE-RLS
/// rejects it (every row silently warn-dropped). The pool variant cannot
/// share the caller's transaction — prefer [`insert_outbox_row`] on the
/// domain transaction.
pub async fn insert_outbox_row_pool(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    stream_family: &str,
    event_type: &str,
    payload: &serde_json::Value,
) -> Result<Uuid, OutboxError> {
    validate_stream_family(stream_family)?;
    let mut conn = pool.begin().await?;
    sqlx::query(
        "SELECT sentin8_set_tenant_context($1, NULL, NULL, NULL, false, false, false, NULL, $2)",
    )
    .bind(env_id)
    .bind(stream_family)
    .execute(&mut *conn)
    .await?;
    let id = insert_outbox_row(&mut *conn, env_id, stream_family, event_type, payload).await?;
    conn.commit().await?;
    Ok(id)
}

/// One outbox row as read by the relay.
#[derive(Debug)]
pub struct OutboxRow {
    /// Row id — also the produce idempotency key.
    pub id: Uuid,
    /// Tenant environment of the event.
    pub env_id: Uuid,
    /// Platform event name.
    pub event_type: String,
    /// Target stream family.
    pub stream_family: String,
    /// The domain payload.
    pub payload: serde_json::Value,
    /// Publisher identity token captured at insert time.
    pub publisher_id_token: Option<String>,
    /// Publisher subject captured at insert time.
    pub publisher_subject: Option<String>,
}

/// Drain up to `batch` unrelayed outbox rows (oldest first) that have not
/// exhausted their retry budget and are not in retryable backoff
/// (`next_retry_at` in the future — set by a 429/5xx/transport failure).
async fn drain_rows(pool: &sqlx::PgPool, batch: i64) -> Result<Vec<OutboxRow>, sqlx::Error> {
    // RLS: `outbox` is FORCE-RLS'd on (context_initialized, env_id) — the
    // relay task has NO tenant context of its own, so a bare-pool SELECT
    // silently returns 0 rows and the relay drains NOTHING while rows
    // accumulate (incident 2026-09-23: every service's unrelayed outbox grew
    // unbounded; sys's identity:updated invalidation events never reached
    // Bus). The relay is the OWNER of this table (its own schema): read it
    // inside a transaction whose context covers ALL of its envs. There is
    // no single env_id to set — rows span every tenant the service touched
    // — so the drain runs per-env: collect distinct envs first (bypass via
    // owner-role table read is not available under FORCE RLS), then drain
    // each env under its own context transaction.
    //
    // Simpler + correct: set context for each env present in the queue. The
    // env list itself is derived from the rows we can see, so the first
    // pass runs with context on SYSTEM_ENV_ID (the outbox rows for platform
    // families live there) — but tenant-family rows would be invisible.
    //
    // Target state: the relay drains env-by-env using `sentin8_outbox_envs()`
    // (SECURITY DEFINER, owner-side helper returning DISTINCT env_id of
    // unrelayed rows) — installed by the shared outbox init (see below).
    let envs: Vec<Uuid> =
        sqlx::query_scalar("SELECT DISTINCT env_id FROM sentin8_outbox_unrelayed_envs()")
            .fetch_all(pool)
            .await?;
    let mut rows = Vec::new();
    for env_id in envs {
        let mut tx = pool.begin().await?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        let mut batch_rows = sqlx::query(
            r#"SELECT id, env_id, event_type, stream_family, payload,
                      publisher_id_token, publisher_subject
                 FROM outbox
                WHERE relayed = false AND relay_attempts < $2
                  AND (next_retry_at IS NULL OR next_retry_at <= now())
                ORDER BY created_at
                LIMIT $1"#,
        )
        .bind(batch)
        .bind(RELAY_MAX_ATTEMPTS)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.append(&mut batch_rows);
        if rows.len() >= batch as usize {
            break;
        }
    }
    Ok(rows
        .into_iter()
        .map(|r| OutboxRow {
            id: r.get("id"),
            env_id: r.get("env_id"),
            event_type: r.get("event_type"),
            stream_family: r.get("stream_family"),
            payload: r.get("payload"),
            publisher_id_token: r.get("publisher_id_token"),
            publisher_subject: r.get("publisher_subject"),
        })
        .collect())
}

/// Retry budget per outbox row (relay design): a row that failed produce
/// this many times is no longer drained — it stays `relayed = false` with
/// its attempts count as the DLQ marker for manual replay/inspection.
/// At-least-once delivery means a transient outage always drains long
/// before the cap; only a PERMANENT rejection (4xx, e.g. a cross-env
/// contract violation) reaches it.
pub const RELAY_MAX_ATTEMPTS: i32 = 10;

/// Mark a row relayed (produce API accepted it).
async fn mark_relayed(pool: &sqlx::PgPool, id: Uuid, env_id: Uuid) -> Result<(), sqlx::Error> {
    // RLS: same-connection context in an explicit transaction (§4.3d) — a
    // bare-pool UPDATE fails the FORCE-RLS policy (context_initialized
    // false) exactly like drain_rows' SELECT.
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    sqlx::query(
        "UPDATE outbox SET relayed = true, relayed_at = now() WHERE id = $1 AND env_id = $2",
    )
    .bind(id)
    .bind(env_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Record one failed produce attempt for a row (retry budget / DLQ marker)
/// and schedule its next attempt. `retry_after` honors Bus's explicit
/// backoff signal (the 429 body carries `retry-after: 60` — the token-bucket
/// window); `None` takes the relay's short tick. Without this, a burst
/// backlog larger than Bus's per-minute rate limit burns the whole
/// 10-attempt budget against 429s in ~50s and self-parks (the D4 defect
/// class — rate limiting is exactly what the budget exists to absorb).
/// Same-connection tenant-context discipline as [`mark_relayed`].
async fn mark_attempt(
    pool: &sqlx::PgPool,
    id: Uuid,
    env_id: Uuid,
    retry_after: Option<u64>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    sqlx::query(
        "UPDATE outbox SET relay_attempts = relay_attempts + 1, \
         next_retry_at = now() + make_interval(secs => $3) WHERE id = $1 AND env_id = $2",
    )
    .bind(id)
    .bind(env_id)
    .bind(retry_after.unwrap_or(2) as f64)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Extract Bus's explicit backoff hint from a retryable error: the 429
/// body reads `rate limit exceeded for stream family; retry-after: 60`.
/// Falls back to `None` (the short tick) for every other failure form.
fn retry_after_hint(error_text: &str) -> Option<u64> {
    error_text.find("retry-after: ").and_then(|i| {
        error_text[i + "retry-after: ".len()..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u64>()
            .ok()
    })
}

/// Mark a row TERMINALLY rejected (outbox relay design): a permanent 4xx
/// from Bus can never succeed on retry (the rejection is a property of the
/// request — e.g. an env that no longer exists), so the row is pinned at
/// the retry cap — the drain predicate (`relay_attempts < cap`) stops
/// re-reading it — and stays `relayed = false` for manual
/// inspection/replay. One warn line carries the rejection body.
async fn mark_terminal(
    pool: &sqlx::PgPool,
    id: Uuid,
    env_id: Uuid,
    status: u16,
    body: &str,
) -> Result<(), sqlx::Error> {
    tracing::warn!(
        id = %id,
        status,
        body = %body,
        "outbox relay: produce REJECTED permanently — row parked (no retry)"
    );
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    sqlx::query("UPDATE outbox SET relay_attempts = $3 WHERE id = $1 AND env_id = $2")
        .bind(id)
        .bind(env_id)
        .bind(RELAY_MAX_ATTEMPTS)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// True when the produce failure is PERMANENT (a 4xx rejection) — the row
/// must be parked, never retried. [`sentin8_bus_client::BusError::Permanent`]
/// carries the status + body; every other error form stays retryable.
fn is_permanent(e: &OutboxError) -> Option<(u16, String)> {
    match e {
        OutboxError::Produce(sentin8_bus_client::BusError::Permanent { status, body }) => {
            Some((*status, body.clone()))
        }
        _ => None,
    }
}

/// Spawn the post-commit outbox relay for THIS service.
///
/// Loop: LISTEN/NOTIFY on `{schema}_outbox_changed` for millisecond wakeups
/// with a 5s safety-poll fallback (NOTIFY is not durable), drain unrelayed
/// rows in batches, push each to Bus `POST /v1/produce` via the provided
/// [`BusClient`] (M2M, scope `sentin8:bus:produce`), mark relayed on 2xx.
/// On failure the row stays unrelayed and is retried on the next tick.
///
/// `notify_channel` is the channel name from [`outbox_table_sql`] for this
/// service's schema (`{schema}_outbox_changed`).
pub fn spawn_relay(
    pool: sqlx::PgPool,
    bus: std::sync::Arc<sentin8_bus_client::BusClient>,
    notify_channel: String,
) {
    tokio::spawn(async move {
        let mut listener = match sqlx::postgres::PgListener::connect_with(&pool).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "outbox relay: LISTEN connect failed — poll-only mode");
                sqlx::postgres::PgListener::connect_with(&pool)
                    .await
                    .expect("outbox relay: could not connect listener")
            }
        };
        if let Err(e) = listener.listen(&notify_channel).await {
            tracing::warn!(error = %e, channel = %notify_channel, "outbox relay: LISTEN failed — poll-only mode");
        }
        tracing::info!(channel = %notify_channel, "outbox relay started (local outbox + produce API)");
        loop {
            // Wait for a notification or the 5s safety tick — then drain
            // IMMEDIATELY on either wakeup (bus DESIGN §4.3). A notification
            // resolves `recv()` in milliseconds; the previous structure
            // (`while let Ok(Ok(_))` until a timeout expiry) consumed the
            // notification and then re-blocked on `recv()` until the NEXT
            // 5s timeout ELAPSED, deferring every notification-driven drain
            // to a safety tick anyway (relayed_at − created_at clustered at
            // 5s/2×5s). NOTIFY is not durable, so the 5s tick stays as the
            // fallback; the notification path must be the PROMPT one.
            let wakeup = tokio::select! {
                recv = listener.recv() => recv.is_ok(), // error → safety poll covers the fallback
                _ = tokio::time::sleep(std::time::Duration::from_millis(5_000)) => false,
            };
            let _ = wakeup;
            // Drain + push until empty. Batches of >1 row go through
            // `produce_batch` (BUS-3, one HTTP call per drained batch,
            // ≤ 100 rows — the drain cap); a single row keeps the plain
            // `produce` path. Per-row failure semantics are identical in
            // both paths: successes are marked relayed, failures record
            // an attempt (retry budget / DLQ marker) and back off.
            loop {
                match drain_rows(&pool, 100).await {
                    Ok(rows) if rows.is_empty() => break,
                    Ok(rows) => {
                        // BUS-3: >1 pending row → one `produce_batch` HTTP
                        // call for the whole drain batch (≤ 100 — the drain
                        // cap); a lone row keeps the plain `produce` path.
                        if rows.len() > 1 {
                            match push_batch_to_bus(&bus, &rows).await {
                                Ok(outcomes) => {
                                    for (row, outcome) in rows.into_iter().zip(outcomes) {
                                        match outcome {
                                            Some(e) => {
                                                // Per-row failure inside a
                                                // successful batch: record the
                                                // attempt (retry budget / DLQ
                                                // marker) — siblings stay
                                                // relayed, no hot-loop backoff
                                                // is needed (the batch already
                                                // returned; the next pass
                                                // re-drains the failed row
                                                // once its backoff elapses).
                                                if let Err(ue) = mark_attempt(
                                                    &pool,
                                                    row.id,
                                                    row.env_id,
                                                    retry_after_hint(&e.to_string()),
                                                )
                                                .await
                                                {
                                                    tracing::error!(error = %ue, id = %row.id, "outbox relay: mark_attempt failed");
                                                }
                                                tracing::warn!(error = %e, id = %row.id, event_type = %row.event_type, "outbox relay: batch produce row failed — will retry");
                                            }
                                            None => {
                                                if let Err(e) =
                                                    mark_relayed(&pool, row.id, row.env_id).await
                                                {
                                                    tracing::error!(error = %e, id = %row.id, "outbox relay: mark_relayed failed (row will re-push)");
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    // The whole batch call failed at the
                                    // transport level: every row records an
                                    // attempt and the relay backs off one tick
                                    // (same discipline as the single path) —
                                    // EXCEPT a permanent 4xx, which parks
                                    // EVERY row (a transport-level 4xx — e.g.
                                    // the gate rejecting the batch body —
                                    // applies to all rows in it).
                                    if let Some((status, body)) = is_permanent(&e) {
                                        for row in &rows {
                                            if let Err(ue) = mark_terminal(
                                                &pool, row.id, row.env_id, status, &body,
                                            )
                                            .await
                                            {
                                                tracing::error!(error = %ue, id = %row.id, "outbox relay: mark_terminal failed");
                                            }
                                        }
                                        continue;
                                    }
                                    tracing::warn!(error = %e, rows = "batch", "outbox relay: batch produce failed — will retry");
                                    let hint = retry_after_hint(&e.to_string());
                                    for row in &rows {
                                        if let Err(ue) =
                                            mark_attempt(&pool, row.id, row.env_id, hint).await
                                        {
                                            tracing::error!(error = %ue, id = %row.id, "outbox relay: mark_attempt failed");
                                        }
                                    }
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                }
                            }
                        } else {
                            for row in rows {
                                match push_to_bus(&bus, &row).await {
                                    Ok(()) => {
                                        if let Err(e) =
                                            mark_relayed(&pool, row.id, row.env_id).await
                                        {
                                            tracing::error!(error = %e, id = %row.id, "outbox relay: mark_relayed failed (row will re-push)");
                                        }
                                    }
                                    Err(e) => {
                                        // A PERMANENT 4xx parks the row
                                        // immediately (never retried — the
                                        // rejection is a property of the
                                        // request, e.g. an env that no longer
                                        // exists); other failures record the
                                        // attempt (retry budget / DLQ marker)
                                        // then back off a tick. The drain
                                        // predicate stops re-reading a row
                                        // once it exhausts the cap (principles
                                        // §6.7: exhausted retries land in the
                                        // DLQ, never silently dropped, never
                                        // hot-looped).
                                        if let Some((status, body)) = is_permanent(&e) {
                                            if let Err(ue) = mark_terminal(
                                                &pool, row.id, row.env_id, status, &body,
                                            )
                                            .await
                                            {
                                                tracing::error!(error = %ue, id = %row.id, "outbox relay: mark_terminal failed");
                                            }
                                            continue;
                                        }
                                        if let Err(ue) = mark_attempt(
                                            &pool,
                                            row.id,
                                            row.env_id,
                                            retry_after_hint(&e.to_string()),
                                        )
                                        .await
                                        {
                                            tracing::error!(error = %ue, id = %row.id, "outbox relay: mark_attempt failed");
                                        }
                                        tracing::warn!(error = %e, id = %row.id, event_type = %row.event_type, "outbox relay: produce failed — will retry");
                                        // Back off a tick before the next pass so a
                                        // Bus outage does not hot-loop.
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "outbox relay: drain failed");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        break;
                    }
                }
            }
        }
    });
}

/// Push one outbox row to the Bus produce API.
async fn push_to_bus(
    bus: &sentin8_bus_client::BusClient,
    row: &OutboxRow,
) -> Result<(), OutboxError> {
    use sentin8_bus_contracts::ProduceRequest;
    let req = ProduceRequest {
        stream_family: row.stream_family.clone(),
        event_type: row.event_type.clone(),
        payload: row.payload.clone(),
        env_id: Some(row.env_id),
        idempotency_key: Some(row.id.to_string()),
        publisher_id_token: row.publisher_id_token.clone(),
        publisher_subject: row.publisher_subject.clone(),
        ..Default::default()
    };
    // BUSRELAY-1: one connection-level retry on the single-row path too
    // (same contract as `push_batch_to_bus` — idempotency_key dedupes a
    // re-send; HTTP-status errors pass through unchanged).
    match bus.produce(&req).await {
        Ok(_) => Ok(()),
        Err(e @ sentin8_bus_client::BusError::Http(_)) => {
            tracing::warn!(error = %e, "outbox relay: connection-level produce failure — retrying once with a fresh call");
            bus.produce(&req)
                .await
                .map(|_| ())
                .map_err(OutboxError::from)
        }
        Err(e) => Err(e.into()),
    }
}

/// Push a drained batch (2..=100 rows) to Bus in ONE `produce_batch` call
/// (BUS-3, bus DESIGN §4.3 / README §7 — the relay's transport-level batch).
/// Returns one outcome per input row, IN ORDER: `None` = produced
/// (mark relayed), `Some(error)` = that row was rejected (record the
/// attempt). A transport-level failure of the whole call is returned as
/// the outer `Err` — the caller then records an attempt for every row.
async fn push_batch_to_bus(
    bus: &sentin8_bus_client::BusClient,
    rows: &[OutboxRow],
) -> Result<Vec<Option<String>>, OutboxError> {
    use sentin8_bus_contracts::ProduceRequest;
    let events: Vec<ProduceRequest> = rows
        .iter()
        .map(|row| ProduceRequest {
            stream_family: row.stream_family.clone(),
            event_type: row.event_type.clone(),
            payload: row.payload.clone(),
            env_id: Some(row.env_id),
            idempotency_key: Some(row.id.to_string()),
            publisher_id_token: row.publisher_id_token.clone(),
            publisher_subject: row.publisher_subject.clone(),
            ..Default::default()
        })
        .collect();
    // BUSRELAY-1: a CONNECTION-level failure (never an HTTP status) is
    // retried once with a fresh call. The relay's reqwest transport reuses
    // pooled connections routed through the proxy's L4 pipe — a Bus
    // restart mid-pool kills the piped socket and the next produce rides
    // a half-open connection; reqwest treats POST as non-idempotent and
    // refuses its own retry, surfacing `error sending request` forever
    // (the observed failure: parked rows + late policy events). The
    // retry here is safe by the produce CONTRACT: every event carries
    // `idempotency_key = row id` and Bus dedupes on it, so a re-send
    // after a request that never reached Bus (connection died before the
    // response) is at-worst a duplicate Bus already rejects. A 4xx/5xx
    // HTTP status is NOT retried — `BusError::Permanent`/status-bearing
    // errors pass through unchanged.
    let resp = match bus.produce_batch(&events).await {
        Ok(r) => r,
        Err(e @ sentin8_bus_client::BusError::Http(_)) => {
            tracing::warn!(error = %e, rows = rows.len(), "outbox relay: connection-level produce failure — retrying once with a fresh call");
            bus.produce_batch(&events)
                .await
                .map_err(OutboxError::from)?
        }
        Err(e) => return Err(e.into()),
    };
    // Align response rows with the request order (index is authoritative;
    // a missing row is treated as a failure so the caller re-drains it).
    let mut outcomes: Vec<Option<String>> = vec![None; rows.len()];
    for item in resp.results {
        let idx = item.index;
        if idx >= outcomes.len() {
            continue;
        }
        outcomes[idx] = item.error;
    }
    Ok(outcomes)
}

/// Count unrelayed outbox rows (monitoring).
pub async fn pending_count(pool: &sqlx::PgPool, stream_family: &str) -> Result<i64, OutboxError> {
    let row = sqlx::query(
        r#"SELECT count(*)::int8 AS n FROM outbox WHERE relayed = false AND stream_family = $1"#,
    )
    .bind(stream_family)
    .fetch_one(pool)
    .await?;
    Ok(row.get("n"))
}

// ── Policy change events ─────────────────────────────────────────────────
// Identity-cache invalidation + policy reload events ride the `policy`
// stream family: policy sets (`…:updated`), relation tuples
// (`…:relations:updated`), principal attributes (`…:attrs:updated`). Under
// DBX these are ordinary local-outbox rows on the `policy` family — the
// produce path accepts them because sys/auth's registry entries declare
// `policy` as one of their families.

/// Self-contained envelope for `sentin8:sys:policy:updated` — payload
/// completeness: the consumer reloads from the envelope alone.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyUpdatedEnvelope {
    /// Tenant environment the policy belongs to.
    pub env_id: Uuid,
    /// Colon service_type of the owning service, e.g. `sentin8:post`.
    pub service: String,
    /// Name of the policy set that changed.
    pub policy_set_name: String,
    /// Monotonic policy-set version.
    pub version: i64,
    /// Whether the policy set is enabled.
    pub enabled: bool,
    /// `shadow` | `enforced` policy mode.
    pub mode: String,
}

impl PolicyUpdatedEnvelope {
    /// Serialize the envelope into the event payload value.
    pub fn to_event_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("policy envelope serializes")
    }
}

/// Insert a `sentin8:sys:policy:updated` outbox row in the same DB transaction
/// as the policy-set row write (outbox-first). The relay drains it
/// into the `policy` stream; services consume as direct consumers and reload
/// their `PolicyEngine` cache.
///
/// For relation/attribute changes use [`insert_policy_change_event`] with the
/// matching event type (`sentin8:sys:policy:relations:updated` /
/// `sentin8:sys:policy:attrs:updated`).
pub async fn insert_policy_event<'e, E>(
    executor: E,
    envelope: &PolicyUpdatedEnvelope,
) -> Result<Uuid, OutboxError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    insert_policy_change_event(executor, envelope, "sentin8:sys:policy:updated").await
}

/// Insert one of the three policy change events with an explicit event type.
/// The envelope fields beyond `env_id` are informational for consumers of the
/// relations/attrs events (they identify the owning service + env to reload).
pub async fn insert_policy_change_event<'e, E>(
    executor: E,
    envelope: &PolicyUpdatedEnvelope,
    event_type: &str,
) -> Result<Uuid, OutboxError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    insert_outbox_row(
        executor,
        envelope.env_id,
        "policy",
        event_type,
        &envelope.to_event_value(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_family_validation() {
        assert!(validate_stream_family("ledger").is_ok());
        assert!(validate_stream_family("sys").is_ok());
        assert!(validate_stream_family("a-b.c_d").is_ok());
        assert!(validate_stream_family("").is_err());
        assert!(validate_stream_family("dlq").is_err());
        assert!(validate_stream_family("has space").is_err());
        assert!(validate_stream_family(&"x".repeat(65)).is_err());
    }

    #[test]
    fn outbox_table_sql_includes_schema() {
        let sql = outbox_table_sql("ledger");
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS ledger.outbox"));
        assert!(sql.contains("pg_notify('ledger_outbox_changed'"));
    }
}
