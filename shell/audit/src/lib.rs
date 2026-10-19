// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-audit
//!
//! Audit event envelope and emitter interface for all Sentin8 services.
//!
//! Every state-changing operation in the Sentin8 platform emits an audit
//! event. Events are written to a transactional audit-journal table in the
//! service's DB schema and relayed to the Sys audit ingest API asynchronously
//! (journal-first - same transaction-local pattern as the Bus outbox).
#![deny(missing_docs)]
pub mod security_audit;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sentin8_middleware::http_client::Sentin8HttpClient;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The severity of an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    /// Informational events (default).
    Info,
    /// Unusual but handled condition.
    Warning,
    /// Operation failed.
    Error,
    /// Security-relevant failure requiring attention.
    Critical,
}

/// The action performed. Mirrors common audit verb patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditAction {
    /// Resource created.
    Create,
    /// Resource modified.
    Update,
    /// Resource deleted.
    Delete,
    /// Resource archived (soft delete).
    Archive,
    /// Authentication event.
    Login,
    /// Sign-out event.
    Logout,
    /// Permission/role granted.
    Grant,
    /// Permission/role revoked.
    Revoke,
    /// Function/operation executed.
    Execute,
    /// Anything not covered by the above.
    Other,
}

/// The canonical Sentin8 audit event envelope.
///
/// All fields are required except `details`, `before`, and `after` which are
/// optional context payloads. The `correlation_id` ties the event back to the
/// originating request (propagated via `X-Sentin8-Correlation-Id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID (UUID v4).
    pub id: Uuid,
    /// The service that emitted this event (e.g. "auth", "ledger", "sys").
    pub service: String,
    /// The action performed (e.g. "create", "update", "delete").
    pub action: AuditAction,
    /// The type of resource affected (e.g. "organization", "account", "user").
    pub resource_type: String,
    /// The ID of the affected resource.
    pub resource_id: String,
    /// Who performed the action (Auth subject ID).
    pub actor_id: String,
    /// Actor type (system_user | org_staff | customer | machine | api_client | support_actor).
    pub actor_type: String,
    /// Organization the resource belongs to (resolved from env_id - context only).
    pub org_id: Uuid,
    /// Environment the resource belongs to (System Env ID for platform
    /// operations).
    pub env_id: Uuid,
    /// Application ID (if the action was performed on behalf of an app instance).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<Uuid>,
    /// Event severity.
    pub severity: AuditSeverity,
    /// When the event occurred (UTC).
    pub timestamp: DateTime<Utc>,
    /// Correlation ID from the originating request.
    pub correlation_id: String,
    /// Human-readable description.
    pub message: String,
    /// Structured key/value details (arbitrary JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Before-state snapshot (for updates/deletes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    /// After-state snapshot (for creates/updates).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
}

impl AuditEvent {
    /// Build a new audit event with sensible defaults.
    ///
    /// `id` and `timestamp` are generated; `severity` defaults to `Info`.
    pub fn builder() -> AuditEventBuilder {
        AuditEventBuilder {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            service: String::new(),
            action: AuditAction::Other,
            resource_type: String::new(),
            resource_id: String::new(),
            actor_id: String::new(),
            actor_type: String::new(),
            org_id: Uuid::nil(),
            env_id: Uuid::nil(),
            application_id: None,
            severity: AuditSeverity::Info,
            correlation_id: String::new(),
            message: String::new(),
            details: None,
            before: None,
            after: None,
        }
    }
}

/// Builder for [`AuditEvent`].
#[derive(Debug, Clone)]
pub struct AuditEventBuilder {
    id: Uuid,
    timestamp: DateTime<Utc>,
    service: String,
    action: AuditAction,
    resource_type: String,
    resource_id: String,
    actor_id: String,
    actor_type: String,
    org_id: Uuid,
    env_id: Uuid,
    application_id: Option<Uuid>,
    severity: AuditSeverity,
    correlation_id: String,
    message: String,
    details: Option<serde_json::Value>,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
}

impl AuditEventBuilder {
    /// Set the emitting service identity.
    pub fn service(mut self, service: impl Into<String>) -> Self {
        self.service = service.into();
        self
    }
    /// Set the action performed.
    pub fn action(mut self, action: AuditAction) -> Self {
        self.action = action;
        self
    }
    /// Set the affected resource type and id.
    pub fn resource(
        mut self,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        self.resource_type = resource_type.into();
        self.resource_id = resource_id.into();
        self
    }
    /// Set the acting principal (Auth subject id and actor type).
    pub fn actor(mut self, actor_id: impl Into<String>, actor_type: impl Into<String>) -> Self {
        self.actor_id = actor_id.into();
        self.actor_type = actor_type.into();
        self
    }
    /// Set the tenant scope (org id + env id).
    pub fn tenant(mut self, org_id: Uuid, env_id: Uuid) -> Self {
        self.org_id = org_id;
        self.env_id = env_id;
        self
    }
    /// Set the app instance acting on behalf of the user.
    pub fn application(mut self, app_id: Uuid) -> Self {
        self.application_id = Some(app_id);
        self
    }
    /// Set the event severity.
    pub fn severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = severity;
        self
    }
    /// Set the originating request's correlation id.
    pub fn correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = correlation_id.into();
        self
    }
    /// Set the human-readable description.
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }
    /// Attach structured key/value details.
    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
    /// Attach the before-state snapshot.
    pub fn before(mut self, before: serde_json::Value) -> Self {
        self.before = Some(before);
        self
    }
    /// Attach the after-state snapshot.
    pub fn after(mut self, after: serde_json::Value) -> Self {
        self.after = Some(after);
        self
    }

    /// Build the event.
    pub fn build(self) -> AuditEvent {
        AuditEvent {
            id: self.id,
            service: self.service,
            action: self.action,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            actor_id: self.actor_id,
            actor_type: self.actor_type,
            org_id: self.org_id,
            env_id: self.env_id,
            application_id: self.application_id,
            severity: self.severity,
            timestamp: self.timestamp,
            correlation_id: self.correlation_id,
            message: self.message,
            details: self.details,
            before: self.before,
            after: self.after,
        }
    }
}

// ── Emitter interface ────────────────────────────────────────────────────

/// Trait implemented by audit event sinks.
///
/// The default implementation writes to a DB outbox table; services relay
/// the outbox to Bus asynchronously. Other implementations could write
/// directly to Bus or an external SIEM.
#[async_trait]
pub trait AuditEmitter: Send + Sync {
    /// Emit an audit event. Implementations should not block the request
    /// path - write to the outbox and return.
    async fn emit(&self, event: AuditEvent) -> Result<(), AuditError>;
}

/// Error type for audit emission.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The emission (journal write or Sys push) failed.
    #[error("audit emission failed: {0}")]
    Emit(String),
}

/// A no-op emitter for tests and services that don't need audit (yet).
pub struct NoopAuditEmitter;

#[async_trait]
impl AuditEmitter for NoopAuditEmitter {
    async fn emit(&self, _event: AuditEvent) -> Result<(), AuditError> {
        Ok(())
    }
}

// ── Sys ingest sink ──────────────────────────────────────────────────────
// Canonical audit path: every service pushes to Sys `POST /v1/audit`
// (M2M, `sentin8:sys:audit:write`). The service keeps a local spill journal
// (`{service}.audit_journal`, DDL via `audit_journal_sql`); `journal_insert`
// writes it in the domain transaction and `push_journal_to_sys` drains it to
// Sys in the background. A Sys outage never drops audit - the journal retries.

/// `INSERT INTO audit_journal` - the local spill journal in the service's own
/// schema. Call on the SAME connection/transaction as the domain change where
/// possible.
pub async fn journal_insert<'e, E>(executor: E, ev: &AuditEvent) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        r#"INSERT INTO audit_journal
           (id, env_id, action, target_resource_type, target_resource_id,
            actor_user_id, actor_subject_type, severity, correlation_id,
            before_state, after_state, details)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
    )
    .bind(ev.id)
    .bind(ev.env_id)
    .bind(format!("{:?}", ev.action).to_lowercase())
    .bind(&ev.resource_type)
    .bind(&ev.resource_id)
    .bind(&ev.actor_id)
    .bind(&ev.actor_type)
    .bind(format!("{:?}", ev.severity).to_lowercase())
    .bind(&ev.correlation_id)
    .bind(&ev.before)
    .bind(&ev.after)
    .bind(&ev.details)
    .execute(executor)
    .await
    .map(|_| ())
}

/// The `{service}.audit_journal` DDL (apply in the service's init.sql with its
/// schema name).
pub fn audit_journal_sql(schema: &str) -> String {
    format!(
        r#"
CREATE TABLE IF NOT EXISTS {schema}.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_{schema}_audit_journal_unpushed
    ON {schema}.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE {schema}.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE {schema}.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON {schema}.audit_journal;
CREATE POLICY audit_journal_dml ON {schema}.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
"#
    )
}

/// Push pending journal rows to Sys `POST /v1/audit` (M2M). One-shot helper -
/// call from the service's background task; failures leave rows unpushed for
/// the next pass. Returns the number of rows accepted. The `http` client is
/// supplied by the caller (pooled per-process - see `spawn_journal_pusher`).
pub async fn push_journal_to_sys(
    pool: &sqlx::PgPool,
    sys_url: &str,
    http: &Sentin8HttpClient,
) -> Result<usize, AuditError> {
    use sqlx::Row;
    let rows = sqlx::query(
        r#"SELECT id, env_id, action, target_resource_type, target_resource_id,
                  actor_user_id, actor_subject_type, severity, correlation_id,
                  before_state, after_state, details
             FROM audit_journal WHERE pushed = false ORDER BY created_at LIMIT 200"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| AuditError::Emit(e.to_string()))?;
    if rows.is_empty() {
        return Ok(0);
    }
    let events: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "env_id": r.get::<uuid::Uuid, _>("env_id"),
                "action": r.get::<String, _>("action"),
                "target_resource_type": r.get::<Option<String>, _>("target_resource_type"),
                "target_resource_id": r.get::<Option<String>, _>("target_resource_id"),
                "actor_user_id": r.get::<Option<String>, _>("actor_user_id"),
                "actor_subject_type": r.get::<Option<String>, _>("actor_subject_type"),
                "severity": r.get::<String, _>("severity"),
                "correlation_id": r.get::<Option<String>, _>("correlation_id"),
                "before_state": r.get::<Option<serde_json::Value>, _>("before_state"),
                "after_state": r.get::<Option<serde_json::Value>, _>("after_state"),
                "details": r.get::<Option<serde_json::Value>, _>("details"),
            })
        })
        .collect();
    let body = serde_json::json!({ "events": events });
    let resp = http
        .post(format!("{}/v1/audit", sys_url.trim_end_matches('/')))
        .json(&body)
        .send()
        .await
        .map_err(|e| AuditError::Emit(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(AuditError::Emit(format!(
            "sys audit ingest: {}",
            resp.status()
        )));
    }
    // Mark pushed.
    let ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.get::<uuid::Uuid, _>("id")).collect();
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| AuditError::Emit(e.to_string()))?;
    for id in &ids {
        let _ =
            sqlx::query("UPDATE audit_journal SET pushed = true, pushed_at = now() WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await;
    }
    tx.commit()
        .await
        .map_err(|e| AuditError::Emit(e.to_string()))?;
    Ok(ids.len())
}

/// Spawn the shared audit-journal push loop (architecture-principles §6.8):
/// every `POLL_INTERVAL_SECS`, DCR-register (or load)
/// the service's M2M workload for `sentin8:sys:audit:write`, push pending
/// `{service}.audit_journal` rows to Sys `POST /v1/audit`, mark them pushed
/// on 2xx. A Sys outage only delays the push - rows persist and retry.
/// The `service_name` identifies the workload (e.g. `sentin8:db` →
/// `sentin8:db-audit`); the scope grant must be declared in the service's
/// `M2M_GRANTS` registration and provisioned by `vertical enroll`.
/// Spawned by the shell (boot step 8c) for every shell-booted service -
/// a Sys outage never drops audit. The HTTP client is built ONCE per
/// process (pooled connection to Sys - a per-pass client pays a fresh
/// PQ TLS handshake on every push with pending rows).
pub fn spawn_journal_pusher(
    pool: sqlx::PgPool,
    sys_url: String,
    auth_issuer: String,
    service_type: &str,
) {
    const POLL_INTERVAL_SECS: u64 = 5;
    const RETRY_BACKOFF_SECS: u64 = 2;
    let leaf = service_type.rsplit(':').next().unwrap_or(service_type);
    let workload = format!("{leaf}-audit");
    tokio::spawn(async move {
        // auth DESIGN §4.3f: the certificate is the identity -
        // ensure it once (mint from Acme on a first boot; retries cover an
        // Acme that is still coming up), then build the cert-presenting
        // transport. No token is fetched or attached; Sys's TLS layer
        // authenticates the `{leaf}-audit` workload from the handshake.
        let cert = loop {
            match sentin8_m2m::ensure_workload_certificate(
                &auth_issuer,
                &workload,
                &sentin8_m2m::platform_ca_path(),
            )
            .await
            {
                Ok(c) => break c,
                Err(e) => {
                    tracing::debug!(error = %e, workload = %workload, "audit journal push: certificate not ready yet");
                    tokio::time::sleep(std::time::Duration::from_secs(RETRY_BACKOFF_SECS)).await;
                }
            }
        };
        let mtls = sentin8_middleware::mtls::MtlsConfig::new(
            &cert.ca_cert_path,
            &cert.cert_path,
            &cert.key_path,
        );
        let http = sentin8_middleware::mtls::build_mtls_client(&mtls)
            .map(Sentin8HttpClient::from_client)
            .expect("audit push: mTLS client build failed");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
            match push_journal_to_sys(&pool, &sys_url, &http).await {
                Ok(0) => {}
                Ok(n) => {
                    tracing::debug!(pushed = n, workload = %workload, "audit journal pushed to sys")
                }
                Err(e) => {
                    tracing::warn!(error = %e, workload = %workload, "audit journal push failed - rows stay queued");
                    // Back off briefly so a Sys outage does not spin.
                    tokio::time::sleep(std::time::Duration::from_secs(RETRY_BACKOFF_SECS)).await;
                }
            }
        }
    });
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sentin8_config::{SYSTEM_ENV_ID, SYSTEM_ORG_ID};

    #[test]
    fn builder_produces_complete_event() {
        let event = AuditEvent::builder()
            .service("auth")
            .action(AuditAction::Login)
            .resource("user", "550e8400-...")
            .actor("a@m.n", "system_user")
            .tenant(SYSTEM_ORG_ID, SYSTEM_ENV_ID)
            .severity(AuditSeverity::Info)
            .correlation_id("corr-123")
            .message("user signed in")
            .build();

        assert_eq!(event.service, "auth");
        assert_eq!(event.action, AuditAction::Login);
        assert_eq!(event.resource_type, "user");
        assert_eq!(event.resource_id, "550e8400-...");
        assert_eq!(event.actor_id, "a@m.n");
        assert_eq!(event.actor_type, "system_user");
        assert_eq!(event.org_id, SYSTEM_ORG_ID);
        assert_eq!(event.env_id, SYSTEM_ENV_ID);
        assert_eq!(event.severity, AuditSeverity::Info);
        assert_eq!(event.correlation_id, "corr-123");
        assert_eq!(event.message, "user signed in");
    }

    #[tokio::test]
    async fn noop_emitter_succeeds() {
        let emitter = NoopAuditEmitter;
        let event = AuditEvent::builder()
            .service("test")
            .action(AuditAction::Other)
            .resource("test", "id")
            .actor("test", "machine")
            .tenant(SYSTEM_ORG_ID, SYSTEM_ENV_ID)
            .correlation_id("c")
            .message("m")
            .build();
        emitter.emit(event).await.unwrap();
    }
}
