// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Shared policy-admin API (design/sentin8-shield-technical-design.md ).
//!
//! Every adopting service exposes the SAME uniform surface - policy sets,
//! relation tuples, principal attributes, and the relations dry-run check -
//! implemented once here. A service mounts it by putting a
//! [`SharedAdminState`] in its `AppState` and routing these handlers.
//!
//! All endpoints follow the standard pipeline: token verify →
//! `policy:read`/`policy:write` scope → step-5 policy evaluation →
//! `target_env_id` REQUIRED → RLS context on the
//! SAME connection → inbox-first event on mutation → audit.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use sentin8_auth_client::{AuthContext, Client as AuthClient, ClientOptions};
use sentin8_outbox::PolicyUpdatedEnvelope;

use crate::runtime::evaluate_full;

/// Everything the shared admin handlers need. Cheap to clone (`Arc`s).
#[derive(Clone)]
pub struct SharedAdminState {
    /// Colon service_type this admin surface manages, e.g. `sentin8:post`.
    pub service: String,
    /// RLS-scoped pool of the owning service.
    pub pool: sqlx::PgPool,
    /// The service's policy engine (for the step-5 gate).
    pub policy: Arc<crate::PolicyEngine>,
    /// Auth client for token verification.
    pub auth_client: Arc<AuthClient>,
}

/// Access trait: every service's `AppState` implements this so the shared
/// handlers can extract its admin surface (generic over each service's own
/// state type - no per-service handler copies).
pub trait HasPolicyAdmin {
    fn policy_admin(&self) -> &SharedAdminState;
}

/// Blanket impl for `Arc`-wrapped app states: services whose routers carry
/// `Arc<AppState>` (acme, proxy) can mount the shared admin handlers
/// directly over `Arc<AppState>` without a per-service forwarding newtype.
impl<T: HasPolicyAdmin> HasPolicyAdmin for std::sync::Arc<T> {
    fn policy_admin(&self) -> &SharedAdminState {
        T::policy_admin(self)
    }
}

impl SharedAdminState {
    /// Test constructor: empty engine + lazy auth client. Used by service
    /// test fixtures that exercise domain flows, not the policy surface.
    pub fn test(service: impl Into<String>, pool: sqlx::PgPool) -> Self {
        // Test fixtures bypass the shell boot (which installs the PQ crypto
        // provider) - building an AuthClient constructs a reqwest client,
        // which panics "No provider set" without it. Install Once-guarded.
        {
            use std::sync::Once;
            static ONCE: Once = Once::new();
            ONCE.call_once(|| {
                let _ = sentin8_tls::crypto::sentin8_pq_provider().install_default();
            });
        }
        Self {
            service: service.into(),
            pool,
            policy: Arc::new(crate::PolicyEngine::new("sentin8:test")),
            auth_client: Arc::new(AuthClient::new(ClientOptions::default())),
        }
    }

    /// The per-service policy-admin scope for this surface: `{first-two-segments}:policy:read` or `…:write`
    /// (e.g. service `sentin8:post` → `sentin8:post:policy:read`, service
    /// `bank8:ledger` → `bank8:ledger:policy:write`). Every scope starts
    /// with its vertical - the crate name is NOT a service identity, so a
    /// bare `sentin8:policy:*` literal would violate the uniform naming
    /// rule. Falls back to the whole service string when it has fewer than
    /// two segments (never happens for enrolled identities, which are
    /// `vertical:service[:worker]`).
    pub fn policy_read_scope(&self) -> String {
        format!("{}:policy:read", scope_prefix(&self.service))
    }

    /// Write counterpart of [`Self::policy_read_scope`].
    pub fn policy_write_scope(&self) -> String {
        format!("{}:policy:write", scope_prefix(&self.service))
    }
}

/// Scope namespace for a service identity: the first TWO colon segments
/// plus a trailing colon. `bank8:ledger` →
/// `bank8:ledger:`; `sentin8:post` → `sentin8:post:`.
fn scope_prefix(service: &str) -> String {
    let mut segs = service.split(':');
    match (segs.next(), segs.next()) {
        (Some(v), Some(s)) => format!("{v}:{s}"),
        (Some(v), None) => v.to_string(),
        _ => String::new(),
    }
}

/// Query carrying `target_env_id` (REQUIRED - the caller's RLS context).
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct TargetEnv {
    #[serde(default)]
    pub target_env_id: Option<String>,
}

fn resolve_env(q: &TargetEnv) -> Result<Uuid, (StatusCode, String)> {
    q.target_env_id
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "missing target_env_id - auth is env-scoped".into(),
            )
        })
}

/// Verify the Bearer token via the caller-provided Auth client.
async fn verify(
    s: &SharedAdminState,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    sentin8_auth_client::verify_bearer_token(&s.auth_client, headers).await
}

/// Scope-gate over a verified context (SDK inherent method).
fn scope_gate(a: &AuthContext, scope: &str) -> Result<(), (StatusCode, String)> {
    a.require_any_scope(&[scope])
}

/// The standard admin pipeline prefix: token verify → granular scope →
/// step-5 policy evaluation → target env resolution → RLS context on the
/// same connection.
async fn admin_gate(
    s: &SharedAdminState,
    headers: &HeaderMap,
    q: &TargetEnv,
    scope: &str,
) -> Result<
    (
        AuthContext,
        Uuid,
        sqlx::pool::PoolConnection<sqlx::Postgres>,
    ),
    (StatusCode, String),
> {
    let a = verify(s, headers).await?;
    scope_gate(&a, scope)?;
    evaluate_full(
        &s.policy,
        a.claims.sub.as_str(),
        a.env_id(),
        a.claims.token_tp.as_str(),
        a.claims.scope.as_str(),
        headers,
        scope,
    )
    .await?;
    let env_id = resolve_env(q)?;
    let mut conn = s
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_ctx(&mut conn, env_id, &a).await?;
    Ok((a, env_id, conn))
}

/// Read gate for this service's policy-admin surface - the scope is derived
/// from the service identity, not a crate-name literal.
fn read_scope(s: &SharedAdminState) -> String {
    s.policy_read_scope()
}

/// Write gate counterpart of [`read_scope`].
fn write_scope(s: &SharedAdminState) -> String {
    s.policy_write_scope()
}

async fn set_ctx(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    a: &AuthContext,
) -> Result<(), (StatusCode, String)> {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, $2, $3, $4, false, false, $5)")
        .bind(env_id)
        .bind(a.claims.sub.clone())
        .bind(a.claims.token_tp.clone())
        .bind(a.claims.scope.clone())
        .bind(a.claims.is_env_admin())
        .execute(conn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn emit_event(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    // The envelope record's natural arity - allow keeps the single
    // flat call shape instead of threading a params struct through.
    #[allow(clippy::too_many_arguments)] service: &str,
    name: &str,
    version: i64,
    enabled: bool,
    mode: &str,
    event_type: &str,
) -> Result<(), String> {
    let envelope = PolicyUpdatedEnvelope {
        env_id,
        service: service.to_string(),
        policy_set_name: name.to_string(),
        version,
        enabled,
        mode: mode.to_string(),
    };
    sentin8_outbox::insert_policy_change_event(pool, &envelope, event_type)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

async fn audit(pool: &sqlx::PgPool, env_id: Uuid, service: &str, event: serde_json::Value) {
    let short = service.rsplit(':').next().unwrap_or(service);
    let _ = sqlx::query(
        r#"INSERT INTO audit_journal (id, env_id, action, details) VALUES ($1, $2, $3, $4)"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(env_id)
    .bind(short)
    .bind(event)
    .execute(pool)
    .await;
}

// ── Policy-set endpoints ─────────────────────────────────────────

/// `GET /v1/admin/policy-sets` - list this service's policy sets.
pub async fn list_policy_sets<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Query(q): Query<TargetEnv>,
) -> Result<Json<Vec<PolicySetRow>>, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    let (_a, env_id, mut conn) = admin_gate(s, &headers, &q, &read_scope(s)).await?;
    let rows = sqlx::query(
        r#"SELECT policy_set_name, description, origin, mode, version, enabled,
         updated_at, length(policies)::bigint AS policies_len
       FROM policy_sets
      WHERE service = $1 AND env_id = $2
      ORDER BY policy_set_name"#,
    )
    .bind(&s.service)
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let sets: Vec<PolicySetRow> = rows
        .iter()
        .map(|r| PolicySetRow {
            // id = the set name - the RFW row actions substitute {id}
            // from this field; without it every Delete/Enforce
            // click POSTed `policy-sets//delete` (empty id → 404).
            id: r.get::<String, _>("policy_set_name"),
            policy_set_name: r.get::<String, _>("policy_set_name"),
            description: r.get::<String, _>("description"),
            origin: r.get::<String, _>("origin"),
            mode: r.get::<String, _>("mode"),
            version: r.get::<i32, _>("version"),
            enabled: r.get::<bool, _>("enabled"),
            policies_len: r.get::<i64, _>("policies_len"),
            updated_at: r
                .get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
                .to_rfc3339(),
        })
        .collect();
    Ok(Json(sets))
}

/// `GET /v1/admin/policy-sets/{name}` - fetch one set.
pub async fn get_policy_set<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<TargetEnv>,
) -> Result<Json<PolicySetDetail>, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    let (_a, env_id, mut conn) = admin_gate(s, &headers, &q, &read_scope(s)).await?;
    let row = sqlx::query(
        r#"SELECT policy_set_name, description, policies, schema, origin, mode,
         version, enabled, created_at, updated_at
       FROM policy_sets
      WHERE service = $1 AND env_id = $2 AND policy_set_name = $3"#,
    )
    .bind(&s.service)
    .bind(env_id)
    .bind(&name)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("policy set '{name}' not found"),
        )
    })?;
    Ok(Json(PolicySetDetail {
        policy_set_name: row.get::<String, _>("policy_set_name"),
        description: row.get::<String, _>("description"),
        policies: row.get::<String, _>("policies"),
        schema: row.get::<Option<String>, _>("schema"),
        origin: row.get::<String, _>("origin"),
        mode: row.get::<String, _>("mode"),
        version: row.get::<i32, _>("version"),
        enabled: row.get::<bool, _>("enabled"),
        created_at: row
            .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
            .to_rfc3339(),
        updated_at: row
            .get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
            .to_rfc3339(),
    }))
}

/// `PUT /v1/admin/policy-sets/{name}` body.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct PutPolicySetBody {
    pub policies: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
}

/// `PUT /v1/admin/policy-sets/{name}` - create/update with write-time
/// validation. Platform rows are enroll-managed (409); tenant rows
/// (or new rows) are validated then stored, starting in `shadow`.
pub async fn put_policy_set<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<TargetEnv>,
    axum::Json(body): axum::Json<PutPolicySetBody>,
) -> Result<(StatusCode, Json<PolicySetMutated>), (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    let (a, env_id, mut conn) = admin_gate(s, &headers, &q, &write_scope(s)).await?;
    // Size caps before any parse work - a multi-MB submit must
    // fail fast with 413, not with a truncated Shield parse error.
    let schema = normalize_schema(body.schema.as_deref());
    check_text_caps(&body.policies, schema)?;
    // Write-time validation gate: invalid policy never stored.
    crate::validate_record_text(&name, &body.policies, schema).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid policy: {e}"),
        )
    })?;
    let mode = body.mode.as_deref().unwrap_or("shadow");
    if mode != "shadow" && mode != "enforced" {
        return Err((
            StatusCode::BAD_REQUEST,
            "mode must be 'shadow' or 'enforced'".into(),
        ));
    }
    // Platform rows are enroll-managed - refuse to overwrite.
    let existing: Option<(String,)> = sqlx::query_as(
    "SELECT origin FROM policy_sets WHERE service = $1 AND env_id = $2 AND policy_set_name = $3",
  )
  .bind(&s.service)
  .bind(env_id)
  .bind(&name)
  .fetch_optional(&mut *conn)
  .await
  .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some((origin,)) = &existing {
        if origin == "platform" {
            return Err((
                StatusCode::CONFLICT,
                "policy set is platform-managed (registration section) - edit via enroll".into(),
            ));
        }
    }
    let (version, out_mode): (i32, String) = sqlx::query_as(
    r#"INSERT INTO policy_sets
        (env_id, service, policy_set_name, description, policies, schema, origin, mode, version, enabled)
      VALUES ($1, $2, $3, $4, $5, $6, 'tenant', $7, 1, COALESCE($8, true))
      ON CONFLICT (env_id, service, policy_set_name) DO UPDATE
        SET description = EXCLUDED.description,
          policies  = EXCLUDED.policies,
          schema   = EXCLUDED.schema,
          mode    = EXCLUDED.mode,
          enabled   = EXCLUDED.enabled,
          version   = policy_sets.version + 1,
          updated_at = now()
      RETURNING version, mode"#,
  )
  .bind(env_id)
  .bind(&s.service)
  .bind(&name)
  .bind(&body.description)
  .bind(&body.policies)
  .bind(schema.map(str::to_string))
  .bind(mode)
  .bind(body.enabled.unwrap_or(true))
  .fetch_one(&mut *conn)
  .await
  .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Err(e) = emit_event(
        &s.pool,
        env_id,
        &s.service,
        &name,
        version as i64,
        body.enabled.unwrap_or(true),
        &out_mode,
        "sentin8:sys:policy:updated",
    )
    .await
    {
        tracing::warn!(error = %e, "policy event emit failed (hot-reload delay only)");
    }
    audit(
        &s.pool,
        env_id,
        &s.service,
        serde_json::json!({
          "action": "policy_set.updated",
          "resource_type": "policy_set",
          "resource_id": name,
          "actor": a.claims.sub,
        }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(PolicySetMutated {
            policy_set_name: name,
            version,
            mode: out_mode,
        }),
    ))
}

/// `DELETE /v1/admin/policy-sets/{name}` - tenant sets only.
pub async fn delete_policy_set<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<TargetEnv>,
) -> Result<StatusCode, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    let (a, env_id, mut conn) = admin_gate(s, &headers, &q, &write_scope(s)).await?;
    let result = sqlx::query(
    "DELETE FROM policy_sets WHERE service = $1 AND env_id = $2 AND policy_set_name = $3 AND origin = 'tenant'",
  )
  .bind(&s.service)
  .bind(env_id)
  .bind(&name)
  .execute(&mut *conn)
  .await
  .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "policy set not found or platform-managed".into(),
        ));
    }
    if let Err(e) = emit_event(
        &s.pool,
        env_id,
        &s.service,
        &name,
        0,
        false,
        "shadow",
        "sentin8:sys:policy:updated",
    )
    .await
    {
        tracing::warn!(error = %e, "policy delete event emit failed");
    }
    audit(
        &s.pool,
        env_id,
        &s.service,
        serde_json::json!({
          "action": "policy_set.deleted",
          "resource_type": "policy_set",
          "resource_id": name,
          "actor": a.claims.sub,
        }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/admin/policy-sets/{name}/test` body.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct TestPolicySetBody {
    pub policies: String,
    #[serde(default)]
    pub schema: Option<String>,
    pub subject_id: String,
    #[serde(default)]
    pub token_tp: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Sample live-role names for role-based candidate rules.
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub action: Option<String>,
}

/// `POST /v1/admin/policy-sets/{name}/test` - dry-run candidate policy text
/// against a sample context; returns decision WITHOUT storing.
pub async fn test_policy_set<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<TargetEnv>,
    axum::Json(body): axum::Json<TestPolicySetBody>,
) -> Result<Json<PolicyTestOutcome>, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    let a = verify(s, &headers).await?;
    scope_gate(&a, &write_scope(s))?;
    let _env_id = resolve_env(&q)?;
    let schema = normalize_schema(body.schema.as_deref());
    check_text_caps(&body.policies, schema)?;
    crate::validate_record_text(&name, &body.policies, schema).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid policy: {e}"),
        )
    })?;
    let record = crate::PolicySetRecord {
        id: Uuid::nil(),
        env_id: a.env_id(),
        service: s.service.clone(),
        policy_set_name: name.clone(),
        description: "dry-run".into(),
        policies: body.policies.clone(),
        schema: schema.map(str::to_string),
        origin: crate::PolicyOrigin::Tenant,
        mode: crate::PolicyMode::Enforced, // evaluate as if enforced
        version: 0,
        enabled: true,
    };
    let engine = crate::PolicyEngine::new(s.service.clone());
    engine
        .load_from_rows(vec![record])
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    let mut ctx = crate::runtime::request_ctx(
        body.subject_id.as_str(),
        a.env_id(),
        if body.token_tp.is_empty() {
            "user"
        } else {
            body.token_tp.as_str()
        },
        body.scopes.join(" ").as_str(),
    );
    ctx.roles = body.roles.iter().cloned().collect();
    let action = body.action.unwrap_or_else(|| format!("{}:read", s.service));
    let outcome = engine.evaluate(&ctx, &crate::EvalTarget::new(action.clone()));
    let would_deny = outcome.shadow_deny.is_some() || !outcome.enforce_decision.is_allow();
    Ok(Json(PolicyTestOutcome {
        policy_set_name: name,
        action,
        decision: outcome.enforce_decision,
        would_deny,
    }))
}

/// `POST /v1/admin/policy-sets/{mode}` body (RFW row actions).
#[derive(Deserialize, utoipa::ToSchema)]
pub struct PolicyModeBody {
    pub policy_set_name: String,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Shared mode-flip: tenant rows flip freely; platform rows flip MODE only
/// (shadow→enforced promotion is the ops lever - allowed; origin stays).
async fn flip_policy_mode(
    s: &SharedAdminState,
    headers: &HeaderMap,
    q: &TargetEnv,
    mode: Option<&str>,
    enabled_override: Option<bool>,
    body: &PolicyModeBody,
) -> Result<Json<PolicyModeMutated>, (StatusCode, String)> {
    let (a, env_id, mut conn) = admin_gate(s, headers, q, &write_scope(s)).await?;
    let (new_mode, new_enabled) = match (mode, enabled_override) {
        (Some("enforced"), _) => ("enforced".to_string(), body.enabled.unwrap_or(true)),
        (Some("shadow"), _) => ("shadow".to_string(), body.enabled.unwrap_or(true)),
        (_, Some(false)) => ("shadow".to_string(), false),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "no mode/enabled change requested".into(),
            ))
        }
    };
    let (version, out_mode, out_enabled): (i32, String, bool) = sqlx::query_as(
        r#"UPDATE policy_sets
       SET mode = $3, enabled = COALESCE($4, enabled), version = version + 1, updated_at = now()
      WHERE service = $2 AND env_id = $1 AND policy_set_name = $5
    RETURNING version, mode, enabled"#,
    )
    .bind(env_id)
    .bind(&s.service)
    .bind(&new_mode)
    .bind(new_enabled)
    .bind(&body.policy_set_name)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("policy set '{}' not found", body.policy_set_name),
        )
    })?;
    if let Err(e) = emit_event(
        &s.pool,
        env_id,
        &s.service,
        &body.policy_set_name,
        version as i64,
        out_enabled,
        &out_mode,
        "sentin8:sys:policy:updated",
    )
    .await
    {
        tracing::warn!(error = %e, "policy flip event emit failed");
    }
    audit(
        &s.pool,
        env_id,
        &s.service,
        serde_json::json!({
          "action": "policy_set.mode_flipped",
          "resource_type": "policy_set",
          "resource_id": body.policy_set_name,
          "mode": out_mode,
          "enabled": out_enabled,
          "actor": a.claims.sub,
        }),
    )
    .await;
    Ok(Json(PolicyModeMutated {
        policy_set_name: body.policy_set_name.clone(),
        mode: out_mode,
        enabled: out_enabled,
        version,
    }))
}

// ── RFW renderer helpers ──────────────────────────────────
// The RFW renderer only supports POST and submits row
// actions with an empty body and no row context, so every mutation the UI
// needs gets a POST alias whose target is identified by the PATH (not the
// body). CLI callers keep the canonical verbs.

/// Policy text / schema size caps: a multi-MB textarea submit
/// must fail fast instead of bloating a Shield parse error (or hanging the
/// engine compile) - 413 before any validation runs.
pub const MAX_POLICY_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_SCHEMA_TEXT_BYTES: usize = 64 * 1024;

/// Normalize the optional Shield schema from a request body: an empty or
/// whitespace-only string means "no schema". The RFW form renderer submits
/// `""` for untouched optional textareas (`onSaved: v ?? ""`), which would
/// otherwise be schema-VALIDATED (and fail to parse) instead of being
/// treated as absent - the create form 422'd every submit that left the
/// schema field blank .
pub(crate) fn normalize_schema(schema: Option<&str>) -> Option<&str> {
    schema.filter(|s| !s.trim().is_empty())
}

fn check_text_caps(policies: &str, schema: Option<&str>) -> Result<(), (StatusCode, String)> {
    if policies.len() > MAX_POLICY_TEXT_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "policy text exceeds {} KiB (got {} bytes)",
                MAX_POLICY_TEXT_BYTES / 1024,
                policies.len()
            ),
        ));
    }
    if let Some(schema) = schema {
        if schema.len() > MAX_SCHEMA_TEXT_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "schema text exceeds {} KiB (got {} bytes)",
                    MAX_SCHEMA_TEXT_BYTES / 1024,
                    schema.len()
                ),
            ));
        }
    }
    Ok(())
}

/// `POST /v1/admin/policy-sets` - create a tenant policy set (name in body).
/// The RFW create form is POST-only and cannot PUT to a path with
/// the name; the shared `put_policy_set` core runs with `origin='tenant'`
/// validation, then the renderer is redirected to the editor page.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreatePolicySetBody {
    pub policy_set_name: String,
    pub policies: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
}

pub async fn create_policy_set<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Query(q): Query<TargetEnv>,
    axum::Json(body): axum::Json<CreatePolicySetBody>,
) -> Result<axum::response::Response, (StatusCode, String)>
where
    T: HasPolicyAdmin + Clone,
{
    check_text_caps(&body.policies, normalize_schema(body.schema.as_deref()))?;
    let name = body.policy_set_name.trim().to_string();
    if name.is_empty()
        || name.len() > 128
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "policy_set_name must be 1-128 chars of [A-Za-z0-9_-]".into(),
        ));
    }
    let st2 = st.clone();
    let put = axum::Json(PutPolicySetBody {
        policies: body.policies,
        description: body.description,
        schema: body.schema,
        enabled: None,
        mode: body.mode,
    });
    // Reuse the shared PUT core (validation, tenant-origin, event, audit) -
    // a create is just a PUT to the not-yet-existing name.
    let (status, Json(payload)) = put_policy_set(
        State(st2),
        headers,
        axum::extract::Path(name.clone()),
        axum::extract::Query(q),
        put,
    )
    .await?;
    let redirect = format!("policy-sets/{name}/edit");
    Ok(match status {
        StatusCode::CREATED => axum::Json(serde_json::json!({
          "response_type": "redirect",
          "route": redirect,
          "policy_set": payload,
        })),
        _ => axum::Json(serde_json::json!({
          "response_type": "error",
          "message": payload,
        })),
    }
    .into_response())
}

/// `POST /v1/admin/policy-sets/{name}/save` - PUT alias for the RFW
/// renderer. Identical body + validation to the canonical PUT.
pub async fn save_policy_set<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<TargetEnv>,
    body: axum::Json<PutPolicySetBody>,
) -> Result<(StatusCode, Json<PolicySetMutated>), (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    check_text_caps(&body.policies, normalize_schema(body.schema.as_deref()))?;
    put_policy_set(State(st), headers, Path(name), Query(q), body).await
}

/// Path-param row-action alias: `POST …/{name}/enforce|shadow|
/// disable|delete` - the RFW row action submits an empty body, so the target
/// set and the operation come from the path. One route shape serves all four
/// actions (axum's matchit router cannot register `{name}/delete` next to
/// `{name}/{action}` without a conflict), so this dispatcher covers both
/// routers. enforce/shadow/disable reuse the shared flip logic; delete is
/// the tenant-only DELETE (platform rows 404 here).
pub async fn admin_flip_policy_set<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Path((name, action)): Path<(String, String)>,
    Query(q): Query<TargetEnv>,
) -> Result<axum::response::Response, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    if action == "delete" {
        let status = delete_policy_set(State(st), headers, Path(name), Query(q)).await?;
        return Ok(status.into_response());
    }
    let mode = match action.as_str() {
        "enforce" => Some("enforced"),
        "shadow" => Some("shadow"),
        "disable" => None,
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                format!("unknown policy-set action '{action}'"),
            ))
        }
    };
    let body = PolicyModeBody {
        policy_set_name: name,
        enabled: None,
    };
    flip_policy_mode(st.policy_admin(), &headers, &q, mode, None, &body)
        .await
        .map(|Json(v)| Json(v).into_response())
}

/// `POST /v1/admin/policy-sets/{name}/delete`-style alias - kept as a named
/// handler for direct mounting where a dedicated route shape exists (the
/// canonical router mounts the dispatcher above instead).
pub async fn admin_delete_policy_set<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<TargetEnv>,
) -> Result<StatusCode, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    delete_policy_set(State(st), headers, Path(name), Query(q)).await
}

/// `POST /v1/admin/relations/{id}/delete` - row-action alias.
/// `id` is the colon-joined tuple the RFW list emits
/// (`subject_type:subject_id:relation:object_type:object_id`) - the
/// renderer substitutes only `{id}`, so the tuple rides one segment.
pub async fn admin_delete_relation<T>(
    st: State<T>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<TargetEnv>,
) -> Result<StatusCode, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let parts: Vec<&str> = id.split(':').collect();
    if parts.len() < 5 {
        return Err((
            StatusCode::BAD_REQUEST,
            "relation id must be subject_type:subject_id:relation:object_type:object_id".into(),
        ));
    }
    let (subject_type, object_type, object_id, relation) = (
        parts[0],
        parts[parts.len() - 2],
        parts[parts.len() - 1],
        parts[parts.len() - 3],
    );
    let subject_id = parts[1..parts.len() - 3].join(":");
    let dq = DeleteRelationQuery {
        subject_type: subject_type.to_string(),
        subject_id,
        relation: relation.to_string(),
        object_type: object_type.to_string(),
        object_id: object_id.to_string(),
        target_env_id: q.target_env_id.clone(),
    };
    delete_relation(st, headers, Query(dq)).await
}

/// `POST /v1/admin/attributes/{id}/delete` - row-action alias.
/// `id` is `subject_id:attr_key` as emitted by the RFW list; splitn(2)
/// keeps any colons inside the attribute key.
pub async fn admin_delete_attribute<T>(
    st: State<T>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<TargetEnv>,
) -> Result<StatusCode, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let (subject_id, attr_key) = id.split_once(':').ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "attribute id must be subject_id:attr_key".into(),
        )
    })?;
    let dq = DeleteAttributeQuery {
        subject_id: subject_id.to_string(),
        attr_key: attr_key.to_string(),
        target_env_id: q.target_env_id.clone(),
    };
    delete_attribute(st, headers, Query(dq)).await
}

/// `GET /v1/admin/policy-decisions` - deny / would-deny feed for the UI
///. Reads the shared audit trail (`sentin8.audit_events`) rows the
/// runtime decision-audit writes (crate runtime `emit_decision_audit`):
/// `event->>'action' IN ('policy.deny','policy.would_deny')`.
pub async fn list_policy_decisions<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Query(q): Query<TargetEnv>,
) -> Result<Json<Vec<PolicyDecisionRow>>, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    let (_a, env_id, mut conn) = admin_gate(s, &headers, &q, &read_scope(s)).await?;
    let rows = sqlx::query(
        r#"SELECT id, created_at, event
       FROM audit_events
      WHERE env_id = $1
       AND service = $2
       AND (event->>'action' = 'policy.deny' OR event->>'action' = 'policy.would_deny')
      ORDER BY created_at DESC
      LIMIT 200"#,
    )
    .bind(env_id)
    .bind(s.service.rsplit(':').next().unwrap_or(&s.service))
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items: Vec<PolicyDecisionRow> = rows
        .iter()
        .map(|r| {
            let event: serde_json::Value = r.get("event");
            PolicyDecisionRow {
                id: r.get::<Uuid, _>("id"),
                timestamp: r
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
                decision: event
                    .get("action")
                    .cloned()
                    .unwrap_or(serde_json::json!("unknown")),
                action_id: event
                    .get("action_id")
                    .cloned()
                    .unwrap_or(serde_json::json!("")),
                reason: event
                    .get("reason")
                    .cloned()
                    .unwrap_or(serde_json::json!("")),
                policy_set: event
                    .get("policy_set")
                    .cloned()
                    .unwrap_or(serde_json::json!("")),
                subject: event
                    .get("subject")
                    .cloned()
                    .unwrap_or(serde_json::json!("")),
                enforced: event
                    .get("enforced")
                    .cloned()
                    .unwrap_or(serde_json::json!(false)),
            }
        })
        .collect();
    Ok(Json(items))
}

/// `POST /v1/admin/policy-sets/enforce` - promote a set to enforced.
pub async fn admin_enforce_policy_set<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Query(q): Query<TargetEnv>,
    Json(body): Json<PolicyModeBody>,
) -> Result<Json<PolicyModeMutated>, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    flip_policy_mode(s, &headers, &q, Some("enforced"), None, &body).await
}

/// `POST /v1/admin/policy-sets/shadow` - demote a set to shadow (rollback).
pub async fn admin_shadow_policy_set<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Query(q): Query<TargetEnv>,
    Json(body): Json<PolicyModeBody>,
) -> Result<Json<PolicyModeMutated>, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    flip_policy_mode(s, &headers, &q, Some("shadow"), None, &body).await
}

/// `POST /v1/admin/policy-sets/disable` - disable a set.
pub async fn admin_disable_policy_set<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Query(q): Query<TargetEnv>,
    Json(body): Json<PolicyModeBody>,
) -> Result<Json<PolicyModeMutated>, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    flip_policy_mode(s, &headers, &q, None, Some(false), &body).await
}

// ── Relations endpoints ──────────────────────────────────────────

/// `PUT /v1/admin/relations` body - one relation tuple.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct PutRelationBody {
    pub subject_type: String,
    pub subject_id: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
}

fn emit_relations_event(
    s: &SharedAdminState,
    env_id: Uuid,
    subject_type: &str,
    relation: &str,
    object_id: &str,
) {
    let envelope = PolicyUpdatedEnvelope {
        env_id,
        service: s.service.clone(),
        policy_set_name: format!("{subject_type}/{relation}/{object_id}"),
        version: 1,
        enabled: true,
        mode: "enforced".to_string(),
    };
    let pool = s.pool.clone();
    tokio::spawn(async move {
        let _ = sentin8_outbox::insert_policy_change_event(
            &pool,
            &envelope,
            "sentin8:sys:policy:relations:updated",
        )
        .await;
    });
}

/// `GET /v1/admin/relations` - list this service's relation tuples.
pub async fn list_relations<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Query(q): Query<TargetEnv>,
) -> Result<Json<Vec<RelationRecordRow>>, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    let (_a, env_id, mut conn) = admin_gate(s, &headers, &q, &read_scope(s)).await?;
    let rows = sqlx::query(
        r#"SELECT subject_type, subject_id, relation, object_type, object_id, origin
       FROM policy_relations
      WHERE service = $1 AND env_id = $2
      ORDER BY subject_type, subject_id, relation
      LIMIT 500"#,
    )
    .bind(&s.service)
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items: Vec<RelationRecordRow> = rows
        .iter()
        .map(|r| RelationRecordRow {
            subject_type: r.get::<String, _>("subject_type"),
            subject_id: r.get::<String, _>("subject_id"),
            relation: r.get::<String, _>("relation"),
            object_type: r.get::<String, _>("object_type"),
            object_id: r.get::<String, _>("object_id"),
            origin: r.get::<String, _>("origin"),
        })
        .collect();
    Ok(Json(items))
}

/// `PUT /v1/admin/relations` - upsert one relation tuple (tenant origin).
pub async fn put_relation<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Query(q): Query<TargetEnv>,
    axum::Json(body): axum::Json<PutRelationBody>,
) -> Result<(StatusCode, Json<RelationUpserted>), (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    let (a, env_id, mut conn) = admin_gate(s, &headers, &q, &write_scope(s)).await?;
    let row: (Uuid,) = sqlx::query_as(
        r#"INSERT INTO policy_relations
        (env_id, service, subject_type, subject_id, relation, object_type, object_id, origin)
      VALUES ($1, $2, $3, $4, $5, $6, $7, 'tenant')
      ON CONFLICT (env_id, subject_type, subject_id, relation, object_type, object_id) DO UPDATE
        SET service = EXCLUDED.service, origin = 'tenant'
      RETURNING id"#,
    )
    .bind(env_id)
    .bind(&s.service)
    .bind(&body.subject_type)
    .bind(&body.subject_id)
    .bind(&body.relation)
    .bind(&body.object_type)
    .bind(&body.object_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    emit_relations_event(
        s,
        env_id,
        &body.subject_type,
        &body.relation,
        &body.object_id,
    );
    audit(
        &s.pool,
        env_id,
        &s.service,
        serde_json::json!({
          "action": "policy_relation.upserted",
          "resource_type": "policy_relation",
          "resource_id": row.0,
          "subject": format!("{}/{}", body.subject_type, body.subject_id),
          "relation": body.relation,
          "object": format!("{}/{}", body.object_type, body.object_id),
          "actor": a.claims.sub,
        }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(RelationUpserted {
            id: row.0,
            status: "upserted".to_string(),
        }),
    ))
}

/// `DELETE /v1/admin/relations` query - identifies the tuple.
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct DeleteRelationQuery {
    pub subject_type: String,
    pub subject_id: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
    #[serde(default)]
    pub target_env_id: Option<String>,
}

fn target_env_of(target_env_id: &Option<String>) -> TargetEnv {
    TargetEnv {
        target_env_id: target_env_id.clone(),
    }
}

/// `DELETE /v1/admin/relations` - remove one relation tuple.
pub async fn delete_relation<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Query(q): Query<DeleteRelationQuery>,
) -> Result<StatusCode, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    let tq = target_env_of(&q.target_env_id);
    let (a, env_id, mut conn) = admin_gate(s, &headers, &tq, &write_scope(s)).await?;
    let result = sqlx::query(
        r#"DELETE FROM policy_relations
      WHERE env_id = $1 AND service = $2
       AND subject_type = $3 AND subject_id = $4
       AND relation = $5 AND object_type = $6 AND object_id = $7"#,
    )
    .bind(env_id)
    .bind(&s.service)
    .bind(&q.subject_type)
    .bind(&q.subject_id)
    .bind(&q.relation)
    .bind(&q.object_type)
    .bind(&q.object_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "relation tuple not found".into()));
    }
    emit_relations_event(s, env_id, &q.subject_type, &q.relation, &q.object_id);
    audit(
        &s.pool,
        env_id,
        &s.service,
        serde_json::json!({
          "action": "policy_relation.deleted",
          "resource_type": "policy_relation",
          "subject": format!("{}/{}", q.subject_type, q.subject_id),
          "relation": q.relation,
          "object": format!("{}/{}", q.object_type, q.object_id),
          "actor": a.claims.sub,
        }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/admin/relations/check` query - Zanzibar-style dry-run.
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct RelationCheckQuery {
    pub subject_type: String,
    pub subject_id: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
    #[serde(default)]
    pub target_env_id: Option<String>,
}

/// `GET /v1/admin/relations/check` - is `subject` connected to `object` by
/// `relation` (directly or transitively)? Returns path info + decision.
pub async fn check_relation<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Query(q): Query<RelationCheckQuery>,
) -> Result<Json<RelationCheckResult>, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    let tq = target_env_of(&q.target_env_id);
    let (_a, env_id, _conn) = admin_gate(s, &headers, &tq, &read_scope(s)).await?;
    let slice: Vec<crate::RelationRecord> = crate::load_relations(&s.pool, env_id, &s.service)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Direct edge?
    let direct = slice.iter().any(|r| {
        r.subject_type == q.subject_type
            && r.subject_id == q.subject_id
            && r.relation == q.relation
            && r.object_type == q.object_type
            && r.object_id == q.object_id
    });
    // Transitive closure: BFS over subject→parent edges.
    let mut visited = std::collections::HashSet::new();
    let mut frontier = vec![format!("{}/{}", q.subject_type, q.subject_id)];
    let mut transitive = false;
    while let Some(cur) = frontier.pop() {
        if !visited.insert(cur.clone()) {
            continue;
        }
        for r in &slice {
            let subj = format!("{}/{}", r.subject_type, r.subject_id);
            let obj = format!("{}/{}", r.object_type, r.object_id);
            if subj == cur && r.relation == q.relation {
                if obj == format!("{}/{}", q.object_type, q.object_id) {
                    transitive = true;
                    break;
                }
                frontier.push(obj);
            }
        }
        if transitive {
            break;
        }
    }
    Ok(Json(RelationCheckResult {
        subject: format!("{}/{}", q.subject_type, q.subject_id),
        relation: q.relation,
        object: format!("{}/{}", q.object_type, q.object_id),
        direct,
        transitive,
        connected: direct || transitive,
        tuple_count: slice.len(),
    }))
}

// ── Attributes endpoints ─────────────────────────────────────────

/// `PUT /v1/admin/attributes` body - one principal attribute.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct PutAttributeBody {
    pub subject_id: String,
    pub attr_key: String,
    pub attr_value: serde_json::Value,
}

/// `GET /v1/admin/attributes` query - list attributes for one subject (or
/// all subjects in the env when omitted).
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct ListAttributesQuery {
    #[serde(default)]
    pub subject_id: Option<String>,
    #[serde(default)]
    pub target_env_id: Option<String>,
}

fn emit_attrs_event(s: &SharedAdminState, env_id: Uuid, subject_id: &str, attr_key: &str) {
    let envelope = PolicyUpdatedEnvelope {
        env_id,
        service: s.service.clone(),
        policy_set_name: format!("{subject_id}/{attr_key}"),
        version: 1,
        enabled: true,
        mode: "enforced".to_string(),
    };
    let pool = s.pool.clone();
    tokio::spawn(async move {
        let _ = sentin8_outbox::insert_policy_change_event(
            &pool,
            &envelope,
            "sentin8:sys:policy:attrs:updated",
        )
        .await;
    });
}

/// `GET /v1/admin/attributes` - list principal attributes for one subject
/// (or all subjects when `subject_id` is omitted) in the target env.
pub async fn list_attributes<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Query(q): Query<ListAttributesQuery>,
) -> Result<Json<Vec<PrincipalAttr>>, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    let tq = target_env_of(&q.target_env_id);
    let (_a, env_id, mut conn) = admin_gate(s, &headers, &tq, &read_scope(s)).await?;
    let rows = if let Some(sub) = &q.subject_id {
        sqlx::query(
            r#"SELECT subject_id, attr_key, attr_value, origin
         FROM policy_principal_attrs
        WHERE env_id = $1 AND subject_id = $2
        ORDER BY subject_id, attr_key
        LIMIT 500"#,
        )
        .bind(env_id)
        .bind(sub)
        .fetch_all(&mut *conn)
        .await
    } else {
        sqlx::query(
            r#"SELECT subject_id, attr_key, attr_value, origin
         FROM policy_principal_attrs
        WHERE env_id = $1
        ORDER BY subject_id, attr_key
        LIMIT 500"#,
        )
        .bind(env_id)
        .fetch_all(&mut *conn)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items: Vec<PrincipalAttr> = rows
        .iter()
        .map(|r| PrincipalAttr {
            subject_id: r.get::<String, _>("subject_id"),
            attr_key: r.get::<String, _>("attr_key"),
            attr_value: r.get::<serde_json::Value, _>("attr_value"),
            origin: r.get::<String, _>("origin"),
        })
        .collect();
    Ok(Json(items))
}

/// `PUT /v1/admin/attributes` - upsert one principal attribute. Values must
/// be JSON scalars or arrays of scalars (Shield restricted expressions cannot
/// represent nested objects - 422 otherwise).
pub async fn put_attribute<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Query(q): Query<TargetEnv>,
    axum::Json(body): axum::Json<PutAttributeBody>,
) -> Result<(StatusCode, Json<AttributeUpserted>), (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    let (a, env_id, mut conn) = admin_gate(s, &headers, &q, &write_scope(s)).await?;
    if crate::json_to_restricted_expr(&body.attr_value).is_none() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "attr_value must be a scalar or an array of scalars".into(),
        ));
    }
    sqlx::query(
        r#"INSERT INTO policy_principal_attrs
        (env_id, subject_id, attr_key, attr_value, origin)
      VALUES ($1, $2, $3, $4, 'tenant')
      ON CONFLICT (env_id, subject_id, attr_key) DO UPDATE
        SET attr_value = EXCLUDED.attr_value, origin = 'tenant'"#,
    )
    .bind(env_id)
    .bind(&body.subject_id)
    .bind(&body.attr_key)
    .bind(&body.attr_value)
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    emit_attrs_event(s, env_id, &body.subject_id, &body.attr_key);
    audit(
        &s.pool,
        env_id,
        &s.service,
        serde_json::json!({
          "action": "policy_attribute.upserted",
          "resource_type": "policy_attribute",
          "subject_id": body.subject_id,
          "attr_key": body.attr_key,
          "actor": a.claims.sub,
        }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(AttributeUpserted {
            status: "upserted".to_string(),
        }),
    ))
}

/// `DELETE /v1/admin/attributes` query - identifies the attribute.
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct DeleteAttributeQuery {
    pub subject_id: String,
    pub attr_key: String,
    #[serde(default)]
    pub target_env_id: Option<String>,
}

/// `DELETE /v1/admin/attributes` - remove one principal attribute.
pub async fn delete_attribute<T>(
    State(st): State<T>,
    headers: HeaderMap,
    Query(q): Query<DeleteAttributeQuery>,
) -> Result<StatusCode, (StatusCode, String)>
where
    T: HasPolicyAdmin,
{
    let s = st.policy_admin();
    let tq = target_env_of(&q.target_env_id);
    let (a, env_id, mut conn) = admin_gate(s, &headers, &tq, &write_scope(s)).await?;
    let result = sqlx::query(
    "DELETE FROM policy_principal_attrs WHERE env_id = $1 AND subject_id = $2 AND attr_key = $3",
  )
  .bind(env_id)
  .bind(&q.subject_id)
  .bind(&q.attr_key)
  .execute(&mut *conn)
  .await
  .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "attribute not found".into()));
    }
    emit_attrs_event(s, env_id, &q.subject_id, &q.attr_key);
    audit(
        &s.pool,
        env_id,
        &s.service,
        serde_json::json!({
          "action": "policy_attribute.deleted",
          "resource_type": "policy_attribute",
          "subject_id": q.subject_id,
          "attr_key": q.attr_key,
          "actor": a.claims.sub,
        }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Typed admin responses (no free-form bodies) ────────────────

/// One policy set in the list view (the RFW row shape).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct PolicySetRow {
    /// The set name; doubles as the RFW row id.
    pub id: String,
    /// The set name.
    pub policy_set_name: String,
    /// Human description.
    pub description: String,
    /// Row origin (`platform` enroll-managed vs `tenant`).
    pub origin: String,
    /// Evaluation mode (`shadow`/`enforced`).
    pub mode: String,
    /// Monotonic revision.
    pub version: i32,
    /// Whether the set participates in evaluation.
    pub enabled: bool,
    /// Number of policy statements in the set.
    pub policies_len: i64,
    /// Last update instant (RFC 3339).
    pub updated_at: String,
}

/// One policy set in the detail view (adds the full policy text).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct PolicySetDetail {
    /// The set name.
    pub policy_set_name: String,
    /// Human description.
    pub description: String,
    /// The full policy text (Shield policy language).
    pub policies: String,
    /// Optional schema text bound to the set.
    pub schema: Option<String>,
    /// Row origin (`platform`/`tenant`).
    pub origin: String,
    /// Evaluation mode.
    pub mode: String,
    /// Monotonic revision.
    pub version: i32,
    /// Whether the set participates in evaluation.
    pub enabled: bool,
    /// Creation instant (RFC 3339).
    pub created_at: String,
    /// Last update instant (RFC 3339).
    pub updated_at: String,
}

/// A stored policy-set mutation result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct PolicySetMutated {
    /// The set name.
    pub policy_set_name: String,
    /// The revision after the mutation.
    pub version: i32,
    /// The evaluation mode after the mutation.
    pub mode: String,
}

/// A dry-run (test) outcome; nothing was stored.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct PolicyTestOutcome {
    /// The set name the candidate text was compiled under.
    pub policy_set_name: String,
    /// The action evaluated.
    pub action: String,
    /// The enforce-mode decision.
    pub decision: crate::Decision,
    /// Whether the shadow evaluation would deny.
    pub would_deny: bool,
}

/// A mode/enable flip result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct PolicyModeMutated {
    /// The set name flipped.
    pub policy_set_name: String,
    /// The evaluation mode after the flip.
    pub mode: String,
    /// Whether the set is enabled after the flip.
    pub enabled: bool,
    /// The revision after the flip.
    pub version: i32,
}

/// One principal attribute in the list view.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct PrincipalAttr {
    /// The attribute owner (subject id).
    pub subject_id: String,
    /// The attribute key.
    pub attr_key: String,
    /// The attribute value (free-form JSON by contract).
    pub attr_value: serde_json::Value,
    /// Row origin.
    pub origin: String,
}

/// An attribute upsert result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AttributeUpserted {
    /// Always `upserted`.
    pub status: String,
}

/// One relation tuple in the list view.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct RelationRecordRow {
    /// The subject entity type.
    pub subject_type: String,
    /// The subject entity id.
    pub subject_id: String,
    /// The relation name.
    pub relation: String,
    /// The object entity type.
    pub object_type: String,
    /// The object entity id.
    pub object_id: String,
    /// Row origin.
    pub origin: String,
}

/// A relation-tuple upsert result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct RelationUpserted {
    /// The stored tuple id.
    pub id: Uuid,
    /// Always `upserted`.
    pub status: String,
}

/// A relation connectivity check result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct RelationCheckResult {
    /// The subject in `type/id` form.
    pub subject: String,
    /// The relation checked.
    pub relation: String,
    /// The object in `type/id` form.
    pub object: String,
    /// Whether a direct tuple exists.
    pub direct: bool,
    /// Whether a transitive path exists.
    pub transitive: bool,
    /// `direct || transitive`.
    pub connected: bool,
    /// Number of tuples inspected.
    pub tuple_count: usize,
}

/// One recent deny / would-deny decision feed row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct PolicyDecisionRow {
    /// Audit row id.
    pub id: Uuid,
    /// Decision instant (RFC 3339).
    pub timestamp: String,
    /// The decision action (`policy.deny`/`policy.would_deny`).
    pub decision: serde_json::Value,
    /// The evaluated action id.
    pub action_id: serde_json::Value,
    /// Why the decision was reached.
    pub reason: serde_json::Value,
    /// The policy set that produced the decision.
    pub policy_set: serde_json::Value,
    /// The subject the decision was about.
    pub subject: serde_json::Value,
    /// Whether the deny was enforced (vs shadow-mode).
    pub enforced: serde_json::Value,
}

// ── Scope-derivation tests (28.7 reopen per-service naming) ─────

#[cfg(test)]
mod scope_tests {
    use super::*;

    #[test]
    fn policy_scope_prefix_uses_first_two_segments() {
        assert_eq!(scope_prefix("sentin8:post"), "sentin8:post");
        assert_eq!(scope_prefix("bank8:ledger"), "bank8:ledger");
        assert_eq!(scope_prefix("bank8:payments:worker"), "bank8:payments");
        assert_eq!(scope_prefix("lone"), "lone");
    }

    #[test]
    fn scope_prefix_strips_to_vertical_service() {
        assert_eq!(scope_prefix("sentin8:post"), "sentin8:post");
        assert_eq!(scope_prefix("bank8:ledger"), "bank8:ledger");
        assert_eq!(scope_prefix("bank8:payments:worker"), "bank8:payments");
        assert_eq!(scope_prefix("lone"), "lone");
    }

    // PgPool::connect_lazy starts the pool's background reaper via
    // tokio::spawn (sqlx-core inner.rs) - a sync #[test] has no Tokio
    // context and panics (backing-service-coupled
    // tests run under an async runtime).
    #[tokio::test]
    async fn shared_admin_state_derives_per_service_policy_scopes() {
        let s = SharedAdminState::test(
            "sentin8:post",
            sqlx::PgPool::connect_lazy("postgres://x:y@z/db").unwrap(),
        );
        assert_eq!(s.policy_read_scope(), "sentin8:post:policy:read");
        assert_eq!(s.policy_write_scope(), "sentin8:post:policy:write");

        let v = SharedAdminState::test(
            "bank8:ledger",
            sqlx::PgPool::connect_lazy("postgres://x:y@z/db").unwrap(),
        );
        assert_eq!(v.policy_read_scope(), "bank8:ledger:policy:read");
        assert_eq!(v.policy_write_scope(), "bank8:ledger:policy:write");
    }
}
