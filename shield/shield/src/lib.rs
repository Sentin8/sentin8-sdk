// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-shield
//!
//! Declarative authorization for Sentin8 - an embedded Shield engine that
//! is the authoritative decision point of the platform's authorization
//! pipeline (the step after authentication and tenant resolution).
//!
//! ## Positioning
//!
//! One engine, three models: Shield is the authoritative decision point for
//! **RBAC** (live-resolved role membership), **ABAC** (attribute
//! conditions), and **ReBAC** (relationship hierarchy).
//! Handlers authenticate + resolve tenant first, then the engine decides.
//! There is no per-service JWT scope check; the JWT
//! `scope` claim is a coarse pre-filter + RLS context feed, never the
//! decision. PostgreSQL RLS is the tenant-isolation barrier only.
//!
//! ## Semantics
//!
//! - **Fail-closed**: no matching permit in an enforced set → deny; eval/
//!   cache/role-resolution error → deny + audit; unparsable policy text at
//!   boot → the caller refuses to start (`PolicyEngine::load` returns `Err`).
//! - **Shadow vs enforced**: a set in `mode='shadow'` evaluates and logs
//!   `policy.would_deny` but never blocks; `mode='enforced'` rejects.
//! - **M2M parity**: token type never bypasses policy.
//!
//! ## Distribution
//!
//! Policy sets, relation tuples, and principal attributes live in the
//! env-scoped `sentin8_policy_*` tables (RLS). Services load their own rows
//! at boot (as their own PG role) and hot-reload on the `policy` stream
//! events (`sentin8:sys:policy:updated`, `…:relations:updated`,
//! `…:attrs:updated` - direct consumers). Policies are *data* - declared in
//! `vertical-registry.json`, upserted by `vertical enroll`; zero
//! compile-time vertical knowledge. Tenant-authored rows are
//! env-administered.

use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use shield::{
    Authorizer, Decision as ShieldDecision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    Policy, PolicyId, PolicySet, Request, RestrictedExpression, Schema, ValidationMode,
    ValidationResult, Validator,
};
use thiserror::Error;
use uuid::Uuid;

#[cfg(test)]
mod tests;

pub mod admin;
pub mod runtime;
pub mod stat_emit;
pub mod substrate;

// Re-export the Shield engine crate itself: consumers reach the full engine
// API as `sentin8_shield::shield::…` without naming the vendor package.
pub use shield;
// Convenience re-exports (services build attribute maps without touching the
// engine crate directly).
pub use shield::RestrictedExpression as RestrictedExpr;
pub use substrate::{
    entity_uid, json_to_restricted_expr, load_principal_attrs, load_relations,
    relations_to_parents, PrincipalAttrRecord, RelationRecord, ResolvedIdentity, RoleError,
    RoleResolver, RELATION_SLICE_CAP,
};

// ── Errors ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy parse error in `{set}`: {detail}")]
    Parse { set: String, detail: String },
    #[error("schema parse error in `{set}`: {detail}")]
    SchemaParse { set: String, detail: String },
    #[error("schema validation error in `{set}`: {detail}")]
    Validation { set: String, detail: String },
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("invalid policy record: {0}")]
    InvalidRecord(String),
    #[error("policy set not found: {0}")]
    NotFound(String),
}

// ── Record (DB row shape) ───────────────────────────────────────────────

/// Origin of a policy-set row: `platform` rows come from
/// `vertical-registry.json` via enroll and are overwritten on re-enroll;
/// `tenant` rows are authored by env admins and are never touched by enroll.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "text", rename_all = "lowercase")]
pub enum PolicyOrigin {
    Platform,
    Tenant,
}

/// Evaluation mode: `shadow` evaluates and logs would-deny but never
/// blocks; `enforced` rejects. Promotion/rollback is a single UPDATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "text", rename_all = "lowercase")]
pub enum PolicyMode {
    Shadow,
    Enforced,
}

impl PolicyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyMode::Shadow => "shadow",
            PolicyMode::Enforced => "enforced",
        }
    }
}

/// One row of `policy_sets`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySetRecord {
    pub id: Uuid,
    pub env_id: Uuid,
    /// Colon service_type of the owning service, e.g. `sentin8:post`.
    pub service: String,
    pub policy_set_name: String,
    #[serde(default)]
    pub description: String,
    /// Shield policy text. One policy per statement - parsed one-by-one
    /// (multi-statement strings are rejected by Shield's parser).
    pub policies: String,
    /// Optional Shield schema. Required for tenant-authored sets (strict mode).
    #[serde(default)]
    pub schema: Option<String>,
    pub origin: PolicyOrigin,
    pub mode: PolicyMode,
    pub version: i64,
    pub enabled: bool,
}

// ── Validation (write-time + boot-time) ─────────────────────────────────

/// Validate the policy text of a record: every statement must parse, and -
/// when a schema is present - the set must pass schema-linked validation
/// (invalid policies are rejected at write time, never stored).
pub fn validate_record_text(
    set_name: &str,
    policies: &str,
    schema: Option<&str>,
) -> Result<(), PolicyError> {
    let mut pset = PolicySet::new();
    parse_statements(set_name, policies, &mut pset)?;
    if let Some(schema_src) = schema {
        let schema = Schema::from_str(schema_src).map_err(|e| PolicyError::SchemaParse {
            set: set_name.into(),
            detail: e.to_string(),
        })?;
        let result: ValidationResult =
            Validator::new(schema).validate(&pset, ValidationMode::Strict);
        let errs: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
        if !errs.is_empty() {
            return Err(PolicyError::Validation {
                set: set_name.into(),
                detail: errs.join("; "),
            });
        }
    }
    Ok(())
}

/// Parse a whitespace-separated policy text into individual Shield statements.
/// Shield parses ONE policy per string; blank lines/comments between statements
/// are stripped, and each remaining statement is validated with `Policy::parse`.
fn parse_statements(
    set_name: &str,
    policies: &str,
    pset: &mut PolicySet,
) -> Result<(), PolicyError> {
    for (idx, stmt) in split_statements(policies).into_iter().enumerate() {
        let id = PolicyId::new(format!("{set_name}:{idx}"));
        let parsed = Policy::parse(Some(id), &stmt).map_err(|e| PolicyError::Parse {
            set: set_name.into(),
            detail: e.to_string(),
        })?;
        pset.add(parsed).map_err(|e| PolicyError::Parse {
            set: set_name.into(),
            detail: e.to_string(),
        })?;
    }
    Ok(())
}

/// Split policy text into statements: a statement starts at `permit(` or
/// `forbid(` (ignoring an optional `@annotation` comment) and ends at the
/// matching `;` - quotes and braces are respected so `contains("...;")` never
/// terminates a statement early.
fn split_statements(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut escape = false;
    let mut started = false;
    for ch in text.chars() {
        if in_str {
            current.push(ch);
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        match ch {
            '"' => {
                in_str = true;
                current.push(ch);
            }
            '(' => {
                depth += 1;
                current.push(ch);
                started = true;
            }
            ')' => {
                depth -= 1;
                current.push(ch);
            }
            ';' if depth <= 0 && started => {
                current.push(ch);
                out.push(current.trim().to_string());
                current = String::new();
                started = false;
            }
            _ => current.push(ch),
        }
    }
    let tail = current.trim();
    if !tail.is_empty() {
        out.push(tail.to_string());
    }
    out.into_iter().filter(|s| !s.is_empty()).collect()
}

// ── Evaluation input ────────────────────────────────────────────────────

/// Request context assembled from the verified token (steps 1-6 already ran).
/// The engine never re-verifies tokens - it consumes what the caller resolved.
#[derive(Debug, Clone)]
pub struct RequestCtx {
    /// Token `sub`.
    pub subject_id: String,
    pub env_id: Uuid,
    pub org_id: Uuid,
    /// `user` | `m2m` | `delegated` | … (token type never bypasses policy).
    pub token_tp: String,
    /// Resolved scope claim (coarse pre-filter + RLS feed - not the decision).
    /// When the caller passes a full live evaluation (`evaluate_full`), this
    /// holds the LIVE effective scope set (empty on resolution failure).
    pub scopes: HashSet<String>,
    /// The verified-but-STALE JWT scope snapshot. Injected
    /// as `principal.token_attrs.scopes` - a separate attribute the live
    /// scopes never downgrade to; no platform policy may reference it.
    pub token_scopes: HashSet<String>,
    /// LIVE-resolved role names (from Sentin8:Auth, not the JWT).
    /// The engine injects them as the `roles` set attribute.
    pub roles: HashSet<String>,
    /// Env relation slice - feeds Shield entity-hierarchy edges.
    pub relations: Vec<crate::substrate::RelationRecord>,
    /// Optional extra principal attributes (handler-supplied, e.g. `amr`).
    pub principal_attrs: BTreeMap<String, RestrictedExpression>,
}

impl RequestCtx {
    pub fn new(
        subject_id: impl Into<String>,
        env_id: Uuid,
        org_id: Uuid,
        token_tp: impl Into<String>,
        scopes: HashSet<String>,
    ) -> Self {
        Self {
            subject_id: subject_id.into(),
            env_id,
            org_id,
            token_tp: token_tp.into(),
            scopes: scopes.clone(),
            token_scopes: scopes,
            roles: HashSet::new(),
            relations: Vec::new(),
            principal_attrs: BTreeMap::new(),
        }
    }

    /// Set the LIVE-resolved role names (fetched from Sentin8:Auth,
    /// never read from the JWT). Policies test `"role" in principal.roles`.
    pub fn with_roles(mut self, roles: HashSet<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Attach the env's relation slice - converted to Shield entity
    /// hierarchy `parents` edges at evaluation time (`in` operator).
    pub fn with_relations(mut self, records: Vec<crate::substrate::RelationRecord>) -> Self {
        self.relations = records;
        self
    }
}

/// Evaluation target: action id (`{service}:{resource}:{action}`) plus the
/// optional resource uid + attributes (handler-supplied, e.g. `amount`).
#[derive(Debug, Clone)]
pub struct EvalTarget {
    pub action: String,
    /// Resource entity uid string, e.g. `Resource::"m1"`. Defaults to `"*"` id.
    pub resource_id: String,
    pub resource_attrs: BTreeMap<String, RestrictedExpression>,
}

impl EvalTarget {
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            resource_id: "*".into(),
            resource_attrs: BTreeMap::new(),
        }
    }

    pub fn with_resource(mut self, id: impl Into<String>) -> Self {
        self.resource_id = id.into();
        self
    }

    pub fn with_attr(mut self, name: impl Into<String>, expr: RestrictedExpression) -> Self {
        self.resource_attrs.insert(name.into(), expr);
        self
    }
}

// ── Decision ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase", tag = "decision")]
pub enum Decision {
    Allow,
    Deny { reason: String },
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// What the evaluator should do with the result for a given mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforce {
    /// Reject on deny (mode = enforced).
    Yes,
    /// Log would-deny, always allow (mode = shadow).
    No,
}

// ── Loaded policy sets ──────────────────────────────────────────────────

/// A validated, compiled policy set held in the engine cache.
#[derive(Debug, Clone)]
pub struct CompiledSet {
    pub record: PolicySetRecord,
    pub shield: PolicySet,
}

/// Hot-reloadable cache key: `(env_id, policy_set_name)`. A service only loads
/// rows for its own `service` value, so the service column is not part of it.
pub type CacheKey = (Uuid, String);

/// Load result for `PolicyEngine::load` / hot-reload: the new cache contents.
pub type Cache = BTreeMap<CacheKey, CompiledSet>;

// ── Engine ──────────────────────────────────────────────────────────────

/// The per-service policy engine. Holds an `ArcSwap` cache
/// of compiled sets; evaluation is pure, in-process, µs-scale, no I/O.
pub struct PolicyEngine {
    service: String,
    cache: ArcSwap<Cache>,
    authorizer: Authorizer,
    /// Single-flight for the synchronous reload-on-empty-coverage retry:
    /// concurrent requests hitting a not-yet-loaded env collapse into ONE
    /// reload attempt.
    reload_lock: AsyncMutex<()>,
}

impl PolicyEngine {
    /// Create an empty engine for `service` (colon service_type). Call `load`
    /// at boot - an unparsable policy set makes `load` fail so the caller can
    /// refuse to start (fail-closed at boot).
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            cache: ArcSwap::from_pointee(BTreeMap::new()),
            authorizer: Authorizer::new(),
            reload_lock: AsyncMutex::new(()),
        }
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    /// True when the cache holds at least one set for `env_id` (policy
    /// sync-reload branch predicate).
    pub fn has_sets_for_env(&self, env_id: Uuid) -> bool {
        self.cache.load().keys().any(|(env, _)| *env == env_id)
    }

    /// Load all enabled rows for this service from `policy_sets`
    /// via the `sentin8_boot_policy_load(service)` SECURITY DEFINER function
    /// Boot runs BEFORE any tenant context exists,
    /// so the table's `sentin8_context_initialized()` RLS gate would hide
    /// every row from a NOBYPASSRLS service role (0 rows → fail-closed deny
    /// on everything). The function filters `service = $1 AND enabled`
    /// server-side - a service can only ever load its own rows; the admin
    /// API keeps reading the table directly under the caller's request
    /// context. ANY invalid set fails the whole load - services refuse to
    /// start on broken policy.
    pub async fn load(&self, pool: &sqlx::PgPool) -> Result<usize, PolicyError> {
        let rows: Vec<PolicySetRecord> = sqlx::query_as!(
            PolicySetRecord,
            r#"SELECT id AS "id!", env_id AS "env_id!", service AS "service!",
                      policy_set_name AS "policy_set_name!",
                      description AS "description!", policies AS "policies!",
                      schema,
                      origin AS "origin!: PolicyOrigin",
                      mode AS "mode!: PolicyMode", version AS "version!",
                      enabled AS "enabled!"
               FROM sentin8_boot_policy_load($1)"#,
            self.service,
        )
        .fetch_all(pool)
        .await?;
        let cache = compile_rows(self.service.as_str(), rows)?;
        let n = cache.len();
        self.cache.store(Arc::new(cache));
        Ok(n)
    }

    /// Replace the cache with `rows` (used by tests and by the hot-reload
    /// handler which has already fetched the fresh rows). Fails on any invalid
    /// row - the previous cache is retained (atomic swap, fail-closed).
    pub fn load_from_rows(&self, rows: Vec<PolicySetRecord>) -> Result<(), PolicyError> {
        let cache = compile_rows(self.service.as_str(), rows)?;
        self.cache.store(Arc::new(cache));
        Ok(())
    }

    /// Validate + upsert a single set into the cache (hot-reload path). A
    /// disabled or invalid set REPLACES the cached entry (invalid → removed,
    /// disabled → removed) so evaluation falls back to no-match deny.
    pub fn upsert(&self, record: PolicySetRecord) -> Result<(), PolicyError> {
        let key: CacheKey = (record.env_id, record.policy_set_name.clone());
        let guard = self.cache.load();
        let mut next: Cache = BTreeMap::clone(&*guard);
        drop(guard);
        if record.service != self.service || !record.enabled {
            // Not ours, or disabled: ensure it is absent (no-match → deny).
            next.remove(&key);
        } else {
            validate_record_text(
                &record.policy_set_name,
                &record.policies,
                record.schema.as_deref(),
            )?;
            let shield = compile_set(&record)?;
            next.insert(key, CompiledSet { record, shield });
        }
        self.cache.store(Arc::new(next));
        Ok(())
    }

    /// Remove a set from the cache (e.g. deleted/disabled via event).
    pub fn remove(&self, env_id: Uuid, policy_set_name: &str) {
        let key: CacheKey = (env_id, policy_set_name.to_string());
        let guard = self.cache.load();
        let mut next: Cache = BTreeMap::clone(&*guard);
        drop(guard);
        next.remove(&key);
        self.cache.store(Arc::new(next));
    }

    /// Evaluate a request against every cached set matching `(env_id, …)`.
    ///
    /// Semantics: ALL matching sets are evaluated (shadow sets
    /// always contribute their would-deny signal); an `enforced` set's Shield
    /// `Deny` (no-match, forbid, or error) short-circuits → reject. If every
    /// set allows, the request proceeds.
    ///
    /// **Fail-closed on no coverage: if NO cached set exists
    /// for the request's env, the decision is DENY.** "No matching permit →
    /// deny" applies equally to "no matching set" - an env whose sets failed
    /// to load (or were never seeded) must not silently fall open. Every
    /// platform service seeds its `scope-mirror` set at enroll (16 sets,
    /// enforced); the empty-cache case only arises on a broken deploy, which
    /// must fail closed.
    pub fn evaluate(&self, ctx: &RequestCtx, target: &EvalTarget) -> EvalOutcome {
        let guard = self.cache.load();
        let cache: &Cache = &guard;
        let mut shadow_deny: Option<String> = None;
        let mut enforced_deny: Option<String> = None;
        let mut sets_for_env = 0usize;
        for ((env_id, _name), compiled) in cache.iter() {
            if *env_id != ctx.env_id {
                continue;
            }
            sets_for_env += 1;
            let shield_decision = self.eval_set(compiled, ctx, target);
            if shield_decision != ShieldDecision::Allow {
                let reason = format!(
                    "set '{}' ({})",
                    compiled.record.policy_set_name,
                    reason_text(shield_decision)
                );
                match compiled.record.mode {
                    PolicyMode::Enforced => {
                        // Short-circuit: enforced deny is final. First one wins.
                        if enforced_deny.is_none() {
                            enforced_deny = Some(reason);
                            break;
                        }
                    }
                    PolicyMode::Shadow => {
                        // First shadow deny reason wins; keep scanning for an
                        // enforced deny that may still reject the request.
                        if shadow_deny.is_none() {
                            shadow_deny = Some(reason);
                        }
                    }
                }
            }
        }
        if let Some(reason) = enforced_deny {
            return EvalOutcome {
                enforce_decision: Decision::Deny {
                    reason: "policy".into(),
                },
                would_deny: Some(reason),
                shadow_deny,
            };
        }
        // Fail-closed on no coverage: zero cached sets for this env.
        if sets_for_env == 0 {
            tracing::warn!(
                env_id = %ctx.env_id,
                service = %self.service,
                "policy.no_set_for_env - no policy set loaded for this env; denying (fail-closed)"
            );
            return EvalOutcome {
                enforce_decision: Decision::Deny {
                    reason: "policy".into(),
                },
                would_deny: Some("no policy set loaded for env".to_string()),
                shadow_deny: None,
            };
        }
        EvalOutcome {
            enforce_decision: Decision::Allow,
            would_deny: None,
            shadow_deny,
        }
    }

    /// Evaluate one compiled set (pure Shield call; eval errors → Deny).
    fn eval_set(
        &self,
        compiled: &CompiledSet,
        ctx: &RequestCtx,
        target: &EvalTarget,
    ) -> ShieldDecision {
        let principal = build_principal(ctx);
        let principal_uid = principal.clone();
        let action = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").expect("static"),
            EntityId::from_str(target.action.as_str()).expect("action id"),
        );
        let resource = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Resource").expect("static"),
            EntityId::from_str(target.resource_id.as_str()).expect("resource id"),
        );
        // Principal attrs: scopes + token_tp are ALWAYS set (policies rely on
        // them); handler-supplied attrs are merged after (never override).
        let mut attrs: BTreeMap<String, RestrictedExpression> = BTreeMap::new();
        let scope_list: Vec<RestrictedExpression> = ctx
            .scopes
            .iter()
            .map(|s| RestrictedExpression::new_string(s.clone()))
            .collect();
        attrs.insert("scopes".into(), RestrictedExpression::new_set(scope_list));
        attrs.insert(
            "token_tp".into(),
            RestrictedExpression::new_string(ctx.token_tp.clone()),
        );
        attrs.insert(
            "subject_id".into(),
            RestrictedExpression::new_string(ctx.subject_id.clone()),
        );
        attrs.insert(
            "env_id".into(),
            RestrictedExpression::new_string(ctx.env_id.to_string()),
        );
        // LIVE roles: injected as a set attribute - policies test
        // `"role" in principal.roles`. Empty set = role-less principal (deny
        // on role-gated rules, fail-closed).
        let role_list: Vec<RestrictedExpression> = ctx
            .roles
            .iter()
            .map(|r| RestrictedExpression::new_string(r.clone()))
            .collect();
        attrs.insert("roles".into(), RestrictedExpression::new_set(role_list));
        // The verified-but-STALE JWT scope snapshot rides
        // under a dedicated namespace so live scopes and the snapshot can
        // never be confused. No platform policy may reference `token_attrs`.
        let token_scope_list: Vec<RestrictedExpression> = ctx
            .token_scopes
            .iter()
            .map(|s| RestrictedExpression::new_string(s.clone()))
            .collect();
        let mut token_attrs: BTreeMap<String, RestrictedExpression> = BTreeMap::new();
        token_attrs.insert(
            "scopes".into(),
            RestrictedExpression::new_set(token_scope_list),
        );
        attrs.insert(
            "token_attrs".into(),
            RestrictedExpression::new_record(token_attrs)
                .expect("token_attrs record construction - static keys"),
        );
        for (k, v) in &ctx.principal_attrs {
            attrs.entry(k.clone()).or_insert_with(|| v.clone());
        }
        // Relation hierarchy edges: every tuple whose subject_id
        // matches the caller contributes its object as a parent edge on the
        // principal entity (matching by id - the record's subject_type is
        // authoring metadata; the principal entity here is always
        // `User::"<subject_id>"`). Entity types are canonicalized to
        // PascalCase: Shield type names are case-sensitive and policy
        // literals are conventionally capitalized (`Group::"fx-ops"`), so a
        // tuple row with subject_type 'group' must land on type `Group`.
        let parents: HashSet<EntityUid> = {
            let e: HashSet<EntityUid> = ctx
                .relations
                .iter()
                .filter(|r| r.subject_id == ctx.subject_id)
                .filter_map(|r| {
                    parse_shield_uid(&format!(
                        "{}::\"{}\"",
                        canonicalize_type(&r.object_type),
                        r.object_id
                    ))
                })
                .collect();
            e
        };
        let parent_uids_fallback = parents.clone();
        let principal = Entity::new(principal.clone(), attrs.into_iter().collect(), parents)
            .unwrap_or_else(|e| {
                // Attr eval failed - build a bare entity; the policy decision will
                // deny on missing attrs (fail-closed) rather than panic. Keep the
                // hierarchy edges in the fallback (they are independent of
                // attributes - dropping them would silently change decisions).
                tracing::warn!(error = %e, "principal attr eval failed; using bare entity");
                Entity::new_no_attrs(principal.clone(), parent_uids_fallback)
            });
        let resource_entity = Entity::new(
            resource.clone(),
            target.resource_attrs.clone().into_iter().collect(),
            HashSet::new(),
        )
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "resource attr eval failed; using bare entity");
            Entity::new_no_attrs(resource.clone(), HashSet::new())
        });
        // Relation objects must exist as entities for `principal in
        // Group::"x"` to evaluate - Shield hierarchy checks walk the graph,
        // so referenced parents are materialized as bare entities (no
        // attrs). Deduped by UID; a build failure skips that edge (the
        // hierarchy rule then denies - fail-closed).
        let mut all_entities = vec![principal, resource_entity];
        let mut seen_parents: HashSet<EntityUid> = HashSet::new();
        for r in &ctx.relations {
            let uid_str = format!("{}::\"{}\"", canonicalize_type(&r.object_type), r.object_id);
            if let Some(puid) = parse_shield_uid(&uid_str) {
                if seen_parents.insert(puid.clone()) {
                    all_entities.push(Entity::new_no_attrs(puid, HashSet::new()));
                }
            }
        }
        let entities = Entities::from_entities(all_entities, None).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "entities build failed; using empty set");
            Entities::empty()
        });
        let request = Request::new(
            principal_uid,
            action,
            resource,
            shield::Context::empty(),
            None,
        )
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "request build failed; using fallback uids");
            let p = EntityUid::from_type_name_and_id(
                EntityTypeName::from_str("User").expect("static"),
                EntityId::from_str("unknown").expect("static"),
            );
            Request::new(p.clone(), p.clone(), p, shield::Context::empty(), None)
                .expect("fallback request")
        });
        let response = self
            .authorizer
            .is_authorized(&request, &compiled.shield, &entities);
        // Surface Shield's own eval errors (missing attrs, hierarchy issues)
        // in the log - the deny path must be explainable in the audit trail.
        for err in response.diagnostics().errors() {
            tracing::debug!(policy_error = %err, "shield evaluation error (deny path)");
        }
        response.decision()
    }
}

/// Full evaluation result.
#[derive(Debug, Clone)]
pub struct EvalOutcome {
    /// The decision that must be enforced (step-7 verdict). `Allow` unless an
    /// `enforced` set denied.
    pub enforce_decision: Decision,
    /// Set to Some when an enforced set denied (for audit emission).
    pub would_deny: Option<String>,
    /// Set to Some when a shadow set denied (emit `policy.would_deny`).
    pub shadow_deny: Option<String>,
}

impl EvalOutcome {
    pub fn is_allow(&self) -> bool {
        self.enforce_decision.is_allow()
    }

    /// True when the enforced deny came from the fail-closed no-coverage
    /// branch (`policy.no_set_for_env`) - the predicate for the
    /// sync-reload-on-empty retry (runtime `check_policy`). The no-coverage
    /// text rides `would_deny`; the enforce reason is the coarse "policy".
    pub fn enforce_deny_reason_is_no_coverage(&self) -> bool {
        self.would_deny
            .as_deref()
            .map(|r| r.contains("no policy set loaded for env"))
            .unwrap_or(false)
    }
}

fn reason_text(d: ShieldDecision) -> String {
    match d {
        ShieldDecision::Allow => "allow".into(),
        ShieldDecision::Deny => "deny".into(),
    }
}

fn build_principal(ctx: &RequestCtx) -> EntityUid {
    EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("User").expect("static"),
        EntityId::from_str(ctx.subject_id.as_str())
            .unwrap_or_else(|_| EntityId::from_str("unknown").expect("static")),
    )
}

/// Canonicalize an author-supplied entity type to Shield's PascalCase
/// convention: `group` → `Group`, `user_group` → `UserGroup`. Idempotent -
/// already-capitalized names pass through unchanged.
fn canonicalize_type(t: &str) -> String {
    let mut c = t.chars();
    match c.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + c.as_str(),
        None => String::new(),
    }
}

/// Parse a `Type::"id"` string (as produced by `relations_to_parents`) back
/// into an `EntityUid` for the hierarchy edges. Malformed entries are
/// skipped (they can never match a policy literal, which is the safe
/// direction).
fn parse_shield_uid(s: &str) -> Option<EntityUid> {
    use std::str::FromStr;
    let (tn, id) = s.split_once("::\"")?;
    let id = id.strip_suffix('"')?;
    Some(EntityUid::from_type_name_and_id(
        EntityTypeName::from_str(tn).ok()?,
        EntityId::from_str(id).ok()?,
    ))
}

// ── Compilation ─────────────────────────────────────────────────────────

fn compile_rows(service: &str, rows: Vec<PolicySetRecord>) -> Result<Cache, PolicyError> {
    let mut cache = BTreeMap::new();
    for record in rows {
        if record.service != service {
            return Err(PolicyError::InvalidRecord(format!(
                "row service '{}' does not match engine service '{}'",
                record.service, service
            )));
        }
        if !record.enabled {
            continue;
        }
        let shield = compile_set(&record)?;
        cache.insert(
            (record.env_id, record.policy_set_name.clone()),
            CompiledSet { record, shield },
        );
    }
    Ok(cache)
}

/// Test-only bridge: compile rows into a fresh engine (unit tests exercise the
/// same compile path production uses). Not exported to consumers.
#[cfg(test)]
pub(crate) fn compile_rows_for_tests(
    engine: &PolicyEngine,
    rows: Vec<PolicySetRecord>,
) -> Result<(), PolicyError> {
    engine.load_from_rows(rows)
}

/// Test-only accessor to the statement splitter (unit tests).
#[cfg(test)]
pub(crate) fn test_only_split_statements(text: &str) -> Vec<String> {
    split_statements(text)
}

fn compile_set(record: &PolicySetRecord) -> Result<PolicySet, PolicyError> {
    // Re-validate here so boot/hot-reload both fail closed on bad text.
    validate_record_text(
        record.policy_set_name.as_str(),
        record.policies.as_str(),
        record.schema.as_deref(),
    )?;
    let mut pset = PolicySet::new();
    parse_statements(
        record.policy_set_name.as_str(),
        record.policies.as_str(),
        &mut pset,
    )?;
    Ok(pset)
}
// ── (bridge types removed - the CLI/admin paths project columns directly) ──
