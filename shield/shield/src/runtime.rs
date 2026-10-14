// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Shared service-side integration for `sentin8-shield`.
//!
//! Every adopting service wires the same three pieces:
//!
//! 1. **Boot**: `PolicyEngine::new("<service>")` + `engine.load(&pool)` —
//!    an error means invalid policy text → the service refuses to start.
//! 2. **Hot-reload**: `spawn_hot_reload(pool, bus_client, engine)` consumes
//!    the `policy` stream as a direct consumer via SSE push (one
//!    long-lived stream per process, never a periodic HTTP poll) —
//!    policy-set text, relation tuples, attribute events, and identity-
//!    invalidation triggers all dispatch here.
//! 3. **Handlers**: `require_auth` (verify + tenant) then
//!    `require_policy(engine, ctx, action)` — step 5 is THE decision.
//!
//! The axum-facing glue is small: services build the `RequestCtx` from their
//! verified token (each service's `auth.rs` knows its claims type — the
//! engine consumes the resolved values, never re-verifying tokens).

use std::collections::HashSet;
use std::sync::Arc;

use axum::http::StatusCode;

use sentin8_outbox::PolicyUpdatedEnvelope;

use crate::{Decision, EvalOutcome, EvalTarget, PolicyEngine, RequestCtx, RoleResolver};

// ── Consolidated service bridge (replaces 13 per-service shims) ─────────

/// Build the boot engine for a service (colon service_type). Empty until
/// `load` runs — an unparsable set fails `load`, and the caller refuses to
/// start (fail-closed at boot).
pub fn engine_for(service: impl Into<String>) -> Arc<PolicyEngine> {
    Arc::new(PolicyEngine::new(service))
}

/// Build the cert-presenting Bus client used by the hot-reload consumer
/// (auth DESIGN §4.3f): the `{service}-policy` certificate is
/// the workload identity — minted from Acme on a first boot (retrying
/// while Acme comes up), presented in the TLS handshake on every call.
/// No DCR, no token. Every service calls this with its own colon
/// service_type — one implementation instead of 13 identical shims.
pub async fn policy_bus_client(service: &str) -> sentin8_bus_client::BusClient {
    let cfg = sentin8_config::Sentin8Config::from_env();
    let workload = format!("{service}-policy");
    loop {
        match sentin8_bus_client::BusClient::for_workload(
            cfg.sentin8_bus_url().as_str(),
            cfg.sentin8_auth_issuer().as_str(),
            &workload,
        )
        .await
        {
            Ok(client) => return client,
            Err(e) => {
                // First birth: Acme may still be coming up. The consumer
                // loop retries via its own reconnect; keep the boot-path
                // wait bounded and quiet.
                tracing::debug!(error = %e, workload, "policy bus client: certificate not ready yet");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

/// The full policy boot: boot load (refuse-to-start on
/// invalid text) + shared step-5 deps + hot-reload direct consumer + stat
/// emitter. The SHELL runs this for every shell service in boot step 8 —
/// services consume `core.admin.policy` and never call this. Only binaries
/// that do NOT boot on the shell (captain, web, acme) call it once in their
/// own boot. A load failure aborts boot (fail-closed).
pub async fn boot_full(
    pool: &sqlx::PgPool,
    issuer: &str,
    service: &str,
    engine: &Arc<PolicyEngine>,
) -> anyhow::Result<()> {
    engine
        .load(pool)
        .await
        .map_err(|e| anyhow::anyhow!("policy engine boot load failed: {e}"))?;
    init_shared_deps(issuer, pool.clone());
    let bus = policy_bus_client(service).await;
    spawn_hot_reload(pool.clone(), bus, Arc::clone(engine));
    // Deny/would-deny decision telemetry — failure degrades to log-only.
    // Transport is MemBus `stat.telemetry` Pub/Sub (SDD §2.3) — no pool,
    // no DCR workload; stat resolves the slug server-side at ingest.
    crate::stat_emit::init_stat_emitter_for_service(service).await;
    Ok(())
}

/// Shared role resolver keyed per process (one per service binary). The
/// Auth base URL is the platform issuer.
pub fn shared_role_resolver(auth_issuer: &str) -> Arc<RoleResolver> {
    use std::sync::OnceLock;
    static RESOLVER: OnceLock<Arc<RoleResolver>> = OnceLock::new();
    RESOLVER
        .get_or_init(|| Arc::new(RoleResolver::new(auth_issuer)))
        .clone()
}

/// Build the evaluation context from verified token fields (steps 1–4 ran).
/// `scope_claim` is the space-separated resolved scope; org_id is nil for
/// services whose tokens do not carry org context (policy rules key on env).
pub fn request_ctx(
    subject_id: &str,
    env_id: uuid::Uuid,
    token_tp: &str,
    scope_claim: &str,
) -> RequestCtx {
    let scopes: HashSet<String> = scope_claim
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    RequestCtx::new(
        subject_id.to_string(),
        env_id,
        uuid::Uuid::nil(),
        token_tp.to_string(),
        scopes,
    )
}

/// The step-5 evaluation with LIVE role resolution: resolves the caller's role
/// names from Sentin8:Auth (the endpoint re-verifies the raw Bearer token
/// server-side — the resolver never trusts caller-supplied role lists),
/// builds the context, then evaluates. A role change takes effect on the
/// next request. Resolution failure → empty roles → role-gated rules deny
/// (fail-closed); scope-based rules are unaffected.
#[allow(clippy::too_many_arguments)]
pub async fn check_policy_with_roles(
    engine: &PolicyEngine,
    resolver: &RoleResolver,
    subject_id: &str,
    env_id: uuid::Uuid,
    token_tp: &str,
    scope_claim: &str,
    access_token: &str,
    action: &str,
) -> Result<EvalOutcome, (StatusCode, String)> {
    let mut ctx = request_ctx(subject_id, env_id, token_tp, scope_claim);
    match resolver.resolve(env_id, subject_id, access_token).await {
        Ok(roles) => ctx = ctx.with_roles(roles),
        Err(e) => {
            tracing::warn!(error = %e, subject = %subject_id, env_id = %env_id,
                "role resolution failed; evaluating with empty roles (fail-closed)");
        }
    }
    check_policy(engine, &ctx, action).await
}

/// Step 5 glue for the SDK `AuthContext` (used by every service except
/// bus, whose local context type carries the same three fields). Converts
/// an enforced deny into HTTP 403; logs shadow would-deny. This is the
/// single implementation the per-service shims re-export as
/// `require_policy` — handlers keep calling `crate::policy::require_policy`.
///
/// Step 5 is the ONLY access gate: this is the FULL live
/// evaluation — live effective scopes + roles, the env's relation
/// slice, and principal attributes. `headers` must be the
/// request's HeaderMap so the raw Bearer drives live identity resolution;
/// on resolution failure the live sets are empty and scope/role-gated rules
/// deny (fail-closed). The plain scope-snapshot evaluation
/// remains available as [`check_policy`] for bus-style callers that cannot
/// pass headers.
pub async fn require_policy(
    engine: &PolicyEngine,
    a: &sentin8_auth_client::AuthContext,
    headers: &axum::http::HeaderMap,
    target: EvalTarget,
) -> Result<EvalOutcome, (StatusCode, String)> {
    evaluate_full(
        engine,
        a.claims.sub.as_str(),
        a.env_id(),
        a.claims.token_tp.as_str(),
        a.claims.scope.as_str(),
        headers,
        &target.action,
    )
    .await
}

/// Everything step 5 needs beyond the engine: the per-process role resolver
/// plus an optional pool for the relation/attribute slices. Services set the
/// pool via [`set_shared_pool`] at boot; the resolver is built lazily from
/// the platform issuer.
pub struct PolicyDeps {
    pub resolver: Arc<RoleResolver>,
    pool: std::sync::OnceLock<sqlx::PgPool>,
}

static SHARED_DEPS: std::sync::OnceLock<PolicyDeps> = std::sync::OnceLock::new();

/// Initialize the shared step-5 dependencies once per process. Called by
/// each service's `build_state` with the platform issuer + boot pool.
pub fn init_shared_deps(auth_issuer: &str, pool: sqlx::PgPool) {
    let deps = PolicyDeps {
        resolver: shared_role_resolver(auth_issuer),
        pool: std::sync::OnceLock::new(),
    };
    let _ = deps.pool.set(pool);
    let _ = SHARED_DEPS.set(deps);
}

/// Access the shared deps (None before init — tests).
pub fn shared_deps() -> Option<&'static PolicyDeps> {
    SHARED_DEPS.get()
}

fn shared_pool() -> Option<sqlx::PgPool> {
    SHARED_DEPS.get().and_then(|d| d.pool.get().cloned())
}

/// Extract the raw Bearer token from request headers (passed through to
/// Auth's userinfo endpoint for live-role resolution — the endpoint
/// re-verifies it server-side).
pub fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .or_else(|| headers.get("authorization"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Full step-5 evaluation for the pilot path: live roles when the
/// headers carry a Bearer token + shared deps are initialized, the env's
/// relation slice, and the caller's principal attributes.
/// Every substrate failure degrades independently (fail-closed per surface:
/// no roles = role rules deny; no edges = hierarchy rules deny; no attrs =
/// attr rules deny) — non-dependent rules still decide.
pub async fn evaluate_full(
    engine: &PolicyEngine,
    subject_id: &str,
    env_id: uuid::Uuid,
    token_tp: &str,
    scope_claim: &str,
    headers: &axum::http::HeaderMap,
    action: &str,
) -> Result<EvalOutcome, (StatusCode, String)> {
    let mut ctx = request_ctx(subject_id, env_id, token_tp, scope_claim);
    if let Some(deps) = SHARED_DEPS.get() {
        // Live identity: roles AND the live effective scope set —
        // ONE userinfo call resolves both. On failure both stay empty
        // (scope/role-gated rules deny — fail-closed); the verified
        // JWT scope snapshot remains available only as `token_attrs.scopes`
        // (see below), which no platform policy references.
        if let Some(token) = bearer_token(headers) {
            match deps
                .resolver
                .resolve_identity(env_id, subject_id, &token)
                .await
            {
                Ok((roles, live_scopes)) => {
                    ctx = ctx.with_roles(roles);
                    ctx.scopes = live_scopes;
                }
                Err(e) => {
                    tracing::warn!(error = %e, subject = %subject_id,
                        "identity resolution failed; evaluating with empty live scopes/roles (fail-closed)");
                    emit_stat_identity_failure(engine.service(), &ctx);
                }
            }
        } else {
            emit_stat_identity_failure(engine.service(), &ctx);
        }
        // Relation slice.
        if let Some(pool) = shared_pool() {
            match crate::substrate::load_relations(&pool, env_id, engine.service()).await {
                Ok(slice) => ctx = ctx.with_relations(slice),
                Err(e) => tracing::warn!(error = %e, env_id = %env_id,
                    "relation slice load failed; evaluating without hierarchy edges"),
            }
            // Principal attributes — injected as restricted exprs.
            match crate::substrate::load_principal_attrs(&pool, env_id, subject_id).await {
                Ok(attrs) => {
                    for a in attrs {
                        if let Some(expr) = crate::substrate::json_to_restricted_expr(&a.attr_value)
                        {
                            ctx.principal_attrs.entry(a.attr_key).or_insert(expr);
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, subject = %subject_id,
                    "principal attr load failed; evaluating without custom attributes"),
            }
        }
    }
    // The verified-but-stale JWT scope snapshot rides on the context as
    // `token_scopes` — the engine injects it as `principal.token_attrs.scopes`
    // (a separate attribute; the LIVE set in `ctx.scopes` is always
    // `principal.scopes`). No platform policy may reference `token_attrs`
    // (the stale JWT snapshot).
    ctx.token_scopes = scope_claim.split_whitespace().map(str::to_string).collect();
    check_policy(engine, &ctx, action).await
}

/// Step 5 glue: evaluate and convert an enforced deny into HTTP 403.
/// Shadow would-deny results are logged (the caller may additionally emit
/// to Stat). This is the single implementation every service shim re-exports.
pub async fn check_policy(
    engine: &PolicyEngine,
    ctx: &RequestCtx,
    action: &str,
) -> Result<EvalOutcome, (StatusCode, String)> {
    let mut outcome = engine.evaluate(ctx, &EvalTarget::new(action.to_string()));

    // Sync-reload-on-empty-coverage: when
    // the cache holds NO set for this env (freshly-created env, hot-reload
    // event still in the outbox→Bus→SSE pipeline), retry the load once
    // synchronously before failing closed. Read-your-writes for provisioning
    // — the set rows are already committed; a failed reload keeps the empty
    // cache → deny (fail-closed preserved). Single-flight via the engine's
    // reload lock. The re-evaluated outcome falls through to the SAME
    // deny conversion below — returning `Ok(deny-outcome)` here would let
    // a no-coverage env (unknown env, mid-provision env) bypass step 5
    // entirely (deny treated as allow by every handler).
    if outcome.enforce_deny_reason_is_no_coverage() && !engine.has_sets_for_env(ctx.env_id) {
        if let Some(pool) = shared_pool() {
            let _guard = engine.reload_lock.lock().await;
            if !engine.has_sets_for_env(ctx.env_id) {
                // Self-heal empty coverage (VDC §VDC.6): the env-init seed
                // (event-driven, service:updated) may not have run yet for
                // this env (event consumed before the seed code deployed,
                // relay lag, or a skipped enable). Copy the service's
                // SYSTEM-env `origin='platform'` template sets into this
                // env — the same statement the ledger/fdx env-init
                // consumers run. Idempotent (`ON CONFLICT DO NOTHING`);
                // requires the substrate's SELECT/INSERT grant on
                // `sys.policy_sets` for this service's role.
                // The policy crate does not depend on sentin8-config (the
                // dependency direction is one-way); the SYSTEM env UUID is
                // the same constant (uuid::Uuid::from_u128(2)).
                let sys_env = uuid::Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0002);
                // Same-transaction context (rule 2): the substrate's
                // INSERT policy is `WITH CHECK (sentin8_context_initialized())`
                // and the context is transaction-local — the copy runs
                // inside ONE explicit transaction with the context set on
                // the SAME connection.
                let seeded = async {
                    let mut tx = pool.begin().await?;
                    let _ = sqlx::query(
                        "SELECT sentin8_set_tenant_context($1, '', 'm2m', 'sys:admin')",
                    )
                    .bind(sys_env)
                    .execute(&mut *tx)
                    .await;
                    sqlx::query(
                        r#"INSERT INTO sys.policy_sets
                               (env_id, service, policy_set_name, description, policies, schema, origin, mode, version, enabled)
                           SELECT $2, service, policy_set_name, description, policies, schema,
                                  'platform', mode, 1, true
                             FROM sys.policy_sets
                            WHERE env_id = $1 AND service = $3 AND origin = 'platform' AND enabled
                           ON CONFLICT (env_id, service, policy_set_name) DO NOTHING"#,
                    )
                    .bind(sys_env)
                    .bind(ctx.env_id)
                    .bind(engine.service())
                    .execute(&mut *tx)
                    .await?;
                    tx.commit().await?;
                    Ok::<(), sqlx::Error>(())
                }
                .await;
                match seeded {
                    Ok(_) => match engine.load(&pool).await {
                        Ok(n) => tracing::info!(
                            env_id = %ctx.env_id,
                            service = %engine.service(),
                            sets = n,
                            "policy: sync reload on empty coverage — env sets loaded"
                        ),
                        Err(e) => tracing::warn!(
                            error = %e,
                            env_id = %ctx.env_id,
                            "policy: sync reload on empty coverage FAILED — denying (fail-closed)"
                        ),
                    },
                    Err(e) => tracing::warn!(
                        error = %e,
                        env_id = %ctx.env_id,
                        "policy: template seed on empty coverage FAILED — denying (fail-closed)"
                    ),
                }
            }
            // Re-evaluate INLINE (no recursive async call — Box::pin would be
            // needed otherwise): cache now holds the env's sets, or still empty
            // → the same fail-closed deny as before. The final outcome is
            // enforced by the shared tail below (Deny → Err 403).
            outcome = engine.evaluate(ctx, &EvalTarget::new(action.to_string()));
        }
    }
    if let Some(reason) = &outcome.shadow_deny {
        tracing::warn!(
            env_id = %ctx.env_id,
            subject = %ctx.subject_id,
            action,
            reason,
            "policy.would_deny"
        );
        // Audit sink (28.13): fire-and-forget Stat emission with the
        // decision inputs (self-contained envelope).
        crate::stat_emit::emit_decision(
            engine.service(),
            &ctx.subject_id,
            action,
            false,
            reason,
            &reason_set_name(reason),
        );
        // Shared audit trail: the would-deny lands in
        // `sentin8.audit_events` so admin UIs can surface it (Stat is
        // best-effort and invisible in dashboards). Same env context rules.
        emit_decision_audit(
            shared_pool().as_ref(),
            ctx,
            "policy.would_deny",
            engine.service(),
            action,
            false,
            reason,
            &reason_set_name(reason),
        );
    }
    match &outcome.enforce_decision {
        Decision::Allow => Ok(outcome),
        Decision::Deny { reason } => {
            // Enforced-deny visibility (the produce 500
            // storm was invisible because the ENFORCED deny path logged
            // nothing — only shadow would-deny got a warn). The reason text
            // here is the matched set + verdict (`set 'scope-mirror' (deny)`)
            // or the fail-closed no-coverage text.
            tracing::warn!(
                env_id = %ctx.env_id,
                subject = %ctx.subject_id,
                action,
                reason,
                token_tp = %ctx.token_tp,
                "policy.enforce_deny"
            );
            crate::stat_emit::emit_decision(
                engine.service(),
                &ctx.subject_id,
                action,
                true,
                reason,
                &reason_set_name(reason),
            );
            emit_decision_audit(
                shared_pool().as_ref(),
                ctx,
                "policy.deny",
                engine.service(),
                action,
                true,
                reason,
                &reason_set_name(reason),
            );
            Err((
                StatusCode::FORBIDDEN,
                format!("forbidden by policy ({reason})"),
            ))
        }
    }
}

/// Best-effort audit-trail write for a policy decision.
///
/// Every `policy.deny` / `policy.would_deny` ALSO lands in
/// `sentin8.audit_events` (the shared audit sink all services can INSERT;
/// `sentin8_stat_service` can read) so the policy UIs can render a decision
/// feed without depending on the optional Stat pipeline. Fire-and-forget on
/// a fresh pooled connection: set the caller's env context FIRST, then
/// INSERT on the same connection (sqlx 0.8 does not `DISCARD ALL` on
/// release — session-local GUCs persist across acquires, so the
/// context-on-connection pattern is the established safe shape). Failure is
/// logged and never propagated — audit must not be able to fail a request.
#[allow(clippy::too_many_arguments)]
fn emit_decision_audit(
    pool: Option<&sqlx::PgPool>,
    ctx: &RequestCtx,
    audit_action: &str,
    service: &str,
    action: &str,
    enforced: bool,
    reason: &str,
    set_name: &str,
) {
    let Some(pool) = pool else {
        return; // no shared pool (tests / bus-style callers) — log-only
    };
    let pool = pool.clone();
    let subject = ctx.subject_id.clone();
    let env_id = ctx.env_id;
    let token_tp = ctx.token_tp.clone();
    let reason = reason.to_string();
    let set_name = set_name.to_string();
    let service = service.to_string();
    let action = action.to_string();
    let audit_action = audit_action.to_string();
    // tokio::spawn: the request path never waits for the audit write.
    tokio::spawn(async move {
        if let Ok(mut conn) = pool.acquire().await {
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                .bind(env_id)
                .execute(&mut *conn)
                .await;
            if let Err(e) = sqlx::query(
                r#"INSERT INTO audit_journal (id, env_id, action, details) VALUES ($1, $2, $3, $4)"#,
            )
            .bind(uuid::Uuid::new_v4())
            .bind(env_id)
            .bind(service.rsplit(':').next().unwrap_or(&service))
            .bind(audit_action.clone())
            .bind(serde_json::json!({
                "action_id": action,
                "reason": reason,
                "policy_set": set_name,
                "enforced": enforced,
                "subject": subject,
                "token_tp": token_tp,
            }))
            .execute(&mut *conn)
            .await
            {
                tracing::debug!(error = %e, action = %audit_action, "policy decision audit write failed (log-only)");
            }
        }
    });
}

/// Fire-and-forget Stat emission for identity-resolution failures
/// (observability only — never a bypass signal). Silently
/// no-ops when the Stat emitter is not initialized for this process.
fn emit_stat_identity_failure(service: &str, ctx: &RequestCtx) {
    crate::stat_emit::emit_decision(
        service,
        &ctx.subject_id,
        "identity_resolution_failed",
        false,
        "live identity resolution failed; live scopes/roles empty",
        "identity-resolution",
    );
}

/// Enroll-time dry-run gate: verify a candidate platform set
/// permits its own referenced actions. For every statement of the form
/// `permit(principal, action == Action::"A", resource) when {
/// principal.scopes.contains("S"); }`, evaluate that exact action `A` with a
/// synthetic principal whose live scope set is exactly `{S}` (plus, for
/// role-keyed rules, the role in `principal.roles`) and require ALLOW.
///
/// This proves an `enforced` set does not deny its own grants (a typo'd scope
/// string, a wrong action id, or a stray `forbid` would lock the service out
/// at the next request). `shadow` sets skip the gate's failure (they never
/// block) but a hard parse error still fails (validation ran earlier).
pub fn dry_run_mirror(policies: &str, set_name: &str, service: &str) -> Result<(), String> {
    use crate::{EvalTarget, PolicyEngine, PolicyMode, PolicyOrigin, PolicySetRecord, RequestCtx};
    use std::collections::HashSet;

    // Extract (action, scope, role) triples from each permit statement.
    let mut checks: Vec<(String, Option<String>, Option<String>)> = Vec::new();
    for stmt in crate::split_statements(policies) {
        if !stmt.trim_start().starts_with("permit(") {
            // forbid / other statements: the engine's forbid-beats-permit
            // semantics are intentional authoring; nothing to dry-run.
            continue;
        }
        let action = stmt.find("Action::\"").and_then(|i| {
            stmt[i + 9..]
                .find('"')
                .map(|e| stmt[i + 9..i + 9 + e].to_string())
        });
        const SCOPE_NEEDLE: &str = "principal.scopes.contains(\"";
        let scope = stmt.find(SCOPE_NEEDLE).and_then(|i| {
            let rest = &stmt[i + SCOPE_NEEDLE.len()..];
            rest.find('"').map(|e| rest[..e].to_string())
        });
        const ROLE_NEEDLE: &str = "principal.roles.contains(\"";
        let role = stmt.find(ROLE_NEEDLE).and_then(|i| {
            let rest = &stmt[i + ROLE_NEEDLE.len()..];
            rest.find('"').map(|e| rest[..e].to_string())
        });
        // An unconstrained action (`permit(principal, action, resource)`)
        // mirrors a role/scope grant to every action — evaluate one
        // representative action per permit to prove the referenced
        // principal attribute is satisfiable.
        let representative = action
            .clone()
            .unwrap_or_else(|| format!("{service}:dry-run"));
        checks.push((representative, scope, role));
    }
    if checks.is_empty() {
        return Err(format!(
            "set '{set_name}': no permit statements found — an empty enforced set denies everything"
        ));
    }

    // Compile the candidate as the ONLY set of a synthetic engine.
    let engine = PolicyEngine::new(service);
    let env = uuid::Uuid::nil();
    let record = PolicySetRecord {
        id: uuid::Uuid::nil(),
        env_id: env,
        service: service.to_string(),
        policy_set_name: set_name.to_string(),
        description: String::new(),
        policies: policies.to_string(),
        schema: None,
        origin: PolicyOrigin::Platform,
        mode: PolicyMode::Enforced,
        version: 1,
        enabled: true,
    };
    engine
        .load_from_rows(vec![record])
        .map_err(|e| e.to_string())?;

    // One synthetic principal per permit — holds exactly what the permit
    // references (scope and/or role). The set must ALLOW its own action.
    for (action, scope, role) in &checks {
        let mut scopes: HashSet<String> = HashSet::new();
        if let Some(s) = scope {
            scopes.insert(s.clone());
        }
        let mut roles: HashSet<String> = HashSet::new();
        if let Some(r) = role {
            roles.insert(r.clone());
        }
        if scopes.is_empty() && roles.is_empty() {
            // Unconditional permit (no `when` clause): nothing to verify —
            // Shield evaluates the head directly.
            scopes.insert(format!("{service}:dry-run-unconditional"));
        }
        let ctx = RequestCtx::new(
            "dry-run-subject",
            env,
            uuid::Uuid::nil(),
            "user",
            scopes.clone(),
        )
        .with_roles(roles);
        // The set's own permit is the only rule — but the synthetic ctx must
        // carry `principal.scopes` as the LIVE set (same injection the real
        // path uses): RequestCtx.scopes IS the live set on the evaluate path.
        let outcome = engine.evaluate(&ctx, &EvalTarget::new(action.clone()));
        if outcome.enforce_decision != crate::Decision::Allow {
            return Err(format!(
                "action '{action}' would DENY under its own permit (scopes={scopes:?}); \
                 an enforced set must permit its own grants"
            ));
        }
    }
    Ok(())
}

/// Extract the matched rule-set name from a decision reason of the form
/// `set 'name' (deny)` (produced by `PolicyEngine::evaluate`). Best-effort —
/// falls back to `unknown` for free-form reasons.
fn reason_set_name(reason: &str) -> String {
    let start = reason.find("set '").map(|i| i + 5);
    let end = start.and_then(|s| reason[s..].find('\'').map(|e| s + e));
    match (start, end) {
        (Some(s), Some(e)) if e > s => reason[s..e].to_string(),
        _ => "unknown".to_string(),
    }
}

/// Consumer group identity for the policy subscription (shared by all
/// services; each consumer reloads only rows for its own `service`).
pub const POLICY_CONSUMER_GROUP: &str = "sentin8-shield-reload";

/// Stream family the policy runtime consumes: policy-set changes, relation
/// tuple changes, attribute changes, and identity-cache invalidation
/// triggers all ride this family.
pub const POLICY_STREAM_FAMILY: &str = "policy";

/// Reconnect delay after a dropped SSE stream.
const SSE_RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// Events that invalidate the per-process RoleResolver cache:
/// sys org/env provisioning granted tenant access, and Auth membership
/// mutations. Payload `{ env_id, subject_ids? }` / `{ user_id, ... }`.
fn invalidation_env_id(event_type: &str, payload: &serde_json::Value) -> Option<uuid::Uuid> {
    match event_type {
        "sentin8:sys:identity:updated"
        | "sentin8:auth:membership:created"
        | "sentin8:auth:membership:deleted" => {}
        _ => return None,
    }
    let env = payload
        .get("env_id")
        .or_else(|| payload.get("org_id")) // auth membership events carry org_id
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok());
    if env.is_none() {
        tracing::warn!(
            event_type,
            "identity invalidation event missing env/org id; ignoring"
        );
    }
    env
}

/// One SSE connection epoch: connect, read events, dispatch, ACK each.
/// Returns when the stream ends (caller reconnects with backoff).
async fn run_sse_epoch(
    bus_client: &sentin8_bus_client::BusClient,
    service: &str,
    pool: &sqlx::PgPool,
    engine: &Arc<PolicyEngine>,
) {
    let resp = match bus_client
        .sse_consume(POLICY_STREAM_FAMILY, POLICY_CONSUMER_GROUP)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, service, "policy SSE consume unavailable; retrying");
            return;
        }
    };
    tracing::info!(service, "policy hot-reload SSE connected");

    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buffer = String::new();
    while let Some(chunk_result) = stream.next().await {
        let chunk = match chunk_result {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, service, "policy SSE stream error; reconnecting");
                return;
            }
        };
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        // SSE events are separated by a blank line. Heartbeats (`: ...`)
        // carry no `data:` line and fall through to `continue`.
        while let Some(pos) = buffer.find("\n\n") {
            let event_text = buffer[..pos].to_string();
            buffer = buffer[pos + 2..].to_string();
            let Some(data_line) = event_text.lines().find_map(|l| l.strip_prefix("data: ")) else {
                continue; // comment/heartbeat or malformed frame
            };
            let Ok(msg) = serde_json::from_str::<sentin8_bus_contracts::Message>(data_line) else {
                tracing::warn!(service, "malformed policy SSE event; skipping");
                continue;
            };

            let mut needs_reload = false;
            match msg.event_type.as_str() {
                // Policy set/relation/attribute changes reload the engine
                // (sets, relations, attributes share the cache family).
                "sentin8:sys:policy:updated"
                | "sentin8:sys:policy:relations:updated"
                | "sentin8:sys:policy:attrs:updated" => {
                    match serde_json::from_value::<PolicyUpdatedEnvelope>(msg.payload.clone()) {
                        // service "*" = fleet-wide signal (e.g. sys seeded a
                        // new env's per-env sets — every service reloads).
                        Ok(env) if env.service == service || env.service == "*" => {
                            needs_reload = true
                        }
                        Ok(_) => {} // other services' events: ACK + ignore
                        Err(e) => {
                            tracing::warn!(error = %e, "malformed policy event; reloading anyway");
                            needs_reload = true;
                        }
                    }
                }
                // Identity-cache invalidation — fresh tenant
                // access must be visible on the next request, not after the
                // 30s TTL (role changes must be visible immediately after
                // org creation). Whole-env sweep; the resolver is per-process
                // so this cannot leak across tenants.
                "sentin8:sys:identity:updated"
                | "sentin8:auth:membership:created"
                | "sentin8:auth:membership:deleted" => {
                    if let Some(env_id) = invalidation_env_id(&msg.event_type, &msg.payload) {
                        if let Some(deps) = shared_deps() {
                            deps.resolver.invalidate_env(env_id);
                            tracing::info!(%env_id, service, "identity cache invalidated (policy event)");
                        }
                    }
                }
                _ => {}
            }
            let _ = bus_client
                .ack(POLICY_STREAM_FAMILY, POLICY_CONSUMER_GROUP, &msg.message_id)
                .await;
            if needs_reload {
                match engine.load(pool).await {
                    Ok(n) => tracing::info!(service, sets = n, "policy cache reloaded"),
                    Err(e) => tracing::error!(
                        error = %e,
                        "policy reload FAILED; previous cache retained"
                    ),
                }
            }
        }
    }
    tracing::info!(service, "policy SSE stream ended; reconnecting");
}

/// Spawn the direct-consumer hot-reload task. Boot-time load stays
/// authoritative; this task applies `sentin8:sys:policy:*` change events and
/// identity invalidation triggers.
///
/// Transport is `BusClient::sse_consume` — one long-lived
/// push stream per process. The HTTP batch `POST /v1/consume` endpoint must
/// NOT be polled periodically: 21 service processes × a 5s poll was
/// a fixed idle request budget on Sentin8:Bus.
pub fn spawn_hot_reload(
    pool: sqlx::PgPool,
    bus_client: sentin8_bus_client::BusClient,
    engine: Arc<PolicyEngine>,
) {
    tokio::spawn(async move {
        let service = engine.service().to_string();
        tracing::info!(service, "policy hot-reload consumer starting (SSE)");
        loop {
            run_sse_epoch(&bus_client, &service, &pool, &engine).await;
            tokio::time::sleep(SSE_RECONNECT_DELAY).await;
        }
    });
}
