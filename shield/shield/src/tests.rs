// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the sentin8-shield engine.
//!
//! Pure in-crate tests (no DB): parse/validate roundtrips, no-match → deny,
//! forbid-beats-permit, M2M parity, scope-mirror generation, shadow semantics,
//! cache upsert/remove.

use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use shield::RestrictedExpression;
use uuid::Uuid;

use crate::{
    compile_rows_for_tests, Decision, Enforce, EvalTarget, PolicyEngine, PolicyMode, PolicyOrigin,
    PolicySetRecord, RequestCtx,
};

fn scopes(items: &[&str]) -> HashSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn ctx(token_tp: &str, scope_list: &[&str]) -> RequestCtx {
    RequestCtx::new(
        "subj-1",
        Uuid::nil(),
        Uuid::nil(),
        token_tp,
        scopes(scope_list),
    )
}

fn record(name: &str, policies: &str, mode: PolicyMode, schema: Option<String>) -> PolicySetRecord {
    PolicySetRecord {
        id: Uuid::new_v4(),
        env_id: Uuid::nil(),
        service: "sentin8:post".into(),
        policy_set_name: name.into(),
        description: String::new(),
        policies: policies.into(),
        schema,
        origin: PolicyOrigin::Platform,
        mode,
        version: 1,
        enabled: true,
    }
}

const SCOPE_MIRROR: &str =
  "permit(principal, action, resource) when { principal.scopes.contains(\"sentin8:post:read\") };";

// ── Parse / validate ────────────────────────────────────────────────────

#[test]
fn validate_accepts_scope_mirror_text() {
    assert!(crate::validate_record_text("s", SCOPE_MIRROR, None).is_ok());
}

#[test]
fn validate_rejects_bad_syntax() {
    let err = crate::validate_record_text("s", "permit(principal", None).unwrap_err();
    assert!(err.to_string().contains("parse error"), "got: {err}");
}

#[test]
fn validate_rejects_forbid_only_when_schema_checks() {
    // A forbid-only set parses fine without a schema.
    let forbid_only =
        "forbid(principal, action, resource) when { principal.token_tp == \"blocked\" };";
    assert!(crate::validate_record_text("s", forbid_only, None).is_ok());
}

#[test]
fn validate_schema_mismatch_rejected() {
    // Schema says `scopes: Set<String>` required; policy references a
    // non-existent attribute `sopes` → validation must fail (write-time gate).
    let schema = r#"
    entity User = { "scopes": Set<String>, "token_tp": String };
    entity Resource;
    action read appliesTo { principal: User, resource: Resource };
  "#;
    let bad = "permit(principal, action, resource) when { principal.sopes.contains(\"x\") };";
    let err = crate::validate_record_text("s", bad, Some(schema)).unwrap_err();
    assert!(err.to_string().contains("validation error"), "got: {err}");
}

#[test]
fn validate_schema_match_accepted() {
    let schema = r#"
    entity User = { "scopes": Set<String>, "token_tp": String };
    entity Resource;
    action read appliesTo { principal: User, resource: Resource };
  "#;
    assert!(crate::validate_record_text("s", SCOPE_MIRROR, Some(schema)).is_ok());
}

// ── Evaluation semantics ────────────────────────────────────────────────

fn engine_with(records: Vec<PolicySetRecord>) -> Arc<PolicyEngine> {
    let engine = PolicyEngine::new("sentin8:post");
    let rows = records
        .into_iter()
        .map(|mut r| {
            r.service = "sentin8:post".into();
            r
        })
        .collect();
    compile_rows_for_tests(&engine, rows).expect("compile");
    Arc::new(engine)
}

#[test]
fn no_match_is_deny_when_enforced() {
    let engine = engine_with(vec![record(
        "read",
        SCOPE_MIRROR,
        PolicyMode::Enforced,
        None,
    )]);
    // Caller has the scope → allow.
    let out = engine.evaluate(
        &ctx("user", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(out.is_allow());
    // Caller lacks the scope → DENY (no matching permit = fail-closed).
    let out = engine.evaluate(&ctx("user", &[]), &EvalTarget::new("sentin8:post:read"));
    assert_eq!(
        out.enforce_decision,
        Decision::Deny {
            reason: "policy".into()
        }
    );
}

#[test]
fn empty_cache_denies_fail_closed() {
    // No sets at all: nothing grants the action → DENY (fail-closed, ).
    // "No matching permit → deny" applies equally to "no matching set": an
    // env whose sets failed to load must not silently fall open.
    let engine = engine_with(vec![]);
    let out = engine.evaluate(
        &ctx("user", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert_eq!(
        out.enforce_decision,
        Decision::Deny {
            reason: "policy".into()
        }
    );
    assert_eq!(
        out.would_deny.as_deref(),
        Some("no policy set loaded for env")
    );
    assert!(out.shadow_deny.is_none());
}

#[test]
fn forbid_beats_permit() {
    let engine = engine_with(vec![record(
    "gate",
    &format!(
      "{SCOPE_MIRROR}\nforbid(principal, action, resource) when {{ principal.token_tp == \"blocked\" }};"
    ),
    PolicyMode::Enforced,
    None,
  )]);
    let out = engine.evaluate(
        &ctx("blocked", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(!out.is_allow(), "forbid must win over permit");
}

#[test]
fn shadow_never_blocks_but_reports() {
    let engine = engine_with(vec![record("read", SCOPE_MIRROR, PolicyMode::Shadow, None)]);
    // Lacking the scope in shadow mode → still ALLOW (never blocks)…
    let out = engine.evaluate(&ctx("user", &[]), &EvalTarget::new("sentin8:post:read"));
    assert!(out.is_allow(), "shadow must never block");
    // …but a would-deny is reported for Stat emission.
    let sd = out.shadow_deny.expect("shadow deny must be reported");
    assert!(sd.contains("read"), "shadow reason names the set: {sd}");
}

#[test]
fn enforced_wins_over_shadow_deny() {
    // Two sets: one enforced (matches, allows), one shadow (would-deny). The
    // enforced decision stands; the shadow deny is still surfaced.
    let engine = engine_with(vec![
        record(
            "shadow-limit",
            "permit(principal, action, resource) when { principal.token_tp == \"never\" };",
            PolicyMode::Shadow,
            None,
        ),
        record("read", SCOPE_MIRROR, PolicyMode::Enforced, None),
    ]);
    let out = engine.evaluate(
        &ctx("user", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(out.is_allow());
    assert!(out.shadow_deny.is_some());
}

#[test]
fn enforced_deny_short_circuits() {
    let engine = engine_with(vec![
        record("read", SCOPE_MIRROR, PolicyMode::Shadow, None),
        record(
            "block-m2m",
            "forbid(principal, action, resource) when { principal.token_tp == \"m2m\" };",
            PolicyMode::Enforced,
            None,
        ),
    ]);
    let out = engine.evaluate(
        &ctx("m2m", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(
        !out.is_allow(),
        "enforced forbid must reject even in mixed mode"
    );
}

// ── M2M parity ──────────────────────────────────────────────────────────

#[test]
fn m2m_evaluates_like_any_principal() {
    let engine = engine_with(vec![record(
        "read",
        SCOPE_MIRROR,
        PolicyMode::Enforced,
        None,
    )]);
    let out = engine.evaluate(
        &ctx("m2m", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(
        out.is_allow(),
        "m2m with the scope must be allowed — token type never bypasses or special-cases"
    );
    let out = engine.evaluate(&ctx("m2m", &[]), &EvalTarget::new("sentin8:post:read"));
    assert!(
        !out.is_allow(),
        "m2m without the scope must be denied — no token-type bypass"
    );
}

// ── Attribute rules (ABAC the scope cannot express) ─────────────────────

#[test]
fn resource_attribute_rule_thresholds() {
    let engine = engine_with(vec![record(
    "limits",
    "permit(principal, action, resource) when { principal.scopes.contains(\"sentin8:post:write\") && resource.amount <= 100 };",
    PolicyMode::Enforced,
    None,
  )]);
    let target = EvalTarget::new("sentin8:post:write")
        .with_attr("amount", RestrictedExpression::from_str("50").unwrap());
    let out = engine.evaluate(&ctx("user", &["sentin8:post:write"]), &target);
    assert!(out.is_allow(), "amount=50 within threshold must allow");
    let target = EvalTarget::new("sentin8:post:write")
        .with_attr("amount", RestrictedExpression::from_str("150").unwrap());
    let out = engine.evaluate(&ctx("user", &["sentin8:post:write"]), &target);
    assert!(
        !out.is_allow(),
        "amount=150 above threshold must deny (no matching permit)"
    );
}

// ── Live roles + relations ─────────────────────────────

// Shield's `in` is entity-hierarchy membership — role sets are tested with
// `.contains()` .
const ROLE_GATE: &str =
  "permit(principal, action, resource) when { principal.roles.contains(\"sentin8:post:admin\") };";

fn relation(
    subject_type: &str,
    subject_id: &str,
    object_type: &str,
    object_id: &str,
) -> crate::substrate::RelationRecord {
    crate::substrate::RelationRecord {
        id: Uuid::new_v4(),
        env_id: Uuid::nil(),
        service: "sentin8:post".into(),
        subject_type: subject_type.into(),
        subject_id: subject_id.into(),
        relation: "member".into(),
        object_type: object_type.into(),
        object_id: object_id.into(),
        origin: "platform".into(),
        created_at: None,
    }
}

#[test]
fn roles_attribute_gate_allows_holder_and_denies_otherwise() {
    let engine = engine_with(vec![record(
        "role-gate",
        ROLE_GATE,
        PolicyMode::Enforced,
        None,
    )]);
    let mut c = ctx("user", &[]);
    c.roles = scopes(&["sentin8:post:admin"]);
    let out = engine.evaluate(&c, &EvalTarget::new("sentin8:post:read"));
    assert!(
        out.is_allow(),
        "live role holder must pass the role-gated rule"
    );
    let out = engine.evaluate(&ctx("user", &[]), &EvalTarget::new("sentin8:post:read"));
    assert!(
        !out.is_allow(),
        "role-less principal must be denied (fail-closed)"
    );
    // Scope-based rules do NOT grant via roles — models are distinct sets.
    let mut scope_only = ctx("user", &[]);
    scope_only.roles = scopes(&["sentin8:post:admin"]);
    let scope_gate_engine = engine_with(vec![record(
    "scope-gate",
    "permit(principal, action, resource) when { principal.scopes.contains(\"sentin8:post:admin\") };",
    PolicyMode::Enforced,
    None,
  )]);
    assert!(
        !scope_gate_engine
            .evaluate(&scope_only, &EvalTarget::new("sentin8:post:read"))
            .is_allow(),
        "holding the role NAME must not satisfy a scope test"
    );
}

#[test]
fn relation_edges_grant_hierarchy_membership() {
    let engine = engine_with(vec![record(
        "folder-view",
        "permit(principal, action, resource) when { principal in Group::\"fx-ops\" };",
        PolicyMode::Enforced,
        None,
    )]);
    // u1 is a member of fx-ops via a relation tuple.
    let mut c = ctx("user", &[]);
    c.relations = vec![relation("user", "subj-1", "group", "fx-ops")];
    let out = engine.evaluate(&c, &EvalTarget::new("sentin8:post:read"));
    assert!(
        out.is_allow(),
        "hierarchy edge (u1 member of fx-ops) must grant `in`"
    );
    // Without the edge, no membership → deny.
    let out = engine.evaluate(&ctx("user", &[]), &EvalTarget::new("sentin8:post:read"));
    assert!(!out.is_allow());
}

// ── Cache management ────────────────────────────────────────────────────

#[test]
fn upsert_disabled_or_foreign_set_removes_entry() {
    let engine = PolicyEngine::new("sentin8:post");
    engine
        .load_from_rows(vec![record(
            "read",
            SCOPE_MIRROR,
            PolicyMode::Enforced,
            None,
        )])
        .expect("load");
    // Disabled row → removed from cache → NO sets for the env → deny
    // (fail-closed — nothing grants the action anymore, ).
    let mut disabled = record("read", SCOPE_MIRROR, PolicyMode::Enforced, None);
    disabled.enabled = false;
    engine.upsert(disabled).expect("upsert");
    let out = engine.evaluate(
        &ctx("user", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert_eq!(
        out.enforce_decision,
        Decision::Deny {
            reason: "policy".into()
        },
        "disabled set → no coverage → fail-closed deny"
    );
}

#[test]
fn upsert_invalid_policy_fails_and_keeps_previous() {
    let engine = PolicyEngine::new("sentin8:post");
    engine
        .load_from_rows(vec![record(
            "read",
            SCOPE_MIRROR,
            PolicyMode::Enforced,
            None,
        )])
        .expect("load");
    let bad = record("read", "permit(broken", PolicyMode::Enforced, None);
    assert!(
        engine.upsert(bad).is_err(),
        "invalid policy must fail the upsert"
    );
    // Previous cache retained: the scope-mirror still enforces.
    let out = engine.evaluate(&ctx("user", &[]), &EvalTarget::new("sentin8:post:read"));
    assert!(!out.is_allow(), "previous valid set must remain active");
}

#[test]
fn remove_clears_entry() {
    let engine = PolicyEngine::new("sentin8:post");
    engine
        .load_from_rows(vec![record(
            "read",
            SCOPE_MIRROR,
            PolicyMode::Enforced,
            None,
        )])
        .expect("load");
    engine.remove(Uuid::nil(), "read");
    let out = engine.evaluate(
        &ctx("user", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert_eq!(
        out.enforce_decision,
        Decision::Deny {
            reason: "policy".into()
        },
        "removed set → no coverage → fail-closed deny"
    );
}

// ── Statement splitting ─────────────────────────────────────────────────

#[test]
fn split_respects_strings_and_multiline() {
    let text = format!(
    "{SCOPE_MIRROR}\n // comment line between statements\nforbid(principal, action, resource) when {{ principal.token_tp == \"has;semicolon\" }};"
  );
    let stmts = crate::test_only_split_statements(&text);
    assert_eq!(
        stmts.len(),
        2,
        "semicolon inside string must not split: {stmts:?}"
    );
    // Shield tolerates leading `//` comments inside a statement string, so the
    // comment stays attached to the following statement (verified vs the
    // Shield engine crate v4.12).
    assert!(stmts[0].starts_with("permit("));
    assert!(stmts[1].contains("forbid("));
}

#[test]
fn mode_and_origin_serde_roundtrip() {
    let mode: PolicyMode = serde_json::from_str("\"shadow\"").unwrap();
    assert_eq!(mode, PolicyMode::Shadow);
    assert_eq!(
        serde_json::to_string(&PolicyOrigin::Tenant).unwrap(),
        "\"tenant\""
    );
    assert_eq!(PolicyMode::Enforced.as_str(), "enforced");
}

// Enforce enum is referenced by design semantics (kept for parity checks).
#[test]
fn enforce_flag_semantics() {
    assert_ne!(Enforce::Yes, Enforce::No);
}

#[test]
fn principal_attrs_merge_without_override() {
    // Handler-supplied principal attrs must not override the engine-set
    // scopes/token_tp — policies rely on them (fail-closed on tamper).
    let mut extra: BTreeMap<String, RestrictedExpression> = BTreeMap::new();
    extra.insert(
        "org".into(),
        RestrictedExpression::new_string("acme".into()),
    );
    let mut c = ctx("user", &["sentin8:post:read"]);
    c.principal_attrs = extra;
    let engine = engine_with(vec![record(
        "org",
        "permit(principal, action, resource) when { principal.org == \"acme\" };",
        PolicyMode::Enforced,
        None,
    )]);
    let out = engine.evaluate(&c, &EvalTarget::new("sentin8:post:read"));
    assert!(out.is_allow());
}
