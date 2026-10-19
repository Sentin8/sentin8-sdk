// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # Security audit checklists
//!
//! This module provides **checklist-style** audit helpers that document the
//! edge cases and coverage requirements for the three Sentin8 security
//! pillars:
//!
//! 1. **Token validation edge cases** - every malformed,
//!    expired, replayed, or mismatched token scenario that Auth (and every
//!    downstream verifier) must reject.
//! 2. **Row-Level Security coverage** - every tenant-scoped
//!    table must have an RLS policy that filters by `org_id`/`env_id` from
//!    the session context.
//! 3. **Secret reference enforcement** - no plaintext secrets
//!    may be stored in the database; every secret column must hold a
//!    `sentin8-secrets://` reference that resolves via the `sentin8-secrets`
//!    crate.
//!
//! Each helper returns a `Vec<SecurityAuditResult>` - a machine-readable
//! checklist that an operator or CI job can iterate to verify coverage.
//! The `recommendation` field describes the expected state; the `finding`
//! field describes what to look for in the running system.

use serde::{Deserialize, Serialize};

/// The severity of a security audit finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    /// Critical - exploitable vulnerability that must be fixed before release.
    Critical,
    /// High - likely exploitable; fix in the current sprint.
    High,
    /// Medium - defence-in-depth concern; schedule a fix.
    Medium,
    /// Low - informational or hardening opportunity.
    Low,
    /// Info - checklist item that has been verified compliant.
    Info,
}

/// The category of a security audit finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// Token validation edge cases.
    TokenValidation,
    /// Row-Level Security coverage.
    RlsCoverage,
    /// Secret reference enforcement.
    SecretReferences,
}

/// A single security audit result - one checklist item.
///
/// `category` and `severity` classify the finding, `finding` describes the
/// condition to check, and `recommendation` describes the expected state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditResult {
    /// Which audit category this finding belongs to.
    pub category: AuditCategory,
    /// How severe a failure of this check would be.
    pub severity: AuditSeverity,
    /// Human-readable description of the condition to verify.
    pub finding: String,
    /// The recommended state (what "passing" looks like).
    pub recommendation: String,
}

/// Story 14.1.1 - Token validation edge cases.
///
/// Returns the full checklist of token-validation edge cases that Auth and
/// every downstream token verifier (sentin8-middleware JWKS verifier, BFF
/// cookie verifier, m2m client verifiers) must handle. Each entry documents
/// an input that must be **rejected**; a verifier that accepts any of these
/// tokens has a critical vulnerability.
pub fn audit_token_validation_edge_cases() -> Vec<SecurityAuditResult> {
    use AuditCategory::TokenValidation as T;
    use AuditSeverity::{Critical as C, High as H, Medium as M};
    vec![
        SecurityAuditResult {
            category: T,
            severity: C,
            finding: "Expired access token (exp < now)".to_string(),
            recommendation: "Verifier must reject tokens whose `exp` claim is in the past. \
                 Allow up to 60s clock skew via SENTIN8_AUTH_CLOCK_SKEW_SECONDS."
                .to_string(),
        },
        SecurityAuditResult {
            category: T,
            severity: C,
            finding: "Token with `nbf` in the future".to_string(),
            recommendation: "Verifier must reject tokens whose `nbf` claim is in the future \
                 (with the same clock-skew tolerance as `exp`)."
                .to_string(),
        },
        SecurityAuditResult {
            category: T,
            severity: C,
            finding: "Token signed with an unknown `kid`".to_string(),
            recommendation: "Verifier must reject tokens whose `kid` is not present in the \
                 fetched JWKS. Do not fall back to any default key."
                .to_string(),
        },
        SecurityAuditResult {
            category: T,
            severity: C,
            finding: "Token signed with `alg: none`".to_string(),
            recommendation: "Verifier must reject any token whose header `alg` is `none`. \
                 Only `RS256`, `ES256`, and `PS256` are permitted (per FAPI \
                 security profile)."
                .to_string(),
        },
        SecurityAuditResult {
            category: T,
            severity: C,
            finding: "Token with mismatched issuer (`iss`)".to_string(),
            recommendation: "Verifier must reject tokens whose `iss` claim does not \
                 exactly match the configured Auth issuer URL."
                .to_string(),
        },
        SecurityAuditResult {
            category: T,
            severity: C,
            finding: "Token with mismatched audience (`aud`)".to_string(),
            recommendation: "Verifier must reject tokens whose `aud` claim does not \
                 include this service's configured audience (e.g. `ledger`)."
                .to_string(),
        },
        SecurityAuditResult {
            category: T,
            severity: H,
            finding: "Replayed token (`jti` already seen)".to_string(),
            recommendation: "Verifier must cache seen `jti` values in Valkey (TTL = token \
                 lifetime) and reject duplicates. Required for DPoP and \
                 FAPI 1.0 ADV security profiles."
                .to_string(),
        },
        SecurityAuditResult {
            category: T,
            severity: H,
            finding: "Token with `token_tp` not permitted for the endpoint".to_string(),
            recommendation: "Verifier must check `token_tp` (m2m vs access vs \
                 support_actor) against the endpoint's allowed token types. \
                 Machine-to-machine tokens must not hit user-facing endpoints."
                .to_string(),
        },
        SecurityAuditResult {
            category: T,
            severity: M,
            finding: "Malformed JWT (not three dot-separated segments)".to_string(),
            recommendation: "Verifier must reject tokens that do not parse as \
                 `header.payload.signature` with valid base64url segments."
                .to_string(),
        },
        SecurityAuditResult {
            category: T,
            severity: M,
            finding: "Token with `iat` in the future".to_string(),
            recommendation: "Verifier should log a warning for tokens whose `iat` is in \
                 the future (clock drift indicator) but may accept them if \
                 `exp`/`nbf` are valid."
                .to_string(),
        },
        SecurityAuditResult {
            category: T,
            severity: H,
            finding: "Refresh token presented as access token".to_string(),
            recommendation: "Verifier must reject tokens whose `token_tp` is `refresh` \
                 when presented as a bearer access token. Refresh tokens are \
                 only accepted at the token endpoint."
                .to_string(),
        },
        SecurityAuditResult {
            category: T,
            severity: C,
            finding: "Token whose signature does not verify against JWKS key".to_string(),
            recommendation: "Verifier must cryptographically verify the token signature \
                 against the key referenced by `kid`. A missing or invalid \
                 signature is a critical failure."
                .to_string(),
        },
        SecurityAuditResult {
            category: T,
            severity: M,
            finding: "Token missing required claims (sub, iss, aud, exp, iat, jti)".to_string(),
            recommendation: "Verifier must reject tokens missing any of the six required \
                 Sentin8 claims: `sub`, `iss`, `aud`, `exp`, `iat`, `jti`."
                .to_string(),
        },
    ]
}

/// Story 14.1.2 - RLS policy coverage.
///
/// Returns the checklist for verifying that every tenant-scoped table in the
/// Sentin8 schema has a Row-Level Security policy that filters rows by the
/// `env_id` from the current database session context (set by the
/// service's tenant-context middleware). Platform-level tables (users, orgs,
/// environments, app listings) are exempt.
pub fn audit_rls_coverage() -> Vec<SecurityAuditResult> {
    use AuditCategory::RlsCoverage as R;
    use AuditSeverity::{Critical as C, High as H, Medium as M};
    vec![
        SecurityAuditResult {
            category: R,
            severity: C,
            finding: "Tenant-scoped table without an RLS policy".to_string(),
            recommendation: "Every table that holds tenant data (ledger accounts, payments \
                 instructions, db tables, buck objects, app instances, \
                 fdx consents, etc.) must have an ENABLE ROW LEVEL SECURITY \
                 policy that filters by `env_id` from the session \
                 context (`app.current_setting('sentin8.env_id')`)."
                .to_string(),
        },
        SecurityAuditResult {
            category: R,
            severity: C,
            finding: "RLS policy that uses `USING (true)` or `USING (1=1)`".to_string(),
            recommendation: "No RLS policy may be a no-op. Every policy must reference \
                 `env_id` columns compared against session \
                 settings."
                .to_string(),
        },
        SecurityAuditResult {
            category: R,
            severity: C,
            finding: "Table with RLS disabled (`FORCE ROW LEVEL SECURITY` not set)".to_string(),
            recommendation: "Every tenant table must have `FORCE ROW LEVEL SECURITY` \
                 enabled so that even the table owner is subject to the \
                 policies."
                .to_string(),
        },
        SecurityAuditResult {
            category: R,
            severity: H,
            finding: "Service connects as a superuser (bypasses RLS)".to_string(),
            recommendation: "No Sentin8 service may connect to PostgreSQL as a superuser. \
                 Each service uses a dedicated role with `NOBYPASSRLS` that \
                 inherits only the privileges it needs."
                .to_string(),
        },
        SecurityAuditResult {
            category: R,
            severity: H,
            finding: "Session context not set before tenant query".to_string(),
            recommendation: "Every service must call `SET LOCAL sentin8.env_id` \
                 (via `set_tenant_context`) inside \
                 the transaction before issuing tenant-scoped queries. \
                 Missing context must return 401, not a cross-tenant leak."
                .to_string(),
        },
        SecurityAuditResult {
            category: R,
            severity: M,
            finding: "Foreign-key columns without RLS on the parent table".to_string(),
            recommendation: "If a tenant table has a foreign key to another tenant \
                 table, the parent table must also have an RLS policy, or \
                 the FK must include `env_id` as a composite key \
                 to prevent cross-tenant references."
                .to_string(),
        },
        SecurityAuditResult {
            category: R,
            severity: H,
            finding: "Platform-level table accidentally given an RLS policy".to_string(),
            recommendation: "System tables (sentin8_auth_users, sentin8_sys_organizations, \
                 sentin8_sys_environments, sentin8_app_listings) must NOT have RLS policies - \
                 they are global. An RLS policy on these tables would break \
                 cross-tenant lookups. Verify via `pg_policies`."
                .to_string(),
        },
        SecurityAuditResult {
            category: R,
            severity: C,
            finding: "Cross-tenant read returns rows (isolation failure)".to_string(),
            recommendation: "Run the tenant-isolation integration test: query a \
                 tenant-A table with tenant-B's session context. The query \
                 must return zero rows. Any non-zero result is a critical \
                 RLS bypass."
                .to_string(),
        },
        SecurityAuditResult {
            category: R,
            severity: M,
            finding: "Missing index on `org_id`/`env_id` for tenant tables".to_string(),
            recommendation: "Every tenant table should have a composite index on \
                 `(org_id, env_id)` to keep RLS predicate evaluation fast at \
                 scale. Verify via `pg_indexes`."
                .to_string(),
        },
    ]
}

/// Story 14.1.3 - Secret reference enforcement.
///
/// Returns the checklist for verifying that no plaintext secrets are stored
/// in the database. Every secret (OAuth client secrets, m2m tokens, API
/// keys, integration credentials, signing keys) must be stored as a
/// `sentin8-secrets://` reference that resolves through the `sentin8-secrets`
/// crate, never as the raw value.
pub fn audit_secret_references() -> Vec<SecurityAuditResult> {
    use AuditCategory::SecretReferences as S;
    use AuditSeverity::{Critical as C, High as H, Medium as M};
    vec![
        SecurityAuditResult {
            category: S,
            severity: C,
            finding: "Column named `*_secret`, `*_password`, `*_key`, `*_token` holds plaintext"
                .to_string(),
            recommendation: "Scan every column matching `*_secret`, `*_password`, \
                 `*_key`, `*_token` in the information_schema. Values must \
                 start with `sentin8-secrets://` (or be NULL). Any value that \
                 looks like a raw credential (long base64, JWT, PEM) is a \
                 critical finding."
                .to_string(),
        },
        SecurityAuditResult {
            category: S,
            severity: C,
            finding: "OAuth client secret stored as plaintext".to_string(),
            recommendation: "The `sentin8_auth_oauth_clients.client_secret` column (and any \
                 per-app DCR client secret) must hold a `sentin8-secrets://` \
                 reference. Plaintext client secrets are a critical finding."
                .to_string(),
        },
        SecurityAuditResult {
            category: S,
            severity: H,
            finding: "m2m token stored in the database".to_string(),
            recommendation: "m2m access tokens are never persisted. They live in memory \
                 (or a short-TTL Valkey cache). Any `m2m_token` column in a \
                 tenant table is a finding - remove it and fetch tokens \
                 on-demand via the m2m client."
                .to_string(),
        },
        SecurityAuditResult {
            category: S,
            severity: H,
            finding: "Integration credentials stored without a secret reference".to_string(),
            recommendation: "Any integration credentials (payment provider auth configs, \
                 FDX provider API keys, third-party secrets) must be stored as a \
                 `sentin8-secrets://` reference. The `sentin8-secrets` crate \
                 resolves the reference to the actual value at runtime. \
                 Vertical-specific audit findings are registered via \
                 `sentin8-cli vertical enroll` and stored in \
                 `sentin8_vertical_audit_findings`."
                .to_string(),
        },
        SecurityAuditResult {
            category: S,
            severity: H,
            finding: "JWT signing key stored in the database".to_string(),
            recommendation: "Auth JWKS private keys must live in `sentin8-secrets` (or \
                 an HSM/KMS), never in a database column. Only the public \
                 JWKS is published at `/.well-known/jwks.json`."
                .to_string(),
        },
        SecurityAuditResult {
            category: S,
            severity: M,
            finding: "Secret reference that does not resolve".to_string(),
            recommendation: "Run `sentin8-cli secrets resolve --ref <sentin8-secrets://...>` \
                 against every `sentin8-secrets://` reference in the database. \
                 A reference that returns \
                 `NotFound` is a stale reference - the secret was deleted but \
                 the row was not updated."
                .to_string(),
        },
        SecurityAuditResult {
            category: S,
            severity: H,
            finding: "Secret material stored outside Sentin8:Secrets".to_string(),
            recommendation: "All tenant secret material (provider API keys, OAuth client \
                 secrets, webhook signing secrets, app env vars) must be stored \
                 in the Sentin8:Secrets service tables (`sentin8.secrets`, \
                 AES-256-GCM envelopes) and referenced by URI in consumer \
                 columns. Ad-hoc backends (`env://` outside dev bootstrap, \
                 `file://` outside dev) are a finding - migrate to \
                 `sentin8-secrets://` refs resolved via `sentin8-cli secrets`."
                .to_string(),
        },
        SecurityAuditResult {
            category: S,
            severity: M,
            finding: "Secret logged in structured logs or audit events".to_string(),
            recommendation: "Scan structured logs and audit-event `details`/`before`/\
                 `after` payloads for secret-shaped strings. The logging \
                 layer must redact any field whose key matches \
                 `*_secret|*_password|*_key|*_token`."
                .to_string(),
        },
        SecurityAuditResult {
            category: S,
            severity: C,
            finding: "Connection-string password in plaintext config".to_string(),
            recommendation: "Database and Valkey connection strings must not embed \
                 passwords. Use `sentin8-secrets://` references in the \
                 `DATABASE_URL`/`VALKEY_URL` config (resolved at startup) \
                 or separate `PGPASSWORD`/`VALKEY_PASSWORD` env vars \
                 injected from the secrets manager."
                .to_string(),
        },
        SecurityAuditResult {
            category: S,
            severity: H,
            finding: "Backup or dump containing secret columns".to_string(),
            recommendation: "Logical backups (`pg_dump`) of tenant tables include \
                 secret-reference columns by value. Verify that the backup \
                 only contains `sentin8-secrets://` strings, not raw secrets. \
                 Rotate any secret whose reference appears in a leaked \
                 backup."
                .to_string(),
        },
    ]
}

/// Convenience: run all three security audits and concatenate the results.
pub fn run_all_security_audits() -> Vec<SecurityAuditResult> {
    let mut out = Vec::new();
    out.extend(audit_token_validation_edge_cases());
    out.extend(audit_rls_coverage());
    out.extend(audit_secret_references());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_validation_returns_non_empty() {
        let results = audit_token_validation_edge_cases();
        assert!(!results.is_empty(), "checklist must not be empty");
        assert!(results
            .iter()
            .all(|r| r.category == AuditCategory::TokenValidation));
    }

    #[test]
    fn token_validation_covers_alg_none() {
        let results = audit_token_validation_edge_cases();
        assert!(
            results.iter().any(|r| r.finding.contains("alg: none")),
            "must cover alg:none attack"
        );
    }

    #[test]
    fn token_validation_covers_expired() {
        let results = audit_token_validation_edge_cases();
        assert!(results.iter().any(|r| r.finding.contains("Expired")));
    }

    #[test]
    fn token_validation_covers_replay() {
        let results = audit_token_validation_edge_cases();
        assert!(results.iter().any(|r| r.finding.contains("Replayed")));
    }

    #[test]
    fn token_validation_covers_audience() {
        let results = audit_token_validation_edge_cases();
        assert!(results.iter().any(|r| r.finding.contains("audience")));
    }

    #[test]
    fn rls_coverage_returns_non_empty() {
        let results = audit_rls_coverage();
        assert!(!results.is_empty());
        assert!(results
            .iter()
            .all(|r| r.category == AuditCategory::RlsCoverage));
    }

    #[test]
    fn rls_coverage_covers_no_op_policy() {
        let results = audit_rls_coverage();
        assert!(
            results.iter().any(|r| r.finding.contains("USING (true)")),
            "must flag no-op RLS policies"
        );
    }

    #[test]
    fn rls_coverage_covers_superuser() {
        let results = audit_rls_coverage();
        assert!(results.iter().any(|r| r.finding.contains("superuser")));
    }

    #[test]
    fn rls_coverage_covers_cross_tenant_isolation() {
        let results = audit_rls_coverage();
        assert!(results
            .iter()
            .any(|r| r.finding.contains("isolation failure")));
    }

    #[test]
    fn secret_references_returns_non_empty() {
        let results = audit_secret_references();
        assert!(!results.is_empty());
        assert!(results
            .iter()
            .all(|r| r.category == AuditCategory::SecretReferences));
    }

    #[test]
    fn secret_references_covers_oauth_client_secret() {
        let results = audit_secret_references();
        assert!(results
            .iter()
            .any(|r| r.finding.contains("OAuth client secret")));
    }

    #[test]
    fn secret_references_covers_signing_key() {
        let results = audit_secret_references();
        assert!(results.iter().any(|r| r.finding.contains("signing key")));
    }

    #[test]
    fn run_all_concatenates_all_categories() {
        let all = run_all_security_audits();
        let token = audit_token_validation_edge_cases();
        let rls = audit_rls_coverage();
        let secrets = audit_secret_references();
        assert_eq!(all.len(), token.len() + rls.len() + secrets.len());
        assert!(all
            .iter()
            .any(|r| r.category == AuditCategory::TokenValidation));
        assert!(all.iter().any(|r| r.category == AuditCategory::RlsCoverage));
        assert!(all
            .iter()
            .any(|r| r.category == AuditCategory::SecretReferences));
    }

    #[test]
    fn security_audit_result_is_serializable() {
        let r = SecurityAuditResult {
            category: AuditCategory::TokenValidation,
            severity: AuditSeverity::Critical,
            finding: "test finding".to_string(),
            recommendation: "test recommendation".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"category\":\"token_validation\""));
        assert!(json.contains("\"severity\":\"critical\""));
        let back: SecurityAuditResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.category, AuditCategory::TokenValidation);
        assert_eq!(back.severity, AuditSeverity::Critical);
    }

    #[test]
    fn severity_variants_round_trip() {
        for s in [
            AuditSeverity::Critical,
            AuditSeverity::High,
            AuditSeverity::Medium,
            AuditSeverity::Low,
            AuditSeverity::Info,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: AuditSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn category_variants_round_trip() {
        for c in [
            AuditCategory::TokenValidation,
            AuditCategory::RlsCoverage,
            AuditCategory::SecretReferences,
        ] {
            let json = serde_json::to_string(&c).unwrap();
            let back: AuditCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(c, back);
        }
    }

    #[test]
    fn every_finding_has_non_empty_recommendation() {
        for r in run_all_security_audits() {
            assert!(!r.finding.is_empty(), "finding empty: {:?}", r);
            assert!(
                !r.recommendation.is_empty(),
                "recommendation empty: {:?}",
                r
            );
        }
    }
}
