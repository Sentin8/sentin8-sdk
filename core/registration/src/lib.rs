// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-registration
//!
//! Shared service self-registration structs and the `--print-registration`
//! print helper. Every Sentin8 service (platform + verticals) exposes its
//! registration data — service info, admin scopes, error codes, admin UI,
//! SQL migrations, PostgreSQL OAuth role mappings, OpenAPI spec — via a
//! `--print-registration` flag. This crate is the **single definition** of
//! those structs and the section-matching logic; services only supply data.
//!
//! ## Usage (in a service's `registration.rs`)
//!
//! ```text
//! use sentin8_registration::{print_registration, PgRole, Registration};
//!
//! const PG_ROLES: &[PgRole] = &[
//!     PgRole { scope: "ledger:read,ledger:write", role: "bank8_ledger_service", bypass_rls: false },
//! ];
//!
//! pub fn print(section: Option<String>) -> anyhow::Result<()> {
//!     let reg = Registration {
//!         service_type: "bank8-ledger",
//!         // ... data-only fields ...
//!     };
//!     print_registration(section, &reg, || serde_json::to_value(MyOpenApi::openapi()))
//! }
//! ```
//!
//! ## Sections
//!
//! | `--section=`    | Output                                    |
//! |-----------------|-------------------------------------------|
//! | *(none)/`all`   | Full `Registration` object                 |
//! | `service`       | `ServiceInfo`                              |
//! | `admin_scopes`  | `AdminScope` array (tuple or typed style)  |
//! | `error_codes`   | `ErrorCode` array                          |
//! | `admin_ui`      | `Option<AdminUi>`                          |
//! | `consent`       | `Consent`                                  |
//! | `sql`           | `SqlMigration` array                       |
//! | `pg_roles`      | `PgRole` array                             |
//! | `policies`      | `PolicySetDecl` array (default Shield sets) |
//! | `relations`     | `RelationDecl` array (ReBAC tuples)        |
//! | `audit_findings`| `AuditFinding` array                       |
//! | `service_actions`| `ServiceActionEntry` array                |
//! | `openapi`       | OpenAPI spec (from the `openapi()` closure)|
//!
//! The registration output feeds `sentin8-cli vertical init/enroll`, which
//! provisions platform and vertical rows from it — the CLI holds no
//! per-service knowledge of its own.

#![deny(missing_docs)]

use serde::Serialize;
use serde_json::Value;

// ── Structs ──────────────────────────────────────────────────────────────

/// One admin-UI page exposed by the service (`GET /v1/admin/ui/{route}`).
#[derive(Debug, Serialize)]
pub struct AdminUiPage {
    /// URL route of the page (e.g. `"buckets"`).
    pub route: &'static str,
    /// Sidebar label.
    pub label: &'static str,
    /// RFW definition endpoint (`GET /v1/admin/ui/{page}`).
    pub ui_endpoint: &'static str,
    /// Data endpoint the page reads (POST alias for update/delete).
    pub data_endpoint: &'static str,
    /// Material Icons code point (hex string), e.g. `"0xe062"`.
    pub icon: &'static str,
}

/// The service's admin UI definition — consumed by Sentin8:Dash to build the
/// dynamic sidebar (RFW rendering host; `architecture-principles.md` §4.15).
#[derive(Debug, Serialize)]
pub struct AdminUi {
    /// Sidebar section label.
    pub label: &'static str,
    /// Material Icons code point (hex string).
    pub icon: &'static str,
    /// The feature/service flag this admin UI is gated on.
    pub service_flag: &'static str,
    /// The service's admin pages, in sidebar order.
    pub pages: &'static [AdminUiPage],
}

/// Minimal service identity — the `--section=service` output.
#[derive(Debug, Serialize)]
pub struct ServiceInfo {
    /// Canonical colon service identity.
    pub service_type: &'static str,
    /// Hostname label used in the derived domain.
    pub subdomain: &'static str,
    /// Liveness probe path.
    pub health_path: &'static str,
    /// Where the OpenAPI spec is served.
    pub openapi_url: &'static str,
}

/// Consent surface (`--section=consent`).
#[derive(Debug, Serialize)]
pub struct Consent {
    /// Consent provider declarations.
    pub consent_providers: &'static [Value],
    /// Consent flow declarations.
    pub consent_flows: &'static [Value],
}

/// One SQL migration the service applies during enrollment.
#[derive(Debug, Serialize, Clone)]
pub struct SqlMigration {
    /// Ordered version.
    pub version: i32,
    /// Migration name.
    pub name: &'static str,
    /// Raw SQL text.
    pub sql: &'static str,
}

/// A PostgreSQL role this service connects as, on the certificate-identity
/// plane (group DESIGN.md §3.2).
///
/// Emitted by `--section=pg_roles`; `sentin8-cli vertical init/enroll`
/// creates the PASSWORDLESS role and writes the `pgm` identity-map row
/// binding the service's workload CN (`m2m-{service_type}`) to it — the
/// TLS handshake's `cert` auth resolves the connection. Registration-
/// driven: a future vertical's roles bind with zero platform knowledge
/// of the vertical (§4.14 parity with the Valkey ACL provisioning).
#[derive(Debug, Serialize, Clone)]
pub struct PgRole {
    /// Comma-separated scopes the role's grants serve (provenance for
    /// the registration audit; the connection itself is certified).
    pub scope: &'static str,
    /// PostgreSQL role name (e.g. `"bank8_ledger_service"`). Roles are
    /// cluster-wide; grants live in [`PgRole::database`] only.
    pub role: &'static str,
    /// Whether the role gets `BYPASSRLS`. No role on the cluster may
    /// bypass RLS; enrollment rejects `true`. The field is retained for
    /// schema compatibility; every service declares `false`.
    pub bypass_rls: bool,
    /// The vertical database this role's grants + scope-map row live in:
    /// `"sentin8"` for platform
    /// services, `"{vertical}"` for vertical services. Empty means the
    /// platform default (`sentin8`) — kept for older registrations that
    /// have not been regenerated.
    #[serde(default)]
    pub database: &'static str,
    /// Explicitly declared intra-database cross-schema reads this service
    /// needs (e.g. payments' holder-scope RLS reading `ledger.customers`).
    /// Enrollment applies exactly these grants — never blanket schema-wide
    /// grants. Empty for services that own all their reads.
    #[serde(default)]
    pub cross_schema_grants: &'static [CrossSchemaGrant],
}

/// One cross-schema read grant declared by a service's [`PgRole`].
/// Applied by `sentin8-cli vertical init/enroll` inside the role's declared
/// database. Grants are SELECT-only by design — cross-schema writes go
/// through the owning service's API or the bus, never direct table DML.
#[derive(Debug, Serialize, Clone)]
pub struct CrossSchemaGrant {
    /// Schema holding the table (e.g. `"ledger"`).
    pub schema: &'static str,
    /// Table the grant targets (e.g. `"customers"`).
    pub table: &'static str,
    /// Privilege — `"SELECT"` only in the current vocabulary.
    pub privilege: &'static str,
}

/// An admin scope in either the platform tuple style or the vertical typed
/// style. `#[serde(untagged)]` keeps both historical output shapes stable:
/// platform services serialize as `["scope", "scope"]` pairs, verticals as
/// `{"role": ..., "scope": ...}` objects.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum AdminScope {
    /// Platform tuple style: `("sentin8:sys:admin", "sentin8:sys:admin")`.
    Tuple(&'static str, &'static str),
    /// Vertical typed style: `{ role, scope }`.
    Typed {
        /// Role the scope is granted to.
        role: &'static str,
        /// The scope string.
        scope: &'static str,
    },
}

/// An error code the service can emit (`--section=error_codes`).
#[derive(Debug, Serialize, Clone)]
pub struct ErrorCode {
    /// The Rust enum variant name.
    pub enum_name: &'static str,
    /// The stable wire error code string.
    pub error_code: &'static str,
    /// The canonical HTTP status.
    pub status_code: i32,
}

/// One default declarative Shield policy set the service seeds at enrollment.
/// Upserted into `policy_sets` (`origin='platform'`; tenant-authored
/// rows are never touched). The CLI validates the Shield text at enroll time.
#[derive(Debug, Serialize, Clone)]
pub struct PolicySetDecl {
    /// Policy set name (unique per service/env).
    pub policy_set_name: &'static str,
    /// Human-readable description.
    #[serde(default)]
    pub description: &'static str,
    /// Shield policy text — one policy per statement.
    pub policies: &'static str,
    /// Optional Shield schema (strict validation for tenant-visible sets).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<&'static str>,
    /// Seed mode. Platform sets ship `enforced` — there are no shadow
    /// platform sets and no scope-check fallback. `shadow` is for
    /// tenant-authored authoring and the emergency one-UPDATE rollback
    /// lever only.
    #[serde(default = "default_mode")]
    pub mode: &'static str,
    /// Whether the set is enabled when seeded.
    #[serde(default = "default_true")]
    pub default_enabled: bool,
}

#[allow(dead_code)] // serde default fn — used only when the field is omitted
fn default_mode() -> &'static str {
    "enforced"
}

#[allow(dead_code)] // reserved for future optional-flag decls
fn default_true() -> bool {
    true
}

/// One ReBAC relation tuple the service seeds at enrollment.
/// Upserted into `policy_relations` (`origin='platform'`). Entity
/// types are Shield type names — case-sensitive, PascalCase by convention
/// (`Group`, `Folder`); the engine canonicalizes lowercase authoring forms.
#[derive(Debug, Serialize, Clone)]
pub struct RelationDecl {
    /// Subject entity type (Shield type name, PascalCase convention).
    pub subject_type: &'static str,
    /// Subject entity id.
    pub subject_id: &'static str,
    /// Relation name, e.g. `owner` | `member` | `parent` | `viewer`.
    pub relation: &'static str,
    /// Object entity type.
    pub object_type: &'static str,
    /// Object entity id.
    pub object_id: &'static str,
}

/// Declarative event→work binding (AGENTS.md "event-driven execution").
/// Registered at enroll time; the platform never hardcodes a vertical's
/// triggers. `target.kind` is `func` | `flow` | `cron` | `direct`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EventTriggerDecl {
    /// Event type to match, e.g. `bank8:ledger:posting:committed`.
    pub event_type: &'static str,
    /// Target binding: `{"kind": "flow", "logic_id": "..."}` |
    /// `{"kind": "func", "module_id": "...", "hook": "..."}` |
    /// `{"kind": "cron", "schedule_type": "..."}` |
    /// `{"kind": "direct"}` (the owning service consumes the stream itself).
    pub target: serde_json::Value,
    /// Consumer group that drains the matched stream.
    pub consumer_group: &'static str,
    /// Retry policy: `{"max_retries": 3, "backoff": "exponential"}`.
    #[serde(default)]
    pub retry: serde_json::Value,
}

impl EventTriggerDecl {
    /// The target binding `kind` (`func`|`flow`|`cron`|`direct`).
    pub fn target_kind(&self) -> &'static str {
        // Static strings: kind is a compile-time field for common kinds.
        match self.target.get("kind").and_then(|v| v.as_str()) {
            Some("func") => "func",
            Some("flow") => "flow",
            Some("cron") => "cron",
            _ => "direct",
        }
    }
}

/// A recurring internal schedule a service declares for Cron to own
/// (SDD §2.4). The service makes no boot-time cron registration call —
/// `sentin8-cli vertical enroll` reads the `schedules` registration
/// section and upserts `cron.schedules` rows; cron's ticker fires the
/// schedule against the service's own proxy-back endpoint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScheduleDecl {
    /// Stable schedule identifier — the cron `schedule_type` and the
    /// enroll idempotency key (unique per (env, domain)).
    pub schedule_type: &'static str,
    /// Cron expression (5-field, cron's parser).
    pub cron_expression: &'static str,
    /// IANA zone the expression's wall-clock fields match (`UTC` keeps
    /// the default behavior).
    pub timezone: &'static str,
    /// The service's own endpoint cron proxy-calls on fire — a JSON
    /// object literal as a string (`{"internalPath": "…"}`); the CLI
    /// resolves `baseUrl` from the platform domain at enroll time and
    /// parses this fragment into cron's `target_config`. A string (not
    /// `serde_json::Value`) so the declaration is a compile-time
    /// `const` like every other registration slice.
    pub target_config: &'static str,
    /// Mechanical retry cap before the schedule lands in cron's DLQ.
    pub max_retries: u32,
}

/// An audit finding surfaced by the service (`--section=audit_findings`).
#[derive(Debug, Serialize, Clone)]
pub struct AuditFinding {
    /// The condition to check.
    pub finding: &'static str,
    /// The expected state / remediation.
    pub recommendation: &'static str,
}

/// A cross-service action the service exposes (`--section=service_actions`).
#[derive(Debug, Serialize, Clone)]
pub struct ServiceActionEntry {
    /// Action name (e.g. `"produce"`).
    pub action: &'static str,
    /// The owning service identity.
    pub service_type: &'static str,
    /// The service-type key used to derive the platform domain.
    pub platform_domain_key: &'static str,
    /// HTTP method.
    pub method: &'static str,
    /// Endpoint path.
    pub endpoint: &'static str,
    /// Required scope.
    pub scope: &'static str,
}

/// An M2M workload DCR scope grant (`--section=m2m_grants`). One row per
/// workload the service registers with Sentin8:Auth via DCR (RFC 7591):
/// its own identity, the Shield hot-reload consumer (`{service_type}-policy`),
/// and the stat emitter (`{short}-policy`). `vertical enroll` upserts these
/// into `auth.m2m_scope_grants` so the fail-closed DCR gate admits the
/// registration. Scope values must use the
/// full vocabulary form (`sentin8:bus:consume`, never bare
/// `bus:consume`) — the gate's superset check and the bus Shield
/// scope-mirror both require the prefixed spelling.
#[derive(Debug, Serialize, Clone)]
pub struct M2mGrant {
    /// DCR `client_name` (cert-less identity path). Use the colon
    /// service_type for the service's own client and for
    /// `policy_bus_client` (`{service_type}-policy`); use the short form
    /// for the stat emitter (`{short}-policy`), mirroring
    /// `stat_emit::build_client`'s derivation.
    pub workload: &'static str,
    /// The closed scope set this workload may request at registration.
    pub scopes: &'static [&'static str],
}

/// The full registration object — the `--print-registration` (no section)
/// output. Services construct this with their own data; the shared
/// [`print_registration`] helper handles section dispatch + JSON emission.
#[derive(Debug, Serialize)]
pub struct Registration {
    /// Canonical colon service identity.
    pub service_type: &'static str,
    /// Hostname label for the service (e.g. `sentin8-func` → `func`).
    /// Defaults to the service_type minus a leading `sentin8-` prefix when
    /// not explicitly set — matching the platform registry.
    pub subdomain: &'static str,
    /// Liveness probe path.
    pub health_path: &'static str,
    /// Admin scopes the service's admin UI/actions require.
    pub admin_scopes: &'static [AdminScope],
    /// Error codes the service can emit.
    pub error_codes: &'static [ErrorCode],
    /// Consent provider declarations.
    pub consent_providers: &'static [Value],
    /// Consent flow declarations.
    pub consent_flows: &'static [Value],
    /// The service's admin UI definition, when it has one.
    pub admin_ui: Option<AdminUi>,
    /// SQL migrations applied at enrollment.
    pub sql_migrations: Vec<SqlMigration>,
    /// PostgreSQL OAuth scope→role mappings.
    pub pg_roles: &'static [PgRole],
    /// Default declarative policy sets. Empty slice =
    /// the service declares none (its actions then deny until an env admin
    /// authors a set).
    #[serde(skip_serializing_if = "slice_is_empty::<PolicySetDecl>")]
    pub policies: &'static [PolicySetDecl],
    /// Default ReBAC relation tuples.
    #[serde(skip_serializing_if = "slice_is_empty::<RelationDecl>")]
    pub relations: &'static [RelationDecl],
    /// Declarative event→function bindings.
    #[serde(skip_serializing_if = "slice_is_empty::<EventTriggerDecl>")]
    pub event_triggers: &'static [EventTriggerDecl],
    /// Recurring internal schedules owned by cron but declared by this
    /// service (SDD §2.4) — provisioned at enroll, never registered
    /// via boot-time cross-service calls.
    #[serde(skip_serializing_if = "slice_is_empty::<ScheduleDecl>")]
    pub schedules: &'static [ScheduleDecl],
    /// Security-audit findings the service declares.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_findings: Option<&'static [AuditFinding]>,
    /// Cross-service actions the service exposes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_actions: Option<&'static [ServiceActionEntry]>,
    /// M2M DCR scope grants. `None` = no grants declared (the
    /// service registers no M2M workloads — unusual; every shell service
    /// has at least the `-policy` pair).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub m2m_grants: Option<&'static [M2mGrant]>,
    /// Where the OpenAPI spec is served.
    pub openapi_url: &'static str,
    /// Serialized at print time via the `openapi` closure (utoipa).
    #[serde(skip_serializing)]
    pub openapi: fn() -> Value,
}

// ── Print helper ───────────────────────────────────────────────────────

/// `skip_serializing_if` helper for optional static slices (services that
/// declare no policies/relations omit the key entirely).
fn slice_is_empty<T>(s: &[T]) -> bool {
    s.is_empty()
}

/// Print the registration JSON for the requested `section` to stdout.
///
/// Called from each service's `registration::print(section)`. The `openapi`
/// closure serializes the service's utoipa spec lazily (only for the `all`
/// and `openapi` sections).
pub fn print_registration(
    section: Option<String>,
    reg: &Registration,
    openapi: fn() -> Value,
) -> anyhow::Result<()> {
    let json = match section.as_deref() {
        None | Some("all") => {
            let mut value = serde_json::to_value(reg)?;
            if let Some(obj) = value.as_object_mut() {
                obj.insert("openapi_spec".to_string(), openapi());
            }
            value
        }
        Some("service") => serde_json::to_value(ServiceInfo {
            service_type: reg.service_type,
            subdomain: reg.subdomain,
            health_path: reg.health_path,
            openapi_url: reg.openapi_url,
        })?,
        Some("admin_scopes") => serde_json::to_value(reg.admin_scopes)?,
        Some("error_codes") => serde_json::to_value(reg.error_codes)?,
        Some("admin_ui") => serde_json::to_value(&reg.admin_ui)?,
        Some("consent") => serde_json::to_value(Consent {
            consent_providers: reg.consent_providers,
            consent_flows: reg.consent_flows,
        })?,
        Some("sql") => serde_json::to_value(&reg.sql_migrations)?,
        Some("pg_roles") => serde_json::to_value(reg.pg_roles)?,
        Some("policies") => serde_json::to_value(reg.policies)?,
        Some("relations") => serde_json::to_value(reg.relations)?,
        Some("event_triggers") => serde_json::to_value(reg.event_triggers)?,
        Some("schedules") => serde_json::to_value(reg.schedules)?,
        Some("audit_findings") => serde_json::to_value(reg.audit_findings.unwrap_or(&[]))?,
        Some("service_actions") => serde_json::to_value(reg.service_actions.unwrap_or(&[]))?,
        Some("m2m_grants") => serde_json::to_value(reg.m2m_grants.unwrap_or(&[]))?,
        Some("openapi") => openapi(),
        Some(other) => anyhow::bail!("unknown section: {other}"),
    };
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PG: &[PgRole] = &[PgRole {
        scope: "test:read",
        role: "test_service",
        bypass_rls: false,
        database: "sentin8",
        cross_schema_grants: &[],
    }];

    const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
        policy_set_name: "role-mirror",
        description: "test permits",
        policies:
            "permit(principal, action, resource) when { principal.roles.contains(\"test:admin\") };",
        schema: None,
        mode: "enforced",
        default_enabled: true,
    }];

    const RELATIONS: &[RelationDecl] = &[RelationDecl {
        subject_type: "group",
        subject_id: "fx-ops",
        relation: "member",
        object_type: "folder",
        object_id: "accounts-fx",
    }];

    fn sample() -> Registration {
        Registration {
            service_type: "test-svc",
            subdomain: "test-svc",
            health_path: "/v1/health",
            admin_scopes: &[AdminScope::Tuple("test:admin", "test:admin")],
            error_codes: &[],
            consent_providers: &[],
            consent_flows: &[],
            admin_ui: None,
            sql_migrations: vec![],
            pg_roles: PG,
            policies: POLICIES,
            relations: RELATIONS,
            event_triggers: &[],
            schedules: &[],
            audit_findings: None,
            service_actions: None,
            m2m_grants: None,
            openapi_url: "/openapi.json",
            openapi: || serde_json::json!({"openapi": "3.1.0"}),
        }
    }

    #[test]
    fn pg_roles_section() {
        let out = print_registration(Some("pg_roles".into()), &sample(), || Value::Null);
        // print_registration writes to stdout; here just assert it succeeded.
        assert!(out.is_ok());
    }

    #[test]
    fn policies_section_serializes_declarations() {
        let reg = sample();
        let v = serde_json::to_value(reg.policies).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["policy_set_name"], "role-mirror");
        assert_eq!(arr[0]["default_enabled"], serde_json::json!(true));
        assert!(arr[0].get("schema").is_none(), "None schema is omitted");
    }

    #[test]
    fn relations_section_serializes_tuples() {
        let v = serde_json::to_value(RELATIONS).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["relation"], "member");
        assert_eq!(arr[0]["object_type"], "folder");
    }

    #[test]
    fn empty_slices_omit_keys() {
        let mut reg = sample();
        reg.policies = &[];
        reg.relations = &[];
        let v = serde_json::to_value(&reg).unwrap();
        assert!(
            v.get("policies").is_none(),
            "empty policies must be omitted"
        );
        assert!(
            v.get("relations").is_none(),
            "empty relations must be omitted"
        );
    }

    #[test]
    fn unknown_section_bails() {
        let out = print_registration(Some("nope".into()), &sample(), || Value::Null);
        assert!(out.is_err());
    }
}
