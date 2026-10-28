// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Policy substrates (design/sentin8-shield-technical-design.md
//! three models) - the authorization data the engine evaluates against:
//!
//! - **RBAC - live roles**: `resolve_roles(env_id, subject_id)` fetches
//!   the caller's resolved role names from Sentin8:Auth (the role/group/nesting
//!   graph behind the scope resolution). Roles are NEVER read from the JWT -
//!   a role change takes effect on the next request. Short-TTL cache,
//!   env+subject keyed, invalidated by the Auth role-change Bus events.
//! - **ABAC - principal attributes**: `policy_principal_attrs`
//!   rows, loaded env-scoped per service.
//! - **ReBAC - relation tuples**: `policy_relations` rows,
//!   loaded as Shield entity-hierarchy `parents` edges (size-capped).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use serde::Deserialize;
use shield::EntityUid;
use thiserror::Error;
use uuid::Uuid;

/// Error type for the live role resolver.
#[derive(Debug, Error)]
pub enum RoleError {
    #[error("auth service returned {status}: {detail}")]
    Http { status: u16, detail: String },
    #[error("auth response decode failed: {0}")]
    Decode(String),
    #[error("role fetch failed: {0}")]
    Reqwest(String),
}

/// Response shape of Sentin8:Auth's `GET /oauth/userinfo` (the resolved
/// identity endpoint). Both branches (user / M2M) return `roles` and
/// `scopes`; `groups` is user-only. `scopes` is the LIVE effective scope set
/// (the role-permission closure recomputed per request - the exact
/// computation sign-in stamps into the JWT, resolved live per design
/// so role changes take effect on the next request).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ResolvedIdentity {
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

// ── Live role resolver ──────────────────────────────────────────────────────

/// Cache entry: resolved identity (role names + effective scopes) + fetch
/// time.
#[derive(Debug, Clone)]
struct RoleEntry {
    roles: HashSet<String>,
    scopes: HashSet<String>,
    fetched_at: Instant,
}

/// Live role resolution for step 5. Keys on `(env_id, subject_id)` - the
/// resolved roles of a principal are env-scoped (roles live in the Auth
/// env realm), so the cache never leaks across tenants.
///
/// Freshness: entries older than [`Self::ttl`] are re-fetched on the next
/// call; [`Self::invalidate_env`] clears an env after a role-change Bus
/// event. Resolution failure is returned to the caller - `require_policy`
/// treats it as a fail-closed deny.
pub struct RoleResolver {
    auth_base_url: String,
    http: reqwest::Client,
    ttl: Duration,
    cache: ArcSwap<HashMap<(Uuid, String), RoleEntry>>,
}

impl RoleResolver {
    /// Build a resolver against Sentin8:Auth's base URL (issuer). The HTTP
    /// client uses the platform's post-quantum TLS provider.
    ///
    /// When the embedding service declares its certificate workload
    /// identity (`SENTIN8_TLS_SERVICE_IDENTITY`), the userinfo call
    /// presents that `{leaf}-tls` workload CERTIFICATE - auth's userinfo
    /// gate admits a CA-verified platform-workload caller as the
    /// sender-constraint carrier for forwarded DPoP-bound tokens
    /// (RFC 8705 §3: the certificate IS the sender constraint; DPoPRS-1).
    /// The identity pair is the SAME m2m-credentials cache every other
    /// channel uses (0700/0600, load-or-mint) - it must exist at first
    /// boot; a missing pair falls back to the plain client and the
    /// resolver logs why resolution will demand proofs (fail-closed
    /// remains the downstream behavior).
    pub fn new(auth_base_url: impl Into<String>) -> Self {
        let base = auth_base_url.into();
        let http = Self::build_identity_client(&base).unwrap_or_default();
        Self {
            auth_base_url: base,
            http,
            ttl: Duration::from_secs(30),
            cache: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    /// Build the certificate-presenting userinfo client from the
    /// embedding service's declared workload identity. `None` when no
    /// identity is declared or the pair cannot be minted - callers fall
    /// back to the plain client.
    ///
    /// Naming (TLS-RLS-4): the enrolled `{dash}-tls` workload -
    /// `sentin8:sys` → `sentin8-sys-tls`, matching the registration's
    /// declared m2m grant and the Valkey workload registry. The pair rides
    /// the SAME m2m-credentials cache every other channel uses
    /// (0700/0600, load-or-mint): the fast path reads the persisted pair
    /// (no network); a first boot mints through the async ensure (bounded
    /// by Acme's own request deadlines, one time per workload lifetime).
    fn build_identity_client(auth_base_url: &str) -> Option<reqwest::Client> {
        let service = sentin8_middleware::structured_logging::current_service_name()?;
        // `{dash}-tls` (dash form, NOT the underscore env slug - the
        // registration + registry name the workload with hyphens:
        // `sentin8:sys` → `sentin8-sys-tls`, matching
        // `registration.rs`'s declared m2m grant).
        let tls_workload = format!("{}-tls", service.replace(':', "-"));
        let ca_path = sentin8_m2m::platform_ca_pem_path();
        let pair = match sentin8_m2m::ensure_workload_certificate_blocking(
            auth_base_url,
            &tls_workload,
            &ca_path,
        ) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    workload = %tls_workload,
                    "shield: workload identity unavailable - resolver falls back to bearer-only resolution"
                );
                return None;
            }
        };
        let cfg = sentin8_middleware::mtls::MtlsConfig::new(
            &pair.ca_cert_path,
            &pair.cert_path,
            &pair.key_path,
        );
        match sentin8_middleware::mtls::build_mtls_client(&cfg) {
            Ok(c) => {
                tracing::info!(workload = %tls_workload, "shield: role resolver presents its workload certificate on identity resolution (dpops-1)");
                Some(c)
            }
            Err(e) => {
                tracing::warn!(error = %e, "shield: mTLS identity client build failed - resolver falls back to bearer-only");
                None
            }
        }
    }

    /// Test/ops constructor: fixed TTL.
    pub fn with_ttl(auth_base_url: impl Into<String>, ttl: Duration) -> Self {
        let base = auth_base_url.into();
        Self {
            auth_base_url: base.clone(),
            http: Self::build_identity_client(&base).unwrap_or_default(),
            ttl,
            cache: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    /// Resolve the caller's identity (live): role names AND the live
    /// effective scope set. `access_token` is the caller's verified Bearer
    /// token - passed through to Auth's userinfo endpoint, which re-verifies
    /// it server-side (the resolver never trusts a client-supplied identity).
    pub async fn resolve_identity(
        &self,
        env_id: Uuid,
        subject_id: &str,
        access_token: &str,
    ) -> Result<(HashSet<String>, HashSet<String>), RoleError> {
        let key = (env_id, subject_id.to_string());
        if let Some(entry) = self.cache.load().get(&key) {
            if entry.fetched_at.elapsed() < self.ttl {
                return Ok((entry.roles.clone(), entry.scopes.clone()));
            }
        }
        let url = format!(
            "{}/oauth/userinfo",
            self.auth_base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| RoleError::Reqwest(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(RoleError::Http {
                status: resp.status().as_u16(),
                detail: resp.text().await.unwrap_or_default(),
            });
        }
        let identity: ResolvedIdentity = resp
            .json()
            .await
            .map_err(|e| RoleError::Decode(e.to_string()))?;
        let entry = RoleEntry {
            roles: identity.roles.iter().cloned().collect(),
            scopes: identity.scopes.iter().cloned().collect(),
            fetched_at: Instant::now(),
        };
        let mut next = HashMap::clone(&*self.cache.load());
        // The TTL is an eviction bound, not only a staleness check: prune
        // entries that expired before storing the new one - otherwise the
        // cache grows with every unique `(env_id, subject_id)` that ever
        // passed a policy gate, for the life of the process (policy
        // README §6 - bounded role-resolver cache).
        next.retain(|_, entry| entry.fetched_at.elapsed() < self.ttl);
        next.insert(key, entry.clone());
        self.cache.store(Arc::new(next));
        Ok((entry.roles, entry.scopes))
    }

    /// Resolve the caller's role names (live). Roles-only convenience over
    /// [`Self::resolve_identity`] (same cache entry - no extra fetch).
    pub async fn resolve(
        &self,
        env_id: Uuid,
        subject_id: &str,
        access_token: &str,
    ) -> Result<HashSet<String>, RoleError> {
        let (roles, _) = self
            .resolve_identity(env_id, subject_id, access_token)
            .await?;
        Ok(roles)
    }

    /// Drop all cached entries for one env (Auth role-change event handler).
    pub fn invalidate_env(&self, env_id: Uuid) {
        let mut next = HashMap::clone(&*self.cache.load());
        next.retain(|(env, _), _| *env != env_id);
        self.cache.store(Arc::new(next));
    }
}

// ── Relation tuples ────────────────────────────────────────────────────────

/// One row of `policy_relations`.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct RelationRecord {
    pub id: Uuid,
    pub env_id: Uuid,
    /// Colon service_type owning the graph slice, e.g. `sentin8:post`.
    pub service: String,
    /// Subject entity type in the Shield policy language (e.g. `user` | `group`).
    pub subject_type: String,
    pub subject_id: String,
    /// Relation name, e.g. `owner` | `member` | `parent` | `viewer`.
    pub relation: String,
    /// Object entity type in the Shield policy language (e.g. `account` | `folder`).
    pub object_type: String,
    pub object_id: String,
    /// `platform` (registry-seeded, enroll-managed) | `tenant` (env admin).
    pub origin: String,
    #[sqlx(default)]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// One row of `policy_principal_attrs`.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct PrincipalAttrRecord {
    pub id: Uuid,
    pub env_id: Uuid,
    pub subject_id: String,
    pub attr_key: String,
    /// JSON value (string/number/bool/array) - stored as `jsonb`.
    pub attr_value: serde_json::Value,
    /// `platform` | `tenant`.
    pub origin: String,
    #[sqlx(default)]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Default cap on relation tuples loaded per evaluation set. Over-cap → the
/// loader returns an error → enforced evaluation fails closed (deny + audit).
pub const RELATION_SLICE_CAP: usize = 10_000;

/// Load the bounded relation slice for `(env_id, service)`.
pub async fn load_relations(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    service: &str,
) -> Result<Vec<RelationRecord>, sqlx::Error> {
    let rows: Vec<RelationRecord> = sqlx::query_as(
        r#"SELECT id, env_id, service, subject_type, subject_id, relation,
                  object_type, object_id, origin, created_at
             FROM sys.policy_relations
            WHERE env_id = $1 AND service = $2
            ORDER BY created_at
            LIMIT $3"#,
    )
    .bind(env_id)
    .bind(service)
    .bind(RELATION_SLICE_CAP as i64 + 1) // +1 detects over-cap below
    .fetch_all(pool)
    .await?;
    if rows.len() > RELATION_SLICE_CAP {
        return Err(sqlx::Error::Configuration(
            format!(
                "relation slice for {service} in {env_id} exceeds the {RELATION_SLICE_CAP}-tuple cap"
            )
            .into(),
        ));
    }
    Ok(rows)
}

/// Load all principal attributes for one subject in one env.
pub async fn load_principal_attrs(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    subject_id: &str,
) -> Result<Vec<PrincipalAttrRecord>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT id, env_id, subject_id, attr_key, attr_value, origin, created_at
             FROM sys.policy_principal_attrs
            WHERE env_id = $1 AND subject_id = $2"#,
    )
    .bind(env_id)
    .bind(subject_id)
    .fetch_all(pool)
    .await
}

/// Convert a JSON value into a Shield `RestrictedExpression` for attribute
/// injection (string / number / bool / set-of-strings). Nulls and objects are
/// skipped (cannot be expressed as restricted expressions).
pub fn json_to_restricted_expr(v: &serde_json::Value) -> Option<shield::RestrictedExpression> {
    use shield::RestrictedExpression;
    match v {
        serde_json::Value::String(s) => Some(RestrictedExpression::new_string(s.clone())),
        serde_json::Value::Bool(b) => Some(RestrictedExpression::new_bool(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(RestrictedExpression::new_long(i))
            } else {
                // Shield 4.12 restricted expressions support strings, longs,
                // bools, sets, and entity references - floats are truncated
                // to long (attribute values are admin-authored, not floats
                // in practice).
                n.as_f64().map(|f| RestrictedExpression::new_long(f as i64))
            }
        }
        serde_json::Value::Array(items) => {
            let elems: Vec<RestrictedExpression> =
                items.iter().filter_map(json_to_restricted_expr).collect();
            if elems.len() != items.len() {
                return None; // mixed nulls/objects - not representable
            }
            Some(RestrictedExpression::new_set(elems))
        }
        _ => None,
    }
}

/// Build the Shield entity `parents` edges from a relation slice.
///
/// Returns a map of entity UID string (`Type::"id"`) → set of parent UIDs.
/// A tuple `(subject, relation, object)` becomes a `parents` edge on the
/// SUBJECT entity (subject `in` object semantics for membership tuples).
/// Objects that appear only as objects get no entry (they exist implicitly
/// for `resource in Folder::"x"` style checks via the resource attrs).
pub fn relations_to_parents(records: &[RelationRecord]) -> BTreeMap<String, HashSet<String>> {
    let mut map: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for r in records {
        let subject_uid = format!("{}::\"{}\"", r.subject_type, r.subject_id);
        let object_uid = format!("{}::\"{}\"", r.object_type, r.object_id);
        map.entry(subject_uid).or_default().insert(object_uid);
    }
    map
}

/// Helper: build an `EntityUid` from colon-form type + id.
pub fn entity_uid(type_name: &str, id: &str) -> EntityUid {
    use std::str::FromStr;
    EntityUid::from_type_name_and_id(
        shield::EntityTypeName::from_str(type_name)
            .unwrap_or_else(|_| shield::EntityTypeName::from_str("User").expect("static fallback")),
        shield::EntityId::from_str(id)
            .unwrap_or_else(|_| shield::EntityId::from_str("unknown").expect("static fallback")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_expr_roundtrips_scalars_and_sets() {
        use shield::RestrictedExpression;
        assert!(json_to_restricted_expr(&json!("dept-eng")).is_some());
        assert!(json_to_restricted_expr(&json!(true)).is_some());
        assert!(json_to_restricted_expr(&json!(42)).is_some());
        assert!(json_to_restricted_expr(&json!(1.5)).is_some());
        assert!(json_to_restricted_expr(&json!(["a", "b"])).is_some());
        assert!(json_to_restricted_expr(&json!(null)).is_none());
        assert!(json_to_restricted_expr(&json!({"k": "v"})).is_none());
        let _: RestrictedExpression = json_to_restricted_expr(&json!("x")).unwrap();
    }

    #[test]
    fn relations_map_to_subject_parents() {
        let recs = vec![
            RelationRecord {
                id: Uuid::new_v4(),
                env_id: Uuid::nil(),
                service: "sentin8:post".into(),
                subject_type: "user".into(),
                subject_id: "u1".into(),
                relation: "member".into(),
                object_type: "group".into(),
                object_id: "fx-ops".into(),
                origin: "platform".into(),
                created_at: None,
            },
            RelationRecord {
                id: Uuid::new_v4(),
                env_id: Uuid::nil(),
                service: "sentin8:post".into(),
                subject_type: "group".into(),
                subject_id: "fx-ops".into(),
                relation: "member".into(),
                object_type: "folder".into(),
                object_id: "accounts-fx".into(),
                origin: "platform".into(),
                created_at: None,
            },
        ];
        let parents = relations_to_parents(&recs);
        assert_eq!(parents.get("user::\"u1\"").map(|s| s.len()), Some(1));
        assert!(parents
            .get("user::\"u1\"")
            .unwrap()
            .contains("group::\"fx-ops\""));
        assert!(parents
            .get("group::\"fx-ops\"")
            .unwrap()
            .contains("folder::\"accounts-fx\""));
    }

    #[test]
    fn role_entry_env_keying_prevents_cross_tenant_leak() {
        // The cache key includes env_id - two envs with the same subject id
        // never share entries (tenant-isolation invariant).
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_ne!(a, b);
        assert_ne!((a, "s".to_string()), (b, "s".to_string()));
    }

    #[tokio::test]
    async fn resolver_fails_closed_on_auth_unreachable() {
        // reqwest panics with "No provider set" without the PQ provider
        // (workspace reqwest uses rustls-tls-native-roots-no-provider).
        let _ = sentin8_tls::crypto::sentin8_pq_provider().install_default();
        // Auth unreachable → Err → the caller (require_policy) denies.
        let resolver = RoleResolver::with_ttl("http://127.0.0.1:1", Duration::from_millis(50));
        let out = resolver.resolve(Uuid::nil(), "subj", "tok").await;
        assert!(
            out.is_err(),
            "unreachable auth must error, never silently allow"
        );
    }
}
