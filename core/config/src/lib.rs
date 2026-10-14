// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-config
//!
//! Sentin8 domain derivation, constants, and platform configuration.
//!
//! All Sentin8 domains are derived at runtime from a single root configured via
//! `SENTIN8_DOMAIN` (default: `sentin8.local`). This crate is the single source
//! of truth for domain derivation: `{service}.{env}.{org}.{tld}` — platform
//! services live at `{service}.ops.sys.{domain}`.
//!
//! ## System UUIDs
//!
//! - `System Org ID`  = `00000000-0000-0000-0000-000000000001` — System organization (slug `sys`)
//! - `System Env ID`  = `00000000-0000-0000-0000-000000000002` — System environment (slug `ops`)

use std::env;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod bootstrap;
pub mod dns;
pub mod pg_pool;

// ── Constants ───────────────────────────────────────────────────────────

/// System organization UUID — the platform organization (slug `sys`).
/// Used for platform-level tables only (sentin8_sys_organizations, etc.).
pub const SYSTEM_ORG_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0001);

/// System organization slug.
pub const SYSTEM_ORG_SLUG: &str = "sys";

/// System environment UUID — the platform environment (slug `ops`).
pub const SYSTEM_ENV_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0002);

/// System environment slug.
pub const SYSTEM_ENV_SLUG: &str = "ops";

/// Default root domain if `SENTIN8_DOMAIN` is not set.
pub const DEFAULT_SENTIN8_DOMAIN: &str = "sentin8.local";

// ── Base port ───────────────────────────────────────────────────────────

/// Default base port — every Sentin8 service port derives from this as an
/// offset (see [`base_port`] and the `PORT_OFFSET_*` constants below).
///
/// `SENTIN8_BASE_PORT` env var overrides it. The fleet port layout:
///
/// | service      | offset              | default  |
/// |--------------|---------------------|----------|
/// | captain (API)  | `PORT_OFFSET_ORCH8` | base +0  |
/// | log (UDP)   | `PORT_OFFSET_LOG8`  | base +1  |
/// | proxy (TLS)  | `PORT_OFFSET_PROXY8` | 443      |
/// | service pool | `+2` … `+N`         | auto     |
///
/// The auto-assigned service pool starts at `base_port() + 2` and runs up
/// to `base_port() + 101` (overridable via `SENTIN8_CAPTAIN_PORT_RANGE_LOW/HIGH`).
/// dash, web, and every other service are auto-assigned from this pool —
/// no fixed per-service ports.
pub const DEFAULT_BASE_PORT: u16 = 8000;

/// Captain management API. The first thing that starts; base + 0.
pub const PORT_OFFSET_ORCH8: u16 = 0;
/// Log UDP ingest (fixed, well-known so services know where to send logs).
pub const PORT_OFFSET_LOG8: u16 = 1;
/// Proxy external L4 LB — always on the standard HTTPS port 443 (overridable
/// via `SENTIN8_PROXY_PORT`). Not a base-port offset because it's a well-known port.
pub const SENTIN8_PROXY_DEFAULT_PORT: u16 = 443;
/// First auto-assigned service pool port = base + 2.
pub const PORT_POOL_START_OFFSET: u16 = 2;
/// Number of auto-assignable service pool slots (base+2 .. base+2+this).
pub const PORT_POOL_COUNT: u16 = 100;

/// Resolve the Sentin8 base port from `SENTIN8_BASE_PORT` (default `DEFAULT_BASE_PORT`).
///
/// Every service port in the platform derives from this single value, so the
/// whole fleet can be re-sharded by setting one env var. See the table in
/// [`DEFAULT_BASE_PORT`]'s docs.
pub fn base_port() -> u16 {
    std::env::var("SENTIN8_BASE_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|p: &u16| *p > 0)
        .unwrap_or(DEFAULT_BASE_PORT)
}

/// Captain management API port = `base_port() + PORT_OFFSET_ORCH8`.
pub fn captain_port() -> u16 {
    base_port() + PORT_OFFSET_ORCH8
}

/// Log UDP ingest port = `base_port() + PORT_OFFSET_LOG8`.
pub fn sentin8_log_port() -> u16 {
    base_port() + PORT_OFFSET_LOG8
}

/// Proxy external port (default `SENTIN8_PROXY_DEFAULT_PORT` = 443).
pub fn sentin8_proxy_port() -> u16 {
    std::env::var("SENTIN8_PROXY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|p: &u16| *p > 0)
        .unwrap_or(SENTIN8_PROXY_DEFAULT_PORT)
}

/// Auto-assigned service pool low bound = `base_port() + PORT_POOL_START_OFFSET`.
pub fn port_pool_low() -> u16 {
    base_port() + PORT_POOL_START_OFFSET
}

/// Auto-assigned service pool high bound = `port_pool_low() + PORT_POOL_COUNT - 1`.
pub fn port_pool_high() -> u16 {
    port_pool_low() + PORT_POOL_COUNT - 1
}

// ── FHS paths (Debian packaging) ───────────────────────────────────────
//
// These helpers resolve the FHS-conventional directories used by the
// packaged (`.deb`) deployment, overridable via env vars for dev builds.
//
// | env var                  | default (prod)      | dev fallback        |
// |--------------------------|----------------------|---------------------|
// | `SENTIN8_CONFIG_DIR`     | `/etc/sentin8`       | (unset — unused)    |
// | `SENTIN8_STATE_DIR`      | `/var/lib/sentin8`   | (unset — unused)    |
// | `SENTIN8_LOG_DIR`        | `/var/log/sentin8`   | `.run/logs`         |
// | `SENTIN8_RUN_DIR`        | `/run/sentin8`       | `.run`              |

// The helpers resolve the packaged deployment's FHS-conventional
// directories, overridable via env vars for dev builds.

/// Configuration directory — `/etc/sentin8` in production (overridable via
/// `SENTIN8_CONFIG_DIR`). Holds `sentin8.env`, `sentin8.toml`, per-vertical
/// overrides.
pub fn config_dir() -> String {
    std::env::var("SENTIN8_CONFIG_DIR").unwrap_or_else(|_| "/etc/sentin8".to_string())
}

/// Stateful data directory — `/var/lib/sentin8` in production (overridable via
/// `SENTIN8_STATE_DIR`). Holds TLS certs, storage adapter root, captain state.
pub fn state_dir() -> String {
    std::env::var("SENTIN8_STATE_DIR").unwrap_or_else(|_| "/var/lib/sentin8".to_string())
}

/// Log directory — `/var/log/sentin8` in production (overridable via
/// `SENTIN8_LOG_DIR`). Defaults to `.run/logs` for dev builds (relative).
pub fn log_dir() -> String {
    std::env::var("SENTIN8_LOG_DIR").unwrap_or_else(|_| ".run/logs".to_string())
}

/// Runtime (PID/socket) directory — `/run/sentin8` in production (overridable
/// via `SENTIN8_RUN_DIR`). Defaults to `.run` for dev builds (relative).
/// `/run` is a tmpfs in Debian, so PID files do not survive reboot.
pub fn run_dir() -> String {
    std::env::var("SENTIN8_RUN_DIR").unwrap_or_else(|_| ".run".to_string())
}

/// TLS state directory — `{state_dir()}/tls`. Holds the Acme CA + service certs.
pub fn tls_dir() -> String {
    format!("{}/tls", state_dir())
}

/// Sentin8:Storage local-FS adapter root — `{state_dir()}/storage`.
pub fn storage_dir() -> String {
    format!("{}/storage", state_dir())
}

/// Captain state directory — `{state_dir()}/captain`.
pub fn captain_state_dir() -> String {
    format!("{}/captain", state_dir())
}

/// Path to the captain PID file — `{run_dir()}/captain.pid`.
pub fn captain_pid_file() -> String {
    format!("{}/captain.pid", run_dir())
}

/// Path to the captain local control socket — `{run_dir()}/captain.sock`.
///
/// The Unix domain socket serves the same management API as the TCP
/// listener; requests from root or the socket owner are authorized by
/// kernel-proven peer credentials (`SO_PEERCRED`) instead of a Bearer
/// token — the `systemctl` model for local `make start/stop/status`.
/// Overridable via `SENTIN8_CAPTAIN_SOCK`.
pub fn captain_socket_file() -> String {
    std::env::var("SENTIN8_CAPTAIN_SOCK").unwrap_or_else(|_| format!("{}/captain.sock", run_dir()))
}

// ── Config ──────────────────────────────────────────────────────────────

/// Platform configuration loaded from environment variables.
///
/// Construct via [`Sentin8Config::from_env`] or [`Sentin8Config::builder`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sentin8Config {
    /// Root domain — all Sentin8 domains derive from this.
    pub sentin8_domain: String,
}

impl Sentin8Config {
    /// Load configuration from the optional TOML file at `config_dir()/sentin8.toml`,
    /// then override with environment variables.
    ///
    /// Layer order (figment): TOML file (base) → env vars (override).
    /// The `.env` file is loaded by the caller (e.g. via `dotenvy::dotenv` in
    /// `main`), so env vars from `.env` are also picked up.
    ///
    /// Reads `SENTIN8_DOMAIN` (default: `sentin8.local`).
    pub fn from_env() -> Self {
        use figment::providers::{Env, Format, Toml};

        // Build a figment: TOML file (if present) as base, env as override.
        let toml_path = format!("{}/sentin8.toml", config_dir());
        let mut figment = figment::Figment::new();

        // TOML layer — only if the file exists (optional).
        if std::path::Path::new(&toml_path).is_file() {
            figment = figment.merge(Toml::file(&toml_path));
        }

        // Env layer — SENTIN8_* prefixed, overrides TOML.
        figment = figment.merge(Env::prefixed("SENTIN8_"));

        // Extract the domain. Figment uses snake_case keys without the prefix.
        let sentin8_domain = figment
            .extract_inner::<String>("domain")
            .unwrap_or_else(|_| {
                env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| DEFAULT_SENTIN8_DOMAIN.to_string())
            });

        Self { sentin8_domain }
    }

    /// Create a builder for constructing a config programmatically (tests).
    pub fn builder() -> Sentin8ConfigBuilder {
        Sentin8ConfigBuilder {
            sentin8_domain: DEFAULT_SENTIN8_DOMAIN.to_string(),
        }
    }
}

/// Builder for [`Sentin8Config`].
#[derive(Debug, Clone)]
pub struct Sentin8ConfigBuilder {
    sentin8_domain: String,
}

impl Sentin8ConfigBuilder {
    pub fn sentin8_domain(mut self, domain: impl Into<String>) -> Self {
        self.sentin8_domain = domain.into();
        self
    }

    pub fn build(self) -> Sentin8Config {
        Sentin8Config {
            sentin8_domain: self.sentin8_domain,
        }
    }
}

// ── Service identity naming ─────────────────────────────────────────────

/// Canonical `service_type` — the colon identity `vertical:service[:worker]`.
///
/// Normalizes any accepted input to the colon form:
/// - `sentin8:auth`              → `sentin8:auth` (canonical, returned as-is)
/// - `bank8:payments:worker`     → `bank8:payments:worker` (canonical worker)
/// - `bank8:payments:w`          → `bank8:payments:worker` (worker alias)
/// - `sentin8-auth`              → `sentin8:auth` (legacy hyphen form)
/// - `bank8-payments-worker`     → `bank8:payments:worker` (legacy hyphen form)
/// - `bank8-ledger`              → `bank8:ledger` (legacy hyphen form)
///
/// A legacy token has exactly one leading segment before the first dash
/// (the vertical); every subsequent dash-separated component is joined
/// with colons. Workers are recognized by their trailing `worker`
/// component (the legacy `-worker` suffix or the canonical `:worker`).
pub fn canonical_service_type(token: &str) -> String {
    let t = token.trim();
    if t.is_empty() {
        return t.to_string();
    }
    // Worker alias shorthand (`…:w`) → `…:worker` first, on both forms.
    let t = match t.strip_suffix(":w") {
        Some(base) => format!("{base}:worker"),
        None => t.to_string(),
    };
    // Already canonical (colon-only): return as-is.
    if t.contains(':') && !t.contains('-') {
        return t;
    }
    // Legacy hyphen form: `vertical-rest…` → `vertical:rest…`.
    // `bank8-payments-worker` → `bank8:payments-worker` → `bank8:payments:worker`.
    t.replace('-', ":")
}

/// True when the identity names a worker process (has a `worker` segment).
pub fn is_worker_service(service_type: &str) -> bool {
    service_type.ends_with(":worker")
        || service_type.ends_with("-worker")
        || service_type.ends_with(":w")
}

/// The service identity without its `worker` segment.
///
/// `bank8:payments:worker` → `bank8:payments`; `bank8:ledger` → `bank8:ledger`.
/// Does not normalize dash forms to colon form — callers working with
/// legacy inputs should pass through [`canonical_service_type`] first.
pub fn service_base_type(service_type: &str) -> &str {
    if let Some(base) = service_type.strip_suffix(":worker") {
        return base;
    }
    if let Some(base) = service_type.strip_suffix("-worker") {
        return base;
    }
    if let Some(base) = service_type.strip_suffix(":w") {
        return base;
    }
    service_type
}

/// The worker identity for a base identity — `bank8:payments` → `bank8:payments:worker`.
/// Returns the input unchanged when it is not a base (non-worker) identity.
pub fn worker_type(service_type: &str) -> String {
    if is_worker_service(service_type) {
        return service_type.to_string();
    }
    format!("{service_type}:worker")
}

/// Dash (DNS/binary) form of a service identity — `:` → `-`.
///
/// `bank8:payments:worker` → `bank8-payments-worker`; `bank8:ledger` → `bank8-ledger`.
/// Used for binary names, log filenames, and any DNS-derived label that
/// starts from the full identity.
pub fn service_dash_form(service_type: &str) -> String {
    service_type.replace(':', "-")
}

/// Upper-snake env-var slug — `:` and `-` → `_`, uppercased.
///
/// `sentin8:stat` → `SENTIN8_STAT`; `bank8:payments` → `BANK8_PAYMENTS`.
/// This is the slug used for `{SLUG}_PORT` / `{SLUG}_W_PORT` env vars.
pub fn service_env_slug(service_type: &str) -> String {
    service_base_type(service_type)
        .replace([':', '-'], "_")
        .to_ascii_uppercase()
}

/// The scope namespace for a service identity.
///
/// Uniform rule: every RBAC name starts with its vertical — the namespace
/// is the identity's first TWO segments
/// plus a trailing colon, for ALL services (`sentin8:auth` →
/// `sentin8:auth:`, `bank8:ledger` → `bank8:ledger:`). Workers resolve to
/// their base service's namespace. Platform scopes therefore carry the
/// literal `sentin8` segment (`sentin8:auth:read`), exactly like vertical
/// scopes (`bank8:ledger:products:write`) — no exceptions.
pub fn service_scope_namespace(service_type: &str) -> String {
    let base = service_base_type(service_type);
    let segments: Vec<&str> = base.split(':').collect();
    match segments.as_slice() {
        [vertical, _service] => format!("{vertical}:{}:", segments[1]),
        _ => format!("{}:", base.replace('-', ":")),
    }
}

// ── Domain derivation ────────────────────────────────────────────────────

impl Sentin8Config {
    /// Root domain (e.g. `sentin8.local`).
    pub fn domain(&self) -> &str {
        &self.sentin8_domain
    }

    /// Platform service domain: `{service}.ops.sys.{sentin8_domain}`.
    ///
    /// Accepts either a bare service name (`auth`), the colon identity
    /// (`sentin8:auth`, `bank8:ledger`), or the legacy hyphen form
    /// (`sentin8-auth`). The input is normalized to the canonical colon
    /// identity first, then converted to the dash-form DNS label — e.g.
    /// `sentin8:auth` → `auth.ops.sys.sentin8.local` (the `sentin8:`
    /// prefix is dropped), `bank8:ledger` and the legacy `bank8-ledger`
    /// both → `bank8-ledger.ops.sys.sentin8.local`.
    ///
    /// E.g. `auth.ops.sys.sentin8.local`.
    pub fn platform_domain(&self, service: &str) -> String {
        let canonical = canonical_service_type(service);
        let label = if let Some(rest) = canonical.strip_prefix("sentin8:") {
            rest.to_string()
        } else {
            service_dash_form(&canonical)
        };
        format!("{label}.ops.sys.{}", self.sentin8_domain)
    }

    /// Resolve the subdomain (hostname label) for a service from the runtime
    /// registry (`sys.vertical_services.subdomain`).
    ///
    /// This is the single source of truth for service → subdomain resolution,
    /// used by the BFF proxy, proxy domain resolver, and TLS context to build
    /// the correct upstream hostname. Falls back to the service name itself
    /// if not found in the registry.
    ///
    /// Platform services like `sentin8:func` have `subdomain = "func"` in the
    /// registry, so the upstream URL becomes `func.ops.sys.sentin8.local` (not
    /// `sentin8-func.ops.sys.sentin8.local`). Vertical services like
    /// `bank8:ledger` have `subdomain = "bank8-ledger"` (the DNS label form of
    /// the identity). Inputs are normalized to the canonical colon identity
    /// first, so legacy hyphen callers resolve identically.
    pub async fn resolve_subdomain(&self, pool: &sqlx::PgPool, service: &str) -> String {
        let canonical = canonical_service_type(service);
        sqlx::query_scalar::<_, String>(
            r#"SELECT subdomain FROM sys.vertical_services WHERE service_type = $1"#,
        )
        .bind(canonical.clone())
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        // The fallback must be DNS-valid (config README §5): under a
        // tenant-scoped RLS context the SYSTEM-scoped registry row is
        // invisible, and the raw colon identity (`bank8:fdx`) is not a
        // hostname — a URL built from it (`https://bank8:fdx.…`) cannot be
        // navigated by any browser (colon = authority/port separator) nor
        // matched by TLS SNI. The dash form (`bank8-fdx`) is the registry's
        // own convention for vertical services, so the fallback matches it
        // by construction.
        .unwrap_or_else(|| service_dash_form(&canonical))
    }

    /// Check if a service is a platform service (vertical = "sentin8") by
    /// querying the runtime registry. No hardcoded list — the `vertical`
    /// column is the single source of truth. Inputs are normalized to the
    /// canonical colon identity first.
    pub async fn is_platform_service(&self, pool: &sqlx::PgPool, service: &str) -> bool {
        let canonical = canonical_service_type(service);
        sqlx::query_scalar::<_, i64>(
            r#"SELECT COUNT(*) FROM sys.vertical_services WHERE service_type = $1 AND vertical = 'sentin8'"#,
        )
        .bind(canonical)
        .fetch_one(pool)
        .await
        .map(|c| c > 0)
        .unwrap_or(false)
    }

    /// Build the platform-scoped upstream URL for a service, resolving its
    /// subdomain from the runtime registry.
    ///
    /// Convenience wrapper: `resolve_subdomain` + `platform_domain`.
    /// Returns `https://{subdomain}.ops.sys.{sentin8_domain}`.
    pub async fn platform_service_url(&self, pool: &sqlx::PgPool, service: &str) -> String {
        let subdomain = self.resolve_subdomain(pool, service).await;
        format!("https://{}", self.platform_domain(&subdomain))
    }

    /// Build the env-scoped upstream URL for a service, resolving its
    /// subdomain from the runtime registry.
    ///
    /// Returns `https://{subdomain}.{env_domain}`.
    pub async fn env_service_url(
        &self,
        pool: &sqlx::PgPool,
        service: &str,
        env_domain: &str,
    ) -> String {
        let subdomain = self.resolve_subdomain(pool, service).await;
        format!("https://{}.{}", subdomain, env_domain)
    }

    /// Resolve a subdomain label back to the full service_type from the
    /// runtime registry. This is the reverse of `resolve_subdomain`.
    ///
    /// Used by the proxy and TLS to resolve a hostname's first DNS label
    /// (e.g. `func`) to the full service identity (e.g. `sentin8:func`).
    /// Falls back to the dash-form `sentin8-web` for unknown labels (app
    /// instances) — consumers normalize via `canonical_service_type` when
    /// they need the colon form.
    pub async fn resolve_service_type(&self, pool: &sqlx::PgPool, label: &str) -> String {
        sqlx::query_scalar::<_, String>(
            r#"SELECT service_type FROM sys.vertical_services WHERE subdomain = $1"#,
        )
        .bind(label)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "sentin8-web".to_string())
    }

    /// Transaction-scoped variant of [`Self::resolve_service_type`].
    ///
    /// `sys.vertical_services` carries tenant RLS — callers inside a
    /// context-carrying transaction MUST query on that transaction's
    /// connection, not a pooled one: a pooled query has no tenant context
    /// (RLS-filtered → wrong fallback) and leaks an open transaction per
    /// miss (idle-in-transaction pool exhaustion).
    pub async fn resolve_service_type_in_tx(
        &self,
        conn: &mut sqlx::PgConnection,
        label: &str,
    ) -> String {
        sqlx::query_scalar::<_, String>(
            r#"SELECT service_type FROM sys.vertical_services WHERE subdomain = $1"#,
        )
        .bind(label)
        .fetch_optional(conn)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "sentin8-web".to_string())
    }

    /// Load the full subdomain → service_type map from the runtime registry.
    /// Used by the proxy to build an in-memory cache for SNI resolution.
    pub async fn load_subdomain_map(
        &self,
        pool: &sqlx::PgPool,
    ) -> std::collections::HashMap<String, String> {
        sqlx::query(r#"SELECT service_type, subdomain FROM sys.vertical_services"#)
            .fetch_all(pool)
            .await
            .map(|rows| {
                use sqlx::Row;
                rows.into_iter()
                    .map(|r| {
                        (
                            r.get::<String, _>("subdomain"),
                            r.get::<String, _>("service_type"),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Transaction-scoped variant of [`Self::load_subdomain_map`] — same RLS
    /// rule as [`Self::resolve_service_type_in_tx`]: callers inside a
    /// context-carrying transaction must query on that connection.
    pub async fn load_subdomain_map_in_tx(
        &self,
        conn: &mut sqlx::PgConnection,
    ) -> std::collections::HashMap<String, String> {
        sqlx::query(r#"SELECT service_type, subdomain FROM sys.vertical_services"#)
            .fetch_all(conn)
            .await
            .map(|rows| {
                use sqlx::Row;
                rows.into_iter()
                    .map(|r| {
                        (
                            r.get::<String, _>("subdomain"),
                            r.get::<String, _>("service_type"),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Organization domain (default): `{org_slug}.{sentin8_domain}`.
    pub fn org_domain(&self, org_slug: &str) -> String {
        format!("{org_slug}.{}", self.sentin8_domain)
    }

    /// Build the typed [`OrgDomain`] for the given org slug (default pattern).
    pub fn org_domain_typed(&self, org_slug: &str) -> OrgDomain {
        OrgDomain::new(self.org_domain(org_slug))
    }

    /// Build a typed [`OrgDomain`] from a (possibly custom) domain string.
    pub fn org_domain_from(&self, domain: impl Into<String>) -> OrgDomain {
        OrgDomain::new(domain.into())
    }

    /// Organization Auth (staff) domain: `auth.ops.{org_domain}`.
    pub fn org_auth_domain(&self, org_domain: &str) -> String {
        format!("auth.ops.{org_domain}")
    }

    /// Organization Dash domain: `dash.ops.{org_domain}`.
    pub fn org_dash_domain(&self, org_domain: &str) -> String {
        format!("dash.ops.{org_domain}")
    }

    /// Organization BFF domain: `bff.ops.{org_domain}`.
    pub fn org_sentin8_bff_domain(&self, org_domain: &str) -> String {
        format!("bff.ops.{org_domain}")
    }

    /// Organization Buck domain: `storage.ops.{org_domain}`.
    pub fn org_sentin8_storage_domain(&self, org_domain: &str) -> String {
        format!("storage.ops.{org_domain}")
    }

    // ── Service-specific org sub-domains ──────────────────────────
    //
    // All Sentin8 services can be exposed at an org-scoped sub-domain of the
    // form `{service_prefix}.ops.{org_domain}`. The `ops` segment is the
    // org-level (staff) environment — the same `ops` slug used by the `sys`
    // org for platform services. These helpers generate the canonical
    // hostname for each service at the org level. The platform only upserts
    // a subset of these mappings into `sentin8_tls_mappings` by default (auth,
    // dash, bff, storage); the remaining helpers exist so that services and
    // tests can construct/verify the canonical names when needed.

    /// Organization App domain: `app.ops.{org_domain}`.
    pub fn org_sentin8_app_domain(&self, org_domain: &str) -> String {
        format!("app.ops.{org_domain}")
    }

    /// Organization DB domain: `db.ops.{org_domain}`.
    pub fn org_sentin8_db_domain(&self, org_domain: &str) -> String {
        format!("db.ops.{org_domain}")
    }

    /// Organization Bus domain: `bus.ops.{org_domain}`.
    pub fn org_sentin8_bus_domain(&self, org_domain: &str) -> String {
        format!("bus.ops.{org_domain}")
    }

    /// Organization Stat domain: `stat.ops.{org_domain}`.
    pub fn org_sentin8_stat_domain(&self, org_domain: &str) -> String {
        format!("stat.ops.{org_domain}")
    }

    /// Organization Captain domain: `captain.ops.{org_domain}`.
    pub fn org_orch_domain(&self, org_domain: &str) -> String {
        format!("captain.ops.{org_domain}")
    }

    /// Organization Func domain: `func.ops.{org_domain}`.
    pub fn org_sentin8_func_domain(&self, org_domain: &str) -> String {
        format!("func.ops.{org_domain}")
    }

    /// Organization Cron domain: `cron.ops.{org_domain}`.
    pub fn org_sentin8_cron_domain(&self, org_domain: &str) -> String {
        format!("cron.ops.{org_domain}")
    }

    /// Organization Flow domain: `flow.ops.{org_domain}`.
    pub fn org_sentin8_flow_domain(&self, org_domain: &str) -> String {
        format!("flow.ops.{org_domain}")
    }

    /// Organization Sys domain: `sys.ops.{org_domain}`.
    pub fn org_sentin8_sys_domain(&self, org_domain: &str) -> String {
        format!("sys.ops.{org_domain}")
    }

    /// Environment domain: `{env_slug}.{org_domain}`.
    pub fn env_domain(&self, env_slug: &str, org_domain: &str) -> String {
        format!("{env_slug}.{org_domain}")
    }

    /// Build the typed [`EnvDomain`] for the given env slug + org domain.
    pub fn env_domain_typed(&self, env_slug: &str, org_domain: &OrgDomain) -> EnvDomain {
        EnvDomain::new(self.env_domain(env_slug, org_domain.as_str()))
    }

    /// Build a typed [`EnvDomain`] from a (possibly custom) domain string.
    pub fn env_domain_from(&self, domain: impl Into<String>) -> EnvDomain {
        EnvDomain::new(domain.into())
    }

    /// Environment Auth (customer) domain: `auth.{env_domain}`.
    pub fn env_auth_domain(&self, env_domain: &str) -> String {
        format!("auth.{env_domain}")
    }

    /// Environment Storage domain: `storage.{env_domain}`.
    pub fn env_sentin8_storage_domain(&self, env_domain: &str) -> String {
        format!("storage.{env_domain}")
    }

    // ── Service-specific env sub-domains ──────────────────────────

    /// Environment Dash domain: `dash.{env_domain}`.
    pub fn env_dash_domain(&self, env_domain: &str) -> String {
        format!("dash.{env_domain}")
    }

    /// Environment BFF domain: `bff.{env_domain}`.
    pub fn env_sentin8_bff_domain(&self, env_domain: &str) -> String {
        format!("bff.{env_domain}")
    }

    /// Environment App domain: `app.{env_domain}`.
    pub fn env_sentin8_app_domain(&self, env_domain: &str) -> String {
        format!("app.{env_domain}")
    }

    /// Environment DB domain: `db.{env_domain}`.
    pub fn env_sentin8_db_domain(&self, env_domain: &str) -> String {
        format!("db.{env_domain}")
    }

    /// Environment Bus domain: `bus.{env_domain}`.
    pub fn env_sentin8_bus_domain(&self, env_domain: &str) -> String {
        format!("bus.{env_domain}")
    }

    /// Environment TLS domain: `tls.{env_domain}`.
    pub fn env_sentin8_tls_domain(&self, env_domain: &str) -> String {
        format!("tls.{env_domain}")
    }

    /// Environment Stat domain: `stat.{env_domain}`.
    pub fn env_sentin8_stat_domain(&self, env_domain: &str) -> String {
        format!("stat.{env_domain}")
    }

    /// Environment Log domain: `log.{env_domain}`.
    pub fn env_sentin8_log_domain(&self, env_domain: &str) -> String {
        format!("log.{env_domain}")
    }

    /// Environment Captain domain: `captain.{env_domain}`.
    pub fn env_orch_domain(&self, env_domain: &str) -> String {
        format!("captain.{env_domain}")
    }

    /// Environment Func domain: `func.{env_domain}`.
    pub fn env_sentin8_func_domain(&self, env_domain: &str) -> String {
        format!("func.{env_domain}")
    }

    /// Environment Cron domain: `cron.{env_domain}`.
    pub fn env_sentin8_cron_domain(&self, env_domain: &str) -> String {
        format!("cron.{env_domain}")
    }

    /// Environment Flow domain: `flow.{env_domain}`.
    pub fn env_sentin8_flow_domain(&self, env_domain: &str) -> String {
        format!("flow.{env_domain}")
    }

    /// Environment Sys domain: `sys.{env_domain}`.
    pub fn env_sentin8_sys_domain(&self, env_domain: &str) -> String {
        format!("sys.{env_domain}")
    }

    /// Application domain (default): `{app_slug}.{env_domain}`.
    pub fn app_domain(&self, app_slug: &str, env_domain: &str) -> String {
        format!("{app_slug}.{env_domain}")
    }

    /// Build the typed [`AppDomain`] for the given app slug + env domain.
    pub fn app_domain_typed(&self, app_slug: &str, env_domain: &EnvDomain) -> AppDomain {
        AppDomain::new(self.app_domain(app_slug, env_domain.as_str()))
    }

    /// Build a typed [`AppDomain`] from a (possibly custom) domain string.
    pub fn app_domain_from(&self, domain: impl Into<String>) -> AppDomain {
        AppDomain::new(domain.into())
    }

    /// Application BFF domain: `bff.{app_domain}`.
    ///
    /// The BFF hostname for an app instance is always `bff.{app_domain}` —
    /// e.g. `bff.www.ibank.local`.
    pub fn app_bff_domain(&self, app_domain: &str) -> String {
        format!("bff.{app_domain}")
    }

    // ── Platform service URLs ──────────────────────────────────────

    /// Auth base URL: `https://auth.ops.sys.{sentin8_domain}`.
    pub fn sentin8_auth_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:auth"))
    }

    /// Auth JWKS URL: `https://auth.ops.sys.{sentin8_domain}/.well-known/jwks.json`.
    pub fn sentin8_auth_jwks_url(&self) -> String {
        format!("{}/.well-known/jwks.json", self.sentin8_auth_url())
    }

    /// Auth issuer: `https://auth.ops.sys.{sentin8_domain}`.
    pub fn sentin8_auth_issuer(&self) -> String {
        self.sentin8_auth_url()
    }

    /// DB base URL: `https://db.ops.sys.{sentin8_domain}`.
    pub fn sentin8_db_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:db"))
    }

    /// Storage base URL: `https://storage.ops.sys.{sentin8_domain}`.
    pub fn sentin8_storage_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:storage"))
    }

    /// BFF base URL: `https://bff.ops.sys.{sentin8_domain}`.
    pub fn sentin8_bff_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:bff"))
    }

    /// TLS base URL: `https://tls.ops.sys.{sentin8_domain}`.
    pub fn sentin8_tls_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:tls"))
    }

    /// Bus base URL: `https://bus.ops.sys.{sentin8_domain}`.
    pub fn sentin8_bus_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:bus"))
    }

    /// Sys base URL: `https://sys.ops.sys.{sentin8_domain}`.
    pub fn sentin8_sys_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:sys"))
    }

    /// App base URL: `https://app.ops.sys.{sentin8_domain}`.
    pub fn sentin8_app_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:app"))
    }

    /// Dash base URL: `https://dash.ops.sys.{sentin8_domain}`.
    pub fn dash_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:dash"))
    }

    /// Func base URL: `https://func.ops.sys.{sentin8_domain}`.
    pub fn sentin8_func_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:func"))
    }

    /// Cron base URL: `https://cron.ops.sys.{sentin8_domain}`.
    pub fn sentin8_cron_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:cron"))
    }

    /// Flow base URL: `https://flow.ops.sys.{sentin8_domain}`.
    pub fn sentin8_flow_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:flow"))
    }

    /// Stat base URL: `https://stat.ops.sys.{sentin8_domain}`.
    pub fn sentin8_stat_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:stat"))
    }

    /// Log base URL: `https://log.ops.sys.{sentin8_domain}`.
    pub fn sentin8_log_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:log"))
    }

    /// Post base URL: `https://post.ops.sys.{sentin8_domain}`.
    pub fn sentin8_post_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:post"))
    }

    /// AI base URL: `https://ai.ops.sys.{sentin8_domain}`.
    pub fn sentin8_ai_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:ai"))
    }

    /// Captain base URL: `https://captain.ops.sys.{sentin8_domain}`.
    pub fn captain_url(&self) -> String {
        format!("https://{}", self.platform_domain("sentin8:captain"))
    }

    /// Default database URL for local dev:
    /// `postgres://sentin8_app@localhost:5432/sentin8`.
    ///
    /// Uses the `sentin8_app` role so that RLS policies are enforced at
    /// runtime. The `sentin8` superuser role is only used for
    /// migrations/init scripts. PostgreSQL certificate identity
    /// (group DESIGN.md §3.2): the connection presents the `sentin8_app`
    /// workload pair — there is no password component.
    pub fn default_database_url() -> &'static str {
        "postgres://sentin8_app@localhost:5432/sentin8"
    }

    /// Default PostgreSQL superuser URL (for migrations/init only).
    pub fn superuser_database_url() -> &'static str {
        "postgres://sentin8@localhost:5432/sentin8"
    }

    /// Minimum required PostgreSQL major version.
    pub const MIN_POSTGRES_VERSION: u32 = 18;

    /// Check that the connected PostgreSQL server meets the minimum version
    /// requirement. Returns an error if the version is too low.
    pub async fn check_postgres_version(pool: &sqlx::PgPool) -> Result<(), String> {
        let row: (String,) = sqlx::query_as("SELECT version()")
            .fetch_one(pool)
            .await
            .map_err(|e| format!("failed to query PostgreSQL version: {e}"))?;
        let version_str = row.0;
        // Parse "PostgreSQL 18.0 on ..." → extract major version
        let major: u32 = version_str
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.split('.').next())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if major < Self::MIN_POSTGRES_VERSION {
            return Err(format!(
                "PostgreSQL {major} is below the minimum required version {}",
                Self::MIN_POSTGRES_VERSION
            ));
        }
        tracing::info!(version = %version_str, "PostgreSQL version check passed");
        Ok(())
    }

    /// Default Valkey URL: `valkey://localhost:6379/0` (plaintext — the
    /// platform runs Valkey on a trusted internal network; no TLS).
    pub fn default_valkey_url() -> &'static str {
        // The Valkey data plane is TLS-only (group DESIGN.md §3.1) — the
        // default scheme matches the deployed plane; a plaintext default
        // would fail-closed at the factory's scheme gate by design.
        "valkeys://localhost:6379/0"
    }

    /// Read `VALKEY_URL` from the environment, falling back to the default
    /// `valkey://localhost:6379/0` when unset or empty.
    pub fn valkey_url_from_env() -> String {
        std::env::var("VALKEY_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| Self::default_valkey_url().to_string())
    }

    /// Enforce the PostgreSQL 18+ version requirement at service startup.
    ///
    /// Behaviour is mode-dependent so the dev environment (which may still
    /// be on PostgreSQL 16) is not broken:
    ///
    /// - **Release** builds: a version below `MIN_POSTGRES_VERSION` is a
    ///   hard error — the service aborts startup.
    /// - **Debug** builds: a low version only logs a `warn!` so developers
    ///   can keep iterating against the dev image.
    ///
    /// On success (or in debug-mode with a low version) the function
    /// returns `Ok(())`; in release-mode failure it returns the error
    /// string so the caller can `.expect()` it.
    pub async fn enforce_postgres_version(pool: &sqlx::PgPool) -> Result<(), String> {
        match Self::check_postgres_version(pool).await {
            Ok(()) => Ok(()),
            Err(err) => {
                if cfg!(debug_assertions) {
                    tracing::warn!(error = %err, "PostgreSQL version check failed (debug build — continuing)");
                    Ok(())
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Parse the `SENTIN8_LOG_DESTINATIONS` env var into a de-duplicated
    /// `Vec<LogDestination>`. Defaults to `[LogDestination::LogUdp]` when
    /// the var is **unset**. An explicit empty value
    /// (`SENTIN8_LOG_DESTINATIONS=`) or `"none"` disables emission
    /// entirely — used by log itself to avoid the feedback
    /// loop of forwarding its own tracing events back to its own UDP
    /// listener.
    ///
    /// Unknown values panic (the service fails fast at startup) — a typo
    /// like `log:foo` should never silently degrade observability.
    pub fn log_destinations(&self) -> Vec<LogDestination> {
        // Distinguish "unset" from "explicitly empty": an unset var
        // falls back to the default `[log:udp]`, but an empty value
        // (e.g. `export SENTIN8_LOG_DESTINATIONS=` in a per-service env
        // file) means "no fan-out — do not echo events back over UDP to
        // the listener we are hosting".
        match std::env::var("SENTIN8_LOG_DESTINATIONS") {
            Ok(raw) => parse_log_destinations(&raw),
            Err(_) => vec![LogDestination::LogUdp],
        }
    }
}

/// The database name a service identity owns (VDC §VDC.3, DSN integrity).
///
/// Platform services (`sentin8:*` / `sentin8-*`) own the `sentin8`
/// database; a vertical service owns its vertical's database — the first
/// identity segment (`bank8:ledger` → `bank8`, `bank8:payments:worker` →
/// `bank8`). This is the *expected* database for the service's main pool;
/// a DSN pointing anywhere else is a misconfiguration (wrong-database
/// accident) and must fail fast at boot, never silently fall back.
///
/// # Examples
///
/// ```
/// assert_eq!(sentin8_config::expected_database_name("bank8:ledger"), "bank8");
/// assert_eq!(sentin8_config::expected_database_name("sentin8:auth"), "sentin8");
/// assert_eq!(
///     sentin8_config::expected_database_name("bank8:payments:worker"),
///     "bank8");
/// ```
pub fn expected_database_name(service_identity: &str) -> String {
    let canonical = canonical_service_type(service_identity);
    let first = canonical.split(':').next().unwrap_or(&canonical);
    first.to_string()
}

/// Derive a service's PostgreSQL DSN from its service identity
/// (DSNDERIVE-1, group DESIGN.md §3.2).
///
/// Under certificate identity a DSN is PURE STRUCTURE — the connecting
/// role, the host, and the database; no secret component exists (the
/// client certificate is the credential, resolved by the pg_pool
/// factory from the role). All three parts derive from the
/// `service_type` the service already hardcodes in `main.rs`:
///
/// - **role** — the canonical identity with `:`→`_` and the `_service`
///   suffix: `exchange8:sor` → `exchange8_sor_service`.
///   `:worker` identities resolve to the parent service's role
///   (`bank8:payments:worker` → `bank8_payments_service` — the worker
///   rides the same schema/role as its parent; a separate role would
///   defeat schema-per-service).
/// - **database** — [`expected_database_name`] (the vertical, VDC
///   §VDC.3): `exchange8:sor` → `exchange8`.
/// - **host/port** — `SENTIN8_PG_HOST` / `SENTIN8_PG_PORT`, defaulting
///   to `localhost` / `5432`.
///
/// The result is the DEFAULT DSN for [`ShellConfig::from_env`]; an
/// explicit `{SERVICE}_DATABASE_URL` env var still overrides it (custom
/// topologies — replicas, non-local hosts — keep the env-var channel),
/// and the VDC §VDC.3 wrong-database guard checks whatever resolved.
///
/// # Examples
///
/// ```
/// assert_eq!(
///     sentin8_config::service_database_url("exchange8:sor"),
///     "postgres://exchange8_sor_service@localhost:5432/exchange8");
/// assert_eq!(
///     sentin8_config::service_database_url("bank8:ledger"),
///     "postgres://bank8_ledger_service@localhost:5432/bank8");
/// // Workers ride the parent service's role + database:
/// assert_eq!(
///     sentin8_config::service_database_url("bank8:payments:worker"),
///     "postgres://bank8_payments_service@localhost:5432/bank8");
/// ```
pub fn service_database_url(service_identity: &str) -> String {
    // Workers connect with the PARENT service's role (schema-per-service:
    // a separate worker role would fragment the schema's ownership).
    let binding = canonical_service_type(service_identity);
    let base = service_base_type(&binding);
    let role = format!("{}_service", base.replace(':', "_"));
    let db = expected_database_name(service_identity);
    let host = std::env::var("SENTIN8_PG_HOST").unwrap_or_else(|_| "localhost".to_string());
    let port = std::env::var("SENTIN8_PG_PORT").unwrap_or_else(|_| "5432".to_string());
    format!("postgres://{role}@{host}:{port}/{db}")
}

/// Extract the database name from a PostgreSQL DSN (VDC §VDC.3).
///
/// Parses both URL forms (`postgres://user:pw@host:port/dbname?...`)
/// and key/value forms (`host=... dbname=db ...`). Returns `None` for
/// DSNs whose database segment is empty (`postgres://.../`).
///
/// # Examples
///
/// ```
/// assert_eq!(sentin8_config::dsn_database_name(
///     "postgres://u:p@localhost:5432/bank8").as_deref(), Some("bank8"));
/// assert_eq!(sentin8_config::dsn_database_name(
///     "postgres://u:p@localhost:5432/sentin8?sslmode=require").as_deref(),
///     Some("sentin8"));
/// assert_eq!(sentin8_config::dsn_database_name(
///     "host=localhost dbname=bank8").as_deref(), Some("bank8"));
/// assert_eq!(sentin8_config::dsn_database_name(
///     "postgres://u:p@localhost:5432/"), None);
/// ```
pub fn dsn_database_name(dsn: &str) -> Option<String> {
    // URL form: everything after the last '/' before '?' or end.
    if dsn.starts_with("postgres://") || dsn.starts_with("postgresql://") {
        let no_scheme = dsn.split("://").nth(1).unwrap_or("");
        let path = no_scheme.split(['?', '#']).next().unwrap_or("");
        let db = path.rsplit('/').next().unwrap_or("");
        return (!db.is_empty()).then(|| db.to_string());
    }
    // Key/value form: `dbname=` token.
    for token in dsn.split_whitespace() {
        if let Some(v) = token.strip_prefix("dbname=") {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Derive the platform Valkey URL from the plane's coordinates
/// (VALKEYDERIVE-1, group DESIGN.md §3.1).
///
/// Under certificate identity a Valkey URL is PURE STRUCTURE (scheme,
/// host, and port); the client certificate authenticates and the
/// per-workload ACL namespaces authorize (no secret component exists).
/// Host/port come from `SENTIN8_VALKEY_HOST` / `SENTIN8_VALKEY_PORT`,
/// defaulting to `localhost:6379`.
///
/// The `/0` suffix is EXPLICIT-BUT-INERT: the SDK factory's
/// `parse_host_port` discards the number and GLIDE connects at its
/// default DB 0 — the historical per-service `/1|/2|/3` URLs were
/// inoperative. Logical-DB isolation was never the mechanism; the
/// ACL key namespaces (`~{ns}:*` per workload) are the only
/// isolation boundary.
///
/// Call sites resolve: an explicit `{SERVICE}_VALKEY_URL` env var
/// (override, highest precedence) → else this derived URL.
///
/// # Examples
///
/// ```
/// assert_eq!(
///     sentin8_config::service_valkey_url(),
///     "valkeys://localhost:6379/0");
/// ```
pub fn service_valkey_url() -> String {
    let host = std::env::var("SENTIN8_VALKEY_HOST").unwrap_or_else(|_| "localhost".to_string());
    let port = std::env::var("SENTIN8_VALKEY_PORT").unwrap_or_else(|_| "6379".to_string());
    format!("valkeys://{host}:{port}/0")
}

/// One configured destination for a service's log emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogDestination {
    /// UDP fast-path to `log` (loopback-bound, no HMAC;
    /// works without Auth). This is the **default**.
    LogUdp,
    /// WebSocket reliable path to `log` (Auth M2M bearer token).
    LogWs,
    /// Append JSONL to `/var/log/sentin8/{service}.log` (local audit / fallback).
    LocalDisk,
}

impl LogDestination {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LogUdp => "log:udp",
            Self::LogWs => "log:ws",
            Self::LocalDisk => "local:disk",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "log:udp" => Ok(Self::LogUdp),
            "log:ws" => Ok(Self::LogWs),
            "local:disk" => Ok(Self::LocalDisk),
            other => Err(format!(
                "unknown SENTIN8_LOG_DESTINATIONS value: {other:?} (expected log:udp | log:ws | local:disk | none)"
            )),
        }
    }
}

impl std::fmt::Display for LogDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse a raw `SENTIN8_LOG_DESTINATIONS` string into a de-duplicated
/// `Vec<LogDestination>`.
///
/// - `""` (unset or explicit empty) or `"none"` → disabled.
/// - Bare `","` or other separator-only input → disabled
///   (consistent with empty).
/// - Unknown value → panic with a clear message so the service
///   fails fast at startup.
///
/// The caller (`Sentin8Config::log_destinations`) substitutes the
/// default `[log:udp]` only when the env var is **unset** (not
/// when it's present but empty).
pub fn parse_log_destinations(raw: &str) -> Vec<LogDestination> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    let mut out: Vec<LogDestination> = Vec::new();
    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let dest = LogDestination::parse(part).unwrap_or_else(|e| panic!("sentin8-config: {e}"));
        if !out.contains(&dest) {
            out.push(dest);
        }
    }
    out
}

// ── Typed domain newtypes ────────────────────────────────────────────────
//
// `OrgDomain`, `EnvDomain`, and `AppDomain` are thin newtypes around the
// domain string. They carry the resolved hostname and offer convenience
// methods to derive the service-specific sub-domains at the appropriate
// scope. Construct via `Sentin8Config::org_domain_typed` /
// `env_domain_typed` / `app_domain_typed`, or `from_str` when the domain is
// already known (e.g. custom domain).

/// Organization-scoped domain (e.g. `org1.sentin8.local` or a custom domain).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrgDomain(String);

impl OrgDomain {
    pub fn new(domain: String) -> Self {
        Self(domain)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for OrgDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for OrgDomain {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl OrgDomain {
    pub fn auth_subdomain(&self) -> String {
        format!("auth.ops.{}", self.0)
    }
    pub fn dash_subdomain(&self) -> String {
        format!("dash.ops.{}", self.0)
    }
    pub fn sentin8_bff_subdomain(&self) -> String {
        format!("bff.ops.{}", self.0)
    }
    pub fn sentin8_storage_subdomain(&self) -> String {
        format!("storage.ops.{}", self.0)
    }
    pub fn sentin8_app_subdomain(&self) -> String {
        format!("app.ops.{}", self.0)
    }
    pub fn sentin8_db_subdomain(&self) -> String {
        format!("db.ops.{}", self.0)
    }
    pub fn sentin8_bus_subdomain(&self) -> String {
        format!("bus.ops.{}", self.0)
    }
    pub fn sentin8_tls_subdomain(&self) -> String {
        format!("tls.ops.{}", self.0)
    }
    pub fn sentin8_stat_subdomain(&self) -> String {
        format!("stat.ops.{}", self.0)
    }
    pub fn sentin8_log_subdomain(&self) -> String {
        format!("log.ops.{}", self.0)
    }
    pub fn orch_subdomain(&self) -> String {
        format!("captain.ops.{}", self.0)
    }
    pub fn sentin8_func_subdomain(&self) -> String {
        format!("func.ops.{}", self.0)
    }
    pub fn sentin8_cron_subdomain(&self) -> String {
        format!("cron.ops.{}", self.0)
    }
    pub fn sentin8_flow_subdomain(&self) -> String {
        format!("flow.ops.{}", self.0)
    }
    pub fn sentin8_sys_subdomain(&self) -> String {
        format!("sys.ops.{}", self.0)
    }
}

/// Environment-scoped domain (e.g. `qa1.org1.sentin8.local`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnvDomain(String);

impl EnvDomain {
    pub fn new(domain: String) -> Self {
        Self(domain)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for EnvDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for EnvDomain {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl EnvDomain {
    pub fn auth_subdomain(&self) -> String {
        format!("auth.{}", self.0)
    }
    pub fn dash_subdomain(&self) -> String {
        format!("dash.{}", self.0)
    }
    pub fn sentin8_bff_subdomain(&self) -> String {
        format!("bff.{}", self.0)
    }
    pub fn sentin8_storage_subdomain(&self) -> String {
        format!("storage.{}", self.0)
    }
    pub fn sentin8_app_subdomain(&self) -> String {
        format!("app.{}", self.0)
    }
    pub fn sentin8_db_subdomain(&self) -> String {
        format!("db.{}", self.0)
    }
    pub fn sentin8_bus_subdomain(&self) -> String {
        format!("bus.{}", self.0)
    }
    pub fn sentin8_tls_subdomain(&self) -> String {
        format!("tls.{}", self.0)
    }
    pub fn sentin8_stat_subdomain(&self) -> String {
        format!("stat.{}", self.0)
    }
    pub fn sentin8_log_subdomain(&self) -> String {
        format!("log.{}", self.0)
    }
    pub fn orch_subdomain(&self) -> String {
        format!("captain.{}", self.0)
    }
    pub fn sentin8_func_subdomain(&self) -> String {
        format!("func.{}", self.0)
    }
    pub fn sentin8_cron_subdomain(&self) -> String {
        format!("cron.{}", self.0)
    }
    pub fn sentin8_flow_subdomain(&self) -> String {
        format!("flow.{}", self.0)
    }
    pub fn sentin8_sys_subdomain(&self) -> String {
        format!("sys.{}", self.0)
    }
}

/// Application-scoped domain (e.g. `ebank.qa1.org1.sentin8.local`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppDomain(String);

impl AppDomain {
    pub fn new(domain: String) -> Self {
        Self(domain)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    /// Application BFF sub-domain: `bff.{app_domain}`.
    pub fn bff_subdomain(&self) -> String {
        format!("bff.{}", self.0)
    }
}

impl std::fmt::Display for AppDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for AppDomain {
    fn from(s: String) -> Self {
        Self(s)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize tests that mutate `SENTIN8_LOG_DESTINATIONS` — env vars
    /// are process-global and Rust runs tests on parallel threads.
    fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn cfg() -> Sentin8Config {
        Sentin8Config::builder()
            .sentin8_domain("sentin8.local")
            .build()
    }

    #[test]
    fn platform_domains() {
        let c = cfg();
        assert_eq!(
            c.platform_domain("sentin8:auth"),
            "auth.ops.sys.sentin8.local"
        );
        assert_eq!(
            c.platform_domain("sentin8:dash"),
            "dash.ops.sys.sentin8.local"
        );
        assert_eq!(c.platform_domain("auth"), "auth.ops.sys.sentin8.local");
        // Colon identity of a vertical service → dash-form DNS label
        assert_eq!(
            c.platform_domain("bank8:ledger"),
            "bank8-ledger.ops.sys.sentin8.local"
        );
        // Legacy hyphen forms normalize identically
        assert_eq!(
            c.platform_domain("sentin8-auth"),
            "auth.ops.sys.sentin8.local"
        );
        assert_eq!(
            c.platform_domain("bank8-ledger"),
            "bank8-ledger.ops.sys.sentin8.local"
        );
    }

    #[test]
    fn canonical_service_type_forms() {
        // Canonical passes through.
        assert_eq!(canonical_service_type("sentin8:auth"), "sentin8:auth");
        assert_eq!(canonical_service_type("bank8:ledger"), "bank8:ledger");
        assert_eq!(
            canonical_service_type("bank8:payments:worker"),
            "bank8:payments:worker"
        );
        // Worker alias shorthand.
        assert_eq!(
            canonical_service_type("bank8:payments:w"),
            "bank8:payments:worker"
        );
        // Legacy hyphen forms.
        assert_eq!(canonical_service_type("sentin8-auth"), "sentin8:auth");
        assert_eq!(canonical_service_type("bank8-ledger"), "bank8:ledger");
        assert_eq!(
            canonical_service_type("bank8-payments-worker"),
            "bank8:payments:worker"
        );
        // Whitespace tolerance.
        assert_eq!(canonical_service_type(" sentin8:auth "), "sentin8:auth");
        // Empty stays empty.
        assert_eq!(canonical_service_type(""), "");
    }

    #[test]
    fn worker_detection_and_base() {
        assert!(is_worker_service("bank8:payments:worker"));
        // Legacy forms still detected.
        assert!(is_worker_service("bank8-payments-worker"));
        assert!(is_worker_service("bank8:payments:w"));
        assert!(!is_worker_service("sentin8:stat"));
        assert!(!is_worker_service("bank8:ledger"));

        assert_eq!(service_base_type("bank8:payments:worker"), "bank8:payments");
        assert_eq!(service_base_type("bank8:payments:w"), "bank8:payments");
        assert_eq!(service_base_type("sentin8:stat"), "sentin8:stat");
        assert_eq!(service_base_type("bank8-payments-worker"), "bank8-payments");
        assert_eq!(worker_type("bank8:payments"), "bank8:payments:worker");
        // Already a worker — unchanged.
        assert_eq!(
            worker_type("bank8:payments:worker"),
            "bank8:payments:worker"
        );
    }

    #[test]
    fn service_env_slug_forms() {
        assert_eq!(service_env_slug("sentin8:auth"), "SENTIN8_AUTH");
        assert_eq!(service_env_slug("sentin8:stat"), "SENTIN8_STAT");
        assert_eq!(service_env_slug("bank8:ledger"), "BANK8_LEDGER");
        // Workers derive from the base — BANK8_PAYMENTS_W_PORT, not
        // BANK8_PAYMENTS_WORKER_PORT.
        assert_eq!(service_env_slug("bank8:payments:worker"), "BANK8_PAYMENTS");
    }

    #[test]
    fn scope_namespace_forms() {
        // Uniform rule: every namespace starts with its vertical —
        // no special case for the platform vertical.
        assert_eq!(service_scope_namespace("sentin8:auth"), "sentin8:auth:");
        assert_eq!(service_scope_namespace("sentin8:app"), "sentin8:app:");
        assert_eq!(service_scope_namespace("bank8:ledger"), "bank8:ledger:");
        assert_eq!(service_scope_namespace("bank8:fdx"), "bank8:fdx:");
        // Workers resolve to the base namespace.
        assert_eq!(
            service_scope_namespace("bank8:payments:worker"),
            "bank8:payments:"
        );
    }

    #[test]
    fn dash_forms() {
        assert_eq!(service_dash_form("sentin8:auth"), "sentin8-auth");
        assert_eq!(service_dash_form("bank8:ledger"), "bank8-ledger");
        assert_eq!(
            service_dash_form("bank8:payments:worker"),
            "bank8-payments-worker"
        );
        assert_eq!(service_dash_form("sentin8:stat"), "sentin8-stat");
    }

    #[test]
    fn org_domain_derivation() {
        let c = cfg();
        let org = c.org_domain("org1");
        assert_eq!(org, "org1.sentin8.local");
        assert_eq!(c.org_auth_domain(&org), "auth.ops.org1.sentin8.local");
        assert_eq!(c.org_dash_domain(&org), "dash.ops.org1.sentin8.local");
        assert_eq!(c.org_sentin8_bff_domain(&org), "bff.ops.org1.sentin8.local");
        assert_eq!(
            c.org_sentin8_storage_domain(&org),
            "storage.ops.org1.sentin8.local"
        );
    }

    #[test]
    fn env_domain_derivation() {
        let c = cfg();
        let org = c.org_domain("org1");
        let env = c.env_domain("qa1", &org);
        assert_eq!(env, "qa1.org1.sentin8.local");
        assert_eq!(c.env_auth_domain(&env), "auth.qa1.org1.sentin8.local");
        assert_eq!(
            c.env_sentin8_storage_domain(&env),
            "storage.qa1.org1.sentin8.local"
        );
    }

    #[test]
    fn app_domain_derivation() {
        let c = cfg();
        let org = c.org_domain("org1");
        let env = c.env_domain("qa1", &org);
        let app = c.app_domain("ebank", &env);
        assert_eq!(app, "ebank.qa1.org1.sentin8.local");
        assert_eq!(c.app_bff_domain(&app), "bff.ebank.qa1.org1.sentin8.local");
    }

    #[test]
    fn system_uuids_are_distinct() {
        assert_ne!(SYSTEM_ORG_ID, SYSTEM_ENV_ID);
        assert_eq!(
            SYSTEM_ORG_ID.to_string(),
            "00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            SYSTEM_ENV_ID.to_string(),
            "00000000-0000-0000-0000-000000000002"
        );
    }

    #[test]
    fn log_destinations_default() {
        // Empty / whitespace-only / bare-comma parses as DISABLED.
        // (Note: the env-var default of [log:udp] lives in
        // Sentin8Config::log_destinations and only kicks in when the
        // var is unset.)
        assert!(parse_log_destinations("").is_empty());
        assert!(parse_log_destinations("   ").is_empty());
        assert!(parse_log_destinations(",").is_empty());
        assert!(parse_log_destinations(" , , ").is_empty());
    }

    #[test]
    fn log_destinations_single_each() {
        assert_eq!(
            parse_log_destinations("log:udp"),
            vec![LogDestination::LogUdp]
        );
        assert_eq!(
            parse_log_destinations("log:ws"),
            vec![LogDestination::LogWs]
        );
        assert_eq!(
            parse_log_destinations("local:disk"),
            vec![LogDestination::LocalDisk]
        );
    }

    #[test]
    fn log_destinations_multi_select() {
        assert_eq!(
            parse_log_destinations("log:udp,local:disk"),
            vec![LogDestination::LogUdp, LogDestination::LocalDisk]
        );
        assert_eq!(
            parse_log_destinations("log:ws, log:udp,local:disk"),
            vec![
                LogDestination::LogWs,
                LogDestination::LogUdp,
                LogDestination::LocalDisk
            ]
        );
    }

    #[test]
    fn log_destinations_case_insensitive() {
        assert_eq!(
            parse_log_destinations("LOG:UDP"),
            vec![LogDestination::LogUdp]
        );
        assert_eq!(
            parse_log_destinations("Local:Disk"),
            vec![LogDestination::LocalDisk]
        );
    }

    #[test]
    fn log_destinations_dedup() {
        assert_eq!(
            parse_log_destinations("log:udp,log:udp"),
            vec![LogDestination::LogUdp]
        );
        assert_eq!(
            parse_log_destinations("log:udp,log:ws,log:udp,local:disk,log:ws"),
            vec![
                LogDestination::LogUdp,
                LogDestination::LogWs,
                LogDestination::LocalDisk
            ]
        );
    }

    #[test]
    fn log_destinations_disable() {
        assert!(parse_log_destinations("none").is_empty());
        assert!(parse_log_destinations("NONE").is_empty());
        assert!(parse_log_destinations("  none  ").is_empty());
        assert!(parse_log_destinations("").is_empty()); // explicit disable
    }

    #[test]
    fn log_destinations_env_var_default_when_unset() {
        // Unset env var → default [log:udp] (the documented default).
        // Serialized with the explicit-empty test — env vars are process-global.
        let _g = env_test_lock();
        std::env::remove_var("SENTIN8_LOG_DESTINATIONS");
        let cfg = Sentin8Config::from_env();
        assert_eq!(cfg.log_destinations(), vec![LogDestination::LogUdp]);
    }

    #[test]
    fn log_destinations_env_var_explicit_empty_disables() {
        // Explicit empty value disables fan-out (used by log
        // to break the self-loop on its own UDP listener).
        // Serialized with the unset-env test — env vars are process-global.
        let _g = env_test_lock();
        std::env::set_var("SENTIN8_LOG_DESTINATIONS", "");
        let cfg = Sentin8Config::from_env();
        assert!(cfg.log_destinations().is_empty());
        std::env::remove_var("SENTIN8_LOG_DESTINATIONS");
    }

    #[test]
    #[should_panic(expected = "unknown SENTIN8_LOG_DESTINATIONS value")]
    fn log_destinations_invalid_panics() {
        parse_log_destinations("log:foo");
    }

    #[test]
    fn log_destinations_as_str_roundtrip() {
        for d in [
            LogDestination::LogUdp,
            LogDestination::LogWs,
            LogDestination::LocalDisk,
        ] {
            assert_eq!(LogDestination::parse(d.as_str()).unwrap(), d);
        }
    }

    #[test]
    fn typed_org_domain_subdomains() {
        let c = cfg();
        let org = c.org_domain_typed("org1");
        assert_eq!(org.as_str(), "org1.sentin8.local");
        assert_eq!(org.auth_subdomain(), "auth.ops.org1.sentin8.local");
        assert_eq!(org.dash_subdomain(), "dash.ops.org1.sentin8.local");
        assert_eq!(org.sentin8_bff_subdomain(), "bff.ops.org1.sentin8.local");
        assert_eq!(
            org.sentin8_storage_subdomain(),
            "storage.ops.org1.sentin8.local"
        );
        assert_eq!(org.sentin8_app_subdomain(), "app.ops.org1.sentin8.local");
        assert_eq!(org.sentin8_db_subdomain(), "db.ops.org1.sentin8.local");
        assert_eq!(org.sentin8_bus_subdomain(), "bus.ops.org1.sentin8.local");
        assert_eq!(org.sentin8_tls_subdomain(), "tls.ops.org1.sentin8.local");
        assert_eq!(org.sentin8_stat_subdomain(), "stat.ops.org1.sentin8.local");
        assert_eq!(org.sentin8_log_subdomain(), "log.ops.org1.sentin8.local");
        assert_eq!(org.sentin8_func_subdomain(), "func.ops.org1.sentin8.local");
        assert_eq!(org.sentin8_cron_subdomain(), "cron.ops.org1.sentin8.local");
        assert_eq!(org.sentin8_flow_subdomain(), "flow.ops.org1.sentin8.local");
        assert_eq!(org.sentin8_sys_subdomain(), "sys.ops.org1.sentin8.local");
    }

    #[test]
    fn typed_env_domain_subdomains() {
        let c = cfg();
        let org = c.org_domain_typed("org1");
        let env = c.env_domain_typed("qa1", &org);
        assert_eq!(env.as_str(), "qa1.org1.sentin8.local");
        assert_eq!(env.auth_subdomain(), "auth.qa1.org1.sentin8.local");
        assert_eq!(env.dash_subdomain(), "dash.qa1.org1.sentin8.local");
        assert_eq!(env.sentin8_bff_subdomain(), "bff.qa1.org1.sentin8.local");
        assert_eq!(
            env.sentin8_storage_subdomain(),
            "storage.qa1.org1.sentin8.local"
        );
        assert_eq!(env.sentin8_app_subdomain(), "app.qa1.org1.sentin8.local");
        assert_eq!(env.sentin8_db_subdomain(), "db.qa1.org1.sentin8.local");
        assert_eq!(env.sentin8_bus_subdomain(), "bus.qa1.org1.sentin8.local");
        assert_eq!(env.sentin8_tls_subdomain(), "tls.qa1.org1.sentin8.local");
        assert_eq!(env.sentin8_stat_subdomain(), "stat.qa1.org1.sentin8.local");
        assert_eq!(env.sentin8_log_subdomain(), "log.qa1.org1.sentin8.local");
        assert_eq!(env.sentin8_func_subdomain(), "func.qa1.org1.sentin8.local");
        assert_eq!(env.sentin8_cron_subdomain(), "cron.qa1.org1.sentin8.local");
        assert_eq!(env.sentin8_flow_subdomain(), "flow.qa1.org1.sentin8.local");
        assert_eq!(env.sentin8_sys_subdomain(), "sys.qa1.org1.sentin8.local");
    }

    #[test]
    fn typed_app_domain_bff_subdomain() {
        let c = cfg();
        let org = c.org_domain_typed("org1");
        let env = c.env_domain_typed("qa1", &org);
        let app = c.app_domain_typed("ebank", &env);
        assert_eq!(app.as_str(), "ebank.qa1.org1.sentin8.local");
        assert_eq!(app.bff_subdomain(), "bff.ebank.qa1.org1.sentin8.local");
    }

    #[test]
    fn typed_domain_from_custom() {
        let c = cfg();
        let org = c.org_domain_from("acme.com");
        assert_eq!(org.as_str(), "acme.com");
        assert_eq!(org.auth_subdomain(), "auth.ops.acme.com");
    }
}

// ── PostgreSQL 18 OAuth configuration ───────────────────────────────────
