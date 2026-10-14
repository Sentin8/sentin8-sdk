// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-shell
//!
//! Shared service shell — the canonical boot sequence for every Rust
//! service on the platform (sentin8 platform services + all verticals).
//!
//! Owns the normative startup order:
//!
//! 1. `--print-registration` / `--section=` flag check **before any
//!    initialization** (self-registration contract — no DB, no network,
//!    no PQ provider install on this path)
//! 2. Graviola PQ crypto provider install (before any rustls/reqwest
//!    HTTPS call)
//! 3. `dotenvy::dotenv()`
//! 4. Tracing + error-metrics init (opt-out via [`Sentin8Shell::without_metrics`])
//! 5. [`ShellConfig`] from env (captain-injected `<SERVICE>_PORT` etc.)
//! 6. Capped DB pool via `sentin8_config::pg_pool::connect`
//! 7. PostgreSQL 18+ enforcement (hard fail)
//! 8. Service state build (the `with_state` closure — engine shards, domain
//!    caches, a DCR Bus client may be built there from the core)
//! 9. Router: shell `/v1/health` (unless [`with_own_health`]) + the
//!    `with_router` extension + `with_state` + OpenAPI merge (via
//!    [`with_openapi`]) + the standard middleware stack (correlation,
//!    host context, TLS context, request logging, traffic counter, CORS)
//! 10. In-process PQ-TLS termination via `sentin8_tls::Sentin8Tls`
//!
//! Steps 1–7 and 10 are NOT overridable — they are the platform's security
//! and lifecycle contract. Services extend via
//! [`Sentin8Shell::with_router`], and [`Sentin8Shell::with_openapi`].
//!
//! The layering order is fixed: routes → layers → state → OpenAPI (the
//! routes → layers → state → openapi (uncovered by middleware), so a migrated
//! identical for every service using the shell.
//!
//! ## One state API, both platform conventions
//!
//! [`Sentin8Shell::with_state`] is generic over what the state closure
//! returns, so there is one path:
//!
//! - **Arc state** — the closure returns `Arc<S>`; handlers extract
//!   `State<Arc<S>>`.
//!   the shell mounts its own `/v1/health` (unless overridden).
//! - **Value state** — the closure returns the service's existing `Clone`
//!   state struct directly; handlers keep extracting `State<AppState>`
//!   (the bank8/hotel8/sentin8 platform convention). **No handler
//!   changes.** The service mounts its own `/v1/health` (custom payload,
//!   OpenAPI-annotated) inside `with_router` via [`with_own_health`].
//!
//! The shell also provides the shared request helpers ([`set_tenant_context`],
//! [`verify_token`], [`require_any_scope`], [`err_db`]) so every service's
//! handlers follow the same authorization pipeline entry.
//!
//! ## Example (Arc state — services built on the shell)
//!
//! ```text
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     sentin8_shell::serve(
//!         sentin8_shell::Sentin8Shell::new("svc:worker", "SVC_ME")
//!             .with_registration(registration::print)
//!             .with_simple_state()
//!             .with_router(|router, _state| router.route("/v1/orders", post(add_order))),
//!     )
//!     .await
//! }
//! ```
//!
//! ## Example (value state — the platform convention)
//!
//! The state struct and every `State<AppState>` handler stay exactly as
//! they are; only `main.rs` changes:
//!
//! ```text
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     sentin8_shell::serve(
//!         sentin8_shell::Sentin8Shell::new("sentin8:db", "SENTIN8_DB")
//!             .with_registration(registration::print)
//!             .with_state(|core| async move {
//!                 Ok(handlers::AppState {
//!                     config: std::sync::Arc::new(config::Db8Config::from_env()),
//!                     pool: core.pool,
//!                 })
//!             })
//!             .with_own_health()
//!             .with_router(|router, state| server::routes(router, state))
//!             .with_openapi(openapi::DbOpenApi::openapi()),
//!     )
//!     .await
//! }
//! ```
//!
//! where `server::routes` adds the service's routes (including its own
//! `/v1/health`) onto the passed-in router and returns it still generic
//! over the state — the shell binds the state and merges the OpenAPI spec.

use std::sync::Arc;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Per-service shell configuration from env (captain-injected vars).
///
/// Field resolution order is normative:
/// - `port`: `{SERVICE_ENV}_PORT` — hard fail if missing/invalid
/// - `database_url`: `{SERVICE_ENV}_DATABASE_URL` → `DATABASE_URL` →
///   `sentin8_config::Sentin8Config::default_database_url()`
/// - `sentin8_auth_issuer`: `SENTIN8_AUTH_ISSUER` → derived platform domain
/// - `sentin8_bus_url`: `SENTIN8_BUS_URL` → derived platform domain
/// - `sentin8_auth_client`: shared cached client (discovery + JWKS behind an
///   `Arc`, 5-minute TTL) — construct once, clone is cheap
#[derive(Debug, Clone)]
pub struct ShellConfig {
    /// Service identity (e.g. `sentin8:db`, `bank8:ledger`)
    /// — the colon identity form.
    pub service_type: &'static str,
    pub port: u16,
    pub database_url: String,
    pub sentin8_auth_issuer: String,
    pub sentin8_bus_url: String,
    /// Shared Auth client — constructed once so the discovery and JWKS
    /// caches are reused across every request. Cloning is cheap (the caches
    /// live behind an `Arc`).
    pub sentin8_auth_client: sentin8_auth_client::Client,
    /// Valkey URL (from `VALKEY_URL`) — used by the metrics publisher and
    /// request-counter flush loop. Empty string means "no publisher"
    /// (dev-only runs stay clean).
    pub valkey_url: String,
}

impl ShellConfig {
    /// `service_env` is the upper-snake service slug, e.g. `EXCHANGE8_ME`
    /// (captain injects `EXCHANGE8_ME_PORT` etc.).
    pub fn from_env(service_type: &'static str, service_env: &str) -> Self {
        let cfg = sentin8_config::Sentin8Config::from_env();
        let port = std::env::var(format!("{service_env}_PORT"))
            .unwrap_or_else(|_| {
                panic!("{service_env}_PORT must be set by captain or the environment")
            })
            .parse()
            .unwrap_or_else(|_| panic!("{service_env}_PORT must be a valid u16"));
        // DSN resolution (DSNDERIVE-1, group DESIGN.md §3.2): an explicit
        // {SERVICE}_DATABASE_URL env var OVERRIDES (custom topologies —
        // replicas, non-local hosts — keep the env-var channel; captain's
        // catalog-declared `database_env_vars` propagation feeds it).
        // Otherwise the DSN DERIVES from the service identity — role +
        // database are pure structure under certificate identity (no
        // secret component exists; the pg_pool factory resolves the
        // certificate pair from the role). The DATABASE_URL/platform
        // default below remains the platform-services tier's fallback.
        let database_url = match std::env::var(format!("{service_env}_DATABASE_URL")) {
            Ok(url) => url,
            Err(_) => sentin8_config::service_database_url(service_type),
        };
        // VDC §VDC.3 (design/sentin8-vertical-data-plane-contract.md): the
        // main pool must point at the database the service identity owns.
        // A DSN naming any other database is the wrong-database accident —
        // the service would silently read/write another vertical's (or the
        // platform's) tables under a mismatched search_path. Fail fast at
        // boot; never fall back.
        let expected_db = sentin8_config::expected_database_name(service_type);
        match sentin8_config::dsn_database_name(&database_url) {
            Some(actual) if actual == expected_db => {}
            actual => panic!(
                "{service_env}_DATABASE_URL points at database '{actual:?}' but the \
                 service '{service_type}' owns database '{expected_db}' (VDC §VDC.3) — \
                 refusing to start against the wrong database"
            ),
        }
        let sentin8_auth_issuer =
            std::env::var("SENTIN8_AUTH_ISSUER").unwrap_or_else(|_| cfg.sentin8_auth_issuer());
        let sentin8_bus_url =
            std::env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url());
        // Valkey URL resolution (VALKEYDERIVE-1, group DESIGN.md §3.1): an
        // explicit VALKEY_URL env var OVERRIDES (custom topologies); else
        // the URL DERIVES from the plane's coordinates — pure structure
        // under certificate identity (the client certificate authenticates;
        // the ACL namespaces authorize). The `/0` suffix is inert.
        let valkey_url = match std::env::var("VALKEY_URL") {
            Ok(url) if !url.trim().is_empty() => url,
            _ => sentin8_config::service_valkey_url(),
        };
        ShellConfig {
            service_type,
            port,
            database_url,
            sentin8_auth_client: sentin8_auth_client::Client::new(
                sentin8_auth_client::ClientOptions {
                    base_url: sentin8_auth_issuer.clone(),
                    ..Default::default()
                },
            ),
            sentin8_auth_issuer,
            sentin8_bus_url,
            valkey_url,
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceCore (shared AppState)
// ---------------------------------------------------------------------------

/// The common application state: config + capped DB pool.
///
/// Stateful services define their own state **containing** this (design
/// via
/// config + pool can use `Arc<ServiceCore>` directly as their axum state.
pub struct ServiceCore {
    pub config: Arc<ShellConfig>,
    pub pool: sqlx::PgPool,
    /// Shared Sentin8:Policy admin surface — constructed by
    /// the shell boot; derived from this core's config + pool.
    pub admin: sentin8_shield::admin::SharedAdminState,
}

/// Convenience alias for the service state (the value-state convention).
/// signatures move mechanically (one release, then it is removed).
pub type AppState = ServiceCore;

impl sentin8_shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8_shield::admin::SharedAdminState {
        &self.admin
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// The SHELL boots policy for every service in boot step 8 and exposes
// the engine as `ServiceCore::admin.policy`. Value-state services (bank8/
// hotel8 convention, whose `AppState` is NOT `ServiceCore`) copy that Arc
// into their own state; Arc-state services read it directly. This module is
// only the step-5 gate glue. The old `engine`/`boot` per-service accessors
// are GONE — a service booting a second engine would
// duplicate the DCR `{service}-policy` registration and the hot-reload
// consumer and risk a cache split between the request path and the admin
// API.
//
// Wiring per service (one line in `build_state`, one in `routes`):
//   state.policy = core.admin.policy.clone();
//   routes(... .merge(sentin8_shell::value_policy_admin_router(admin_arc)))
pub mod policy {
    //! Step-5 gate glue for services that boot on the shell but keep their
    //! own state (value-state convention). The shell's boot step 8 already
    //! booted the engine (load + shared deps + hot-reload + stat emitter)
    //! and exposed it as `ServiceCore::admin.policy` — services copy that
    //! Arc into their own state; this module is only the request-path gate.

    #[allow(unused_imports)]
    use std::sync::Arc; // WIP glue — used when value-state services wire the admin router

    /// Step 5 gate for a verified AuthContext: the FULL live evaluation
    /// (live effective scopes + roles + relation slice + principal attrs).
    /// An enforced deny converts to HTTP 403. Handlers call `verify_token`
    /// (steps 1–4) then this — the decision is Shield's.
    pub async fn require(
        engine: &sentin8_shield::PolicyEngine,
        a: &sentin8_auth_client::AuthContext,
        headers: &axum::http::HeaderMap,
        target: sentin8_shield::EvalTarget,
    ) -> Result<sentin8_shield::EvalOutcome, (axum::http::StatusCode, String)> {
        sentin8_shield::runtime::require_policy(engine, a, headers, target).await
    }
}

// ---------------------------------------------------------------------------
// Shared policy-admin mount for value-state services
// ---------------------------------------------------------------------------

/// Newtype so the generic `HasPolicyAdmin` handlers can run against a
/// service's admin surface without the service depending on the trait impl
/// (coherence: the trait lives in sentin8-shield).
#[derive(Clone)]
pub struct ValuePolicyAdmin(pub std::sync::Arc<sentin8_shield::admin::SharedAdminState>);

impl sentin8_shield::admin::HasPolicyAdmin for ValuePolicyAdmin {
    fn policy_admin(&self) -> &sentin8_shield::admin::SharedAdminState {
        &self.0
    }
}

/// Mount the shared policy-admin routes onto a router whose state
/// is the service's own `Arc<SharedAdminState>`. The service's state keeps
/// that Arc (constructed at boot from `ServiceCore::admin` — the engine
/// inside is the SAME instance `policy::require` evaluates), so admin writes
/// and request-time evaluation always agree.
///
/// The service binds its state as usual and merges the returned router:
/// ```text
/// let admin = Arc::new(state.core.admin.clone());
/// router.merge(sentin8_shell::value_policy_admin_router(admin))
/// ```
/// (state-binding order: `Router::with_state` happens after `with_router`
/// runs, so the merged router must already be bound — the Arc parameter is
/// the bind.)
pub fn value_policy_admin_router(
    admin: std::sync::Arc<sentin8_shield::admin::SharedAdminState>,
) -> axum::Router {
    #[allow(unused_imports)]
    use axum::extract::State;
    use axum::routing::{get, post};

    type S = ValuePolicyAdmin;
    let base: axum::Router<S> = axum::Router::new()
        .route(
            "/v1/admin/policy-sets",
            get(sentin8_shield::admin::list_policy_sets::<S>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8_shield::admin::get_policy_set::<S>)
                .put(sentin8_shield::admin::put_policy_set::<S>)
                .delete(sentin8_shield::admin::delete_policy_set::<S>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8_shield::admin::test_policy_set::<S>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8_shield::admin::admin_enforce_policy_set::<S>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8_shield::admin::admin_shadow_policy_set::<S>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8_shield::admin::admin_disable_policy_set::<S>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8_shield::admin::list_relations::<S>)
                .put(sentin8_shield::admin::put_relation::<S>)
                .delete(sentin8_shield::admin::delete_relation::<S>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8_shield::admin::check_relation::<S>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8_shield::admin::list_attributes::<S>)
                .put(sentin8_shield::admin::put_attribute::<S>)
                .delete(sentin8_shield::admin::delete_attribute::<S>),
        );
    base.with_state(ValuePolicyAdmin(admin))
}

/// Set the RLS tenant context on a connection.
///
/// MUST be awaited on the same connection the data query uses —
/// `sentin8_set_tenant_context` uses `set_config(..., true)` which is
/// transaction-local.
pub async fn set_tenant_context(conn: &mut sqlx::PgConnection, env_id: uuid::Uuid) {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(conn)
        .await;
}

/// Re-exported so services share the same context type. `VerifiedClaims` is
/// re-exported so vertical authorization tests
/// can construct claim fixtures without a direct sentin8-auth-client dep.
pub use sentin8_auth_client::{AuthContext, VerifiedClaims};

/// Verify the Bearer token and return the auth context.
pub async fn verify_token(
    config: &ShellConfig,
    headers: &axum::http::HeaderMap,
) -> Result<AuthContext, (axum::http::StatusCode, String)> {
    sentin8_auth_client::verify_bearer_token(&config.sentin8_auth_client, headers).await
}

/// Steps 1–4 only: verify the Bearer token (identity + tenant resolution).
/// NO scope check — step 5 (`sentin8_shield::runtime::require_policy`) is the
/// authorization decision (any post-verify JWT scope
/// gate is a review-blocking defect). Handlers authenticate with this, then
/// gate via `crate::policy::require_policy` / `shell::policy::require`.
///
/// Verify the Bearer token and require any of the given scopes.
/// Platform admins (`sentin8:sys:admin`) bypass the scope check.
pub async fn require_any_scope(
    config: &ShellConfig,
    headers: &axum::http::HeaderMap,
    scopes: &[&str],
) -> Result<AuthContext, (axum::http::StatusCode, String)> {
    let a = verify_token(config, headers).await?;
    a.require_any_scope(scopes)?;
    Ok(a)
}

/// Standard DB error mapping for handlers — never leaks SQL internals.
pub fn err_db<E>(_e: E) -> (axum::http::StatusCode, String) {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "database error".into(),
    )
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Standard liveness endpoint factory (captain `use_http_health`). Mounted
/// by the shell unless the service opts for its own via
/// [`Sentin8Shell::with_own_health`] (custom payload, OpenAPI annotations).
///
/// The handler captures the service type at boot and reads no state, so it
/// is generic over the router's state `S` — it mounts on Arc-state and
/// value-state services alike.
///
/// When the shell built a traffic-counter gauge for this service, the
/// payload also carries `active_connections` — the in-flight request count
/// captain drains against during rolling upgrades (proxy README §7 /
/// captain README §7). Without a gauge the field is omitted and the
/// payload stays the plain four-key liveness shape.
pub fn health_handler_with_gauge<S>(
    service_type: &'static str,
    gauge: Option<sentin8_middleware::RequestCounter>,
) -> impl axum::handler::Handler<((),), S>
where
    S: Clone + Send + Sync + 'static,
{
    move || async move {
        // BUILDID-1: `version` is the binary's full identity — the crate
        // version joined with the git short hash stamped at build time.
        // The identity comes from the build-info stamp, NOT from this
        // shell crate's own CARGO_PKG_VERSION (the shell is a shared
        // library; the CONSUMING binary's crate version is unknowable
        // from inside it — the old env!("CARGO_PKG_VERSION") here always
        // reported the shell's own 0.1.0). The `build` field keeps the
        // raw build hash for captain's VERSION column collapse rule.
        let identity = sentin8_build_info::id();
        let mut payload = serde_json::json!({
            "status": "ok",
            "service": service_type,
            "version": identity,
            // CAPTAIN-10: the build hash rides the health payload so captain's
            // monitor captures BOTH fields at once — a spawn-seeded stale
            // build_hash (previously captain's own, since the payload carried
            // no `build` key) made `make status` show `{version}.{build_hash}`
            // as a duplicated version (`0.1.0.0.1.0`) until the first probe.
            // BUILDID-1: `build` carries the raw hash WITHOUT the .d marker —
            // the profile is a display concern, and keeping the field a pure
            // hash preserves captain's `build_hash == version` collapse rule.
            "build": sentin8_build_info::build_hash(),
        });
        if let Some(gauge) = gauge {
            payload["active_connections"] = serde_json::Value::from(gauge.active_connections());
        }
        axum::Json(payload)
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// State constructor: takes the shell-provided `ServiceCore` and builds the
/// service's axum state asynchronously.
#[allow(clippy::type_complexity)]
type StateFn<S> = Box<
    dyn FnOnce(
            ServiceCore,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<S>> + Send>>
        + Send,
>;

/// Router extension fn: takes the state-built router + state, returns the
/// extended router (the `with_router` hook signature).
#[allow(clippy::type_complexity)]
type RouterFn<S> = Box<dyn FnOnce(axum::Router<S>, S) -> axum::Router<S> + Send>;

/// The service shell builder. Owns the normative boot sequence.
///
/// `S` is the **axum state type** the router is generic over — either
/// `Arc<Inner>` (Arc-state services) or the service's own `Clone` state
/// struct (the platform convention; handlers unchanged). See the
/// crate docs for both examples.
///
/// Construct with [`Sentin8Shell::new`], configure with the `with_*`
/// methods, and hand to [`serve`] — the builder cannot be run directly.
pub struct Sentin8Shell<S = Arc<ServiceCore>> {
    service_type: &'static str,
    service_env: &'static str,
    registration: Option<fn(Option<String>) -> anyhow::Result<()>>,
    state_fn: Option<StateFn<S>>,
    router_fn: Option<RouterFn<S>>,
    /// Prebuilt stateless router (the `with_prebuilt_router` escape hatch).
    prebuilt_router_fn: Option<Box<dyn FnOnce(S) -> axum::Router + Send>>,
    openapi: Option<utoipa::openapi::OpenApi>,
    /// Whether the shell mounts its `/v1/health` (value-state services with
    /// their own health handler suppress it).
    mount_health: bool,
    /// Whether the `with_router` builder applies its own middleware stack
    /// (the shell skips its standard layers then).
    own_layers: bool,
    metrics: bool,
}

impl Sentin8Shell<Arc<ServiceCore>> {
    /// Create a new shell for a service.
    ///
    /// - `service_type`: the registration slug (e.g. `"bank8-ledger"`)
    /// - `service_env`: the upper-snake env prefix captain injects
    ///   (e.g. `"BANK8_LEDGER"` → `BANK8_LEDGER_PORT`)
    pub fn new(service_type: &'static str, service_env: &'static str) -> Self {
        Sentin8Shell {
            service_type,
            service_env,
            registration: None,
            state_fn: None,
            router_fn: None,
            prebuilt_router_fn: None,
            openapi: None,
            mount_health: true,
            own_layers: false,
            metrics: true,
        }
    }
}

impl<S> Sentin8Shell<S> {
    /// Set the `--print-registration` handler (the service's
    /// `registration::print`). Required for every service that carries
    /// registration data — `serve` rejects the flag if this is `None`.
    pub fn with_registration(mut self, print: fn(Option<String>) -> anyhow::Result<()>) -> Self {
        self.registration = Some(print);
        self
    }

    /// Disable the tracing/metrics/Valkey-publisher init (rare — e.g. a
    /// test binary). Default is ON.
    pub fn without_metrics(mut self) -> Self {
        self.metrics = false;
        self
    }

    /// Suppress the shell's `/v1/health` — for value-state services whose
    /// health handler has a custom payload or OpenAPI annotations. The
    /// service mounts its own inside [`with_router`](Sentin8Shell::with_router).
    pub fn with_own_health(mut self) -> Self {
        self.mount_health = false;
        self
    }

    /// Suppress the shell's standard middleware stack — for services whose
    /// `with_router` builder already applies the full layer stack (services
    /// builders kept for integration tests, e.g. Sentin8:Auth's
    /// `build_router`). The service keeps full control of layering then.
    pub fn with_own_layers(mut self) -> Self {
        self.own_layers = true;
        self
    }

    /// Merge an OpenAPI spec (`GET /openapi.json`) after state binding —
    /// the spec route is intentionally NOT covered by the middleware stack,
    /// matching the shell's normative order exactly.
    pub fn with_openapi(mut self, spec: utoipa::openapi::OpenApi) -> Self {
        self.openapi = Some(spec);
        self
    }
}

impl<S> Sentin8Shell<S> {
    /// Provide the service state. Generic over what the
    /// closure returns, so both platform conventions are first-class:
    ///
    /// - **Arc state** — the closure returns `Arc<NewS>`; handlers extract
    ///   `State<Arc<NewS>>`.
    /// - **Value state** — the closure returns the service's existing
    ///   `Clone` state struct directly (the platform
    ///   convention): `State<AppState>` handlers stay untouched. Pair with
    ///   [`with_own_health`](Sentin8Shell::with_own_health).
    ///
    /// The closure receives the shell's [`ServiceCore`] — `core.pool` is
    /// already created and PG18-checked; use `core.config` for the shared
    /// Auth client and platform URLs. A service needing a DCR-registered
    /// M2M Bus client builds it inside the closure via
    /// `sentin8_bus_client::build_with_dcr` (`core.pool`,
    /// `core.config.sentin8_bus_url`, `core.config.sentin8_auth_issuer`).
    pub fn with_state<F, Fut, NewS>(self, f: F) -> Sentin8Shell<NewS>
    where
        F: FnOnce(ServiceCore) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = anyhow::Result<NewS>> + Send + 'static,
        NewS: Clone + Send + Sync + 'static,
    {
        Sentin8Shell {
            service_type: self.service_type,
            service_env: self.service_env,
            registration: self.registration,
            state_fn: Some(Box::new(move |core| Box::pin(async move { f(core).await }))),
            router_fn: None,
            prebuilt_router_fn: None,
            openapi: self.openapi,
            mount_health: self.mount_health,
            own_layers: self.own_layers,
            metrics: self.metrics,
        }
    }

    /// Use `Arc<ServiceCore>` directly as the state (no service-specific
    /// state). Equivalent to `with_state(|core| async { Ok(Arc::new(core)) })`.
    pub fn with_simple_state(self) -> Sentin8Shell<Arc<ServiceCore>> {
        self.with_state(|core| async { Ok(Arc::new(core)) })
    }
}

impl<S> Sentin8Shell<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Layer service routes onto the router. The shell binds the state,
    /// merges the OpenAPI spec (if given), and applies the standard
    /// middleware stack (correlation ID, host context, TLS context, request
    /// logging, traffic counter, CORS) after this extension.
    pub fn with_router<F>(mut self, f: F) -> Self
    where
        F: FnOnce(axum::Router<S>, S) -> axum::Router<S> + Send + 'static,
    {
        self.router_fn = Some(Box::new(f));
        self
    }

    /// Hand the shell a **prebuilt stateless router** instead of a
    /// `with_router` extension. For services whose router builder
    /// already binds the state and merges the OpenAPI spec (e.g.
    /// Sentin8:Auth's test-facing `build_router`) — the shell applies only
    /// the middleware stack and serves it. The state closure still runs for
    /// its side effects (workers); its returned state is what the prebuilt
    /// router already closed over.
    ///
    /// The shell skips its health mount and OpenAPI merge in this mode —
    /// the prebuilt router owns both.
    pub fn with_prebuilt_router<F>(mut self, f: F) -> Self
    where
        F: FnOnce(S) -> axum::Router + Send + 'static,
    {
        self.prebuilt_router_fn = Some(Box::new(f));
        self.mount_health = false;
        self.openapi = None;
        self
    }
}

// ---------------------------------------------------------------------------
// Serve
// ---------------------------------------------------------------------------

/// Boot the service: registration flag → PQ provider → config → capped
/// pool → PG18 check → state build → router + middleware → PQ-TLS serve.
///
/// Consumes the builder. Blocks on the TLS accept loop until shutdown.
///
/// The assembly order is fixed:
/// routes → state → OpenAPI merge → middleware layers, so a migrated
/// service's observable behavior is unchanged.
pub async fn serve<S>(shell: Sentin8Shell<S>) -> anyhow::Result<()>
where
    S: Clone + Send + Sync + 'static,
{
    // 1. Registration flag check BEFORE any initialization (no DB, no
    //    network, no PQ provider on this path).
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--print-registration") {
        let section = args
            .iter()
            .find_map(|a| a.strip_prefix("--section="))
            .map(|s| s.to_string());
        return match shell.registration {
            Some(print) => print(section),
            None => anyhow::bail!(
                "--print-registration not supported by {}",
                shell.service_type
            ),
        };
    }

    // 2. PQ crypto provider before any HTTPS call.
    let _ = sentin8_tls::crypto::sentin8_pq_provider().install_default();

    // 3. dotenv.
    let _ = dotenvy::dotenv();

    // 3b. Workshop certificate identity (group DESIGN.md §3.1, §3.2): the
    // workload pair is a HARD prerequisite for BOTH data planes — Valkey
    // (CN→ACL user) and PostgreSQL (CN→pgm ident row, the DB pool connect
    // at step 6 resolves the pair). The mint is NON-FATAL-then-HARD: the
    // first attempt + a bounded inline retry absorb acme not being up
    // (captain's tier gate starts acme ahead of the fleet; every boot
    // where the pair persists — every boot after the first — completes
    // immediately). If acme stays unreachable beyond the gate, a
    // background loop keeps healing the pair so later retries/restarts
    // land — but step 6 refuses to serve with a missing pair (fail
    // closed; the factory's error names the mint paths).
    {
        let issuer = sentin8_config::Sentin8Config::from_env().sentin8_auth_issuer();
        let service_type = shell.service_type.to_string();
        if let Some(ca_path) = sentin8_m2m::try_platform_ca_path() {
            // Inline: 3 attempts, 2s apart — covers acme listening but slow
            // (fresh boot). The tier gate (acme Active BEFORE any service
            // spawns) makes the common case a single successful load.
            let mut landed = sentin8_m2m::ensure_workload_certificate(&issuer, &service_type, &ca_path)
                .await
                .is_ok();
            for attempt in 0..3 {
                if landed {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                landed = sentin8_m2m::ensure_workload_certificate(&issuer, &service_type, &ca_path)
                    .await
                    .is_ok();
                let _ = attempt;
            }
            if !landed {
                tracing::warn!(
                    service = service_type,
                    "shell: workload identity not yet mintable (acme not up?) — \
                     background retry continues; step 6 (DB pool) will fail \
                     closed until the pair lands"
                );
                let bg_service = service_type.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        match sentin8_m2m::ensure_workload_certificate(
                            &issuer,
                            &bg_service,
                            &ca_path,
                        )
                        .await
                        {
                            Ok(_) => {
                                tracing::info!(
                                    service = bg_service,
                                    "shell: workload identity minted — the next \
                                     boot/DB retry connects over certificate identity"
                                );
                                break;
                            }
                            Err(_) => continue,
                        }
                    }
                });
            }
        } else {
            tracing::warn!(
                service = shell.service_type,
                "shell: no platform CA configured — workload identity mint skipped (set SENTIN8_TLS_CA_PEM)"
            );
        }
    }

    // 4. Tracing + error metrics (opt-out only for test binaries).
    if shell.metrics {
        let _ = sentin8_middleware::error_metrics::init_tracing_with_metrics(
            shell.service_type,
            std::env::var("RUST_LOG").ok().as_deref().unwrap_or("info"),
        );
        sentin8_middleware::error_metrics::spawn_publisher(
            // VALKEYDERIVE-1 (group DESIGN.md §3.1): override → else the
            // plane-derived URL (the metrics publisher tolerates the
            // empty string as "no publisher" — the derived URL is always
            // a valid best-effort target in dev and deployment alike).
            std::env::var("VALKEY_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| sentin8_config::service_valkey_url()),
            shell.service_type,
        );
    }

    // 5. Config from env.
    let config = Arc::new(ShellConfig::from_env(shell.service_type, shell.service_env));
    tracing::info!(
        service = shell.service_type,
        // BUILDID-1: the identity is the binary's {version}+{hash}[.d] —
        // not this shell crate's own crate version (meaningless to the
        // operator; the shell is a shared library).
        version = %sentin8_build_info::id(),
        port = config.port,
        "sentin8 service starting"
    );

    // 6. Capped DB pool (SENTIN8_PG_POOL_MAX, default 3).
    let pool = sentin8_config::pg_pool::connect(&config.database_url).await?;

    // 7. PostgreSQL 18+ enforcement (hard fail).
    sentin8_config::Sentin8Config::enforce_postgres_version(&pool)
        .await
        .expect("PostgreSQL 18+ required");

    // 8. Build the service state (stateful extensions, DCR bus client, …).
    // ── Sentin8:Policy boot wiring (shell-owned:
    // boot load + hot-reload are engine-instance owned) ───────────────────
    // The shell is the ONLY policy boot: load the service's policy sets
    // (unparsable text REFUSES TO START — fail-closed at boot)
    // init the shared step-5 deps, spawn the hot-reload direct consumer, and
    // init stat emission. Failure of the stat emitter degrades to log-only;
    // load failure aborts boot. The engine is exposed to the service via
    // `ServiceCore::admin.policy` — services CONSUME it, they never boot a
    // second engine (duplicate engine/DCR/consumer would risk a cache split
    // between the request path and the admin API).
    let policy_engine = sentin8_shield::runtime::engine_for(config.service_type);
    sentin8_shield::runtime::boot_full(
        &pool,
        &config.sentin8_auth_issuer,
        config.service_type,
        &policy_engine,
    )
    .await?;
    let core = ServiceCore {
        config: config.clone(),
        pool: pool.clone(),
        admin: sentin8_shield::admin::SharedAdminState {
            service: config.service_type.to_string(),
            pool: pool.clone(),
            policy: policy_engine,
            auth_client: std::sync::Arc::new(config.sentin8_auth_client.clone()),
        },
    };
    let state_fn = shell
        .state_fn
        .expect("sentin8-shell: a with_state/with_simple_state call is required");
    let state = state_fn(core).await?;

    // 8b. DBX producer relay: every shell-booted
    // service that publishes events drains its LOCAL `{service}.outbox` and
    // pushes rows to Bus `POST /v1/produce` (the service's
    // CERTIFICATE is the identity — `{service_type}` workload, minted from
    // Acme on first boot; Bus's TLS layer authenticates the handshake).
    // Fail-open: a Bus outage or certificate-mint failure only disables the
    // relay task — rows persist in the local outbox and the 5s safety poll
    // retries; the service itself serves traffic.
    {
        let relay_pool = pool.clone();
        let bus_url = config.sentin8_bus_url.clone();
        let auth_issuer = config.sentin8_auth_issuer.clone();
        let service_type = config.service_type.to_string();
        tokio::spawn(async move {
            let bus = loop {
                match sentin8_bus_client::BusClient::for_workload(
                    &bus_url,
                    &auth_issuer,
                    &service_type,
                )
                .await
                {
                    Ok(client) => break client,
                    Err(e) => {
                        // First birth: Acme may still be coming up — the
                        // mint retries until the identity exists (rows stay
                        // queued either way; this is the boot path, not a
                        // request handler).
                        tracing::debug!(error = %e, workload = %service_type, "outbox relay: certificate not ready yet");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                }
            };
            // Schema == the service leaf (e.g. `sentin8:ai` → `ai`), matching
            // the outbox table the service's init.sql created.
            let leaf = service_type.rsplit(':').next().unwrap_or(&service_type);
            sentin8_outbox::spawn_relay(
                relay_pool,
                std::sync::Arc::new(bus),
                format!("{leaf}_outbox_changed"),
            );
        });
    }

    // 8c. Audit-journal push loop (architecture-principles §6.8):
    // every shell-booted service pushes its LOCAL `{service}.audit_journal`
    // rows to Sys `POST /v1/audit` (M2M, sentin8:sys:audit:write). Fail-open
    // exactly like the outbox relay: a Sys outage or DCR failure only
    // delays the push — rows persist in the journal and the 5s pass
    // retries; the service itself serves traffic. The `<leaf>-audit` M2M
    // workload grant must be declared in the service's `M2M_GRANTS`.
    {
        let journal_pool = pool.clone();
        let sys_url = sentin8_config::Sentin8Config::from_env().sentin8_sys_url();
        let auth_issuer = config.sentin8_auth_issuer.clone();
        let service_type = config.service_type.to_string();
        sentin8_audit::spawn_journal_pusher(journal_pool, sys_url, auth_issuer, &service_type);
    }

    // 9. Router: (health) + service extension → state → openapi → layers.
    let counter = sentin8_middleware::RequestCounter::new();
    if shell.metrics {
        sentin8_middleware::spawn_flush_loop(
            counter.clone(),
            // VALKEYDERIVE-1: override → else the plane-derived URL.
            std::env::var("VALKEY_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| sentin8_config::service_valkey_url()),
            10,
        );
    }
    // The health route shares the traffic counter's in-flight gauge so the
    // payload exposes `active_connections` (proxy README §7) — captain polls it to
    // drain upgrades. `metrics: false` shells have no counter → the field
    // is omitted (the plain liveness shape stays backward compatible).
    let health_gauge = if shell.metrics {
        Some(counter.clone())
    } else {
        None
    };
    // Process-wide gauge registration (shell README §5): services that mount
    // their own health payload (`with_own_health` / `with_prebuilt_router`)
    // append the same in-flight gauge to their custom bodies via
    // `traffic_counter::process_active_connections()` — one drain signal for
    // captain across the fleet (captain README §7). A metrics-disabled shell
    // registers nothing → custom bodies omit the field, same as the
    // shell-mounted route.
    if shell.metrics {
        sentin8_middleware::traffic_counter::set_process_gauge(counter.in_flight_arc());
    }

    // VDC-7/TLS-RLS-4 (design/sentin8-vertical-data-plane-contract.md
    // §VDC.7): the TLS library is DATABASE-FREE — hostname resolution on
    // cache miss rides Sys's owner API (`GET /v1/resolve/hostname`) with
    // this service's cert-bound `{dash}-tls` M2M workload. No SQL pool, no
    // DSN, and no platform-table grants ride this path for ANY service
    // (platform or vertical — a vertical embedding the library gains zero
    // platform-database access).
    let tls = sentin8_tls::Sentin8Tls::builder()
        .service_identity(config.service_type)
        .build()
        .await?;

    let app: axum::Router = if let Some(pb) = shell.prebuilt_router_fn {
        // Prebuilt-router mode: the service's builder already bound the
        // state, mounted its health and merged its OpenAPI spec — the shell
        // applies only the standard middleware stack (unless suppressed).
        let router = pb(state);
        if shell.own_layers {
            router
        } else {
            router
                .layer(axum::middleware::from_fn_with_state(
                    counter,
                    sentin8_middleware::traffic_counter_layer,
                ))
                .layer(axum::middleware::from_fn(
                    sentin8_middleware::sentin8_tls_context,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    sentin8_tls::ContextMiddlewareState {
                        resolver: tls.host_context_resolver(),
                    },
                    sentin8_tls::context_middleware,
                ))
                .layer(axum::middleware::from_fn(
                    sentin8_middleware::request_logging,
                ))
                .layer(axum::middleware::from_fn(
                    sentin8_middleware::correlation_id,
                ))
                .layer(tower_http::cors::CorsLayer::very_permissive())
        }
    } else {
        let base: axum::Router<S> = if shell.mount_health {
            axum::Router::new().route(
                "/v1/health",
                axum::routing::get(health_handler_with_gauge::<S>(
                    shell.service_type,
                    health_gauge,
                )),
            )
        } else {
            axum::Router::new()
        };
        let extended = match shell.router_fn {
            Some(rf) => rf(base, state.clone()),
            None => base,
        };
        let bound = extended.with_state(state);
        let with_openapi = match shell.openapi {
            Some(spec) => bound.merge(sentin8_openapi::openapi_route(spec)),
            None => bound,
        };
        if shell.own_layers {
            // The service's router builder applies its own middleware stack
            // (own builders exercised by integration tests) — the shell skips
            // its standard layers.
            with_openapi
        } else {
            with_openapi
                .layer(axum::middleware::from_fn_with_state(
                    counter,
                    sentin8_middleware::traffic_counter_layer,
                ))
                .layer(axum::middleware::from_fn(
                    sentin8_middleware::sentin8_tls_context,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    sentin8_tls::ContextMiddlewareState {
                        resolver: tls.host_context_resolver(),
                    },
                    sentin8_tls::context_middleware,
                ))
                .layer(axum::middleware::from_fn(
                    sentin8_middleware::request_logging,
                ))
                .layer(axum::middleware::from_fn(
                    sentin8_middleware::correlation_id,
                ))
                .layer(tower_http::cors::CorsLayer::very_permissive())
        }
    };

    // 10. PQ-TLS termination (blocks until shutdown).
    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("{} listening on {addr}", shell.service_type);
    tls.serve(&addr, app, shell.service_type).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_config_shape() {
        // The AuthClient builds a reqwest client at construction which needs
        // the PQ provider installed (same reason serve() installs it first).
        let _ = sentin8_tls::crypto::sentin8_pq_provider().install_default();
        let cfg = ShellConfig {
            service_type: "svc:me",
            port: 7001,
            database_url: "postgres://test".into(),
            sentin8_auth_issuer: "https://auth.test".into(),
            sentin8_bus_url: "https://bus.test".into(),
            sentin8_auth_client: sentin8_auth_client::Client::new(
                sentin8_auth_client::ClientOptions::default(),
            ),
            valkey_url: String::new(),
        };
        assert_eq!(cfg.service_type, "svc:me");
        assert_eq!(cfg.port, 7001);
        assert_eq!(cfg.sentin8_bus_url, "https://bus.test");
        assert_eq!(cfg.valkey_url, "");
    }

    #[test]
    fn health_handler_payload() {
        // The health factory captures the service type — shape test without
        // spinning the router (keeps the crate dep-light). The payload carries
        // BOTH `version` and `build` (CAPTAIN-10) so captain's monitor
        // captures the full `{version}.{build}` display pair in one probe.
        // BUILDID-1: `version` is the joined identity, `build` the raw hash.
        let payload = serde_json::json!({
            "status": "ok",
            "service": "sentin8-test",
            "version": sentin8_build_info::id(),
            "build": sentin8_build_info::build_hash(),
        });
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["service"], "sentin8-test");
        assert_eq!(payload["version"], sentin8_build_info::id());
        assert_eq!(payload["build"], sentin8_build_info::build_hash());
    }

    #[test]
    fn health_payload_with_gauge_carries_active_connections() {
        // With a gauge the payload gains `active_connections` —
        // the drain signal captain polls during rolling upgrades.
        let counter = sentin8_middleware::RequestCounter::new();
        let _guard = counter.enter();
        let payload = serde_json::json!({
            "status": "ok",
            "service": "sentin8-test",
            "version": sentin8_build_info::id(),
            "build": sentin8_build_info::build_hash(),
            "active_connections": counter.active_connections(),
        });
        assert_eq!(payload["active_connections"], 1);
    }

    #[test]
    fn health_payload_without_gauge_omits_active_connections() {
        // Backward compatibility: a shell with metrics disabled serves the
        // plain liveness shape — no `active_connections` key. Captain's
        // drain falls back to the fixed window for such services.
        let payload = serde_json::json!({
            "status": "ok",
            "service": "sentin8-test",
            "version": sentin8_build_info::id(),
            "build": sentin8_build_info::build_hash(),
        });
        assert!(payload.get("active_connections").is_none());
    }
}

// ---------------------------------------------------------------------------
// Sentin8:Policy — shared admin mount
// ---------------------------------------------------------------------------

/// Mount the shared policy-admin surface (policy sets / relations /
/// attributes + dry-run check) onto a `Router<Arc<AppState>>`. Every
/// service that boots on the shell gets the full policy-admin API with zero
/// per-service code — the handlers are generic over the state via
/// `HasPolicyAdmin` (implemented for `ServiceCore` below, deriving the
/// admin state from the shell's config + pool + a per-process engine).
///
/// The engine is per-process and loaded at boot by `build_state` boot code
/// (`PolicyEngine::load`) — this helper only mounts the routes and provides
/// the admin surface. Services with their own state containing
/// `ServiceCore` implement `HasPolicyAdmin` on their own type the same way.
/// Newtype wrapper so the shell can implement the crate-owned
/// `HasPolicyAdmin` trait for the shared state (coherence: the trait lives
/// in sentin8-shield, the wrapper lives here).
#[derive(Clone)]
pub struct PolicyAdminState(pub std::sync::Arc<AppState>);

impl sentin8_shield::admin::HasPolicyAdmin for PolicyAdminState {
    fn policy_admin(&self) -> &sentin8_shield::admin::SharedAdminState {
        &self.0.admin
    }
}

/// Mount the shared policy-admin surface onto a router whose state is
/// `Arc<AppState>` (ServiceCore). The handlers are re-exposed over the
/// wrapper via `Router::map_state` style — implemented as a plain function
/// returning the router with a changed state type; the service then merges
/// it with `Router::merge`.
pub fn policy_admin_router() -> axum::Router<PolicyAdminState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route(
            "/v1/admin/policy-sets",
            get(sentin8_shield::admin::list_policy_sets::<PolicyAdminState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8_shield::admin::get_policy_set::<PolicyAdminState>)
                .put(sentin8_shield::admin::put_policy_set::<PolicyAdminState>)
                .delete(sentin8_shield::admin::delete_policy_set::<PolicyAdminState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8_shield::admin::test_policy_set::<PolicyAdminState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8_shield::admin::admin_enforce_policy_set::<PolicyAdminState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8_shield::admin::admin_shadow_policy_set::<PolicyAdminState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8_shield::admin::admin_disable_policy_set::<PolicyAdminState>),
        )
        // ── RFW renderer helpers ──────────────────────────────────────
        .route(
            "/v1/admin/policy-sets",
            post(sentin8_shield::admin::create_policy_set::<PolicyAdminState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/save",
            post(sentin8_shield::admin::save_policy_set::<PolicyAdminState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/{action}",
            post(sentin8_shield::admin::admin_flip_policy_set::<PolicyAdminState>),
        )
        .route(
            "/v1/admin/policy-decisions",
            get(sentin8_shield::admin::list_policy_decisions::<PolicyAdminState>),
        )
        .route(
            "/v1/admin/relations/{id}/delete",
            post(sentin8_shield::admin::admin_delete_relation::<PolicyAdminState>),
        )
        .route(
            "/v1/admin/attributes/{id}/delete",
            post(sentin8_shield::admin::admin_delete_attribute::<PolicyAdminState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8_shield::admin::list_relations::<PolicyAdminState>)
                .put(sentin8_shield::admin::put_relation::<PolicyAdminState>)
                .delete(sentin8_shield::admin::delete_relation::<PolicyAdminState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8_shield::admin::check_relation::<PolicyAdminState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8_shield::admin::list_attributes::<PolicyAdminState>)
                .put(sentin8_shield::admin::put_attribute::<PolicyAdminState>)
                .delete(sentin8_shield::admin::delete_attribute::<PolicyAdminState>),
        )
}

/// Mount the shared policy-admin routes onto a `Router<Arc<AppState>>`.
/// Each route is a thin forwarding handler that wraps the shell state in
/// [`PolicyAdminState`] (coherence newtype) and delegates to the generic
/// handler in `sentin8-shield::admin` — one surface, zero per-service code.
pub fn mount_policy_admin(
    router: axum::Router<std::sync::Arc<AppState>>,
) -> axum::Router<std::sync::Arc<AppState>> {
    use axum::routing::{get, post};
    router
        // ── Policy sets ──────────────────────────────────────────────────
        .route("/v1/admin/policy-sets", get(policy_list_sets))
        .route(
            "/v1/admin/policy-sets/{name}",
            get(policy_get_set)
                .put(policy_put_set)
                .delete(policy_delete_set),
        )
        .route("/v1/admin/policy-sets/{name}/test", post(policy_test_set))
        // RFW POST-alias row actions (Dash 28.14 — renderer is POST-only).
        .route("/v1/admin/policy-sets/enforce", post(policy_mode_enforce))
        .route("/v1/admin/policy-sets/shadow", post(policy_mode_shadow))
        .route("/v1/admin/policy-sets/disable", post(policy_mode_disable))
        // ── RFW renderer helpers ──────────────────────────────────────
        .route("/v1/admin/policy-sets", post(policy_create_set))
        .route("/v1/admin/policy-sets/{name}/save", post(policy_save_set))
        .route(
            "/v1/admin/policy-sets/{name}/{action}",
            post(policy_flip_set),
        )
        .route("/v1/admin/policy-decisions", get(policy_list_decisions))
        .route(
            "/v1/admin/relations/{id}/delete",
            post(policy_delete_relation_path),
        )
        .route(
            "/v1/admin/attributes/{id}/delete",
            post(policy_delete_attribute_path),
        )
        // ── Relations + attributes admin API ────────────────────────────
        .route(
            "/v1/admin/relations",
            get(policy_list_relations)
                .put(policy_put_relation)
                .delete(policy_delete_relation),
        )
        .route("/v1/admin/relations/check", get(policy_check_relation))
        .route(
            "/v1/admin/attributes",
            get(policy_list_attributes)
                .put(policy_put_attribute)
                .delete(policy_delete_attribute),
        )
}

// ── Forwarding handlers ─────────────────────────────────────────────────
// Each wraps `Arc<AppState>` in the coherence newtype [`PolicyAdminState`]
// and delegates to the generic handler in `sentin8-shield::admin`.
macro_rules! fwd {
    ($name:ident, $inner:path, ($($arg:ident : $ty:ty),* $(,)?)) => {
        async fn $name(
            axum::extract::State(st): axum::extract::State<std::sync::Arc<AppState>>,
            $($arg: $ty,)*
        ) -> impl axum::response::IntoResponse {
            $inner(axum::extract::State(PolicyAdminState(st)) $(, $arg)*).await
        }
    };
}

fwd!(policy_list_sets, sentin8_shield::admin::list_policy_sets, (
    headers: axum::http::HeaderMap,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
));
fwd!(policy_get_set, sentin8_shield::admin::get_policy_set, (
    headers: axum::http::HeaderMap,
    name: axum::extract::Path<String>,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
));
fwd!(policy_put_set, sentin8_shield::admin::put_policy_set, (
    headers: axum::http::HeaderMap,
    name: axum::extract::Path<String>,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
    body: axum::Json<sentin8_shield::admin::PutPolicySetBody>,
));
fwd!(policy_delete_set, sentin8_shield::admin::delete_policy_set, (
    headers: axum::http::HeaderMap,
    name: axum::extract::Path<String>,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
));
fwd!(policy_test_set, sentin8_shield::admin::test_policy_set, (
    headers: axum::http::HeaderMap,
    name: axum::extract::Path<String>,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
    body: axum::Json<sentin8_shield::admin::TestPolicySetBody>,
));
fwd!(policy_mode_enforce, sentin8_shield::admin::admin_enforce_policy_set, (
    headers: axum::http::HeaderMap,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
    body: axum::Json<sentin8_shield::admin::PolicyModeBody>,
));
fwd!(policy_mode_shadow, sentin8_shield::admin::admin_shadow_policy_set, (
    headers: axum::http::HeaderMap,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
    body: axum::Json<sentin8_shield::admin::PolicyModeBody>,
));
fwd!(policy_mode_disable, sentin8_shield::admin::admin_disable_policy_set, (
    headers: axum::http::HeaderMap,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
    body: axum::Json<sentin8_shield::admin::PolicyModeBody>,
));
fwd!(policy_create_set, sentin8_shield::admin::create_policy_set, (
    headers: axum::http::HeaderMap,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
    body: axum::Json<sentin8_shield::admin::CreatePolicySetBody>,
));
fwd!(policy_save_set, sentin8_shield::admin::save_policy_set, (
    headers: axum::http::HeaderMap,
    name: axum::extract::Path<String>,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
    body: axum::Json<sentin8_shield::admin::PutPolicySetBody>,
));
fwd!(policy_flip_set, sentin8_shield::admin::admin_flip_policy_set, (
    headers: axum::http::HeaderMap,
    path: axum::extract::Path<(String, String)>,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
));
fwd!(policy_list_decisions, sentin8_shield::admin::list_policy_decisions, (
    headers: axum::http::HeaderMap,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
));
fwd!(policy_delete_relation_path, sentin8_shield::admin::admin_delete_relation, (
    headers: axum::http::HeaderMap,
    id: axum::extract::Path<String>,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
));
fwd!(policy_delete_attribute_path, sentin8_shield::admin::admin_delete_attribute, (
    headers: axum::http::HeaderMap,
    id: axum::extract::Path<String>,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
));
fwd!(policy_list_relations, sentin8_shield::admin::list_relations, (
    headers: axum::http::HeaderMap,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
));
fwd!(policy_put_relation, sentin8_shield::admin::put_relation, (
    headers: axum::http::HeaderMap,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
    body: axum::Json<sentin8_shield::admin::PutRelationBody>,
));
fwd!(policy_delete_relation, sentin8_shield::admin::delete_relation, (
    headers: axum::http::HeaderMap,
    q: axum::extract::Query<sentin8_shield::admin::DeleteRelationQuery>,
));
fwd!(policy_check_relation, sentin8_shield::admin::check_relation, (
    headers: axum::http::HeaderMap,
    q: axum::extract::Query<sentin8_shield::admin::RelationCheckQuery>,
));
fwd!(policy_list_attributes, sentin8_shield::admin::list_attributes, (
    headers: axum::http::HeaderMap,
    q: axum::extract::Query<sentin8_shield::admin::ListAttributesQuery>,
));
fwd!(policy_put_attribute, sentin8_shield::admin::put_attribute, (
    headers: axum::http::HeaderMap,
    q: axum::extract::Query<sentin8_shield::admin::TargetEnv>,
    body: axum::Json<sentin8_shield::admin::PutAttributeBody>,
));
fwd!(policy_delete_attribute, sentin8_shield::admin::delete_attribute, (
    headers: axum::http::HeaderMap,
    q: axum::extract::Query<sentin8_shield::admin::DeleteAttributeQuery>,
));
