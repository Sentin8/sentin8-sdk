// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8 — the Sentin8 shared-plane facade
//!
//! The namespace facade for the **shared library plane only** (SDD §2.2):
//! every platform shared crate is reachable as `sentin8::{leaf}` or
//! `sentin8::{domain}::{kind}`. Service-scoped SDK crates
//! (`{svc}-client`/`{svc}-contracts`) are **not** re-exported here — each
//! lives in its owning service repo behind a per-service mini-facade
//! (`sentin8-{svc}-sdk`), because the shared plane links no service SDK
//! crate (SDD-1) and the facade never pins a service repo (SDD-6).
//!
//! # Modules
//!
//! | Module | Crate(s) | Purpose |
//! |--------|----------|---------|
//! | [`auth`] | auth-client · jwt · m2m · fapi | Identity plane: token verification, JWT helpers, M2M token source, FAPI OAuth client |
//! | [`bus`] | bus-client · bus-contracts · outbox | Bus plane: produce/consume/ack, wire types, local-outbox relay |
//! | [`tls`] | tls · tls-contracts | Post-quantum TLS termination library + contracts |
//!
//! Infrastructure crates (config, errors, crypto, shell, shield, membus,
//! middleware, openapi, rfw, registration, audit, idempotency,
//! build-info, service-discovery) re-export at the top level:
//! `sentin8::shell`, `sentin8::shield`, …
//!
//! Service SDK imports use their owner mini-facades, e.g.
//! `use sentin8_flow_sdk::client::FlowClient` (sentin8-flow repo).
//!
//! # Quick start
//!
//! ```no_run
//! use sentin8::shell;
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// ── Platform crate namespace facade ───────────────────────────────────
//
// Every shared-plane crate is named `{workspace}::{leaf}` (package
// `sentin8::{leaf}`, lib `{leaf}`) and is imported through this facade.
// See `design/sentin8-sdk-dependency-cleanup-design.md` §2.2 and
// `sentin8/design/sentin8-architecture-principles.md` §2.1.

// Infrastructure crates — one level.
pub use sentin8_audit as audit;
pub use sentin8_build_info as build_info;
pub use sentin8_config as config;
pub use sentin8_crypto as crypto;
pub use sentin8_errors as errors;
pub use sentin8_idempotency as idempotency;
pub use sentin8_membus as membus;
pub use sentin8_middleware as middleware;
pub use sentin8_openapi as openapi;
pub use sentin8_shield as shield;
pub use sentin8_registration as registration;
pub use sentin8_rfw as rfw;
pub use sentin8_service_discovery as service_discovery;
pub use sentin8_shell as shell;

/// Sentin8:Auth domain — platform identity client, JWT helpers, M2M token
/// source, and the discovery-driven FAPI OAuth client. All identity-plane
/// crates live here (architecture-principles §4.1). The identity plane is
/// shared (shell/shield link it) — it stays in the SDK workspace.
pub mod auth {
    pub use sentin8_auth_client as client;
    pub use sentin8_fapiclient as fapi;
    pub use sentin8_jwt as jwt;
    pub use sentin8_m2m as m2m;
    pub use sentin8_workload_registry as workload_registry;
}

/// Sentin8:Bus domain — platform client + contracts, outbox.
pub mod bus {
    pub use sentin8_bus_client as client;
    pub use sentin8_bus_contracts as contracts;
    pub use sentin8_outbox as outbox;
}

/// Sentin8:TLS termination library + contracts.
pub mod tls {
    pub use sentin8_tls::*;
    pub use sentin8_tls_contracts as contracts;
}