// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Service composition helper — the adopter-facing face of MemBus.
//!
//! [`ServiceBus::connect`] is what a latency-critical service calls in
//! its `sentin8-shell` `with_state` closure (the same composition
//! pattern as the control-plane `bus_client`). It encodes the fail-soft
//! policy **once**, so the four realtime adopters cannot drift:
//!
//! - empty `valkey_url`  → disabled silently (the shell's existing
//!   "no publisher" convention for dev-only runs);
//! - Valkey unreachable / bad env id → disabled with a WARN;
//! - **never an `Err`** — MemBus is a hot-path accelerator, never a
//!   startup dependency (a realtime service must still boot).
//!
//! Disabled means every publish is a silent no-op.

use std::sync::Arc;

use crate::{EnvBus, MemBus, MemBusConfig, NoopMetrics};

/// A tenant-bound publish handle for one service, or a disabled
/// placeholder. Clone-cheap; the `EnvBus` inside is already
/// per-tenant-bound (`for_env` was resolved at connect).
#[derive(Clone)]
pub struct ServiceBus {
    env: Option<Arc<EnvBus>>,
}

impl ServiceBus {
    /// Connect for `service_name` (used to stamp the envelope `by`
    /// field and to resolve `{SERVICE}_ENV_ID`). Reads the env id via
    /// the design's fallback chain:
    /// `{SERVICE_SLUG_UPPER}_ENV_ID` → `SENTIN8_ENV_ID` →
    /// `sentin8_config::SYSTEM_ENV_ID`.
    ///
    /// `valkey_url` comes from `core.config.valkey_url` (the shell's
    /// resolved `VALKEY_URL`); empty string disables the bus — the
    /// same convention the shell applies to its metrics publisher.
    ///
    /// The connect is bounded (2 s): an unreachable Valkey disables
    /// the bus with a WARN rather than hanging startup.
    pub async fn connect(service_name: &str, valkey_url: &str) -> Self {
        if valkey_url.trim().is_empty() {
            // Dev-only run without a publisher — quiet by design.
            return Self::disabled();
        }
        let env_id = Self::resolve_env_id(service_name);
        let cfg = MemBusConfig {
            url: valkey_url.to_string(),
            // The service_name IS the workload identity: services pass
            // the same hardcoded identity they pass Sentin8Shell (the
            // certificate CN / ACL user derive from it).
            workload: service_name.to_string(),
            service_name: service_name.to_string(),
            trim_default: crate::DEFAULT_TRIM,
            metrics: Arc::new(NoopMetrics),
        };
        // Bound the PING: MemBus::connect must never hang a realtime
        // service's startup on a dead endpoint.
        let connect = tokio::time::Duration::from_secs(2);
        match tokio::time::timeout(connect, MemBus::connect(cfg)).await {
            Ok(Ok(bus)) => match bus.for_env(&env_id) {
                Ok(env) => Self {
                    env: Some(Arc::new(env)),
                },
                Err(e) => {
                    tracing::warn!(
                        service = service_name,
                        error = %e,
                        "membus: invalid env id '{env_id}' — publishing disabled"
                    );
                    Self::disabled()
                }
            },
            Ok(Err(e)) => {
                tracing::warn!(
                    service = service_name,
                    error = %e,
                    "membus: Valkey unreachable — publishing disabled"
                );
                Self::disabled()
            }
            Err(_) => {
                tracing::warn!(
                    service = service_name,
                    url = valkey_url,
                    "membus: connect timed out — publishing disabled"
                );
                Self::disabled()
            }
        }
    }

    /// Whether publishes go anywhere (diagnostics/tests).
    pub fn is_enabled(&self) -> bool {
        self.env.is_some()
    }

    /// Durable publish — no-op when disabled. Errors surface at DEBUG:
    /// a lost fast-bus tick is tolerable by contract; the
    /// caller's durable record (journal, DB) remains authoritative.
    pub async fn publish_stream(&self, family: &str, event_type: &str, payload: serde_json::Value) {
        if let Some(env) = &self.env {
            let envelope = crate::Envelope::new(event_type, payload.to_string().into_bytes());
            if let Err(e) = env.publish_stream(family, &envelope).await {
                tracing::debug!(error = %e, %event_type, "membus: publish_stream failed");
            }
        }
    }

    /// Ephemeral publish — no-op when disabled.
    pub async fn publish_pubsub(&self, family: &str, event_type: &str, payload: serde_json::Value) {
        if let Some(env) = &self.env {
            let envelope = crate::Envelope::new(event_type, payload.to_string().into_bytes());
            if let Err(e) = env.publish_pubsub(family, &envelope).await {
                tracing::debug!(error = %e, %event_type, "membus: publish_pubsub failed");
            }
        }
    }

    fn disabled() -> Self {
        Self { env: None }
    }

    fn resolve_env_id(service_name: &str) -> String {
        // Colon and hyphen separators both map to `_` (colon identity
        // `svc:role` → `SVC_ROLE_ENV_ID`; hyphen form maps to the same
        // slug).
        let slug = service_name.to_ascii_uppercase().replace([':', '-'], "_");
        std::env::var(format!("{slug}_ENV_ID"))
            .or_else(|_| std::env::var("SENTIN8_ENV_ID"))
            .unwrap_or_else(|_| sentin8_config::SYSTEM_ENV_ID.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_url_disables_silently() {
        let bus = ServiceBus::connect("svc-role", "").await;
        assert!(!bus.is_enabled());
        // Publishes are no-ops, not errors.
        bus.publish_stream("me.exec", "svc:me:trade:printed", serde_json::json!({}))
            .await;
        bus.publish_pubsub("md.book", "svc:md:book:delta", serde_json::json!({}))
            .await;
    }

    #[tokio::test]
    async fn unreachable_valkey_disables_with_warn() {
        // A port nothing listens on — connect must disable, not error.
        let bus = ServiceBus::connect("svc-role", "valkey://localhost:59999/0").await;
        assert!(!bus.is_enabled());
    }

    #[test]
    fn env_id_slug_resolution() {
        // The slug derivation is pure — verify the mandated shape
        // (`svc:role` → `SVC_ROLE_ENV_ID`). The legacy hyphen form maps
        // to the same slug.
        let slug = "svc:role".to_ascii_uppercase().replace([':', '-'], "_");
        assert_eq!(slug, "SVC_ROLE");
        let legacy = "svc-role".to_ascii_uppercase().replace([':', '-'], "_");
        assert_eq!(legacy, "SVC_ROLE");
    }
}
