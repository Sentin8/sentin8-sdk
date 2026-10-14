// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Policy-decision and service-metric telemetry via MemBus (SDD §2.3).
//!
//! `policy.would_deny` (shadow) and `policy.deny` (enforced) events carry
//! the decision inputs for the audit sink: action, reason, rule set,
//! subject. Fire-and-forget — a Valkey outage never blocks a request,
//! and a lost frame degrades to log-only.
//!
//! Transport is MemBus Pub/Sub (`stat.telemetry` family, ephemeral
//! newest-wins class), consumed by Sentin8:Stat's worker. No
//! service-scoped HTTP client, no M2M DCR workload — the shared plane
//! links no service SDK crate (SDD-1). The publish handle is built once
//! per process at boot; every path degrades to log-only on failure.

use std::sync::Arc;

use sentin8_membus::{Envelope, MemBus, MemBusConfig};

/// `client_type` on every emitted frame. Stat ingest validates
/// `web|server|mobile` and rejects anything else with 400 (stat's
/// `clean()`) — backend emitters are "server" clients.
pub const EMIT_CLIENT_TYPE: &str = "server";

/// MemBus Pub/Sub family for the telemetry class.
pub const TELEMETRY_FAMILY: &str = "stat.telemetry";

/// Frame event type — platform colon naming.
const FRAME_EVENT_TYPE: &str = "sentin8:stat:telemetry:emitted";

/// The shared per-process MemBus handle. `None` = emission disabled
/// (log-only) — Valkey unreachable at init.
static MBUS: std::sync::OnceLock<Option<Arc<MemBus>>> = std::sync::OnceLock::new();
/// The producer slug reported in frames (service short name; stat
/// resolves the property server-side at ingest).
static PROPERTY_SLUG: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Build (once) the telemetry publisher for a service — called by
/// `boot_full` (shell services) and non-shell binaries' own boot. Failure
/// degrades to log-only: emission stays disabled, decisions still trace.
///
/// `service` — colon service_type; the frame's `by` producer and
/// `property_slug` carry its short name.
pub async fn init_stat_emitter_for_service(service: &str) {
    let cfg = MemBusConfig::from_env(service);
    init_stat_emitter(&cfg.url, service).await;
}

/// Build (once) the telemetry publisher with explicit configuration —
/// the test seam. `valkey_url` empty disables emission.
///
/// `service` — colon service_type; the frame's `property_slug` carries
/// its short name.
///
/// Called by each service's boot before serving (failure to emit is
/// never fatal — it only degrades the audit sink).
pub async fn init_stat_emitter(valkey_url: &str, service: &str) {
    let short = service.rsplit(':').next().unwrap_or(service);
    let _ = PROPERTY_SLUG.set(short.to_string());
    let bus = if valkey_url.is_empty() {
        tracing::info!("telemetry emission disabled (no Valkey URL)");
        None
    } else {
        let cfg = MemBusConfig {
            url: valkey_url.to_string(),
            // The cert-presenting workload identity (group DESIGN.md
            // §3.1): an empty name resolved `.crt` — no cert, no
            // connection, and the retry loop churned a client every
            // few seconds. The service's own identity is the one the
            // Valkey plane provisions (its ACL user + key namespace).
            ..MemBusConfig::from_env(service)
        };
        match MemBus::connect(cfg).await {
            Ok(bus) => Some(bus),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "telemetry MemBus connect failed; emission degrades to log-only"
                );
                None
            }
        }
    };
    let _ = MBUS.set(bus.map(Arc::new));
}

/// Emit a policy decision event (fire-and-forget). No-op until
/// `init_stat_emitter` ran, or when emission was disabled at init.
///
/// `enforced=false` → `policy.would_deny` (shadow); `enforced=true` →
/// `policy.deny`. The frame is self-contained for the audit sink:
/// service, action, reason, matched rule set, subject.
pub fn emit_decision(
    service: &str,
    subject_id: &str,
    action: &str,
    enforced: bool,
    reason: &str,
    set_name: &str,
) {
    let event_name = if enforced {
        "policy.deny"
    } else {
        "policy.would_deny"
    };
    let props = serde_json::json!({
        "service": service,
        "action": action,
        "reason": reason,
        "policy_set": set_name,
        "enforced": enforced,
    });
    publish_frame(event_name, Some(subject_id), serde_json::json!({}), props);
}

/// Emit a single metric event for the calling service: `metrics` must be
/// a JSON object of NUMERIC values (stat's ingest drops non-numeric
/// metric values), `props` any JSON object. Fire-and-forget — a disabled
/// or failed emission degrades to log-only. The publisher must have been
/// initialized first ([`init_stat_emitter_for_service`]); without it this
/// is a no-op.
pub fn emit_metric_event(
    service: &str,
    event_name: &str,
    metrics: serde_json::Value,
    props: serde_json::Value,
) {
    let mut props = match props {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    if !service.is_empty() {
        props.insert("service".to_string(), serde_json::json!(service));
    }
    publish_frame(
        event_name,
        None,
        metrics,
        serde_json::Value::Object(props),
    );
}

/// Serialize one telemetry frame (stat `EventEnvelope` shape) and publish
/// it to the Pub/Sub channel. Fire-and-forget: the publish is spawned on
/// the caller's runtime (the caller never awaits), and any failure drops
/// the frame with a warn — the emission contract is log-only degradation.
fn publish_frame(
    event_name: &str,
    subject_id: Option<&str>,
    metrics: serde_json::Value,
    props: serde_json::Value,
) {
    let Some(bus) = MBUS.get().and_then(|b| b.as_ref()) else {
        return; // disabled — the decision/metric is already in the tracing log
    };
    let payload = telemetry_frame(event_name, subject_id, metrics, props);
    let envelope = Envelope {
        event_type: FRAME_EVENT_TYPE.to_string(),
        ts_us: chrono::Utc::now().timestamp_micros().max(0) as u64,
        correlation_id: String::new(),
        producer: PROPERTY_SLUG.get().cloned().unwrap_or_default(),
        sq: 0, // assigned by EnvBus at publish time
        payload,
    };
    // Bind the platform env: server telemetry is platform-scoped — stat
    // resolves the property (slug) server-side at ingest, matching the
    // domain-resolver/sys MemBus precedent (`for_env(SYSTEM_ENV_ID)`).
    let env_bus = match bus.for_env(&sentin8_config::SYSTEM_ENV_ID.to_string()) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "telemetry for_env failed — frame dropped");
            return;
        }
    };
    // Clone the handle: the spawned publish must not borrow the local
    // `envelope` (E0597 — the future needs 'static).
    let bus = env_bus;
    let publish = async move {
        if let Err(e) = bus.publish_pubsub(TELEMETRY_FAMILY, &envelope).await {
            tracing::warn!(error = %e, "telemetry publish failed — frame dropped (log-only)");
        }
    };
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(publish);
        }
        Err(_) => {
            // No runtime context (unit tests, sync-only paths): the frame
            // drops — emission is best-effort by contract.
        }
    }
}

/// The frame payload — the stat `EventEnvelope` wire shape the stat
/// worker decodes on the Pub/Sub channel.
fn telemetry_frame(
    event_name: &str,
    subject_id: Option<&str>,
    metrics: serde_json::Value,
    props: serde_json::Value,
) -> Vec<u8> {
    let has_metrics = metrics
        .as_object()
        .map(|m| !m.is_empty())
        .unwrap_or(false);
    let frame = serde_json::json!({
        "event_id": uuid::Uuid::new_v4(),
        "client_id": PROPERTY_SLUG.get().cloned().unwrap_or_default(),
        "property_id": uuid::Uuid::nil(),
        "property_slug": PROPERTY_SLUG.get().cloned().unwrap_or_default(),
        // See EMIT_CLIENT_TYPE — must stay within stat's accepted set.
        "client_type": EMIT_CLIENT_TYPE,
        "event_type": if has_metrics { "metric" } else { "event" },
        "event_name": event_name,
        "timestamp": chrono::Utc::now(),
        "subject_id": subject_id,
        "metrics": metrics,
        "props": props,
    });
    serde_json::to_vec(&frame).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `emit_decision` before init must be a silent no-op (no panic) —
    /// emission is opt-in via init and every path degrades to log-only.
    #[test]
    fn emit_before_init_is_noop() {
        emit_decision(
            "sentin8:post",
            "subj",
            "sentin8:post:read",
            true,
            "test",
            "role-mirror",
        );
    }

    /// The producer slug derives from the service short name.
    #[test]
    fn short_name_extraction() {
        assert_eq!("sentin8:post".rsplit(':').next().unwrap_or("x"), "post");
    }

    /// Pin: the emitted frame's `client_type` must
    /// be a value stat ingest accepts (`web|server|mobile` in stat's
    /// `clean()`). This duplicates stat's accepted set; a change on
    /// either side must update both (a wire-contract test in stat keeps it
    /// honest end-to-end).
    #[test]
    fn emit_client_type_is_accepted_by_stat_ingest() {
        assert!(
            matches!(EMIT_CLIENT_TYPE, "web" | "server" | "mobile"),
            "telemetry client_type '{EMIT_CLIENT_TYPE}' must be one of web|server|mobile (stat ingest clean())"
        );
    }

    /// The frame payload serializes to the stat `EventEnvelope` shape —
    /// the stat worker decodes exactly these fields.
    #[test]
    fn telemetry_frame_shape() {
        let frame = telemetry_frame(
            "policy.deny",
            Some("subj"),
            serde_json::json!({}),
            serde_json::json!({"service": "sentin8:post", "action": "read"}),
        );
        let v: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(v["client_type"], "server");
        assert_eq!(v["event_name"], "policy.deny");
        assert_eq!(v["event_type"], "event");
        assert_eq!(v["subject_id"], "subj");
        assert_eq!(v["property_id"], serde_json::json!(uuid::Uuid::nil()));
        assert!(v["event_id"].is_string());
        assert!(v["timestamp"].is_string());
    }

    /// Metric frames classify as `event_type: "metric"` when metrics are
    /// present — the rollup pipeline keys on it.
    #[test]
    fn metric_frame_classifies_as_metric() {
        let frame = telemetry_frame(
            "func.execute",
            None,
            serde_json::json!({"duration_ms": 12}),
            serde_json::json!({"service": "sentin8:func"}),
        );
        let v: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(v["event_type"], "metric");
        assert!(v["subject_id"].is_null());
    }
}