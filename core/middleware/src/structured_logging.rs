// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # Structured logging
//!
//! JSON structured logging for all Sentin8 services. Every log line is a single
//! JSON object containing, at minimum:
//!
//! - `timestamp` — RFC 3339 UTC
//! - `level`     — `error` / `warn` / `info` / `debug` / `trace`
//! - `service`   — service name (e.g. `ledger`, `payments`, `tls`)
//! - `message`   — the human-readable message
//! - `target`    — the module path of the emitting code
//! - `correlation_id` — the request's `X-Sentin8-Correlation-Id` (if any)
//! - `tenant`    — `{ org_id, env_id, app_id, hostname, service }` when present
//!
//! ## Why a custom layer?
//!
//! The `tracing-subscriber` `json` layer doesn't natively inject fields
//! like `service` or pull a correlation_id out of an axum extension. We
//! wrap it in a `tracing_subscriber::Layer` that:
//!
//! 1. Pre-populates the `service` field via a process-wide
//!    `OnceCell<String>` (set by [`init_structured_logging`]).
//! 2. In `on_new_span`, walks the `Attributes` looking for a
//!    `correlation_id` field (set by the `correlation_id` middleware)
//!    and stores the value in the span's extensions as a
//!    [`CorrelationIdMarker`]. Same for `org_id` / `env_id` / etc. as a
//!    [`TenantMarker`].
//! 3. In `on_event`, reads the markers from the current span chain
//!    and emits them as `correlation_id` / `tenant` fields in the
//!    JSON line.
//!
//! ## Usage
//!
//! ```text
//! use sentin8_middleware::structured_logging::init_structured_logging;
//!
//! init_structured_logging("ledger", "info");
//! tracing::info!(account_id = %id, "created account");
//! ```
//!
//! The `correlation_id` and tenant fields are populated automatically
//! by the corresponding axum middleware; no per-handler work is
//! required.

use chrono::{DateTime, Utc};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use tracing::span::{Attributes, Id};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::{LookupSpan, SpanRef};

pub(crate) static SERVICE_NAME: OnceCell<String> = OnceCell::new();

/// Wire-schema identifier for every JSON log line emitted by the platform.
///
/// Bump this constant when the on-the-wire shape of [`LogEntry`] changes
/// in a breaking way (renaming a field, changing a type, adding/removing
/// a required field). The value is included as a top-level `schema` field
/// in every line so an LLM consumer (or Loki/ES) can reject or migrate
/// older lines without parsing surprises.
pub const LOG_SCHEMA_VERSION: &str = "sentin8.log/v1";

/// A structured log entry — the shape of every JSON line written to stdout.
///
/// This struct is primarily for documentation and testing; the actual log
/// lines are emitted by [`Sentin8JsonLayer`], not by serialising this struct
/// directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// RFC 3339 timestamp.
    pub timestamp: DateTime<Utc>,
    /// Log level (`error`, `warn`, `info`, `debug`, `trace`).
    pub level: String,
    /// Service name (e.g. `ledger`, `payments`).
    pub service: String,
    /// Human-readable message.
    pub message: String,
    /// Module path of the emitter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Correlation ID from the request (UUID v4 or any string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Tenant context: `{ org_id, env_id, app_id, hostname, service }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<serde_json::Value>,
    /// Arbitrary structured fields (key → value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<serde_json::Value>,
}

impl LogEntry {
    /// Build a `LogEntry` for testing.
    pub fn new(service: &str, level: &str, message: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            level: level.to_string(),
            service: service.to_string(),
            message: message.to_string(),
            target: None,
            correlation_id: None,
            tenant: None,
            fields: None,
        }
    }

    /// Attach a correlation ID.
    pub fn with_correlation_id(mut self, cid: impl Into<String>) -> Self {
        self.correlation_id = Some(cid.into());
        self
    }

    /// Attach structured fields.
    pub fn with_fields(mut self, fields: serde_json::Value) -> Self {
        self.fields = Some(fields);
        self
    }
}

// ── Sentin8JsonLayer ──────────────────────────────────────────────────────

/// A `tracing_subscriber::Layer` that:
/// - Captures the `correlation_id` and tenant fields on every new span
///   and stores them in the span's extensions.
/// - Injects the `service` field on every event.
/// - Emits structured JSON to stdout.
pub struct Sentin8JsonLayer;

impl<S> Layer<S> for Sentin8JsonLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        // Walk the span's recorded fields. If we find a `correlation_id`
        // or any of the tenant fields, store a marker in the span's
        // extensions so `on_event` can pick it up.
        let span = ctx.span(id);
        let Some(span) = span else { return };
        let mut correlation_id: Option<String> = None;
        let mut tenant = TenantMarker::default();
        struct FieldReader<'a> {
            correlation_id: &'a mut Option<String>,
            tenant: &'a mut TenantMarker,
        }
        impl<'a> tracing::field::Visit for FieldReader<'a> {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                match field.name() {
                    "correlation_id" => {
                        if self.correlation_id.is_none() {
                            *self.correlation_id = Some(value.to_string());
                        }
                    }
                    "env_id" => {
                        if self.tenant.env_id.is_none() && !value.is_empty() {
                            self.tenant.env_id = Some(value.to_string());
                        }
                    }
                    "app_id" => {
                        if self.tenant.application_id.is_none() && !value.is_empty() {
                            self.tenant.application_id = Some(value.to_string());
                        }
                    }
                    "hostname" if self.tenant.hostname.is_none() && !value.is_empty() => {
                        self.tenant.hostname = Some(value.to_string());
                    }
                    "service" if self.tenant.service.is_none() && !value.is_empty() => {
                        self.tenant.service = Some(value.to_string());
                    }
                    _ => {}
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                let name = field.name();
                if name == "correlation_id" {
                    if self.correlation_id.is_none() {
                        *self.correlation_id = Some(format!("{value:?}"));
                    }
                } else if name == "env_id" {
                    let s = format!("{value:?}");
                    let trimmed = s.trim_matches('"').to_string();
                    if self.tenant.env_id.is_none() && !trimmed.is_empty() {
                        self.tenant.env_id = Some(trimmed);
                    }
                }
            }
        }
        let mut reader = FieldReader {
            correlation_id: &mut correlation_id,
            tenant: &mut tenant,
        };
        attrs.record(&mut reader);

        if let Some(cid) = correlation_id {
            span.extensions_mut().insert(CorrelationIdMarker(cid));
        }
        if tenant.env_id.is_some()
            || tenant.application_id.is_some()
            || tenant.hostname.is_some()
            || tenant.service.is_some()
        {
            span.extensions_mut().insert(tenant);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let meta = event.metadata();
        let level = meta.level().to_string();
        let target = meta.target().to_string();

        // Collect structured fields (skip the "message" placeholder).
        let mut fields = serde_json::Map::new();
        let mut message = String::new();
        struct FieldVisitor<'a> {
            fields: &'a mut serde_json::Map<String, serde_json::Value>,
            message: &'a mut String,
        }
        impl<'a> tracing::field::Visit for FieldVisitor<'a> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    *self.message = format!("{value:?}");
                    return;
                }
                self.fields.insert(
                    field.name().to_string(),
                    serde_json::Value::String(format!("{value:?}")),
                );
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "message" {
                    *self.message = value.to_string();
                    return;
                }
                self.fields.insert(
                    field.name().to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            }
            fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
                if field.name() == "message" {
                    return;
                }
                self.fields.insert(
                    field.name().to_string(),
                    serde_json::Value::Number(value.into()),
                );
            }
            fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                if field.name() == "message" {
                    return;
                }
                self.fields.insert(
                    field.name().to_string(),
                    serde_json::Value::Number(value.into()),
                );
            }
            fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
                if field.name() == "message" {
                    return;
                }
                self.fields
                    .insert(field.name().to_string(), serde_json::Value::Bool(value));
            }
        }
        {
            let mut visitor = FieldVisitor {
                fields: &mut fields,
                message: &mut message,
            };
            event.record(&mut visitor);
        }

        // Walk the span chain looking for correlation_id and tenant markers.
        let mut correlation_id: Option<String> = None;
        let mut tenant_marker: Option<TenantMarker> = None;
        if let Some(span) = ctx.lookup_current() {
            for s in span.scope() {
                walk_span_markers(&s, &mut correlation_id, &mut tenant_marker);
            }
        }

        let mut tenant = serde_json::Map::new();
        if let Some(t) = tenant_marker {
            if let Some(v) = t.env_id {
                tenant.insert("env_id".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = t.application_id {
                tenant.insert("app_id".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = t.hostname {
                tenant.insert("hostname".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = t.service {
                tenant.insert("service".to_string(), serde_json::Value::String(v));
            }
        }

        let service = SERVICE_NAME
            .get()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let entry = LogEntry {
            timestamp: Utc::now(),
            level,
            service,
            message,
            target: Some(target),
            correlation_id,
            tenant: if tenant.is_empty() {
                None
            } else {
                Some(serde_json::Value::Object(tenant))
            },
            fields: if fields.is_empty() {
                None
            } else {
                Some(serde_json::Value::Object(fields))
            },
        };

        if let Ok(line) = serde_json::to_string(&entry) {
            println!("{line}");
        }
    }
}

fn walk_span_markers<'a, S>(
    s: &SpanRef<'a, S>,
    cid: &mut Option<String>,
    tenant: &mut Option<TenantMarker>,
) where
    S: LookupSpan<'a>,
{
    let exts = s.extensions();
    if cid.is_none() {
        if let Some(c) = exts.get::<CorrelationIdMarker>() {
            *cid = Some(c.0.clone());
        }
    }
    if tenant.is_none() {
        if let Some(t) = exts.get::<TenantMarker>() {
            *tenant = Some(t.clone());
        }
    }
}

// ── Span markers ────────────────────────────────────────────────────────

/// Marker stored in span extensions carrying the correlation ID.
#[derive(Debug, Clone)]
pub struct CorrelationIdMarker(pub String);

/// Marker stored in span extensions carrying tenant context.
#[derive(Debug, Clone, Default)]
pub struct TenantMarker {
    /// Tenant environment id string.
    pub env_id: Option<String>,
    /// Application instance id string.
    pub application_id: Option<String>,
    /// Request hostname.
    pub hostname: Option<String>,
    /// Target backend service name.
    pub service: Option<String>,
}

impl TenantMarker {
    /// Build the marker from the TLS-injected context.
    pub fn from_sentin8_tls_context(ctx: &crate::context::TLSContext) -> Self {
        Self {
            env_id: ctx.env_id.map(|u| u.to_string()),
            application_id: ctx.application_id.map(|u| u.to_string()),
            hostname: ctx.hostname.clone(),
            service: ctx.service.clone(),
        }
    }
}

// ── Initialisation ──────────────────────────────────────────────────────

/// Initialise global structured (JSON) logging for a service.
///
/// Call once at startup, before any `tracing::info!` / `tracing::error!`
/// calls. Re-initialising will panic (use [`init_structured_logging_try`]
/// in tests).
///
/// `service_name` is included as a top-level `service` field in every log
/// line. `level` is an `EnvFilter`-style directive (e.g. `info`,
/// `debug`, `sentin8_middleware=trace`).
pub fn init_structured_logging(service_name: &str, level: &str) {
    let _ = SERVICE_NAME.set(service_name.to_string());

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new(level))
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(Sentin8JsonLayer);

    tracing::subscriber::set_global_default(subscriber)
        .expect("set_global_default failed; init_structured_logging called twice");
}

/// Like [`init_structured_logging`] but tolerant of being called twice
/// (e.g. from tests). The second call is a no-op.
pub fn init_structured_logging_try(service_name: &str, level: &str) {
    let _ = SERVICE_NAME.set(service_name.to_string());

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new(level))
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(Sentin8JsonLayer);

    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Return the service name set by the last call to
/// [`init_structured_logging`]. Used by tests.
pub fn current_service_name() -> Option<&'static str> {
    SERVICE_NAME.get().map(|s| s.as_str())
}

/// Set the service name from external code (e.g. `error_metrics::init`).
/// This ensures the `Sentin8JsonLayer` includes the correct service name
/// in every log line even when the caller uses `init_tracing_with_metrics`
/// instead of `init_structured_logging` directly.
pub fn set_service_name(name: &str) {
    let _ = SERVICE_NAME.set(name.to_string());
}

/// Initialise structured logging for tests — uses the pretty
/// `tracing-subscriber` test writer so log output is captured by the test
/// framework.
#[cfg(test)]
pub fn init_test_logging() {
    let _ = SERVICE_NAME.set("test".to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .with_test_writer()
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::TLSContext;
    use tracing::subscriber::with_default;
    use uuid::Uuid;

    #[test]
    fn log_entry_construction() {
        let e = LogEntry::new("ledger", "info", "created account");
        assert_eq!(e.service, "ledger");
        assert_eq!(e.level, "info");
        assert_eq!(e.message, "created account");
        assert!(e.correlation_id.is_none());
        assert!(e.fields.is_none());
    }

    #[test]
    fn log_entry_with_correlation_id() {
        let e = LogEntry::new("payments", "error", "payment failed").with_correlation_id("abc-123");
        assert_eq!(e.correlation_id.as_deref(), Some("abc-123"));
    }

    #[test]
    fn log_entry_with_fields() {
        let e = LogEntry::new("auth", "warn", "bad token")
            .with_fields(serde_json::json!({"ip": "10.0.0.1"}));
        assert_eq!(e.fields.as_ref().unwrap()["ip"], "10.0.0.1");
    }

    #[test]
    fn log_entry_serializes_to_json() {
        let e = LogEntry::new("db", "info", "ok").with_correlation_id("cid");
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"service\":\"db\""));
        assert!(json.contains("\"level\":\"info\""));
        assert!(json.contains("\"correlation_id\":\"cid\""));
    }

    #[test]
    fn log_entry_skips_none_fields_in_json() {
        let e = LogEntry::new("db", "info", "ok");
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains("correlation_id"), "None should be skipped");
        assert!(!json.contains("fields"));
        assert!(!json.contains("tenant"));
        assert!(!json.contains("target"));
    }

    #[test]
    fn current_service_name_returns_set_value() {
        let _ = current_service_name();
    }

    #[test]
    fn layer_does_not_panic_under_event() {
        let subscriber = tracing_subscriber::registry().with(Sentin8JsonLayer);
        with_default(subscriber, || {
            tracing::info!("hello");
            tracing::warn!(extra = "value", "structured");
        });
    }

    #[test]
    fn tenant_marker_from_sentin8_tls_context_populates_all_fields() {
        let ctx = TLSContext {
            env_id: Some(Uuid::parse_str("660e8400-e29b-41d4-a716-446655440001").unwrap()),
            application_id: Some(Uuid::parse_str("770e8400-e29b-41d4-a716-446655440002").unwrap()),
            service: Some("bff".to_string()),
            hostname: Some("bff.example.com".to_string()),
            domain_type: Some("app_bff".to_string()),
            client_cert_thumbprint: None,
        };
        let marker = TenantMarker::from_sentin8_tls_context(&ctx);
        assert_eq!(
            marker.env_id.as_deref(),
            Some("660e8400-e29b-41d4-a716-446655440001")
        );
        assert_eq!(
            marker.application_id.as_deref(),
            Some("770e8400-e29b-41d4-a716-446655440002")
        );
        assert_eq!(marker.service.as_deref(), Some("bff"));
        assert_eq!(marker.hostname.as_deref(), Some("bff.example.com"));
    }
}
