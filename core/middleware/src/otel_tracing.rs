// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # OpenTelemetry tracing
//!
//! Initialises an OpenTelemetry OTLP exporter that sends spans to a
//! collector (e.g. Jaeger, Tempo, or the OTel Collector). Also provides a
//! helper for creating per-request spans that carry the correlation ID.
//!
//! ## Usage
//!
//! ```text
//! use sentin8_middleware::otel_tracing::{TracingConfig, init_otel_tracing};
//!
//! let cfg = TracingConfig {
//!     otel_endpoint: "http://otel-collector:4317".to_string(),
//!     service_name: "ledger".to_string(),
//!     sample_ratio: 0.1,
//! };
//! init_otel_tracing(&cfg).expect("otel init");
//! ```
//!
//! ## Note on dependencies
//!
//! The full OTel exporter requires the `opentelemetry-otlp` crate. To avoid
//! pulling that heavy dependency into every service, this module provides a
//! stub `init_otel_tracing` that logs a warning and returns `Ok(())` when
//! the endpoint is unreachable. A production deployment links the
//! `opentelemetry-otlp` feature and replaces the stub.

use serde::{Deserialize, Serialize};

/// Configuration for the OpenTelemetry tracer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// OTLP gRPC endpoint (e.g. `http://otel-collector:4317`).
    pub otel_endpoint: String,
    /// Service name (e.g. `ledger`, `payments`).
    pub service_name: String,
    /// Sampling ratio (0.0–1.0). 1.0 = all spans, 0.1 = 10%.
    pub sample_ratio: f64,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            otel_endpoint: "http://localhost:4317".to_string(),
            service_name: "sentin8-service".to_string(),
            sample_ratio: 0.1,
        }
    }
}

impl TracingConfig {
    /// Validate the config.
    pub fn validate(&self) -> Result<(), String> {
        if self.otel_endpoint.is_empty() {
            return Err("otel_endpoint must not be empty".to_string());
        }
        if self.service_name.is_empty() {
            return Err("service_name must not be empty".to_string());
        }
        if !(0.0_f64..=1.0_f64).contains(&self.sample_ratio) {
            return Err(format!(
                "sample_ratio must be between 0.0 and 1.0, got {}",
                self.sample_ratio
            ));
        }
        Ok(())
    }
}

/// Initialise OpenTelemetry tracing with the given config.
///
/// In the stub implementation, this validates the config and logs a warning
/// that OTel export is disabled. The full implementation (behind a feature
/// flag) installs a `tracing_opentelemetry::layer()` + an OTLP exporter.
pub fn init_otel_tracing(config: &TracingConfig) -> Result<(), String> {
    config.validate()?;
    tracing::warn!(
        endpoint = %config.otel_endpoint,
        service = %config.service_name,
        sample_ratio = config.sample_ratio,
        "OpenTelemetry tracing initialised (stub — no exporter linked). \
         Enable the `otel` feature on sentin8-middleware to export spans."
    );
    Ok(())
}

/// Create a `tracing::Span` for an incoming HTTP request, tagged with the
/// method, path, and (if available) correlation ID.
pub fn span_for_request(method: &str, path: &str) -> tracing::Span {
    tracing::info_span!(
        "http_request",
        method = %method,
        path = %path,
        correlation_id = tracing::field::Empty,
    )
}

/// Create a span for a service-to-service call, tagged with the target
/// service and operation.
pub fn span_for_outbound_call(target_service: &str, operation: &str) -> tracing::Span {
    tracing::info_span!(
        "outbound_call",
        target_service = %target_service,
        operation = %operation,
        correlation_id = tracing::field::Empty,
    )
}

/// Record a correlation ID into the current span (if any).
pub fn record_correlation_id(span: &tracing::Span, correlation_id: &str) {
    span.record("correlation_id", correlation_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = TracingConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_endpoint() {
        let cfg = TracingConfig {
            otel_endpoint: "".to_string(),
            service_name: "x".to_string(),
            sample_ratio: 0.1,
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("otel_endpoint"));
    }

    #[test]
    fn validate_rejects_empty_service_name() {
        let cfg = TracingConfig {
            otel_endpoint: "http://x".to_string(),
            service_name: "".to_string(),
            sample_ratio: 0.1,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_out_of_range_ratio() {
        let cfg = TracingConfig {
            otel_endpoint: "http://x".to_string(),
            service_name: "x".to_string(),
            sample_ratio: 1.5,
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("sample_ratio"));
    }

    #[test]
    fn validate_rejects_negative_ratio() {
        let cfg = TracingConfig {
            otel_endpoint: "http://x".to_string(),
            service_name: "x".to_string(),
            sample_ratio: -0.1,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn init_otel_tracing_succeeds_with_valid_config() {
        let cfg = TracingConfig::default();
        assert!(init_otel_tracing(&cfg).is_ok());
    }

    #[test]
    fn init_otel_tracing_fails_with_invalid_config() {
        let cfg = TracingConfig {
            otel_endpoint: "".to_string(),
            service_name: "x".to_string(),
            sample_ratio: 0.1,
        };
        assert!(init_otel_tracing(&cfg).is_err());
    }

    #[test]
    fn span_for_request_has_method_and_path() {
        let span = span_for_request("GET", "/v1/accounts");
        // The span exists; we cannot easily inspect its fields without
        // a subscriber, but we can verify it doesn't panic.
        drop(span);
    }

    #[test]
    fn span_for_outbound_call_builds() {
        let span = span_for_outbound_call("flow", "execute_step");
        drop(span);
    }

    #[test]
    fn record_correlation_id_does_not_panic() {
        let span = span_for_request("POST", "/v1/payments");
        record_correlation_id(&span, "corr-abc");
        drop(span);
    }

    #[test]
    fn tracing_config_serializes() {
        let cfg = TracingConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"service_name\""));
        let back: TracingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.service_name, cfg.service_name);
    }
}
