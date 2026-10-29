// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # Health check endpoints
//!
//! Provides a `/health` (or `/healthz`) handler that reports the service's
//! own status plus the status of its dependencies (DB, Valkey, downstream
//! services). Dependencies that fail to respond within a timeout are
//! marked `Unhealthy`; the overall status is `Degraded` if any dependency
//! is `Unhealthy`, `Unhealthy` if the service itself cannot serve.
//!
//! ## Usage
//!
//! ```text
//! use sentin8_middleware::health::{health_check_handler, DependencyHealth, HealthStatus};
//!
//! async fn health() -> impl axum::response::IntoResponse {
//!     let deps = vec![
//!         DependencyHealth { name: "db".into(), status: HealthStatus::Healthy, latency_ms: Some(2) },
//!         DependencyHealth { name: "valkey".into(), status: HealthStatus::Healthy, latency_ms: Some(1) },
//!     ];
//!     health_check_handler(deps).await
//! }
//! ```

use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

/// The health status of a service or dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Fully operational.
    Healthy,
    /// Operational but one or more dependencies are degraded.
    Degraded,
    /// Cannot serve requests.
    Unhealthy,
}

impl HealthStatus {
    /// Merge two statuses - the worse one wins.
    pub fn merge(self, other: HealthStatus) -> HealthStatus {
        use HealthStatus::*;
        match (self, other) {
            (Healthy, Healthy) => Healthy,
            (Unhealthy, _) | (_, Unhealthy) => Unhealthy,
            (Degraded, _) | (_, Degraded) => Degraded,
        }
    }
}

/// The health of a single dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyHealth {
    /// Dependency name (e.g. `db`, `valkey`, `auth`).
    pub name: String,
    /// Current status.
    pub status: HealthStatus,
    /// Last-known latency in milliseconds (if measured).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u32>,
}

impl DependencyHealth {
    /// Create a healthy dependency with a latency.
    pub fn healthy(name: &str, latency_ms: u32) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Healthy,
            latency_ms: Some(latency_ms),
        }
    }

    /// Create a degraded dependency (slow but responding).
    pub fn degraded(name: &str, latency_ms: u32) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Degraded,
            latency_ms: Some(latency_ms),
        }
    }

    /// Create an unhealthy dependency (not responding or erroring).
    pub fn unhealthy(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Unhealthy,
            latency_ms: None,
        }
    }
}

/// The overall health of a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// The service name (e.g. `ledger`).
    pub service_name: String,
    /// Aggregated status (worst of all dependencies, or the service itself).
    pub status: HealthStatus,
    /// Per-dependency status.
    pub dependencies: Vec<DependencyHealth>,
}

impl HealthCheck {
    /// Build a `HealthCheck` from the service name and its dependencies.
    /// The overall status is the merge of all dependency statuses (worst
    /// wins), starting from `Healthy`.
    pub fn from_dependencies(service_name: &str, dependencies: Vec<DependencyHealth>) -> Self {
        let status = dependencies
            .iter()
            .fold(HealthStatus::Healthy, |acc, d| acc.merge(d.status));
        Self {
            service_name: service_name.to_string(),
            status,
            dependencies,
        }
    }
}

/// Axum handler: returns the health check as JSON with the appropriate HTTP
/// status code (`200` for Healthy, `200` for Degraded, `503` for Unhealthy).
pub async fn health_check_handler(axum::Json(check): axum::Json<HealthCheck>) -> impl IntoResponse {
    let code = match check.status {
        HealthStatus::Healthy | HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };
    (code, axum::Json(check))
}

/// Convenience: build a `HealthCheck` from dependencies and serialise it
/// as a JSON response. Use this from a handler that already has the
/// dependency statuses in hand.
pub fn build_health_response(
    service_name: &str,
    dependencies: Vec<DependencyHealth>,
) -> (StatusCode, axum::Json<HealthCheck>) {
    let check = HealthCheck::from_dependencies(service_name, dependencies);
    let code = match check.status {
        HealthStatus::Healthy | HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };
    (code, axum::Json(check))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_healthy_healthy_is_healthy() {
        assert_eq!(
            HealthStatus::Healthy.merge(HealthStatus::Healthy),
            HealthStatus::Healthy
        );
    }

    #[test]
    fn merge_degraded_healthy_is_degraded() {
        assert_eq!(
            HealthStatus::Degraded.merge(HealthStatus::Healthy),
            HealthStatus::Degraded
        );
    }

    #[test]
    fn merge_unhealthy_anything_is_unhealthy() {
        assert_eq!(
            HealthStatus::Unhealthy.merge(HealthStatus::Healthy),
            HealthStatus::Unhealthy
        );
        assert_eq!(
            HealthStatus::Healthy.merge(HealthStatus::Unhealthy),
            HealthStatus::Unhealthy
        );
    }

    #[test]
    fn from_dependencies_all_healthy() {
        let deps = vec![
            DependencyHealth::healthy("db", 2),
            DependencyHealth::healthy("valkey", 1),
        ];
        let check = HealthCheck::from_dependencies("ledger", deps);
        assert_eq!(check.status, HealthStatus::Healthy);
        assert_eq!(check.dependencies.len(), 2);
    }

    #[test]
    fn from_dependencies_one_degraded() {
        let deps = vec![
            DependencyHealth::healthy("db", 2),
            DependencyHealth::degraded("valkey", 500),
        ];
        let check = HealthCheck::from_dependencies("ledger", deps);
        assert_eq!(check.status, HealthStatus::Degraded);
    }

    #[test]
    fn from_dependencies_one_unhealthy() {
        let deps = vec![
            DependencyHealth::healthy("db", 2),
            DependencyHealth::unhealthy("valkey"),
        ];
        let check = HealthCheck::from_dependencies("ledger", deps);
        assert_eq!(check.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn from_dependencies_empty_is_healthy() {
        let check = HealthCheck::from_dependencies("solo", vec![]);
        assert_eq!(check.status, HealthStatus::Healthy);
    }

    #[test]
    fn dependency_health_constructors() {
        let h = DependencyHealth::healthy("a", 5);
        assert_eq!(h.status, HealthStatus::Healthy);
        assert_eq!(h.latency_ms, Some(5));

        let d = DependencyHealth::degraded("b", 999);
        assert_eq!(d.status, HealthStatus::Degraded);

        let u = DependencyHealth::unhealthy("c");
        assert_eq!(u.status, HealthStatus::Unhealthy);
        assert!(u.latency_ms.is_none());
    }

    #[test]
    fn health_check_serializes() {
        let check = HealthCheck::from_dependencies("x", vec![DependencyHealth::healthy("a", 1)]);
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"service_name\":\"x\""));
    }

    #[test]
    fn health_status_round_trips() {
        for s in [
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Unhealthy,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: HealthStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn build_health_response_returns_200_for_healthy() {
        let (code, _) = build_health_response("x", vec![DependencyHealth::healthy("a", 1)]);
        assert_eq!(code, StatusCode::OK);
    }

    #[test]
    fn build_health_response_returns_200_for_degraded() {
        let (code, _) = build_health_response("x", vec![DependencyHealth::degraded("a", 1)]);
        assert_eq!(code, StatusCode::OK);
    }

    #[test]
    fn build_health_response_returns_503_for_unhealthy() {
        let (code, _) = build_health_response("x", vec![DependencyHealth::unhealthy("a")]);
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn handler_returns_200_for_healthy() {
        let check = HealthCheck::from_dependencies("x", vec![DependencyHealth::healthy("a", 1)]);
        let resp = health_check_handler(axum::Json(check))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handler_returns_503_for_unhealthy() {
        let check = HealthCheck::from_dependencies("x", vec![DependencyHealth::unhealthy("a")]);
        let resp = health_check_handler(axum::Json(check))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

// ── Liveness payload (typed bodies) ─────────────────────────────

/// The `GET /v1/health` liveness payload every service returns: the
/// status string, the serving service's short name, build identity, and
/// (when the process tracks them) the count of live connections.
/// `service` and `active_connections` stay absent when a service does
/// not set them (e.g. the bus mounts the generic handler).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct LiveHealth {
    /// Always `ok` on a live instance.
    pub status: String,
    /// The serving service's short name (absent when the generic handler
    /// does not carry one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Build identity id (`sentin8::build_info::id()`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Build hash (`sentin8::build_info::build_hash()`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    /// Live socket count when the traffic counter is mounted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_connections: Option<i64>,
}
