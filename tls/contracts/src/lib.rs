// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # tls-contracts
//!
//! Rust types and OpenAPI contract for TLS hostname resolution — the
//! `Mapping` type produced by host-context resolution and consumed as
//! `X-Sentin8-*` request headers by every backend service.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A hostname → service + tenant mapping. Deduced at runtime by the
/// domain resolver from `sys.organizations`, `sys.environments`,
/// and `sys.app_instances` — no `domains` table needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mapping {
    /// Synthetic identity of this mapping (freshly generated per deduction).
    pub id: Uuid,
    /// The resolved hostname (without port).
    pub hostname: String,
    /// The backend service identifier serving this hostname.
    pub service: String,
    /// The organization the hostname belongs to.
    pub org_id: Uuid,
    /// The environment the hostname belongs to (RLS tenant context).
    pub env_id: Uuid,
    /// The app instance bound to this hostname, when it is an app frontend
    /// or app BFF hostname (platform service hostnames carry `None`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<Uuid>,
    /// Developer-provided backend URL for app hostnames (app metadata).
    pub backend_url: Option<String>,
    /// Creation timestamp of the deduction record.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last update timestamp of the deduction record.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl PartialEq for Mapping {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.hostname == other.hostname
            && self.service == other.service
            && self.org_id == other.org_id
            && self.env_id == other.env_id
            && self.application_id == other.application_id
            && self.backend_url == other.backend_url
        // Timestamps may differ at sub-second precision across a wire
        // hop; equality is identity+mapping content only.
    }
}

// Serde roundtrip tests pinning the wire contract.

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn sample() -> Mapping {
        Mapping {
            id: uuid::Uuid::new_v4(),
            hostname: "auth.ops.sys.example.com".into(),
            service: "auth".into(),
            org_id: uuid::Uuid::new_v4(),
            env_id: uuid::Uuid::new_v4(),
            application_id: None,
            backend_url: None,
            created_at: utc("2026-01-01T00:00:00Z"),
            updated_at: utc("2026-01-01T00:00:00Z"),
        }
    }

    #[test]
    fn mapping_roundtrip() {
        let m = sample();
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["hostname"], "auth.ops.sys.example.com");
        let back: Mapping = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn mapping_optional_fields_omitted_when_none() {
        let m = sample();
        let v = serde_json::to_value(&m).unwrap();
        // application_id has skip_serializing_if — absent when None.
        assert!(v.get("application_id").is_none());
        // backend_url has NO skip attr — None serializes as null (wire
        // contract pinned here; services always emit the field).
        assert!(v.get("backend_url").is_some_and(|x| x.is_null()));
        let back: Mapping = serde_json::from_value(v).unwrap();
        assert!(back.application_id.is_none());
        assert!(back.backend_url.is_none());
    }

    #[test]
    fn mapping_app_backend_shape_roundtrip() {
        // App-hostname mapping: application_id + backend_url set —
        // backend_url is developer-provided metadata.
        let mut m = sample();
        m.application_id = Some(uuid::Uuid::new_v4());
        m.backend_url = Some("https://ebank-backend.example.com".into());
        let v = serde_json::to_value(&m).unwrap();
        assert!(v.get("application_id").is_some());
        assert_eq!(v["backend_url"], "https://ebank-backend.example.com");
        let back: Mapping = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
    }
}
