// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-errors
//!
//! Normalized error types, error codes, and HTTP status mapping for all
//! Sentin8 services.
//!
//! Every Sentin8 service returns errors using the [`Sentin8Error`] enum and the
//! [`Error::into_response`] axum integration. Error responses use the
//! canonical Sentin8 problem-details shape:
//!
//! ```json
//! {
//!   "error": "<error_code>",
//!   "message": "<human-readable message>",
//!   "correlation_id": "<uuid>",
//!   "details": { ... }
//! }
//! ```

#![deny(missing_docs)]
use std::collections::BTreeMap;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

// ── Error codes ──────────────────────────────────────────────────────────

/// Stable, machine-readable error codes used across all Sentin8 services.
///
/// Codes follow a `{service}_{problem}` convention, e.g. `sentin8_auth_token_invalid`,
/// `sentin8_db_table_not_found`, `sentin8_bff_tenant_mismatch`. Codes are stable across
/// releases and documented in each service's design doc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // ── Cross-cutting ──
    /// A required request header was missing or invalid.
    InvalidRequest,
    /// The caller did not present a valid Auth-issued token.
    Unauthorized,
    /// The caller's token lacks the required scope or role.
    Forbidden,
    /// The requested resource was not found.
    NotFound,
    /// A conflicting state was encountered (e.g. duplicate resource).
    Conflict,
    /// The request rate exceeded the allowed limit.
    RateLimited,
    /// An upstream service returned an error or timed out.
    UpstreamError,
    /// The tenant context could not be resolved from the request.
    TenantResolutionFailed,
    /// A tenant mismatch was detected (header tenant != session tenant).
    TenantMismatch,
    /// A required feature is not enabled for the environment.
    FeatureDisabled,
    /// Internal server error - unexpected failure.
    Internal,

    // ── Auth ──
    /// The presented token failed verification (signature, issuer, audience).
    AuthTokenInvalid,
    /// The presented token has expired.
    AuthTokenExpired,
    /// The presented token was revoked (e.g. refresh-family revocation).
    AuthTokenRevoked,
    /// The OAuth client does not exist or is not registered.
    AuthClientNotFound,
    /// The referenced session is missing or no longer valid.
    AuthSessionInvalid,

    // ── TLS ──
    /// No service could be resolved for the requested hostname.
    TLSUnknownHostname,
    /// The hostname resolved but no mapping/config exists for it.
    TLSMappingNotFound,

    // ── BFF ──
    /// The BFF session is missing or malformed.
    BffSessionInvalid,
    /// The BFF session has expired.
    BffSessionExpired,
    /// Tenant context from the request contradicts the session's tenant.
    BffTenantMismatch,
    /// The session's scopes are insufficient for the requested operation.
    BffScopeInsufficient,
    /// The CSRF token is missing or fails validation.
    BffCsrfInvalid,

    // ── DB ──
    /// The referenced table/relation does not exist.
    DbTableNotFound,
    /// A query violated row-level security (tenant context missing/invalid).
    DbRlsViolation,

    // ── Storage ──
    /// The requested object does not exist in storage.
    StorageObjectNotFound,
    /// The requested path escapes its bucket/object prefix.
    StoragePathTraversal,

    // ── Bus ──
    /// The referenced event stream does not exist.
    BusStreamNotFound,
    /// The referenced message/entry does not exist in the stream.
    BusMessageNotFound,

    // ── Sys ──
    /// The referenced organization does not exist.
    SysOrgNotFound,
    /// The referenced environment does not exist.
    SysEnvNotFound,

    // ── App ──
    /// The referenced app instance does not exist.
    AppInstanceNotFound,
    /// The referenced app-store listing does not exist.
    AppListingNotFound,

    // ── Func ──
    /// The referenced WASM module does not exist.
    FuncModuleNotFound,
    /// WASM execution failed (trap, missing export, fuel exhaustion).
    FuncWasmError,

    // ── Cron ──
    /// The referenced schedule does not exist.
    CronScheduleNotFound,

    // ── Flow ──
    /// The referenced workflow definition does not exist.
    FlowWorkflowNotFound,

    // ── Stat ──
    /// The referenced event property does not exist.
    StatPropertyNotFound,
    /// The query shape requires a raw scan (rejected by policy).
    StatQueryRequiresRawScan,
}

impl ErrorCode {
    /// The canonical wire string for this code (e.g.
    /// `sentin8_auth_token_invalid`); cross-cutting codes use the bare
    /// problem name (e.g. `not_found`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited => "rate_limited",
            Self::UpstreamError => "upstream_error",
            Self::TenantResolutionFailed => "tenant_resolution_failed",
            Self::TenantMismatch => "tenant_mismatch",
            Self::FeatureDisabled => "feature_disabled",
            Self::Internal => "internal",
            Self::AuthTokenInvalid => "sentin8_auth_token_invalid",
            Self::AuthTokenExpired => "sentin8_auth_token_expired",
            Self::AuthTokenRevoked => "sentin8_auth_token_revoked",
            Self::AuthClientNotFound => "sentin8_auth_client_not_found",
            Self::AuthSessionInvalid => "sentin8_auth_session_invalid",
            Self::TLSUnknownHostname => "sentin8_tls_unknown_hostname",
            Self::TLSMappingNotFound => "sentin8_tls_mapping_not_found",
            Self::BffSessionInvalid => "sentin8_bff_session_invalid",
            Self::BffSessionExpired => "sentin8_bff_session_expired",
            Self::BffTenantMismatch => "sentin8_bff_tenant_mismatch",
            Self::BffScopeInsufficient => "sentin8_bff_scope_insufficient",
            Self::BffCsrfInvalid => "sentin8_bff_csrf_invalid",
            Self::DbTableNotFound => "sentin8_db_table_not_found",
            Self::DbRlsViolation => "sentin8_db_rls_violation",
            Self::StorageObjectNotFound => "sentin8_storage_object_not_found",
            Self::StoragePathTraversal => "sentin8_storage_path_traversal",
            Self::BusStreamNotFound => "sentin8_bus_stream_not_found",
            Self::BusMessageNotFound => "sentin8_bus_message_not_found",
            Self::SysOrgNotFound => "sentin8_sys_org_not_found",
            Self::SysEnvNotFound => "sentin8_sys_env_not_found",
            Self::AppInstanceNotFound => "sentin8_app_instance_not_found",
            Self::AppListingNotFound => "sentin8_app_listing_not_found",
            Self::FuncModuleNotFound => "sentin8_func_module_not_found",
            Self::FuncWasmError => "sentin8_func_wasm_error",
            Self::CronScheduleNotFound => "sentin8_cron_schedule_not_found",
            Self::FlowWorkflowNotFound => "sentin8_flow_workflow_not_found",
            Self::StatPropertyNotFound => "sentin8_stat_property_not_found",
            Self::StatQueryRequiresRawScan => "sentin8_stat_query_requires_raw_scan",
        }
    }

    /// Map an error code to the canonical HTTP status code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::Unauthorized
            | Self::AuthTokenInvalid
            | Self::AuthTokenExpired
            | Self::AuthTokenRevoked
            | Self::AuthSessionInvalid
            | Self::BffSessionInvalid
            | Self::BffSessionExpired
            | Self::BffCsrfInvalid => StatusCode::UNAUTHORIZED,
            Self::Forbidden
            | Self::BffScopeInsufficient
            | Self::DbRlsViolation
            | Self::StoragePathTraversal => StatusCode::FORBIDDEN,
            Self::NotFound
            | Self::AuthClientNotFound
            | Self::TLSMappingNotFound
            | Self::DbTableNotFound
            | Self::StorageObjectNotFound
            | Self::BusStreamNotFound
            | Self::BusMessageNotFound
            | Self::SysOrgNotFound
            | Self::SysEnvNotFound
            | Self::AppInstanceNotFound
            | Self::AppListingNotFound
            | Self::FuncModuleNotFound
            | Self::CronScheduleNotFound
            | Self::FlowWorkflowNotFound
            | Self::StatPropertyNotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::TenantResolutionFailed | Self::TLSUnknownHostname => {
                StatusCode::MISDIRECTED_REQUEST
            }
            Self::TenantMismatch | Self::BffTenantMismatch => StatusCode::BAD_REQUEST,
            Self::FeatureDisabled => StatusCode::NOT_IMPLEMENTED,
            Self::UpstreamError => StatusCode::BAD_GATEWAY,
            Self::FuncWasmError => StatusCode::UNPROCESSABLE_ENTITY,
            Self::StatQueryRequiresRawScan => StatusCode::BAD_REQUEST,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Error ────────────────────────────────────────────────────────────────

/// The canonical Sentin8 error type. Carries a stable code, a human-readable
/// message, an optional correlation ID, and structured details.
#[derive(Debug, Error)]
pub struct Sentin8Error {
    /// The stable machine-readable error code.
    pub code: ErrorCode,
    /// Human-readable description of the failure.
    pub message: String,
    /// Request correlation ID propagated to the response when present.
    pub correlation_id: Option<String>,
    /// Structured extra fields rendered in the response `details` object.
    pub details: BTreeMap<String, Value>,
}

impl Sentin8Error {
    /// Create an error with a code and message (no correlation id, no
    /// details).
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            correlation_id: None,
            details: BTreeMap::new(),
        }
    }

    /// Attach a request correlation ID (rendered in the response body).
    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }

    /// Add one structured detail entry (rendered in the response body).
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

impl std::fmt::Display for Sentin8Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

// Convenience constructors - cross-cutting.
impl Sentin8Error {
    /// Build a `400 invalid_request` error.
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, msg)
    }
    /// Build a `401 unauthorized` error.
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthorized, msg)
    }
    /// Build a `403 forbidden` error.
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, msg)
    }
    /// Build a `404 not_found` error.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, msg)
    }
    /// Build a `409 conflict` error.
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, msg)
    }
    /// Build a `500 internal` error.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, msg)
    }
}

/// Convert anyhow errors into a Sentin8 internal error.
impl From<anyhow::Error> for Sentin8Error {
    fn from(err: anyhow::Error) -> Self {
        Self::internal(err.to_string())
    }
}

// ── Response body ────────────────────────────────────────────────────────

/// Canonical Sentin8 error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// The machine-readable error code string.
    pub error: String,
    /// The human-readable message.
    pub message: String,
    /// Request correlation ID (omitted when absent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Structured extra fields (omitted when empty).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

impl IntoResponse for Sentin8Error {
    fn into_response(self) -> Response {
        let status = self.code.status_code();
        let body = ErrorResponse {
            error: self.code.as_str().to_string(),
            message: self.message,
            correlation_id: self.correlation_id,
            details: self.details,
        };
        (status, Json(body)).into_response()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_status_mapping() {
        assert_eq!(ErrorCode::NotFound.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(ErrorCode::Conflict.status_code(), StatusCode::CONFLICT);
        assert_eq!(
            ErrorCode::TLSUnknownHostname.status_code(),
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(
            ErrorCode::RateLimited.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn error_code_string_round_trip() {
        for code in [
            ErrorCode::InvalidRequest,
            ErrorCode::AuthTokenExpired,
            ErrorCode::TLSUnknownHostname,
            ErrorCode::BffTenantMismatch,
        ] {
            let s = code.to_string();
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn constructor_and_details() {
        let err = Sentin8Error::new(ErrorCode::NotFound, "org not found")
            .with_correlation_id("corr-123")
            .with_detail("org_id", serde_json::json!("550e8400-..."));
        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(err.message, "org not found");
        assert_eq!(err.correlation_id.as_deref(), Some("corr-123"));
        assert_eq!(err.details.len(), 1);
    }
}
