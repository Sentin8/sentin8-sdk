// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! OIDC discovery document types.
//!
//! Parses the Auth `/.well-known/openid-configuration` response.
//! for the full
//! FAPI 2.0 profile example.

use serde::{Deserialize, Serialize};

/// The OIDC discovery document.
///
/// All optional fields are `None` when the issuer does not advertise them.
/// The client adapts its OAuth flow based on which fields are present.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_endpoint_aliases: Option<MtlsEndpointAliases>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub response_modes_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_response_iss_parameter_supported: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_parameter_supported: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_uri_parameter_supported: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_types_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    /// FAPI profile markers (Auth-specific).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_mtls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_par: Option<bool>,
}

impl DiscoveryDocument {
    /// True if `response_modes_supported` includes `jwt` (JARM is active).
    pub fn jarm_supported(&self) -> bool {
        self.response_modes_supported.iter().any(|m| m == "jwt")
    }

    /// True if PAR is advertised.
    pub fn par_supported(&self) -> bool {
        self.pushed_authorization_request_endpoint.is_some()
    }

    /// True if JAR (request object signing) is advertised.
    pub fn jar_supported(&self) -> bool {
        self.request_object_signing_alg_values_supported
            .as_ref()
            .is_some_and(|v| !v.is_empty())
    }

    /// True if DPoP is advertised.
    pub fn dpop_supported(&self) -> bool {
        self.dpop_signing_alg_values_supported
            .as_ref()
            .is_some_and(|v| !v.is_empty())
    }

    /// True if `tls_client_auth` is advertised as a token endpoint auth method.
    pub fn mtls_client_auth_supported(&self) -> bool {
        self.token_endpoint_auth_methods_supported
            .as_ref()
            .is_some_and(|methods| methods.iter().any(|m| m == "tls_client_auth"))
    }

    /// Resolve the token endpoint, preferring `mtls_endpoint_aliases` when mTLS is advertised.
    pub fn token_endpoint(&self) -> &str {
        self.mtls_endpoint_aliases
            .as_ref()
            .and_then(|a| a.token_endpoint.as_deref())
            .filter(|_| self.mtls_client_auth_supported())
            .unwrap_or(&self.token_endpoint)
    }

    /// Resolve the revocation endpoint, preferring `mtls_endpoint_aliases`.
    pub fn revocation_endpoint(&self) -> Option<&str> {
        self.mtls_endpoint_aliases
            .as_ref()
            .and_then(|a| a.revocation_endpoint.as_deref())
            .filter(|_| self.mtls_client_auth_supported())
            .or(self.revocation_endpoint.as_deref())
    }

    /// Resolve the introspection endpoint, preferring `mtls_endpoint_aliases`.
    pub fn introspection_endpoint(&self) -> Option<&str> {
        self.mtls_endpoint_aliases
            .as_ref()
            .and_then(|a| a.introspection_endpoint.as_deref())
            .filter(|_| self.mtls_client_auth_supported())
            .or(self.introspection_endpoint.as_deref())
    }
}

/// MTLS endpoint aliases — alternative endpoints used when mTLS is required.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MtlsEndpointAliases {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
}

/// PAR (Pushed Authorization Request) response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ParResponse {
    pub request_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
}

/// JWKS (JSON Web Key Set) document.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// A single JSON Web Key.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    // RSA
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    // EC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}
