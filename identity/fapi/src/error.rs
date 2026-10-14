// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Error types for the FAPI client.

/// All errors returned by the FAPI client.
#[derive(Debug, thiserror::Error)]
pub enum FapiError {
    #[error("discovery fetch failed: {0}")]
    Discovery(String),

    #[error("OAuth flow error: {0}")]
    Flow(String),

    #[error("token exchange failed: {0}")]
    TokenExchange(String),

    #[error("token refresh failed: {0}")]
    TokenRefresh(String),

    #[error("JARM validation failed: {0}")]
    Jarm(String),

    #[error("JWKS fetch failed: {0}")]
    Jwks(String),

    #[error("JWT error: {0}")]
    Jwt(String),

    #[error("DPoP error: {0}")]
    Dpop(String),

    #[error("JAR (request object) error: {0}")]
    Jar(String),

    #[error("mTLS setup error: {0}")]
    Mtls(String),

    #[error("iss parameter mismatch: expected {expected}, got {actual}")]
    IssMismatch { expected: String, actual: String },

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("config error: {0}")]
    Config(String),
}

impl From<jsonwebtoken::errors::Error> for FapiError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        FapiError::Jwt(e.to_string())
    }
}
