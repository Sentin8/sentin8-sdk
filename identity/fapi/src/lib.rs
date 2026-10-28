// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-fapiclient
//!
//! Discovery-driven FAPI-compliant OAuth client for Sentin8.
//!
//! All Sentin8 clients (BFF, FDX, backend services, third-party Rust
//! integrations) **must read the Auth OIDC discovery document** and adapt
//! their OAuth flow to the advertised capabilities (PAR, DPoP, mTLS, JARM,
//! `iss` parameter). This crate implements the full discovery-driven flow.
//!

//!
//! # Example
//!
//! ```no_run
//! # async fn demo() -> Result<(), sentin8_fapiclient::FapiError> {
//! use sentin8_fapiclient::{Client, ClientOptions};
//!
//! let opts = ClientOptions::builder()
//!     .issuer_url("https://auth.ibank.local")
//!     .client_id("my-client")
//!     .client_secret("secret")
//!     .redirect_uri("https://app.ibank.local/callback")
//!     .scopes("openid profile email offline_access")
//!     .build()?;
//!
//! let client = Client::new(opts)?;
//! let doc = client.discover().await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod client;
mod crypto;
mod discovery;
mod error;
mod jwks;
mod options;
mod types;

pub use client::Client;
pub use crypto::{
    ciba_request_object, dpop_proof, ec_public_jwk, generate_dpop_key_pem, generate_pkce_verifier,
    pkce_s256_challenge, url_encode, CibaRequestObject,
};
pub use discovery::{DiscoveryDocument, Jwk, JwkSet, MtlsEndpointAliases, ParResponse};
pub use error::FapiError;
pub use jwks::JwksCache;
pub use options::{ClientOptions, ClientOptionsBuilder};
pub use types::{IntrospectionResponse, ManagedToken, TokenResponse, UserInfoResponse};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_verifier_length() {
        let v = Client::generate_pkce_verifier();
        assert!(v.len() >= 43 && v.len() <= 128, "len = {}", v.len());
    }

    #[test]
    fn options_builder_validates_required_fields() {
        // Missing issuer_url.
        let res = ClientOptions::builder()
            .client_id("c")
            .redirect_uri("r")
            .build();
        assert!(res.is_err());

        // Missing client_id.
        let res = ClientOptions::builder()
            .issuer_url("https://a")
            .redirect_uri("r")
            .build();
        assert!(res.is_err());

        // Missing redirect_uri.
        let res = ClientOptions::builder()
            .issuer_url("https://a")
            .client_id("c")
            .build();
        assert!(res.is_err());

        // Complete.
        let res = ClientOptions::builder()
            .issuer_url("https://a")
            .client_id("c")
            .redirect_uri("r")
            .build();
        assert!(res.is_ok());
    }

    #[test]
    fn options_builder_mtls_requires_key() {
        let res = ClientOptions::builder()
            .issuer_url("https://a")
            .client_id("c")
            .redirect_uri("r")
            .tls_cert("/tmp/cert.pem")
            .build();
        let err = res.unwrap_err().to_string();
        assert!(err.contains("tls_key"), "unexpected: {}", err);
    }

    #[test]
    fn managed_token_expiry() {
        let resp = TokenResponse {
            access_token: "at".into(),
            refresh_token: Some("rt".into()),
            token_type: "Bearer".into(),
            expires_in: 60,
            scope: Some("openid".into()),
            id_token: None,
        };
        let mt = ManagedToken::from_response(resp);
        assert!(!mt.is_expired());
        assert!(mt.time_to_expiry().as_secs() <= 60);
        assert!(mt.expires_within(std::time::Duration::from_secs(120)));
    }

    #[test]
    fn discovery_jarm_supported() {
        let doc = DiscoveryDocument {
            response_modes_supported: vec!["query".into(), "jwt".into()],
            ..Default::default()
        };
        assert!(doc.jarm_supported());

        let doc2 = DiscoveryDocument {
            response_modes_supported: vec!["query".into()],
            ..Default::default()
        };
        assert!(!doc2.jarm_supported());
    }

    #[test]
    fn discovery_par_supported() {
        let doc = DiscoveryDocument {
            pushed_authorization_request_endpoint: Some("https://a/par".into()),
            ..Default::default()
        };
        assert!(doc.par_supported());

        let doc2 = DiscoveryDocument::default();
        assert!(!doc2.par_supported());
    }

    #[test]
    fn discovery_jar_supported() {
        let doc = DiscoveryDocument {
            request_object_signing_alg_values_supported: Some(vec!["RS256".into()]),
            ..Default::default()
        };
        assert!(doc.jar_supported());

        let doc2 = DiscoveryDocument {
            request_object_signing_alg_values_supported: Some(vec![]),
            ..Default::default()
        };
        assert!(!doc2.jar_supported());
    }

    #[test]
    fn discovery_dpop_supported() {
        let doc = DiscoveryDocument {
            dpop_signing_alg_values_supported: Some(vec!["ES256".into()]),
            ..Default::default()
        };
        assert!(doc.dpop_supported());

        let doc2 = DiscoveryDocument::default();
        assert!(!doc2.dpop_supported());
    }

    #[test]
    fn discovery_mtls_endpoint_resolution() {
        let doc = DiscoveryDocument {
            token_endpoint: "https://a/token".into(),
            mtls_endpoint_aliases: Some(MtlsEndpointAliases {
                token_endpoint: Some("https://a/mtls/token".into()),
                ..Default::default()
            }),
            token_endpoint_auth_methods_supported: Some(vec!["tls_client_auth".into()]),
            ..Default::default()
        };
        assert_eq!(doc.token_endpoint(), "https://a/mtls/token");

        // Without tls_client_auth advertised, falls back to base endpoint.
        let doc2 = DiscoveryDocument {
            token_endpoint: "https://a/token".into(),
            mtls_endpoint_aliases: Some(MtlsEndpointAliases {
                token_endpoint: Some("https://a/mtls/token".into()),
                ..Default::default()
            }),
            token_endpoint_auth_methods_supported: Some(vec!["client_secret_basic".into()]),
            ..Default::default()
        };
        assert_eq!(doc2.token_endpoint(), "https://a/token");
    }
}
