// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Configuration for creating a FAPI client.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::error::FapiError;

/// Configuration for creating a FAPI client.
///
/// Build with [`ClientOptions::builder`] or construct directly.
/// All time-to-live durations are configurable; defaults follow
/// the FAPI profile documentation):
///   - discovery TTL: 5 minutes
///   - JWKS TTL: 5 minutes
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// The Auth issuer URL, e.g. `https://auth.ibank.local`.
    pub issuer_url: String,
    /// OAuth client ID registered with Auth.
    pub client_id: String,
    /// OAuth client secret (confidential clients). Optional for public clients.
    pub client_secret: Option<String>,
    /// Redirect URI registered with Auth.
    pub redirect_uri: String,
    /// Optional scopes to request by default (space-separated).
    pub scopes: Option<String>,
    /// Scopes to request at the token endpoint (e.g. `openid profile email offline_access`).
    /// Path to a PEM-encoded client TLS certificate for `tls_client_auth` / mTLS.
    pub tls_cert: Option<PathBuf>,
    /// Path to a PEM-encoded client TLS private key for mTLS.
    pub tls_key: Option<PathBuf>,
    /// `tls_client_auth` subject distinguished name (the `tls_client_auth_subject_dn`
    /// registered with Auth). Sent as `tls_client_auth` body parameter when set.
    pub tls_client_auth_subject_dn: Option<String>,
    /// Discovery document cache TTL. Default 5 minutes.
    pub discovery_ttl: Duration,
    /// JWKS cache TTL. Default 5 minutes.
    pub jwks_ttl: Duration,
    /// Request timeout for HTTP calls. Default 30 seconds.
    pub http_timeout: Duration,
    /// Max retries for token auto-refresh. Default 1.
    pub refresh_retries: u32,
    /// DPoP signing key (PEM-encoded PKCS#8 private key), used when
    /// `dpop_signing_alg_values_supported` is advertised. Optional.
    pub dpop_key_pem: Option<Arc<String>>,
    /// JAR (request object) signing key (PEM-encoded PKCS#8 private key),
    /// used when `request_object_signing_alg_values_supported` is advertised. Optional.
    pub jar_key_pem: Option<Arc<String>>,
    /// JAR signing algorithm to use (e.g. `RS256`, `ES256`). Must be one of the
    /// algorithms advertised in `request_object_signing_alg_values_supported`.
    pub jar_signing_alg: Option<String>,
    /// DPoP signing algorithm (e.g. `ES256`, `RS256`). Must be one of the
    /// algorithms advertised in `dpop_signing_alg_values_supported`.
    pub dpop_signing_alg: Option<String>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            issuer_url: String::new(),
            client_id: String::new(),
            client_secret: None,
            redirect_uri: String::new(),
            scopes: None,
            tls_cert: None,
            tls_key: None,
            tls_client_auth_subject_dn: None,
            discovery_ttl: Duration::from_secs(300),
            jwks_ttl: Duration::from_secs(300),
            http_timeout: Duration::from_secs(30),
            refresh_retries: 1,
            dpop_key_pem: None,
            jar_key_pem: None,
            jar_signing_alg: None,
            dpop_signing_alg: None,
        }
    }
}

impl ClientOptions {
    /// Create a builder for [`ClientOptions`].
    pub fn builder() -> ClientOptionsBuilder {
        ClientOptionsBuilder::default()
    }

    /// Validate the options before constructing a client.
    pub fn validate(&self) -> Result<(), FapiError> {
        if self.issuer_url.trim().is_empty() {
            return Err(FapiError::Config("issuer_url is required".into()));
        }
        if self.client_id.trim().is_empty() {
            return Err(FapiError::Config("client_id is required".into()));
        }
        if self.redirect_uri.trim().is_empty() {
            return Err(FapiError::Config("redirect_uri is required".into()));
        }
        // If mTLS cert is set, key must also be set.
        if self.tls_cert.is_some() && self.tls_key.is_none() {
            return Err(FapiError::Config(
                "tls_cert set but tls_key is missing".into(),
            ));
        }
        Ok(())
    }
}

/// Builder for [`ClientOptions`].
#[derive(Debug, Default)]
pub struct ClientOptionsBuilder {
    opts: ClientOptions,
}

impl ClientOptionsBuilder {
    pub fn issuer_url(mut self, url: impl Into<String>) -> Self {
        self.opts.issuer_url = url.into();
        self
    }
    pub fn client_id(mut self, id: impl Into<String>) -> Self {
        self.opts.client_id = id.into();
        self
    }
    pub fn client_secret(mut self, secret: impl Into<String>) -> Self {
        self.opts.client_secret = Some(secret.into());
        self
    }
    pub fn redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.opts.redirect_uri = uri.into();
        self
    }
    pub fn scopes(mut self, scopes: impl Into<String>) -> Self {
        self.opts.scopes = Some(scopes.into());
        self
    }
    /// Set mTLS client certificate and private key paths.
    pub fn tls_client_auth(
        mut self,
        cert: impl Into<PathBuf>,
        key: impl Into<PathBuf>,
        subject_dn: impl Into<String>,
    ) -> Self {
        self.opts.tls_cert = Some(cert.into());
        self.opts.tls_key = Some(key.into());
        self.opts.tls_client_auth_subject_dn = Some(subject_dn.into());
        self
    }
    /// Set only the TLS client cert path (for testing validation - use
    /// [`tls_client_auth`](Self::tls_client_auth) for real mTLS config).
    pub fn tls_cert(mut self, cert: impl Into<PathBuf>) -> Self {
        self.opts.tls_cert = Some(cert.into());
        self
    }
    pub fn discovery_ttl(mut self, ttl: Duration) -> Self {
        self.opts.discovery_ttl = ttl;
        self
    }
    pub fn jwks_ttl(mut self, ttl: Duration) -> Self {
        self.opts.jwks_ttl = ttl;
        self
    }
    pub fn http_timeout(mut self, timeout: Duration) -> Self {
        self.opts.http_timeout = timeout;
        self
    }
    pub fn refresh_retries(mut self, retries: u32) -> Self {
        self.opts.refresh_retries = retries;
        self
    }
    /// Set the DPoP signing key (PEM-encoded PKCS#8) and algorithm.
    pub fn dpop_key(mut self, pem: impl Into<String>, alg: impl Into<String>) -> Self {
        self.opts.dpop_key_pem = Some(Arc::new(pem.into()));
        self.opts.dpop_signing_alg = Some(alg.into());
        self
    }
    /// Set the JAR (request object) signing key (PEM-encoded PKCS#8) and algorithm.
    pub fn jar_key(mut self, pem: impl Into<String>, alg: impl Into<String>) -> Self {
        self.opts.jar_key_pem = Some(Arc::new(pem.into()));
        self.opts.jar_signing_alg = Some(alg.into());
        self
    }
    pub fn build(self) -> Result<ClientOptions, FapiError> {
        self.opts.validate()?;
        Ok(self.opts)
    }
}
